"""Bundle collector wrapper for offline mobile forensic images.

Adapts the mobile_ffs.CellebriteAdapter (zip → resolved artifacts) to
the (file_path, metadata) generator contract that the GUI dispatch
loop already drives for live AndroidCollector / iOSCollector instances.

A bundle device is treated identically to a live device by the rest
of the pipeline: same artifact-type checkbox, same upload path, same
chain-of-custody manifest. The only difference is the byte source —
a vendor extraction zip on disk instead of an ADB / pymobiledevice3
session.
"""
from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .mobile_ffs import (
    CellebriteAdapter,
    ContainerSafetyError,
    ExtractionPolicy,
    FormatID,
    ResolvedArtifact,
    safe_iter_entries,
)

logger = logging.getLogger(__name__)

ANDROID_FFS_ALIASES = {
    "mobile_android_sms_provider": "mobile_android_sms",
    "mobile_android_call_provider": "mobile_android_call",
    "mobile_android_contacts_provider": "mobile_android_contacts",
}

ANDROID_FFS_SYSTEM_EXPANSION = {
    "mobile_android_app_install_history",
    "mobile_android_batterystats",
    "mobile_android_bluetooth_pairings",
    "mobile_android_dropbox_logs",
    "mobile_android_locksettings",
    "mobile_android_wifi",
}

ANDROID_FFS_APP_EXCLUDE = {
    "mobile_android_sms",
    "mobile_android_call",
    "mobile_android_contacts",
    "mobile_android_calendar_provider",
    "mobile_android_media",
    *ANDROID_FFS_SYSTEM_EXPANSION,
}

ANDROID_FFS_GENERIC_EXPANSIONS = {
    "mobile_android_system_info": ANDROID_FFS_SYSTEM_EXPANSION,
    "mobile_android_location": {"mobile_android_google_maps"},
}


def canonicalize_mobile_ffs_artifact(artifact_type: str) -> str:
    """Return the FFS canonical artifact id for live-device aliases."""
    return ANDROID_FFS_ALIASES.get(artifact_type, artifact_type)


def expand_mobile_ffs_selection(
    artifact_type: str,
    available_types: Iterable[str],
    *,
    platform: str = "android",
) -> List[str]:
    """Expand generic/live mobile selections into FFS-routable ids.

    FFS bundles are already offline full-filesystem exports. Live Android
    provider ids and generic UI ids should therefore route to the concrete
    artifact ids present in the bundle so server parsing and embeddings keep
    their specific type labels.
    """
    available = set(available_types or ())
    canonical = canonicalize_mobile_ffs_artifact(artifact_type)

    if canonical in available:
        return [canonical]

    if platform.lower() != "android":
        return []

    if canonical == "mobile_android_app":
        return sorted(
            t for t in available
            if (
                (t.startswith("mobile_android_") or t.startswith("ai_mobile_"))
                and t not in ANDROID_FFS_APP_EXCLUDE
            )
        )

    expanded = ANDROID_FFS_GENERIC_EXPANSIONS.get(canonical)
    if expanded:
        return sorted(t for t in expanded if t in available)

    return []


class MobileFFSBundleCollector:
    """Per-artifact lazy extractor over an open Cellebrite zip handle."""

    SQLITE_SUFFIXES = (".db", ".sqlite", ".sqlitedb", ".sqlite3")

    def __init__(self, output_dir: str, zip_path: str):
        self.output_dir = Path(output_dir)
        self.zip_path = Path(zip_path)
        self._adapter: Optional[CellebriteAdapter] = None
        self._artifacts_by_type: Dict[str, List[ResolvedArtifact]] = {}
        self._zip_entries: set = set()
        self._policy = ExtractionPolicy()
        self._platform: str = "unknown"

    def open(self) -> None:
        if self._adapter is not None:
            return
        adapter = CellebriteAdapter(self.zip_path)
        adapter.__enter__()
        self._adapter = adapter
        self._zip_entries = set(adapter._zf.namelist()) if adapter._zf else set()
        self._platform = (
            "ios" if adapter.format_id == FormatID.CELLEBRITE_CLBX_IOS
            else "android"
        )
        for ra in adapter.iter_known_artifacts():
            self._artifacts_by_type.setdefault(ra.artifact_type, []).append(ra)
        self._install_android_aliases()
        logger.info(
            "FFS bundle opened: %s platform=%s artifact_types=%d",
            self.zip_path.name, self._platform, len(self._artifacts_by_type),
        )

    def close(self) -> None:
        if self._adapter is not None:
            self._adapter.__exit__(None, None, None)
            self._adapter = None
            self._artifacts_by_type.clear()
            self._zip_entries = set()

    def _install_android_aliases(self) -> None:
        if self._platform != "android":
            return

        exact_types = set(self._artifacts_by_type)
        for alias, canonical in ANDROID_FFS_ALIASES.items():
            if canonical in self._artifacts_by_type:
                self._artifacts_by_type.setdefault(alias, self._artifacts_by_type[canonical])

        for generic, expansion in ANDROID_FFS_GENERIC_EXPANSIONS.items():
            ras = [
                ra
                for artifact_type in sorted(expansion)
                for ra in self._artifacts_by_type.get(artifact_type, [])
            ]
            if ras:
                self._artifacts_by_type.setdefault(generic, ras)

        app_like = [
            ra
            for artifact_type in sorted(exact_types)
            if (
                (artifact_type.startswith("mobile_android_") or artifact_type.startswith("ai_mobile_"))
                and artifact_type not in ANDROID_FFS_APP_EXCLUDE
            )
            for ra in self._artifacts_by_type.get(artifact_type, [])
        ]
        if app_like:
            self._artifacts_by_type.setdefault("mobile_android_app", app_like)

    def _stage_upload_file(self, artifact_type: str, entry) -> Path:
        """Move a nested extracted entry to a short upload-staging path.

        Zip paths can be deeply nested. Returning those paths directly makes
        Windows upload code vulnerable to path normalization and length edge
        cases. The original zip path remains in metadata; the upload file is a
        stable flat copy under ``ffs_bundle/_upload``.
        """
        source_name = entry.zip_entry_path.replace("\\", "/").rsplit("/", 1)[-1]
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", source_name).strip("._")
        if not safe_name:
            safe_name = "artifact.bin"
        safe_name = safe_name[:96]

        prefix = (entry.source_sha256 or "unknown")[:16]
        upload_dir = self.output_dir / "ffs_bundle" / "_upload" / artifact_type
        upload_dir.mkdir(parents=True, exist_ok=True)
        candidate = upload_dir / f"{prefix}_{safe_name}"

        if not candidate.exists():
            shutil.move(str(entry.extracted_path), str(candidate))
        elif entry.extracted_path.exists():
            entry.extracted_path.unlink()
        return candidate

    def collect(
        self, artifact_type: str, **_ignored
    ) -> Iterator[Tuple[str, dict]]:
        """Extract every present file for *artifact_type* and yield
        (extracted_path, metadata) pairs. Errors yield ('', {...}) so
        the dispatch loop's error path triggers normally."""
        if self._adapter is None:
            self.open()

        requested_artifact_type = artifact_type
        ras = self._artifacts_by_type.get(artifact_type)
        if not ras:
            yield "", {
                "status": "skipped",
                "error": (
                    f"Artifact '{artifact_type}' is not supported by this "
                    "FFS bundle profile"
                ),
            }
            return

        present = [ra for ra in ras if ra.present and ra.actual_zip_path]
        if not present:
            yield "", {
                "status": "not_found",
                "error": f"No matching files for '{artifact_type}' in bundle",
            }
            return

        dest_dir = self.output_dir / "ffs_bundle" / artifact_type
        dest_dir.mkdir(parents=True, exist_ok=True)

        wanted: Dict[str, ResolvedArtifact] = {
            ra.actual_zip_path: ra for ra in present if ra.actual_zip_path
        }

        sidecars = self._collect_sqlite_sidecars(wanted)
        wanted_extract = {**wanted, **sidecars}

        select = lambda info: info.filename in wanted_extract
        try:
            for entry in safe_iter_entries(
                self._adapter._zf, dest_dir,
                select=select, policy=self._policy,
            ):
                if entry.zip_entry_path in sidecars:
                    continue
                ra = wanted[entry.zip_entry_path]
                upload_path = self._stage_upload_file(ra.artifact_type, entry)
                metadata = {
                    "status": "success",
                    "source_path": entry.zip_entry_path,
                    "original_path": entry.zip_entry_path,
                    "extracted_source_path": str(entry.extracted_path),
                    "sha256": entry.source_sha256,
                    "crc32": entry.source_crc32,
                    "source_size": entry.source_size,
                    "mtime_unix": entry.mtime_unix,
                    "atime_unix": entry.atime_unix,
                    "birthtime_unix": entry.birthtime_unix,
                    "mtime_source": entry.mtime_source,
                    "spec_description": ra.spec_description,
                    "platform": self._platform,
                    "collection_method": "ffs_bundle",
                    "bundle_format": "cellebrite_clbx",
                    "bundle_path": str(self.zip_path),
                }
                if requested_artifact_type != ra.artifact_type:
                    metadata["requested_artifact_type"] = requested_artifact_type
                    metadata["upload_artifact_type"] = ra.artifact_type
                yield str(upload_path), metadata
        except ContainerSafetyError as e:
            yield "", {
                "status": "error",
                "error": f"Container safety violation: {type(e).__name__}: {e}",
            }

    def _collect_sqlite_sidecars(
        self, wanted: Dict[str, ResolvedArtifact]
    ) -> Dict[str, ResolvedArtifact]:
        """For every SQLite primary in *wanted*, also pull -wal/-shm
        sidecars so sqlite3.connect transparently merges WAL state on
        the parser side. Android apps often use extensionless SQLite
        files (for example ``bugle_db`` or ``signal_v4.db`` variants),
        so sidecar detection is based on adjacent filenames rather than
        only on the primary extension. Sidecars are extracted to disk but
        not yielded as separate artifacts."""
        sidecars: Dict[str, ResolvedArtifact] = {}
        sidecar_suffixes = ("-wal", "-shm", "-journal")

        for candidate in list(wanted):
            for suffix in sidecar_suffixes:
                if candidate.endswith(suffix):
                    primary = candidate[:-len(suffix)]
                    if primary in wanted:
                        sidecars[candidate] = wanted[primary]
                        wanted.pop(candidate, None)
                    break

        for primary_path, ra in list(wanted.items()):
            for suffix in sidecar_suffixes:
                cand = primary_path + suffix
                if cand in self._zip_entries and cand not in wanted:
                    sidecars[cand] = ra
        return sidecars
