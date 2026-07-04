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

import hashlib
import logging
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .mobile_ffs import (
    CellebriteAdapter,
    ContainerSafetyError,
    CRCMismatchError,
    ExtractedEntry,
    ExtractionPolicy,
    FormatID,
    ResolvedArtifact,
    safe_iter_entries,
)
from .mobile_ffs.safe_zip import (
    EntryCountError,
    FilenameLengthError,
    PathTraversalError,
    SymlinkEntryError,
    ZipBombError,
    _dos_dt_to_unix,
    _is_symlink_entry,
    _parse_x5455_extra,
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

        try:
            for entry in self._iter_selected_entries(dest_dir, wanted_extract):
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

    def _iter_selected_entries(
        self,
        dest_dir: Path,
        wanted_extract: Dict[str, ResolvedArtifact],
    ) -> Iterator[ExtractedEntry]:
        """Yield selected entries with a 7z fallback for split UFED archives.

        Python's zipfile can read a split ZIP central directory but cannot always
        stream member bodies from multi-volume UFED exports. The normal safe_zip
        path remains primary; 7z is used only after zipfile raises BadZipFile.
        """
        select = lambda info: info.filename in wanted_extract
        yielded: set[str] = set()
        try:
            for entry in safe_iter_entries(
                self._adapter._zf, dest_dir,
                select=select, policy=self._policy,
            ):
                yielded.add(entry.zip_entry_path)
                yield entry
        except zipfile.BadZipFile as exc:
            seven_zip = self._seven_zip_binary()
            if not seven_zip:
                raise ContainerSafetyError(
                    "zipfile failed to read this UFED container and 7z/7zz was "
                    f"not found for split-archive fallback: {exc}"
                ) from exc
            logger.warning(
                "zipfile failed while extracting %s; retrying selected FFS "
                "entries with %s fallback: %s",
                self.zip_path.name,
                seven_zip,
                exc,
            )
            for entry in self._iter_selected_entries_with_7z(
                dest_dir,
                wanted_extract,
                seven_zip,
                already_yielded=yielded,
            ):
                yield entry

    @staticmethod
    def _seven_zip_binary() -> Optional[str]:
        return shutil.which("7z") or shutil.which("7zz")

    def _iter_selected_entries_with_7z(
        self,
        dest_dir: Path,
        wanted_extract: Dict[str, ResolvedArtifact],
        seven_zip: str,
        *,
        already_yielded: set[str],
    ) -> Iterator[ExtractedEntry]:
        if self._adapter is None or self._adapter._zf is None:
            raise RuntimeError("adapter not opened")

        dest_dir.mkdir(parents=True, exist_ok=True)
        stream_dir = dest_dir / "_7z_stream"
        stream_dir.mkdir(parents=True, exist_ok=True)

        entry_count = 0
        bytes_written_total = 0
        for info in self._adapter._zf.infolist():
            entry_count += 1
            if entry_count > self._policy.max_entries:
                raise EntryCountError(
                    f"entry count exceeds {self._policy.max_entries}"
                )
            if info.is_dir() or info.filename not in wanted_extract:
                continue
            if info.filename in already_yielded:
                continue
            if _is_symlink_entry(info):
                raise SymlinkEntryError(
                    f"symlink entry rejected: {info.filename!r}"
                )
            self._validate_7z_member_name(info.filename)

            projected_out = bytes_written_total + (info.file_size or 0)
            if projected_out > self._policy.max_out_bytes:
                raise ZipBombError(
                    f"projected output {projected_out} exceeds "
                    f"{self._policy.max_out_bytes}"
                )

            out_path = self._fallback_output_path(stream_dir, info.filename)
            if out_path.exists():
                out_path.unlink()
            sha256_hex, written = self._extract_member_with_7z(
                seven_zip,
                info,
                out_path,
            )
            bytes_written_total += written

            mtime_unix, atime_unix, btime_unix = _parse_x5455_extra(info.extra)
            mtime_source = "x5455" if mtime_unix is not None else "dos"
            if mtime_unix is None:
                mtime_unix = _dos_dt_to_unix(info.date_time)
            if mtime_unix is not None:
                try:
                    os.utime(out_path, (atime_unix or mtime_unix, mtime_unix))
                except OSError:
                    pass

            yield ExtractedEntry(
                zip_entry_path=info.filename,
                extracted_path=out_path,
                source_size=info.file_size,
                source_sha256=sha256_hex,
                source_crc32=info.CRC,
                mtime_unix=mtime_unix,
                atime_unix=atime_unix,
                birthtime_unix=btime_unix,
                mtime_source=mtime_source,
            )

    def _validate_7z_member_name(self, name: str) -> None:
        if not name:
            raise PathTraversalError("empty entry name")
        if len(name.encode("utf-8", errors="surrogateescape")) > self._policy.max_filename_bytes:
            raise FilenameLengthError(
                f"filename exceeds {self._policy.max_filename_bytes} bytes"
            )
        normalized = name.replace("\\", "/")
        if normalized.startswith("/") or normalized.startswith("../"):
            raise PathTraversalError(f"unsafe member path: {name!r}")
        if "/../" in normalized or normalized.endswith("/.."):
            raise PathTraversalError(f"unsafe member path: {name!r}")
        if len(normalized) >= 2 and normalized[1] == ":":
            raise PathTraversalError(f"absolute drive path: {name!r}")
        if "\x00" in normalized:
            raise PathTraversalError("NUL in filename")

    @staticmethod
    def _fallback_output_path(stream_dir: Path, member_name: str) -> Path:
        source_name = member_name.replace("\\", "/").rsplit("/", 1)[-1]
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", source_name).strip("._")
        if not safe_name:
            safe_name = "artifact.bin"
        safe_name = safe_name[:96]
        prefix = hashlib.sha1(
            member_name.encode("utf-8", "surrogateescape")
        ).hexdigest()[:16]
        return stream_dir / f"{prefix}_{safe_name}"

    def _extract_member_with_7z(
        self,
        seven_zip: str,
        info,
        out_path: Path,
    ) -> Tuple[str, int]:
        import zlib

        out_path.parent.mkdir(parents=True, exist_ok=True)
        proc = subprocess.Popen(
            [seven_zip, "x", "-so", str(self.zip_path), info.filename],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        sha256 = hashlib.sha256()
        crc = 0
        written = 0
        try:
            assert proc.stdout is not None
            with open(out_path, "wb") as dst:
                while True:
                    chunk = proc.stdout.read(self._policy.chunk_bytes)
                    if not chunk:
                        break
                    sha256.update(chunk)
                    crc = zlib.crc32(chunk, crc)
                    dst.write(chunk)
                    written += len(chunk)
            stderr = proc.stderr.read() if proc.stderr is not None else b""
            rc = proc.wait()
        except Exception:
            proc.kill()
            try:
                out_path.unlink()
            except OSError:
                pass
            raise

        if rc != 0:
            try:
                out_path.unlink()
            except OSError:
                pass
            detail = stderr.decode("utf-8", errors="replace").strip()[:500]
            raise ContainerSafetyError(
                f"7z extraction failed for {info.filename!r}: {detail or rc}"
            )
        if info.file_size and written != info.file_size:
            try:
                out_path.unlink()
            except OSError:
                pass
            raise CRCMismatchError(
                f"size mismatch: read {written}, central dir says {info.file_size}"
            )
        if info.CRC and crc != info.CRC:
            try:
                out_path.unlink()
            except OSError:
                pass
            raise CRCMismatchError(
                f"crc mismatch: computed 0x{crc:08x}, central dir 0x{info.CRC:08x}"
            )
        return sha256.hexdigest(), written

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
