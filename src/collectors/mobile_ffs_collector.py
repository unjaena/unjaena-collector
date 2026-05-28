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
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from .mobile_ffs import (
    CellebriteAdapter,
    ContainerSafetyError,
    ExtractionPolicy,
    FormatID,
    ResolvedArtifact,
    safe_iter_entries,
)

logger = logging.getLogger(__name__)


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

    def collect(
        self, artifact_type: str, **_ignored
    ) -> Iterator[Tuple[str, dict]]:
        """Extract every present file for *artifact_type* and yield
        (extracted_path, metadata) pairs. Errors yield ('', {...}) so
        the dispatch loop's error path triggers normally."""
        if self._adapter is None:
            self.open()

        ras = self._artifacts_by_type.get(artifact_type)
        if not ras:
            yield "", {
                "status": "not_implemented",
                "error": f"Artifact '{artifact_type}' not in FFS path-spec table",
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
                yield str(entry.extracted_path), {
                    "status": "success",
                    "source_path": entry.zip_entry_path,
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
        the parser side. Sidecars are extracted to disk but not yielded
        as separate artifacts."""
        sidecars: Dict[str, ResolvedArtifact] = {}
        for primary_path, ra in list(wanted.items()):
            if not primary_path.lower().endswith(self.SQLITE_SUFFIXES):
                continue
            for suffix in ("-wal", "-shm"):
                cand = primary_path + suffix
                if cand in self._zip_entries and cand not in wanted:
                    sidecars[cand] = ra
        return sidecars
