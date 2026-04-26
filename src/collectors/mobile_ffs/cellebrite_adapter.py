"""Cellebrite UFED Full File System container adapter.

Exposes the contents of a Cellebrite zip (CLBX-class) as a uniform
read-only FFSView so downstream code can treat Android and iOS
extractions identically. Works in tandem with:

  - safe_zip          : safe streaming extraction primitives
  - format_detector   : zip → FormatID classification
  - path_specs        : artifact-type → expected path table
  - ios_uuid_resolver : iOS bundle-id → UUID resolution
  - case_manifest     : Daubert-grade bundle writer

The adapter is the integration point. Downstream callers do not see
zipfile, plistlib, or the per-vendor layout; they ask for an artifact
type or a path and get bytes + provenance metadata back.
"""
from __future__ import annotations

import logging
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from .case_manifest import CaseManifestWriter
from .format_detector import (
    FormatID,
    HIGH_CONFIDENCE,
    MEDIUM_CONFIDENCE,
    detect_zip_format,
)
from .ios_uuid_resolver import (
    UUIDMapping,
    build_uuid_map,
    resolve_app_path,
)
from .path_specs import (
    ANDROID_PATH_SPECS,
    AndroidArtifactSpec,
    ContainerKind,
    IOS_PATH_SPECS,
    IOSArtifactSpec,
)
from .safe_zip import (
    ContainerSafetyError,
    ExtractionPolicy,
    InventoryEntry,
    inventory_all,
    safe_iter_entries,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResolvedArtifact:
    """A spec resolved against the actual contents of an FFS dump.

    `expected_zip_path` is what the spec told us to look for.
    `actual_zip_path` is what we found (may equal expected for
    Android, or differ for iOS where UUIDs vary).
    `present` records whether the file actually exists in the zip.
    """
    artifact_type: str
    expected_zip_path: Optional[str]
    actual_zip_path: Optional[str]
    present: bool
    spec_description: str


class CellebriteAdapter:
    """Adapter for Cellebrite UFED Android/iOS FFS zip containers.

    Use as a context manager so the underlying zip handle closes
    deterministically:

        with CellebriteAdapter(zip_path) as ad:
            for resolved in ad.iter_known_artifacts():
                if resolved.present:
                    ad.extract_artifact_to(resolved, dest_dir, manifest)
    """

    def __init__(self, zip_path: Path):
        self.zip_path = Path(zip_path)
        self._zf: Optional[zipfile.ZipFile] = None
        self._format_id: Optional[FormatID] = None
        self._detection = None
        self._uuid_map: Optional[UUIDMapping] = None
        # Cached set for O(1) "does the zip have this entry" lookups.
        self._entry_set: Optional[set] = None

    # ---------- context-manager lifecycle ----------------------------
    def __enter__(self) -> "CellebriteAdapter":
        self._detection = detect_zip_format(self.zip_path)
        self._format_id = self._detection.format_id
        if self._format_id not in (FormatID.CELLEBRITE_CLBX_IOS,
                                   FormatID.CELLEBRITE_CLBX_ANDROID):
            raise ValueError(
                f"CellebriteAdapter requires a Cellebrite CLBX zip; "
                f"detected: {self._format_id.value} "
                f"(confidence={self._detection.confidence})"
            )
        self._zf = zipfile.ZipFile(self.zip_path, "r")
        self._entry_set = set(self._zf.namelist())
        # iOS-only: build UUID map up front (single pass over central dir).
        if self._format_id == FormatID.CELLEBRITE_CLBX_IOS:
            logger.info(
                "Building iOS UUID → bundle-id map for %s", self.zip_path
            )
            self._uuid_map = build_uuid_map(self._zf)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._zf is not None:
            self._zf.close()
            self._zf = None
        return False  # never suppress

    # ---------- introspection ----------------------------------------
    @property
    def format_id(self) -> FormatID:
        if self._format_id is None:
            raise RuntimeError("adapter not entered (use 'with' statement)")
        return self._format_id

    @property
    def detection(self):
        return self._detection

    @property
    def uuid_map(self) -> Optional[UUIDMapping]:
        return self._uuid_map

    # ---------- artifact resolution ----------------------------------
    def iter_known_artifacts(self) -> Iterator[ResolvedArtifact]:
        """Yield one ResolvedArtifact per entry in the relevant
        path-spec table for this zip's platform. Includes specs whose
        target file is *absent* from the source — the caller decides
        whether to record those as "expected but absent" in the case
        manifest."""
        if self._format_id == FormatID.CELLEBRITE_CLBX_ANDROID:
            yield from self._iter_android()
        elif self._format_id == FormatID.CELLEBRITE_CLBX_IOS:
            yield from self._iter_ios()

    def _iter_android(self) -> Iterator[ResolvedArtifact]:
        for spec in ANDROID_PATH_SPECS:
            expected = self._android_expected_path(spec)
            present = expected in self._entry_set
            yield ResolvedArtifact(
                artifact_type=spec.artifact_type,
                expected_zip_path=expected,
                actual_zip_path=expected if present else None,
                present=present,
                spec_description=spec.description,
            )

    def _iter_ios(self) -> Iterator[ResolvedArtifact]:
        assert self._uuid_map is not None
        for spec in IOS_PATH_SPECS:
            expected, actual, present = self._ios_resolve(spec)
            yield ResolvedArtifact(
                artifact_type=spec.artifact_type,
                expected_zip_path=expected,
                actual_zip_path=actual,
                present=present,
                spec_description=spec.description,
            )

    def _android_expected_path(self, spec: AndroidArtifactSpec) -> str:
        if spec.container_kind == ContainerKind.APP_DATA:
            return f"Dump/data/data/{spec.package}/{spec.relative_path}"
        if spec.container_kind == ContainerKind.SYSTEM:
            return f"Dump/{spec.relative_path}"
        # Fallback for less-common kinds — direct join under Dump/
        return f"Dump/{spec.relative_path}"

    def _ios_resolve(self, spec: IOSArtifactSpec
                     ) -> Tuple[Optional[str], Optional[str], bool]:
        """Return (expected_path, actual_path, present) for one iOS
        spec. expected_path is the canonical statement of "where we
        looked"; actual_path is None when no UUID matched."""
        if spec.container_kind in (ContainerKind.SYSTEM,
                                   ContainerKind.ROOT_SYSTEM):
            expected = f"filesystem1/{spec.relative_path}"
            present = expected in self._entry_set
            return expected, expected if present else None, present

        if spec.container_kind in (ContainerKind.APP_DATA,
                                   ContainerKind.APP_GROUP,
                                   ContainerKind.APP_BUNDLE):
            assert self._uuid_map is not None
            kind_map = {
                ContainerKind.APP_DATA: "app_data",
                ContainerKind.APP_GROUP: "app_group",
                ContainerKind.APP_BUNDLE: "app_bundle",
            }
            kind = kind_map[spec.container_kind]
            actual = resolve_app_path(
                self._uuid_map,
                bundle_id=spec.package or "",
                container_kind=kind,
                relative_path=spec.relative_path,
            )
            expected_repr = (
                f"<{kind}>/<UUID>/{spec.relative_path} "
                f"(bundle={spec.package})"
            )
            present = (actual is not None) and (actual in self._entry_set)
            return expected_repr, actual if present else None, present

        return None, None, False

    # ---------- extraction (delegates to safe_zip + manifest) --------
    def extract_to_manifest(
        self,
        dest_dir: Path,
        *,
        manifest: CaseManifestWriter,
        policy: Optional[ExtractionPolicy] = None,
    ) -> Dict[str, int]:
        """Walk known artifacts; extract every present one into
        dest_dir under safe_iter_entries; record results in manifest.

        Also writes one `not_extracted` row for every spec whose target
        was absent — that's how the case proves we looked.
        """
        if self._zf is None:
            raise RuntimeError("adapter not entered")
        manifest.set_detection(self._detection)
        policy = policy or ExtractionPolicy()
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Build a quick map: actual_zip_path → ResolvedArtifact for
        # entries that should be extracted.
        wanted: Dict[str, ResolvedArtifact] = {}
        absent_specs: List[ResolvedArtifact] = []
        for ra in self.iter_known_artifacts():
            if ra.present and ra.actual_zip_path:
                wanted[ra.actual_zip_path] = ra
            else:
                absent_specs.append(ra)

        # Single pass — extract anything in `wanted`.
        select = lambda info: info.filename in wanted
        counts = {"extracted": 0, "absent": 0, "errors": 0}
        try:
            for entry in safe_iter_entries(
                self._zf, dest_dir, select=select, policy=policy
            ):
                ra = wanted[entry.zip_entry_path]
                manifest.append_artifact(
                    entry, artifact_type=ra.artifact_type
                )
                counts["extracted"] += 1
        except ContainerSafetyError as e:
            manifest.append_safety_violation(f"{type(e).__name__}: {e}")
            counts["errors"] += 1

        # Record everything we EXPECTED but DIDN'T find.
        for ra in absent_specs:
            inv = InventoryEntry(
                zip_entry_path=(ra.expected_zip_path or
                                f"<spec:{ra.artifact_type}>"),
                source_size=0,
                compressed_size=0,
                central_crc32=0,
                is_symlink=False,
                is_dir=False,
                reason=f"expected_but_absent:{ra.artifact_type}",
            )
            manifest.append_not_extracted(inv)
            counts["absent"] += 1

        return counts

    # ---------- support: full inventory (for the not_extracted side) -
    def write_full_not_extracted(self, manifest: CaseManifestWriter,
                                 *, exclude: Optional[set] = None) -> int:
        """Walk every entry in the zip and write a not_extracted row
        for entries not in `exclude`. The caller passes the set of
        entries it just extracted so they don't get logged as
        not-extracted."""
        if self._zf is None:
            raise RuntimeError("adapter not entered")
        exclude = exclude or set()
        # Selection predicate: True if we previously extracted it
        # (so inventory_all marks the *opposite* — entries it didn't
        # select — as not_in_extraction_spec).
        select = lambda info: info.filename in exclude
        n = 0
        for inv in inventory_all(self._zf, select_predicate=select):
            manifest.append_not_extracted(inv)
            n += 1
        return n
