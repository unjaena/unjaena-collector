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
            if spec.is_directory and spec.container_kind in (
                ContainerKind.SYSTEM, ContainerKind.ROOT_SYSTEM,
            ):
                # Fan out: one ResolvedArtifact per child file under
                # the directory prefix. If the directory has no
                # children present, emit a single absent record so
                # the case manifest still shows we looked.
                children = list(self._ios_directory_children(spec))
                if children:
                    for child_path in children:
                        yield ResolvedArtifact(
                            artifact_type=spec.artifact_type,
                            expected_zip_path=child_path,
                            actual_zip_path=child_path,
                            present=True,
                            spec_description=spec.description,
                        )
                else:
                    yield ResolvedArtifact(
                        artifact_type=spec.artifact_type,
                        expected_zip_path=(
                            f"filesystem1/{spec.relative_path}/<children>"
                        ),
                        actual_zip_path=None,
                        present=False,
                        spec_description=spec.description,
                    )
                continue
            expected, actual, present = self._ios_resolve(spec)
            yield ResolvedArtifact(
                artifact_type=spec.artifact_type,
                expected_zip_path=expected,
                actual_zip_path=actual,
                present=present,
                spec_description=spec.description,
            )

    # Apple housekeeping dotfiles to exclude from directory dispatch.
    # Forensically irrelevant; they bloat the manifest if surfaced.
    _DIRECTORY_DOTFILE_SKIP = frozenset({
        ".DS_Store", ".metadata_never_index",
        ".metadata_never_index_unless_rootfs", ".Trashes",
        ".fseventsd", ".Spotlight-V100",
    })

    def _ios_directory_children(self, spec) -> Iterator[str]:
        """Yield zip entry paths under a SYSTEM/ROOT_SYSTEM directory
        spec. Recurses into subdirectories. Skips zip directory
        entries (trailing '/') and known-irrelevant Apple housekeeping
        dotfiles (.DS_Store etc). When the spec carries a non-empty
        `child_suffix_filter`, ONLY entries whose filename ends in one
        of those suffixes (case-insensitive) are yielded — this keeps
        directory specs like CoreSpotlight from pulling thousands of
        binary index files when only the SQLite portion (.store.db)
        is forensically usable.

        IMPORTANT: dotfile filtering uses a denylist of known noise
        names, not a generic `startswith('.')` check. Some real
        forensic artifacts (e.g. `.store.db`) start with a dot — a
        blanket dotfile skip would silently drop them.
        """
        prefix = f"filesystem1/{spec.relative_path}"
        # Trailing slash to ensure we match children, not the dir itself
        prefix_slash = prefix + ("/" if not prefix.endswith("/") else "")
        suffix_filter = tuple(
            s.lower() for s in (spec.child_suffix_filter or ())
        )
        for entry in self._entry_set or ():
            if not entry.startswith(prefix_slash):
                continue
            if entry.endswith("/"):
                continue
            tail = entry[len(prefix_slash):]
            base = tail.rsplit("/", 1)[-1]
            if base in self._DIRECTORY_DOTFILE_SKIP:
                continue
            if suffix_filter:
                lname = base.lower()
                if not any(lname.endswith(s) for s in suffix_filter):
                    continue
            yield entry

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

        # SQLite sidecar augmentation: for every primary entry whose
        # path ends in a SQLite suffix, also pull the -wal and -shm
        # sidecars when present in the zip. They land in the same
        # destination directory as the primary file so sqlite3.connect
        # transparently merges WAL state, AND so the recovery pipeline
        # (deleted-row walker) can locate the WAL file by suffix.
        # The sidecars are tagged with the SAME artifact_type as the
        # primary, with a `_wal` / `_shm` filename suffix marker in
        # the manifest, so the case record carries them as auxiliary
        # evidence without dispatching them as separate artifacts.
        zip_entries_set = self._entry_set or set()
        sqlite_suffixes = (".db", ".sqlite", ".sqlitedb", ".sqlite3")
        sidecar_extras: Dict[str, ResolvedArtifact] = {}
        for primary_path, ra in list(wanted.items()):
            if not primary_path.lower().endswith(sqlite_suffixes):
                continue
            for suffix in ("-wal", "-shm"):
                cand = primary_path + suffix
                if cand in zip_entries_set and cand not in wanted:
                    sidecar_extras[cand] = ra
        # Merge — use a separate map so the dispatcher routes only
        # the primary, but extraction grabs all three.
        wanted_extract = dict(wanted)
        wanted_extract.update(sidecar_extras)

        # Single pass — extract anything in `wanted_extract`.
        # IMPORTANT: only PRIMARY artifacts get recorded in the
        # artifacts manifest. Sidecars (-wal/-shm) are extracted to
        # disk alongside the primary so sqlite3.connect transparently
        # merges WAL state, but they are NOT separately dispatched to
        # parsers (they are not standalone SQLite databases — opening
        # them via sqlite3 raises). Sidecars land in the manifest's
        # not_extracted list with reason="sidecar_pulled:<artifact>"
        # for chain-of-custody transparency.
        select = lambda info: info.filename in wanted_extract
        counts = {"extracted": 0, "absent": 0, "errors": 0,
                  "sidecars_pulled": 0}
        try:
            for entry in safe_iter_entries(
                self._zf, dest_dir, select=select, policy=policy
            ):
                ra = wanted_extract[entry.zip_entry_path]
                if entry.zip_entry_path in sidecar_extras:
                    # Pull-only — file is on disk for transparent
                    # WAL merge but NOT dispatched as a separate
                    # artifact_type. Record under not_extracted with
                    # a sidecar reason so the chain of custody shows
                    # exactly what was pulled.
                    inv = InventoryEntry(
                        zip_entry_path=entry.zip_entry_path,
                        source_size=entry.source_size,
                        compressed_size=0,
                        central_crc32=entry.source_crc32,
                        is_symlink=False,
                        is_dir=False,
                        reason=f"sidecar_pulled:{ra.artifact_type}",
                    )
                    manifest.append_not_extracted(inv)
                    counts["sidecars_pulled"] += 1
                else:
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
