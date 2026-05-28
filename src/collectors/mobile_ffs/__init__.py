"""Offline mobile forensic image (FFS dump) collector module.

Accepts vendor extraction containers (currently Cellebrite UFED zip
format) and exposes their contents through a uniform read-only view
so the existing artifact upload path can ingest them as if they were
a live device.

Phase 1A delivers safe container handling primitives. Layout adapters
and format detection arrive in Phase 1B and 1D.
"""
from .case_manifest import (
    ArtifactRecord,
    BinaryBlobRecord,
    BlobReason,
    CaseManifest,
    CaseManifestWriter,
    NotExtractedRecord,
)
from .cellebrite_adapter import (
    CellebriteAdapter,
    ResolvedArtifact,
)
from .format_detector import (
    FormatDetection,
    FormatID,
    HIGH_CONFIDENCE,
    LOW_CONFIDENCE,
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
    all_artifact_types,
    find_android_spec_by_path,
    find_ios_system_spec_by_path,
)
from .safe_zip import (
    ContainerSafetyError,
    CRCMismatchError,
    EntryCountError,
    ExtractedEntry,
    ExtractionPolicy,
    FilenameLengthError,
    InventoryEntry,
    PathTraversalError,
    SymlinkEntryError,
    ZipBombError,
    inventory_all,
    safe_iter_entries,
)

__all__ = [
    # safe_zip
    "ContainerSafetyError",
    "CRCMismatchError",
    "EntryCountError",
    "ExtractedEntry",
    "ExtractionPolicy",
    "FilenameLengthError",
    "InventoryEntry",
    "PathTraversalError",
    "SymlinkEntryError",
    "ZipBombError",
    "inventory_all",
    "safe_iter_entries",
    # format_detector
    "FormatDetection",
    "FormatID",
    "HIGH_CONFIDENCE",
    "MEDIUM_CONFIDENCE",
    "LOW_CONFIDENCE",
    "detect_zip_format",
    # case_manifest
    "ArtifactRecord",
    "BinaryBlobRecord",
    "BlobReason",
    "CaseManifest",
    "CaseManifestWriter",
    "NotExtractedRecord",
    # path_specs
    "ANDROID_PATH_SPECS",
    "AndroidArtifactSpec",
    "ContainerKind",
    "IOS_PATH_SPECS",
    "IOSArtifactSpec",
    "all_artifact_types",
    "find_android_spec_by_path",
    "find_ios_system_spec_by_path",
    # ios_uuid_resolver
    "UUIDMapping",
    "build_uuid_map",
    "resolve_app_path",
    # cellebrite_adapter
    "CellebriteAdapter",
    "ResolvedArtifact",
]
