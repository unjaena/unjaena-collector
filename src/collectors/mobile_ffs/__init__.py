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
from .format_detector import (
    FormatDetection,
    FormatID,
    HIGH_CONFIDENCE,
    LOW_CONFIDENCE,
    MEDIUM_CONFIDENCE,
    detect_zip_format,
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
]
