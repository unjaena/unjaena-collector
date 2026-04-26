"""Offline mobile forensic image (FFS dump) collector module.

Accepts vendor extraction containers (currently Cellebrite UFED zip
format) and exposes their contents through a uniform read-only view
so the existing artifact upload path can ingest them as if they were
a live device.

Phase 1A delivers safe container handling primitives. Layout adapters
and format detection arrive in Phase 1B and 1D.
"""
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
]
