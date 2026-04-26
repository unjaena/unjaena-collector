"""iOS Cellebrite FFS UUID → bundle-id resolver.

iOS stores per-app data in directories whose names are random UUIDs:

  filesystem1/private/var/mobile/Containers/Data/Application/<UUID>/
  filesystem1/private/var/mobile/Containers/Shared/AppGroup/<UUID>/
  filesystem1/private/var/containers/Bundle/Application/<UUID>/

To find an app's data path inside an FFS dump, we must walk the
container metadata sidecar that Apple writes inside each UUID
directory:

  .com.apple.mobile_container_manager.metadata.plist

That plist (binary plist format) contains an `MCMMetadataIdentifier`
key whose value is the app's bundle identifier (e.g.
`net.whatsapp.WhatsApp`).

This resolver does a single pass over the zip's central directory,
extracts each metadata plist into memory (each is small, ~1 KB),
parses with the stdlib `plistlib`, and returns three maps —
data UUID → bundle, app-group UUID → bundle, bundle UUID → bundle.

The resolver is read-only and pure: it touches only the zip's
central directory + the metadata plists themselves, never any
user data. Memory cost is bounded — there are typically hundreds
of UUIDs per device, not millions.
"""
from __future__ import annotations

import logging
import plistlib
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


METADATA_PLIST_BASENAME = ".com.apple.mobile_container_manager.metadata.plist"
MCM_BUNDLE_KEY = "MCMMetadataIdentifier"


# Container-kind path prefixes inside a Cellebrite iOS FFS zip
DATA_CONTAINER_PREFIX = (
    "filesystem1/private/var/mobile/Containers/Data/Application/"
)
APP_GROUP_CONTAINER_PREFIX = (
    "filesystem1/private/var/mobile/Containers/Shared/AppGroup/"
)
BUNDLE_CONTAINER_PREFIX = (
    "filesystem1/private/var/containers/Bundle/Application/"
)


@dataclass
class UUIDMapping:
    """Resolved maps + diagnostic counters. The unresolved lists carry
    UUID directories whose metadata plist was missing or unparseable —
    the case manifest records them so an examiner can investigate."""
    data: Dict[str, str] = field(default_factory=dict)
    app_group: Dict[str, str] = field(default_factory=dict)
    bundle: Dict[str, str] = field(default_factory=dict)
    unresolved_data: List[str] = field(default_factory=list)
    unresolved_app_group: List[str] = field(default_factory=list)
    unresolved_bundle: List[str] = field(default_factory=list)

    def by_bundle_data(self, bundle_id: str) -> Optional[str]:
        """Return the data-container UUID for a given bundle id, or None."""
        for uuid, bid in self.data.items():
            if bid == bundle_id:
                return uuid
        return None

    def by_bundle_group(self, bundle_id: str) -> Optional[str]:
        for uuid, bid in self.app_group.items():
            if bid == bundle_id:
                return uuid
        return None

    def by_bundle_app(self, bundle_id: str) -> Optional[str]:
        for uuid, bid in self.bundle.items():
            if bid == bundle_id:
                return uuid
        return None

    def summary_counts(self) -> Dict[str, int]:
        return {
            "data_resolved": len(self.data),
            "app_group_resolved": len(self.app_group),
            "bundle_resolved": len(self.bundle),
            "data_unresolved": len(self.unresolved_data),
            "app_group_unresolved": len(self.unresolved_app_group),
            "bundle_unresolved": len(self.unresolved_bundle),
        }


def _classify(zip_entry_path: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (kind, uuid) for a zip entry path that lives directly
    under one of the three container prefixes. Returns (None, None)
    if the entry is not directly under such a prefix or if it isn't
    the metadata plist itself.

    Only entries ending in METADATA_PLIST_BASENAME are considered —
    we don't open every file in every UUID dir.
    """
    if not zip_entry_path.endswith(METADATA_PLIST_BASENAME):
        return None, None

    for kind, prefix in (
        ("data", DATA_CONTAINER_PREFIX),
        ("app_group", APP_GROUP_CONTAINER_PREFIX),
        ("bundle", BUNDLE_CONTAINER_PREFIX),
    ):
        if zip_entry_path.startswith(prefix):
            rest = zip_entry_path[len(prefix):]
            # Expect "<UUID>/<basename>"
            parts = rest.split("/", 1)
            if len(parts) == 2 and parts[1] == METADATA_PLIST_BASENAME:
                return kind, parts[0]
    return None, None


def _parse_bundle_id(plist_bytes: bytes) -> Optional[str]:
    """Extract MCMMetadataIdentifier from a metadata plist. Tolerates
    binary or XML plist. Returns None on parse failure or when the
    expected key is missing."""
    try:
        d = plistlib.loads(plist_bytes)
    except (plistlib.InvalidFileException, ValueError, TypeError):
        return None
    if not isinstance(d, dict):
        return None
    val = d.get(MCM_BUNDLE_KEY)
    if isinstance(val, str) and val:
        return val
    return None


def build_uuid_map(zf: zipfile.ZipFile) -> UUIDMapping:
    """Single-pass resolution of every per-app container UUID found
    in the zip's central directory.

    Memory bound: even on a phone with 500 installed apps + share
    extensions there are typically <2000 UUID directories combined.
    Each metadata plist is ~1 KB so total transient memory < 2 MB.
    """
    mapping = UUIDMapping()

    # Pass 1 — find every metadata plist entry and read it
    for info in zf.infolist():
        kind, uuid = _classify(info.filename)
        if kind is None or uuid is None:
            continue
        try:
            body = zf.read(info)
        except (zipfile.BadZipFile, RuntimeError):
            _record_unresolved(mapping, kind, uuid)
            continue
        bundle = _parse_bundle_id(body)
        if bundle is None:
            _record_unresolved(mapping, kind, uuid)
            continue
        getattr(mapping, kind)[uuid] = bundle

    return mapping


def _record_unresolved(mapping: UUIDMapping, kind: str, uuid: str) -> None:
    if kind == "data":
        mapping.unresolved_data.append(uuid)
    elif kind == "app_group":
        mapping.unresolved_app_group.append(uuid)
    elif kind == "bundle":
        mapping.unresolved_bundle.append(uuid)


def resolve_app_path(uuid_map: UUIDMapping, *, bundle_id: str,
                     container_kind: str, relative_path: str) -> Optional[str]:
    """Compose an absolute zip-entry path for an app artifact spec.

    container_kind: "app_data" | "app_group" | "app_bundle"
    bundle_id:      the spec's bundle identifier
    relative_path:  the spec's path under the per-app container

    Returns None if the bundle id was not found in the requested kind.
    """
    if container_kind == "app_data":
        uuid = uuid_map.by_bundle_data(bundle_id)
        prefix = DATA_CONTAINER_PREFIX
    elif container_kind == "app_group":
        uuid = uuid_map.by_bundle_group(bundle_id)
        prefix = APP_GROUP_CONTAINER_PREFIX
    elif container_kind == "app_bundle":
        uuid = uuid_map.by_bundle_app(bundle_id)
        prefix = BUNDLE_CONTAINER_PREFIX
    else:
        return None
    if uuid is None:
        return None
    return f"{prefix}{uuid}/{relative_path}"
