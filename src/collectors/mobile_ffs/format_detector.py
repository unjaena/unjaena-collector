"""Detect the publisher / layout of an offline mobile forensic image
(FFS dump) container.

Strategy is layered. Publisher signals (version file, metadata sidecar)
are consulted first because they are the authoritative declaration by
the extraction tool. When the publisher did not write a manifest into
the container, the detector falls back to a deterministic layout
heuristic over the zip central directory.

This split addresses the peer-review concern that custom layout
heuristics alone are brittle and Daubert-attackable: when the
publisher tells us what they wrote, we trust them; we only guess when
they were silent.

Returned `FormatDetection` is verbose by design — the case manifest
records every signal that fired, so an auditor can reproduce the
decision later.
"""
from __future__ import annotations

import logging
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# How many entries from the central directory the heuristic samples
# when no publisher signal is present. Bounded so a 30 GB zip with
# millions of entries doesn't read all of them just to detect format.
HEURISTIC_SAMPLE_LIMIT = 2000


class FormatID(Enum):
    """Stable identifiers for supported (and unsupported) container
    formats. New entries are appended only — never renumbered, never
    renamed, because the case manifest records this enum value as
    part of the chain-of-custody."""

    UNKNOWN = "unknown"
    CELLEBRITE_CLBX_IOS = "cellebrite_clbx_ios"
    CELLEBRITE_CLBX_ANDROID = "cellebrite_clbx_android"
    CELLEBRITE_LEGACY_DAR = "cellebrite_legacy_dar"
    CELLEBRITE_UFDR = "cellebrite_ufdr"
    GRAYKEY_OUTPUT = "graykey_output"
    MAGNET_AXIOM_PORTABLE = "magnet_axiom_portable"
    OXYGEN_OFB = "oxygen_ofb"
    MSAB_XRY = "msab_xry"
    ITUNES_BACKUP_DIR = "itunes_backup_dir"
    GENERIC_ZIP = "generic_zip"


# Confidence levels recorded with each detection. Daubert: an
# operator can sort "high confidence" cases from "guess" cases and
# manually confirm the latter before processing.
HIGH_CONFIDENCE = "high"
MEDIUM_CONFIDENCE = "medium"
LOW_CONFIDENCE = "low"


@dataclass(frozen=True)
class FormatDetection:
    """Result of running detect_zip_format against a container.

    `format_id` is the canonical identifier. `confidence` records how
    sure the detector is. `signals_fired` is the human-readable list
    of evidence the detector relied on — every entry must be
    independently reproducible by an auditor (filename + content
    snippet, never a heuristic vote count).
    """
    format_id: FormatID
    confidence: str
    signals_fired: List[str] = field(default_factory=list)
    publisher_version: Optional[str] = None
    publisher_software: Optional[str] = None  # e.g. "UFED 10.2.0.359"
    extra: Dict[str, str] = field(default_factory=dict)


# =============================================================================
# Publisher-signal probes (ordered by reliability, most-trusted first)
# =============================================================================
def _probe_version_file(zf: zipfile.ZipFile) -> Optional[Tuple[str, str]]:
    """Cellebrite CLBX containers ship a small text file at the zip
    root literally named `version` whose contents look like
    `CLBX-0.3.1`.

    Returns (raw_version_string, format_family) or None.
    """
    if "version" not in zf.namelist():
        return None
    try:
        body = zf.read("version")
    except (zipfile.BadZipFile, KeyError, RuntimeError):
        return None
    if not body or len(body) > 1024:
        return None
    text = body.decode("utf-8", errors="replace").strip()
    if text.upper().startswith("CLBX-"):
        return (text, "clbx")
    return None


def _probe_log_txt(zf: zipfile.ZipFile) -> Optional[str]:
    """`Log.txt` at zip root, UTF-16 LE encoded, contains
    `UFED version: <version>` on an early line."""
    if "Log.txt" not in zf.namelist():
        return None
    try:
        raw = zf.read("Log.txt")
    except (zipfile.BadZipFile, KeyError, RuntimeError):
        return None
    if len(raw) < 4:
        return None
    # UTF-16 LE BOM check
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            text = raw[:4096].decode("utf-16", errors="replace")
        except UnicodeError:
            return None
    else:
        text = raw[:4096].decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("ufed version:"):
            return f"UFED {line.split(':', 1)[1].strip()}"
    return None


def _probe_metadata1_dir(zf: zipfile.ZipFile) -> bool:
    """Presence of `metadata1/*.msgpack` is a Cellebrite iOS CLBX
    indicator — Android CLBX dumps do not write this directory."""
    for name in zf.namelist()[:HEURISTIC_SAMPLE_LIMIT]:
        if name.startswith("metadata1/") and name.endswith(".msgpack"):
            return True
    return False


def _probe_ufdr_report_xml(zf: zipfile.ZipFile) -> bool:
    """UFDR (Cellebrite Reader) bundles a `report.xml` at the zip
    root and stores files under `files/` named by hash."""
    names = zf.namelist()[:HEURISTIC_SAMPLE_LIMIT]
    has_report = any(n.lower() == "report.xml" for n in names)
    has_hash_files = any(n.lower().startswith("files/") for n in names)
    return has_report and has_hash_files


# =============================================================================
# Layout heuristic (only consulted when publisher signals are silent)
# =============================================================================
_ANDROID_ROOT_PREFIXES = (
    "Dump/data/", "Dump/system/", "Dump/vendor/", "Dump/apex/",
    "Dump/product/", "Dump/system_ext/",
)
_IOS_ROOT_PREFIXES = (
    "filesystem1/private/var/mobile/", "filesystem1/private/var/",
    "filesystem1/System/", "filesystem1/Applications/",
    "filesystem1/Library/",
)


def _heuristic_layout(zf: zipfile.ZipFile) -> Tuple[Optional[FormatID],
                                                    List[str]]:
    """Sample the first HEURISTIC_SAMPLE_LIMIT entries and look for
    well-known root prefixes. Returns (format_id_or_None, signals).

    Signals returned are concrete entry names so an auditor can
    reproduce the decision. The Android `Dump/` and iOS
    `filesystem1/` prefixes are tested by the union of partition-
    level prefixes — a real extraction touches several partitions so
    a sampled window of 2000 entries reliably hits one of them.
    """
    signals: List[str] = []
    android_hit: Optional[str] = None
    ios_hit: Optional[str] = None
    for i, name in enumerate(zf.namelist()):
        if i >= HEURISTIC_SAMPLE_LIMIT:
            break
        if android_hit is None:
            for pre in _ANDROID_ROOT_PREFIXES:
                if name.startswith(pre):
                    android_hit = name
                    break
        if ios_hit is None:
            for pre in _IOS_ROOT_PREFIXES:
                if name.startswith(pre):
                    ios_hit = name
                    break
        if android_hit and ios_hit:
            break
    # Mixed result is a real signal — refuse to guess in that case.
    if android_hit and ios_hit:
        signals.append(
            f"heuristic: BOTH Dump/ and filesystem1/ prefixes seen "
            f"(android='{android_hit}', ios='{ios_hit}')"
        )
        return None, signals
    if android_hit:
        signals.append(f"heuristic: Dump/ prefix entries (e.g. {android_hit})")
        return FormatID.CELLEBRITE_CLBX_ANDROID, signals
    if ios_hit:
        signals.append(f"heuristic: filesystem1/ prefix entries (e.g. {ios_hit})")
        return FormatID.CELLEBRITE_CLBX_IOS, signals
    return None, signals


# =============================================================================
# Public API
# =============================================================================
def detect_zip_format(zip_path) -> FormatDetection:
    """Detect the format of *zip_path*. Returns FormatDetection with
    enough evidence to reproduce the decision.

    Always opens the zip read-only. Never modifies the source
    container.
    """
    signals: List[str] = []
    publisher_version: Optional[str] = None
    publisher_software: Optional[str] = None

    try:
        zf = zipfile.ZipFile(zip_path, "r")
    except zipfile.BadZipFile as e:
        return FormatDetection(
            format_id=FormatID.UNKNOWN,
            confidence=LOW_CONFIDENCE,
            signals_fired=[f"open_failed: {type(e).__name__}: {e}"],
        )
    try:
        # Pass 1 — publisher signals (high trust)
        v = _probe_version_file(zf)
        if v is not None:
            publisher_version = v[0]
            signals.append(f"version_file: {v[0]!r}")
        ufed_log = _probe_log_txt(zf)
        if ufed_log:
            publisher_software = ufed_log
            signals.append(f"Log.txt: {ufed_log!r}")
        has_metadata1 = _probe_metadata1_dir(zf)
        if has_metadata1:
            signals.append("metadata1/*.msgpack present")
        is_ufdr = _probe_ufdr_report_xml(zf)
        if is_ufdr:
            signals.append("report.xml + files/ (UFDR layout)")

        # Decision tree (publisher first)
        if is_ufdr:
            return FormatDetection(
                format_id=FormatID.CELLEBRITE_UFDR,
                confidence=HIGH_CONFIDENCE,
                signals_fired=signals,
                publisher_version=publisher_version,
                publisher_software=publisher_software,
            )
        if publisher_version and publisher_version.upper().startswith("CLBX-"):
            # CLBX is Cellebrite's published format. Tells us "this is
            # Cellebrite", but the iOS-vs-Android split needs a layout
            # signal (metadata1 → iOS; absence → Android in modern UFED).
            if has_metadata1:
                return FormatDetection(
                    format_id=FormatID.CELLEBRITE_CLBX_IOS,
                    confidence=HIGH_CONFIDENCE,
                    signals_fired=signals,
                    publisher_version=publisher_version,
                    publisher_software=publisher_software,
                )
            # CLBX without metadata1 — fall through to layout heuristic
            # to confirm Android vs another iOS extraction mode.
            heur_format, heur_signals = _heuristic_layout(zf)
            signals.extend(heur_signals)
            if heur_format is not None:
                return FormatDetection(
                    format_id=heur_format,
                    confidence=HIGH_CONFIDENCE,
                    signals_fired=signals,
                    publisher_version=publisher_version,
                    publisher_software=publisher_software,
                )
            return FormatDetection(
                format_id=FormatID.CELLEBRITE_CLBX_ANDROID,
                confidence=MEDIUM_CONFIDENCE,
                signals_fired=signals + ["no layout signals — defaulting to ANDROID"],
                publisher_version=publisher_version,
                publisher_software=publisher_software,
            )

        # Pass 2 — no publisher signal; layout heuristic only
        heur_format, heur_signals = _heuristic_layout(zf)
        signals.extend(heur_signals)
        if heur_format is not None:
            return FormatDetection(
                format_id=heur_format,
                # Without publisher signal, drop confidence one tier.
                confidence=MEDIUM_CONFIDENCE,
                signals_fired=signals,
                publisher_software=publisher_software,
            )

        # Last resort — generic zip we can't categorise
        return FormatDetection(
            format_id=FormatID.GENERIC_ZIP,
            confidence=LOW_CONFIDENCE,
            signals_fired=signals + ["no recognised layout"],
            publisher_software=publisher_software,
        )
    finally:
        zf.close()
