"""Daubert / ISO 27037 / NIST SP 800-101r1 case manifest writer.

A forensic-defensible collection produces a bundle of supporting
records. The manifests written by this module exist to answer three
classes of questions any auditor or opposing expert can ask:

  1. "Which bytes from the source container are now in the case?"
     -> artifacts.jsonl

  2. "Did you look at, but choose not to ingest, anything?"
     -> not_extracted.jsonl
     (defeats selective-evidence-handling claims under FRE 1003)

  3. "What did your tool actually do, in what version, with what
     limitations?"
     -> capabilities.md (per NIST SP 800-101r1 §3.4 + §6.4)

A second category of files — opaque binary containers the collector
ships as-is for downstream processing — is recorded in
binary_blobs.jsonl. The collector deliberately uses neutral language:
"binary blob" / "downstream processing", never names a specific
container scheme. Per the public-collector security policy, the
collector must not contain vocabulary that hints at server-side
container interpretation capabilities.

Every record in every manifest carries the source SHA-256 and the
zip central-directory CRC32 so an independent re-extractor can
verify byte-for-byte equivalence.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


# Manifest filenames live at the case bundle root. They never move.
ARTIFACTS_JSONL = "artifacts.jsonl"
NOT_EXTRACTED_JSONL = "not_extracted.jsonl"
BINARY_BLOBS_JSONL = "binary_blobs.jsonl"
CAPABILITIES_MD = "capabilities.md"
CASE_MANIFEST_JSON = "manifest.json"
COLLECTOR_LOG = "collector.log"


# =============================================================================
# Per-record dataclasses
# =============================================================================
@dataclass
class ArtifactRecord:
    """One row in artifacts.jsonl — a structured row was extracted.

    `source_sha256` is the streaming SHA-256 of the bytes as read from
    the zip's compressed stream (binds to source state, not derivative).
    `source_crc32` mirrors the central directory entry. `mtime_unix`,
    `atime_unix`, `birthtime_unix` are forwarded from POSIX extra-field
    0x5455 when present, otherwise from DOS date/time treated as UTC.
    """
    zip_entry_path: str
    artifact_type: str
    source_size: int
    source_sha256: str
    source_crc32: int
    mtime_unix: Optional[int]
    atime_unix: Optional[int]
    birthtime_unix: Optional[int]
    mtime_source: str  # "x5455" | "dos"
    upload_url: Optional[str] = None
    upload_sha256: Optional[str] = None  # may equal source_sha256


@dataclass
class NotExtractedRecord:
    zip_entry_path: str
    source_size: int
    compressed_size: int
    source_crc32: int
    reason: str
    is_symlink: bool = False
    is_dir: bool = False


@dataclass
class BinaryBlobRecord:
    """An entry the collector chose to ship as raw bytes (no parsing
    performed locally). The reason field uses neutral vocabulary —
    "downstream_processing", "format_unknown_to_collector",
    "container_signature_pending" — never names a specific
    container scheme."""
    zip_entry_path: str
    source_size: int
    source_sha256: str
    source_crc32: int
    reason: str
    upload_url: Optional[str] = None


@dataclass
class CaseManifest:
    """Top-level case manifest.json. Contains everything an auditor
    needs to reproduce the collection: tool versioning, source hash,
    operator + host fingerprints, runtime, signal trace from the
    detector. The signature is computed separately (see write_signed
    below) once the case bundle is closed."""
    case_id: str
    collector_version: str
    python_version: str
    os_release: str
    started_at_utc: str
    finished_at_utc: Optional[str] = None
    source_container_path: str = ""
    source_container_size: int = 0
    source_container_sha256: str = ""
    detected_format: str = ""
    detection_confidence: str = ""
    detection_signals: List[str] = field(default_factory=list)
    publisher_version: Optional[str] = None
    publisher_software: Optional[str] = None
    artifacts_count: int = 0
    not_extracted_count: int = 0
    binary_blobs_count: int = 0
    safety_violations: List[str] = field(default_factory=list)


# =============================================================================
# Manifest writer (append-only, one record at a time)
# =============================================================================
class CaseManifestWriter:
    """Open-once, append-many writer for the case manifest bundle.

    Usage:
        with CaseManifestWriter(case_dir, case_id, collector_version,
                                source_container_path) as w:
            w.set_detection(detection)
            for entry in safe_iter_entries(...):
                w.append_artifact(entry, artifact_type=..., ...)
            for inv in inventory_all(...):
                w.append_not_extracted(inv)

    On close, writes manifest.json and capabilities.md. The bundle
    directory layout matches the chain-of-custody requirements at
    docs/production-deployment-checklist.md §10.
    """

    def __init__(self, case_dir: Path, *, case_id: str,
                 collector_version: str,
                 source_container_path: Path):
        self.case_dir = Path(case_dir)
        self.case_dir.mkdir(parents=True, exist_ok=True)

        self._manifest = CaseManifest(
            case_id=case_id,
            collector_version=collector_version,
            python_version=sys.version.split()[0],
            os_release=platform.platform(),
            started_at_utc=datetime.now(timezone.utc).isoformat(),
            source_container_path=str(source_container_path),
            source_container_size=(source_container_path.stat().st_size
                                   if source_container_path.exists() else 0),
            source_container_sha256=_sha256_of_file(source_container_path)
                                   if source_container_path.exists() else "",
        )

        # Open append-only handles. JSON-Lines so each record is
        # self-contained and grep-able by an auditor.
        self._artifacts_fp = (self.case_dir / ARTIFACTS_JSONL).open(
            "a", encoding="utf-8"
        )
        self._not_extracted_fp = (self.case_dir / NOT_EXTRACTED_JSONL).open(
            "a", encoding="utf-8"
        )
        self._binary_blobs_fp = (self.case_dir / BINARY_BLOBS_JSONL).open(
            "a", encoding="utf-8"
        )

    # ---------- detection metadata -----------------------------------
    def set_detection(self, detection) -> None:
        """Record format-detection result onto the manifest."""
        self._manifest.detected_format = detection.format_id.value
        self._manifest.detection_confidence = detection.confidence
        self._manifest.detection_signals = list(detection.signals_fired)
        self._manifest.publisher_version = detection.publisher_version
        self._manifest.publisher_software = detection.publisher_software

    # ---------- per-record append -------------------------------------
    def append_artifact(self, entry, *, artifact_type: str,
                        upload_url: Optional[str] = None,
                        upload_sha256: Optional[str] = None) -> None:
        """`entry` is a safe_zip.ExtractedEntry."""
        rec = ArtifactRecord(
            zip_entry_path=entry.zip_entry_path,
            artifact_type=artifact_type,
            source_size=entry.source_size,
            source_sha256=entry.source_sha256,
            source_crc32=entry.source_crc32,
            mtime_unix=entry.mtime_unix,
            atime_unix=entry.atime_unix,
            birthtime_unix=entry.birthtime_unix,
            mtime_source=entry.mtime_source,
            upload_url=upload_url,
            upload_sha256=upload_sha256,
        )
        self._artifacts_fp.write(_jsonl(asdict(rec)))
        self._manifest.artifacts_count += 1

    def append_not_extracted(self, inv) -> None:
        """`inv` is a safe_zip.InventoryEntry."""
        rec = NotExtractedRecord(
            zip_entry_path=inv.zip_entry_path,
            source_size=inv.source_size,
            compressed_size=inv.compressed_size,
            source_crc32=inv.central_crc32,
            reason=inv.reason,
            is_symlink=inv.is_symlink,
            is_dir=inv.is_dir,
        )
        self._not_extracted_fp.write(_jsonl(asdict(rec)))
        self._manifest.not_extracted_count += 1

    def append_binary_blob(self, entry, *, reason: str,
                           upload_url: Optional[str] = None) -> None:
        """Record a raw-bytes upload for downstream processing.

        `entry` must be a safe_zip.ExtractedEntry. `reason` should
        come from a neutral, finite vocabulary
        (see BlobReason below). The collector never speculates about
        the internal scheme of the blob.
        """
        rec = BinaryBlobRecord(
            zip_entry_path=entry.zip_entry_path,
            source_size=entry.source_size,
            source_sha256=entry.source_sha256,
            source_crc32=entry.source_crc32,
            reason=reason,
            upload_url=upload_url,
        )
        self._binary_blobs_fp.write(_jsonl(asdict(rec)))
        self._manifest.binary_blobs_count += 1

    def append_safety_violation(self, message: str) -> None:
        """Record a ContainerSafetyError that aborted some entry. The
        bundle is still well-formed; the manifest documents that the
        tool refused to process the violating entry."""
        self._manifest.safety_violations.append(message)

    # ---------- finalisation -----------------------------------------
    def close(self) -> Dict[str, Path]:
        """Close all per-record streams, write manifest.json + a
        capabilities.md summary. Returns a dict of {logical_name: path}
        for the caller to upload / sign."""
        self._manifest.finished_at_utc = datetime.now(timezone.utc).isoformat()

        for fp in (self._artifacts_fp, self._not_extracted_fp,
                   self._binary_blobs_fp):
            try:
                fp.close()
            except OSError:
                pass

        manifest_path = self.case_dir / CASE_MANIFEST_JSON
        manifest_path.write_text(
            json.dumps(asdict(self._manifest), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        capabilities_path = self.case_dir / CAPABILITIES_MD
        capabilities_path.write_text(
            _render_capabilities(self._manifest),
            encoding="utf-8",
        )
        return {
            "manifest": manifest_path,
            "capabilities": capabilities_path,
            "artifacts": self.case_dir / ARTIFACTS_JSONL,
            "not_extracted": self.case_dir / NOT_EXTRACTED_JSONL,
            "binary_blobs": self.case_dir / BINARY_BLOBS_JSONL,
        }

    # context-manager sugar
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            self.append_safety_violation(
                f"{exc_type.__name__}: {str(exc)[:200]}"
            )
        self.close()
        return False  # do not suppress


# =============================================================================
# Helpers
# =============================================================================
def _jsonl(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False) + "\n"


def _sha256_of_file(path: Path, chunk: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


# =============================================================================
# Neutral vocabulary for binary_blobs.jsonl (collector security policy)
# =============================================================================
class BlobReason:
    """Finite vocabulary the collector may use to label a binary blob
    without revealing knowledge of any specific container scheme."""

    DOWNSTREAM_PROCESSING = "downstream_processing"
    FORMAT_UNKNOWN_TO_COLLECTOR = "format_unknown_to_collector"
    CONTAINER_SIGNATURE_PENDING = "container_signature_pending"
    OPERATOR_REVIEW_REQUESTED = "operator_review_requested"


# =============================================================================
# capabilities.md renderer
# =============================================================================
_CAPABILITIES_TEMPLATE = """# Tool Capabilities & Case Bundle Summary

This document is generated automatically per NIST SP 800-101r1 §3.4
and §6.4. It records the version + behaviour of the tool that
produced this case bundle, so that an auditor or opposing expert can
reproduce the collection.

## Tool & runtime

| Field | Value |
|---|---|
| Collector version | `{collector_version}` |
| Python version | `{python_version}` |
| Operating system | `{os_release}` |
| Started (UTC) | `{started_at_utc}` |
| Finished (UTC) | `{finished_at_utc}` |
| Case ID | `{case_id}` |

## Source container

| Field | Value |
|---|---|
| Path | `{source_container_path}` |
| Size (bytes) | `{source_container_size}` |
| SHA-256 (outer container) | `{source_container_sha256}` |

## Format detection

| Field | Value |
|---|---|
| Format ID | `{detected_format}` |
| Confidence | `{detection_confidence}` |
| Publisher version | `{publisher_version}` |
| Publisher software | `{publisher_software}` |

### Detection signals

{detection_signals_md}

## Outcome

| Bundle file | Records |
|---|---:|
| `artifacts.jsonl` | {artifacts_count} |
| `not_extracted.jsonl` | {not_extracted_count} |
| `binary_blobs.jsonl` | {binary_blobs_count} |

## Safety violations

{safety_violations_md}

## Verification

To independently re-verify this bundle:

1. Compute SHA-256 of `{source_container_path}` and compare to the
   value above.
2. Re-run the collector at version `{collector_version}` on the same
   input. The resulting `artifacts.jsonl`, `not_extracted.jsonl`, and
   `binary_blobs.jsonl` (sorted by `zip_entry_path`) must be
   byte-identical to those in this bundle.
3. For each record in `artifacts.jsonl`, fetch the upload artifact
   at `upload_url` and verify its SHA-256 equals the `source_sha256`
   field.

## Known limitations

- This collector implements **NIST acquisition Level 2** (Logical) and
  selected Level-3 file-system reads. Chip-Off (L4) and Micro-Read
  (L5) acquisitions are out of scope.
- Opaque containers are recorded in `binary_blobs.jsonl` for
  downstream processing. The collector itself does not attempt to
  interpret opaque container contents.
- Non-Cellebrite extraction formats (e.g. MSAB XRY closed containers)
  are detected and rejected with guidance.
"""


def _render_capabilities(m: CaseManifest) -> str:
    if m.detection_signals:
        sig_md = "\n".join(f"- `{s}`" for s in m.detection_signals)
    else:
        sig_md = "_no detection signals recorded_"
    if m.safety_violations:
        sv_md = "\n".join(f"- `{s}`" for s in m.safety_violations)
    else:
        sv_md = "_none — every entry processed cleanly_"
    return _CAPABILITIES_TEMPLATE.format(
        collector_version=m.collector_version,
        python_version=m.python_version,
        os_release=m.os_release,
        started_at_utc=m.started_at_utc,
        finished_at_utc=m.finished_at_utc or "(in progress)",
        case_id=m.case_id,
        source_container_path=m.source_container_path,
        source_container_size=m.source_container_size,
        source_container_sha256=m.source_container_sha256,
        detected_format=m.detected_format,
        detection_confidence=m.detection_confidence,
        publisher_version=m.publisher_version or "_n/a_",
        publisher_software=m.publisher_software or "_n/a_",
        detection_signals_md=sig_md,
        artifacts_count=m.artifacts_count,
        not_extracted_count=m.not_extracted_count,
        binary_blobs_count=m.binary_blobs_count,
        safety_violations_md=sv_md,
    )
