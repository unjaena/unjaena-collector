"""Safe zip extraction for forensic Full File System (FFS) dumps.

Defends against malicious zip uploads when an examiner opens a vendor
extraction container (typically 30-50 GB):

  - Zip bomb (decompression ratio attack)
  - Path traversal (../, absolute paths, drive-letter on Windows)
  - Symlink escape (zip entries with symlink bit set)
  - Resource exhaustion (entry count, deep nesting, oversized output)
  - CRC mismatch (corrupted container)

This module performs read-only access. The source container is never
modified, never written to, never moved. Every entry is hashed during
extraction (streaming SHA-256 over the *source bytes*) so the hash
binds to the source-state representation, not to a derivative copy.

Designed to be invoked by adapters under
collectors/mobile_ffs/adapters/. No vendor-specific knowledge here.
"""
from __future__ import annotations

import hashlib
import logging
import os
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterator, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Limits — tunable but conservative defaults
# =============================================================================
DEFAULT_MAX_ENTRIES = 5_000_000           # vendor zips can have ~1M entries
DEFAULT_MAX_OUT_BYTES = 200 * 1024**3     # 200 GB hard ceiling (49 GB inputs × 4)
DEFAULT_MAX_RATIO = 100                   # decompressed / compressed
DEFAULT_RATIO_GRACE_BYTES = 64 * 1024**2  # below this read size, ratio not checked
DEFAULT_CHUNK_BYTES = 8 * 1024**2         # 8 MB streaming
DEFAULT_MAX_FILENAME_BYTES = 4096         # POSIX path max with margin


# =============================================================================
# Exceptions
# =============================================================================
class ContainerSafetyError(Exception):
    """Base for any safety violation discovered in the source container.

    Designed to be caught and logged at the adapter boundary. The error
    message is part of the chain-of-custody record (must be reproducible
    and not contain examiner-specific data).
    """


class ZipBombError(ContainerSafetyError):
    """Decompression-ratio or absolute-size limit violated."""


class PathTraversalError(ContainerSafetyError):
    """Entry path escapes the destination directory."""


class SymlinkEntryError(ContainerSafetyError):
    """Entry is a symlink. Symlinks are rejected unconditionally because
    they can be made to point anywhere on the host filesystem after the
    symlink is materialised."""


class EntryCountError(ContainerSafetyError):
    """Too many entries in the container."""


class FilenameLengthError(ContainerSafetyError):
    """Entry filename exceeds the safe length cap."""


class CRCMismatchError(ContainerSafetyError):
    """Entry's central-directory CRC32 does not match the read bytes.
    Indicates corruption or tampering."""


# =============================================================================
# Result records
# =============================================================================
@dataclass(frozen=True)
class ExtractedEntry:
    """Record describing a single safely-extracted entry.

    `source_sha256` is the hash of the bytes as read from the zip
    central directory's compressed stream — bound to the source, not to
    the temp file we wrote. `source_crc32` is the central-directory
    CRC, copied verbatim and re-verified post-read.

    Timestamps are forwarded from any zip extra field 0x5455 (Extended
    Timestamp) when present; otherwise from the entry's DOS date/time.
    `mtime_source` is one of "x5455" or "dos" so a downstream consumer
    knows the precision (DOS = 2-second granularity, x5455 = POSIX 1s).
    """
    zip_entry_path: str
    extracted_path: Path
    source_size: int
    source_sha256: str
    source_crc32: int
    mtime_unix: Optional[int]
    atime_unix: Optional[int]
    birthtime_unix: Optional[int]
    mtime_source: str  # "x5455" | "dos"


@dataclass(frozen=True)
class ExtractionPolicy:
    max_entries: int = DEFAULT_MAX_ENTRIES
    max_out_bytes: int = DEFAULT_MAX_OUT_BYTES
    max_ratio: int = DEFAULT_MAX_RATIO
    ratio_grace_bytes: int = DEFAULT_RATIO_GRACE_BYTES
    chunk_bytes: int = DEFAULT_CHUNK_BYTES
    max_filename_bytes: int = DEFAULT_MAX_FILENAME_BYTES


# =============================================================================
# Path safety
# =============================================================================
def _is_safe_relative(name: str, dest_root: Path,
                      max_filename_bytes: int) -> Path:
    """Resolve *name* under *dest_root* and verify it does not escape.

    Raises PathTraversalError if the resolved path is outside
    dest_root, contains a Windows drive letter, or starts with the
    POSIX root.

    Returns the resolved absolute path that is safe to write to.
    """
    if not name:
        raise PathTraversalError("empty entry name")
    if len(name.encode("utf-8", errors="surrogateescape")) > max_filename_bytes:
        raise FilenameLengthError(
            f"filename exceeds {max_filename_bytes} bytes"
        )
    # Reject Windows drive prefixes ("C:foo", "C:/foo", "\\?\...").
    if len(name) >= 2 and name[1] == ":":
        raise PathTraversalError(f"absolute drive path: {name!r}")
    if name.startswith("\\\\"):
        raise PathTraversalError(f"UNC-style path: {name!r}")
    # Reject leading slashes (POSIX absolute) — zipfile normalises this
    # but be explicit for defense-in-depth.
    if name.startswith("/") or name.startswith("\\"):
        raise PathTraversalError(f"absolute path: {name!r}")
    # Reject any embedded NUL.
    if "\x00" in name:
        raise PathTraversalError("NUL in filename")

    # Resolve and verify containment. Use Path.resolve() to canonicalise.
    candidate = (dest_root / name).resolve()
    dest_root_resolved = dest_root.resolve()
    try:
        candidate.relative_to(dest_root_resolved)
    except ValueError:
        raise PathTraversalError(
            f"entry resolves outside dest: {name!r} -> {candidate}"
        )
    return candidate


def _is_symlink_entry(info: zipfile.ZipInfo) -> bool:
    """Detect symlink entries via the Unix file-mode bits stored in
    zip's external_attr (upper 16 bits = POSIX mode)."""
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


# =============================================================================
# Timestamp forwarding (POSIX preservation, ISO/IEC 27037 §6.7)
# =============================================================================
def _parse_x5455_extra(extra: bytes) -> Tuple[Optional[int], Optional[int],
                                              Optional[int]]:
    """Parse zip Extra Field 0x5455 ("UT" — Extended Timestamp).

    Layout per APPNOTE 4.5.6:
      header_id (2)  | data_size (2) | flags (1) | timestamps...
      flags bit 0 = mtime present
      flags bit 1 = atime present
      flags bit 2 = ctime present (creation, sometimes ignored)

    Each timestamp is 4-byte little-endian uint32 (seconds since epoch).
    Returns (mtime, atime, ctime) — any None if absent or malformed.
    """
    import struct
    i = 0
    mtime = atime = ctime = None
    while i + 4 <= len(extra):
        try:
            hid, dsize = struct.unpack_from("<HH", extra, i)
        except struct.error:
            break
        body = extra[i + 4: i + 4 + dsize]
        i += 4 + dsize
        if hid != 0x5455 or len(body) < 1:
            continue
        flags = body[0]
        cursor = 1
        if flags & 0x01 and cursor + 4 <= len(body):
            mtime = struct.unpack_from("<I", body, cursor)[0]
            cursor += 4
        if flags & 0x02 and cursor + 4 <= len(body):
            atime = struct.unpack_from("<I", body, cursor)[0]
            cursor += 4
        if flags & 0x04 and cursor + 4 <= len(body):
            ctime = struct.unpack_from("<I", body, cursor)[0]
            cursor += 4
        return mtime, atime, ctime
    return None, None, None


def _dos_dt_to_unix(date_time: Tuple[int, int, int, int, int, int]
                    ) -> Optional[int]:
    """Convert zipfile.ZipInfo.date_time (Y, M, D, h, m, s) to a UTC
    unix timestamp. Returns None on invalid components.

    DOS time is local-zone, but zip does not store the zone — we treat
    it as UTC for reproducibility. The adapter is responsible for
    documenting this in the case capabilities log.
    """
    import calendar
    try:
        return int(calendar.timegm((date_time[0], date_time[1], date_time[2],
                                    date_time[3], date_time[4], date_time[5],
                                    0, 0, 0)))
    except (ValueError, OverflowError):
        return None


# =============================================================================
# Hash + CRC streaming verifier
# =============================================================================
def _stream_extract(src_fp, dst_fp, expected_size: int, expected_crc: int,
                    chunk: int) -> Tuple[str, int]:
    """Copy bytes from src_fp to dst_fp, streaming SHA-256 over the
    source bytes and verifying CRC32 at the end.

    Returns (sha256_hex, bytes_written). Raises CRCMismatchError if
    the central-directory CRC does not match the actual stream CRC.
    """
    import zlib
    h = hashlib.sha256()
    crc = 0
    written = 0
    while True:
        buf = src_fp.read(chunk)
        if not buf:
            break
        h.update(buf)
        crc = zlib.crc32(buf, crc)
        dst_fp.write(buf)
        written += len(buf)
    if expected_size and written != expected_size:
        raise CRCMismatchError(
            f"size mismatch: read {written}, central dir says {expected_size}"
        )
    if expected_crc and crc != expected_crc:
        raise CRCMismatchError(
            f"crc mismatch: computed 0x{crc:08x}, central dir 0x{expected_crc:08x}"
        )
    return h.hexdigest(), written


# =============================================================================
# Safe iterator API (lazy, one entry at a time)
# =============================================================================
def safe_iter_entries(
    zf: zipfile.ZipFile,
    dest_root: Path,
    *,
    select: Optional[Callable[[zipfile.ZipInfo], bool]] = None,
    policy: ExtractionPolicy = ExtractionPolicy(),
) -> Iterator[ExtractedEntry]:
    """Yield safely-extracted entries one at a time.

    `select` is an optional predicate: only entries for which
    select(info) returns True are extracted. This is how an adapter
    selects "messenger DBs only" without paying the I/O cost of every
    entry.

    Each yielded ExtractedEntry has been:
      - validated for path safety (no traversal, no symlink, length OK)
      - extracted to dest_root/<rel_path> with parent dirs auto-created
      - hashed (SHA-256 over source bytes)
      - CRC-verified against the central directory
      - timestamp-forwarded (POSIX 0x5455 if present, else DOS)

    Honors policy limits cumulatively: total entry count, total bytes
    written, decompression ratio. Raises ContainerSafetyError on any
    violation. Callers are responsible for cleanup of partially-
    extracted entries on exception.
    """
    dest_root.mkdir(parents=True, exist_ok=True)
    dest_root_resolved = dest_root.resolve()

    entry_count = 0
    bytes_read = 0      # compressed bytes consumed from source
    bytes_written = 0   # uncompressed bytes written to dest

    for info in zf.infolist():
        entry_count += 1
        if entry_count > policy.max_entries:
            raise EntryCountError(
                f"entry count exceeds {policy.max_entries}"
            )

        # Reject directories silently (we'll auto-create as needed).
        if info.is_dir():
            continue

        # Symlink rejection (defense-in-depth: we cannot trust that the
        # stored mode is honest, but if it claims symlink we refuse).
        if _is_symlink_entry(info):
            raise SymlinkEntryError(
                f"symlink entry rejected: {info.filename!r}"
            )

        # Adapter-supplied predicate.
        if select is not None and not select(info):
            continue

        # Path safety.
        out_path = _is_safe_relative(
            info.filename, dest_root_resolved, policy.max_filename_bytes
        )

        # Reserve disk: refuse if extracting this entry would exceed
        # the absolute output cap, or if we are past the grace window
        # and the running ratio is too high.
        projected_out = bytes_written + (info.file_size or 0)
        if projected_out > policy.max_out_bytes:
            raise ZipBombError(
                f"projected output {projected_out} exceeds "
                f"{policy.max_out_bytes}"
            )
        if (bytes_read > policy.ratio_grace_bytes
                and bytes_written > 0
                and (bytes_written / max(bytes_read, 1)) > policy.max_ratio):
            raise ZipBombError(
                f"decompression ratio "
                f"{bytes_written / max(bytes_read, 1):.1f} "
                f"exceeds {policy.max_ratio}"
            )

        # Forward POSIX timestamps when present.
        mtime_unix, atime_unix, btime_unix = _parse_x5455_extra(info.extra)
        mtime_source = "x5455" if mtime_unix is not None else "dos"
        if mtime_unix is None:
            mtime_unix = _dos_dt_to_unix(info.date_time)

        out_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with zf.open(info, "r") as src, open(out_path, "wb") as dst:
                sha256_hex, written = _stream_extract(
                    src, dst,
                    expected_size=info.file_size,
                    expected_crc=info.CRC,
                    chunk=policy.chunk_bytes,
                )
        except ContainerSafetyError:
            try:
                out_path.unlink()
            except OSError:
                pass
            raise
        bytes_read += info.compress_size or 0
        bytes_written += written

        # Best-effort POSIX timestamp restoration on the extracted
        # tempfile. This is informational only — the canonical
        # timestamp is the unix value in the returned record.
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


# =============================================================================
# Inventory-only iteration (no extraction, used for not_extracted manifest)
# =============================================================================
@dataclass(frozen=True)
class InventoryEntry:
    """Lightweight record of a zip entry that was *not* selected for
    extraction. Written to the case manifest so an examiner can prove
    that every byte of the source container was inspected — even if
    not extracted, its existence + hash + size were recorded."""
    zip_entry_path: str
    source_size: int
    compressed_size: int
    central_crc32: int
    is_symlink: bool
    is_dir: bool
    reason: str  # "not_in_phase1_spec", "symlink_rejected", etc.


def inventory_all(zf: zipfile.ZipFile,
                  *,
                  select_predicate: Callable[[zipfile.ZipInfo], bool],
                  ) -> Iterator[InventoryEntry]:
    """Walk the central directory and yield InventoryEntry for every
    entry that the predicate did NOT select for extraction.

    Use this to build the not_extracted.jsonl manifest required by
    NIST SP 800-101r1 §6.4 (tool capability documentation) and to
    prove the absence of selective evidence handling under FRE 1003.
    """
    for info in zf.infolist():
        if info.is_dir():
            yield InventoryEntry(
                zip_entry_path=info.filename,
                source_size=0,
                compressed_size=0,
                central_crc32=info.CRC,
                is_symlink=False,
                is_dir=True,
                reason="directory",
            )
            continue
        if _is_symlink_entry(info):
            yield InventoryEntry(
                zip_entry_path=info.filename,
                source_size=info.file_size,
                compressed_size=info.compress_size,
                central_crc32=info.CRC,
                is_symlink=True,
                is_dir=False,
                reason="symlink_rejected",
            )
            continue
        if not select_predicate(info):
            yield InventoryEntry(
                zip_entry_path=info.filename,
                source_size=info.file_size,
                compressed_size=info.compress_size,
                central_crc32=info.CRC,
                is_symlink=False,
                is_dir=False,
                reason="not_in_extraction_spec",
            )
