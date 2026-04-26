"""Adversarial test suite for safe_zip.py.

Each test crafts a hostile zip and asserts that our extractor refuses
it. These tests are part of the chain-of-custody record — they
demonstrate that the tool's safety behaviour is reproducible and that
known attack vectors are blocked before any source byte is processed
beyond the zip central directory.

Run:
  python -m pytest collector/src/collectors/mobile_ffs/test_safe_zip.py -v
or:
  python collector/src/collectors/mobile_ffs/test_safe_zip.py
"""
from __future__ import annotations

import io
import os
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

# Allow direct invocation without installing the package.
HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parent.parent.parent
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from collectors.mobile_ffs.safe_zip import (
    ContainerSafetyError,
    CRCMismatchError,
    EntryCountError,
    ExtractionPolicy,
    PathTraversalError,
    SymlinkEntryError,
    ZipBombError,
    inventory_all,
    safe_iter_entries,
)


def _build_zip(entries: list, *, symlinks: dict = None) -> bytes:
    """Assemble an in-memory zip from (name, payload) pairs.

    `symlinks` maps entry name -> True for entries that should have the
    POSIX symlink bit set in external_attr.
    """
    symlinks = symlinks or {}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if name in symlinks:
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            else:
                info.external_attr = 0o600 << 16
            zf.writestr(info, payload)
    return buf.getvalue()


class SafeZipAdversarial(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    # ---------------------------------------------------------------
    # T1 — Zip bomb
    # ---------------------------------------------------------------
    def test_zip_bomb_size_cap(self):
        """Output bytes cap kicks in on oversize entry."""
        big = b"A" * (2 * 1024 * 1024)  # 2 MB compressible payload
        data = _build_zip([("big.bin", big)])
        policy = ExtractionPolicy(max_out_bytes=1024)  # 1 KB cap
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            with self.assertRaises(ZipBombError):
                list(safe_iter_entries(zf, self.dest, policy=policy))

    def test_zip_bomb_ratio_cap(self):
        """Ratio cap fires once compressed bytes consumed exceed grace
        window. Use multiple high-compression entries so the cumulative
        bytes_read crosses the grace threshold and the ratio test
        applies."""
        # Each entry: 1 MB of zeros (compresses to ~1 KB).
        # 200 entries → bytes_read ~200 KB, bytes_written 200 MB,
        # ratio ~1000.
        entries = [(f"f{i}.bin", b"\x00" * (1 * 1024 * 1024))
                   for i in range(200)]
        data = _build_zip(entries)
        policy = ExtractionPolicy(
            max_out_bytes=300 * 1024 * 1024,
            max_ratio=10,
            ratio_grace_bytes=128 * 1024,  # 128 KB — trip after a few entries
        )
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            with self.assertRaises(ZipBombError):
                list(safe_iter_entries(zf, self.dest, policy=policy))

    # ---------------------------------------------------------------
    # T2 — Path traversal
    # ---------------------------------------------------------------
    def test_traversal_dotdot(self):
        data = _build_zip([("../escape.txt", b"x")])
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            with self.assertRaises(PathTraversalError):
                list(safe_iter_entries(zf, self.dest))

    def test_traversal_absolute_posix(self):
        data = _build_zip([("/etc/passwd", b"x")])
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            with self.assertRaises(PathTraversalError):
                list(safe_iter_entries(zf, self.dest))

    def test_traversal_drive_letter(self):
        data = _build_zip([("C:windows.txt", b"x")])
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            with self.assertRaises(PathTraversalError):
                list(safe_iter_entries(zf, self.dest))

    def test_traversal_unc(self):
        data = _build_zip([("\\\\server\\share\\f", b"x")])
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            with self.assertRaises(PathTraversalError):
                list(safe_iter_entries(zf, self.dest))

    def test_traversal_nul_at_helper(self):
        """Python's zipfile silently strips NUL from filenames at write
        time, so a NUL never reaches our extractor through the public
        API. The defense-in-depth NUL check is asserted directly on
        the helper to prove the rejection path exists if zipfile ever
        changes."""
        from collectors.mobile_ffs.safe_zip import _is_safe_relative
        with self.assertRaises(PathTraversalError):
            _is_safe_relative("evil\x00.txt", self.dest, max_filename_bytes=4096)

    # ---------------------------------------------------------------
    # T3 — Symlink rejection
    # ---------------------------------------------------------------
    def test_symlink_rejected(self):
        data = _build_zip(
            [("evil_link", b"/etc/shadow")],
            symlinks={"evil_link": True},
        )
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            with self.assertRaises(SymlinkEntryError):
                list(safe_iter_entries(zf, self.dest))

    # ---------------------------------------------------------------
    # T4 — Entry count cap
    # ---------------------------------------------------------------
    def test_entry_count_cap(self):
        entries = [(f"f{i}.txt", b"x") for i in range(100)]
        data = _build_zip(entries)
        policy = ExtractionPolicy(max_entries=50)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            with self.assertRaises(EntryCountError):
                list(safe_iter_entries(zf, self.dest, policy=policy))

    # ---------------------------------------------------------------
    # Filename length cap
    # ---------------------------------------------------------------
    def test_filename_length_cap(self):
        long_name = "a" * 5000 + ".txt"
        data = _build_zip([(long_name, b"x")])
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            with self.assertRaises(ContainerSafetyError):
                list(safe_iter_entries(zf, self.dest))

    # ---------------------------------------------------------------
    # Happy path — sane zip is extracted with hashes + timestamps
    # ---------------------------------------------------------------
    def test_happy_path_extraction(self):
        data = _build_zip([
            ("Dump/data/data/com.whatsapp/databases/msgstore.db",
             b"SQLite format 3\x00" + b"\x00" * 1024),
            ("Dump/system/build.prop", b"ro.product.brand=Google\n"),
        ])
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            entries = list(safe_iter_entries(zf, self.dest))
        self.assertEqual(len(entries), 2)
        for e in entries:
            self.assertTrue(e.extracted_path.exists())
            self.assertEqual(len(e.source_sha256), 64)  # hex
            self.assertGreater(e.source_size, 0)
            # Path must be inside dest (containment check).
            self.assertTrue(
                e.extracted_path.resolve().is_relative_to(self.dest.resolve())
            )

    # ---------------------------------------------------------------
    # Predicate selection — only matching entries get extracted
    # ---------------------------------------------------------------
    def test_predicate_selection(self):
        data = _build_zip([
            ("Dump/data/data/com.whatsapp/databases/msgstore.db", b"db"),
            ("Dump/data/data/com.whatsapp/cache/icon.png", b"png"),
            ("Dump/system/build.prop", b"prop"),
        ])
        wanted = lambda i: i.filename.endswith(".db")
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            entries = list(safe_iter_entries(zf, self.dest, select=wanted))
        names = [e.zip_entry_path for e in entries]
        self.assertEqual(names,
                         ["Dump/data/data/com.whatsapp/databases/msgstore.db"])

    # ---------------------------------------------------------------
    # not_extracted manifest — every non-selected entry is recorded
    # ---------------------------------------------------------------
    def test_inventory_all(self):
        data = _build_zip([
            ("a.db", b"db"),
            ("b.png", b"png"),
            ("c.txt", b"txt"),
        ])
        wanted = lambda i: i.filename.endswith(".db")
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            inv = list(inventory_all(zf, select_predicate=wanted))
        # All three appear in the inventory pass; only the .db is
        # *not* surfaced because it would have been selected.
        not_selected = [i for i in inv
                        if i.reason == "not_in_extraction_spec"]
        self.assertEqual(
            sorted(i.zip_entry_path for i in not_selected),
            ["b.png", "c.txt"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
