#!/usr/bin/env python3
"""
libimobiledevice Windows Binaries Downloader

Downloads LGPL-2.1 licensed binaries and bundles them with the collector.
Automatically downloaded during build or on first run.

Source: https://github.com/libimobiledevice-win32/imobiledevice-net
License: LGPL-2.1 (https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)

Usage:
    python download_libimobiledevice.py
"""

import os
import sys
import zipfile
import hashlib
import shutil
from pathlib import Path
from urllib.request import urlretrieve
from urllib.error import URLError

# =============================================================================
# Configuration
# =============================================================================

LIBIMOBILEDEVICE_VERSION = "1.3.17"
LIBIMOBILEDEVICE_URL = (
    "https://github.com/libimobiledevice-win32/imobiledevice-net/releases/download/"
    f"v{LIBIMOBILEDEVICE_VERSION}/libimobiledevice.1.2.1-r1122-win-x64.zip"
)

# Expected SHA256 hash (for integrity verification)
# Note: Update this if downloading a different version
EXPECTED_SHA256 = None  # Will be populated after first download

# Tools directory (where this script is located)
TOOLS_DIR = Path(__file__).parent
LIBIMOBILEDEVICE_DIR = TOOLS_DIR / "libimobiledevice"

# Required executables for iOS forensics
REQUIRED_EXECUTABLES = [
    "idevice_id.exe",
    "ideviceinfo.exe",
    "idevicesyslog.exe",
    "idevicecrashreport.exe",
    "ideviceinstaller.exe",
    "idevicebackup2.exe",
]


def download_progress(block_num: int, block_size: int, total_size: int) -> None:
    """Download progress callback"""
    if total_size > 0:
        percent = min(100, block_num * block_size * 100 // total_size)
        bar_length = 40
        filled = int(bar_length * percent // 100)
        bar = "=" * filled + "-" * (bar_length - filled)
        print(f"\r  [{bar}] {percent}%", end="", flush=True)


def compute_sha256(filepath: Path) -> str:
    """Compute SHA256 hash of file"""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def download_libimobiledevice(force: bool = False) -> bool:
    """
    Download and extract libimobiledevice Windows binaries.

    Args:
        force: Force re-download even if already exists

    Returns:
        True if successful
    """
    print("=" * 60)
    print("libimobiledevice Windows Binaries Installer")
    print("=" * 60)
    print(f"Version: {LIBIMOBILEDEVICE_VERSION}")
    print(f"License: LGPL-2.1")
    print(f"Source:  https://github.com/libimobiledevice-win32/imobiledevice-net")
    print("=" * 60)

    # Check if already installed
    if not force and is_installed():
        print("\n[OK] libimobiledevice is already installed.")
        print(f"     Location: {LIBIMOBILEDEVICE_DIR}")
        return True

    # Create directories
    LIBIMOBILEDEVICE_DIR.mkdir(parents=True, exist_ok=True)

    # Download
    zip_path = TOOLS_DIR / "libimobiledevice.zip"

    print(f"\n[1/3] Downloading libimobiledevice...")
    print(f"      URL: {LIBIMOBILEDEVICE_URL}")

    try:
        urlretrieve(LIBIMOBILEDEVICE_URL, zip_path, download_progress)
        print()  # New line after progress bar
    except URLError as e:
        print(f"\n[ERROR] Download failed: {e}")
        return False
    except Exception as e:
        print(f"\n[ERROR] Download failed: {e}")
        return False

    # Verify hash (if known)
    if EXPECTED_SHA256:
        print(f"\n[2/3] Verifying integrity...")
        actual_hash = compute_sha256(zip_path)
        if actual_hash != EXPECTED_SHA256:
            print(f"[ERROR] SHA256 mismatch!")
            print(f"        Expected: {EXPECTED_SHA256}")
            print(f"        Actual:   {actual_hash}")
            zip_path.unlink()
            return False
        print("      [OK] SHA256 verified")
    else:
        print(f"\n[2/3] Skipping hash verification (hash not configured)")
        actual_hash = compute_sha256(zip_path)
        print(f"      SHA256: {actual_hash}")

    # Extract
    print(f"\n[3/3] Extracting...")

    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Extract all files to libimobiledevice directory
            for member in zf.namelist():
                # Get just the filename (flatten directory structure)
                filename = Path(member).name
                if not filename:
                    continue

                # Extract to libimobiledevice directory
                source = zf.read(member)
                dest_path = LIBIMOBILEDEVICE_DIR / filename
                dest_path.write_bytes(source)

        print(f"      Extracted to: {LIBIMOBILEDEVICE_DIR}")
    except Exception as e:
        print(f"[ERROR] Extraction failed: {e}")
        return False
    finally:
        # Clean up zip file
        if zip_path.exists():
            zip_path.unlink()

    # Write LGPL license file
    write_license_file()

    # Verify installation
    if is_installed():
        print("\n" + "=" * 60)
        print("[SUCCESS] libimobiledevice installed successfully!")
        print("=" * 60)
        print("\nInstalled executables:")
        for exe in REQUIRED_EXECUTABLES:
            exe_path = LIBIMOBILEDEVICE_DIR / exe
            status = "[OK]" if exe_path.exists() else "[MISSING]"
            print(f"  {status} {exe}")
        return True
    else:
        print("\n[ERROR] Installation verification failed")
        return False


def is_installed() -> bool:
    """Check if libimobiledevice is installed"""
    if not LIBIMOBILEDEVICE_DIR.exists():
        return False

    # Check for at least the essential executables
    essential = ["idevice_id.exe", "ideviceinfo.exe", "idevicebackup2.exe"]
    for exe in essential:
        if not (LIBIMOBILEDEVICE_DIR / exe).exists():
            return False

    return True


def get_tool_path(tool_name: str) -> Path:
    """Get path to a specific tool"""
    return LIBIMOBILEDEVICE_DIR / f"{tool_name}.exe"


def write_license_file() -> None:
    """Write LGPL-2.1 license notice"""
    license_text = """libimobiledevice - Windows Binaries

License: GNU Lesser General Public License v2.1 (LGPL-2.1)

This directory contains pre-built Windows binaries of libimobiledevice,
distributed under the LGPL-2.1 license.

Source Code:
  https://github.com/libimobiledevice/libimobiledevice

Windows Builds:
  https://github.com/libimobiledevice-win32/imobiledevice-net

Full License Text:
  https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html

================================================================================

                  GNU LESSER GENERAL PUBLIC LICENSE
                       Version 2.1, February 1999

 Copyright (C) 1991, 1999 Free Software Foundation, Inc.
 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

[This is the first released version of the Lesser GPL.  It also counts
 as the successor of the GNU Library Public License, version 2, hence
 the version number 2.1.]

                            Preamble

  The licenses for most software are designed to take away your
freedom to share and change it.  By contrast, the GNU General Public
Licenses are intended to guarantee your freedom to share and change
free software--to make sure the software is free for all its users.

  This license, the Lesser General Public License, applies to some
specially designated software packages--typically libraries--of the
Free Software Foundation and other authors who decide to use it.  You
can use it too, but we suggest you first think carefully about whether
this license or the ordinary General Public License is the better
strategy to use in any particular case, based on the explanations below.

================================================================================

You may replace these binaries with your own builds of libimobiledevice.
The source code is available at the URLs listed above.
"""

    license_path = LIBIMOBILEDEVICE_DIR / "LICENSE"
    license_path.write_text(license_text, encoding="utf-8")
    print("      License file written: LICENSE")


def uninstall() -> bool:
    """Remove libimobiledevice installation"""
    if LIBIMOBILEDEVICE_DIR.exists():
        shutil.rmtree(LIBIMOBILEDEVICE_DIR)
        print(f"[OK] Removed: {LIBIMOBILEDEVICE_DIR}")
        return True
    else:
        print("[INFO] libimobiledevice is not installed")
        return False


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Download libimobiledevice Windows binaries"
    )
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Force re-download even if already installed"
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove libimobiledevice installation"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check if libimobiledevice is installed"
    )

    args = parser.parse_args()

    if args.check:
        if is_installed():
            print(f"[OK] libimobiledevice is installed at: {LIBIMOBILEDEVICE_DIR}")
            sys.exit(0)
        else:
            print("[NOT INSTALLED] libimobiledevice is not installed")
            sys.exit(1)

    if args.uninstall:
        success = uninstall()
        sys.exit(0 if success else 1)

    success = download_libimobiledevice(force=args.force)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
