#!/usr/bin/env python3
"""
Collector Build Script

Usage:
    python build.py --production    # Production build (production server URL)
    python build.py --development   # Development build (local server URL)
    python build.py                 # Default: production build
    python build.py --check-deps    # Check USB dependencies only
    python build.py --download-libusb  # Download libusb DLL
"""
import argparse
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

# libusb release info
LIBUSB_VERSION = "1.0.27"
LIBUSB_DOWNLOAD_PAGE = "https://github.com/libusb/libusb/releases"


def check_usb_dependencies():
    """Check if USB libraries are available for Android collection"""
    print("\n[USB] Checking USB dependencies for Android collection...")

    collector_dir = Path(__file__).parent
    resources_dir = collector_dir / "resources"

    # Check Python packages
    usb_packages_ok = True
    try:
        import adb_shell
        print(f"  [OK] adb-shell: {adb_shell.__version__ if hasattr(adb_shell, '__version__') else 'installed'}")
    except ImportError:
        print("  [!!] adb-shell: NOT INSTALLED")
        print("       Install: pip install adb-shell[usb]")
        usb_packages_ok = False

    try:
        import usb1
        print(f"  [OK] libusb1: installed")
    except ImportError:
        print("  [!!] libusb1: NOT INSTALLED")
        print("       Install: pip install libusb1")
        usb_packages_ok = False

    try:
        import rsa
        print(f"  [OK] rsa: installed")
    except ImportError:
        print("  [!!] rsa: NOT INSTALLED")
        print("       Install: pip install rsa")
        usb_packages_ok = False

    # Check libusb DLL
    dll_found = False
    dll_locations = [
        resources_dir / "libusb-1.0.dll",
        Path(os.environ.get('PROGRAMFILES', '')) / 'libusb-1.0' / 'VS2022' / 'MS64' / 'dll' / 'libusb-1.0.dll',
        Path(os.environ.get('PROGRAMFILES', '')) / 'libusb' / 'x64' / 'libusb-1.0.dll',
    ]

    # Check PATH
    for path_dir in os.environ.get('PATH', '').split(os.pathsep):
        dll_locations.append(Path(path_dir) / 'libusb-1.0.dll')

    # Check usb1 package directory
    try:
        import usb1
        usb1_dir = Path(usb1.__file__).parent
        dll_locations.insert(0, usb1_dir / 'libusb-1.0.dll')
    except ImportError:
        pass

    for dll_path in dll_locations:
        if dll_path.exists():
            print(f"  [OK] libusb-1.0.dll: {dll_path}")
            dll_found = True
            break

    if not dll_found:
        print("  [!!] libusb-1.0.dll: NOT FOUND")
        print("       Run: python build.py --download-libusb")
        print("       Or download from: https://github.com/libusb/libusb/releases")

    # Summary
    if usb_packages_ok and dll_found:
        print("\n[USB] All USB dependencies are ready!")
        return True
    else:
        print("\n[USB] Some dependencies are missing.")
        print("[USB] Android USB collection may not work without these.")
        return False


def download_libusb():
    """Guide user to download and install libusb DLL"""
    print("\n[USB] libusb Installation Guide")
    print("=" * 60)

    collector_dir = Path(__file__).parent
    resources_dir = collector_dir / "resources"
    resources_dir.mkdir(exist_ok=True)

    dll_dest = resources_dir / "libusb-1.0.dll"

    if dll_dest.exists():
        print(f"[OK] libusb-1.0.dll already exists: {dll_dest}")
        return True

    # Check if libusb1 Python package has bundled DLL
    try:
        import usb1
        usb1_dir = Path(usb1.__file__).parent
        bundled_dll = usb1_dir / "libusb-1.0.dll"
        if bundled_dll.exists():
            shutil.copy(bundled_dll, dll_dest)
            print(f"[OK] Copied from Python package: {bundled_dll}")
            print(f"[OK] Destination: {dll_dest}")
            return True
    except ImportError:
        pass

    # Check common installation paths
    common_paths = [
        Path(os.environ.get('PROGRAMFILES', 'C:/Program Files')) / 'libusb-1.0' / 'VS2022' / 'MS64' / 'dll' / 'libusb-1.0.dll',
        Path(os.environ.get('PROGRAMFILES', 'C:/Program Files')) / 'libusb' / 'x64' / 'libusb-1.0.dll',
        Path('C:/libusb/VS2022/MS64/dll/libusb-1.0.dll'),
        Path('C:/libusb/MinGW64/dll/libusb-1.0.dll'),
    ]

    for path in common_paths:
        if path.exists():
            shutil.copy(path, dll_dest)
            print(f"[OK] Found and copied from: {path}")
            print(f"[OK] Destination: {dll_dest}")
            return True

    # Manual installation instructions
    print("\n[!!] libusb-1.0.dll not found automatically.")
    print("\nManual Installation Steps:")
    print("-" * 60)
    print(f"1. Download libusb from:")
    print(f"   {LIBUSB_DOWNLOAD_PAGE}")
    print(f"")
    print(f"2. Download the .7z file (e.g., libusb-1.0.27.7z)")
    print(f"")
    print(f"3. Extract using 7-Zip or similar tool")
    print(f"")
    print(f"4. Find the 64-bit DLL:")
    print(f"   VS2022/MS64/dll/libusb-1.0.dll")
    print(f"   or MinGW64/dll/libusb-1.0.dll")
    print(f"")
    print(f"5. Copy the DLL to:")
    print(f"   {dll_dest}")
    print("-" * 60)

    # Alternative: pip install libusb
    print("\nAlternative: Try installing via pip:")
    print("  pip install libusb")
    print("  (May include bundled DLL on some systems)")

    return False


def main():
    parser = argparse.ArgumentParser(description='Build Intelligence Collector')
    parser.add_argument(
        '--production', '-p',
        action='store_true',
        help='Production build (uses config.production.json)'
    )
    parser.add_argument(
        '--development', '-d',
        action='store_true',
        help='Development build (uses config.development.json)'
    )
    parser.add_argument(
        '--server-url',
        type=str,
        help='Override server URL in config'
    )
    parser.add_argument(
        '--check-deps',
        action='store_true',
        help='Check USB dependencies only (no build)'
    )
    parser.add_argument(
        '--download-libusb',
        action='store_true',
        help='Download libusb DLL to resources folder'
    )
    parser.add_argument(
        '--skip-usb-check',
        action='store_true',
        help='Skip USB dependency check'
    )
    parser.add_argument(
        '--reuse-key',
        action='store_true',
        help='Reuse existing signing key from .signing_key (skip key generation)'
    )
    args = parser.parse_args()

    collector_dir = Path(__file__).parent

    # Download libusb only
    if args.download_libusb:
        download_libusb()
        return

    # Check dependencies only
    if args.check_deps:
        check_usb_dependencies()
        return

    # Check USB dependencies before build
    if not args.skip_usb_check:
        print("=" * 60)
        usb_ok = check_usb_dependencies()
        print("=" * 60)

        if not usb_ok:
            print("\n[WARNING] USB dependencies missing. Android USB collection will not work.")
            response = input("Continue build anyway? [y/N]: ").strip().lower()
            if response != 'y':
                print("[BUILD] Aborted.")
                sys.exit(1)

    # Determine build type
    if args.development:
        config_source = 'config.development.json'
        build_type = 'Development'
    else:
        config_source = 'config.production.json'
        build_type = 'Production'

    config_source_path = collector_dir / config_source
    config_dest_path = collector_dir / 'config.json'

    # Check config file exists
    if not config_source_path.exists():
        print(f"[ERROR] Config file not found: {config_source_path}")
        print("Create config.production.json or config.development.json")
        sys.exit(1)

    print(f"\n[BUILD] Build type: {build_type}")
    print(f"[BUILD] Config file: {config_source} -> config.json")

    # Copy config (with optional server URL override)
    if args.server_url:
        import json
        with open(config_source_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        config['server_url'] = args.server_url
        # Auto-generate ws_url
        if args.server_url.startswith('https://'):
            config['ws_url'] = args.server_url.replace('https://', 'wss://')
        elif args.server_url.startswith('http://'):
            config['ws_url'] = args.server_url.replace('http://', 'ws://')
        with open(config_dest_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4)
        print(f"[BUILD] Server URL override: {args.server_url}")
    else:
        shutil.copy(config_source_path, config_dest_path)

    # Ensure resources directory exists
    resources_dir = collector_dir / "resources"
    resources_dir.mkdir(exist_ok=True)

    # =========================================================================
    # Signing key generation & embedding
    # Generates a random base_key, XOR-encrypts it with the fixed diversifier,
    # and patches request_signer.py so the binary contains the key.
    # =========================================================================
    import secrets as _secrets
    import re as _re

    signer_path = collector_dir / 'src' / 'core' / 'request_signer.py'
    if signer_path.exists():
        # Fixed diversifier (must match request_signer.py)
        diversifier = (
            b'\xa3\x7f\x1b\xe4\x92\x56\xd8\x0c'
            b'\x4e\xb1\x63\xf7\x28\x9d\x05\xca'
            b'\x71\xde\x3a\x8f\x44\xbb\x10\x65'
            b'\xf2\x07\x59\xc6\x83\x2d\xae\x17'
        )

        # --reuse-key: reuse existing .signing_key instead of generating new one
        key_file = collector_dir / '.signing_key'
        if args.reuse_key and key_file.exists():
            key_hex = key_file.read_text(encoding='utf-8').strip()
            base_key = bytes.fromhex(key_hex)
            print(f"\n[SIGN] Reusing existing signing key from {key_file}")
        else:
            base_key = _secrets.token_bytes(32)
            print("\n[SIGN] Generating new request signing key...")

        encrypted_key = bytes(a ^ b for a, b in zip(base_key, diversifier))

        # Format as Python bytes literal
        enc_repr = repr(encrypted_key)

        # Read and patch the source file (use string find+replace, not regex,
        # because repr() output contains \x escapes that break re.sub)
        signer_source = signer_path.read_text(encoding='utf-8')
        marker = "# BUILD_REPLACE_MARKER"
        marker_idx = signer_source.find(marker)

        if marker_idx >= 0:
            # Find the start of the line containing the marker
            line_start = signer_source.rfind('\n', 0, marker_idx) + 1
            line_end = signer_source.find('\n', marker_idx)
            if line_end == -1:
                line_end = len(signer_source)
            new_line = f"_EMBEDDED_KEY_ENC = {enc_repr}  {marker}"
            patched = signer_source[:line_start] + new_line + signer_source[line_end:]
            signer_path.write_text(patched, encoding='utf-8')
            print(f"[SIGN] Embedded key patched into request_signer.py")
        else:
            print(f"[SIGN] WARNING: Could not find BUILD_REPLACE_MARKER in request_signer.py")

        # Save base_key for server configuration
        key_hex = base_key.hex()
        key_file = collector_dir / '.signing_key'
        key_file.write_text(key_hex, encoding='utf-8')
        print(f"[SIGN] Base key saved to: {key_file}")
        print(f"[SIGN] ┌──────────────────────────────────────────────────────────────────┐")
        print(f"[SIGN] │ CLIENT_SIGNING_BASE_KEY={key_hex} │")
        print(f"[SIGN] └──────────────────────────────────────────────────────────────────┘")
        print(f"[SIGN] Set the above value in your server .env file")
    else:
        print(f"\n[SIGN] WARNING: request_signer.py not found at {signer_path}")

    # Run PyInstaller
    print("\n[BUILD] Starting PyInstaller build...")
    spec_file = collector_dir / 'ForensicCollector.spec'

    result = subprocess.run(
        [sys.executable, '-m', 'PyInstaller', str(spec_file), '--clean'],
        cwd=collector_dir
    )

    if result.returncode == 0:
        dist_dir = collector_dir / 'dist'
        exe_path = dist_dir / 'IntelligenceCollector.exe'

        print(f"\n[SUCCESS] Build completed!")
        print(f"[SUCCESS] Output: {dist_dir}")
        print(f"[SUCCESS] Executable: {exe_path}")

        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print(f"[SUCCESS] Size: {size_mb:.1f} MB")
    else:
        print(f"\n[ERROR] Build failed (exit code: {result.returncode})")
        sys.exit(result.returncode)


if __name__ == '__main__':
    main()
