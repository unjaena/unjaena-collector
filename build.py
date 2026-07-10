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
import base64
import importlib.util
import json
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
SUPPORTED_UI_LOCALES = ("en", "ko", "ja")


def _read_json_object(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Locale file must contain a JSON object: {path}")
    return {str(k): str(v) for k, v in data.items()}


def _write_json_object(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _load_default_ui_messages(collector_dir: Path) -> dict:
    """Load English UI defaults without importing the gui package."""
    i18n_path = collector_dir / "src" / "gui" / "i18n.py"
    spec = importlib.util.spec_from_file_location(
        "collector_build_i18n_defaults",
        i18n_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load UI defaults from {i18n_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    messages = getattr(module, "DEFAULT_MESSAGES", None)
    if not isinstance(messages, dict):
        raise RuntimeError(f"DEFAULT_MESSAGES missing from {i18n_path}")
    return {str(k): str(v) for k, v in messages.items()}


def _locale_from_env(locale_code: str) -> dict:
    upper = locale_code.upper()
    raw = os.environ.get(f"COLLECTOR_UI_LOCALE_{upper}_JSON")
    raw_b64 = os.environ.get(f"COLLECTOR_UI_LOCALE_{upper}_JSON_B64")
    if raw_b64:
        try:
            raw = base64.b64decode(raw_b64, validate=True).decode("utf-8")
        except Exception:
            raw = raw_b64
    if not raw:
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"COLLECTOR_UI_LOCALE_{upper}_JSON must be a JSON object")
    return {str(k): str(v) for k, v in data.items()}


def prepare_ui_locales(collector_dir: Path) -> list:
    """Prepare private UI locale JSON files for PyInstaller bundling.

    Public source keeps English fallback strings in code. Private/customer
    builds can inject locale files from:

    - COLLECTOR_LOCALE_DIR/en.json, ko.json, ja.json
    - collector/private/locales/en.json, ko.json, ja.json
    - COLLECTOR_UI_LOCALE_<LOCALE>_JSON[_B64] CI secrets
    """
    locale_dir = collector_dir / "locales"
    source_dir = Path(
        os.environ.get(
            "COLLECTOR_LOCALE_DIR",
            str(collector_dir / "private" / "locales"),
        )
    )

    included = set()
    if source_dir.exists() and source_dir.resolve() != locale_dir.resolve():
        for locale_code in SUPPORTED_UI_LOCALES:
            source_file = source_dir / f"{locale_code}.json"
            if not source_file.exists():
                continue
            data = _read_json_object(source_file)
            _write_json_object(locale_dir / f"{locale_code}.json", data)
            included.add(locale_code)

    for locale_code in SUPPORTED_UI_LOCALES:
        env_data = _locale_from_env(locale_code)
        if not env_data:
            continue
        _write_json_object(locale_dir / f"{locale_code}.json", env_data)
        included.add(locale_code)

    if "en" not in included and not (locale_dir / "en.json").exists():
        _write_json_object(
            locale_dir / "en.json",
            _load_default_ui_messages(collector_dir),
        )
        included.add("en")

    if locale_dir.exists():
        for locale_code in SUPPORTED_UI_LOCALES:
            if (locale_dir / f"{locale_code}.json").exists():
                included.add(locale_code)

    if included:
        print(f"[I18N] UI locales prepared: {', '.join(sorted(included))}")
    else:
        print("[I18N] No UI locale files found; English fallback only.")
    return sorted(included)


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
        '--platform',
        type=str,
        choices=['windows', 'linux', 'macos'],
        default=None,
        help='Target platform for cross-platform builds'
    )
    parser.add_argument(
        '--ci',
        action='store_true',
        help='CI mode: non-interactive, no prompts'
    )
    parser.add_argument(
        '--require-ui-locales',
        action='store_true',
        help='Fail the build unless all supported UI locale files are prepared'
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
            if args.ci:
                print("[CI] Continuing without USB dependencies.")
            else:
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

    # Inject version from git tag or environment variable
    import json as _json
    import subprocess as _subprocess
    with open(config_dest_path, 'r', encoding='utf-8') as f:
        _cfg = _json.load(f)
    # CI sets GITHUB_REF_NAME=collector-vX.Y.Z
    _env_version = os.environ.get('GITHUB_REF_NAME', '')
    if _env_version.startswith('collector-v'):
        _cfg['version'] = _env_version.replace('collector-v', '')
        print(f"[BUILD] Version from tag: {_cfg['version']}")
    elif _cfg.get('version', '0.0.0') == '0.0.0':
        # Fallback: try git describe
        try:
            _git_ver = _subprocess.check_output(['git', 'describe', '--tags', '--abbrev=0'], text=True).strip()
            _cfg['version'] = _git_ver.replace('collector-v', '')
            print(f"[BUILD] Version from git: {_cfg['version']}")
        except Exception:
            _cfg['version'] = '1.0.0'
            print(f"[BUILD] Version fallback: {_cfg['version']}")
    with open(config_dest_path, 'w', encoding='utf-8') as f:
        _json.dump(_cfg, f, indent=4)

    # Ensure resources directory exists
    resources_dir = collector_dir / "resources"
    resources_dir.mkdir(exist_ok=True)

    # Prepare optional private UI locale files for bundled release builds.
    included_locales = prepare_ui_locales(collector_dir)
    require_ui_locales = (
        args.require_ui_locales
        or os.environ.get('COLLECTOR_REQUIRE_UI_LOCALES', '').lower()
        in {'1', 'true', 'yes'}
    )
    missing_locales = sorted(set(SUPPORTED_UI_LOCALES) - set(included_locales))
    if require_ui_locales and missing_locales:
        print(
            "[I18N] Required UI locales missing: "
            + ", ".join(missing_locales)
        )
        print(
            "[I18N] Provide COLLECTOR_UI_LOCALE_<LOCALE>_JSON_B64 secrets "
            "or collector/private/locales/<locale>.json before building."
        )
        sys.exit(1)

    # NOTE: Signing keys are now server-issued ephemeral keys (per-session).
    # No build-time key generation or embedding is needed.
    print("\n[SIGN] Ephemeral signing: keys are issued by server at /authenticate")
    print("[SIGN] No build-time key embedding required.")

    # Run PyInstaller
    print("\n[BUILD] Starting PyInstaller build...")
    spec_file = collector_dir / 'ForensicCollector.spec'

    result = subprocess.run(
        [sys.executable, '-m', 'PyInstaller', str(spec_file), '--clean'],
        cwd=collector_dir
    )

    if result.returncode == 0:
        dist_dir = collector_dir / 'dist'
        import platform as _platform
        target_os = args.platform or _platform.system().lower()
        if target_os == 'windows':
            exe_path = dist_dir / 'IntelligenceCollector.exe'
        elif target_os == 'darwin' or target_os == 'macos':
            exe_path = dist_dir / 'IntelligenceCollector.app'
        else:
            exe_path = dist_dir / 'IntelligenceCollector'

        print(f"\n[SUCCESS] Build completed!")
        print(f"[SUCCESS] Output: {dist_dir}")
        print(f"[SUCCESS] Executable: {exe_path}")

        if exe_path.exists():
            if exe_path.is_file():
                size_mb = exe_path.stat().st_size / (1024 * 1024)
                print(f"[SUCCESS] Size: {size_mb:.1f} MB")
    else:
        print(f"\n[ERROR] Build failed (exit code: {result.returncode})")
        sys.exit(result.returncode)


if __name__ == '__main__':
    main()
