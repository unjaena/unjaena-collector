# -*- mode: python ; coding: utf-8 -*-
import os
import sys
import platform
from pathlib import Path

current_os = platform.system().lower()  # 'windows', 'linux', 'darwin'

# =============================================================================
# USB Library Detection (Windows only)
# =============================================================================

def find_libusb_dll():
    """Find libusb-1.0.dll for bundling with the application (Windows only)"""
    if current_os != 'windows':
        return []

    dll_locations = []
    possible_paths = [
        Path('resources/libusb-1.0.dll'),
        Path(os.environ.get('PROGRAMFILES', 'C:/Program Files')) / 'libusb-1.0' / 'MS64' / 'libusb-1.0.dll',
        Path(os.environ.get('PROGRAMFILES(X86)', 'C:/Program Files (x86)')) / 'libusb-1.0' / 'MS32' / 'libusb-1.0.dll',
    ]

    try:
        import usb1
        usb1_path = Path(usb1.__file__).parent
        dll_in_package = usb1_path / 'libusb-1.0.dll'
        if dll_in_package.exists():
            possible_paths.insert(0, dll_in_package)
    except ImportError:
        pass

    for path_dir in os.environ.get('PATH', '').split(os.pathsep):
        dll_path = Path(path_dir) / 'libusb-1.0.dll'
        if dll_path.exists():
            possible_paths.append(dll_path)

    for dll_path in possible_paths:
        if dll_path.exists():
            print(f"[USB] Found libusb DLL: {dll_path}")
            dll_locations.append((str(dll_path), '.'))
            break

    if not dll_locations:
        print("[USB] WARNING: libusb-1.0.dll not found. Android USB collection may not work.")

    return dll_locations


usb_binaries = find_libusb_dll()

# =============================================================================
# ADB Binary Detection (Windows only — fallback when libusb driver conflicts)
# Downloaded at build time by GitHub Actions (Apache-2.0 license)
# =============================================================================

def find_adb_binaries():
    """Find adb.exe + DLLs for bundling (Windows only)"""
    if current_os != 'windows':
        return []

    adb_dir = Path('resources/adb')
    required = ['adb.exe', 'AdbWinApi.dll', 'AdbWinUsbApi.dll']
    binaries = []

    for name in required:
        path = adb_dir / name
        if path.exists():
            binaries.append((str(path), 'resources/adb'))
            print(f"[ADB] Bundling: {path}")

    if not binaries:
        print("[ADB] WARNING: adb binaries not found in resources/adb/. "
              "Run: python build.py --download-libusb or download manually.")

    return binaries

adb_binaries = find_adb_binaries()

# =============================================================================
# Platform-Specific Hidden Imports
# =============================================================================

# Common hidden imports (all platforms)
# License: All listed packages are AGPL-3.0 / GPL-3.0 / MIT / BSD / Apache-2.0 compatible
common_hidden_imports = [
    # --- Android: adb-shell (Apache-2.0) ---
    'adb_shell',
    'adb_shell.adb_device',
    'adb_shell.adb_device_usb',
    'adb_shell.auth',
    'adb_shell.auth.keygen',
    'adb_shell.auth.sign_pythonrsa',
    'adb_shell.exceptions',
    'adb_shell.handle',
    'adb_shell.transport',

    # --- USB: libusb (LGPL-2.1) + PyUSB (BSD) ---
    'usb1',
    'libusb1',
    'usb',                 # PyUSB — device_enumerators
    'usb.core',
    'usb.util',
    'usb.backend',
    'usb.backend.libusb1',
    'usb.backend.libusb0',
    'usb.backend.openusb',
    'usb.control',
    'usb._interop',
    'usb._objfinalizer',
    'usb._lookup',
    'usb.libloader',

    # --- Crypto: rsa (Apache-2.0), cryptography (Apache-2.0/BSD) ---
    'rsa',
    'cryptography',
    'cryptography.hazmat',
    'cryptography.hazmat.primitives',
    'cryptography.hazmat.primitives.ciphers',
    'cryptography.hazmat.primitives.ciphers.aead',  # secure_upload.py
    'cryptography.hazmat.primitives.kdf',
    'cryptography.hazmat.primitives.kdf.hkdf',      # secure_upload.py
    'cryptography.hazmat.backends',

    # --- GUI: PyQt6 (GPL-3.0) ---
    'PyQt6',
    'PyQt6.QtCore',
    'PyQt6.QtGui',
    'PyQt6.QtWidgets',
    'PyQt6.sip',

    # --- HTTP: requests (Apache-2.0) + deps ---
    'requests',            # used in app.py, uploader.py, updater.py, etc.
    'requests.adapters',   # secure_upload.py
    'urllib3',             # requests dependency
    'charset_normalizer',  # requests dependency (has native PYD)
    'idna',                # requests dependency

    # --- Async HTTP: aiohttp (Apache-2.0) + websockets (BSD) ---
    'aiohttp',             # uploader.py — async upload support
    'websockets',          # uploader.py — WebSocket upload
    'aiosignal',           # aiohttp dependency
    'frozenlist',          # aiohttp dependency (has native PYD)
    'multidict',           # aiohttp dependency (has native PYD)
    'yarl',                # aiohttp dependency (has native PYD)
    'propcache',           # aiohttp dependency (has native PYD)
    'attrs',               # aiohttp dependency
    'aiohappyeyeballs',    # aiohttp dependency

    # --- iOS: pymobiledevice3 (GPL-3.0) ---
    # Core modules (traced via runtime import analysis)
    'pymobiledevice3',
    'pymobiledevice3._version',
    'pymobiledevice3.bonjour',
    'pymobiledevice3.ca',
    'pymobiledevice3.common',
    'pymobiledevice3.exceptions',
    'pymobiledevice3.irecv_devices',
    'pymobiledevice3.lockdown',
    'pymobiledevice3.lockdown_service_provider',
    'pymobiledevice3.osu',
    'pymobiledevice3.osu.os_utils',
    'pymobiledevice3.osu.win_util',
    'pymobiledevice3.pair_records',
    'pymobiledevice3.remote',
    'pymobiledevice3.remote.remote_service_discovery',
    'pymobiledevice3.remote.remotexpc',
    'pymobiledevice3.remote.xpc_message',
    'pymobiledevice3.service_connection',
    'pymobiledevice3.usbmux',
    'pymobiledevice3.utils',
    # Services used by collector
    'pymobiledevice3.services',
    'pymobiledevice3.services.afc',
    'pymobiledevice3.services.crash_reports',
    'pymobiledevice3.services.device_link',
    'pymobiledevice3.services.diagnostics',
    'pymobiledevice3.services.house_arrest',
    'pymobiledevice3.services.installation_proxy',
    'pymobiledevice3.services.lockdown_service',
    'pymobiledevice3.services.mobilebackup2',
    'pymobiledevice3.services.notification_proxy',
    'pymobiledevice3.services.os_trace',
    'pymobiledevice3.services.springboard',
    'pymobiledevice3.services.syslog',

    # --- pymobiledevice3 dependencies ---
    'construct',           # MIT
    'construct_typed',     # MIT
    'bpylist2',            # MIT
    'opack2',              # MIT
    'srptools',            # MIT
    'hexdump',             # Public Domain
    'hyperframe',          # MIT
    'ifaddr',              # MIT
    'nest_asyncio',        # BSD-2
    'parameter_decorators',# MIT
    'pycrashreport',       # GPL-3.0
    'pygnuutils',          # GPL-3.0
    'la_panic',            # MIT
    'packaging',           # Apache-2.0/BSD
    'tqdm',                # MPL-2.0/MIT
    'ujson',               # BSD
    'wsproto',             # MIT
    'qh3',                 # MIT — QUIC/HTTP3 for iOS remote connections (native PYD)
    'click',               # BSD — CLI framework (pymobiledevice3 dep)
    'developer_disk_image',# MIT — iOS developer disk image support
    'ipsw_parser',         # MIT — iOS IPSW firmware parsing
    'asn1crypto',          # MIT — ASN.1 parsing (dissect.apfs dep)

    # --- iOS backup: biplist (BSD), iphone_backup_decrypt (MIT) ---
    'biplist',
    'iphone_backup_decrypt',
    'collectors.ios_backup_decryptor',
    'Crypto',
    'Crypto.Cipher',
    'Crypto.Cipher.AES',
    'Crypto.Util',
    'Crypto.Util.Padding',
]

# Windows-specific
windows_hidden_imports = [
    'win32api',
    'win32con',
    'win32file',       # Raw disk access (disk_backends.py)
    'win32security',
    'winioctlcon',     # IOCTL constants for disk geometry (disk_backends.py)
    'pywintypes',      # Win32 COM type support (disk_backends.py)
    'wmi',
    'pytsk3',
    'pyewf',           # E01 forensic image support (libewf-python)
]

# Cross-platform forensic libraries (conditional imports inside try/except)
forensic_hidden_imports = [
    'pyfshfs',         # HFS+ filesystem parsing (forensic_disk_accessor.py)
    'lzfse',           # macOS APFS/LZFSE decompression (disk_backends.py)

    # --- dissect filesystem parsers (conditional imports in forensic_disk_accessor.py) ---
    # NOTE: 'dissect' bare namespace is NOT a pip package; only sub-packages are needed.
    'dissect.extfs',       # ext2/ext3/ext4 filesystem parsing (Linux)
    'dissect.xfs',         # XFS filesystem parsing (Linux)
    'dissect.btrfs',       # Btrfs filesystem parsing (Linux)
    'dissect.ffs',         # UFS/FFS filesystem parsing (FreeBSD)
    'dissect.fat',         # FAT12/16/32 filesystem parsing
    'dissect.fat.exfat',   # exFAT filesystem parsing
    'dissect.apfs',        # APFS filesystem parsing (macOS)
    'dissect.ntfs',        # NTFS parsing (used by dissect internally)
    'dissect.volume',      # Volume/partition parsing (dissect dep)
]

# Combine based on platform
if current_os == 'windows':
    all_hidden_imports = common_hidden_imports + windows_hidden_imports + forensic_hidden_imports
else:
    all_hidden_imports = common_hidden_imports + forensic_hidden_imports

# =============================================================================
# collect_all: Full package bundling for packages with deep import chains
# PyInstaller's automatic analysis misses dynamically imported submodules,
# data files, and native binaries in these packages.
# =============================================================================
from PyInstaller.utils.hooks import collect_all

extra_datas = []
extra_binaries = []
extra_hiddenimports = []

# Packages that require full collection (all submodules + data + binaries)
# License compatibility verified: all AGPL-3.0 / GPL-3.0 / MIT / BSD / Apache-2.0
collect_packages = [
    'certifi',             # MPL-2.0 — SSL CA certificates (cacert.pem required at runtime)
    'pymobiledevice3',     # GPL-3.0 — iOS device communication (161 submodules + resource files)
    'construct',           # MIT — binary data parsing (dynamic struct definitions)
    'srptools',            # MIT — SRP authentication protocol
    'opack2',              # MIT — Apple opack serialization format
    'bpylist2',            # MIT — Apple binary plist parsing
    'pycrashreport',       # GPL-3.0 — iOS crash report parsing
    'pygnuutils',          # GPL-3.0 — GNU utility wrappers
    'adb_shell',           # Apache-2.0 — Android ADB communication
    'dissect.fve',         # AGPL-3.0 — BitLocker/LUKS volume support (_native.pyd)
    'dissect.hypervisor',  # AGPL-3.0 — VMDK/VHD/VHDX/QCOW2/VDI disk images
    'dissect.cstruct',     # AGPL-3.0 — Binary structure parsing (dissect dependency)
    'dissect.util',        # AGPL-3.0 — Utility functions (_native.pyd)
    'dissect.fat',         # AGPL-3.0 — FAT/exFAT filesystem parsing
    'dissect.apfs',        # AGPL-3.0 — APFS filesystem parsing (macOS)
    'dissect.extfs',       # AGPL-3.0 — ext2/ext3/ext4 filesystem parsing (Linux)
    'dissect.xfs',         # AGPL-3.0 — XFS filesystem parsing (Linux)
    'dissect.btrfs',       # AGPL-3.0 — Btrfs filesystem parsing (Linux)
    'dissect.ffs',         # AGPL-3.0 — UFS/FFS filesystem parsing (FreeBSD)
    'dissect.ntfs',        # AGPL-3.0 — NTFS filesystem parsing
    'PyQt6',               # GPL-3.0 — GUI framework (3400+ data files: Qt6 DLLs, plugins, QML)
    'qh3',                 # MIT — QUIC/HTTP3 (_hazmat.pyd native, pymobiledevice3 remote)
    'aiohttp',             # Apache-2.0 — async HTTP (4 native .pyd extensions)
    'charset_normalizer',  # MIT — encoding detection (2 native .pyd extensions, requests dep)
    'cryptography',        # Apache-2.0/BSD — crypto primitives (_rust.pyd 9MB native)
]

for pkg in collect_packages:
    try:
        datas, binaries, hiddenimports = collect_all(pkg)
        extra_datas.extend(datas)
        extra_binaries.extend(binaries)
        extra_hiddenimports.extend(hiddenimports)
    except Exception as e:
        print(f"[WARN] collect_all('{pkg}') failed: {e}")

all_hidden_imports = list(set(all_hidden_imports + extra_hiddenimports))

# =============================================================================
# Platform-Specific Settings
# =============================================================================

if current_os == 'windows':
    exe_name = 'IntelligenceCollector'
    use_console = False
elif current_os == 'darwin':
    exe_name = 'IntelligenceCollector'
    use_console = False
else:
    # Linux
    exe_name = 'IntelligenceCollector'
    use_console = True  # Linux headless environments need console

# =============================================================================
# Analysis Configuration
# =============================================================================

a = Analysis(
    ['src/main.py'],
    pathex=[],
    binaries=usb_binaries + adb_binaries + extra_binaries,
    datas=[
        ('resources', 'resources'),
        ('config.json', '.'),
    ] + extra_datas,
    hiddenimports=all_hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

if current_os == 'darwin':
    # macOS: build .app bundle
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name=exe_name,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=use_console,
        disable_windowed_traceback=False,
        argv_emulation=True,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=False,
        name=exe_name,
    )
    app = BUNDLE(
        coll,
        name=f'{exe_name}.app',
        bundle_identifier='com.forensics.collector',
    )
else:
    # Windows & Linux: single-file binary
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name=exe_name,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=True,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=use_console,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
