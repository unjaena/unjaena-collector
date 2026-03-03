# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from pathlib import Path

# =============================================================================
# USB Library Detection for Android Collector
# =============================================================================

def find_libusb_dll():
    """Find libusb-1.0.dll for bundling with the application"""
    dll_locations = []

    # Check common installation locations
    possible_paths = [
        # Project resources folder
        Path('resources/libusb-1.0.dll'),
        # System paths
        Path(os.environ.get('PROGRAMFILES', 'C:/Program Files')) / 'libusb-1.0' / 'MS64' / 'libusb-1.0.dll',
        Path(os.environ.get('PROGRAMFILES(X86)', 'C:/Program Files (x86)')) / 'libusb-1.0' / 'MS32' / 'libusb-1.0.dll',
        # Python site-packages (if installed via pip)
    ]

    # Check if libusb1 package has bundled DLL
    try:
        import usb1
        usb1_path = Path(usb1.__file__).parent
        dll_in_package = usb1_path / 'libusb-1.0.dll'
        if dll_in_package.exists():
            possible_paths.insert(0, dll_in_package)
    except ImportError:
        pass

    # Also check PATH
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
        print("[USB] Download from: https://github.com/libusb/libusb/releases")
        print("[USB] Place libusb-1.0.dll in collector/resources/ folder")

    return dll_locations


# Find USB binaries
usb_binaries = find_libusb_dll()

# =============================================================================
# Hidden Imports for USB Libraries
# =============================================================================

usb_hidden_imports = [
    # ===========================================
    # Android USB (adb-shell)
    # ===========================================
    'adb_shell',
    'adb_shell.adb_device',
    'adb_shell.adb_device_usb',
    'adb_shell.auth',
    'adb_shell.auth.keygen',
    'adb_shell.auth.sign_pythonrsa',
    'adb_shell.exceptions',
    'adb_shell.handle',
    'adb_shell.transport',

    # libusb1 library
    'usb1',
    'libusb1',

    # RSA for ADB key generation
    'rsa',

    # ===========================================
    # iOS USB (pymobiledevice3)
    # ===========================================
    'pymobiledevice3',
    'pymobiledevice3.usbmux',
    'pymobiledevice3.lockdown',
    'pymobiledevice3.services',
    'pymobiledevice3.services.afc',
    'pymobiledevice3.services.installation_proxy',
    'pymobiledevice3.services.house_arrest',
    'pymobiledevice3.services.diagnostics',
    'pymobiledevice3.services.syslog',
    'pymobiledevice3.exceptions',
    'pymobiledevice3.common',

    # iOS backup parsing
    'biplist',

    # iOS encrypted backup decryption
    'iphone_backup_decrypt',
    'collectors.ios_backup_decryptor',

    # ===========================================
    # Cryptography (shared)
    # ===========================================
    'Crypto',
    'Crypto.Cipher',
    'Crypto.Cipher.AES',
    'Crypto.Util',
    'Crypto.Util.Padding',
    'cryptography',
    'cryptography.hazmat',
    'cryptography.hazmat.primitives',
    'cryptography.hazmat.backends',
]

# =============================================================================
# Analysis Configuration
# =============================================================================

a = Analysis(
    ['src\\main.py'],
    pathex=[],
    binaries=usb_binaries,
    # config.json: Server URL configuration for deployment
    # Development build: config.development.json -> config.json
    # Production build: config.production.json -> config.json
    datas=[
        ('resources', 'resources'),
        ('config.json', '.'),  # Include config.json at root
    ],
    hiddenimports=usb_hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='IntelligenceCollector',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
