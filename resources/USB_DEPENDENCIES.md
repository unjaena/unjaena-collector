# USB Dependencies for Mobile Device Collection

This document describes the USB components needed when collecting from Android
and iOS devices.

Pre-built Windows release binaries include ADB platform-tools as a fallback.
Source builds still need the Python packages and native USB libraries described
below.

## Platform Summary

| Platform | External software | Driver or native library | Collection path |
|----------|-------------------|--------------------------|-----------------|
| Android | None for release binaries; ADB or libusb for source builds | libusb / WinUSB as needed | USB direct or bundled ADB fallback |
| iOS | Apple Mobile Device Support on Windows | Apple Mobile Device USB driver | USB backup and device services |
| Linux source builds | System libusb packages | `libusb-1.0-0` and development headers | USB direct |
| macOS source builds | Homebrew libusb for Android | Native Apple services for iOS | USB direct |

## Android Setup

### Python Packages

```bash
pip install adb-shell[usb] libusb1 rsa
```

### Windows Native USB Library

Check whether the DLL can be found:

```bash
python build.py --check-deps
```

If `libusb-1.0.dll` is missing:

```bash
python build.py --download-libusb
```

If the helper cannot locate a DLL automatically, download libusb manually from
https://github.com/libusb/libusb/releases and copy the 64-bit DLL to:

```text
resources/libusb-1.0.dll
```

### Windows Driver Notes

Some Android devices require a WinUSB-compatible driver before direct USB access
works. Zadig can bind WinUSB to the selected Android interface, but it changes
the driver at the system level. Use it only when needed and only on the intended
device interface.

### Linux

```bash
sudo apt-get install libusb-1.0-0 libusb-1.0-0-dev
```

### macOS

```bash
brew install libusb
```

## iOS Setup

iOS collection on Windows requires Apple Mobile Device Support.

### Option 1: Install iTunes

Install iTunes from Microsoft Store or from Apple. This installs the required
Apple Mobile Device USB driver and service.

### Option 2: Install Driver Components Only

Advanced users can extract the iTunes installer and install:

- `AppleMobileDeviceSupport64.msi`
- `AppleApplicationSupport64.msi` if required by the installer version

Restart Windows after installation.

### macOS

macOS includes the native services required for iOS device communication.

## Build Verification

```bash
python build.py --check-deps
```

Expected Android dependency output includes:

```text
[USB] Checking USB dependencies for Android collection...
  [OK] adb-shell: installed
  [OK] libusb1: installed
  [OK] rsa: installed
  [OK] libusb-1.0.dll: <path>
```

## Troubleshooting

### Android device not found

1. Enable Developer Options and USB debugging on the Android device.
2. Reconnect the USB cable.
3. Accept the "Allow USB debugging" prompt on the device.
4. On Windows, check whether a device driver change is required.

### Android authorization failed

1. Revoke USB debugging authorizations on the device.
2. Remove stale local ADB keys if appropriate.
3. Reconnect the device and accept the authorization prompt again.

### iOS device not found

1. Confirm Apple Mobile Device Support is installed.
2. Unlock the iOS device.
3. Reconnect over USB.
4. Tap "Trust This Computer" on the device.
5. Confirm the Apple Mobile Device USB driver is visible in Device Manager.

### iOS trust dialog does not appear

Restart the Apple Mobile Device service:

```text
net stop "Apple Mobile Device Service"
net start "Apple Mobile Device Service"
```

If the prompt still does not appear, reset trust settings on the iOS device and
try again.
