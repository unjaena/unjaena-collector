# USB Dependencies for Mobile Device Collection

This folder contains USB-related dependencies required for Android and iOS device collection.

---

## Platform Comparison

| Platform | External Software | USB Driver | Collection |
|----------|------------------|------------|------------|
| **Android** | None (included in EXE) | libusb-1.0.dll (bundled) | USB direct ✅ |
| **iOS** | iTunes or Apple Driver | Apple Mobile Device | USB via usbmux |

---

## Required Files

### libusb-1.0.dll (Windows)

The `libusb-1.0.dll` file is required for USB communication with Android devices.

**Automatic Download:**
```bash
python build.py --download-libusb
```

**Manual Installation:**
1. Download from: https://github.com/libusb/libusb/releases
2. Extract the archive
3. Copy `VS2022/MS64/dll/libusb-1.0.dll` to this folder

## Python Packages

Install required Python packages:
```bash
pip install adb-shell[usb] libusb1 rsa
```

## Build Verification

Check all USB dependencies before building:
```bash
python build.py --check-deps
```

Expected output:
```
[USB] Checking USB dependencies for Android collection...
  [OK] adb-shell: installed
  [OK] libusb1: installed
  [OK] rsa: installed
  [OK] libusb-1.0.dll: collector/resources/libusb-1.0.dll

[USB] All USB dependencies are ready!
```

## Platform-Specific Notes

### Windows
- Requires `libusb-1.0.dll` in this folder or in PATH
- May need Zadig (https://zadig.akeo.ie/) to install USB drivers for Android devices

### Linux
```bash
sudo apt-get install libusb-1.0-0 libusb-1.0-0-dev
```

### macOS
```bash
brew install libusb
```

## Troubleshooting

### "USB libraries not available"
- Install: `pip install adb-shell[usb] libusb1`
- Ensure libusb-1.0.dll is in this folder (Windows)

### "Device not found"
1. Enable USB debugging on Android device
2. Connect via USB cable
3. Accept "Allow USB debugging" prompt on device
4. On Windows: Install USB driver via Zadig if needed

### "Auth failed"
- Accept USB debugging authorization on the Android device
- Delete `~/.android/adbkey*` and retry (will regenerate keys)

---

# iOS Device Collection

## Requirements

iOS collection requires Apple Mobile Device Support, which is provided by iTunes.

### Option 1: Install iTunes (Recommended)
Download and install iTunes from:
- Microsoft Store: https://apps.microsoft.com/detail/9PB2MZ1ZMB1S
- Apple Website: https://www.apple.com/itunes/download/

### Option 2: Minimal Driver Only (Advanced)
If you don't want the full iTunes application:

1. Download iTunes installer (Windows 64-bit) from Apple
2. Extract using 7-Zip or WinRAR:
   - Right-click on `iTunes64Setup.exe` → Extract
3. Inside extracted folder, find and install:
   - `AppleMobileDeviceSupport64.msi` (Required)
   - `AppleApplicationSupport64.msi` (May be required)
4. Restart computer after installation

### Option 3: Network Tunnel (iOS 17.4+)
For iOS 17.4 and later, you can use WiFi connection instead of USB:
1. Connect device to same WiFi network as computer
2. Enable WiFi sync in device settings
3. Collection tool will detect device over network

## Troubleshooting

### "No iOS devices found"
1. Ensure iTunes or Apple Mobile Device Support is installed
2. Connect iOS device via USB cable
3. Unlock device and tap "Trust This Computer" when prompted
4. Check Device Manager for "Apple Mobile Device USB Driver"

### "Trust dialog not appearing"
1. Disconnect and reconnect USB cable
2. Restart Apple Mobile Device Service:
   ```
   net stop "Apple Mobile Device Service"
   net start "Apple Mobile Device Service"
   ```
3. Restart computer if needed

### "Pairing failed"
1. Go to iOS Settings > General > Transfer or Reset iPhone > Reset
2. Select "Reset Location & Privacy"
3. Reconnect and trust again

---

# macOS Notes

### Android on macOS
```bash
brew install libusb
pip install adb-shell[usb] libusb1
```

### iOS on macOS
No additional installation required - macOS includes native iOS device support.
