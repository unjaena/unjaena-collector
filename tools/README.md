# Collector Tools

Directory for tools required by the iOS forensic collection module.

## pymobiledevice3

A pure-Python library for communicating directly with iOS devices over USB.

### Installation

```bash
pip install pymobiledevice3
```

### Features

| Feature | Description |
|---------|-------------|
| Device enumeration | List iOS devices connected via USB |
| Device info | UDID, model, iOS version, and other details |
| System logs | Real-time iOS system log collection |
| Crash reports | Extract application crash reports |
| Installed apps | List installed applications |
| Backup creation | Create iOS backups |

### License

pymobiledevice3 is distributed under the **GPL-3.0** license.

- Project: https://github.com/doronz88/pymobiledevice3
- License: https://www.gnu.org/licenses/gpl-3.0.html

### Requirements

- iOS device connected via USB
- "Trust This Computer" must be approved on the device
- On Windows, iTunes or Apple Mobile Device Support drivers are required

### Troubleshooting

**"Device not found"**
1. Check USB cable and connection
2. Unlock the device
3. Look for the "Trust This Computer" prompt
4. Verify iTunes is installed (includes required drivers)

**"Pairing error"**
1. Re-confirm "Trust This Computer" on the device
2. Windows: run as administrator
3. macOS/Linux: use `sudo`

**"pymobiledevice3 installation failed"**
```bash
# Upgrade pip
pip install --upgrade pip

# Force reinstall
pip install --force-reinstall pymobiledevice3
```

### Code Example

```python
from pymobiledevice3.usbmux import list_devices
from pymobiledevice3.lockdown import create_using_usbmux

# List connected devices
devices = list_devices()
for device in devices:
    print(f"UDID: {device.serial}")

# Query device info
if devices:
    lockdown = create_using_usbmux(serial=devices[0].serial)
    info = lockdown.all_values
    print(f"Device: {info.get('DeviceName')}")
    print(f"iOS: {info.get('ProductVersion')}")
```
