from __future__ import annotations

import ctypes
import json
import os
import platform
import plistlib
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DeviceInfo:
    device_id: str
    kind: str
    label: str
    status: str = "ready"
    detail: str = ""
    size_bytes: int = 0
    source_path: Path | None = None
    artifact_type: str | None = None
    live_local: bool = False
    selectable: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def size_label(self) -> str:
        if self.size_bytes <= 0:
            return ""
        value = float(self.size_bytes)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if value < 1024 or unit == "TB":
                return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
            value /= 1024
        return ""


def _run(args: list[str], timeout: int = 4) -> subprocess.CompletedProcess[str] | None:
    try:
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        return subprocess.run(args, text=True, capture_output=True, timeout=timeout, creationflags=flags)
    except Exception:
        return None


def _disk_usage(path: str) -> int:
    try:
        return shutil.disk_usage(path).total
    except Exception:
        return 0


def _local_device() -> DeviceInfo:
    system = platform.system() or "Unknown"
    name = platform.node() or "This computer"
    if sys.platform == "darwin":
        label = f"{name} - macOS live filesystem"
        kind = "local_macos"
    elif sys.platform.startswith("linux"):
        label = f"{name} - Linux live filesystem"
        kind = "local_linux"
    elif sys.platform == "win32":
        label = f"{name} - Windows live filesystem"
        kind = "local_windows"
    else:
        label = f"{name} - {system} live filesystem"
        kind = "local_system"
    return DeviceInfo(
        device_id="local_system",
        kind=kind,
        label=label,
        detail="Uses the authenticated server profile for local filesystem collection.",
        size_bytes=_disk_usage("/" if sys.platform != "win32" else os.environ.get("SystemDrive", "C:") + "\\"),
        live_local=True,
        metadata={"platform": platform.platform(), "hostname": name},
    )


def _windows_logical_volumes() -> list[DeviceInfo]:
    if sys.platform != "win32":
        return []
    devices: list[DeviceInfo] = []
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()
    except Exception:
        return devices
    for index in range(26):
        if not (mask & (1 << index)):
            continue
        letter = chr(65 + index)
        root = f"{letter}:\\"
        dtype = ctypes.windll.kernel32.GetDriveTypeW(root)
        type_name = {
            2: "Removable volume",
            3: "Fixed volume",
            4: "Network volume",
            5: "Optical volume",
        }.get(dtype, "Volume")
        devices.append(DeviceInfo(
            device_id=f"volume_{letter.lower()}",
            kind="windows_volume",
            label=f"{type_name} {letter}:",
            detail="Selectable for server-profile local filesystem collection.",
            size_bytes=_disk_usage(root),
            live_local=True,
            metadata={"root": root, "drive_type": dtype},
        ))
    return devices


def _windows_physical_disks() -> list[DeviceInfo]:
    if sys.platform != "win32":
        return []
    try:
        import wmi  # type: ignore
    except Exception:
        return []
    devices: list[DeviceInfo] = []
    try:
        conn = wmi.WMI()
        for disk in conn.Win32_DiskDrive():
            index = getattr(disk, "Index", None)
            model = getattr(disk, "Model", None) or f"Disk {index}"
            size = int(getattr(disk, "Size", 0) or 0)
            interface = getattr(disk, "InterfaceType", "") or ""
            devices.append(DeviceInfo(
                device_id=f"physical_disk_{index}",
                kind="windows_physical_disk",
                label=f"{model} ({index})",
                detail=f"{interface} physical disk detected. Raw disk imaging remains server-authorized.",
                size_bytes=size,
                live_local=True,
                metadata={"index": index, "interface": interface},
            ))
    except Exception:
        return []
    return devices


def _adb_devices() -> tuple[list[DeviceInfo], str]:
    adb = shutil.which("adb")
    if not adb:
        return [], "Android USB: adb is not available. Install Android platform-tools or use a mobile extraction bundle."
    result = _run([adb, "devices", "-l"], timeout=6)
    if not result or result.returncode != 0:
        return [], "Android USB: adb did not respond."
    devices: list[DeviceInfo] = []
    for line in result.stdout.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        serial = parts[0]
        state = parts[1] if len(parts) > 1 else "unknown"
        fields: dict[str, str] = {}
        for part in parts[2:]:
            if ":" in part:
                key, value = part.split(":", 1)
                fields[key] = value
        model = fields.get("model", "Android device").replace("_", " ")
        selectable = state == "device"
        detail = "USB debugging authorized." if selectable else f"ADB state: {state}. Unlock the device and allow USB debugging."
        devices.append(DeviceInfo(
            device_id=f"android_{serial}",
            kind="android_usb",
            label=f"Android USB - {model}",
            status="ready" if selectable else "locked",
            detail=detail,
            selectable=selectable,
            metadata={"serial_suffix": serial[-8:], "adb_state": state, **fields},
        ))
    return devices, "Android USB: ready." if devices else "Android USB: no device detected."


def _ios_usb_devices() -> tuple[list[DeviceInfo], str]:
    try:
        from pymobiledevice3.usbmux import list_devices  # type: ignore
        from pymobiledevice3.lockdown import create_using_usbmux  # type: ignore
    except Exception:
        return [], "iOS USB: pymobiledevice3 is not available in this build."
    devices: list[DeviceInfo] = []
    try:
        connected = list_devices()
    except Exception:
        return [], "iOS USB: Apple Mobile Device service/usbmux is not available."
    for device in connected:
        serial = getattr(device, "serial", "") or "unknown"
        try:
            lockdown = create_using_usbmux(serial=serial)
            values = lockdown.all_values
            name = values.get("DeviceName") or "iOS device"
            product = values.get("ProductType") or "unknown"
            version = values.get("ProductVersion") or "unknown"
            devices.append(DeviceInfo(
                device_id=f"ios_{serial}",
                kind="ios_usb",
                label=f"iOS USB - {name}",
                detail=f"{product}, iOS {version}. Trusted USB device detected.",
                selectable=True,
                metadata={"udid_suffix": serial[-8:], "product_type": product, "ios_version": version},
            ))
        except Exception:
            devices.append(DeviceInfo(
                device_id=f"ios_{serial}",
                kind="ios_usb",
                label=f"iOS USB - {serial[:8]}...",
                status="locked",
                detail="Device detected but not paired. Unlock it and tap Trust on the device.",
                selectable=False,
                metadata={"udid_suffix": serial[-8:]},
            ))
    return devices, "iOS USB: ready." if devices else "iOS USB: no device detected."


def _ios_backup_roots() -> list[Path]:
    roots: list[Path] = []
    home = Path.home()
    if sys.platform == "darwin":
        roots.append(home / "Library" / "Application Support" / "MobileSync" / "Backup")
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            roots.append(Path(appdata) / "Apple Computer" / "MobileSync" / "Backup")
        roots.append(home / "Apple" / "MobileSync" / "Backup")
    else:
        roots.append(home / ".config" / "libimobiledevice" / "backup")
    return roots


def _ios_backups() -> list[DeviceInfo]:
    devices: list[DeviceInfo] = []
    for root in _ios_backup_roots():
        if not root.exists():
            continue
        for item in root.iterdir():
            if not item.is_dir():
                continue
            info_path = item / "Info.plist"
            name = item.name[:12]
            version = ""
            encrypted = False
            if info_path.exists():
                try:
                    with info_path.open("rb") as handle:
                        data = plistlib.load(handle)
                    name = str(data.get("Device Name") or data.get("Display Name") or name)
                    version = str(data.get("Product Version") or "")
                    encrypted = bool(data.get("IsEncrypted"))
                except Exception:
                    pass
            devices.append(DeviceInfo(
                device_id=f"ios_backup_{item.name}",
                kind="ios_backup",
                label=f"iOS backup - {name}",
                status="locked" if encrypted else "ready",
                detail=(f"iOS {version}. " if version else "") + "Finder/iTunes backup directory detected.",
                source_path=item,
                artifact_type="mobile_ffs_bundle",
                selectable=True,
                metadata={"path": str(item), "encrypted": encrypted},
            ))
    return devices


def discover_devices() -> tuple[list[DeviceInfo], list[str]]:
    devices: list[DeviceInfo] = [_local_device()]
    diagnostics: list[str] = []
    devices.extend(_windows_logical_volumes())
    devices.extend(_windows_physical_disks())
    android_devices, android_diag = _adb_devices()
    ios_devices, ios_diag = _ios_usb_devices()
    devices.extend(android_devices)
    devices.extend(ios_devices)
    devices.extend(_ios_backups())
    diagnostics.extend([android_diag, ios_diag])
    unique: dict[str, DeviceInfo] = {}
    for device in devices:
        unique.setdefault(device.device_id, device)
    return list(unique.values()), diagnostics


def snapshot_json() -> str:
    devices, diagnostics = discover_devices()
    payload = {
        "host": platform.node(),
        "platform": platform.platform(),
        "devices": [
            {
                "id": d.device_id,
                "kind": d.kind,
                "label": d.label,
                "status": d.status,
                "detail": d.detail,
                "size": d.size_bytes,
                "metadata": d.metadata,
            }
            for d in devices
        ],
        "diagnostics": diagnostics,
    }
    return json.dumps(payload, indent=2, sort_keys=True)
