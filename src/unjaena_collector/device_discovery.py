from __future__ import annotations

import asyncio
import ctypes
import hashlib
import inspect
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


def _safe_exception(exc: BaseException) -> str:
    message = str(exc).strip() or exc.__class__.__name__
    return " ".join(message.split())[:160]


async def _await_or_collect(value: Any) -> Any:
    if hasattr(value, "__aiter__"):
        return [item async for item in value]
    return await value


def _run_async_from_running_loop(value: Any) -> Any:
    import threading

    result: dict[str, Any] = {}

    def target() -> None:
        try:
            result["value"] = asyncio.run(_await_or_collect(value))
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout=10)
    if thread.is_alive():
        raise TimeoutError("async device probe timed out")
    if "error" in result:
        raise result["error"]
    return result.get("value")


def _resolve_maybe_async(value: Any) -> Any:
    if not inspect.isawaitable(value) and not hasattr(value, "__aiter__"):
        return value
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_await_or_collect(value))
    return _run_async_from_running_loop(value)


def _path_device_id(prefix: str, path: Path) -> str:
    digest = hashlib.sha1(str(path).encode("utf-8", "ignore")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def _diagnostic_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    try:
        return [str(item) for item in value if item]
    except TypeError:
        return [str(value)]


def _probe(label: str, func: Any) -> tuple[list[DeviceInfo], list[str]]:
    try:
        result = _resolve_maybe_async(func())
        if isinstance(result, tuple) and len(result) == 2:
            devices_raw, diagnostics_raw = result
        else:
            devices_raw, diagnostics_raw = result, []
        devices = [device for device in list(devices_raw or []) if isinstance(device, DeviceInfo)]
        diagnostics = _diagnostic_list(diagnostics_raw)
        return devices, diagnostics
    except Exception as exc:
        return [], [f"{label}: scan failed ({exc.__class__.__name__}: {_safe_exception(exc)})"]


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


def _mounted_volume_roots() -> list[Path]:
    if sys.platform == "win32":
        return []
    home = Path.home()
    roots: list[Path] = []
    if sys.platform == "darwin":
        roots.append(Path("/Volumes"))
    elif sys.platform.startswith("linux"):
        roots.extend([Path("/media"), Path("/run/media"), Path("/mnt")])
        roots.append(home / "media")
    return roots


def _mounted_volumes() -> tuple[list[DeviceInfo], str]:
    if sys.platform == "win32":
        return [], "Mounted volumes: handled through Windows logical drives."
    devices: list[DeviceInfo] = []
    seen: set[str] = set()
    for root in _mounted_volume_roots():
        if not root.exists() or not root.is_dir():
            continue
        candidates: list[Path] = []
        try:
            if root.name in {"media"} and root.parent.name in {"run", ""}:
                for user_dir in root.iterdir():
                    if user_dir.is_dir():
                        candidates.extend([item for item in user_dir.iterdir() if item.is_dir()])
            else:
                candidates.extend([item for item in root.iterdir() if item.is_dir()])
        except Exception:
            continue
        for item in candidates:
            try:
                resolved = str(item.resolve())
            except Exception:
                resolved = str(item)
            if resolved in seen or resolved == "/":
                continue
            seen.add(resolved)
            label = item.name or resolved
            devices.append(DeviceInfo(
                device_id=_path_device_id("mounted_volume", item),
                kind="mounted_volume",
                label=f"Mounted volume - {label}",
                detail="Mounted USB/removable or external filesystem detected. Collection is controlled by the authenticated server profile.",
                size_bytes=_disk_usage(str(item)),
                source_path=item,
                live_local=True,
                metadata={"path": str(item)},
            ))
    return devices, "Mounted volumes: ready." if devices else "Mounted volumes: no additional mounted volume detected."


def _linux_block_devices() -> tuple[list[DeviceInfo], str]:
    if not sys.platform.startswith("linux"):
        return [], "Linux block devices: not applicable."
    lsblk = shutil.which("lsblk")
    if not lsblk:
        return [], "Linux block devices: lsblk is not available."
    result = _run([lsblk, "-J", "-b", "-o", "NAME,TYPE,SIZE,MODEL,TRAN,RM,MOUNTPOINT,LABEL"], timeout=5)
    if not result or result.returncode != 0:
        return [], "Linux block devices: lsblk did not respond."
    try:
        payload = json.loads(result.stdout or "{}")
    except Exception as exc:
        return [], f"Linux block devices: invalid lsblk output ({_safe_exception(exc)})."
    devices: list[DeviceInfo] = []

    def visit(items: list[dict[str, Any]]) -> None:
        for item in items:
            name = str(item.get("name") or "")
            dtype = str(item.get("type") or "")
            if name and dtype in {"disk", "part"}:
                model = str(item.get("model") or "").strip()
                tran = str(item.get("tran") or "").strip()
                label = str(item.get("label") or "").strip()
                mountpoint = str(item.get("mountpoint") or "").strip()
                removable = bool(item.get("rm")) or tran == "usb"
                title = label or model or name
                prefix = "USB block device" if removable else "Block device"
                path = Path("/dev") / name
                devices.append(DeviceInfo(
                    device_id=f"linux_block_{name.replace('/', '_')}",
                    kind="linux_block_device",
                    label=f"{prefix} - {title}",
                    status="ready" if is_root_process() else "limited",
                    detail="Raw block device detected. Administrator/root privileges and a server-authorized profile are required for physical acquisition.",
                    size_bytes=int(item.get("size") or 0),
                    source_path=path,
                    selectable=False,
                    metadata={"path": str(path), "type": dtype, "transport": tran, "mountpoint": mountpoint, "removable": removable},
                ))
            children = item.get("children") or []
            if isinstance(children, list):
                visit(children)

    visit(list(payload.get("blockdevices") or []))
    return devices, "Linux block devices: ready." if devices else "Linux block devices: no block device detected."


def _macos_physical_disks() -> tuple[list[DeviceInfo], str]:
    if sys.platform != "darwin":
        return [], "macOS disks: not applicable."
    diskutil = shutil.which("diskutil")
    if not diskutil:
        return [], "macOS disks: diskutil is not available."
    result = _run([diskutil, "list", "-plist"], timeout=8)
    if not result or result.returncode != 0:
        return [], "macOS disks: diskutil did not respond."
    try:
        payload = plistlib.loads((result.stdout or "").encode("utf-8"))
    except Exception as exc:
        return [], f"macOS disks: invalid diskutil output ({_safe_exception(exc)})."
    devices: list[DeviceInfo] = []
    for item in payload.get("AllDisksAndPartitions") or []:
        identifier = str(item.get("DeviceIdentifier") or "")
        if not identifier:
            continue
        name = str(item.get("VolumeName") or item.get("Content") or identifier)
        size = int(item.get("Size") or 0)
        path = Path("/dev") / f"r{identifier}"
        devices.append(DeviceInfo(
            device_id=f"macos_disk_{identifier}",
            kind="macos_disk",
            label=f"Disk - {name}",
            status="ready" if is_root_process() else "limited",
            detail="Physical disk detected. Administrator/root privileges and a server-authorized profile are required for physical acquisition.",
            size_bytes=size,
            source_path=path,
            selectable=False,
            metadata={"identifier": identifier, "path": str(path)},
        ))
    return devices, "macOS disks: ready." if devices else "macOS disks: no disk detected."


def is_root_process() -> bool:
    if hasattr(os, "geteuid"):
        try:
            return os.geteuid() == 0
        except Exception:
            return False
    return False


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
        connected = _resolve_maybe_async(list_devices())
    except Exception:
        return [], "iOS USB: Apple Mobile Device service/usbmux is not available."
    if connected is None:
        connected = []
    try:
        connected_list = list(connected)
    except TypeError:
        return [], "iOS USB: Apple Mobile Device service returned an unsupported device list."
    for device in connected_list:
        serial = getattr(device, "serial", "") or getattr(device, "udid", "") or "unknown"
        try:
            lockdown = _resolve_maybe_async(create_using_usbmux(serial=serial))
            values_attr = getattr(lockdown, "all_values", {})
            values = _resolve_maybe_async(values_attr() if callable(values_attr) else values_attr)
            if not isinstance(values, dict):
                values = {}
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
    devices: list[DeviceInfo] = []
    diagnostics: list[str] = []
    probes = (
        ("Local filesystem", lambda: ([_local_device()], "Local filesystem: ready.")),
        ("Mounted volumes", _mounted_volumes),
        ("Windows logical volumes", _windows_logical_volumes),
        ("Windows physical disks", _windows_physical_disks),
        ("Linux block devices", _linux_block_devices),
        ("macOS disks", _macos_physical_disks),
        ("Android USB", _adb_devices),
        ("iOS USB", _ios_usb_devices),
        ("iOS backups", _ios_backups),
    )
    for label, func in probes:
        probe_devices, probe_diagnostics = _probe(label, func)
        devices.extend(probe_devices)
        diagnostics.extend(probe_diagnostics)
    if not devices:
        fallback, fallback_diag = _probe("Local filesystem fallback", lambda: ([_local_device()], "Local filesystem: fallback ready."))
        devices.extend(fallback)
        diagnostics.extend(fallback_diag)
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
