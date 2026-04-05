"""
Hardware ID Generation Module

Creates a unique hardware identifier for device binding.
P0 Security Enhancement: Multi-component hardware collection to prevent tampering
Cross-platform: Windows (WMI), Linux (/etc/machine-id), macOS (ioreg)
"""
import hashlib
import subprocess
import platform
import sys
import os
from typing import Dict, Optional, Tuple


class HardwareIdError(Exception):
    """Hardware ID generation error"""
    pass


_IS_WINDOWS = sys.platform == 'win32'
_IS_MACOS = sys.platform == 'darwin'
_IS_LINUX = sys.platform.startswith('linux')


# =============================================================================
# Windows-specific collectors (WMI)
# =============================================================================

def _get_wmi():
    """Return WMI object (Windows only)"""
    try:
        import wmi
        return wmi.WMI()
    except ImportError:
        raise HardwareIdError("WMI module is not installed")
    except Exception as e:
        raise HardwareIdError(f"WMI initialization failed: {e}")


def _win_get_cpu_id() -> Optional[str]:
    try:
        c = _get_wmi()
        cpu = c.Win32_Processor()[0]
        cpu_id = cpu.ProcessorId.strip() if cpu.ProcessorId else None
        return cpu_id if cpu_id else None
    except Exception:
        return None


def _win_get_disk_serial() -> Optional[str]:
    try:
        c = _get_wmi()
        disk = c.Win32_DiskDrive()[0]
        serial = disk.SerialNumber.strip() if disk.SerialNumber else None
        return serial if serial else None
    except Exception:
        return None


def _win_get_mac_address() -> Optional[str]:
    try:
        c = _get_wmi()
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            mac = nic.MACAddress
            if mac:
                return mac
        return None
    except Exception:
        return None


def _win_get_bios_serial() -> Optional[str]:
    try:
        c = _get_wmi()
        bios = c.Win32_BIOS()[0]
        serial = bios.SerialNumber.strip() if bios.SerialNumber else None
        if serial and serial.lower() not in ['none', 'to be filled by o.e.m.', 'default string']:
            return serial
        return None
    except Exception:
        return None


def _win_get_baseboard_serial() -> Optional[str]:
    try:
        c = _get_wmi()
        board = c.Win32_BaseBoard()[0]
        serial = board.SerialNumber.strip() if board.SerialNumber else None
        if serial and serial.lower() not in ['none', 'to be filled by o.e.m.', 'default string']:
            return serial
        return None
    except Exception:
        return None


def _win_get_volume_serial() -> Optional[str]:
    try:
        c = _get_wmi()
        for vol in c.Win32_LogicalDisk():
            if vol.DeviceID == 'C:':
                serial = vol.VolumeSerialNumber
                return serial if serial else None
        return None
    except Exception:
        return None


# =============================================================================
# Linux-specific collectors
# =============================================================================

def _linux_get_machine_id() -> Optional[str]:
    """Read /etc/machine-id (systemd) or /var/lib/dbus/machine-id"""
    for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
        try:
            with open(path, 'r') as f:
                mid = f.read().strip()
                if mid:
                    return mid
        except (IOError, OSError):
            continue
    return None


def _linux_get_cpu_id() -> Optional[str]:
    """Extract CPU serial/model from /proc/cpuinfo"""
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('Serial') or line.startswith('model name'):
                    return line.split(':', 1)[1].strip()
    except (IOError, OSError):
        pass
    return None


# =============================================================================
# macOS-specific collectors
# =============================================================================

def _macos_get_serial() -> Optional[str]:
    """Get macOS hardware serial via ioreg"""
    try:
        result = subprocess.run(
            ['ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if 'IOPlatformSerialNumber' in line:
                return line.split('"')[-2]
    except Exception:
        pass
    return None


def _macos_get_hardware_uuid() -> Optional[str]:
    """Get macOS hardware UUID via ioreg"""
    try:
        result = subprocess.run(
            ['ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if 'IOPlatformUUID' in line:
                return line.split('"')[-2]
    except Exception:
        pass
    return None


# =============================================================================
# Cross-platform public API (backward compatible)
# =============================================================================

# Keep old function names as aliases for Windows callers
get_cpu_id = _win_get_cpu_id
get_disk_serial = _win_get_disk_serial
get_mac_address = _win_get_mac_address
get_bios_serial = _win_get_bios_serial
get_baseboard_serial = _win_get_baseboard_serial
get_volume_serial = _win_get_volume_serial


def get_hardware_components() -> Dict[str, Optional[str]]:
    """
    Collect all hardware identifiers (P0 security enhancement).
    Cross-platform: dispatches to OS-specific collectors.

    Returns:
        dict: Identifiers for each hardware component
    """
    if _IS_WINDOWS:
        return {
            'cpu_id': _win_get_cpu_id(),
            'disk_serial': _win_get_disk_serial(),
            'mac_address': _win_get_mac_address(),
            'bios_serial': _win_get_bios_serial(),
            'baseboard_serial': _win_get_baseboard_serial(),
            'volume_serial': _win_get_volume_serial(),
        }
    elif _IS_LINUX:
        return {
            'machine_id': _linux_get_machine_id(),
            'cpu_id': _linux_get_cpu_id(),
            'hostname': platform.node() or None,
        }
    elif _IS_MACOS:
        return {
            'serial': _macos_get_serial(),
            'hardware_uuid': _macos_get_hardware_uuid(),
            'hostname': platform.node() or None,
        }
    else:
        return {
            'hostname': platform.node() or None,
        }


def _default_require_minimum() -> int:
    """Return the default minimum component count for the current OS."""
    if _IS_WINDOWS:
        return 3
    # Linux/macOS: fewer WMI-like sources available
    return 1


def get_hardware_id(require_minimum: int = None) -> str:
    """
    Generate a unique hardware identifier.
    P0 security enhancement: Multi-component collection and minimum requirements validation

    Args:
        require_minimum: Minimum number of valid components required.
                         Defaults to 3 (Windows) or 1 (Linux/macOS).

    Returns:
        str: SHA256 hash of combined hardware identifiers (first 32 chars)

    Raises:
        HardwareIdError: When minimum requirements are not met
    """
    if require_minimum is None:
        require_minimum = _default_require_minimum()

    try:
        components = get_hardware_components()

        # Filter only valid components
        valid_components = {k: v for k, v in components.items() if v}

        if len(valid_components) < require_minimum:
            raise HardwareIdError(
                f"Unable to collect sufficient hardware identifiers. "
                f"Required: {require_minimum}, Collected: {len(valid_components)} "
                f"(Collected components: {list(valid_components.keys())})"
            )

        # Generate hash from sorted values (maintain consistency)
        combined = '-'.join(sorted(valid_components.values()))
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    except HardwareIdError:
        raise
    except Exception as e:
        # [Security] Do NOT fall back to weak hardware ID — fail explicitly
        import logging
        logger = logging.getLogger(__name__)
        logger.error(
            f"[HardwareID] Hardware collection failed — aborting.\n"
            f"  Cause: {e}\n"
            f"  Action: Ensure WMI/registry access is available."
        )
        raise HardwareIdError(
            f"Hardware ID generation failed: {e}. "
            f"Cannot proceed with weak fallback for security reasons."
        )


def get_hardware_id_with_components(require_minimum: int = None) -> Tuple[str, Dict[str, Optional[str]]]:
    """
    Return hardware ID and individual components (for server binding)

    Returns:
        tuple: (hardware_id, components_dict)
    """
    if require_minimum is None:
        require_minimum = _default_require_minimum()

    components = get_hardware_components()
    valid_components = {k: v for k, v in components.items() if v}

    if len(valid_components) < require_minimum:
        raise HardwareIdError(
            f"Unable to collect sufficient hardware identifiers. "
            f"Required: {require_minimum}, Collected: {len(valid_components)}"
        )

    combined = '-'.join(sorted(valid_components.values()))
    hardware_id = hashlib.sha256(combined.encode()).hexdigest()[:32]

    return hardware_id, components


def get_system_info() -> dict:
    """
    Get system information for logging.

    Returns:
        dict: System information
    """
    if _IS_WINDOWS:
        try:
            c = _get_wmi()

            os_info = c.Win32_OperatingSystem()[0]
            cpu_info = c.Win32_Processor()[0]

            from core.updater import get_current_version
            return {
                'os_name': os_info.Caption,
                'os_version': os_info.Version,
                'cpu_name': cpu_info.Name,
                'cpu_cores': cpu_info.NumberOfCores,
                'hostname': platform.node(),
                'platform': platform.platform(),
                'version': get_current_version(),
                'hardware_id': get_hardware_id(),
                'hardware_components': get_hardware_components(),
            }
        except Exception as e:
            return {
                'hostname': platform.node(),
                'platform': platform.platform(),
                'version': get_current_version(),
                'hardware_id': get_hardware_id(),
                'error': str(e),
            }
    else:
        # Linux / macOS
        from core.updater import get_current_version
        return {
            'os_name': platform.system(),
            'os_version': platform.release(),
            'hostname': platform.node(),
            'platform': platform.platform(),
            'version': get_current_version(),
            'hardware_id': get_hardware_id(),
            'hardware_components': get_hardware_components(),
        }
