"""
Hardware ID Generation Module

Creates a unique hardware identifier for device binding.
P0 Security Enhancement: Multi-component hardware collection to prevent tampering
"""
import hashlib
import subprocess
import platform
from typing import Dict, Optional, Tuple


class HardwareIdError(Exception):
    """Hardware ID generation error"""
    pass


def _get_wmi():
    """Return WMI object"""
    try:
        import wmi
        return wmi.WMI()
    except ImportError:
        raise HardwareIdError("WMI module is not installed")
    except Exception as e:
        raise HardwareIdError(f"WMI initialization failed: {e}")


def get_cpu_id() -> Optional[str]:
    """Retrieve CPU ID"""
    try:
        c = _get_wmi()
        cpu = c.Win32_Processor()[0]
        cpu_id = cpu.ProcessorId.strip() if cpu.ProcessorId else None
        return cpu_id if cpu_id else None
    except Exception:
        return None


def get_disk_serial() -> Optional[str]:
    """Retrieve disk serial number"""
    try:
        c = _get_wmi()
        disk = c.Win32_DiskDrive()[0]
        serial = disk.SerialNumber.strip() if disk.SerialNumber else None
        return serial if serial else None
    except Exception:
        return None


def get_mac_address() -> Optional[str]:
    """Retrieve MAC address"""
    try:
        c = _get_wmi()
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            mac = nic.MACAddress
            if mac:
                return mac
        return None
    except Exception:
        return None


def get_bios_serial() -> Optional[str]:
    """Retrieve BIOS serial number (P0 addition)"""
    try:
        c = _get_wmi()
        bios = c.Win32_BIOS()[0]
        serial = bios.SerialNumber.strip() if bios.SerialNumber else None
        # Exclude placeholder values common in virtualized environments
        if serial and serial.lower() not in ['none', 'to be filled by o.e.m.', 'default string']:
            return serial
        return None
    except Exception:
        return None


def get_baseboard_serial() -> Optional[str]:
    """Retrieve motherboard serial number (P0 addition)"""
    try:
        c = _get_wmi()
        board = c.Win32_BaseBoard()[0]
        serial = board.SerialNumber.strip() if board.SerialNumber else None
        if serial and serial.lower() not in ['none', 'to be filled by o.e.m.', 'default string']:
            return serial
        return None
    except Exception:
        return None


def get_volume_serial() -> Optional[str]:
    """Retrieve C: drive volume serial number (P0 addition)"""
    try:
        c = _get_wmi()
        for vol in c.Win32_LogicalDisk():
            if vol.DeviceID == 'C:':
                serial = vol.VolumeSerialNumber
                return serial if serial else None
        return None
    except Exception:
        return None


def get_hardware_components() -> Dict[str, Optional[str]]:
    """
    Collect all hardware identifiers (P0 security enhancement)

    Returns:
        dict: Identifiers for each hardware component
    """
    return {
        'cpu_id': get_cpu_id(),
        'disk_serial': get_disk_serial(),
        'mac_address': get_mac_address(),
        'bios_serial': get_bios_serial(),
        'baseboard_serial': get_baseboard_serial(),
        'volume_serial': get_volume_serial(),
    }


def get_hardware_id(require_minimum: int = 3) -> str:
    """
    Generate a unique hardware identifier.
    P0 security enhancement: Multi-component collection and minimum requirements validation

    Uses:
    - CPU ID
    - Disk Serial Number
    - MAC Address
    - BIOS Serial Number (added)
    - Baseboard Serial Number (added)
    - Volume Serial Number (added)

    Args:
        require_minimum: Minimum number of valid components required (default 3)

    Returns:
        str: SHA256 hash of combined hardware identifiers (first 32 chars)

    Raises:
        HardwareIdError: When minimum requirements are not met
    """
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
        # [Security Warning] Using fallback - weak hardware binding
        import logging
        logger = logging.getLogger(__name__)
        logger.error(
            f"[HardwareID] WMI access failed - weak fallback used!\n"
            f"  Cause: {e}\n"
            f"  Risk: Hardware binding is weakened, security may be compromised.\n"
            f"  Solution: Enable WMI service or run with administrator privileges"
        )
        print("=" * 50)
        print("[Security Warning] Fallback used for hardware ID generation")
        print("  WMI access required. Please run as administrator.")
        print("=" * 50)
        fallback = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        return hashlib.sha256(fallback.encode()).hexdigest()[:32]


def get_hardware_id_with_components(require_minimum: int = 3) -> Tuple[str, Dict[str, Optional[str]]]:
    """
    Return hardware ID and individual components (for server binding)

    Returns:
        tuple: (hardware_id, components_dict)
    """
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
    try:
        c = _get_wmi()

        os_info = c.Win32_OperatingSystem()[0]
        cpu_info = c.Win32_Processor()[0]

        return {
            'os_name': os_info.Caption,
            'os_version': os_info.Version,
            'cpu_name': cpu_info.Name,
            'cpu_cores': cpu_info.NumberOfCores,
            'hostname': platform.node(),
            'platform': platform.platform(),
            'hardware_id': get_hardware_id(),
            'hardware_components': get_hardware_components(),  # P0 addition
        }
    except Exception as e:
        return {
            'hostname': platform.node(),
            'platform': platform.platform(),
            'hardware_id': get_hardware_id(),
            'error': str(e),
        }
