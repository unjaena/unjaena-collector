"""
Android MediaTek (MTK) BROM Collector Module

Provides forensic imaging of Android devices based on MediaTek chipsets by
communicating with the Boot ROM (BROM) over USB. BROM mode grants hardware-
level read access to device partitions without requiring an unlocked bootloader
or an active operating system on the device.

Collection workflow:
1. Device is placed into BROM mode (hardware key combination, test-point
   shorting, or 'adb reboot brom' on supported firmware)
2. USB device with MediaTek VID 0x0E8D and PID 0x0003 / 0x2000 / 0x0001
   becomes visible on the host
3. mtkclient (https://github.com/bkerler/mtkclient) communicates with BROM
4. Partition table is read via 'mtk printgpt'
5. Selected or all partitions are imaged to local files via 'mtk rf <name>'
   or 'mtk rl <dir>' and SHA-256 checksums are computed

Collectible data:
- android_mtk_partition: Raw binary partition images from BROM-level access

Requirements:
    pip install mtkclient

    or clone and install from source:
    git clone https://github.com/bkerler/mtkclient
    cd mtkclient && pip install .

Supported chipsets (representative):
    MT6580, MT6737, MT6739, MT6750, MT6753, MT6755, MT6757,
    MT6761, MT6762, MT6763, MT6765, MT6768, MT6771, MT6779,
    MT6785, MT6789, MT6833, MT6853, MT6873, MT6877, MT6885,
    MT6893, MT6895, MT8173, MT8183, MT8195

Note:
    BROM mode communicates at a hardware level. Ensure the correct USB driver
    is installed on Windows (use Zadig to bind WinUSB / libusb-win32).
    On Linux, udev rules may be required for non-root access.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional USB detection libraries (used for BROM device enumeration)
# ---------------------------------------------------------------------------

try:
    import usb.core  # type: ignore[import]
    import usb.util  # type: ignore[import]
    _PYUSB_AVAILABLE = True
except ImportError:
    _PYUSB_AVAILABLE = False

try:
    import usb1  # type: ignore[import]
    _USB1_AVAILABLE = True
except ImportError:
    _USB1_AVAILABLE = False

# ---------------------------------------------------------------------------
# Optional PartitionInfo import from sibling collector
# ---------------------------------------------------------------------------

try:
    from collectors.android_edl_collector import PartitionInfo  # type: ignore[import]
except ImportError:
    @dataclass
    class PartitionInfo:  # type: ignore[no-redef]
        """Basic partition descriptor used when android_edl_collector is absent."""
        name: str
        start_sector: int
        num_sectors: int
        size_bytes: int
        partition_type: str = ''
        flags: int = 0

# ---------------------------------------------------------------------------
# MTK USB constants
# ---------------------------------------------------------------------------

MTK_USB_VID: int = 0x0E8D
MTK_BROM_PID: int = 0x0003       # Standard BROM
MTK_PRELOADER_PID: int = 0x2000  # Preloader / download mode
MTK_LEGACY_PID: int = 0x0001     # Older chipsets

_MTK_KNOWN_PIDS: Tuple[int, ...] = (
    MTK_BROM_PID,
    MTK_PRELOADER_PID,
    MTK_LEGACY_PID,
)

# ---------------------------------------------------------------------------
# Platform helpers
# ---------------------------------------------------------------------------


def _no_window_flags() -> int:
    """Return subprocess creation flags to suppress console windows on Windows."""
    if sys.platform == 'win32':
        return subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    return 0


def _run(
    cmd: List[str],
    timeout: int = 30,
    capture: bool = True,
) -> subprocess.CompletedProcess:
    """
    Run a subprocess command and return the CompletedProcess result.

    Args:
        cmd: Command and arguments list.
        timeout: Maximum seconds to wait.
        capture: Whether to capture stdout/stderr.

    Returns:
        CompletedProcess instance (returncode, stdout, stderr).

    Raises:
        subprocess.TimeoutExpired: If the command exceeds *timeout* seconds.
        FileNotFoundError: If the binary is not found on PATH.
    """
    kwargs: Dict[str, Any] = {
        'timeout': timeout,
        'creationflags': _no_window_flags(),
    }
    if capture:
        kwargs['capture_output'] = True
    return subprocess.run(cmd, **kwargs)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class MTKDevice:
    """
    Information about a MediaTek device detected in BROM or Preloader mode.

    Attributes:
        usb_port: Host USB port string (bus/address or system device path).
        vid: USB Vendor ID (always 0x0E8D for MediaTek).
        pid: USB Product ID (0x0003 = BROM, 0x2000 = Preloader, 0x0001 = legacy).
        chip_name: Human-readable chip name, e.g. 'MT6765'.
        hw_code: Hardware code read from BROM (0 if not yet queried).
        hw_sub_code: Hardware sub-code from BROM.
        hw_version: Hardware version from BROM.
        sw_version: Software version from BROM.
        mode: 'brom' or 'preloader'.
    """
    usb_port: str
    vid: int = MTK_USB_VID
    pid: int = MTK_BROM_PID
    chip_name: str = ''
    hw_code: int = 0
    hw_sub_code: int = 0
    hw_version: int = 0
    sw_version: int = 0
    mode: str = 'brom'

    def __str__(self) -> str:
        mode_label = 'BROM' if self.mode == 'brom' else 'Preloader'
        chip = self.chip_name or f'0x{self.hw_code:04X}'
        return (
            f"MTKDevice(port={self.usb_port!r}, chip={chip}, "
            f"mode={mode_label}, pid=0x{self.pid:04X})"
        )


@dataclass
class CollectionResult:
    """Summary result of a collection operation."""
    chip_name: str = ''
    files_collected: int = 0
    bytes_collected: int = 0
    errors: List[str] = field(default_factory=list)
    collection_method: str = 'mtk_brom'


# ---------------------------------------------------------------------------
# Module-level helper functions
# ---------------------------------------------------------------------------


def mtk_available() -> bool:
    """
    Check whether the mtk / mtkclient command-line tool is accessible.

    Searches PATH and common pip-install locations.

    Returns:
        True if mtk (or mtkclient) responds to a version or help query.
    """
    collector = AndroidMTKCollector.__new__(AndroidMTKCollector)
    collector._mtk_path = None  # type: ignore[attr-defined]
    found = collector._find_mtk_binary()
    if found is None:
        return False
    try:
        result = _run([found, '--help'], timeout=10)
        # mtkclient exits with 0 or 1 for --help; either indicates the binary works
        return result.returncode in (0, 1)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def detect_mtk_brom_device() -> bool:
    """
    Check whether a device in MTK BROM or Preloader mode is currently connected.

    Attempts USB enumeration via pyusb, libusb1, or a system-level fallback
    (lsusb on Linux / macOS, Get-PnpDevice on Windows).

    Returns:
        True if a device with MediaTek VID and a known BROM/Preloader PID is found.
    """
    collector = AndroidMTKCollector.__new__(AndroidMTKCollector)
    collector.output_dir = Path('.')  # type: ignore[attr-defined]
    device = collector.detect_mtk_device()
    return device is not None


def check_mtk_guide() -> str:
    """
    Return a multi-line guide for placing an MTK device into BROM mode
    and performing forensic imaging.

    Returns:
        Multi-line plain-text guide string.
    """
    return """\
=============================================================
  Android MediaTek (MTK) BROM Collection — Preparation Guide
=============================================================

BROM MODE ENTRY METHODS
------------------------
Method 1 — Hardware key combination (most common):
  1. Fully power off the device.
  2. Hold [Volume Down] + [Power] simultaneously while the battery is
     critically low (ideally below 5 %) or completely removed and
     reinserted immediately after connecting the USB cable.
  3. The device will NOT display anything on-screen in BROM mode.
  4. On the host, the USB device 0E8D:0003 should appear within 2–5 s.

Method 2 — Download cable (hardware method):
  A special USB cable with a resistor between D+ and GND triggers
  BROM mode on many MTK devices. Cable specifications vary by chipset;
  consult device-specific teardown notes or XDA Developers.

Method 3 — PCB test-point shorting:
  Shorting the BROM test point on the PCB to GND while powering on
  forces BROM mode. Requires disassembly; consult device schematics.

Method 4 — ADB command (supported on some firmware):
  $ adb reboot brom
  Works on certain MediaTek devices that expose the brom reboot target.

Method 5 — SP Flash Tool method:
  Open SP Flash Tool, load the scatter file, and press Download.
  The tool will wait for BROM connection; connect the device at this
  point (power-off state, no battery if removable).

SUPPORTED CHIPSETS (representative)
--------------------------------------
  Entry/Mid: MT6580, MT6737, MT6739, MT6750, MT6753, MT6761, MT6762,
             MT6765, MT6768
  High-end:  MT6771 (Helio P60/P70), MT6779, MT6785, MT6789
  Flagship:  MT6885, MT6893, MT6895 (Dimensity series)
  Tablet/PC: MT8173, MT8183, MT8195

DOWNLOAD MODE vs BROM MODE
-----------------------------
  BROM mode (PID 0x0003):
    - Executed directly from masked ROM inside the SoC.
    - No operating system required; works on a blank, bricked, or
      factory-reset device.
    - Full partition table access via mtkclient 'printgpt'.

  Preloader / Download mode (PID 0x2000):
    - Executed from the on-device preloader stage (first-stage bootloader).
    - Slightly higher-level than BROM; some devices only expose this mode.
    - mtkclient supports both modes transparently.

DRIVER SETUP
--------------
  Windows:
    - Use Zadig (https://zadig.akeo.ie/) to bind WinUSB or libusb-win32
      to the device 0E8D:0003 or 0E8D:2000.
    - Alternatively install the official MediaTek VCOM / SP Flash Tool
      driver package.

  Linux:
    - Create /etc/udev/rules.d/99-mtk-brom.rules:
        SUBSYSTEM=="usb", ATTR{idVendor}=="0e8d", MODE="0666", GROUP="plugdev"
    - Run: sudo udevadm control --reload-rules && sudo udevadm trigger

QUICK START
-----------
  from collectors.android_mtk_collector import AndroidMTKCollector

  collector = AndroidMTKCollector(output_dir='/evidence/mtk_dump')
  if not collector.is_available():
      print("mtkclient not installed — run: pip install mtkclient")
  else:
      device = collector.detect_mtk_device()
      if device:
          partitions = collector.list_partitions()
          for path, meta in collector.collect_all_partitions('/evidence/mtk_dump'):
              print(f"Collected: {path}  ({meta['size']:,} bytes)")

=============================================================
"""


# ---------------------------------------------------------------------------
# Main collector class
# ---------------------------------------------------------------------------


class AndroidMTKCollector:
    """
    Forensic collector that communicates with MediaTek devices in BROM or
    Preloader mode via the mtkclient tool to image device partitions.

    Collection targets raw partition binary data from hardware-level access
    without requiring the device's operating system to be running.
    """

    # Default partition names to image when no explicit filter is provided
    DEFAULT_PARTITION_NAMES: List[str] = [
        'userdata',
        'system',
        'system_a',
        'system_b',
        'boot',
        'preloader',
        'lk',
        'md1img',
    ]

    # Candidate binary names / paths for the mtk CLI (searched in order)
    _MTK_SEARCH_LOCATIONS: List[str] = [
        'mtk',                        # PATH (pip install mtkclient adds 'mtk')
        'mtkclient',                  # Alternative entry-point name
        os.path.join(
            sys.prefix, 'bin', 'mtk'
        ),                            # pip --user or venv prefix
        os.path.join(
            sys.prefix, 'bin', 'mtkclient'
        ),
        os.path.join(
            os.path.expanduser('~'), '.local', 'bin', 'mtk'
        ),                            # pip install --user (Linux/macOS)
        os.path.join(
            os.path.expanduser('~'), '.local', 'bin', 'mtkclient'
        ),
        os.path.join(
            os.path.expanduser('~'), 'AppData', 'Local', 'Programs',
            'Python', 'Scripts', 'mtk.exe'
        ),                            # Windows user install
        os.path.join(
            os.path.expanduser('~'), 'AppData', 'Local', 'Programs',
            'Python', 'Scripts', 'mtkclient.exe'
        ),
        '/usr/local/bin/mtk',
        '/usr/local/bin/mtkclient',
        '/usr/bin/mtk',
        '/usr/bin/mtkclient',
    ]

    # Regex to parse 'mtk printgpt' / 'mtkclient printgpt' output
    _GPT_LINE_RE = re.compile(
        r'Partition:\s+(\w+),\s+Offset:\s+(0x[\da-fA-F]+),\s+Length:\s+(0x[\da-fA-F]+)',
        re.IGNORECASE,
    )

    def __init__(
        self,
        output_dir: str,
        mtk_path: Optional[str] = None,
    ) -> None:
        """
        Initialise the collector.

        Args:
            output_dir: Default directory for collected partition images.
            mtk_path: Explicit path to the mtk / mtkclient binary. If None,
                      the binary is located automatically.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._mtk_path: Optional[str] = mtk_path

    # ------------------------------------------------------------------
    # Binary discovery
    # ------------------------------------------------------------------

    def _find_mtk_binary(self) -> Optional[str]:
        """
        Locate the mtk / mtkclient CLI binary.

        Searches the locations listed in _MTK_SEARCH_LOCATIONS, probing each
        with a '--help' invocation to confirm the binary is functional.

        Returns:
            Absolute path string if found, None otherwise.
        """
        for candidate in self._MTK_SEARCH_LOCATIONS:
            expanded = os.path.expandvars(candidate)
            try:
                result = _run([expanded, '--help'], timeout=10)
                if result.returncode in (0, 1):
                    logger.debug("mtk binary found: %s", expanded)
                    return expanded
            except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
                continue
        logger.warning("mtk/mtkclient binary not found in any standard location")
        return None

    @property
    def mtk(self) -> str:
        """Resolved path to the mtk / mtkclient binary (lazy, cached)."""
        if self._mtk_path is None:
            self._mtk_path = self._find_mtk_binary()
        if self._mtk_path is None:
            raise FileNotFoundError(
                "mtk/mtkclient binary not found. "
                "Install with: pip install mtkclient"
            )
        return self._mtk_path

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """
        Check whether the mtk / mtkclient binary is accessible and functional.

        Returns:
            True if the binary responds to a '--help' invocation.
        """
        try:
            result = _run([self.mtk, '--help'], timeout=10)
            return result.returncode in (0, 1)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return False

    # ------------------------------------------------------------------
    # Device detection
    # ------------------------------------------------------------------

    def detect_mtk_device(self) -> Optional[MTKDevice]:
        """
        Detect a MediaTek device in BROM or Preloader mode on the USB bus.

        Detection order:
        1. pyusb (if available)
        2. libusb1 (if available)
        3. System-level fallback: lsusb (Linux/macOS) or Get-PnpDevice (Windows)

        Returns:
            MTKDevice instance if a matching device is found, None otherwise.
        """
        device = (
            self._detect_via_pyusb()
            or self._detect_via_libusb1()
            or self._detect_via_system()
        )
        if device:
            logger.info("MTK device detected: %s", device)
        else:
            logger.debug("No MTK BROM/Preloader device found on USB")
        return device

    def _detect_via_pyusb(self) -> Optional[MTKDevice]:
        """
        Enumerate USB devices using pyusb to find an MTK BROM device.

        Returns:
            MTKDevice if found, None if pyusb is unavailable or no match.
        """
        if not _PYUSB_AVAILABLE:
            return None
        try:
            for pid in _MTK_KNOWN_PIDS:
                dev = usb.core.find(idVendor=MTK_USB_VID, idProduct=pid)
                if dev is not None:
                    port = self._usb_port_string(dev)
                    mode = 'preloader' if pid == MTK_PRELOADER_PID else 'brom'
                    return MTKDevice(usb_port=port, pid=pid, mode=mode)
        except Exception as exc:  # noqa: BLE001
            logger.debug("pyusb detection failed: %s", exc)
        return None

    def _detect_via_libusb1(self) -> Optional[MTKDevice]:
        """
        Enumerate USB devices using libusb1 (python-libusb1) to find an MTK device.

        Returns:
            MTKDevice if found, None if libusb1 is unavailable or no match.
        """
        if not _USB1_AVAILABLE:
            return None
        try:
            with usb1.USBContext() as ctx:
                for device in ctx.getDeviceList(skip_on_error=True):
                    if device.getVendorID() != MTK_USB_VID:
                        continue
                    pid = device.getProductID()
                    if pid in _MTK_KNOWN_PIDS:
                        port = (
                            f"{device.getBusNumber():03d}/"
                            f"{device.getDeviceAddress():03d}"
                        )
                        mode = 'preloader' if pid == MTK_PRELOADER_PID else 'brom'
                        return MTKDevice(usb_port=port, pid=pid, mode=mode)
        except Exception as exc:  # noqa: BLE001
            logger.debug("libusb1 detection failed: %s", exc)
        return None

    def _detect_via_system(self) -> Optional[MTKDevice]:
        """
        Detect an MTK BROM device using system-level USB enumeration tools.

        Uses 'lsusb' on Linux/macOS and PowerShell 'Get-PnpDevice' on Windows.

        Returns:
            MTKDevice if found, None if not found or the command fails.
        """
        try:
            if sys.platform == 'win32':
                return self._detect_windows_pnp()
            return self._detect_lsusb()
        except Exception as exc:  # noqa: BLE001
            logger.debug("System USB detection failed: %s", exc)
        return None

    def _detect_lsusb(self) -> Optional[MTKDevice]:
        """
        Parse lsusb output for MediaTek VID on Linux/macOS.

        Returns:
            MTKDevice if a match is found, None otherwise.
        """
        try:
            result = _run(['lsusb'], timeout=10)
        except (FileNotFoundError, OSError):
            return None

        if result.returncode != 0:
            return None

        vid_hex = f'{MTK_USB_VID:04x}'
        output = result.stdout.decode(errors='replace')
        for line in output.splitlines():
            line_lower = line.lower()
            if vid_hex not in line_lower:
                continue
            # Attempt to extract PID from "ID vvvv:pppp" token
            m = re.search(r'id\s+([0-9a-f]{4}):([0-9a-f]{4})', line_lower)
            if m:
                pid_val = int(m.group(2), 16)
                if pid_val in _MTK_KNOWN_PIDS:
                    bus_dev = re.search(
                        r'bus\s+(\d+)\s+device\s+(\d+)', line, re.IGNORECASE
                    )
                    port = (
                        f"{bus_dev.group(1)}/{bus_dev.group(2)}"
                        if bus_dev else 'unknown'
                    )
                    mode = 'preloader' if pid_val == MTK_PRELOADER_PID else 'brom'
                    return MTKDevice(usb_port=port, pid=pid_val, mode=mode)
        return None

    def _detect_windows_pnp(self) -> Optional[MTKDevice]:
        """
        Use PowerShell Get-PnpDevice to find MTK BROM devices on Windows.

        Returns:
            MTKDevice if found, None otherwise.
        """
        vid_str = f'VID_{MTK_USB_VID:04X}'
        ps_cmd = (
            f"Get-PnpDevice -PresentOnly | "
            f"Where-Object {{ $_.InstanceId -like '*{vid_str}*' }} | "
            f"Select-Object -ExpandProperty InstanceId"
        )
        try:
            result = _run(
                ['powershell', '-NoProfile', '-Command', ps_cmd],
                timeout=20,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return None

        if result.returncode != 0:
            return None

        output = result.stdout.decode(errors='replace')
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            for pid in _MTK_KNOWN_PIDS:
                pid_str = f'PID_{pid:04X}'
                if pid_str in line.upper():
                    mode = 'preloader' if pid == MTK_PRELOADER_PID else 'brom'
                    return MTKDevice(usb_port=line, pid=pid, mode=mode)
        return None

    @staticmethod
    def _usb_port_string(dev: Any) -> str:
        """
        Build a bus/address port string from a pyusb device object.

        Args:
            dev: usb.core.Device instance.

        Returns:
            String such as '001/007'.
        """
        try:
            return f"{dev.bus:03d}/{dev.address:03d}"
        except Exception:  # noqa: BLE001
            return 'unknown'

    # ------------------------------------------------------------------
    # Partition enumeration
    # ------------------------------------------------------------------

    def list_partitions(self) -> List[PartitionInfo]:
        """
        Query the device partition table using 'mtk printgpt'.

        Returns:
            List of PartitionInfo instances.  Returns an empty list if the
            command fails or no partitions are found.
        """
        try:
            stdout, stderr, rc = self._run_mtk(['printgpt'], timeout=60)
        except Exception as exc:  # noqa: BLE001
            logger.error("list_partitions: command failed: %s", exc)
            return []

        if rc != 0:
            logger.warning(
                "mtk printgpt returned %d: %s",
                rc,
                stderr.strip(),
            )

        partitions = self._parse_gpt_output(stdout + '\n' + stderr)
        logger.info("Found %d partition(s) via printgpt", len(partitions))
        return partitions

    def _parse_gpt_output(self, output: str) -> List[PartitionInfo]:
        """
        Parse 'mtk printgpt' text output into PartitionInfo instances.

        Expected line format (one or more per partition):
            Partition: boot, Offset: 0x640000, Length: 0x4000000

        Also attempts to parse alternate tabular formats emitted by some
        mtkclient versions.

        Args:
            output: Raw combined stdout+stderr text from the printgpt command.

        Returns:
            List of PartitionInfo instances (may be empty).
        """
        partitions: List[PartitionInfo] = []
        seen: set = set()

        for line in output.splitlines():
            m = self._GPT_LINE_RE.search(line)
            if m:
                name = m.group(1)
                offset = int(m.group(2), 16)
                length = int(m.group(3), 16)
                if name in seen:
                    continue
                seen.add(name)
                sector_size = 512
                start_sector = offset // sector_size
                num_sectors = length // sector_size
                partitions.append(
                    PartitionInfo(
                        name=name,
                        start_sector=start_sector,
                        num_sectors=num_sectors,
                        size_bytes=length,
                    )
                )
                continue

            # Alternate format: "  boot     0x640000     0x4000000  ..."
            alt_m = re.match(
                r'\s*(\w+)\s+(0x[\da-fA-F]+)\s+(0x[\da-fA-F]+)',
                line,
            )
            if alt_m:
                name = alt_m.group(1)
                if name.lower() in ('partition', 'name', 'offset', 'length'):
                    continue
                offset = int(alt_m.group(2), 16)
                length = int(alt_m.group(3), 16)
                if name in seen:
                    continue
                seen.add(name)
                sector_size = 512
                start_sector = offset // sector_size
                num_sectors = length // sector_size
                partitions.append(
                    PartitionInfo(
                        name=name,
                        start_sector=start_sector,
                        num_sectors=num_sectors,
                        size_bytes=length,
                    )
                )

        return partitions

    # ------------------------------------------------------------------
    # Single partition collection
    # ------------------------------------------------------------------

    def collect_partition(
        self,
        partition_name: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Image a single named partition using 'mtk rf <name> <output_file>'.

        Args:
            partition_name: Name of the partition to image (e.g. 'userdata').
            output_dir: Directory to write the output image file.
            progress_callback: Optional callback(partition_name, bytes_done,
                               bytes_total). bytes_total may be 0 if unknown.

        Yields:
            Tuples of (local_file_path_str, metadata_dict).
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out_file = output_dir / f"{partition_name}.img"

        logger.info("Imaging partition '%s' -> %s", partition_name, out_file)

        if progress_callback:
            try:
                progress_callback(partition_name, 0, 0)
            except Exception:  # noqa: BLE001
                pass

        try:
            stdout, stderr, rc = self._run_mtk(
                ['rf', partition_name, str(out_file)],
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            logger.error(
                "collect_partition '%s': timed out after 600 s", partition_name
            )
            return
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "collect_partition '%s': command error: %s", partition_name, exc
            )
            return

        if rc != 0:
            logger.warning(
                "mtk rf '%s' returned %d: %s",
                partition_name,
                rc,
                stderr.strip(),
            )

        if not out_file.exists() or out_file.stat().st_size == 0:
            logger.warning(
                "collect_partition '%s': output file missing or empty: %s",
                partition_name,
                out_file,
            )
            return

        size = out_file.stat().st_size
        sha256 = self._sha256_file(out_file)

        # Attempt to extract chip name from mtkclient output
        chip_name = self._extract_chip_name(stdout + stderr)

        if progress_callback:
            try:
                progress_callback(partition_name, size, size)
            except Exception:  # noqa: BLE001
                pass

        metadata: Dict[str, Any] = {
            'artifact_type': 'android_mtk_partition',
            'partition_name': partition_name,
            'size': size,
            'sha256': sha256,
            'collection_method': 'mtk_brom',
            'chip_name': chip_name,
            'hw_code': 0,
            'output_file': str(out_file),
        }
        logger.info(
            "Collected partition '%s': %d bytes, SHA-256=%s",
            partition_name, size, sha256,
        )
        yield str(out_file), metadata

    # ------------------------------------------------------------------
    # Multi-partition collection
    # ------------------------------------------------------------------

    def collect_all_partitions(
        self,
        output_dir: str,
        partition_filter: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Image all partitions listed in the device GPT (or a filtered subset).

        If *partition_filter* is provided, only partitions whose names are in
        that list are imaged.  If None, the DEFAULT_PARTITION_NAMES list is
        used as a filter; set partition_filter=[] to image every partition.

        Args:
            output_dir: Directory to write partition image files.
            partition_filter: Partition names to image. None = use defaults.
                              Empty list = image all discovered partitions.
            progress_callback: Optional callback forwarded to collect_partition.

        Yields:
            Tuples of (local_file_path_str, metadata_dict) from each partition.
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        # Determine which names to image
        if partition_filter is None:
            names_to_collect = list(self.DEFAULT_PARTITION_NAMES)
        else:
            names_to_collect = list(partition_filter)

        # Try to enumerate partitions from device GPT for metadata
        discovered: Dict[str, PartitionInfo] = {}
        try:
            for part in self.list_partitions():
                discovered[part.name] = part
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not enumerate GPT: %s", exc)

        if names_to_collect:
            targets = names_to_collect
        else:
            # Empty filter means collect everything discovered
            targets = list(discovered.keys()) if discovered else list(
                self.DEFAULT_PARTITION_NAMES
            )

        logger.info(
            "collect_all_partitions: %d target(s): %s",
            len(targets),
            ', '.join(targets),
        )

        for name in targets:
            try:
                yield from self.collect_partition(
                    partition_name=name,
                    output_dir=out_path,
                    progress_callback=progress_callback,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to collect partition '%s': %s", name, exc)

    # ------------------------------------------------------------------
    # Full-flash collection
    # ------------------------------------------------------------------

    def collect_full_flash(
        self,
        output_dir: str,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Perform a complete device storage dump using 'mtk rl <dir>'.

        'mtk rl' reads all partitions listed in the GPT and writes each one
        as a separate file inside *output_dir*.

        Args:
            output_dir: Directory to write all partition image files.
            progress_callback: Optional callback(partition_name, bytes_done,
                               bytes_total).

        Yields:
            Tuples of (local_file_path_str, metadata_dict) for each partition
            image written by mtkclient.
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        logger.info("Starting full-flash dump to: %s", out_path)

        if progress_callback:
            try:
                progress_callback('full_flash', 0, 0)
            except Exception:  # noqa: BLE001
                pass

        # Record existing files to identify newly created images
        existing_files: set = set(out_path.iterdir()) if out_path.exists() else set()

        try:
            stdout, stderr, rc = self._run_mtk(
                ['rl', str(out_path)],
                timeout=3600,   # Full dumps can take up to an hour
            )
        except subprocess.TimeoutExpired:
            logger.error("collect_full_flash: timed out after 3600 s")
            return
        except Exception as exc:  # noqa: BLE001
            logger.error("collect_full_flash: command error: %s", exc)
            return

        if rc != 0:
            logger.warning(
                "mtk rl returned %d: %s", rc, stderr.strip()
            )

        chip_name = self._extract_chip_name(stdout + stderr)

        # Yield each new image file written to the output directory
        new_files = sorted(
            f for f in out_path.iterdir()
            if f not in existing_files and f.suffix.lower() == '.img'
        )
        logger.info(
            "collect_full_flash: %d image file(s) written", len(new_files)
        )

        total_size = sum(f.stat().st_size for f in new_files)
        if progress_callback and total_size:
            try:
                progress_callback('full_flash', total_size, total_size)
            except Exception:  # noqa: BLE001
                pass

        for img_file in new_files:
            size = img_file.stat().st_size
            sha256 = self._sha256_file(img_file)
            partition_name = img_file.stem  # filename without .img
            metadata: Dict[str, Any] = {
                'artifact_type': 'android_mtk_partition',
                'partition_name': partition_name,
                'size': size,
                'sha256': sha256,
                'collection_method': 'mtk_brom',
                'chip_name': chip_name,
                'hw_code': 0,
                'output_file': str(img_file),
            }
            logger.info(
                "Full-flash partition '%s': %d bytes, SHA-256=%s",
                partition_name, size, sha256,
            )
            yield str(img_file), metadata

    # ------------------------------------------------------------------
    # Low-level CLI wrapper
    # ------------------------------------------------------------------

    def _run_mtk(
        self,
        args: List[str],
        timeout: int = 300,
    ) -> Tuple[str, str, int]:
        """
        Execute the mtk / mtkclient CLI with the given arguments.

        Args:
            args: Argument list appended after the binary path
                  (e.g. ['rf', 'userdata', '/out/userdata.img']).
            timeout: Maximum seconds to wait for the command to complete.

        Returns:
            Tuple of (stdout_text, stderr_text, returncode).

        Raises:
            subprocess.TimeoutExpired: If the command exceeds *timeout* seconds.
            FileNotFoundError: If the mtk binary is not found.
        """
        cmd = [self.mtk] + args
        logger.debug("Running: %s", ' '.join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                creationflags=_no_window_flags(),
            )
        except subprocess.TimeoutExpired:
            logger.error(
                "_run_mtk timed out after %d s: %s", timeout, ' '.join(cmd)
            )
            raise

        stdout = result.stdout.decode(errors='replace') if result.stdout else ''
        stderr = result.stderr.decode(errors='replace') if result.stderr else ''

        if result.returncode != 0:
            logger.debug(
                "mtk command returned %d\nstdout: %s\nstderr: %s",
                result.returncode,
                stdout[:500],
                stderr[:500],
            )

        return stdout, stderr, result.returncode

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    @staticmethod
    def _sha256_file(file_path: Path, chunk_size: int = 65536) -> str:
        """
        Compute the SHA-256 checksum of a file.

        Args:
            file_path: Path to the file.
            chunk_size: Read chunk size in bytes.

        Returns:
            Lowercase hex-encoded SHA-256 digest string.
        """
        h = hashlib.sha256()
        try:
            with file_path.open('rb') as fh:
                while True:
                    chunk = fh.read(chunk_size)
                    if not chunk:
                        break
                    h.update(chunk)
        except OSError as exc:
            logger.error("SHA-256 computation failed for %s: %s", file_path, exc)
            return ''
        return h.hexdigest()

    @staticmethod
    def _extract_chip_name(text: str) -> str:
        """
        Extract a chip name such as 'MT6765' from mtkclient output text.

        Args:
            text: Combined stdout/stderr text from an mtkclient command.

        Returns:
            Chip name string (e.g. 'MT6765'), or empty string if not found.
        """
        # Common patterns: "MT6765", "Chip: MT6765", "Detected chipset: MT6765"
        patterns = [
            r'\b(MT\d{4}[A-Z0-9]*)\b',
            r'chip(?:set)?\s*[:\-=]\s*(MT\d{4}[A-Z0-9]*)',
            r'detected\s+(?:chipset|chip)\s*[:\-=]?\s*(MT\d{4}[A-Z0-9]*)',
        ]
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                return m.group(1).upper()
        return ''
