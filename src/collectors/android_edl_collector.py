"""
Android Qualcomm EDL (Emergency Download Mode) Collector Module

Collects partition images from Qualcomm-chipset Android devices via the
Emergency Download Mode (EDL) interface. EDL operates at the hardware level
over USB and does not require the device operating system to be running.

Collectible artifacts:
- android_edl_partition: Raw partition binary images from device storage

Requirements:
    - edl >= 3.0.0 (pip install edl  / github.com/bkerler/edl)
    - libusb-1.0 (system library for USB access)
      - Windows: libusb-1.0.dll in PATH or working directory
      - Linux:   sudo apt-get install libusb-1.0-0
      - macOS:   brew install libusb
    - Qualcomm Firehose / Sahara programmer file (.elf or .mbn) for the
      target device. See check_edl_guide() for details.

Notes:
    - The device must already be in EDL mode (9008 mode) before collection
      starts. See check_edl_guide() for methods to enter EDL mode.
    - Root access or ADB developer options are NOT required; EDL operates
      independently of the Android OS.
    - A Qualcomm Firehose programmer file matched to the device SoC is
      typically required. Without it, the edl tool may still perform limited
      operations using its built-in generic loader.
    - Collection is non-destructive — the tool only reads partition data
      and does not write to device storage.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# USB availability check (optional — used for device detection only)
# ---------------------------------------------------------------------------

try:
    import usb1  # type: ignore
    _USB1_AVAILABLE = True
except ImportError:
    _USB1_AVAILABLE = False

try:
    import usb.core  # type: ignore  # PyUSB
    _PYUSB_AVAILABLE = True
except ImportError:
    _PYUSB_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Qualcomm EDL USB descriptor
_QUALCOMM_VID: int = 0x05C6
_QUALCOMM_EDL_PID: int = 0x9008

# Default partitions targeted for forensic imaging
_DEFAULT_PARTITIONS: List[str] = [
    'userdata',
    'system',
    'system_a',
    'system_b',
    'boot',
    'boot_a',
    'boot_b',
    'recovery',
    'modem',
]

# Common filesystem locations that may contain the programmer / loader file
LOADER_SEARCH_PATHS: List[str] = [
    'resources/qualcomm_loaders',
    os.path.expanduser('~/.edl/loaders'),
    '/usr/share/edl/loaders',
    '/usr/local/share/edl/loaders',
]

# edl binary search locations (in priority order)
_EDL_SEARCH_LOCATIONS: List[str] = [
    'edl',                                          # PATH
    'edl.exe',                                      # PATH (Windows)
    os.path.join(sys.exec_prefix, 'bin', 'edl'),   # active venv
    os.path.join(sys.exec_prefix, 'Scripts', 'edl.exe'),  # venv Windows
    os.path.expanduser('~/.local/bin/edl'),
    '/usr/local/bin/edl',
    '/usr/bin/edl',
]


# ---------------------------------------------------------------------------
# Platform helper
# ---------------------------------------------------------------------------

def _no_window_flags() -> int:
    """Return subprocess creation flags that suppress console windows on Windows."""
    if sys.platform == 'win32':
        return subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    return 0


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class EDLDevice:
    """Information about a Qualcomm device detected in EDL mode."""

    usb_port: str
    """USB port/bus-address identifier (e.g., '1-2.3')."""

    vid: int = _QUALCOMM_VID
    """USB Vendor ID (Qualcomm = 0x05C6)."""

    pid: int = _QUALCOMM_EDL_PID
    """USB Product ID (EDL mode = 0x9008)."""

    chip_id: str = ''
    """Qualcomm chip identifier string reported by the Sahara protocol."""

    msm_id: str = ''
    """MSM (Mobile Station Modem) hardware ID."""

    serial_number: str = ''
    """USB serial number string, if available."""

    def __str__(self) -> str:
        return (
            f"EDLDevice(port={self.usb_port!r}, "
            f"vid=0x{self.vid:04X}, pid=0x{self.pid:04X}, "
            f"chip={self.chip_id!r}, msm={self.msm_id!r}, "
            f"serial={self.serial_number!r})"
        )


@dataclass
class PartitionInfo:
    """Metadata describing a single partition from the device GPT."""

    name: str
    """Partition name as reported in the GPT (e.g., 'userdata')."""

    start_sector: int
    """First logical block address (LBA) of the partition."""

    num_sectors: int
    """Number of sectors in the partition."""

    size_bytes: int
    """Total size in bytes (num_sectors × sector_size)."""

    partition_type: str = ''
    """Partition type hint: 'fat', 'ext4', 'raw', etc. (best-effort)."""

    flags: int = 0
    """Raw GPT attribute flags field."""

    def __str__(self) -> str:
        size_mib = self.size_bytes / (1024 * 1024)
        return (
            f"Partition({self.name!r}, "
            f"start={self.start_sector:#x}, "
            f"sectors={self.num_sectors}, "
            f"size={size_mib:.1f} MiB)"
        )


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

def edl_available() -> bool:
    """
    Check whether the edl tool is accessible in the current environment.

    Searches the PATH, active virtual-environment bin directory, and a set
    of common install locations. Also accepts the ``edl`` Python package as
    an importable library as a secondary indicator.

    Returns:
        True if an edl binary is found and responds to a version query, or
        if the edl Python package is importable. False otherwise.
    """
    # Primary: try to locate and invoke the CLI binary
    binary = _find_edl_binary_static()
    if binary is not None:
        try:
            result = subprocess.run(
                [binary, 'version'],
                capture_output=True,
                timeout=5,
                creationflags=_no_window_flags(),
            )
            if result.returncode == 0:
                return True
        except (OSError, subprocess.TimeoutExpired):
            pass
        # Binary exists but --version failed; still treat as available
        return True

    # Secondary: check for importable edl library
    try:
        import importlib
        spec = importlib.util.find_spec('edl')  # type: ignore[attr-defined]
        return spec is not None
    except Exception:  # noqa: BLE001
        return False


def detect_qualcomm_edl_device() -> bool:
    """
    Check whether a Qualcomm device in EDL mode (VID=0x05C6, PID=0x9008)
    is currently connected via USB.

    Detection strategy (in priority order):
    1. usb1 (libusb1 Python binding) — cross-platform, most reliable
    2. PyUSB (usb.core) — common alternative
    3. Subprocess fallback using system USB tools (lsusb / pnputil)

    Returns:
        True if a matching USB device is found, False otherwise.
    """
    # Strategy 1: usb1
    if _USB1_AVAILABLE:
        try:
            with usb1.USBContext() as ctx:
                for dev in ctx.getDeviceList(skip_on_error=True):
                    if (dev.getVendorID() == _QUALCOMM_VID
                            and dev.getProductID() == _QUALCOMM_EDL_PID):
                        return True
        except Exception as exc:  # noqa: BLE001
            logger.debug("usb1 device scan failed: %s", exc)

    # Strategy 2: PyUSB
    if _PYUSB_AVAILABLE:
        try:
            dev = usb.core.find(  # type: ignore[union-attr]
                idVendor=_QUALCOMM_VID, idProduct=_QUALCOMM_EDL_PID
            )
            if dev is not None:
                return True
        except Exception as exc:  # noqa: BLE001
            logger.debug("PyUSB device scan failed: %s", exc)

    # Strategy 3: system tools fallback
    return _detect_via_system_usb_tools()


def check_edl_guide() -> str:
    """
    Return a human-readable guide for EDL-mode collection preparation.

    Covers device entry methods, Qualcomm loader file requirements, and a
    brief note on supported devices.

    Returns:
        Multi-line plain-text guide string.
    """
    return """\
=============================================================
  Android Qualcomm EDL Collection — Preparation Guide
=============================================================

STEP 1 — Enter EDL (Emergency Download) Mode on the device
-----------------------------------------------------------
  The device must be in EDL mode (USB VID=0x05C6, PID=0x9008) before
  collection can begin. Common methods:

  Method A — Hardware key combination (device powered off):
    1. Power off the device completely.
    2. Hold the EDL key combination for the manufacturer:
       - Qualcomm reference / generic: Volume Down + Volume Up + Power
       - Xiaomi / Redmi / POCO: Volume Down + Power (hold ~10 sec)
       - OnePlus: Volume Up + Volume Down simultaneously at power-on
       - Motorola: hold Volume Down while inserting USB cable
    3. The device screen should remain blank (EDL has no UI).
    4. Verify USB connection: lsusb should show 05c6:9008 (Linux/macOS)
       or Device Manager → 'QHUSB_BULK' / 'Qualcomm HS-USB QDLoader 9008'
       (Windows).

  Method B — ADB reboot (requires USB debugging to be already enabled):
    $ adb reboot edl

  Method C — Fastboot OEM command (some Qualcomm devices):
    $ fastboot oem edl

  Method D — PCB test-point shorting (hardware method, no OS required):
    Requires device disassembly and a shorting wire or tweezers.
    Locate the EDL test pads on the PCB (varies per device model).
    Short the pads momentarily while connecting the USB cable.
    Refer to device-specific schematics or community teardown guides.

STEP 2 — Qualcomm Firehose programmer file
-------------------------------------------
  Most operations require a programmer (loader) file matched to the device
  SoC. This is typically named:
    prog_firehose_ddr.elf   (modern devices, DDR RAM-loaded)
    prog_firehose.mbn       (older Snapdragon, NOR flash)

  Sources:
    - Extract from the device firmware / factory package.
    - OEM firmware update packages (often contain firehose loaders).
    - Community resources for specific device models (XDA Developers).

  Place the file in one of these auto-scan directories, or pass the path
  explicitly to AndroidEDLCollector(loader_path=...):
    - resources/qualcomm_loaders/
    - ~/.edl/loaders/
    - /usr/share/edl/loaders/

  Without a matching loader, edl may still operate in a limited capacity
  using its built-in generic loader, but partition read coverage will vary.

STEP 3 — Supported devices
----------------------------
  Any Android device with a Qualcomm Snapdragon SoC that supports the
  Sahara / Firehose EDL protocol. This covers a large portion of the
  Snapdragon 200 through 8 Gen series.

  Note: Some recent devices (Snapdragon 8 Gen 2+) have additional EDL
  authentication requirements imposed by the manufacturer. Collection may
  require a signed programmer file and/or authorisation tokens.

STEP 4 — Run collection
------------------------
  collector = AndroidEDLCollector(
      output_dir='/path/to/output',
      loader_path='/path/to/prog_firehose_ddr.elf',  # or None for auto-scan
  )
  device = collector.detect_edl_device()
  if device:
      for path, meta in collector.collect_all_partitions(output_dir='/output'):
          print(f"Collected: {path}  ({meta['size']} bytes)")

=============================================================
"""


# ---------------------------------------------------------------------------
# Main collector class
# ---------------------------------------------------------------------------

class AndroidEDLCollector:
    """
    Forensic collector that reads partition images from Qualcomm Android
    devices via Emergency Download Mode (EDL).

    The edl CLI tool (github.com/bkerler/edl) is invoked as a subprocess
    for maximum stability across firmware revisions and device models.

    Usage example::

        collector = AndroidEDLCollector(output_dir='/tmp/evidence',
                                        loader_path='/loaders/firehose.elf')
        device = collector.detect_edl_device()
        if device:
            for path, meta in collector.collect_all_partitions('/tmp/evidence'):
                print(path, meta['sha256'])
    """

    def __init__(
        self,
        output_dir: str,
        loader_path: Optional[str] = None,
    ) -> None:
        """
        Initialise the collector.

        Args:
            output_dir: Default directory where partition images are written.
                        Created automatically if it does not exist.
            loader_path: Absolute path to a Qualcomm Firehose / Sahara
                         programmer file (.elf or .mbn). When None, the
                         collector searches LOADER_SEARCH_PATHS and common
                         locations automatically. If no loader is found, the
                         edl tool will attempt to use its built-in generic
                         loader.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._loader_path: Optional[str] = loader_path
        self._edl_bin: Optional[str] = None   # lazily resolved

    # ------------------------------------------------------------------
    # Binary discovery
    # ------------------------------------------------------------------

    def _find_edl_binary(self) -> Optional[str]:
        """
        Locate the edl binary in the PATH, virtual-environment bin
        directory, or common install locations.

        Returns:
            Absolute or relative path string if found, None otherwise.
        """
        result = _find_edl_binary_static()
        if result:
            logger.debug("edl binary found: %s", result)
        else:
            logger.warning("edl binary not found; install with: pip install edl")
        return result

    @property
    def _edl(self) -> str:
        """Resolved path to the edl binary (lazy, cached)."""
        if self._edl_bin is None:
            self._edl_bin = self._find_edl_binary()
        if self._edl_bin is None:
            raise FileNotFoundError(
                "edl binary not found. Install with 'pip install edl' or "
                "add the edl executable to your PATH."
            )
        return self._edl_bin

    # ------------------------------------------------------------------
    # Loader discovery
    # ------------------------------------------------------------------

    def _resolve_loader(self) -> Optional[str]:
        """
        Determine the Firehose programmer file to use.

        If ``loader_path`` was specified at construction it is returned
        directly after existence verification. Otherwise the directories
        listed in ``LOADER_SEARCH_PATHS`` are scanned for .elf/.mbn files.

        Returns:
            Path string to a loader file, or None if none is found.
        """
        if self._loader_path is not None:
            if os.path.isfile(self._loader_path):
                return self._loader_path
            logger.warning(
                "Specified loader path does not exist: %s", self._loader_path
            )
            return None

        # Auto-scan well-known directories
        for search_dir in LOADER_SEARCH_PATHS:
            expanded = os.path.expandvars(os.path.expanduser(search_dir))
            if not os.path.isdir(expanded):
                continue
            for fname in os.listdir(expanded):
                if fname.lower().endswith(('.elf', '.mbn')):
                    found = os.path.join(expanded, fname)
                    logger.info("Auto-detected loader: %s", found)
                    return found

        logger.debug("No Qualcomm loader file found; edl will use built-in generic loader")
        return None

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """
        Check whether the edl tool is installed and runnable.

        Returns:
            True if the edl binary can be located and invoked successfully.
        """
        try:
            bin_path = self._edl
        except FileNotFoundError:
            return False
        try:
            result = subprocess.run(
                [bin_path, 'version'],
                capture_output=True,
                timeout=5,
                creationflags=_no_window_flags(),
            )
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            # Binary exists but version sub-command not supported — still usable
            return True

    # ------------------------------------------------------------------
    # Device detection
    # ------------------------------------------------------------------

    def detect_edl_device(self) -> Optional[EDLDevice]:
        """
        Detect a Qualcomm device in EDL mode connected via USB.

        Uses usb1, PyUSB, or system USB tools to find VID=0x05C6 / PID=0x9008.
        Additional chip / MSM identifiers are best-effort and may not be
        populated if the device has not yet been probed by the edl tool.

        Returns:
            An EDLDevice instance if a matching device is found, else None.
        """
        port, serial = _locate_qualcomm_usb_device()
        if port is None:
            logger.debug("No Qualcomm EDL device detected on USB")
            return None

        device = EDLDevice(
            usb_port=port,
            vid=_QUALCOMM_VID,
            pid=_QUALCOMM_EDL_PID,
            serial_number=serial or '',
        )
        logger.info("Qualcomm EDL device detected: %s", device)
        return device

    # ------------------------------------------------------------------
    # Partition listing
    # ------------------------------------------------------------------

    def list_partitions(self, serial: Optional[str] = None) -> List[PartitionInfo]:
        """
        Retrieve the partition table from the connected EDL device.

        Runs 'edl printgpt' and parses the output into structured
        :class:`PartitionInfo` objects.

        Args:
            serial: USB serial number to target a specific device.
                    When None the first available EDL device is used.

        Returns:
            List of PartitionInfo instances. Empty list on failure.
        """
        args = ['printgpt']
        if serial:
            args += ['--serial', serial]

        stdout, stderr, rc = self._run_edl(args, timeout=60)
        if rc != 0:
            logger.warning(
                "edl printgpt failed (rc=%d): %s",
                rc,
                stderr.strip(),
            )
            return []

        partitions = self._parse_gpt_output(stdout)
        logger.info("Found %d partition(s) on device", len(partitions))
        return partitions

    # ------------------------------------------------------------------
    # Single partition collection
    # ------------------------------------------------------------------

    def collect_partition(
        self,
        partition_name: str,
        output_dir: Path,
        serial: Optional[str] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Image a single named partition to disk and yield its path and metadata.

        Runs ``edl rf <partition_name> <output_file>`` and computes a SHA-256
        digest of the resulting image file.

        Args:
            partition_name: Partition name as it appears in the GPT (e.g.
                            'userdata', 'system_a').
            output_dir: Directory in which to write the image file.
            serial: USB serial string to target a specific device.
            progress_callback: Optional callable invoked periodically as
                               ``callback(partition_name, bytes_done, bytes_total)``.
                               ``bytes_total`` is 0 when the total is unknown.

        Yields:
            ``(local_file_path, metadata_dict)`` tuple where *metadata_dict*
            contains artifact_type, partition_name, size, sha256,
            collection_method, usb_port, and chip_id.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / f"{partition_name}.img"

        logger.info("Imaging partition '%s' → %s", partition_name, output_file)

        args = ['rf', partition_name, str(output_file)]
        if serial:
            args += ['--serial', serial]

        stdout, stderr, rc = self._run_edl(args, timeout=3600)

        if rc != 0:
            logger.error(
                "edl rf '%s' failed (rc=%d): %s",
                partition_name,
                rc,
                stderr.strip(),
            )
            return

        if not output_file.exists():
            logger.error(
                "edl rf completed but output file not found: %s", output_file
            )
            return

        file_size = output_file.stat().st_size
        sha256 = _compute_sha256(output_file)

        # Attempt to retrieve device info for metadata
        device = self.detect_edl_device()
        usb_port = device.usb_port if device else ''
        chip_id = device.chip_id if device else ''

        metadata: Dict[str, Any] = {
            'artifact_type': 'android_edl_partition',
            'partition_name': partition_name,
            'size': file_size,
            'sha256': sha256,
            'collection_method': 'edl_firehose',
            'usb_port': usb_port,
            'chip_id': chip_id,
            'output_file': str(output_file),
            'collected_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        }

        logger.info(
            "Partition '%s' collected: %d bytes, sha256=%s",
            partition_name,
            file_size,
            sha256[:16] + '...',
        )

        if progress_callback:
            try:
                progress_callback(partition_name, file_size, file_size)
            except Exception as exc:  # noqa: BLE001
                logger.debug("progress_callback raised: %s", exc)

        yield str(output_file), metadata

    # ------------------------------------------------------------------
    # Bulk collection
    # ------------------------------------------------------------------

    def collect_all_partitions(
        self,
        output_dir: str,
        partition_filter: Optional[List[str]] = None,
        serial: Optional[str] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Image multiple partitions sequentially and yield results.

        When *partition_filter* is not provided, the default set defined in
        ``_DEFAULT_PARTITIONS`` is used (userdata, system, boot, etc.).
        If the target device has fewer or different partitions the collection
        simply skips any names that do not exist on the device GPT.

        Args:
            output_dir: Directory where partition images are written.
            partition_filter: Explicit list of partition names to image. When
                              None, the default forensic partition set is used.
            serial: USB serial string to target a specific device.
            progress_callback: Forwarded to :meth:`collect_partition`.

        Yields:
            ``(local_file_path, metadata_dict)`` for each successfully imaged
            partition.
        """
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        if partition_filter is None:
            partition_filter = list(_DEFAULT_PARTITIONS)

        # Query the live GPT to know which names actually exist
        available_partitions: Dict[str, PartitionInfo] = {}
        try:
            for part in self.list_partitions(serial=serial):
                available_partitions[part.name.lower()] = part
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Could not retrieve partition table (%s); "
                "proceeding with requested list without GPT validation.", exc
            )

        for name in partition_filter:
            # Check GPT if we were able to retrieve it
            if available_partitions and name.lower() not in available_partitions:
                logger.debug(
                    "Partition '%s' not found in device GPT; skipping", name
                )
                continue

            try:
                yield from self.collect_partition(
                    partition_name=name,
                    output_dir=target_dir,
                    serial=serial,
                    progress_callback=progress_callback,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Error collecting partition '%s': %s", name, exc
                )

    # ------------------------------------------------------------------
    # edl subprocess runner
    # ------------------------------------------------------------------

    def _run_edl(
        self,
        args: List[str],
        timeout: int = 300,
    ) -> Tuple[str, str, int]:
        """
        Invoke the edl CLI with the given arguments.

        The Qualcomm loader file is appended automatically when available.
        Stdout and stderr are decoded with error replacement to avoid
        codec failures on binary-adjacent output.

        Args:
            args: edl sub-command and parameters (e.g. ['rf', 'userdata', '/tmp/out.img']).
            timeout: Maximum seconds to wait for completion.

        Returns:
            Three-tuple of (stdout_str, stderr_str, returncode).
        """
        cmd: List[str] = [self._edl] + args

        loader = self._resolve_loader()
        if loader:
            cmd += ['--loader', loader]

        logger.debug("Running: %s", ' '.join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                creationflags=_no_window_flags(),
            )
        except subprocess.TimeoutExpired as exc:
            logger.error("edl command timed out after %d s: %s", timeout, exc)
            return '', f'TimeoutExpired after {timeout}s', -1
        except FileNotFoundError as exc:
            logger.error("edl binary not found: %s", exc)
            return '', str(exc), -2
        except OSError as exc:
            logger.error("OS error running edl: %s", exc)
            return '', str(exc), -3

        stdout = proc.stdout.decode('utf-8', errors='replace')
        stderr = proc.stderr.decode('utf-8', errors='replace')

        if proc.returncode != 0:
            logger.debug(
                "edl exited %d\nstdout: %s\nstderr: %s",
                proc.returncode,
                stdout[:400],
                stderr[:400],
            )

        return stdout, stderr, proc.returncode

    # ------------------------------------------------------------------
    # GPT output parser
    # ------------------------------------------------------------------

    def _parse_gpt_output(self, output: str) -> List[PartitionInfo]:
        """
        Parse the text produced by 'edl printgpt' into PartitionInfo objects.

        The edl tool emits a table similar to::

            Name                Offset          Length          Attr        Type
            ----------------------------------------------------------------
            xbl                 0x0000000100000  0x0000000180000 0xa
            abl                 0x0000000280000  0x0000000200000 0xa
            userdata            0x00000d0000000  0x0000600000000 0x8

        Both hexadecimal (0x…) and decimal offset/length values are handled.
        Lines that do not match the expected format are silently skipped.

        Args:
            output: Raw stdout string from 'edl printgpt'.

        Returns:
            List of PartitionInfo instances.
        """
        partitions: List[PartitionInfo] = []

        # Sector size assumed 512 bytes unless edl reports otherwise
        sector_size = 512
        _sector_re = re.compile(r'sector\s*size[:\s]+(\d+)', re.IGNORECASE)
        m = _sector_re.search(output)
        if m:
            sector_size = int(m.group(1))

        # Table row pattern: NAME  OFFSET  LENGTH  [ATTR  [TYPE]]
        # Values may be hex (0x…) or decimal.
        _row_re = re.compile(
            r'^(?P<name>\S+)'           # partition name (no spaces)
            r'\s+(?P<offset>0x[0-9a-fA-F]+|\d+)'   # offset/start
            r'\s+(?P<length>0x[0-9a-fA-F]+|\d+)'   # length in bytes or sectors
            r'(?:\s+(?P<attr>0x[0-9a-fA-F]+|\d+))?' # optional attributes
            r'(?:\s+(?P<ptype>\S+))?',              # optional type string
            re.IGNORECASE,
        )

        _skip_prefixes = ('name', '---', '===', 'lun', 'guid', 'gpt', 'disk')

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if any(stripped.lower().startswith(p) for p in _skip_prefixes):
                continue

            m = _row_re.match(stripped)
            if not m:
                continue

            name = m.group('name')
            raw_offset = m.group('offset')
            raw_length = m.group('length')
            raw_attr = m.group('attr') or '0'
            ptype = m.group('ptype') or ''

            try:
                offset = int(raw_offset, 16) if raw_offset.startswith('0x') else int(raw_offset)
                length = int(raw_length, 16) if raw_length.startswith('0x') else int(raw_length)
                attr = int(raw_attr, 16) if raw_attr.startswith('0x') else int(raw_attr)
            except ValueError:
                logger.debug("Skipping unparseable GPT row: %r", stripped)
                continue

            # Determine whether 'length' is in bytes or sectors by magnitude
            if length < 512 * 2:
                # Treat as sector count
                size_bytes = length * sector_size
                num_sectors = length
                start_sector = offset // sector_size if offset >= sector_size else offset
            else:
                # Treat as bytes
                size_bytes = length
                num_sectors = length // sector_size
                start_sector = offset // sector_size

            partitions.append(PartitionInfo(
                name=name,
                start_sector=start_sector,
                num_sectors=num_sectors,
                size_bytes=size_bytes,
                partition_type=ptype,
                flags=attr,
            ))

        return partitions


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _find_edl_binary_static() -> Optional[str]:
    """
    Search for the edl binary without requiring a class instance.

    Checks each path in ``_EDL_SEARCH_LOCATIONS`` plus any executable
    named 'edl' found via :func:`shutil.which`.

    Returns:
        Path string if found, None otherwise.
    """
    # shutil.which covers PATH lookup cleanly
    via_which = shutil.which('edl')
    if via_which:
        return via_which

    for candidate in _EDL_SEARCH_LOCATIONS:
        expanded = os.path.expandvars(os.path.expanduser(candidate))
        if os.path.isfile(expanded) and os.access(expanded, os.X_OK):
            return expanded

    return None


def _locate_qualcomm_usb_device() -> Tuple[Optional[str], Optional[str]]:
    """
    Return (usb_port_str, serial_str) for the first Qualcomm EDL device found.

    Tries usb1, PyUSB, and system-tool fallbacks in order.

    Returns:
        Two-tuple of (port_identifier, usb_serial). Both None if not found.
    """
    # usb1
    if _USB1_AVAILABLE:
        try:
            with usb1.USBContext() as ctx:
                for dev in ctx.getDeviceList(skip_on_error=True):
                    if (dev.getVendorID() == _QUALCOMM_VID
                            and dev.getProductID() == _QUALCOMM_EDL_PID):
                        port = f"{dev.getBusNumber()}-{dev.getDeviceAddress()}"
                        try:
                            serial = dev.getSerialNumber()
                        except Exception:  # noqa: BLE001
                            serial = ''
                        return port, serial
        except Exception as exc:  # noqa: BLE001
            logger.debug("usb1 locate failed: %s", exc)

    # PyUSB
    if _PYUSB_AVAILABLE:
        try:
            dev = usb.core.find(  # type: ignore[union-attr]
                idVendor=_QUALCOMM_VID, idProduct=_QUALCOMM_EDL_PID
            )
            if dev is not None:
                port = f"{dev.bus}-{dev.address}"
                serial = ''
                try:
                    serial = usb.core.util.get_string(dev, dev.iSerialNumber)  # type: ignore
                except Exception:  # noqa: BLE001
                    pass
                return port, serial
        except Exception as exc:  # noqa: BLE001
            logger.debug("PyUSB locate failed: %s", exc)

    # System tools
    if _detect_via_system_usb_tools():
        return 'unknown', None

    return None, None


def _detect_via_system_usb_tools() -> bool:
    """
    Fall back to system USB utilities (lsusb / pnputil) to detect the device.

    Returns:
        True if VID=05c6 PID=9008 is found in system USB output.
    """
    target_vid = f"{_QUALCOMM_VID:04x}"
    target_pid = f"{_QUALCOMM_EDL_PID:04x}"

    if sys.platform.startswith('linux') or sys.platform == 'darwin':
        lsusb = shutil.which('lsusb')
        if lsusb:
            try:
                result = subprocess.run(
                    [lsusb],
                    capture_output=True,
                    timeout=5,
                    creationflags=_no_window_flags(),
                )
                if result.returncode == 0:
                    text = result.stdout.decode('utf-8', errors='replace').lower()
                    pattern = f"{target_vid}:{target_pid}"
                    return pattern in text
            except (OSError, subprocess.TimeoutExpired):
                pass

    elif sys.platform == 'win32':
        try:
            result = subprocess.run(
                ['pnputil', '/enum-devices', '/class', 'USB'],
                capture_output=True,
                timeout=10,
                creationflags=_no_window_flags(),
            )
            if result.returncode == 0:
                text = result.stdout.decode('utf-8', errors='replace').lower()
                # pnputil reports hardware IDs like USB\VID_05C6&PID_9008
                vid_str = f"vid_{target_vid}"
                pid_str = f"pid_{target_pid}"
                if vid_str in text and pid_str in text:
                    return True
        except (OSError, subprocess.TimeoutExpired):
            pass

    return False


def _compute_sha256(file_path: Path, chunk_size: int = 1024 * 1024) -> str:
    """
    Compute the SHA-256 digest of a file.

    Args:
        file_path: Path to the file.
        chunk_size: Read buffer size in bytes.

    Returns:
        Lowercase hex digest string, or empty string on I/O error.
    """
    h = hashlib.sha256()
    try:
        with open(file_path, 'rb') as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError as exc:
        logger.error("SHA-256 computation failed for %s: %s", file_path, exc)
        return ''
