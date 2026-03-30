"""
Android Fastboot Recovery Collector Module

Boots a temporary recovery environment (e.g., TWRP) via fastboot without
modifying the device, then collects filesystem data from the recovery
environment. The device returns to its original OS after reboot.

Collection workflow:
1. Device enters fastboot mode (manual or via 'adb reboot bootloader')
2. 'fastboot boot recovery.img' boots a temporary recovery (non-destructive)
3. Device appears in ADB as recovery mode
4. Filesystem data is collected via ADB from the recovery environment
5. 'adb reboot' returns the device to the original OS

Collectible data:
- android_fastboot_filesystem: Filesystem data from recovery environment
- android_fastboot_partition: Raw partition binary data via dd imaging

Requirements:
    - fastboot binary (Android SDK platform-tools or system package)
    - adb binary (Android SDK platform-tools or system package)
    - A compatible recovery image (e.g., TWRP) for the target device model
    - Unlocked bootloader on the target device

Note:
    'fastboot boot' boots a recovery image temporarily and does NOT flash
    the device. The original boot image is restored automatically on reboot.
"""
from __future__ import annotations

import hashlib
import logging
import os
import shlex
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple

logger = logging.getLogger(__name__)


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
class FastbootDevice:
    """Information about a device visible in fastboot mode."""
    serial: str
    product: str = ''
    model: str = ''
    bootloader_version: str = ''
    unlocked: bool = False
    transport_id: str = ''

    def __str__(self) -> str:
        lock_state = 'unlocked' if self.unlocked else 'locked'
        return (
            f"FastbootDevice(serial={self.serial!r}, "
            f"product={self.product!r}, model={self.model!r}, "
            f"bootloader={self.bootloader_version!r}, {lock_state})"
        )


@dataclass
class CollectionResult:
    """Summary result of a collection operation."""
    device_serial: str
    files_collected: int = 0
    bytes_collected: int = 0
    errors: List[str] = field(default_factory=list)
    collection_method: str = 'fastboot_recovery'


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def fastboot_available() -> bool:
    """
    Check whether a fastboot binary is accessible.

    Searches the PATH and a set of well-known standard locations.

    Returns:
        True if fastboot is found and responds to 'fastboot --version'.
    """
    collector = AndroidFastbootCollector.__new__(AndroidFastbootCollector)
    collector._fastboot_path = None  # type: ignore[attr-defined]
    found = collector._find_fastboot()
    if found is None:
        return False
    try:
        result = _run([found, '--version'], timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def check_fastboot_recovery_guide() -> str:
    """
    Return a multi-line guide string for preparing fastboot recovery collection.

    Covers:
    1. Putting the device into fastboot mode manually.
    2. Bootloader unlock requirements.
    3. How to obtain a recovery image for a specific device model.

    Returns:
        Multi-line plain-text guide string.
    """
    return """\
=============================================================
  Android Fastboot Recovery Collection — Preparation Guide
=============================================================

STEP 1 — Put the device into fastboot (bootloader) mode
---------------------------------------------------------
  Option A — Hardware key combination (power-off method):
    1. Power off the device completely.
    2. Hold [Volume Down] + [Power] simultaneously (most Android devices).
       - Google Pixel: Volume Down + Power
       - Samsung: Volume Down + Bixby/Home + Power
       - OnePlus: Volume Up + Power
       - Xiaomi/Redmi: Volume Down + Power
    3. Release when the fastboot / bootloader screen appears.

  Option B — ADB command (device must be on, USB debugging enabled):
    $ adb reboot bootloader

  Verify the device is visible in fastboot mode:
    $ fastboot devices

STEP 2 — Bootloader unlock requirements
----------------------------------------
  - The device bootloader MUST be unlocked before booting a custom recovery.
  - Unlocking typically wipes all user data (factory reset) and requires a
    manufacturer account on some devices (e.g., Xiaomi Mi Unlock, Sony Emma).
  - Unlock command (standard AOSP / most Pixel, OnePlus, Motorola):
      $ fastboot flashing unlock
    Older devices may use:
      $ fastboot oem unlock
  - After unlock, confirm the on-screen prompt on the device, then:
      $ fastboot reboot
  - Verify unlock status:
      $ fastboot getvar unlocked

  WARNING: Unlocking the bootloader permanently changes device state and may
  void the warranty. Check the device manufacturer's policy before proceeding.

STEP 3 — Obtain a recovery image for the target device model
-------------------------------------------------------------
  - Identify the exact device model and Android version:
      $ fastboot getvar product
      $ fastboot getvar version
  - Sources for TWRP recovery images:
      Official TWRP device list: https://twrp.me/Devices/
  - Sources for OEM / generic recovery images:
      - XDA Developers forum (https://xda-developers.com)
      - Manufacturer support pages for supported devices
  - Match the recovery image to the EXACT device codename (e.g., 'blueline'
    for Pixel 3, 'cheetah' for Pixel 7 Pro). Using the wrong image can result
    in a failed boot or, in rare cases, a bricked device.
  - Store the recovery image locally and supply the path to boot_recovery().

STEP 4 — Run collection
------------------------
  collector = AndroidFastbootCollector(output_dir='/path/to/output')
  devices = collector.find_fastboot_devices()
  if devices and devices[0].unlocked:
      collector.boot_recovery(recovery_img_path='/path/to/twrp.img',
                              serial=devices[0].serial)
      for path, meta in collector.collect_from_recovery(output_dir='/path/to/output'):
          print(f"Collected: {path}")
      collector.reboot_to_os()

=============================================================
"""


# ---------------------------------------------------------------------------
# Main collector class
# ---------------------------------------------------------------------------

class AndroidFastbootCollector:
    """
    Forensic collector that uses fastboot to boot a temporary recovery
    environment and collect filesystem data via ADB.

    The original device OS is not modified; 'fastboot boot' loads the
    recovery image into RAM only.
    """

    # Default filesystem paths to collect from recovery mode
    DEFAULT_COLLECT_PATHS: List[str] = [
        '/data',
        '/sdcard',
        '/system/app',
        '/cache',
    ]

    # Partition names commonly targeted for binary imaging
    DEFAULT_PARTITION_NAMES: List[str] = [
        'userdata',
        'system',
        'boot',
    ]

    # Candidate fastboot binary locations (searched in order)
    _FASTBOOT_SEARCH_LOCATIONS: List[str] = [
        'fastboot',  # PATH
        'resources/platform-tools/fastboot',
        'resources/platform-tools/fastboot.exe',
        os.path.expanduser('~/Android/Sdk/platform-tools/fastboot'),
        os.path.expanduser('~/Android/sdk/platform-tools/fastboot'),
        '/usr/bin/fastboot',
        '/usr/local/bin/fastboot',
        '/opt/android-sdk/platform-tools/fastboot',
        '/opt/homebrew/bin/fastboot',  # macOS Homebrew arm64
    ]

    # Candidate adb binary locations (searched in order)
    _ADB_SEARCH_LOCATIONS: List[str] = [
        'adb',  # PATH
        'resources/platform-tools/adb',
        'resources/platform-tools/adb.exe',
        os.path.expanduser('~/Android/Sdk/platform-tools/adb'),
        os.path.expanduser('~/Android/sdk/platform-tools/adb'),
        '/usr/bin/adb',
        '/usr/local/bin/adb',
        '/opt/android-sdk/platform-tools/adb',
        '/opt/homebrew/bin/adb',
    ]

    def __init__(
        self,
        output_dir: str,
        fastboot_path: Optional[str] = None,
        adb_path: Optional[str] = None,
    ) -> None:
        """
        Initialise the collector.

        Args:
            output_dir: Default directory for collected files.
            fastboot_path: Explicit path to fastboot binary. If None, the
                           binary is located automatically.
            adb_path: Explicit path to adb binary. If None, the binary is
                      located automatically.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._fastboot_path: Optional[str] = fastboot_path
        self._adb_path: Optional[str] = adb_path

    # ------------------------------------------------------------------
    # Binary discovery
    # ------------------------------------------------------------------

    def _find_fastboot(self) -> Optional[str]:
        """
        Find the fastboot binary in standard locations.

        Returns:
            Absolute path string if found, None otherwise.
        """
        for candidate in self._FASTBOOT_SEARCH_LOCATIONS:
            expanded = os.path.expandvars(candidate)
            try:
                result = _run([expanded, '--version'], timeout=5)
                if result.returncode == 0:
                    logger.debug("fastboot found: %s", expanded)
                    return expanded
            except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
                continue
        logger.warning("fastboot binary not found in any standard location")
        return None

    def _find_adb(self) -> Optional[str]:
        """
        Find the adb binary in standard locations.

        Returns:
            Absolute path string if found, None otherwise.
        """
        for candidate in self._ADB_SEARCH_LOCATIONS:
            expanded = os.path.expandvars(candidate)
            try:
                result = _run([expanded, 'version'], timeout=5)
                if result.returncode == 0:
                    logger.debug("adb found: %s", expanded)
                    return expanded
            except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
                continue
        logger.warning("adb binary not found in any standard location")
        return None

    @property
    def fastboot(self) -> str:
        """Resolved path to the fastboot binary (lazy, cached)."""
        if self._fastboot_path is None:
            self._fastboot_path = self._find_fastboot()
        if self._fastboot_path is None:
            raise FileNotFoundError(
                "fastboot binary not found. Install Android SDK platform-tools "
                "or set fastboot_path= on AndroidFastbootCollector."
            )
        return self._fastboot_path

    @property
    def adb(self) -> str:
        """Resolved path to the adb binary (lazy, cached)."""
        if self._adb_path is None:
            self._adb_path = self._find_adb()
        if self._adb_path is None:
            raise FileNotFoundError(
                "adb binary not found. Install Android SDK platform-tools "
                "or set adb_path= on AndroidFastbootCollector."
            )
        return self._adb_path

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """
        Check whether the fastboot binary is accessible and functional.

        Returns:
            True if fastboot responds successfully to a version query.
        """
        try:
            result = _run([self.fastboot, '--version'], timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return False

    # ------------------------------------------------------------------
    # Device enumeration
    # ------------------------------------------------------------------

    def find_fastboot_devices(self) -> List[FastbootDevice]:
        """
        List devices currently visible in fastboot mode.

        Parses the output of 'fastboot devices' and optionally retrieves
        per-device variable data for devices that report a transport ID.

        Returns:
            List of FastbootDevice instances. May be empty if no devices
            are connected in fastboot mode.
        """
        devices: List[FastbootDevice] = []
        try:
            result = _run([self.fastboot, 'devices'], timeout=15)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
            logger.error("fastboot devices failed: %s", exc)
            return devices

        if result.returncode != 0:
            logger.warning(
                "fastboot devices returned %d: %s",
                result.returncode,
                result.stderr.decode(errors='replace').strip(),
            )
            return devices

        output = result.stdout.decode(errors='replace')
        for line in output.splitlines():
            line = line.strip()
            if not line or '\t' not in line:
                continue
            parts = line.split('\t', 1)
            serial = parts[0].strip()
            state = parts[1].strip() if len(parts) > 1 else ''
            if state.lower() != 'fastboot':
                # Some non-fastboot entries may appear; skip them.
                continue
            device = FastbootDevice(serial=serial)
            try:
                self._populate_device_info(device)
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "Could not retrieve info for %s: %s", serial, exc
                )
            devices.append(device)

        logger.info("Found %d fastboot device(s)", len(devices))
        return devices

    def _populate_device_info(self, device: FastbootDevice) -> None:
        """
        Fill in product, model, bootloader version, and unlock status for a
        given FastbootDevice by querying 'fastboot getvar'.

        Args:
            device: FastbootDevice to populate in-place.
        """
        var_map = {
            'product': 'product',
            'version-bootloader': 'bootloader_version',
            'unlocked': None,  # handled separately
        }
        serial_args = ['-s', device.serial] if device.serial else []
        for var_name, attr in var_map.items():
            value = self._getvar(var_name, serial=device.serial)
            if value is None:
                continue
            if var_name == 'unlocked':
                device.unlocked = value.lower() in ('yes', 'true', '1')
            elif attr:
                setattr(device, attr, value)

        # 'product' sometimes returns 'model' on some OEM devices
        model_value = self._getvar('model', serial=device.serial)
        if model_value:
            device.model = model_value

    # ------------------------------------------------------------------
    # Variable queries
    # ------------------------------------------------------------------

    def _getvar(self, variable: str, serial: Optional[str] = None) -> Optional[str]:
        """
        Retrieve a single fastboot variable value.

        Args:
            variable: Variable name (e.g., 'product', 'unlocked').
            serial: Device serial. Uses the default device if None.

        Returns:
            String value if found, None if the query failed or returned empty.
        """
        cmd = [self.fastboot]
        if serial:
            cmd += ['-s', serial]
        cmd += ['getvar', variable]
        try:
            result = _run(cmd, timeout=10)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
            logger.debug("getvar %s failed: %s", variable, exc)
            return None

        # fastboot prints getvar results to stderr
        output = result.stderr.decode(errors='replace')
        for line in output.splitlines():
            # Expected format: "variable: value"
            if line.lower().startswith(variable.lower() + ':'):
                raw_value = line.split(':', 1)[1].strip()
                return raw_value if raw_value else None
        return None

    def get_device_info(self, serial: Optional[str] = None) -> Optional[FastbootDevice]:
        """
        Query and return device information for a fastboot-mode device.

        Args:
            serial: Device serial number. Uses the default device if None.

        Returns:
            FastbootDevice with populated fields, or None on failure.
        """
        try:
            device = FastbootDevice(serial=serial or '')
            self._populate_device_info(device)
            return device
        except Exception as exc:  # noqa: BLE001
            logger.error("get_device_info failed: %s", exc)
            return None

    def is_bootloader_unlocked(self, serial: Optional[str] = None) -> bool:
        """
        Check whether the device bootloader is unlocked.

        Args:
            serial: Device serial. Uses the default device if None.

        Returns:
            True if 'fastboot getvar unlocked' returns 'yes'.
        """
        value = self._getvar('unlocked', serial=serial)
        if value is None:
            logger.warning(
                "Could not determine bootloader unlock status for %s",
                serial or '(default)',
            )
            return False
        return value.lower() in ('yes', 'true', '1')

    # ------------------------------------------------------------------
    # Recovery boot
    # ------------------------------------------------------------------

    def boot_recovery(
        self,
        recovery_img_path: str,
        serial: Optional[str] = None,
        timeout: int = 120,
    ) -> bool:
        """
        Boot a temporary recovery image via fastboot without flashing.

        The recovery image is loaded into RAM only. The original boot image
        is not modified and is restored on the next normal reboot.

        Args:
            recovery_img_path: Local path to the recovery .img file.
            serial: Device serial. Uses the default fastboot device if None.
            timeout: Maximum seconds to wait for the device to appear in ADB
                     recovery mode after issuing the boot command.

        Returns:
            True if the device successfully appeared in ADB recovery mode,
            False if the boot command failed or the timeout was exceeded.
        """
        img_path = Path(recovery_img_path)
        if not img_path.is_file():
            logger.error("Recovery image not found: %s", img_path)
            return False

        cmd = [self.fastboot]
        if serial:
            cmd += ['-s', serial]
        cmd += ['boot', str(img_path)]

        logger.info("Booting recovery image: %s (serial=%s)", img_path.name, serial)
        try:
            result = _run(cmd, timeout=60)
        except subprocess.TimeoutExpired:
            logger.error("fastboot boot timed out after 60s")
            return False
        except (FileNotFoundError, OSError) as exc:
            logger.error("fastboot boot failed: %s", exc)
            return False

        if result.returncode != 0:
            stderr_text = result.stderr.decode(errors='replace').strip()
            logger.error(
                "fastboot boot returned %d: %s", result.returncode, stderr_text
            )
            return False

        logger.info("fastboot boot succeeded; waiting for ADB recovery mode …")
        appeared = self._wait_for_recovery_adb(serial=serial, timeout=timeout)
        if appeared:
            logger.info("Device is in ADB recovery mode (serial=%s)", serial)
        else:
            logger.warning(
                "Device did not appear in ADB recovery mode within %ds", timeout
            )
        return appeared

    # ------------------------------------------------------------------
    # ADB recovery detection
    # ------------------------------------------------------------------

    def _wait_for_recovery_adb(
        self,
        serial: Optional[str] = None,
        timeout: int = 120,
    ) -> bool:
        """
        Poll 'adb devices' until the target device appears with state 'recovery'.

        Uses exponential backoff between polling attempts (2, 4, 8, 16, 16 s).

        Args:
            serial: Expected device serial. If None, any device in recovery
                    mode satisfies the condition.
            timeout: Maximum total seconds to wait.

        Returns:
            True if the device entered recovery state before the timeout.
        """
        deadline = time.monotonic() + timeout
        attempt = 0
        max_backoff_exp = 4  # cap at 2^4 = 16 seconds

        while time.monotonic() < deadline:
            sleep_secs = 2 ** min(attempt, max_backoff_exp)
            remaining = deadline - time.monotonic()
            actual_sleep = min(sleep_secs, max(remaining, 0))
            if actual_sleep > 0:
                time.sleep(actual_sleep)

            attempt += 1
            try:
                result = _run([self.adb, 'devices'], timeout=10)
            except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
                logger.debug("adb devices poll failed: %s", exc)
                continue

            output = result.stdout.decode(errors='replace')
            for line in output.splitlines():
                line = line.strip()
                if not line or line.startswith('List of'):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                dev_serial, dev_state = parts[0], parts[1]
                if dev_state.lower() != 'recovery':
                    continue
                if serial is None or dev_serial == serial:
                    return True

        return False

    def _is_in_recovery(self, serial: Optional[str] = None) -> bool:
        """
        Check immediately (no waiting) whether a device is in ADB recovery mode.

        Args:
            serial: Device serial to check. Any recovery device if None.

        Returns:
            True if the device is currently in recovery mode.
        """
        try:
            result = _run([self.adb, 'devices'], timeout=10)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return False

        output = result.stdout.decode(errors='replace')
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            dev_serial, dev_state = parts[0], parts[1]
            if dev_state.lower() == 'recovery':
                if serial is None or dev_serial == serial:
                    return True
        return False

    # ------------------------------------------------------------------
    # Filesystem collection from recovery
    # ------------------------------------------------------------------

    def collect_from_recovery(
        self,
        output_dir: str,
        serial: Optional[str] = None,
        collect_paths: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Pull filesystem data from the device while it is in recovery mode.

        The device must already be in ADB recovery mode (use boot_recovery()
        first). Each collected file is yielded together with a metadata dict.

        Args:
            output_dir: Local directory to write collected files into.
            serial: Device serial. Uses the first recovery-mode device if None.
            collect_paths: Device-side paths to pull. Defaults to
                           DEFAULT_COLLECT_PATHS.
            progress_callback: Optional callable(path, current_bytes, total_bytes).
                               total_bytes is 0 when unknown.

        Yields:
            (local_file_path, metadata_dict) for each file successfully
            collected.

        Metadata dict keys:
            artifact_type, original_path, filename, size, sha256,
            collection_method, device_serial.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        paths_to_collect = collect_paths if collect_paths else self.DEFAULT_COLLECT_PATHS

        adb_serial_args: List[str] = ['-s', serial] if serial else []
        device_label = serial or '(default)'

        if not self._is_in_recovery(serial=serial):
            logger.error(
                "Device %s is not in ADB recovery mode. "
                "Call boot_recovery() first.",
                device_label,
            )
            return

        for device_path in paths_to_collect:
            # Sanitize device path to a safe local subdirectory name
            safe_subdir = device_path.lstrip('/').replace('/', os.sep)
            local_target = out / safe_subdir
            local_target.mkdir(parents=True, exist_ok=True)

            logger.info(
                "Pulling %s from device %s → %s",
                device_path, device_label, local_target,
            )

            cmd = [self.adb] + adb_serial_args + [
                'pull', device_path, str(local_target),
            ]
            try:
                result = _run(cmd, timeout=3600)  # large directories may take time
            except subprocess.TimeoutExpired:
                logger.error("adb pull timed out for path: %s", device_path)
                continue
            except (FileNotFoundError, OSError) as exc:
                logger.error("adb pull failed for %s: %s", device_path, exc)
                continue

            if result.returncode != 0:
                stderr_text = result.stderr.decode(errors='replace').strip()
                logger.warning(
                    "adb pull %s returned %d: %s",
                    device_path, result.returncode, stderr_text,
                )
                # Partial pulls may still yield files below; continue walking.

            # Walk collected files and yield metadata
            for local_file in local_target.rglob('*'):
                if not local_file.is_file():
                    continue

                file_size = local_file.stat().st_size
                sha256 = _sha256_file(local_file)

                # Reconstruct the original device path
                relative = local_file.relative_to(local_target)
                original_path = device_path.rstrip('/') + '/' + str(relative).replace(os.sep, '/')

                metadata: Dict[str, Any] = {
                    'artifact_type': 'android_fastboot_filesystem',
                    'original_path': original_path,
                    'filename': local_file.name,
                    'size': file_size,
                    'sha256': sha256,
                    'collection_method': 'fastboot_recovery',
                    'device_serial': serial or '',
                    'source_path': device_path,
                }

                if progress_callback is not None:
                    try:
                        progress_callback(original_path, file_size, 0)
                    except Exception:  # noqa: BLE001
                        pass

                yield str(local_file), metadata

    # ------------------------------------------------------------------
    # Partition imaging from recovery
    # ------------------------------------------------------------------

    def partition_image_recovery(
        self,
        partition_names: List[str],
        output_dir: str,
        serial: Optional[str] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Create binary images of raw partitions using 'dd' via ADB shell while
        the device is in recovery mode.

        The block device node for each partition is resolved by checking
        /dev/block/by-name/<partition> on the device, with a fallback to
        /dev/block/<partition>.

        Args:
            partition_names: List of partition names to image
                             (e.g., ['userdata', 'system', 'boot']).
            output_dir: Local directory to write .img files into.
            serial: Device serial. Uses the first recovery-mode device if None.
            progress_callback: Optional callable(partition_name, bytes_written, 0).

        Yields:
            (local_image_path, metadata_dict) for each successfully imaged
            partition.

        Metadata dict keys:
            artifact_type, partition, original_path, filename, size, sha256,
            collection_method, device_serial.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        adb_serial_args: List[str] = ['-s', serial] if serial else []
        device_label = serial or '(default)'

        if not self._is_in_recovery(serial=serial):
            logger.error(
                "Device %s is not in ADB recovery mode. "
                "Call boot_recovery() first.",
                device_label,
            )
            return

        for partition in partition_names:
            block_device = self._resolve_block_device(
                partition, serial=serial, adb_serial_args=adb_serial_args
            )
            if block_device is None:
                logger.warning(
                    "Block device for partition '%s' not found on device %s; skipping.",
                    partition, device_label,
                )
                continue

            local_img = out / f"{partition}.img"
            logger.info(
                "Imaging partition '%s' (%s) → %s",
                partition, block_device, local_img,
            )

            # Stream via 'adb exec-out' to avoid shell escaping issues
            dd_cmd = f"dd if={shlex.quote(block_device)} bs=4096 2>/dev/null"
            exec_cmd = [self.adb] + adb_serial_args + [
                'exec-out', dd_cmd,
            ]

            success = _stream_exec_out_to_file(
                exec_cmd,
                local_img,
                label=partition,
                progress_callback=progress_callback,
            )

            if not success or not local_img.exists():
                logger.error("Partition imaging failed for '%s'", partition)
                continue

            file_size = local_img.stat().st_size
            if file_size == 0:
                logger.warning(
                    "Partition image '%s' is empty; skipping.", partition
                )
                continue

            sha256 = _sha256_file(local_img)

            metadata: Dict[str, Any] = {
                'artifact_type': 'android_fastboot_partition',
                'partition': partition,
                'original_path': block_device,
                'filename': local_img.name,
                'size': file_size,
                'sha256': sha256,
                'collection_method': 'fastboot_recovery',
                'device_serial': serial or '',
            }

            if progress_callback is not None:
                try:
                    progress_callback(partition, file_size, 0)
                except Exception:  # noqa: BLE001
                    pass

            yield str(local_img), metadata

    def _resolve_block_device(
        self,
        partition: str,
        serial: Optional[str],
        adb_serial_args: List[str],
    ) -> Optional[str]:
        """
        Resolve a partition name to its /dev/block path on the device.

        Checks /dev/block/by-name/<partition> first, then falls back to
        /dev/block/<partition>.

        Args:
            partition: Partition name (e.g., 'userdata').
            serial: Device serial (used in logging only).
            adb_serial_args: Pre-built '-s <serial>' list for subprocess calls.

        Returns:
            Device path string, or None if unresolvable.
        """
        by_name = f"/dev/block/by-name/{partition}"
        fallback = f"/dev/block/{partition}"

        for candidate in (by_name, fallback):
            cmd = [self.adb] + adb_serial_args + [
                'shell', f"test -e {shlex.quote(candidate)} && echo EXISTS"
            ]
            try:
                result = _run(cmd, timeout=15)
                if result.returncode == 0 and b'EXISTS' in result.stdout:
                    logger.debug("Block device resolved: %s → %s", partition, candidate)
                    return candidate
            except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
                logger.debug("Block device probe failed for %s: %s", candidate, exc)

        return None

    # ------------------------------------------------------------------
    # Reboot helpers
    # ------------------------------------------------------------------

    def reboot_to_os(self, serial: Optional[str] = None) -> bool:
        """
        Reboot the device from recovery mode back to the normal OS.

        Issues 'adb reboot' from the current ADB connection (recovery mode).

        Args:
            serial: Device serial. Uses the default device if None.

        Returns:
            True if the reboot command was accepted (returncode 0).
        """
        adb_serial_args: List[str] = ['-s', serial] if serial else []
        cmd = [self.adb] + adb_serial_args + ['reboot']
        logger.info("Rebooting device %s to OS …", serial or '(default)')
        try:
            result = _run(cmd, timeout=30)
            if result.returncode == 0:
                logger.info("Reboot command accepted")
                return True
            stderr_text = result.stderr.decode(errors='replace').strip()
            logger.warning("adb reboot returned %d: %s", result.returncode, stderr_text)
            return False
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
            logger.error("adb reboot failed: %s", exc)
            return False

    def reboot_to_fastboot(self, serial: Optional[str] = None) -> bool:
        """
        Reboot a normally running device into fastboot (bootloader) mode.

        Issues 'adb reboot bootloader'. The device must be in normal ADB
        device mode (USB debugging enabled) for this command to work.

        Args:
            serial: Device serial. Uses the default device if None.

        Returns:
            True if the reboot command was accepted.
        """
        adb_serial_args: List[str] = ['-s', serial] if serial else []
        cmd = [self.adb] + adb_serial_args + ['reboot', 'bootloader']
        logger.info("Rebooting device %s to fastboot …", serial or '(default)')
        try:
            result = _run(cmd, timeout=30)
            if result.returncode == 0:
                logger.info("Reboot-to-fastboot command accepted")
                return True
            stderr_text = result.stderr.decode(errors='replace').strip()
            logger.warning(
                "adb reboot bootloader returned %d: %s",
                result.returncode, stderr_text,
            )
            return False
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
            logger.error("adb reboot bootloader failed: %s", exc)
            return False


# ---------------------------------------------------------------------------
# Module-level utility functions
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    """
    Compute the SHA-256 digest of a local file.

    Reads the file in 1 MiB chunks to handle large images efficiently.

    Args:
        path: Path to the file.

    Returns:
        Lowercase hex digest string, or empty string on read error.
    """
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
    except OSError as exc:
        logger.error("SHA-256 computation failed for %s: %s", path, exc)
        return ''
    return h.hexdigest()


def _stream_exec_out_to_file(
    cmd: List[str],
    dest: Path,
    label: str = '',
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> bool:
    """
    Run a command and stream its stdout directly to a local file.

    Used for 'adb exec-out dd …' to pipe binary partition data to disk
    without buffering the entire image in memory.

    Args:
        cmd: Command and arguments list.
        dest: Destination file path.
        label: Human-readable label for progress reporting.
        progress_callback: Optional callable(label, bytes_written, 0).

    Returns:
        True if the command exited with returncode 0, False otherwise.
    """
    bytes_written = 0
    try:
        with open(dest, 'wb') as out_fh:
            proc = subprocess.Popen(
                cmd,
                stdout=out_fh,
                stderr=subprocess.PIPE,
                creationflags=_no_window_flags(),
            )
            # Wait; stderr is piped so it won't block stdout writing
            _, stderr_data = proc.communicate(timeout=7200)
            returncode = proc.returncode

        if dest.exists():
            bytes_written = dest.stat().st_size

        if returncode != 0:
            stderr_text = stderr_data.decode(errors='replace').strip() if stderr_data else ''
            logger.warning(
                "exec-out dd for '%s' returned %d: %s",
                label, returncode, stderr_text,
            )
            return False

        if progress_callback is not None and bytes_written:
            try:
                progress_callback(label, bytes_written, 0)
            except Exception:  # noqa: BLE001
                pass

        logger.debug(
            "Partition '%s' imaged: %d bytes → %s", label, bytes_written, dest
        )
        return True

    except subprocess.TimeoutExpired:
        logger.error("Partition imaging timed out for '%s'", label)
        try:
            proc.kill()  # type: ignore[name-defined]
        except Exception:  # noqa: BLE001
            pass
        return False
    except (FileNotFoundError, OSError) as exc:
        logger.error("exec-out dd failed for '%s': %s", label, exc)
        return False
