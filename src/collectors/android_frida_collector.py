"""
Android Frida Process Memory Collector Module

Collects process memory data from Android applications using the Frida
dynamic instrumentation framework. Requires frida-server running on the
device with root privileges.

Collectible artifacts:
- android_process_memory: Raw memory pages from running application processes

Requirements:
    - frida>=16.0.0
    - frida-tools>=12.0.0 (optional, for frida-ps CLI)
    - Android device with root access
    - frida-server binary pushed to device (auto-setup supported)

Notes:
    - frida-server must match the frida Python package version exactly
    - Device architecture is auto-detected (arm64-v8a, armeabi-v7a, x86_64, x86)
    - Root access is required to start frida-server and attach to app processes
"""
from __future__ import annotations

import hashlib
import json
import logging
import lzma
import os
import struct
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Frida availability check
# ---------------------------------------------------------------------------

try:
    import frida  # type: ignore
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False


def frida_available() -> bool:
    """Return True if the frida Python package is installed and importable."""
    return FRIDA_AVAILABLE


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Frida server release base URL
_FRIDA_RELEASE_BASE = (
    "https://github.com/frida/frida/releases/download"
    "/{version}/frida-server-{version}-android-{arch}.xz"
)

# Remote path where frida-server is pushed
_FRIDA_SERVER_REMOTE = "/data/local/tmp/frida-server"

# Architecture map: Android ABI → frida arch string
_ARCH_MAP: Dict[str, str] = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}

# Memory region size limits
_MIN_REGION_BYTES: int = 4 * 1024          # 4 KB
_MAX_REGION_BYTES: int = 256 * 1024 * 1024  # 256 MB
_MAX_TOTAL_BYTES: int = 2 * 1024 * 1024 * 1024  # 2 GB per process

# Frida script: enumerate readable memory regions on the target process
_ENUM_RANGES_SCRIPT = """
(function() {
    var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
    var filtered = ranges.filter(function(r) {
        return r.size >= %(min_size)d && r.size <= %(max_size)d;
    });
    send(JSON.stringify(filtered));
})();
""" % {
    "min_size": _MIN_REGION_BYTES,
    "max_size": _MAX_REGION_BYTES,
}

# Frida script: read a single contiguous memory region and send raw bytes
_READ_REGION_SCRIPT = """
(function() {
    try {
        var data = Memory.readByteArray(ptr('%(addr)s'), %(size)d);
        send(null, data);
    } catch (e) {
        send('ERROR:' + e.message);
    }
})();
"""

# Target application packages for process memory collection
FORENSIC_TARGET_PACKAGES: List[str] = [
    "com.kakao.talk",
    "com.whatsapp",
    "org.telegram.messenger",
    "com.viber.voip",
    "com.facebook.orca",
    "com.discord",
    "com.microsoft.teams",
    "com.slack",
    "com.skype.raider",
    "com.instagram.android",
    "com.google.android.gm",
    "com.google.android.apps.messaging",
]


# ---------------------------------------------------------------------------
# Helper: compute SHA-256 of a file
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Main collector class
# ---------------------------------------------------------------------------

class AndroidFridaCollector:
    """
    Collects process memory data from Android applications via Frida.

    Requires:
        - frida Python package installed on the host
        - frida-server running (or startable) on the target Android device
        - Root access on the device to start frida-server and attach to processes

    Args:
        adb_shell_func: Callable that executes a shell command on the device and
            returns stdout as a string.  Signature: ``(cmd: str) -> str``.
        adb_push_func:  Callable that pushes a local file to the device.
            Signature: ``(local_path: str, remote_path: str) -> None``.
        output_dir:     Base directory where collected data is written.
        device_serial:  Optional ADB device serial; used when multiple devices
            are connected.
    """

    def __init__(
        self,
        adb_shell_func: Callable[[str], str],
        adb_push_func: Callable[[str, str], None],
        output_dir: str,
        device_serial: Optional[str] = None,
    ) -> None:
        self._adb_shell = adb_shell_func
        self._adb_push = adb_push_func
        self._output_dir = Path(output_dir)
        self._device_serial = device_serial
        self._frida_device: Optional[Any] = None  # frida.Device
        self._server_started_by_us: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if the frida Python package is installed."""
        return frida_available()

    def check_frida_server(self) -> bool:
        """
        Check whether frida-server is currently running on the device.

        Returns:
            True if a frida-server process is found in the device process list.
        """
        try:
            output = self._adb_shell("ps -A 2>/dev/null | grep frida-server")
            return "frida-server" in output
        except Exception as exc:
            logger.debug("check_frida_server: %s", exc)
            return False

    def setup_frida_server(
        self,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> bool:
        """
        Push frida-server to the device and start it if not already running.

        Steps:
            1. Skip if frida-server is already running.
            2. Detect device CPU architecture.
            3. Download the matching frida-server binary from GitHub Releases.
            4. Push the binary to ``/data/local/tmp/frida-server``.
            5. ``chmod 755`` and start with ``su -c '… &'``.

        Args:
            progress_callback: Optional callable receiving human-readable status
                strings during setup.

        Returns:
            True on success, False on any failure.
        """
        def _progress(msg: str) -> None:
            logger.info("frida-server setup: %s", msg)
            if progress_callback:
                progress_callback(msg)

        if self.check_frida_server():
            _progress("frida-server already running — skipping setup")
            return True

        if not frida_available():
            _progress("frida Python package not installed")
            return False

        import frida as _frida  # noqa: F401  (already checked above)

        # Detect device architecture
        arch_abi = self._adb_shell("getprop ro.product.cpu.abi").strip()
        frida_arch = _ARCH_MAP.get(arch_abi)
        if not frida_arch:
            _progress(f"Unsupported device architecture: {arch_abi!r}")
            return False

        # Determine matching frida version from installed package
        try:
            import frida as _frida_pkg
            frida_version: str = _frida_pkg.__version__
        except Exception:
            frida_version = "16.5.6"

        url = _FRIDA_RELEASE_BASE.format(version=frida_version, arch=frida_arch)
        _progress(f"Downloading frida-server {frida_version} for {frida_arch} …")
        logger.debug("Download URL: %s", url)

        try:
            with tempfile.NamedTemporaryFile(suffix=".xz", delete=False) as tmp_xz:
                tmp_xz_path = tmp_xz.name
                urllib.request.urlretrieve(url, tmp_xz_path)

            # Decompress .xz
            tmp_bin_path = tmp_xz_path.replace(".xz", "")
            _progress("Decompressing frida-server binary …")
            with lzma.open(tmp_xz_path, "rb") as xz_in, open(tmp_bin_path, "wb") as bin_out:
                bin_out.write(xz_in.read())

            os.unlink(tmp_xz_path)

            # Push to device
            _progress(f"Pushing frida-server to {_FRIDA_SERVER_REMOTE} …")
            self._adb_push(tmp_bin_path, _FRIDA_SERVER_REMOTE)
            os.unlink(tmp_bin_path)

        except Exception as exc:
            _progress(f"Failed to download/push frida-server: {exc}")
            logger.exception("frida-server download/push failed")
            return False

        # Set executable permission
        try:
            self._adb_shell(f"chmod 755 {_FRIDA_SERVER_REMOTE}")
        except Exception as exc:
            _progress(f"chmod failed: {exc}")
            return False

        # Start frida-server with root
        _progress("Starting frida-server on device …")
        try:
            self._adb_shell(
                f"su -c '{_FRIDA_SERVER_REMOTE} -D &'"
            )
            time.sleep(2)  # Give server time to bind its port
        except Exception as exc:
            _progress(f"Failed to start frida-server: {exc}")
            return False

        if self.check_frida_server():
            _progress("frida-server started successfully")
            self._server_started_by_us = True
            return True

        _progress("frida-server did not appear in process list after start")
        return False

    def collect_process_memory(
        self,
        package_name: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Attach to a running application process and collect its memory pages.

        Memory regions with ``r`` (readable) protection are enumerated and
        saved as individual raw binary files.  A ``memory_map.json`` index
        file is also written alongside the region files.

        Output layout::

            output_dir/
            └── {package_name}/
                ├── memory_map.json
                ├── memory_region_0x7f0000_4096.bin
                └── …

        Args:
            package_name:      Android package name to target, e.g.
                ``"com.kakao.talk"``.
            output_dir:        Directory under which a sub-directory named after
                the package is created.
            progress_callback: Optional status callback.

        Yields:
            Tuples of ``(local_path_str, metadata_dict)``.  Each yielded item
            represents one saved memory region file (or the map file).
        """
        def _progress(msg: str) -> None:
            logger.info("[%s] %s", package_name, msg)
            if progress_callback:
                progress_callback(msg)

        if not frida_available():
            _progress("frida not available — skipping memory collection")
            return

        import frida as _frida

        # Resolve Frida device
        device = self._get_frida_device()
        if device is None:
            _progress("Could not connect to Frida device via USB")
            return

        # Resolve PID
        pid = self._find_pid(device, package_name)
        if pid is None:
            _progress(f"Process not found for package: {package_name}")
            return

        _progress(f"Attaching to PID {pid} …")

        # Prepare output directory
        pkg_dir = output_dir / package_name
        pkg_dir.mkdir(parents=True, exist_ok=True)

        try:
            session = device.attach(pid)
        except Exception as exc:
            _progress(f"Failed to attach to PID {pid}: {exc}")
            return

        try:
            # Enumerate memory regions
            _progress("Enumerating readable memory regions …")
            ranges = self._enumerate_ranges(session)
            if not ranges:
                _progress("No readable regions found or enumeration failed")
                return

            _progress(f"Found {len(ranges)} readable region(s)")

            memory_map: List[Dict[str, Any]] = []
            total_bytes = 0

            for region in ranges:
                base_addr: str = region.get("base", "0x0")
                size: int = region.get("size", 0)
                protection: str = region.get("protection", "---")
                file_info: Dict[str, Any] = region.get("file", {}) or {}
                region_file: str = file_info.get("path", "") if isinstance(file_info, dict) else ""

                if total_bytes + size > _MAX_TOTAL_BYTES:
                    _progress(
                        f"Reached per-process limit ({_MAX_TOTAL_BYTES // (1024**3)} GB) — "
                        "stopping early"
                    )
                    break

                # Sanitize address for filename
                addr_clean = base_addr.replace("0x", "").replace("X", "").lower()
                bin_filename = f"memory_region_{addr_clean}_{size}.bin"
                bin_path = pkg_dir / bin_filename

                raw_data = self._read_region(session, base_addr, size)
                if raw_data is None:
                    logger.debug("Skipping unreadable region %s+%d", base_addr, size)
                    continue

                bin_path.write_bytes(raw_data)
                sha256 = hashlib.sha256(raw_data).hexdigest()
                total_bytes += size

                region_meta: Dict[str, Any] = {
                    "artifact_type": "android_process_memory",
                    "original_path": f"/proc/{pid}/mem@{base_addr}",
                    "filename": bin_filename,
                    "size": size,
                    "sha256": sha256,
                    "collection_method": "frida_memory_read",
                    "pid": pid,
                    "package": package_name,
                    "region_base": base_addr,
                    "region_size": size,
                    "protection": protection,
                    "mapped_file": region_file,
                    "file": str(bin_path),
                }
                memory_map.append(region_meta)
                yield (str(bin_path), region_meta)

                _progress(
                    f"Saved {bin_filename} ({size:,} bytes, "
                    f"total so far: {total_bytes:,} bytes)"
                )

            # Write memory map index
            map_path = pkg_dir / "memory_map.json"
            map_payload = {
                "package": package_name,
                "pid": pid,
                "region_count": len(memory_map),
                "total_bytes": total_bytes,
                "regions": memory_map,
            }
            map_path.write_text(json.dumps(map_payload, indent=2), encoding="utf-8")

            map_meta: Dict[str, Any] = {
                "artifact_type": "android_process_memory",
                "original_path": f"/proc/{pid}/maps",
                "filename": "memory_map.json",
                "size": map_path.stat().st_size,
                "sha256": _sha256_file(map_path),
                "collection_method": "frida_memory_enumerate",
                "pid": pid,
                "package": package_name,
                "region_base": None,
                "region_size": None,
                "protection": None,
                "file": str(map_path),
            }
            yield (str(map_path), map_meta)
            _progress(f"Memory collection complete — {total_bytes:,} bytes in {len(memory_map)} region(s)")

        finally:
            try:
                session.detach()
            except Exception:
                pass

    def collect_all_app_memory(
        self,
        packages: List[str],
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect process memory for each package in *packages*.

        Packages whose processes are not running on the device are silently
        skipped.  Collection continues with the next package after any error.

        Args:
            packages:          List of Android package names to target.
            output_dir:        Base output directory (a sub-directory per
                package is created automatically).
            progress_callback: Optional status callback.

        Yields:
            Same ``(local_path_str, metadata_dict)`` tuples as
            :meth:`collect_process_memory`.
        """
        if not frida_available():
            logger.warning("frida not available — skipping all memory collection")
            return

        for pkg in packages:
            try:
                yield from self.collect_process_memory(
                    package_name=pkg,
                    output_dir=output_dir,
                    progress_callback=progress_callback,
                )
            except Exception as exc:
                logger.warning("Error collecting memory for %s: %s", pkg, exc)
                continue

    def stop_frida_server(self) -> None:
        """Kill the frida-server process on the device."""
        try:
            self._adb_shell("su -c 'pkill -f frida-server 2>/dev/null; true'")
            logger.info("frida-server stopped")
        except Exception as exc:
            logger.debug("stop_frida_server: %s", exc)

    def cleanup(self) -> None:
        """
        Stop frida-server (if started by this collector) and remove the
        binary from the device.
        """
        if self._server_started_by_us:
            self.stop_frida_server()

        try:
            self._adb_shell(f"rm -f {_FRIDA_SERVER_REMOTE}")
            logger.info("Removed frida-server binary from device")
        except Exception as exc:
            logger.debug("cleanup remove: %s", exc)

        self._frida_device = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_frida_device(self) -> Optional[Any]:
        """
        Return a cached frida USB device handle.

        If *device_serial* was supplied to the constructor, the device matching
        that serial is returned; otherwise the first USB device is used.
        """
        if self._frida_device is not None:
            return self._frida_device

        if not frida_available():
            return None

        import frida as _frida

        try:
            if self._device_serial:
                device_manager = _frida.get_device_manager()
                for dev in device_manager.enumerate_devices():
                    if dev.id == self._device_serial:
                        self._frida_device = dev
                        return dev
                logger.warning("Frida device with serial %s not found", self._device_serial)
                return None
            else:
                self._frida_device = _frida.get_usb_device(timeout=10)
                return self._frida_device
        except Exception as exc:
            logger.warning("Could not obtain Frida device: %s", exc)
            return None

    def _find_pid(self, device: Any, package_name: str) -> Optional[int]:
        """
        Return the PID of the first process whose name contains *package_name*.

        Returns None if no matching process is found.
        """
        try:
            processes = device.enumerate_processes()
            for proc in processes:
                if package_name in proc.name:
                    return proc.pid
        except Exception as exc:
            logger.debug("_find_pid error: %s", exc)
        return None

    def _enumerate_ranges(self, session: Any) -> List[Dict[str, Any]]:
        """
        Run the in-process JavaScript to enumerate readable memory regions.

        Returns a list of range dicts (``base``, ``size``, ``protection``,
        optionally ``file``), or an empty list on failure.
        """
        result: List[Dict[str, Any]] = []
        event = threading.Event()
        error_holder: List[Optional[str]] = [None]

        def on_message(message: Dict[str, Any], data: Any) -> None:  # noqa: ANN001
            if message.get("type") == "send":
                payload = message.get("payload")
                if isinstance(payload, str) and payload.startswith("ERROR:"):
                    error_holder[0] = payload
                else:
                    try:
                        result.extend(json.loads(payload))
                    except (json.JSONDecodeError, TypeError) as exc:
                        logger.debug("Range JSON parse error: %s", exc)
            elif message.get("type") == "error":
                error_holder[0] = message.get("description", "unknown error")
            event.set()

        try:
            script = session.create_script(_ENUM_RANGES_SCRIPT)
            script.on("message", on_message)
            script.load()
            event.wait(timeout=30)
            script.unload()
        except Exception as exc:
            logger.warning("Memory enumeration script error: %s", exc)
            return []

        if error_holder[0]:
            logger.warning("Enumeration script reported: %s", error_holder[0])

        return result

    def _read_region(
        self,
        session: Any,
        base_addr: str,
        size: int,
    ) -> Optional[bytes]:
        """
        Read a single memory region and return its raw bytes.

        Returns None if the region is inaccessible or a script error occurs.
        """
        raw_holder: List[Optional[bytes]] = [None]
        event = threading.Event()

        def on_message(message: Dict[str, Any], data: Optional[bytes]) -> None:  # noqa: ANN001
            if message.get("type") == "send":
                payload = message.get("payload")
                if isinstance(payload, str) and payload.startswith("ERROR:"):
                    logger.debug("Region read error %s+%d: %s", base_addr, size, payload)
                elif data is not None:
                    raw_holder[0] = bytes(data)
            event.set()

        script_src = _READ_REGION_SCRIPT % {"addr": base_addr, "size": size}

        try:
            script = session.create_script(script_src)
            script.on("message", on_message)
            script.load()
            # Timeout scales loosely with region size; floor at 10 s, cap at 120 s
            timeout = max(10, min(120, size // (1024 * 1024) + 10))
            event.wait(timeout=timeout)
            script.unload()
        except Exception as exc:
            logger.debug("Region read script failed %s+%d: %s", base_addr, size, exc)
            return None

        return raw_holder[0]
