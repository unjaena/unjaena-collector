"""
Android Frida Collector Modules

Provides two independent collection strategies using the Frida framework:

1. AndroidFridaCollector  — Process memory collection (requires root / frida-server)
   Collectible artifacts:
   - android_process_memory: Raw memory pages from running application processes

2. AndroidGadgetCollector — Gadget-based private data collection (no root required)
   Collectible artifacts:
   - android_app_database: Private application database files extracted via Gadget
   - android_app_files: Private application files extracted via Gadget

   Strategy: Injects Frida Gadget into target APK, reinstalls, then runs a Gadget
   Script that copies the app's private data to external storage for retrieval.

   CRITICAL WARNING: Reinstalling the app DESTROYS existing private data for apps
   with android:allowBackup="false".  Always confirm the investigative authority
   and understand the irreversibility before calling extract_via_gadget().

Requirements (common):
    - frida>=16.0.0

Requirements (AndroidFridaCollector):
    - Android device with root access
    - frida-server binary pushed to device (auto-setup supported)

Requirements (AndroidGadgetCollector):
    - objection>=1.11.0  (pip install objection)
    - apksigner or jarsigner + keytool  (Android build-tools or JDK)
    - ADB binary on host PATH  (for install)
    - Target app must not have strong APK signature verification (v2/v3 scheme)

Notes:
    - frida-server must match the frida Python package version exactly
    - Device architecture is auto-detected (arm64-v8a, armeabi-v7a, x86_64, x86)
"""
from __future__ import annotations

import hashlib
import json
import logging
import lzma
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import zipfile
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


# =============================================================================
# Frida Gadget-Based Private Data Collector (No Root Required)
# =============================================================================

# Gadget Script that runs inside the app process and copies private data to /sdcard
_GADGET_EXTRACT_SCRIPT = r"""
'use strict';

Java.perform(function () {
    // Brief pause to let app init before extracting
    var Thread = Java.use('java.lang.Thread');
    Thread.sleep(1500);

    try {
        var ctx = Java.use('android.app.ActivityThread')
            .currentApplication()
            .getApplicationContext();
        var pkg = ctx.getPackageName();
        var dataDir = ctx.getDataDir().getAbsolutePath();
        var outBase = '/sdcard/forensic_gadget/' + pkg;

        var rt = Java.use('java.lang.Runtime').getRuntime();

        function sh(cmd) {
            try {
                var proc = rt.exec(['/system/bin/sh', '-c', cmd]);
                proc.waitFor();
            } catch (e) { /* ignore */ }
        }

        sh('mkdir -p ' + outBase + '/databases');
        sh('mkdir -p ' + outBase + '/shared_prefs');
        sh('mkdir -p ' + outBase + '/files');
        sh('cp -r ' + dataDir + '/databases/. ' + outBase + '/databases/ 2>/dev/null; true');
        sh('cp -r ' + dataDir + '/shared_prefs/. ' + outBase + '/shared_prefs/ 2>/dev/null; true');
        sh('cp -r ' + dataDir + '/files/. ' + outBase + '/files/ 2>/dev/null; true');
        sh('chmod -R 755 ' + outBase);
        sh('echo ok > ' + outBase + '/.done');

    } catch (e) {
        var ts = new Date().getTime();
        var rt2 = Java.use('java.lang.Runtime').getRuntime();
        rt2.exec(['/system/bin/sh', '-c',
            'echo "' + e.toString().replace(/"/g, "'") + '" '
            + '> /sdcard/forensic_gadget/.error_' + ts + '.txt']);
    }
});
"""

# Gadget config JSON that activates Script interaction mode
_GADGET_CONFIG_TEMPLATE = """{
  "interaction": {
    "type": "script",
    "path": "/sdcard/.frida_gadget_script.js"
  }
}
"""

# Arch label inside APKs (ABI → lib subdir)
_APK_ARCH_DIRS = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]


def gadget_available() -> bool:
    """Return True if objection is installed and usable."""
    try:
        result = subprocess.run(
            ["objection", "version"],
            capture_output=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


class AndroidGadgetCollector:
    """
    Injects Frida Gadget into a target APK to collect the app's private data
    (databases, shared_prefs, files) without requiring device root.

    Workflow
    --------
    1. Pull the target APK from the device.
    2. Patch it with ``objection patchapk`` (injects libfrida-gadget.so).
    3. Inject a Gadget config so the Gadget runs a JS Script automatically.
    4. Re-sign the patched APK with a debug keystore.
    5. **Uninstall** the original app (DESTROYS private data for allowBackup=false).
    6. Install the patched APK.
    7. Launch the app — the Gadget Script copies the app's data to /sdcard.
    8. Pull the collected files and clean up.

    CRITICAL
    --------
    Step 5 permanently destroys the app's private data for apps with
    ``android:allowBackup="false"`` (e.g. KakaoTalk).  Only proceed when:
      • Investigative authority exists.
      • Either a prior backup is available OR the current data is not needed.
      • ``destructive=True`` is explicitly passed to ``extract_via_gadget()``.

    Non-destructive alternative
    ---------------------------
    For apps with ``android:allowBackup="true"`` (WhatsApp, Telegram, etc.),
    ADB backup is available without reinstall — use ``_collect_via_adb_backup``
    in ``android_collector_extended.py`` instead.
    """

    GADGET_REMOTE_DIR = "/sdcard/forensic_gadget"
    GADGET_SCRIPT_REMOTE = "/sdcard/.frida_gadget_script.js"
    WAIT_TIMEOUT_S = 90  # seconds to wait for Gadget script completion

    def __init__(
        self,
        adb_shell_func: Callable[[str], Tuple[str, int]],
        adb_push_func: Callable[[str, str], bool],
        adb_pull_func: Callable[[str, str], bool],
        output_dir: str,
        device_serial: Optional[str] = None,
    ) -> None:
        self._shell = adb_shell_func
        self._push = adb_push_func
        self._pull = adb_pull_func
        self._out = Path(output_dir)
        self._serial = device_serial

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_prerequisites(self) -> Dict[str, bool]:
        """
        Return availability of required host tools.

        Keys: ``objection``, ``apksigner``, ``jarsigner``, ``java``
        """
        result: Dict[str, bool] = {}

        for name, args in [
            ("objection", ["objection", "version"]),
            ("apksigner", ["apksigner", "--version"]),
            ("jarsigner", ["jarsigner", "-help"]),
            ("java", ["java", "-version"]),
        ]:
            try:
                p = subprocess.run(
                    args,
                    capture_output=True,
                    timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW
                    if sys.platform == "win32"
                    else 0,
                )
                result[name] = p.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                result[name] = False

        return result

    def pull_apk(self, package: str, tmp_dir: Optional[Path] = None) -> Optional[Path]:
        """
        Pull the installed APK for *package* from the device.

        Returns the local APK path, or None on failure.
        """
        out_raw, rc = self._shell(f"pm path {shlex.quote(package)}")
        if rc != 0 or not out_raw:
            logger.error("[Gadget] pm path failed for %s", package)
            return None

        m = re.search(r"package:(.+\.apk)", out_raw.strip())
        if not m:
            logger.error("[Gadget] Cannot parse pm path output: %s", out_raw[:80])
            return None

        remote_apk = m.group(1).strip()
        dest_dir = tmp_dir or Path(tempfile.mkdtemp(prefix="frida_gadget_"))
        dest_dir.mkdir(parents=True, exist_ok=True)
        local_apk = dest_dir / f"{package}_original.apk"

        ok = self._pull(remote_apk, str(local_apk))
        if not ok or not local_apk.exists():
            logger.error("[Gadget] Failed to pull APK %s", remote_apk)
            return None

        logger.info("[Gadget] Pulled APK → %s (%d bytes)", local_apk.name, local_apk.stat().st_size)
        return local_apk

    def patch_apk(
        self,
        apk_path: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Optional[Path]:
        """
        Patch *apk_path* with Frida Gadget using objection, then inject the
        Gadget Script config so it runs automatically on app start.

        Returns the signed, patched APK path, or None on failure.
        """

        def _p(msg: str) -> None:
            logger.info("[Gadget] %s", msg)
            if progress_callback:
                progress_callback(f"[Gadget] {msg}")

        # --- Step A: objection patchapk ---
        _p(f"Running objection patchapk on {apk_path.name} …")
        try:
            proc = subprocess.run(
                ["objection", "patchapk", "--source", str(apk_path)],
                capture_output=True,
                timeout=300,
                cwd=str(apk_path.parent),
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
        except FileNotFoundError:
            _p("objection not found — install with: pip install objection")
            return None
        except subprocess.TimeoutExpired:
            _p("objection patchapk timed out (>5 min)")
            return None

        if proc.returncode != 0:
            stderr = proc.stderr.decode(errors="replace")
            _p(f"patchapk failed (rc={proc.returncode}): {stderr[:300]}")
            return None

        # objection writes <stem>.objection.apk in the working directory
        patched = apk_path.parent / f"{apk_path.stem}.objection.apk"
        if not patched.exists():
            # search fallback
            candidates = sorted(
                (f for f in apk_path.parent.glob("*.apk") if "objection" in f.name),
                key=lambda f: f.stat().st_mtime,
                reverse=True,
            )
            if candidates:
                patched = candidates[0]
            else:
                _p("Patched APK not found after objection patchapk")
                return None

        _p(f"objection patched APK: {patched.name}")

        # --- Step B: Inject Gadget Script config into APK ---
        # Push the JS script to the device separately (it's referenced by path)
        # We embed the config JSON as a .so file inside the APK lib dirs
        config_bytes = _GADGET_CONFIG_TEMPLATE.encode("utf-8")
        _p("Injecting Gadget Script config into APK …")

        config_injected = self._inject_gadget_config(patched, config_bytes)
        if not config_injected:
            _p("Config injection failed — Gadget will wait for client (listen mode)")

        # --- Step C: Sign with debug keystore ---
        signed_apk = apk_path.parent / f"{apk_path.stem}_signed.apk"
        ok = self._sign_apk_debug(patched, signed_apk, progress_callback)
        if not ok:
            _p("Signing failed — using unsigned patched APK (install may fail)")
            signed_apk = patched

        _p(f"Final patched APK: {signed_apk.name} ({signed_apk.stat().st_size:,} bytes)")
        return signed_apk

    def extract_via_gadget(
        self,
        package: str,
        artifact_type: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
        destructive: bool = False,
        device_info: Optional[Any] = None,
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Full Gadget injection pipeline — extracts private app data to *output_dir*.

        Parameters
        ----------
        package:
            Android package name (e.g. ``"com.kakao.talk"``).
        artifact_type:
            Artifact type string for metadata (e.g. ``"mobile_android_kakaotalk"``).
        output_dir:
            Local directory to store extracted files.
        progress_callback:
            Optional human-readable progress messages.
        destructive:
            **Must be True to proceed.**  When False (default), the method logs
            that Gadget injection is available and returns without action.
        device_info:
            Optional DeviceInfo object for metadata enrichment.
        """

        def _p(msg: str) -> None:
            logger.info("[Gadget:%s] %s", package, msg)
            if progress_callback:
                progress_callback(f"[Gadget] {msg}")

        if not destructive:
            _p(
                f"Gadget injection available for {package}. "
                "Set destructive=True to proceed — this will REINSTALL the app "
                "and DESTROY existing private data for allowBackup=false apps."
            )
            return

        prereqs = self.check_prerequisites()
        if not prereqs.get("objection"):
            _p("objection not installed. Run: pip install objection")
            return

        tmp_dir = Path(tempfile.mkdtemp(prefix="gadget_"))
        try:
            # 1. Push extraction script to device
            _p("Pushing Gadget extraction script to device …")
            script_local = tmp_dir / "frida_gadget_script.js"
            script_local.write_text(_GADGET_EXTRACT_SCRIPT, encoding="utf-8")
            ok = self._push(str(script_local), self.GADGET_SCRIPT_REMOTE)
            if not ok:
                _p(f"Failed to push script to {self.GADGET_SCRIPT_REMOTE}")
                return

            # 2. Pull APK
            _p(f"Pulling APK for {package} …")
            apk_path = self.pull_apk(package, tmp_dir=tmp_dir)
            if not apk_path:
                return

            # 3. Patch APK
            patched_apk = self.patch_apk(apk_path, progress_callback)
            if not patched_apk:
                _p("APK patching failed — aborting (app not uninstalled)")
                return

            # 4. Uninstall original — DESTRUCTIVE
            _p(f"⚠ Uninstalling {package} (private data will be lost for allowBackup=false) …")
            self._run_adb(["uninstall", package])
            time.sleep(2)

            # 5. Install patched APK
            _p(f"Installing patched APK …")
            rc_install = self._run_adb(["install", "-r", str(patched_apk)])
            if rc_install != 0:
                _p(f"Install failed (rc={rc_install}). Device may need USB debug allow.")
                return

            time.sleep(1)

            # 6. Launch app to trigger Gadget script
            _p(f"Launching {package} — Gadget script will extract data to /sdcard …")
            self._shell(
                f"monkey -p {shlex.quote(package)} "
                f"-c android.intent.category.LAUNCHER 1 2>/dev/null"
            )

            # 7. Wait for completion marker
            done_marker = f"{self.GADGET_REMOTE_DIR}/{package}/.done"
            _p(f"Waiting up to {self.WAIT_TIMEOUT_S}s for extraction to complete …")
            for _ in range(self.WAIT_TIMEOUT_S // 5):
                time.sleep(5)
                chk, _ = self._shell(
                    f"test -f {shlex.quote(done_marker)} && echo yes 2>/dev/null"
                )
                if chk and "yes" in chk:
                    _p("Extraction complete!")
                    break
            else:
                _p("Timeout — pulling whatever was collected so far")

            # 8. Pull extracted files
            remote_base = f"{self.GADGET_REMOTE_DIR}/{package}"
            local_base = output_dir / "gadget_extraction"
            local_base.mkdir(parents=True, exist_ok=True)

            list_out, _ = self._shell(
                f"find {shlex.quote(remote_base)} -type f 2>/dev/null"
            )
            if not list_out or not list_out.strip():
                _p("No files found in Gadget output directory")
                return

            collected = 0
            for remote_file in list_out.strip().split("\n"):
                remote_file = remote_file.strip()
                if not remote_file or remote_file.endswith("/.done"):
                    continue

                # Build local path preserving relative structure
                rel = remote_file[len(remote_base):].lstrip("/")
                safe_rel = re.sub(r'[<>:"|?*\x00-\x1f]', "_", rel)
                if ".." in safe_rel:
                    continue

                local_path = local_base / safe_rel
                local_path.parent.mkdir(parents=True, exist_ok=True)

                ok = self._pull(remote_file, str(local_path))
                if not ok or not local_path.exists() or local_path.stat().st_size == 0:
                    continue

                sha256 = hashlib.sha256()
                with open(local_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        sha256.update(chunk)

                meta: Dict[str, Any] = {
                    "artifact_type": artifact_type,
                    "original_path": f"/data/data/{package}/{rel}",
                    "filename": local_path.name,
                    "size": local_path.stat().st_size,
                    "sha256": sha256.hexdigest(),
                    "collection_method": "frida_gadget_injection",
                    "root_used": False,
                    "package": package,
                    "source": "gadget_extraction",
                    "collected_at": __import__("datetime").datetime.utcnow().isoformat(),
                }
                if device_info:
                    meta.update({
                        "device_serial": getattr(device_info, "serial", ""),
                        "device_model": getattr(device_info, "model", ""),
                        "android_version": getattr(device_info, "android_version", ""),
                    })

                collected += 1
                yield str(local_path), meta
                _p(f"Collected {local_path.name} ({local_path.stat().st_size:,} bytes)")

            _p(f"Gadget extraction finished: {collected} file(s) collected")

        finally:
            # Cleanup device
            self._shell(
                f"rm -rf {shlex.quote(self.GADGET_REMOTE_DIR)}/{shlex.quote(package)} "
                f"{shlex.quote(self.GADGET_SCRIPT_REMOTE)} 2>/dev/null"
            )
            # Cleanup host temp
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_adb(self, args: List[str]) -> int:
        """Run an ADB command on the host and return the exit code."""
        cmd = ["adb"]
        if self._serial:
            cmd += ["-s", self._serial]
        cmd += args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=120,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            return result.returncode
        except Exception as exc:
            logger.warning("[Gadget] ADB command failed %s: %s", args, exc)
            return 1

    def _inject_gadget_config(self, apk_path: Path, config_bytes: bytes) -> bool:
        """
        Inject Frida Gadget config into all lib/* subdirs inside the APK.

        The config filename must be ``libfrida-gadget.config.so`` to be
        picked up alongside ``libfrida-gadget.so``.
        """
        try:
            modified_apk = apk_path.parent / f"{apk_path.stem}_configured.apk"

            with zipfile.ZipFile(apk_path, "r") as zin, \
                 zipfile.ZipFile(modified_apk, "w", zipfile.ZIP_DEFLATED) as zout:

                gadget_dirs: List[str] = []
                for name in zin.namelist():
                    zout.writestr(zin.getinfo(name), zin.read(name))
                    if "libfrida-gadget.so" in name:
                        gadget_dirs.append(str(Path(name).parent))

                # Add config alongside each gadget .so
                config_name = "libfrida-gadget.config.so"
                added = set()
                for gdir in gadget_dirs:
                    cfg_path = f"{gdir}/{config_name}"
                    if cfg_path not in added:
                        zout.writestr(cfg_path, config_bytes)
                        added.add(cfg_path)
                        logger.debug("[Gadget] Injected config at %s", cfg_path)

            # Replace original with configured version
            apk_path.unlink()
            modified_apk.rename(apk_path)
            return len(added) > 0

        except Exception as exc:
            logger.warning("[Gadget] Config injection failed: %s", exc)
            return False

    def _sign_apk_debug(
        self,
        apk_path: Path,
        out_path: Path,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> bool:
        """
        Sign APK with a temporary debug keystore.

        Tries apksigner first, falls back to jarsigner.
        Returns True on success.
        """
        def _p(msg: str) -> None:
            logger.info("[Gadget] %s", msg)
            if progress_callback:
                progress_callback(f"[Gadget] {msg}")

        keystore = apk_path.parent / "debug.keystore"
        if not keystore.exists():
            # Generate debug keystore
            _p("Generating debug keystore …")
            try:
                subprocess.run(
                    [
                        "keytool", "-genkey", "-v",
                        "-keystore", str(keystore),
                        "-alias", "debug",
                        "-keyalg", "RSA", "-keysize", "2048",
                        "-validity", "10000",
                        "-storepass", "android",
                        "-keypass", "android",
                        "-dname", "CN=Android Debug,O=Android,C=US",
                    ],
                    capture_output=True,
                    timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                )
            except Exception as exc:
                _p(f"keytool failed: {exc}")
                # Continue — apksigner can generate its own

        # Try apksigner
        try:
            res = subprocess.run(
                [
                    "apksigner", "sign",
                    "--ks", str(keystore),
                    "--ks-pass", "pass:android",
                    "--key-pass", "pass:android",
                    "--ks-key-alias", "debug",
                    "--out", str(out_path),
                    str(apk_path),
                ],
                capture_output=True,
                timeout=120,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            if res.returncode == 0 and out_path.exists():
                _p(f"Signed with apksigner → {out_path.name}")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: jarsigner
        try:
            shutil.copy2(apk_path, out_path)
            res = subprocess.run(
                [
                    "jarsigner",
                    "-keystore", str(keystore),
                    "-storepass", "android",
                    "-keypass", "android",
                    str(out_path),
                    "debug",
                ],
                capture_output=True,
                timeout=120,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            if res.returncode == 0:
                _p(f"Signed with jarsigner → {out_path.name}")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        _p("Both apksigner and jarsigner failed — APK unsigned")
        return False
