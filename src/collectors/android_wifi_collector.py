"""
Android WiFi/TCP Forensic Collector Module

ADB over WiFi (TCP/IP) collection module for Android forensic analysis.
Allows forensic artifact collection from Android devices accessible on the
same network without a physical USB cable.

Supported connection modes:
  - Classic ADB WiFi: `adb tcpip 5555` then connect via IP:5555
  - Android 11+ Wireless Debugging: Developer Options -> Wireless debugging,
    paired via pairing code, then connected on a separate port

Collectible artifacts (same as android_collector_extended):
  - All artifact types defined in ANDROID_ARTIFACT_TYPES

Requirements:
    - adb-shell>=0.4.4  (TCP variant, no [usb] extra required)
    - Standard library only for network scanning (socket)
    - Optional: zeroconf>=0.38.0 for mDNS discovery (Android 11+)
"""
from __future__ import annotations

import ipaddress
import logging
import os
import shlex
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TCP ADB library imports
# ---------------------------------------------------------------------------

try:
    from adb_shell.adb_device import AdbDeviceTcp
    from adb_shell.auth.sign_pythonrsa import PythonRSASigner
    from adb_shell.auth.keygen import keygen
    from adb_shell.exceptions import (
        TcpTimeoutException,
        DeviceAuthError,
    )
    TCP_ADB_AVAILABLE = True
except ImportError as _tcp_import_error:
    TCP_ADB_AVAILABLE = False
    _TCP_IMPORT_ERROR_MSG = str(_tcp_import_error)

    class AdbDeviceTcp:  # type: ignore
        """Stub class when adb-shell is not installed."""
        pass

    class PythonRSASigner:  # type: ignore
        """Stub class when adb-shell is not installed."""
        pass

    def keygen(path: str) -> None:  # type: ignore
        pass

    class TcpTimeoutException(Exception):  # type: ignore
        pass

    class DeviceAuthError(Exception):  # type: ignore
        pass

    _TCP_IMPORT_ERROR_MSG = "adb-shell not installed"

# ---------------------------------------------------------------------------
# Optional mDNS support for Android 11+ Wireless Debugging discovery
# ---------------------------------------------------------------------------

try:
    from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    ZEROCONF_AVAILABLE = True
except ImportError:
    ZEROCONF_AVAILABLE = False

# ---------------------------------------------------------------------------
# Import shared types from android_collector_extended
# ---------------------------------------------------------------------------

try:
    from collectors.android_collector_extended import (
        AndroidCollector,
        DeviceInfo,
        ANDROID_ARTIFACT_TYPES,
        _create_adb_signer,
        _mask_serial,
        _debug_print,
    )
    _BASE_IMPORT_OK = True
except ImportError:
    try:
        from android_collector_extended import (
            AndroidCollector,
            DeviceInfo,
            ANDROID_ARTIFACT_TYPES,
            _create_adb_signer,
            _mask_serial,
            _debug_print,
        )
        _BASE_IMPORT_OK = True
    except ImportError as _base_err:
        _BASE_IMPORT_OK = False
        _BASE_IMPORT_ERR_MSG = str(_base_err)

        # Minimal stubs so the module can be imported without the base module
        @dataclass
        class DeviceInfo:  # type: ignore
            serial: str
            model: str
            manufacturer: str
            android_version: str
            sdk_version: int
            usb_debugging: bool
            security_patch: str = ''
            rooted: bool = False
            storage_available: int = 0
            vendor_id: int = 0
            product_id: int = 0

        ANDROID_ARTIFACT_TYPES: Dict[str, Any] = {}  # type: ignore

        def _create_adb_signer(key_path: Path) -> Any:  # type: ignore
            raise ImportError("android_collector_extended not available")

        def _mask_serial(serial: str) -> str:  # type: ignore
            if not serial:
                return "(unknown)"
            return f"...{serial[-8:]}" if len(serial) > 8 else serial

        def _debug_print(msg: str) -> None:  # type: ignore
            logger.debug(msg)

        class AndroidCollector:  # type: ignore
            """Stub base class when android_collector_extended is not available."""

            MAX_RETRIES = 3

            def __init__(self, output_dir: str, device_serial: Optional[str] = None):
                self.output_dir = Path(output_dir)
                self.device_serial = device_serial
                self.device_info: Optional[DeviceInfo] = None
                self._adb_key_path = Path.home() / ".android" / "adbkey"
                self._signer: Optional[Any] = None

            def collect(self, artifact_type: str, progress_callback: Any = None, **kwargs) -> Generator:
                raise NotImplementedError("Base AndroidCollector not available")

            def disconnect(self) -> None:
                pass


# ---------------------------------------------------------------------------
# Default TCP ADB port
# ---------------------------------------------------------------------------

DEFAULT_ADB_TCP_PORT = 5555

# mDNS service type used by Android 11+ Wireless Debugging
MDNS_WIRELESS_DEBUG_SERVICE = "_adb-tls-connect._tcp.local."
MDNS_WIRELESS_PAIRING_SERVICE = "_adb-tls-pairing._tcp.local."

# How long (seconds) to wait for a TCP connection probe before timing out
DEFAULT_SCAN_TIMEOUT = 0.5

# Thread pool size for parallel subnet scanning
SCAN_THREAD_POOL_SIZE = 64


# ---------------------------------------------------------------------------
# Public helper functions
# ---------------------------------------------------------------------------

def wifi_adb_available() -> bool:
    """
    Check whether TCP ADB support is available.

    Returns True when the adb-shell library is installed and the
    AdbDeviceTcp class can be imported.  Returns False otherwise.

    Returns:
        bool: True if TCP ADB is usable.
    """
    return TCP_ADB_AVAILABLE


def check_wifi_adb_guide() -> str:
    """
    Return a human-readable guide for enabling wireless ADB on Android devices.

    Returns:
        str: Multi-line setup instructions for both classic and Android 11+
             wireless debugging modes.
    """
    return (
        "=== Android WiFi ADB Setup Guide ===\n"
        "\n"
        "--- Method 1: Classic ADB over WiFi (Android 4.0+) ---\n"
        "1. Connect the device to USB and enable USB Debugging in Developer Options.\n"
        "2. Run: adb tcpip 5555\n"
        "3. Disconnect the USB cable.\n"
        "4. Find the device IP address in Settings -> About phone -> Status -> IP address.\n"
        "5. Run: adb connect <device-ip>:5555\n"
        "   This collector will then use AndroidWiFiCollector.connect('<device-ip>', 5555).\n"
        "\n"
        "--- Method 2: Wireless Debugging (Android 11+) ---\n"
        "1. Go to Settings -> Developer Options -> Wireless debugging.\n"
        "2. Enable 'Wireless debugging'.\n"
        "3. Tap 'Pair device with pairing code' to get the pairing port and 6-digit code.\n"
        "4. Run: adb pair <device-ip>:<pairing-port>\n"
        "   Enter the 6-digit code when prompted.\n"
        "5. After pairing, the main port shown in the Wireless debugging screen is used\n"
        "   for the actual connection (different from the pairing port).\n"
        "6. Run: adb connect <device-ip>:<main-port>\n"
        "   Or use AndroidWiFiCollector.connect('<device-ip>', <main-port>).\n"
        "\n"
        "--- Notes ---\n"
        "- Both the host machine and the Android device must be on the same network.\n"
        "- Firewalls may block ADB ports; ensure port 5555 (or the wireless debugging\n"
        "  port) is reachable from the host.\n"
        "- The RSA key used is the same one at ~/.android/adbkey.  If the device has\n"
        "  not previously authorized this key, a dialog will appear on the device screen.\n"
        "- To reset authorization: Settings -> Developer Options -> Revoke USB debugging\n"
        "  authorizations, then reconnect.\n"
    )


# ---------------------------------------------------------------------------
# AndroidWiFiCollector
# ---------------------------------------------------------------------------

class AndroidWiFiCollector(AndroidCollector):
    """
    Android forensic collector using ADB over WiFi (TCP/IP).

    Extends AndroidCollector by replacing the USB transport layer with
    a TCP connection.  All artifact collection methods from the base class
    (collect(), _adb_shell(), _adb_pull(), etc.) are inherited unchanged;
    only the connection/disconnection logic is overridden to use
    AdbDeviceTcp instead of AdbDeviceUsb.

    Usage::

        collector = AndroidWiFiCollector(output_dir="/tmp/evidence")
        collector.connect("192.168.1.42", port=5555)
        for path, meta in collector.collect("mobile_android_sms_provider"):
            print(path, meta)
        collector.disconnect()

    Context-manager form::

        with AndroidWiFiCollector("/tmp/evidence") as c:
            c.connect("192.168.1.42")
            list(c.collect("mobile_android_call_provider"))
    """

    MAX_RETRIES = 3

    def __init__(self, output_dir: str, device_serial: Optional[str] = None):
        """
        Initialize the WiFi collector.

        Args:
            output_dir: Directory where collected artifacts will be stored.
            device_serial: Optional serial/identifier string (ignored; overwritten
                           by connect() with 'host:port' format).
        """
        super().__init__(output_dir=output_dir, device_serial=device_serial)

        # TCP-specific state
        self._tcp_device: Optional[AdbDeviceTcp] = None
        self._host: Optional[str] = None
        self._port: int = DEFAULT_ADB_TCP_PORT
        self._adb_key_path = Path.home() / ".android" / "adbkey"
        self._signer: Optional[PythonRSASigner] = None

        # Patch the parent's _device reference so inherited methods work
        # (parent references self._device; we keep it in sync with _tcp_device)
        self._device = None  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_or_create_adb_key(self) -> PythonRSASigner:
        """Load or generate the ADB RSA key used for device authentication."""
        if self._signer is not None:
            return self._signer

        if not TCP_ADB_AVAILABLE:
            raise RuntimeError(
                "adb-shell library is not installed. "
                "Install it with: pip install adb-shell"
            )

        if not self._adb_key_path.exists():
            self._adb_key_path.parent.mkdir(parents=True, exist_ok=True)
            keygen(str(self._adb_key_path))
            logger.debug(f"[WiFi ADB] Generated new ADB key at {self._adb_key_path}")

        self._signer = _create_adb_signer(self._adb_key_path)
        return self._signer

    def _connect_tcp(self, host: str, port: int) -> AdbDeviceTcp:
        """
        Establish a TCP ADB connection to the given host and port.

        Args:
            host: Device IP address or hostname.
            port: ADB TCP port (default 5555).

        Returns:
            Connected AdbDeviceTcp instance.

        Raises:
            RuntimeError: When the library is unavailable or connection fails.
        """
        if not TCP_ADB_AVAILABLE:
            raise RuntimeError(
                "adb-shell library is not installed. "
                "Install it with: pip install adb-shell"
            )

        signer = self._get_or_create_adb_key()

        try:
            device = AdbDeviceTcp(host=host, port=port, default_transport_timeout_s=30.0)
            device.connect(rsa_keys=[signer], auth_timeout_s=30.0)
            return device
        except DeviceAuthError:
            raise RuntimeError(
                f"Authorization failed for {host}:{port}. "
                "Check the device screen and accept the 'Allow USB debugging?' prompt."
            )
        except TcpTimeoutException as exc:
            raise RuntimeError(
                f"Connection timed out while connecting to {host}:{port}. "
                f"Ensure ADB is listening on the device (adb tcpip {port})."
            ) from exc
        except OSError as exc:
            raise RuntimeError(
                f"Network error connecting to {host}:{port}: {exc}"
            ) from exc
        except Exception as exc:
            raise RuntimeError(
                f"Failed to connect to {host}:{port}: {exc}"
            ) from exc

    def _get_device_info_tcp(self, host: str, port: int) -> DeviceInfo:
        """
        Query device properties over an already-connected TCP ADB session.

        Args:
            host: Device IP address.
            port: ADB TCP port.

        Returns:
            Populated DeviceInfo instance.
        """
        assert self._tcp_device is not None, "_tcp_device must be connected before calling this"

        def shell(cmd: str) -> str:
            try:
                result = self._tcp_device.shell(cmd, timeout_s=10)  # type: ignore[union-attr]
                return result.strip() if result else ''
            except Exception:
                return ''

        model = shell('getprop ro.product.model')
        manufacturer = shell('getprop ro.product.manufacturer')
        android_version = shell('getprop ro.build.version.release')
        sdk_str = shell('getprop ro.build.version.sdk')
        security_patch = shell('getprop ro.build.version.security_patch')
        storage_str = shell('df /data 2>/dev/null | tail -1 | awk \'{print $4}\'')

        sdk_version = int(sdk_str) if sdk_str.isdigit() else 0
        try:
            storage_available = int(storage_str) * 1024  # df reports in 1 KB blocks
        except (ValueError, TypeError):
            storage_available = 0

        root_check = shell('which su')
        rooted = bool(root_check and 'su' in root_check)

        serial = f"{host}:{port}"

        return DeviceInfo(
            serial=serial,
            model=model or 'Unknown',
            manufacturer=manufacturer or 'Unknown',
            android_version=android_version or 'Unknown',
            sdk_version=sdk_version,
            security_patch=security_patch or '',
            usb_debugging=True,
            rooted=rooted,
            storage_available=storage_available,
            vendor_id=0,
            product_id=0,
        )

    def _ensure_connection(self) -> Optional[AdbDeviceTcp]:  # type: ignore[override]
        """
        Verify the TCP connection and reconnect if necessary.

        Overrides the parent's _ensure_connection to use the TCP device.

        Returns:
            Active AdbDeviceTcp instance, or None if reconnection fails.
        """
        if self._tcp_device is not None:
            try:
                self._tcp_device.shell('echo test', timeout_s=5)
                return self._tcp_device
            except Exception:
                try:
                    self._tcp_device.close()
                except Exception:
                    pass
                self._tcp_device = None
                self._device = None  # type: ignore[assignment]

        if not self._host:
            raise RuntimeError("Not connected. Call connect() first.")

        try:
            self._tcp_device = self._connect_tcp(self._host, self._port)
            self._device = self._tcp_device  # type: ignore[assignment]
            logger.debug(
                f"[WiFi ADB] Reconnected to {self._host}:{self._port}"
            )
        except RuntimeError as exc:
            logger.warning(f"[WiFi ADB] Reconnection failed: {exc}")
            self._tcp_device = None
            self._device = None  # type: ignore[assignment]

        return self._tcp_device

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(self, host: str, port: int = DEFAULT_ADB_TCP_PORT) -> bool:  # type: ignore[override]
        """
        Connect to an Android device via TCP ADB.

        Sets self.device_info so that all inherited collect() methods can
        run immediately after this call returns True.

        Args:
            host: Device IP address or hostname (e.g. "192.168.1.42").
            port: ADB TCP port.  Classic mode uses 5555; Android 11+
                  Wireless Debugging uses a randomly assigned port shown
                  in the Wireless debugging settings screen.

        Returns:
            True on successful connection.

        Raises:
            RuntimeError: If the connection or device info query fails.
        """
        if not TCP_ADB_AVAILABLE:
            raise RuntimeError(
                "adb-shell library is not installed. "
                "Install it with: pip install adb-shell"
            )

        logger.info(f"[WiFi ADB] Connecting to {host}:{port} ...")

        # Disconnect any existing session
        self.disconnect()

        self._host = host
        self._port = port
        self._tcp_device = self._connect_tcp(host, port)
        self._device = self._tcp_device  # type: ignore[assignment]

        # Populate device_info (required by inherited collect())
        self.device_info = self._get_device_info_tcp(host, port)
        self.device_serial = self.device_info.serial

        logger.info(
            f"[WiFi ADB] Connected: {_mask_serial(self.device_serial)} "
            f"({self.device_info.manufacturer} {self.device_info.model}, "
            f"Android {self.device_info.android_version}, "
            f"root={self.device_info.rooted})"
        )
        return True

    def disconnect(self) -> None:
        """
        Close the TCP ADB connection and reset all connection state.
        """
        if self._tcp_device is not None:
            try:
                self._tcp_device.close()
            except Exception:
                pass
            self._tcp_device = None
            self._device = None  # type: ignore[assignment]

        self.device_info = None
        self.device_serial = None
        self._host = None

    def is_available(self) -> Dict[str, Any]:
        """
        Report availability status for the WiFi collector.

        Returns:
            dict with keys: 'wifi', 'tcp_adb', 'device_connected', 'devices'.
        """
        connected = self.device_info is not None
        device_list: List[Dict[str, Any]] = []
        if connected and self.device_info:
            device_list.append({
                'serial': self.device_info.serial,
                'model': self.device_info.model,
                'android_version': self.device_info.android_version,
                'rooted': self.device_info.rooted,
                'usb_debugging': self.device_info.usb_debugging,
            })
        return {
            'wifi': TCP_ADB_AVAILABLE,
            'tcp_adb': TCP_ADB_AVAILABLE,
            'device_connected': connected,
            'devices': device_list,
        }

    # Context manager support (mirrors base class)
    def __enter__(self) -> 'AndroidWiFiCollector':
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        self.disconnect()
        return False

    def __del__(self) -> None:
        self.disconnect()


# ---------------------------------------------------------------------------
# AndroidWiFiDeviceScanner
# ---------------------------------------------------------------------------

@dataclass
class WifiDeviceCandidate:
    """
    Represents a potential Android device found during network scanning.

    Attributes:
        host:    IP address or hostname.
        port:    ADB TCP port the device is listening on.
        source:  How it was discovered: 'tcp_scan', 'known_host', or 'mdns'.
        mdns_name: mDNS service instance name (populated only for 'mdns' source).
    """
    host: str
    port: int
    source: str
    mdns_name: str = ''


class AndroidWiFiDeviceScanner:
    """
    Discovers Android devices reachable via WiFi ADB on the local network.

    Three discovery strategies:

    1. **scan_network**: Iterates all host addresses in a given IPv4 subnet
       and probes the ADB port with a lightweight TCP connect probe.

    2. **scan_known_hosts**: Probes a user-supplied list of IP addresses.

    3. **check_mdns**: Listens for Android 11+ Wireless Debugging mDNS
       advertisements on the local network (requires zeroconf library).

    All methods return lists of WifiDeviceCandidate objects.  Pass a
    candidate to AndroidWiFiCollector.connect() to start a full session::

        scanner = AndroidWiFiDeviceScanner()
        candidates = scanner.scan_network("192.168.1", port=5555, timeout=0.5)
        for c in candidates:
            with AndroidWiFiCollector("/tmp/evidence") as col:
                col.connect(c.host, c.port)
                list(col.collect("mobile_android_system_info"))
    """

    def __init__(self) -> None:
        self._mdns_results: List[WifiDeviceCandidate] = []
        self._mdns_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Strategy 1: subnet scan
    # ------------------------------------------------------------------

    @staticmethod
    def _probe_tcp(host: str, port: int, timeout: float) -> bool:
        """
        Check whether a TCP port is open on the given host.

        Args:
            host:    Target IP address.
            port:    Target TCP port.
            timeout: Connect timeout in seconds.

        Returns:
            True if the port accepted a connection.
        """
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, socket.timeout):
            return False

    def scan_network(
        self,
        subnet: str,
        port: int = DEFAULT_ADB_TCP_PORT,
        timeout: float = DEFAULT_SCAN_TIMEOUT,
    ) -> List[WifiDeviceCandidate]:
        """
        Scan every host address in an IPv4 subnet for an open ADB TCP port.

        Args:
            subnet:  The first three octets of the subnet to scan, e.g.
                     "192.168.1" (a /24 is assumed), or a full CIDR notation
                     such as "10.0.0.0/24".
            port:    ADB TCP port to probe (default 5555).
            timeout: Per-host TCP connect timeout in seconds (default 0.5).

        Returns:
            List of WifiDeviceCandidate for each host with the port open.

        Example::

            scanner.scan_network("192.168.1", port=5555, timeout=0.3)
        """
        # Normalize subnet input
        if '/' in subnet:
            network_str = subnet
        else:
            # Treat "A.B.C" as the /24 network "A.B.C.0/24"
            parts = subnet.strip().rstrip('.')
            if parts.count('.') == 2:
                network_str = f"{parts}.0/24"
            elif parts.count('.') == 3:
                # Full address with no CIDR — assume /24
                octets = parts.rsplit('.', 1)
                network_str = f"{octets[0]}.0/24"
            else:
                logger.warning(
                    f"[WiFi Scanner] Cannot parse subnet '{subnet}'. "
                    "Use format '192.168.1' or '192.168.1.0/24'."
                )
                return []

        try:
            network = ipaddress.IPv4Network(network_str, strict=False)
        except ValueError as exc:
            logger.warning(f"[WiFi Scanner] Invalid network '{network_str}': {exc}")
            return []

        hosts = list(network.hosts())
        logger.info(
            f"[WiFi Scanner] Scanning {len(hosts)} hosts in {network} "
            f"for ADB on port {port} (timeout={timeout}s) ..."
        )

        found: List[WifiDeviceCandidate] = []
        found_lock = threading.Lock()

        def probe(ip: ipaddress.IPv4Address) -> None:
            if self._probe_tcp(str(ip), port, timeout):
                candidate = WifiDeviceCandidate(
                    host=str(ip),
                    port=port,
                    source='tcp_scan',
                )
                with found_lock:
                    found.append(candidate)
                logger.info(f"[WiFi Scanner] ADB port open: {ip}:{port}")

        with ThreadPoolExecutor(max_workers=SCAN_THREAD_POOL_SIZE) as pool:
            futures = [pool.submit(probe, ip) for ip in hosts]
            for _ in as_completed(futures):
                pass

        logger.info(f"[WiFi Scanner] Scan complete. Found {len(found)} candidate(s).")
        return found

    # ------------------------------------------------------------------
    # Strategy 2: known-host probe
    # ------------------------------------------------------------------

    def scan_known_hosts(
        self,
        hosts: List[str],
        port: int = DEFAULT_ADB_TCP_PORT,
        timeout: float = DEFAULT_SCAN_TIMEOUT,
    ) -> List[WifiDeviceCandidate]:
        """
        Probe a specific list of hosts for an open ADB TCP port.

        Args:
            hosts:   List of IP addresses or hostnames to check.
            port:    ADB TCP port to probe (default 5555).
            timeout: Per-host TCP connect timeout in seconds.

        Returns:
            List of WifiDeviceCandidate for each reachable host.

        Example::

            scanner.scan_known_hosts(["192.168.1.10", "192.168.1.20"])
        """
        found: List[WifiDeviceCandidate] = []
        for host in hosts:
            if self._probe_tcp(host, port, timeout):
                found.append(WifiDeviceCandidate(
                    host=host,
                    port=port,
                    source='known_host',
                ))
                logger.info(f"[WiFi Scanner] ADB reachable at {host}:{port}")
            else:
                logger.debug(f"[WiFi Scanner] No response from {host}:{port}")
        return found

    # ------------------------------------------------------------------
    # Strategy 3: mDNS discovery (Android 11+ Wireless Debugging)
    # ------------------------------------------------------------------

    def check_mdns(
        self,
        listen_seconds: float = 5.0,
    ) -> List[WifiDeviceCandidate]:
        """
        Discover Android 11+ Wireless Debugging instances via mDNS.

        Android 11 and later advertise two mDNS services when Wireless
        Debugging is enabled:

        * ``_adb-tls-pairing._tcp.local.`` — pairing endpoint
        * ``_adb-tls-connect._tcp.local.`` — connection endpoint

        This method listens for both service types and returns discovered
        devices.  The zeroconf library must be installed::

            pip install zeroconf

        Args:
            listen_seconds: How long to listen for mDNS announcements
                            before returning (default 5.0 s).

        Returns:
            List of WifiDeviceCandidate with source='mdns'.  Returns an
            empty list if zeroconf is not installed or no devices are found.

        Note:
            The port in the returned candidates is the *connection* port,
            not the pairing port.  Pairing must be completed separately
            (``adb pair <ip>:<pairing-port>``) before connecting.
        """
        if not ZEROCONF_AVAILABLE:
            logger.warning(
                "[WiFi Scanner] zeroconf library not installed. "
                "Install it with: pip install zeroconf"
            )
            return []

        with self._mdns_lock:
            self._mdns_results.clear()

        class _AdbServiceListener:
            """Minimal zeroconf ServiceListener that records ADB service instances."""

            def __init__(self, collector: 'AndroidWiFiDeviceScanner') -> None:
                self._collector = collector

            def add_service(self, zc: 'Zeroconf', service_type: str, name: str) -> None:
                self._handle(zc, service_type, name)

            def update_service(self, zc: 'Zeroconf', service_type: str, name: str) -> None:
                self._handle(zc, service_type, name)

            def remove_service(self, zc: 'Zeroconf', service_type: str, name: str) -> None:
                pass

            def _handle(self, zc: 'Zeroconf', service_type: str, name: str) -> None:
                try:
                    info = zc.get_service_info(service_type, name)
                    if info is None:
                        return
                    addresses = info.parsed_addresses()
                    if not addresses:
                        return
                    host = addresses[0]
                    port = info.port
                    candidate = WifiDeviceCandidate(
                        host=host,
                        port=port,
                        source='mdns',
                        mdns_name=name,
                    )
                    logger.info(
                        f"[WiFi Scanner] mDNS: found {service_type} "
                        f"at {host}:{port} (name={name})"
                    )
                    with self._collector._mdns_lock:
                        # Avoid duplicates by (host, port)
                        existing = {(c.host, c.port) for c in self._collector._mdns_results}
                        if (host, port) not in existing:
                            self._collector._mdns_results.append(candidate)
                except Exception as exc:
                    logger.debug(f"[WiFi Scanner] mDNS handler error: {exc}")

        zc = Zeroconf()  # type: ignore[call-arg]
        listener = _AdbServiceListener(self)
        try:
            browsers = [
                ServiceBrowser(zc, MDNS_WIRELESS_DEBUG_SERVICE, listener),   # type: ignore[call-arg]
                ServiceBrowser(zc, MDNS_WIRELESS_PAIRING_SERVICE, listener),  # type: ignore[call-arg]
            ]
            logger.info(
                f"[WiFi Scanner] Listening for mDNS ADB services for {listen_seconds}s ..."
            )
            time.sleep(listen_seconds)
        finally:
            zc.close()

        with self._mdns_lock:
            results = list(self._mdns_results)

        logger.info(f"[WiFi Scanner] mDNS discovery found {len(results)} device(s).")
        return results
