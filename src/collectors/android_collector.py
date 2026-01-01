"""
Android Forensics Collector Module

Android 기기 포렌식 수집 모듈.
ADB (Android Debug Bridge)를 이용한 실시간 연결 감지 및 아티팩트 수집을 지원합니다.

수집 가능 아티팩트:
- mobile_android_sms: SMS/MMS 메시지
- mobile_android_call: 통화 기록
- mobile_android_contacts: 연락처
- mobile_android_app: 앱 데이터
- mobile_android_wifi: WiFi 설정
- mobile_android_location: 위치 기록
- mobile_android_media: 사진/동영상

Requirements:
    - adb-shell>=0.4.0
    - ppadb>=0.3.0 (optional)
    - ADB 설치 및 PATH 설정 필요
"""
import os
import re
import shutil
import subprocess
import threading
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Generator, Tuple, Dict, Any, Optional, List, Callable
from dataclasses import dataclass

# Check for ADB availability
def check_adb_available() -> bool:
    """Check if ADB is installed and accessible"""
    try:
        result = subprocess.run(
            ['adb', 'version'],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


ADB_AVAILABLE = check_adb_available()


@dataclass
class DeviceInfo:
    """Android 기기 정보"""
    serial: str
    model: str
    manufacturer: str
    android_version: str
    sdk_version: int
    usb_debugging: bool
    rooted: bool = False
    storage_available: int = 0


# Android artifact type definitions
ANDROID_ARTIFACT_TYPES = {
    'mobile_android_sms': {
        'name': 'SMS/MMS Messages',
        'description': 'Text messages and multimedia messages',
        'db_path': '/data/data/com.android.providers.telephony/databases/mmssms.db',
        'requires_root': True,
    },
    'mobile_android_call': {
        'name': 'Call History',
        'description': 'Incoming, outgoing, and missed calls',
        'db_path': '/data/data/com.android.providers.contacts/databases/contacts2.db',
        'requires_root': True,
    },
    'mobile_android_contacts': {
        'name': 'Contacts',
        'description': 'Contact list and details',
        'db_path': '/data/data/com.android.providers.contacts/databases/contacts2.db',
        'requires_root': True,
    },
    'mobile_android_app': {
        'name': 'App Data',
        'description': 'Installed applications and their data',
        'path': '/data/data/',
        'requires_root': True,
    },
    'mobile_android_wifi': {
        'name': 'WiFi Settings',
        'description': 'Saved WiFi networks and credentials',
        'paths': [
            '/data/misc/wifi/wpa_supplicant.conf',
            '/data/misc/wifi/WifiConfigStore.xml',
        ],
        'requires_root': True,
    },
    'mobile_android_location': {
        'name': 'Location History',
        'description': 'GPS and location data',
        'paths': [
            '/data/data/com.google.android.gms/databases/herrevad*',
            '/data/data/com.google.android.gms/databases/location*',
        ],
        'requires_root': True,
    },
    'mobile_android_media': {
        'name': 'Media Files',
        'description': 'Photos, videos, and audio files',
        'paths': [
            '/sdcard/DCIM/',
            '/sdcard/Pictures/',
            '/sdcard/Download/',
        ],
        'requires_root': False,
    },
}


class ADBDeviceMonitor:
    """
    Android 기기 연결 실시간 감지

    USB 케이블 연결을 백그라운드에서 모니터링하고
    연결/해제 이벤트를 콜백으로 전달합니다.
    """

    def __init__(
        self,
        on_connect: Optional[Callable[[DeviceInfo], None]] = None,
        on_disconnect: Optional[Callable[[str], None]] = None
    ):
        """
        Initialize device monitor.

        Args:
            on_connect: Callback when device connects
            on_disconnect: Callback when device disconnects (receives serial)
        """
        self.on_connect = on_connect
        self.on_disconnect = on_disconnect

        self._monitoring = False
        self._thread: Optional[threading.Thread] = None
        self._known_devices: Dict[str, DeviceInfo] = {}
        self._stop_event = threading.Event()

    def start_monitoring(self, poll_interval: float = 1.0):
        """
        Start background device monitoring.

        Args:
            poll_interval: Seconds between device checks
        """
        if self._monitoring:
            return

        self._monitoring = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            args=(poll_interval,),
            daemon=True
        )
        self._thread.start()

    def stop_monitoring(self):
        """Stop device monitoring"""
        self._monitoring = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _monitor_loop(self, poll_interval: float):
        """Background monitoring loop"""
        while self._monitoring and not self._stop_event.is_set():
            try:
                current_devices = self._get_connected_devices()
                current_serials = set(current_devices.keys())
                known_serials = set(self._known_devices.keys())

                # Check for new devices
                for serial in current_serials - known_serials:
                    device_info = self._get_device_info(serial)
                    self._known_devices[serial] = device_info
                    if self.on_connect:
                        self.on_connect(device_info)

                # Check for disconnected devices
                for serial in known_serials - current_serials:
                    del self._known_devices[serial]
                    if self.on_disconnect:
                        self.on_disconnect(serial)

            except Exception as e:
                _debug_print(f"[ADB Monitor] Error: {e}")

            self._stop_event.wait(poll_interval)

    def _get_connected_devices(self) -> Dict[str, str]:
        """Get list of connected device serials"""
        try:
            result = subprocess.run(
                ['adb', 'devices'],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )

            devices = {}
            for line in result.stdout.strip().split('\n')[1:]:
                if '\t' in line:
                    serial, status = line.split('\t')
                    if status == 'device':
                        devices[serial] = status

            return devices

        except Exception:
            return {}

    def _get_device_info(self, serial: str) -> DeviceInfo:
        """Get detailed device information"""
        def adb_shell(cmd: str) -> str:
            try:
                result = subprocess.run(
                    ['adb', '-s', serial, 'shell', cmd],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                )
                return result.stdout.strip()
            except Exception:
                return ''

        model = adb_shell('getprop ro.product.model')
        manufacturer = adb_shell('getprop ro.product.manufacturer')
        android_version = adb_shell('getprop ro.build.version.release')
        sdk_str = adb_shell('getprop ro.build.version.sdk')
        sdk_version = int(sdk_str) if sdk_str.isdigit() else 0

        # Check root status
        root_check = adb_shell('which su')
        rooted = bool(root_check and 'su' in root_check)

        return DeviceInfo(
            serial=serial,
            model=model or 'Unknown',
            manufacturer=manufacturer or 'Unknown',
            android_version=android_version or 'Unknown',
            sdk_version=sdk_version,
            usb_debugging=True,  # If we can connect, USB debugging is enabled
            rooted=rooted,
        )

    def get_connected_devices(self) -> List[DeviceInfo]:
        """Get list of currently connected devices"""
        devices = []
        for serial in self._get_connected_devices():
            devices.append(self._get_device_info(serial))
        return devices

    def wait_for_device(
        self,
        timeout: Optional[float] = None
    ) -> Optional[DeviceInfo]:
        """
        Wait for a device to connect.

        Args:
            timeout: Maximum seconds to wait (None for infinite)

        Returns:
            DeviceInfo if device connected, None if timeout
        """
        import time
        start_time = time.time()

        while True:
            devices = self.get_connected_devices()
            if devices:
                return devices[0]

            if timeout and (time.time() - start_time) > timeout:
                return None

            time.sleep(1.0)


class AndroidCollector:
    """
    Android 포렌식 수집 통합 클래스

    ADB를 통한 Android 기기 아티팩트 수집을 수행합니다.
    """

    def __init__(self, output_dir: str, device_serial: Optional[str] = None):
        """
        Initialize Android collector.

        Args:
            output_dir: Directory to store collected artifacts
            device_serial: Optional specific device serial (auto-detect if None)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.device_serial = device_serial
        self.device_info: Optional[DeviceInfo] = None
        self.monitor = ADBDeviceMonitor()

    def is_available(self) -> Dict[str, Any]:
        """Check availability of Android forensics"""
        return {
            'adb': ADB_AVAILABLE,
            'device_connected': len(self.monitor.get_connected_devices()) > 0,
            'devices': [
                {
                    'serial': d.serial,
                    'model': d.model,
                    'android_version': d.android_version,
                    'rooted': d.rooted,
                }
                for d in self.monitor.get_connected_devices()
            ],
        }

    def connect(self, serial: Optional[str] = None) -> bool:
        """
        Connect to an Android device.

        Args:
            serial: Device serial (uses first available if None)

        Returns:
            True if connected successfully
        """
        if not ADB_AVAILABLE:
            raise RuntimeError("ADB is not installed or not in PATH")

        devices = self.monitor.get_connected_devices()
        if not devices:
            raise RuntimeError("No Android device connected")

        if serial:
            matching = [d for d in devices if d.serial == serial]
            if not matching:
                raise ValueError(f"Device {serial} not found")
            self.device_info = matching[0]
        else:
            self.device_info = devices[0]

        self.device_serial = self.device_info.serial
        return True

    def _adb_shell(self, cmd: str, use_su: bool = False) -> Tuple[str, int]:
        """
        Execute ADB shell command.

        Args:
            cmd: Command to execute
            use_su: Whether to use superuser (root)

        Returns:
            Tuple of (output, return_code)
        """
        if use_su:
            cmd = f'su -c "{cmd}"'

        full_cmd = ['adb', '-s', self.device_serial, 'shell', cmd]

        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            return result.stdout + result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return 'Command timeout', -1
        except Exception as e:
            return str(e), -1

    def _adb_pull(
        self,
        remote_path: str,
        local_path: str,
        use_su: bool = False
    ) -> bool:
        """
        Pull file from device.

        Args:
            remote_path: Path on device
            local_path: Local destination path
            use_su: Whether to use root for access

        Returns:
            True if successful
        """
        local_path = Path(local_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)

        if use_su:
            # For root-protected files, copy to temp location first
            temp_path = f'/data/local/tmp/forensic_temp_{hashlib.md5(remote_path.encode()).hexdigest()[:8]}'
            self._adb_shell(f'cp "{remote_path}" "{temp_path}"', use_su=True)
            self._adb_shell(f'chmod 644 "{temp_path}"', use_su=True)
            remote_path = temp_path

        try:
            result = subprocess.run(
                ['adb', '-s', self.device_serial, 'pull', remote_path, str(local_path)],
                capture_output=True,
                timeout=300,  # 5 minutes for large files
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )

            if use_su:
                # Clean up temp file
                self._adb_shell(f'rm "{remote_path}"', use_su=True)

            return result.returncode == 0

        except Exception as e:
            _debug_print(f"[ADB Pull] Error: {e}")
            return False

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect specific artifact type from device.

        Args:
            artifact_type: Type of artifact to collect
            progress_callback: Callback for progress updates

        Yields:
            Tuple of (local_path, metadata)
        """
        if not self.device_info:
            raise RuntimeError("Not connected to device. Call connect() first.")

        if artifact_type not in ANDROID_ARTIFACT_TYPES:
            raise ValueError(f"Unknown artifact type: {artifact_type}")

        artifact_info = ANDROID_ARTIFACT_TYPES[artifact_type]

        # Check root requirement
        requires_root = artifact_info.get('requires_root', False)
        if requires_root and not self.device_info.rooted:
            yield (
                '',
                {
                    'artifact_type': artifact_type,
                    'status': 'error',
                    'error': 'Root access required but device is not rooted',
                    'device': self.device_info.serial,
                }
            )
            return

        # Create artifact output directory
        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)

        # Collect based on artifact configuration
        if 'db_path' in artifact_info:
            # Single database file
            yield from self._collect_db(
                artifact_type,
                artifact_info['db_path'],
                artifact_dir,
                requires_root,
                progress_callback
            )

        elif 'paths' in artifact_info:
            # Multiple paths/patterns
            for path_pattern in artifact_info['paths']:
                yield from self._collect_path(
                    artifact_type,
                    path_pattern,
                    artifact_dir,
                    requires_root,
                    progress_callback
                )

        elif 'path' in artifact_info:
            # Directory listing
            yield from self._collect_directory(
                artifact_type,
                artifact_info['path'],
                artifact_dir,
                requires_root,
                progress_callback
            )

    def _collect_db(
        self,
        artifact_type: str,
        db_path: str,
        output_dir: Path,
        use_root: bool,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect a database file"""
        filename = Path(db_path).name
        local_path = output_dir / filename

        if progress_callback:
            progress_callback(f"Collecting {filename}")

        success = self._adb_pull(db_path, str(local_path), use_su=use_root)

        if success and local_path.exists():
            # Calculate hash
            sha256 = hashlib.sha256()
            with open(local_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)

            yield str(local_path), {
                'artifact_type': artifact_type,
                'original_path': db_path,
                'filename': filename,
                'size': local_path.stat().st_size,
                'sha256': sha256.hexdigest(),
                'device_serial': self.device_info.serial,
                'device_model': self.device_info.model,
                'android_version': self.device_info.android_version,
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'adb_pull',
                'root_used': use_root,
            }
        else:
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': f'Failed to pull {db_path}',
                'original_path': db_path,
            }

    def _collect_path(
        self,
        artifact_type: str,
        path_pattern: str,
        output_dir: Path,
        use_root: bool,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files matching a path pattern"""
        # List files matching pattern
        ls_cmd = f'ls -la {path_pattern} 2>/dev/null'
        output, _ = self._adb_shell(ls_cmd, use_su=use_root)

        for line in output.strip().split('\n'):
            if not line or line.startswith('total'):
                continue

            # Parse ls output to get filename
            parts = line.split()
            if len(parts) < 8:
                continue

            filename = ' '.join(parts[7:])  # Filename might have spaces
            if not filename or filename in ('.', '..'):
                continue

            remote_path = str(Path(path_pattern).parent / filename)
            local_path = output_dir / filename

            if progress_callback:
                progress_callback(f"Collecting {filename}")

            success = self._adb_pull(remote_path, str(local_path), use_su=use_root)

            if success and local_path.exists():
                sha256 = hashlib.sha256()
                with open(local_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        sha256.update(chunk)

                yield str(local_path), {
                    'artifact_type': artifact_type,
                    'original_path': remote_path,
                    'filename': filename,
                    'size': local_path.stat().st_size,
                    'sha256': sha256.hexdigest(),
                    'device_serial': self.device_info.serial,
                    'device_model': self.device_info.model,
                    'collected_at': datetime.utcnow().isoformat(),
                    'collection_method': 'adb_pull',
                    'root_used': use_root,
                }

    def _collect_directory(
        self,
        artifact_type: str,
        dir_path: str,
        output_dir: Path,
        use_root: bool,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect directory listing and optionally files"""
        # Get directory listing
        ls_cmd = f'ls -la {dir_path} 2>/dev/null'
        output, _ = self._adb_shell(ls_cmd, use_su=use_root)

        listing_file = output_dir / 'directory_listing.txt'
        listing_file.write_text(output)

        yield str(listing_file), {
            'artifact_type': artifact_type,
            'type': 'directory_listing',
            'original_path': dir_path,
            'device_serial': self.device_info.serial,
            'collected_at': datetime.utcnow().isoformat(),
        }

    def create_backup(
        self,
        output_path: Optional[str] = None,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Create ADB backup of device.

        Args:
            output_path: Path for backup file
            progress_callback: Progress callback

        Returns:
            Tuple of (backup_path, metadata)
        """
        if not self.device_info:
            raise RuntimeError("Not connected to device")

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"android_backup_{self.device_info.serial}_{timestamp}.ab"
        backup_path = Path(output_path) if output_path else self.output_dir / backup_filename

        if progress_callback:
            progress_callback("Creating ADB backup (user confirmation required on device)...")

        try:
            result = subprocess.run(
                ['adb', '-s', self.device_serial, 'backup', '-all', '-f', str(backup_path)],
                capture_output=True,
                timeout=3600,  # 1 hour timeout
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )

            if backup_path.exists():
                sha256 = hashlib.sha256()
                with open(backup_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        sha256.update(chunk)

                return str(backup_path), {
                    'artifact_type': 'android_backup',
                    'filename': backup_filename,
                    'size': backup_path.stat().st_size,
                    'sha256': sha256.hexdigest(),
                    'device_serial': self.device_info.serial,
                    'device_model': self.device_info.model,
                    'collected_at': datetime.utcnow().isoformat(),
                }
            else:
                return '', {
                    'artifact_type': 'android_backup',
                    'status': 'error',
                    'error': 'Backup file not created',
                }

        except subprocess.TimeoutExpired:
            return '', {
                'artifact_type': 'android_backup',
                'status': 'error',
                'error': 'Backup operation timed out',
            }

    def get_available_artifacts(self) -> List[Dict[str, Any]]:
        """Get list of available Android artifact types"""
        artifacts = []
        is_rooted = self.device_info.rooted if self.device_info else False

        for type_id, info in ANDROID_ARTIFACT_TYPES.items():
            available = True
            reasons = []

            if info.get('requires_root') and not is_rooted:
                available = False
                reasons.append('Root 권한 필요')

            artifacts.append({
                'type': type_id,
                'name': info['name'],
                'description': info['description'],
                'available': available,
                'reasons': reasons,
                'requires_root': info.get('requires_root', False),
            })

        return artifacts


def check_usb_debugging_guide() -> str:
    """Return USB debugging enable guide"""
    return """
Android USB 디버깅 활성화 방법:

1. 설정 > 휴대전화 정보 > 빌드 번호를 7회 터치
   - "개발자 모드가 활성화되었습니다" 메시지 확인

2. 설정 > 시스템 > 개발자 옵션 진입
   - 또는 설정 > 개발자 옵션 (기기에 따라 다름)

3. "USB 디버깅" 옵션 활성화

4. USB 케이블로 PC 연결

5. "이 컴퓨터의 USB 디버깅을 허용하시겠습니까?" 팝업에서 "허용" 선택
   - "이 컴퓨터를 항상 허용" 체크박스 선택 권장

6. Collector에서 기기 연결 확인

문제 해결:
- 기기가 인식되지 않으면 USB 드라이버 설치 필요
- OEM USB 드라이버: 제조사 웹사이트에서 다운로드
- Google USB 드라이버: Android SDK에 포함
"""


if __name__ == "__main__":
    print("Android Forensics Collector")
    print("=" * 50)

    print("\n[ADB Status]")
    print(f"  ADB Available: {ADB_AVAILABLE}")

    if ADB_AVAILABLE:
        monitor = ADBDeviceMonitor()
        devices = monitor.get_connected_devices()

        print(f"\n[Connected Devices: {len(devices)}]")
        for device in devices:
            print(f"  - {device.serial}")
            print(f"    Model: {device.model}")
            print(f"    Manufacturer: {device.manufacturer}")
            print(f"    Android: {device.android_version} (SDK {device.sdk_version})")
            print(f"    Rooted: {device.rooted}")

        if not devices:
            print("\n[USB Debugging Guide]")
            print(check_usb_debugging_guide())
    else:
        print("\n[Error] ADB not found. Please install Android SDK Platform Tools.")
        print("Download: https://developer.android.com/studio/releases/platform-tools")
