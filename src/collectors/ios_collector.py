"""
iOS Forensics Collector Module

iOS 기기 포렌식 수집 모듈.
- iTunes/Finder 백업 파싱
- libimobiledevice 기기 직접 연결 (idevice 명령어)

수집 가능 아티팩트:
[백업 기반]
- mobile_ios_sms: iMessage/SMS 메시지
- mobile_ios_call: 통화 기록
- mobile_ios_contacts: 연락처
- mobile_ios_app: 앱 데이터
- mobile_ios_safari: Safari 브라우저 데이터
- mobile_ios_location: 위치 기록
- mobile_ios_backup: 백업 메타데이터

[2026-01 신규 - 메신저 앱]
- mobile_ios_kakaotalk: KakaoTalk 메시지 (원본, 복호화는 서버에서)
- mobile_ios_kakaotalk_attachments: KakaoTalk 첨부파일
- mobile_ios_kakaotalk_profile: KakaoTalk 프로필/친구 목록

[기기 직접 연결 - libimobiledevice]
- mobile_ios_device_info: 기기 정보
- mobile_ios_syslog: 시스템 로그
- mobile_ios_crash_logs: 크래시 리포트
- mobile_ios_installed_apps: 설치된 앱 목록
- mobile_ios_device_backup: 새 백업 생성
- mobile_ios_unified_logs: Apple Unified Logs (sysdiagnose)

Requirements:
    - biplist>=1.0.3 (for binary plist parsing)
    - plistlib (stdlib)
    - libimobiledevice (optional, for device connection)

License:
    - This module is open source and uses libimobiledevice (LGPL-2.1)
    - Decryption logic is NOT included here (server-only)
"""
import os
import re
import sqlite3
import hashlib
import shutil
import plistlib
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from typing import Generator, Tuple, Dict, Any, Optional, List, Callable
from dataclasses import dataclass

# Check for biplist (for binary plist support)
try:
    import biplist
    BIPLIST_AVAILABLE = True
except ImportError:
    BIPLIST_AVAILABLE = False


# Check for libimobiledevice tools
def check_libimobiledevice_available() -> Dict[str, bool]:
    """Check availability of libimobiledevice tools"""
    tools = {
        'idevice_id': False,
        'ideviceinfo': False,
        'idevicesyslog': False,
        'idevicecrashreport': False,
        'ideviceinstaller': False,
        'idevicebackup2': False,
    }

    for tool in tools:
        try:
            result = subprocess.run(
                [tool, '--version'] if tool != 'idevice_id' else [tool, '-l'],
                capture_output=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            tools[tool] = result.returncode == 0 or b'usage' in result.stderr.lower()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return tools


LIBIMOBILEDEVICE_TOOLS = check_libimobiledevice_available()
LIBIMOBILEDEVICE_AVAILABLE = any(LIBIMOBILEDEVICE_TOOLS.values())


@dataclass
class BackupInfo:
    """iOS 백업 정보"""
    path: Path
    device_name: str
    device_id: str
    product_type: str
    ios_version: str
    backup_date: datetime
    encrypted: bool
    size_mb: float


# iOS artifact type definitions
IOS_ARTIFACT_TYPES = {
    'mobile_ios_sms': {
        'name': 'iMessage/SMS',
        'description': 'Text messages and iMessages',
        'manifest_domain': 'HomeDomain',
        'manifest_path': 'Library/SMS/sms.db',
    },
    'mobile_ios_call': {
        'name': 'Call History',
        'description': 'Phone call records',
        'manifest_domain': 'HomeDomain',
        'manifest_path': 'Library/CallHistoryDB/CallHistory.storedata',
    },
    'mobile_ios_contacts': {
        'name': 'Contacts',
        'description': 'Address book contacts',
        'manifest_domain': 'HomeDomain',
        'manifest_path': 'Library/AddressBook/AddressBook.sqlitedb',
    },
    'mobile_ios_app': {
        'name': 'App Data',
        'description': 'Application data and preferences',
        'manifest_domain': 'AppDomain-*',
        'pattern': True,
    },
    'mobile_ios_safari': {
        'name': 'Safari',
        'description': 'Browser history, bookmarks, and tabs',
        'manifest_domain': 'HomeDomain',
        'manifest_paths': [
            'Library/Safari/History.db',
            'Library/Safari/Bookmarks.db',
            'Library/Safari/BrowserState.db',
        ],
    },
    'mobile_ios_location': {
        'name': 'Location History',
        'description': 'GPS and location data',
        'manifest_domain': 'RootDomain',
        'manifest_path': 'Library/Caches/locationd/consolidated.db',
    },
    'mobile_ios_backup': {
        'name': 'Backup Metadata',
        'description': 'Backup configuration and device info',
        'files': ['Info.plist', 'Manifest.plist', 'Status.plist'],
    },

    # =========================================================================
    # Device Direct Connection Artifacts (libimobiledevice)
    # =========================================================================

    'mobile_ios_device_info': {
        'name': 'Device Information',
        'description': 'iOS device info (UDID, model, iOS version)',
        'requires_device': True,
        'tool': 'ideviceinfo',
        'collection_method': 'device',
    },
    'mobile_ios_syslog': {
        'name': 'System Log',
        'description': 'Real-time iOS system log',
        'requires_device': True,
        'tool': 'idevicesyslog',
        'collection_method': 'device',
    },
    'mobile_ios_crash_logs': {
        'name': 'Crash Reports',
        'description': 'Application crash reports',
        'requires_device': True,
        'tool': 'idevicecrashreport',
        'collection_method': 'device',
    },
    'mobile_ios_installed_apps': {
        'name': 'Installed Apps',
        'description': 'List of installed applications',
        'requires_device': True,
        'tool': 'ideviceinstaller',
        'collection_method': 'device',
    },
    'mobile_ios_device_backup': {
        'name': 'Create Backup',
        'description': 'Create new iOS backup from device',
        'requires_device': True,
        'tool': 'idevicebackup2',
        'collection_method': 'device',
    },

    # =========================================================================
    # [2026-01] Messaging App Artifacts
    # =========================================================================

    'mobile_ios_kakaotalk': {
        'name': 'KakaoTalk Messages (Raw)',
        'description': 'KakaoTalk 메시지 데이터베이스 (원본, 복호화는 서버에서 처리)',
        'manifest_domain': 'AppDomain-com.kakao.KakaoTalk',
        'manifest_path': 'Documents/Message/Message.sqlite',
        # NOTE: Database is encrypted. Decryption is handled server-side only.
        # Collector extracts raw file without decryption.
    },
    'mobile_ios_kakaotalk_attachments': {
        'name': 'KakaoTalk Attachments',
        'description': 'KakaoTalk 첨부파일 (이미지, 동영상, 파일)',
        'manifest_domain': 'AppDomain-com.kakao.KakaoTalk',
        'manifest_path': 'Documents/Message/Attachment/*',
        'pattern': True,
    },
    'mobile_ios_kakaotalk_profile': {
        'name': 'KakaoTalk Profile Data',
        'description': 'KakaoTalk 프로필 및 친구 목록',
        'manifest_domain': 'AppDomain-com.kakao.KakaoTalk',
        'manifest_paths': [
            'Library/Preferences/com.kakao.KakaoTalk.plist',
            'Documents/Profile.sqlite',
            'Documents/Talk.sqlite',
        ],
    },

    # =========================================================================
    # [2026-01] Apple Unified Logs (sysdiagnose)
    # =========================================================================

    'mobile_ios_unified_logs': {
        'name': 'Apple Unified Logs',
        'description': 'Apple Unified Logging System (sysdiagnose 로그)',
        'requires_device': True,
        'tool': 'sysdiagnose',
        'collection_method': 'device',
        # NOTE: Requires sysdiagnose archive from device
        # Settings > Privacy > Analytics > Analytics Data
    },
}


def get_backup_locations() -> List[Path]:
    """Get default iOS backup locations based on OS"""
    locations = []

    if os.name == 'nt':  # Windows
        # iTunes backup location
        appdata = os.environ.get('APPDATA', '')
        if appdata:
            locations.append(
                Path(appdata) / 'Apple Computer' / 'MobileSync' / 'Backup'
            )

        # Apple Devices app (Windows 11)
        localappdata = os.environ.get('LOCALAPPDATA', '')
        if localappdata:
            locations.append(
                Path(localappdata) / 'Packages' /
                'AppleInc.AppleDevices_nzyj5cx40ttqa' /
                'LocalCache' / 'Roaming' / 'Apple Computer' /
                'MobileSync' / 'Backup'
            )

    else:  # macOS / Linux
        home = Path.home()
        locations.append(
            home / 'Library' / 'Application Support' /
            'MobileSync' / 'Backup'
        )

    return [loc for loc in locations if loc.exists()]


def find_ios_backups() -> List[BackupInfo]:
    """
    Find all iOS backups on the system.

    Returns:
        List of BackupInfo objects for each backup found
    """
    backups = []

    for backup_dir in get_backup_locations():
        if not backup_dir.exists():
            continue

        for item in backup_dir.iterdir():
            if not item.is_dir():
                continue

            # Check for Info.plist (indicates valid backup)
            info_plist = item / 'Info.plist'
            if not info_plist.exists():
                continue

            try:
                backup_info = parse_backup_info(item)
                if backup_info:
                    backups.append(backup_info)
            except Exception as e:
                _debug_print(f"[iOS] Error parsing backup {item.name}: {e}")

    return sorted(backups, key=lambda b: b.backup_date, reverse=True)


def parse_backup_info(backup_path: Path) -> Optional[BackupInfo]:
    """Parse backup Info.plist to extract device information"""
    info_plist = backup_path / 'Info.plist'

    if not info_plist.exists():
        return None

    try:
        with open(info_plist, 'rb') as f:
            info = plistlib.load(f)
    except Exception:
        # Try biplist for binary plists
        if BIPLIST_AVAILABLE:
            try:
                info = biplist.readPlist(str(info_plist))
            except Exception:
                return None
        else:
            return None

    # Calculate backup size
    total_size = sum(
        f.stat().st_size for f in backup_path.rglob('*') if f.is_file()
    )

    return BackupInfo(
        path=backup_path,
        device_name=info.get('Device Name', 'Unknown'),
        device_id=info.get('Target Identifier', backup_path.name),
        product_type=info.get('Product Type', 'Unknown'),
        ios_version=info.get('Product Version', 'Unknown'),
        backup_date=info.get('Last Backup Date', datetime.min),
        encrypted=info.get('IsEncrypted', False),
        size_mb=round(total_size / (1024 * 1024), 2),
    )


class iOSBackupParser:
    """
    iOS 백업 파서

    iTunes/Finder 백업의 Manifest.db를 파싱하여
    특정 파일을 찾고 추출합니다.
    """

    def __init__(self, backup_path: Path):
        """
        Initialize backup parser.

        Args:
            backup_path: Path to iOS backup directory
        """
        self.backup_path = backup_path
        self.manifest_db = backup_path / 'Manifest.db'
        self.manifest_plist = backup_path / 'Manifest.plist'

        # Check backup structure
        if not self.backup_path.exists():
            raise FileNotFoundError(f"Backup not found: {backup_path}")

        self.is_modern = self.manifest_db.exists()
        self.is_legacy = self.manifest_plist.exists() and not self.is_modern

        if not self.is_modern and not self.is_legacy:
            raise ValueError("Invalid backup: No Manifest.db or Manifest.plist found")

    def get_file_hash(self, domain: str, relative_path: str) -> Optional[str]:
        """
        Get file hash (filename) for a domain/path combination.

        Args:
            domain: File domain (e.g., 'HomeDomain')
            relative_path: Relative path within domain

        Returns:
            SHA1 hash used as filename in backup, or None if not found
        """
        if self.is_modern:
            return self._get_file_hash_modern(domain, relative_path)
        else:
            return self._get_file_hash_legacy(domain, relative_path)

    def _get_file_hash_modern(self, domain: str, relative_path: str) -> Optional[str]:
        """Get file hash from Manifest.db (iOS 10+)"""
        try:
            conn = sqlite3.connect(str(self.manifest_db))
            cursor = conn.cursor()

            cursor.execute('''
                SELECT fileID FROM Files
                WHERE domain = ? AND relativePath = ?
            ''', (domain, relative_path))

            row = cursor.fetchone()
            conn.close()

            return row[0] if row else None

        except Exception as e:
            _debug_print(f"[iOS] Manifest.db query error: {e}")
            return None

    def _get_file_hash_legacy(self, domain: str, relative_path: str) -> Optional[str]:
        """Get file hash from Manifest.plist (iOS 9 and earlier)"""
        # Calculate the hash directly: SHA1(domain-relativePath)
        full_path = f"{domain}-{relative_path}"
        return hashlib.sha1(full_path.encode()).hexdigest()

    def list_files(
        self,
        domain_filter: Optional[str] = None,
        path_pattern: Optional[str] = None
    ) -> Generator[Dict[str, Any], None, None]:
        """
        List files in backup matching filters.

        Args:
            domain_filter: Filter by domain (supports * wildcard)
            path_pattern: Filter by path (supports * wildcard)

        Yields:
            File information dictionaries
        """
        if self.is_modern:
            yield from self._list_files_modern(domain_filter, path_pattern)
        else:
            yield from self._list_files_legacy(domain_filter, path_pattern)

    def _list_files_modern(
        self,
        domain_filter: Optional[str],
        path_pattern: Optional[str]
    ) -> Generator[Dict[str, Any], None, None]:
        """List files from Manifest.db"""
        try:
            conn = sqlite3.connect(str(self.manifest_db))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = 'SELECT fileID, domain, relativePath, flags, file FROM Files WHERE 1=1'
            params = []

            if domain_filter:
                if '*' in domain_filter:
                    query += ' AND domain LIKE ?'
                    params.append(domain_filter.replace('*', '%'))
                else:
                    query += ' AND domain = ?'
                    params.append(domain_filter)

            if path_pattern:
                if '*' in path_pattern:
                    query += ' AND relativePath LIKE ?'
                    params.append(path_pattern.replace('*', '%'))
                else:
                    query += ' AND relativePath = ?'
                    params.append(path_pattern)

            cursor.execute(query, params)

            for row in cursor:
                # Parse file blob for metadata
                file_info = {
                    'file_id': row['fileID'],
                    'domain': row['domain'],
                    'relative_path': row['relativePath'],
                    'flags': row['flags'],
                }

                # Get actual file path in backup
                file_hash = row['fileID']
                actual_path = self.backup_path / file_hash[:2] / file_hash
                if actual_path.exists():
                    file_info['backup_path'] = str(actual_path)
                    file_info['size'] = actual_path.stat().st_size

                yield file_info

            conn.close()

        except Exception as e:
            _debug_print(f"[iOS] Error listing files: {e}")

    def _list_files_legacy(
        self,
        domain_filter: Optional[str],
        path_pattern: Optional[str]
    ) -> Generator[Dict[str, Any], None, None]:
        """List files from Manifest.mbdb (legacy)"""
        # Legacy format is more complex, placeholder implementation
        yield {
            'status': 'legacy_backup',
            'message': 'Legacy backup format (iOS 9 and earlier) - limited support',
        }

    def extract_file(
        self,
        domain: str,
        relative_path: str,
        output_path: Path
    ) -> bool:
        """
        Extract a specific file from backup.

        Args:
            domain: File domain
            relative_path: Relative path within domain
            output_path: Where to save the extracted file

        Returns:
            True if extraction successful
        """
        file_hash = self.get_file_hash(domain, relative_path)
        if not file_hash:
            return False

        # Find actual file in backup
        source_path = self.backup_path / file_hash[:2] / file_hash

        if not source_path.exists():
            # Try flat structure (older backups)
            source_path = self.backup_path / file_hash

        if not source_path.exists():
            return False

        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, output_path)
        return True


# =============================================================================
# iOS Device Connector (libimobiledevice)
# =============================================================================

@dataclass
class iOSDeviceInfo:
    """연결된 iOS 기기 정보"""
    udid: str
    device_name: str
    product_type: str
    ios_version: str
    serial_number: str
    is_paired: bool


class iOSDeviceConnector:
    """
    libimobiledevice를 통한 iOS 기기 연결 클래스

    연결된 iOS 기기에서 직접 포렌식 아티팩트를 수집합니다.
    idevice* 명령어가 시스템에 설치되어 있어야 합니다.
    """

    def __init__(self, output_dir: str, udid: Optional[str] = None):
        """
        Initialize device connector.

        Args:
            output_dir: Directory to store collected artifacts
            udid: Optional specific device UDID (auto-detect if None)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.udid = udid
        self.device_info: Optional[iOSDeviceInfo] = None

    @staticmethod
    def is_available() -> Dict[str, Any]:
        """Check libimobiledevice availability"""
        return {
            'available': LIBIMOBILEDEVICE_AVAILABLE,
            'tools': LIBIMOBILEDEVICE_TOOLS,
        }

    def _run_idevice_cmd(
        self,
        cmd: List[str],
        timeout: int = 30
    ) -> Tuple[str, int]:
        """Run idevice command and return output"""
        if self.udid:
            cmd = cmd[:1] + ['-u', self.udid] + cmd[1:]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            return result.stdout + result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return 'Command timeout', -1
        except FileNotFoundError:
            return f'Command not found: {cmd[0]}', -1
        except Exception as e:
            return str(e), -1

    def get_connected_devices(self) -> List[str]:
        """Get list of connected device UDIDs"""
        if not LIBIMOBILEDEVICE_TOOLS.get('idevice_id'):
            return []

        output, returncode = self._run_idevice_cmd(['idevice_id', '-l'])
        if returncode != 0:
            return []

        devices = [line.strip() for line in output.split('\n') if line.strip()]
        return devices

    def connect(self, udid: Optional[str] = None) -> bool:
        """
        Connect to an iOS device.

        Args:
            udid: Device UDID (uses first available if None)

        Returns:
            True if connected successfully
        """
        if not LIBIMOBILEDEVICE_AVAILABLE:
            raise RuntimeError("libimobiledevice is not installed")

        devices = self.get_connected_devices()
        if not devices:
            raise RuntimeError("No iOS device connected")

        if udid:
            if udid not in devices:
                raise ValueError(f"Device {udid} not found")
            self.udid = udid
        else:
            self.udid = devices[0]

        # Get device info
        self.device_info = self._get_device_info()
        return self.device_info is not None

    def _get_device_info(self) -> Optional[iOSDeviceInfo]:
        """Get detailed device information"""
        if not LIBIMOBILEDEVICE_TOOLS.get('ideviceinfo'):
            return None

        output, returncode = self._run_idevice_cmd(['ideviceinfo'])
        if returncode != 0:
            return None

        # Parse ideviceinfo output
        info = {}
        for line in output.split('\n'):
            if ':' in line:
                key, _, value = line.partition(':')
                info[key.strip()] = value.strip()

        return iOSDeviceInfo(
            udid=self.udid,
            device_name=info.get('DeviceName', 'Unknown'),
            product_type=info.get('ProductType', 'Unknown'),
            ios_version=info.get('ProductVersion', 'Unknown'),
            serial_number=info.get('SerialNumber', 'Unknown'),
            is_paired=True,  # If we can get info, device is paired
        )

    def collect_device_info(
        self,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect device information"""
        if progress_callback:
            progress_callback("Collecting device information")

        output, returncode = self._run_idevice_cmd(['ideviceinfo'])

        if returncode != 0:
            yield '', {
                'artifact_type': 'mobile_ios_device_info',
                'status': 'error',
                'error': output,
            }
            return

        filename = f"device_info_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
        local_path = output_dir / filename
        local_path.write_text(output, encoding='utf-8')

        sha256 = hashlib.sha256(output.encode('utf-8')).hexdigest()

        yield str(local_path), {
            'artifact_type': 'mobile_ios_device_info',
            'filename': filename,
            'size': local_path.stat().st_size,
            'sha256': sha256,
            'device_udid': self.udid,
            'device_name': self.device_info.device_name if self.device_info else 'Unknown',
            'ios_version': self.device_info.ios_version if self.device_info else 'Unknown',
            'collected_at': datetime.utcnow().isoformat(),
            'collection_method': 'ideviceinfo',
        }

    def collect_syslog(
        self,
        output_dir: Path,
        duration_seconds: int = 10,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect system log for specified duration"""
        if not LIBIMOBILEDEVICE_TOOLS.get('idevicesyslog'):
            yield '', {
                'artifact_type': 'mobile_ios_syslog',
                'status': 'error',
                'error': 'idevicesyslog not installed',
            }
            return

        if progress_callback:
            progress_callback(f"Collecting system log ({duration_seconds}s)")

        cmd = ['idevicesyslog']
        if self.udid:
            cmd.extend(['-u', self.udid])

        try:
            # Run syslog capture for limited time
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )

            import time
            time.sleep(duration_seconds)
            process.terminate()

            output, _ = process.communicate(timeout=5)
            output_text = output.decode('utf-8', errors='replace')

            filename = f"syslog_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
            local_path = output_dir / filename
            local_path.write_text(output_text, encoding='utf-8')

            sha256 = hashlib.sha256(output_text.encode('utf-8')).hexdigest()

            yield str(local_path), {
                'artifact_type': 'mobile_ios_syslog',
                'filename': filename,
                'size': local_path.stat().st_size,
                'sha256': sha256,
                'duration_seconds': duration_seconds,
                'device_udid': self.udid,
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'idevicesyslog',
            }

        except Exception as e:
            yield '', {
                'artifact_type': 'mobile_ios_syslog',
                'status': 'error',
                'error': str(e),
            }

    def collect_crash_logs(
        self,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect crash reports from device"""
        if not LIBIMOBILEDEVICE_TOOLS.get('idevicecrashreport'):
            yield '', {
                'artifact_type': 'mobile_ios_crash_logs',
                'status': 'error',
                'error': 'idevicecrashreport not installed',
            }
            return

        if progress_callback:
            progress_callback("Collecting crash reports")

        crash_dir = output_dir / 'crash_reports'
        crash_dir.mkdir(exist_ok=True)

        cmd = ['idevicecrashreport', '-e', str(crash_dir)]
        if self.udid:
            cmd = ['idevicecrashreport', '-u', self.udid, '-e', str(crash_dir)]

        output, returncode = self._run_idevice_cmd(cmd, timeout=120)

        # List collected crash files
        crash_files = list(crash_dir.rglob('*'))
        if crash_files:
            for crash_file in crash_files:
                if crash_file.is_file():
                    sha256 = hashlib.sha256()
                    with open(crash_file, 'rb') as f:
                        for chunk in iter(lambda: f.read(65536), b''):
                            sha256.update(chunk)

                    yield str(crash_file), {
                        'artifact_type': 'mobile_ios_crash_logs',
                        'filename': crash_file.name,
                        'size': crash_file.stat().st_size,
                        'sha256': sha256.hexdigest(),
                        'device_udid': self.udid,
                        'collected_at': datetime.utcnow().isoformat(),
                        'collection_method': 'idevicecrashreport',
                    }
        else:
            yield '', {
                'artifact_type': 'mobile_ios_crash_logs',
                'status': 'no_data',
                'message': 'No crash reports found',
            }

    def collect_installed_apps(
        self,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect list of installed apps"""
        if not LIBIMOBILEDEVICE_TOOLS.get('ideviceinstaller'):
            yield '', {
                'artifact_type': 'mobile_ios_installed_apps',
                'status': 'error',
                'error': 'ideviceinstaller not installed',
            }
            return

        if progress_callback:
            progress_callback("Collecting installed apps list")

        cmd = ['ideviceinstaller', '-l']
        if self.udid:
            cmd = ['ideviceinstaller', '-u', self.udid, '-l']

        output, returncode = self._run_idevice_cmd(cmd)

        if returncode != 0:
            yield '', {
                'artifact_type': 'mobile_ios_installed_apps',
                'status': 'error',
                'error': output,
            }
            return

        filename = f"installed_apps_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
        local_path = output_dir / filename
        local_path.write_text(output, encoding='utf-8')

        sha256 = hashlib.sha256(output.encode('utf-8')).hexdigest()

        yield str(local_path), {
            'artifact_type': 'mobile_ios_installed_apps',
            'filename': filename,
            'size': local_path.stat().st_size,
            'sha256': sha256,
            'device_udid': self.udid,
            'collected_at': datetime.utcnow().isoformat(),
            'collection_method': 'ideviceinstaller',
        }

    def create_backup(
        self,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Create new iOS backup from device"""
        if not LIBIMOBILEDEVICE_TOOLS.get('idevicebackup2'):
            yield '', {
                'artifact_type': 'mobile_ios_device_backup',
                'status': 'error',
                'error': 'idevicebackup2 not installed',
            }
            return

        if progress_callback:
            progress_callback("Creating iOS backup (this may take a while)")

        backup_dir = output_dir / 'backup'
        backup_dir.mkdir(exist_ok=True)

        cmd = ['idevicebackup2', 'backup', str(backup_dir)]
        if self.udid:
            cmd = ['idevicebackup2', '-u', self.udid, 'backup', str(backup_dir)]

        output, returncode = self._run_idevice_cmd(cmd, timeout=3600)  # 1 hour

        if returncode == 0:
            # Calculate backup size
            total_size = sum(
                f.stat().st_size for f in backup_dir.rglob('*') if f.is_file()
            )

            yield str(backup_dir), {
                'artifact_type': 'mobile_ios_device_backup',
                'backup_path': str(backup_dir),
                'size_bytes': total_size,
                'size_mb': round(total_size / (1024 * 1024), 2),
                'device_udid': self.udid,
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'idevicebackup2',
            }
        else:
            yield '', {
                'artifact_type': 'mobile_ios_device_backup',
                'status': 'error',
                'error': output,
            }


class iOSCollector:
    """
    iOS 포렌식 수집 통합 클래스

    iTunes/Finder 백업에서 포렌식 아티팩트를 추출합니다.
    """

    def __init__(self, output_dir: str, backup_path: Optional[str] = None):
        """
        Initialize iOS collector.

        Args:
            output_dir: Directory to store collected artifacts
            backup_path: Path to specific backup (auto-detect if None)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.backup_path = Path(backup_path) if backup_path else None
        self.backup_info: Optional[BackupInfo] = None
        self.parser: Optional[iOSBackupParser] = None

    def get_available_backups(self) -> List[BackupInfo]:
        """Get list of available iOS backups"""
        return find_ios_backups()

    def select_backup(self, backup_path: str) -> bool:
        """
        Select a backup to work with.

        Args:
            backup_path: Path to backup directory

        Returns:
            True if backup is valid and selected
        """
        path = Path(backup_path)
        if not path.exists():
            raise FileNotFoundError(f"Backup not found: {backup_path}")

        self.backup_info = parse_backup_info(path)
        if self.backup_info is None:
            raise ValueError(f"Invalid backup: {backup_path}")

        self.backup_path = path
        self.parser = iOSBackupParser(path)
        return True

    def is_encrypted(self) -> bool:
        """Check if selected backup is encrypted"""
        return self.backup_info.encrypted if self.backup_info else False

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect specific artifact type from backup.

        Args:
            artifact_type: Type of artifact to collect
            progress_callback: Callback for progress updates

        Yields:
            Tuple of (local_path, metadata)
        """
        if not self.parser:
            raise RuntimeError("No backup selected. Call select_backup() first.")

        if self.backup_info.encrypted:
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': '암호화된 백업입니다. 백업 비밀번호가 필요합니다.',
                'backup_path': str(self.backup_path),
            }
            return

        if artifact_type not in IOS_ARTIFACT_TYPES:
            raise ValueError(f"Unknown artifact type: {artifact_type}")

        artifact_info = IOS_ARTIFACT_TYPES[artifact_type]

        # Create artifact output directory
        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)

        # Handle backup metadata separately
        if artifact_type == 'mobile_ios_backup':
            yield from self._collect_backup_metadata(artifact_dir, progress_callback)
            return

        # Handle pattern-based collection
        if artifact_info.get('pattern'):
            yield from self._collect_pattern(
                artifact_type,
                artifact_info,
                artifact_dir,
                progress_callback
            )
            return

        # Handle multiple paths
        if 'manifest_paths' in artifact_info:
            for path in artifact_info['manifest_paths']:
                yield from self._collect_file(
                    artifact_type,
                    artifact_info['manifest_domain'],
                    path,
                    artifact_dir,
                    progress_callback
                )
            return

        # Handle single path
        if 'manifest_path' in artifact_info:
            yield from self._collect_file(
                artifact_type,
                artifact_info['manifest_domain'],
                artifact_info['manifest_path'],
                artifact_dir,
                progress_callback
            )

    def _collect_file(
        self,
        artifact_type: str,
        domain: str,
        relative_path: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect a specific file from backup"""
        filename = Path(relative_path).name
        local_path = output_dir / filename

        if progress_callback:
            progress_callback(f"Extracting {filename}")

        success = self.parser.extract_file(domain, relative_path, local_path)

        if success and local_path.exists():
            sha256 = hashlib.sha256()
            with open(local_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)

            yield str(local_path), {
                'artifact_type': artifact_type,
                'domain': domain,
                'original_path': relative_path,
                'filename': filename,
                'size': local_path.stat().st_size,
                'sha256': sha256.hexdigest(),
                'device_name': self.backup_info.device_name,
                'device_id': self.backup_info.device_id,
                'ios_version': self.backup_info.ios_version,
                'backup_date': self.backup_info.backup_date.isoformat(),
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'ios_backup_extraction',
            }
        else:
            yield '', {
                'artifact_type': artifact_type,
                'status': 'not_found',
                'domain': domain,
                'path': relative_path,
                'message': f'File not found in backup: {relative_path}',
            }

    def _collect_pattern(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files matching a domain pattern"""
        domain_pattern = artifact_info.get('manifest_domain', '*')

        for file_info in self.parser.list_files(domain_filter=domain_pattern):
            if 'backup_path' not in file_info:
                continue

            source_path = Path(file_info['backup_path'])
            if not source_path.exists():
                continue

            # Create subdirectory for domain
            domain = file_info.get('domain', 'unknown')
            domain_dir = output_dir / domain.replace('-', '_').replace('.', '_')
            domain_dir.mkdir(exist_ok=True)

            filename = Path(file_info.get('relative_path', 'unknown')).name
            local_path = domain_dir / filename

            if progress_callback:
                progress_callback(f"Extracting {domain}/{filename}")

            shutil.copy2(source_path, local_path)

            sha256 = hashlib.sha256()
            with open(local_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)

            yield str(local_path), {
                'artifact_type': artifact_type,
                'domain': domain,
                'original_path': file_info.get('relative_path'),
                'filename': filename,
                'size': local_path.stat().st_size,
                'sha256': sha256.hexdigest(),
                'device_name': self.backup_info.device_name,
                'collected_at': datetime.utcnow().isoformat(),
            }

    def _collect_backup_metadata(
        self,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect backup metadata files"""
        metadata_files = ['Info.plist', 'Manifest.plist', 'Status.plist']

        for filename in metadata_files:
            source_path = self.backup_path / filename
            if not source_path.exists():
                continue

            local_path = output_dir / filename

            if progress_callback:
                progress_callback(f"Copying {filename}")

            shutil.copy2(source_path, local_path)

            sha256 = hashlib.sha256()
            with open(local_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)

            # Parse plist content
            try:
                with open(local_path, 'rb') as f:
                    content = plistlib.load(f)
            except Exception:
                content = {}

            yield str(local_path), {
                'artifact_type': 'mobile_ios_backup',
                'filename': filename,
                'size': local_path.stat().st_size,
                'sha256': sha256.hexdigest(),
                'content_preview': {
                    k: str(v)[:100] for k, v in list(content.items())[:10]
                },
                'collected_at': datetime.utcnow().isoformat(),
            }

    def get_available_artifacts(self) -> List[Dict[str, Any]]:
        """Get list of available iOS artifact types"""
        artifacts = []
        backup_available = self.backup_info is not None
        encrypted = self.backup_info.encrypted if self.backup_info else False

        for type_id, info in IOS_ARTIFACT_TYPES.items():
            available = backup_available and not encrypted
            reasons = []

            if not backup_available:
                available = False
                reasons.append('백업 선택 필요')

            if encrypted:
                available = False
                reasons.append('암호화된 백업')

            artifacts.append({
                'type': type_id,
                'name': info['name'],
                'description': info['description'],
                'available': available,
                'reasons': reasons,
            })

        return artifacts


def get_backup_guide() -> str:
    """Return iOS backup creation guide"""
    return """
iOS 백업 생성 방법 (iTunes/Finder):

=== Windows (iTunes) ===
1. iTunes를 최신 버전으로 업데이트
2. Lightning/USB-C 케이블로 iPhone 연결
3. "이 컴퓨터 신뢰" 팝업에서 "신뢰" 선택
4. iTunes에서 기기 아이콘 클릭
5. "요약" 탭에서:
   - "이 컴퓨터" 선택 (iCloud 백업 아님)
   - ⚠️ "로컬 백업 암호화" 체크 해제 (포렌식 분석 위해)
   - "지금 백업" 클릭
6. 백업 완료 대기 (기기 데이터양에 따라 수분~수십분)

=== macOS (Finder) - macOS Catalina 이상 ===
1. Lightning/USB-C 케이블로 iPhone 연결
2. Finder에서 iPhone 선택 (사이드바)
3. "일반" 탭에서:
   - "iPhone의 모든 데이터를 이 Mac에 백업"
   - ⚠️ "로컬 백업 암호화" 체크 해제
   - "지금 백업" 클릭

=== 백업 파일 위치 ===
Windows:
  %APPDATA%\\Apple Computer\\MobileSync\\Backup\\

macOS:
  ~/Library/Application Support/MobileSync/Backup/

=== 주의사항 ===
- 암호화된 백업은 비밀번호 없이 분석 불가
- 백업 용량: 기기 데이터와 비슷한 용량 필요
- 백업 중 케이블 분리 금지
- iCloud 백업은 이 도구로 분석 불가 (로컬 백업만 지원)

=== 문제 해결 ===
- "이 컴퓨터 신뢰" 팝업이 안 나타남:
  → 기기 잠금 해제 후 다시 연결
  → 설정 > 일반 > 재설정 > 위치 및 개인정보 보호 재설정

- 백업 실패:
  → 디스크 공간 확인 (백업 용량 이상 필요)
  → USB 케이블 및 포트 변경 시도
  → iTunes/Finder 재시작
"""


if __name__ == "__main__":
    print("iOS Forensics Collector")
    print("=" * 50)

    print("\n[Available Backups]")
    backups = find_ios_backups()

    if backups:
        for backup in backups:
            encrypted_str = " [ENCRYPTED]" if backup.encrypted else ""
            print(f"\n  {backup.device_name}{encrypted_str}")
            print(f"    ID: {backup.device_id}")
            print(f"    Model: {backup.product_type}")
            print(f"    iOS: {backup.ios_version}")
            print(f"    Date: {backup.backup_date}")
            print(f"    Size: {backup.size_mb} MB")
            print(f"    Path: {backup.path}")
    else:
        print("  No iOS backups found.")
        print("\n[Backup Locations Searched]")
        for loc in get_backup_locations():
            print(f"  - {loc}")

        print("\n[How to Create Backup]")
        print(get_backup_guide())
