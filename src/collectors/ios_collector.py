"""
iOS Forensics Collector Module

iOS 기기 포렌식 수집 모듈.
iTunes/Finder 백업을 파싱하여 아티팩트를 추출합니다.

수집 가능 아티팩트:
- mobile_ios_sms: iMessage/SMS 메시지
- mobile_ios_call: 통화 기록
- mobile_ios_contacts: 연락처
- mobile_ios_app: 앱 데이터
- mobile_ios_safari: Safari 브라우저 데이터
- mobile_ios_location: 위치 기록
- mobile_ios_backup: 백업 메타데이터

Requirements:
    - biplist>=1.0.3 (for binary plist parsing)
    - plistlib (stdlib)
"""
import os
import re
import sqlite3
import hashlib
import shutil
import plistlib
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
