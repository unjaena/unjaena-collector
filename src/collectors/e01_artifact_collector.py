# -*- coding: utf-8 -*-
"""
E01 Artifact Collector

E01 증거 이미지에서 아티팩트를 추출하는 수집기.
BaseMFTCollector를 상속하여 MFT 기반 수집을 사용합니다.

디지털 포렌식 원칙:
- MFT 파싱 기반 수집 (디렉토리 탐색 금지)
- 파일 수 제한 없음
- 삭제 파일 포함
- 시스템 폴더 포함

Usage:
    collector = E01ArtifactCollector("evidence.E01", output_dir="./extracted")
    partitions = collector.list_partitions()
    collector.select_partition(0)

    for file_path, metadata in collector.collect("registry"):
        _debug_print(f"Extracted: {file_path}")
"""

import logging
from pathlib import Path
from typing import Generator, Tuple, Dict, Any, List, Optional
from dataclasses import dataclass

# Import base class
from collectors.base_mft_collector import BaseMFTCollector, ARTIFACT_MFT_FILTERS

# Import ForensicDiskAccessor
try:
    from collectors.forensic_disk import ForensicDiskAccessor, FORENSIC_DISK_AVAILABLE
except ImportError:
    FORENSIC_DISK_AVAILABLE = False
    ForensicDiskAccessor = None

logger = logging.getLogger(__name__)

# Debug output control
_DEBUG_OUTPUT = False
def _debug_print(msg): 
    if _DEBUG_OUTPUT: _debug_print(msg)


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class PartitionInfo:
    """파티션 정보"""
    index: int
    offset: int
    size: int
    filesystem: str
    type_name: str
    bootable: bool = False


@dataclass
class ExtractedArtifact:
    """추출된 아티팩트 정보"""
    local_path: str           # 로컬 저장 경로
    original_path: str        # 원본 경로 (이미지 내)
    artifact_type: str        # 아티팩트 유형
    filename: str             # 파일명
    size: int                 # 크기
    sha256: str               # SHA256 해시
    md5: str                  # MD5 해시
    metadata: Dict[str, Any]  # 추가 메타데이터


# =============================================================================
# Legacy Artifact Path Mappings (backward compatibility)
# =============================================================================

ARTIFACT_PATHS = {
    'registry': {
        'description': 'Windows Registry Hives',
        'paths': [
            ('Windows/System32/config/SYSTEM', 'System Registry'),
            ('Windows/System32/config/SOFTWARE', 'Software Registry'),
            ('Windows/System32/config/SAM', 'SAM Registry'),
            ('Windows/System32/config/SECURITY', 'Security Registry'),
            ('Windows/System32/config/DEFAULT', 'Default Registry'),
        ],
        'user_paths': [
            ('NTUSER.DAT', 'User Registry Hive'),
        ],
        'pattern': None,
    },
    'prefetch': {
        'description': 'Windows Prefetch Files',
        'paths': [
            ('Windows/Prefetch', 'Prefetch Directory'),
        ],
        'pattern': '*.pf',
    },
    'eventlog': {
        'description': 'Windows Event Logs',
        'paths': [
            ('Windows/System32/winevt/Logs', 'Event Logs'),
        ],
        'pattern': '*.evtx',
    },
    'browser': {
        'description': 'Browser Data',
        'user_paths': [
            ('AppData/Local/Google/Chrome/User Data/Default/History', 'Chrome History'),
            ('AppData/Local/Google/Chrome/User Data/Default/Cookies', 'Chrome Cookies'),
            ('AppData/Local/Microsoft/Edge/User Data/Default/History', 'Edge History'),
            ('AppData/Roaming/Mozilla/Firefox/Profiles', 'Firefox Profiles'),
        ],
        'pattern': None,
    },
    'usb': {
        'description': 'USB Device History',
        'paths': [
            ('Windows/INF/setupapi.dev.log', 'SetupAPI Device Log'),
            ('Windows/inf/setupapi.dev.log', 'SetupAPI Device Log (lowercase)'),
        ],
        'pattern': None,
    },
    'recent': {
        'description': 'Recent Files',
        'user_paths': [
            ('AppData/Roaming/Microsoft/Windows/Recent', 'Recent Files'),
        ],
        'pattern': '*.lnk',
    },
    'mft': {
        'description': 'Master File Table',
        'special': 'collect_mft_raw',
    },
    'logfile': {
        'description': 'NTFS $LogFile',
        'special': 'collect_logfile',
    },
    'usn_journal': {
        'description': 'USN Journal',
        'special': 'collect_usn_journal',
    },
    'amcache': {
        'description': 'Amcache.hve',
        'paths': [
            ('Windows/AppCompat/Programs/Amcache.hve', 'Amcache'),
        ],
        'pattern': None,
    },
    'userassist': {
        'description': 'UserAssist (NTUSER.DAT)',
        'user_paths': [
            ('NTUSER.DAT', 'User Registry'),
        ],
        'pattern': None,
    },
    'recycle_bin': {
        'description': 'Recycle Bin',
        'paths': [
            ('$Recycle.Bin', 'Recycle Bin'),
        ],
        'pattern': '$I*',
    },
    'srum': {
        'description': 'SRUM Database',
        'paths': [
            ('Windows/System32/sru/SRUDB.dat', 'SRUM'),
            ('Windows/System32/SRU/SRUDB.dat', 'SRUM (uppercase)'),
        ],
        'pattern': None,
    },
    'jumplist': {
        'description': 'Jump Lists',
        'user_paths': [
            ('AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations', 'Auto Destinations'),
            ('AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations', 'Custom Destinations'),
        ],
        'pattern': '*.automaticDestinations-ms,*.customDestinations-ms',
    },
    'shortcut': {
        'description': 'Shortcut Files',
        'user_paths': [
            ('Desktop', 'Desktop Shortcuts'),
        ],
        'pattern': '*.lnk',
    },
    'scheduled_task': {
        'description': 'Scheduled Tasks',
        'paths': [
            ('Windows/System32/Tasks', 'Scheduled Tasks'),
        ],
        'pattern': '*',
    },
    'shellbags': {
        'description': 'ShellBags',
        'user_paths': [
            ('NTUSER.DAT', 'NTUSER.DAT'),
            ('AppData/Local/Microsoft/Windows/UsrClass.dat', 'UsrClass.dat'),
        ],
        'pattern': None,
    },
    'thumbcache': {
        'description': 'Thumbnail Cache',
        'user_paths': [
            ('AppData/Local/Microsoft/Windows/Explorer', 'Explorer Cache'),
        ],
        'pattern': 'thumbcache_*.db',
    },
    'document': {
        'description': 'Documents',
        'pattern': '*.doc,*.docx,*.pdf,*.xls,*.xlsx,*.ppt,*.pptx,*.hwp,*.hwpx,*.txt,*.rtf',
    },
    'email': {
        'description': 'Email Files',
        'pattern': '*.pst,*.ost,*.eml,*.msg',
    },
    'image': {
        'description': 'Image Files',
        'pattern': '*.jpg,*.jpeg,*.png,*.gif,*.bmp,*.tiff,*.webp,*.heic,*.raw',
    },
    'video': {
        'description': 'Video Files',
        'pattern': '*.mp4,*.avi,*.mkv,*.mov,*.wmv,*.flv,*.webm,*.mpeg',
    },
    # Mobile artifacts (skip for E01)
    'mobile_android_sms': {'skip': True},
    'mobile_android_call': {'skip': True},
    'mobile_android_contacts': {'skip': True},
    'mobile_android_app': {'skip': True},
    'mobile_android_wifi': {'skip': True},
    'mobile_android_location': {'skip': True},
    'mobile_android_media': {'skip': True},
    'mobile_ios_sms': {'skip': True},
    'mobile_ios_call': {'skip': True},
    'mobile_ios_contacts': {'skip': True},
    'mobile_ios_app': {'skip': True},
    'mobile_ios_safari': {'skip': True},
    'mobile_ios_location': {'skip': True},
    'mobile_ios_backup': {'skip': True},
}


# =============================================================================
# E01 Artifact Collector
# =============================================================================

class E01ArtifactCollector(BaseMFTCollector):
    """
    E01 이미지 아티팩트 수집기

    BaseMFTCollector를 상속하여 MFT 기반 수집을 사용합니다.

    디지털 포렌식 원칙:
    - MFT 파싱 기반 수집 (디렉토리 탐색 금지)
    - 파일 수 제한 없음
    - 삭제 파일 포함
    - 시스템 폴더 포함
    """

    def __init__(self, e01_path: str, output_dir: str = None):
        """
        Args:
            e01_path: E01 이미지 파일 경로 (첫 번째 세그먼트)
            output_dir: 추출된 아티팩트 저장 디렉토리
        """
        self.e01_path = Path(e01_path)

        if output_dir is None:
            output_dir = str(Path.cwd() / 'e01_extract')

        super().__init__(output_dir)

        self._selected_partition: Optional[int] = None
        self._partitions: List[PartitionInfo] = []
        self._user_folders: List[str] = []

        self._initialize_accessor()

    def _initialize_accessor(self) -> bool:
        """ForensicDiskAccessor 초기화"""
        if not FORENSIC_DISK_AVAILABLE or ForensicDiskAccessor is None:
            logger.error("ForensicDiskAccessor not available")
            return False

        try:
            self._accessor = ForensicDiskAccessor.from_e01(str(self.e01_path))
            logger.info(f"E01 image loaded: {self.e01_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load E01 image: {e}")
            self._accessor = None
            return False

    def _get_source_description(self) -> str:
        """소스 설명 반환"""
        return f"E01: {self.e01_path.name}"

    # =========================================================================
    # Partition Management
    # =========================================================================

    def list_partitions(self) -> List[PartitionInfo]:
        """파티션 목록 조회"""
        if not self._accessor:
            return []

        try:
            raw_partitions = self._accessor.list_partitions()
            self._partitions = []

            for i, p in enumerate(raw_partitions):
                self._partitions.append(PartitionInfo(
                    index=i,
                    offset=p.offset,
                    size=p.size,
                    filesystem=p.filesystem,
                    type_name=p.type_name,
                    bootable=getattr(p, 'is_bootable', False),
                ))

            return self._partitions

        except Exception as e:
            logger.error(f"Failed to list partitions: {e}")
            return []

    def select_partition(self, index: int) -> bool:
        """파티션 선택"""
        if not self._accessor:
            return False

        try:
            self._accessor.select_partition(index)
            self._selected_partition = index
            logger.info(f"Selected partition {index}")

            # 사용자 폴더 탐색
            self._discover_user_folders()

            # MFT 인덱스 초기화
            self._mft_indexed = False
            self._mft_cache = {'active_files': [], 'deleted_files': [], 'directories': []}
            self._extension_index = {}

            return True

        except Exception as e:
            logger.error(f"Failed to select partition {index}: {e}")
            return False

    def get_windows_partition(self) -> Optional[int]:
        """Windows 파티션 자동 탐지"""
        if not self._partitions:
            self.list_partitions()

        for p in self._partitions:
            if p.filesystem.upper() == 'NTFS' and p.size > 20 * 1024 * 1024 * 1024:
                # 20GB 이상의 NTFS 파티션 선택
                return p.index

        # 가장 큰 NTFS 파티션 선택
        ntfs_partitions = [p for p in self._partitions if p.filesystem.upper() == 'NTFS']
        if ntfs_partitions:
            largest = max(ntfs_partitions, key=lambda p: p.size)
            return largest.index

        return None

    def _discover_user_folders(self) -> None:
        """Users 폴더 내 사용자 디렉토리 탐색"""
        if not self._accessor:
            return

        self._user_folders = []
        system_folders = {'public', 'default', 'default user', 'all users', 'desktop.ini'}

        try:
            # Users 디렉토리 찾기
            users_inode = self._accessor.resolve_path('/Users')
            if users_inode is None:
                users_inode = self._accessor.resolve_path('/users')

            if users_inode is None:
                logger.warning("Users directory not found")
                return

            # 사용자 폴더 목록
            entries = self._accessor.list_directory(users_inode)
            for entry in entries:
                name = entry.filename if hasattr(entry, 'filename') else str(entry)
                is_dir = entry.is_directory if hasattr(entry, 'is_directory') else False

                if is_dir and name.lower() not in system_folders:
                    self._user_folders.append(name)

            logger.info(f"Found {len(self._user_folders)} user folders: {self._user_folders}")

        except Exception as e:
            logger.debug(f"Error discovering user folders: {e}")

    # =========================================================================
    # Collection (inherits from BaseMFTCollector)
    # =========================================================================

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None,
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        아티팩트 수집 (MFT 기반)

        Args:
            artifact_type: 수집할 아티팩트 유형
            progress_callback: 진행률 콜백

        Yields:
            (로컬 경로, 메타데이터) 튜플
        """
        if self._selected_partition is None:
            logger.error("No partition selected. Call select_partition() first.")
            return

        # Skip mobile artifacts
        if artifact_type in ARTIFACT_PATHS and ARTIFACT_PATHS[artifact_type].get('skip'):
            logger.debug(f"Skipping {artifact_type} (not applicable for E01)")
            return

        # Use base class implementation
        yield from super().collect(artifact_type, progress_callback, **kwargs)

    # =========================================================================
    # Utilities
    # =========================================================================

    def get_image_info(self) -> Dict[str, Any]:
        """E01 이미지 정보 반환"""
        if not self._accessor:
            return {}

        return {
            'path': str(self.e01_path),
            'partitions': len(self._partitions),
            'selected_partition': self._selected_partition,
            'user_folders': self._user_folders,
        }

    def close(self):
        """리소스 정리"""
        super().close()
        self._selected_partition = None
        self._partitions = []
        self._user_folders = []
