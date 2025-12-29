# -*- coding: utf-8 -*-
"""
E01 Artifact Collector

E01 증거 이미지에서 아티팩트를 추출하는 수집기.
기존 ForensicDiskAccessor를 활용하여 디스크 이미지를 파싱하고
아티팩트를 로컬에 추출한 후 서버로 업로드합니다.

Usage:
    collector = E01ArtifactCollector("evidence.E01", output_dir="./extracted")
    partitions = collector.list_partitions()
    collector.select_partition(0)

    for file_path, metadata in collector.collect("registry"):
        print(f"Extracted: {file_path}")
"""

import os
import hashlib
import logging
from pathlib import Path
from typing import Generator, Tuple, Dict, Any, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


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
# Artifact Path Mappings
# =============================================================================

# 아티팩트 유형별 수집 경로
ARTIFACT_PATHS = {
    # 레지스트리 하이브
    'registry': {
        'description': 'Windows Registry Hives',
        'paths': [
            ('Windows/System32/config/SYSTEM', 'SYSTEM hive'),
            ('Windows/System32/config/SOFTWARE', 'SOFTWARE hive'),
            ('Windows/System32/config/SAM', 'SAM hive'),
            ('Windows/System32/config/SECURITY', 'SECURITY hive'),
            ('Windows/System32/config/DEFAULT', 'DEFAULT hive'),
            ('Windows/AppCompat/Programs/Amcache.hve', 'Amcache'),
        ],
        'user_paths': [
            ('NTUSER.DAT', 'User registry hive'),
            ('AppData/Local/Microsoft/Windows/UsrClass.dat', 'User class hive'),
        ],
    },

    # Prefetch
    'prefetch': {
        'description': 'Windows Prefetch Files',
        'paths': [
            ('Windows/Prefetch', 'Prefetch directory'),
        ],
        'pattern': '*.pf',
    },

    # 이벤트 로그
    'eventlog': {
        'description': 'Windows Event Logs',
        'paths': [
            ('Windows/System32/winevt/Logs', 'Event logs directory'),
        ],
        'pattern': '*.evtx',
    },

    # 브라우저
    'browser': {
        'description': 'Browser Artifacts',
        'user_paths': [
            ('AppData/Local/Google/Chrome/User Data/Default/History', 'Chrome History'),
            ('AppData/Local/Google/Chrome/User Data/Default/Cookies', 'Chrome Cookies'),
            ('AppData/Local/Microsoft/Edge/User Data/Default/History', 'Edge History'),
            ('AppData/Roaming/Mozilla/Firefox/Profiles', 'Firefox Profiles'),
        ],
    },

    # USB 흔적
    'usb': {
        'description': 'USB Device Traces',
        'paths': [
            ('Windows/inf/setupapi.dev.log', 'USB setup log'),
        ],
        # USB 정보는 주로 레지스트리에서 추출
    },

    # 최근 파일
    'recent': {
        'description': 'Recent Files and Links',
        'user_paths': [
            ('AppData/Roaming/Microsoft/Windows/Recent', 'Recent files'),
            ('AppData/Roaming/Microsoft/Office/Recent', 'Office recent'),
        ],
    },

    # MFT
    'mft': {
        'description': 'Master File Table',
        'paths': [
            ('$MFT', 'Master File Table'),
        ],
    },

    # USN Journal
    'usn_journal': {
        'description': 'USN Change Journal',
        'paths': [
            ('$Extend/$UsnJrnl:$J', 'USN Journal'),
        ],
    },

    # 시스템 정보
    'system_info': {
        'description': 'System Information',
        'paths': [
            ('Windows/System32/config/SYSTEM', 'System config'),
        ],
    },
}


# =============================================================================
# E01 Artifact Collector
# =============================================================================

class E01ArtifactCollector:
    """
    E01 이미지에서 아티팩트 추출

    ForensicDiskAccessor를 사용하여 E01 이미지를 파싱하고
    지정된 아티팩트를 로컬 파일로 추출합니다.
    """

    def __init__(self, e01_path: str, output_dir: str = None):
        """
        Args:
            e01_path: E01 이미지 파일 경로 (첫 번째 세그먼트)
            output_dir: 추출된 아티팩트 저장 디렉토리
        """
        self.e01_path = Path(e01_path)
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / 'e01_extract'
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._accessor = None
        self._selected_partition: Optional[int] = None
        self._partitions: List[PartitionInfo] = []
        self._user_folders: List[str] = []

        self._initialize()

    def _initialize(self):
        """이미지 로드 및 초기화"""
        try:
            from collectors.forensic_disk import ForensicDiskAccessor, FORENSIC_DISK_AVAILABLE

            if not FORENSIC_DISK_AVAILABLE:
                raise ImportError("ForensicDiskAccessor not available")

            self._accessor = ForensicDiskAccessor.from_e01(str(self.e01_path))
            logger.info(f"E01 image loaded: {self.e01_path.name}")

        except ImportError as e:
            logger.error(f"Failed to load ForensicDiskAccessor: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to load E01 image: {e}")
            raise

    def list_partitions(self) -> List[Dict[str, Any]]:
        """
        파티션 목록 조회

        Returns:
            파티션 정보 딕셔너리 목록
        """
        if not self._accessor:
            return []

        try:
            partitions = self._accessor.list_partitions()
            self._partitions = []

            result = []
            for i, p in enumerate(partitions):
                info = PartitionInfo(
                    index=i,
                    offset=getattr(p, 'offset', 0),
                    size=getattr(p, 'size', 0),
                    filesystem=getattr(p, 'filesystem', 'Unknown'),
                    type_name=getattr(p, 'type_name', 'Unknown'),
                    bootable=getattr(p, 'bootable', False),
                )
                self._partitions.append(info)

                result.append({
                    'index': i,
                    'offset': info.offset,
                    'size': info.size,
                    'size_display': self._format_size(info.size),
                    'filesystem': info.filesystem,
                    'type': info.type_name,
                    'bootable': info.bootable,
                })

            logger.info(f"Found {len(result)} partitions")
            return result

        except Exception as e:
            logger.error(f"Failed to list partitions: {e}")
            return []

    def select_partition(self, index: int) -> bool:
        """
        분석할 파티션 선택

        Args:
            index: 파티션 인덱스

        Returns:
            성공 여부
        """
        if not self._accessor:
            return False

        try:
            self._accessor.select_partition(index)
            self._selected_partition = index
            logger.info(f"Selected partition {index}")

            # 사용자 폴더 탐색
            self._discover_user_folders()

            return True

        except Exception as e:
            logger.error(f"Failed to select partition {index}: {e}")
            return False

    def _discover_user_folders(self):
        """사용자 프로필 폴더 탐색"""
        self._user_folders = []

        try:
            users_path = "Users"
            if self._accessor.path_exists(users_path):
                for entry in self._accessor.list_directory(users_path):
                    name = entry.name if hasattr(entry, 'name') else str(entry)
                    # 시스템 폴더 제외
                    if name not in ['All Users', 'Default', 'Default User', 'Public', 'desktop.ini']:
                        self._user_folders.append(name)

            logger.info(f"Found {len(self._user_folders)} user folders")

        except Exception as e:
            logger.debug(f"Failed to discover user folders: {e}")

    def collect(
        self,
        artifact_type: str,
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        아티팩트 수집

        Args:
            artifact_type: 수집할 아티팩트 유형

        Yields:
            (로컬 경로, 메타데이터) 튜플
        """
        if self._selected_partition is None:
            logger.error("No partition selected. Call select_partition() first.")
            return

        if artifact_type not in ARTIFACT_PATHS:
            logger.warning(f"Unknown artifact type: {artifact_type}")
            return

        config = ARTIFACT_PATHS[artifact_type]
        extracted_count = 0

        # 시스템 경로 수집
        if 'paths' in config:
            for path, description in config['paths']:
                for result in self._extract_path(artifact_type, path, description, config.get('pattern')):
                    extracted_count += 1
                    yield result

        # 사용자별 경로 수집
        if 'user_paths' in config:
            for user_folder in self._user_folders:
                for rel_path, description in config['user_paths']:
                    full_path = f"Users/{user_folder}/{rel_path}"
                    for result in self._extract_path(
                        artifact_type,
                        full_path,
                        f"{description} ({user_folder})",
                        config.get('pattern')
                    ):
                        extracted_count += 1
                        yield result

        logger.info(f"Extracted {extracted_count} artifacts for {artifact_type}")

    def _extract_path(
        self,
        artifact_type: str,
        path: str,
        description: str,
        pattern: Optional[str] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        경로에서 파일 추출

        Args:
            artifact_type: 아티팩트 유형
            path: 추출할 경로
            description: 설명
            pattern: 파일 패턴 (디렉토리인 경우)

        Yields:
            (로컬 경로, 메타데이터) 튜플
        """
        try:
            # 경로 존재 확인
            if not self._accessor.path_exists(path):
                logger.debug(f"Path not found: {path}")
                return

            # 디렉토리인 경우
            if self._accessor.is_directory(path):
                for file_path, metadata in self._extract_directory(artifact_type, path, description, pattern):
                    yield file_path, metadata
            else:
                # 단일 파일
                for file_path, metadata in self._extract_file(artifact_type, path, description):
                    yield file_path, metadata

        except Exception as e:
            logger.warning(f"Failed to extract {path}: {e}")

    def _extract_directory(
        self,
        artifact_type: str,
        dir_path: str,
        description: str,
        pattern: Optional[str] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """디렉토리 내 파일 추출"""
        try:
            entries = self._accessor.list_directory(dir_path)

            for entry in entries:
                name = entry.name if hasattr(entry, 'name') else str(entry)

                # 패턴 필터링
                if pattern:
                    import fnmatch
                    if not fnmatch.fnmatch(name.lower(), pattern.lower()):
                        continue

                file_path = f"{dir_path}/{name}"

                if not self._accessor.is_directory(file_path):
                    for result in self._extract_file(artifact_type, file_path, description):
                        yield result

        except Exception as e:
            logger.warning(f"Failed to read directory {dir_path}: {e}")

    def _extract_file(
        self,
        artifact_type: str,
        file_path: str,
        description: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        단일 파일 추출

        Args:
            artifact_type: 아티팩트 유형
            file_path: 파일 경로
            description: 설명

        Yields:
            (로컬 경로, 메타데이터) 튜플
        """
        try:
            # 파일 데이터 읽기
            file_data = self._accessor.read_file(file_path)

            if file_data is None:
                logger.debug(f"Could not read file: {file_path}")
                return

            # 파일명 추출
            filename = Path(file_path).name

            # 로컬 저장 경로
            local_dir = self.output_dir / artifact_type
            local_dir.mkdir(parents=True, exist_ok=True)

            # 충돌 방지를 위한 고유 이름 생성
            local_path = self._get_unique_path(local_dir, filename)

            # 파일 저장
            with open(local_path, 'wb') as f:
                f.write(file_data)

            # 해시 계산
            sha256 = hashlib.sha256(file_data).hexdigest()
            md5 = hashlib.md5(file_data).hexdigest()

            # 파일 메타데이터 가져오기
            file_meta = self._accessor.get_file_metadata(file_path) if hasattr(self._accessor, 'get_file_metadata') else None

            metadata = {
                'artifact_type': artifact_type,
                'original_path': file_path,
                'filename': filename,
                'size': len(file_data),
                'sha256': sha256,
                'md5': md5,
                'description': description,
                'source': 'e01_image',
                'e01_path': str(self.e01_path),
                'partition_index': self._selected_partition,
            }

            # 타임스탬프 추가 (가능한 경우)
            if file_meta:
                if hasattr(file_meta, 'created'):
                    metadata['created'] = file_meta.created
                if hasattr(file_meta, 'modified'):
                    metadata['modified'] = file_meta.modified
                if hasattr(file_meta, 'accessed'):
                    metadata['accessed'] = file_meta.accessed

            logger.debug(f"Extracted: {file_path} -> {local_path}")
            yield str(local_path), metadata

        except Exception as e:
            logger.warning(f"Failed to extract file {file_path}: {e}")

    def _get_unique_path(self, directory: Path, filename: str) -> Path:
        """중복되지 않는 파일 경로 생성"""
        path = directory / filename
        if not path.exists():
            return path

        # 중복 시 번호 추가
        stem = path.stem
        suffix = path.suffix
        counter = 1

        while path.exists():
            path = directory / f"{stem}_{counter}{suffix}"
            counter += 1

        return path

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """크기를 사람이 읽기 쉬운 형태로 변환"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"

    def get_supported_artifact_types(self) -> List[str]:
        """지원하는 아티팩트 유형 목록"""
        return list(ARTIFACT_PATHS.keys())

    def close(self):
        """리소스 해제"""
        if self._accessor and hasattr(self._accessor, 'close'):
            self._accessor.close()
            logger.info("E01 accessor closed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
