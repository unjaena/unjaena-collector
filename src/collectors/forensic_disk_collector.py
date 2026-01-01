# -*- coding: utf-8 -*-
"""
Forensic Disk Collector - 계층화 폴백 수집기

ForensicDiskAccessor를 사용하여 잠긴 파일을 수집하고,
실패 시 MFT → Legacy 순서로 폴백합니다.

수집 우선순위:
1. ForensicDiskAccessor (raw sector access) - 잠긴 파일 직접 읽기
2. MFTCollector (pytsk3) - MFT 기반 수집
3. Legacy (shutil) - 일반 파일 복사

Features:
- Registry hive 직접 읽기 (SYSTEM, SAM, SOFTWARE, SECURITY)
- pagefile.sys 수집 (분석은 서버에서 수행)
- hiberfil.sys 수집 (분석은 서버에서 수행)
- ADS (Alternate Data Streams) 추출
- 삭제된 파일 복구

Note: 이 수집기는 파일 수집만 수행합니다.
      모든 분석 로직은 서버 측에서 처리됩니다.
"""

import os
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Generator, Tuple, Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# Debug output control
_DEBUG_OUTPUT = False
def _debug_print(msg): 
    if _DEBUG_OUTPUT: _debug_print(msg)

# Try to import ForensicDiskAccessor
try:
    from collectors.forensic_disk import (
        ForensicDiskAccessor,
        FORENSIC_DISK_AVAILABLE
    )
except ImportError:
    FORENSIC_DISK_AVAILABLE = False
    ForensicDiskAccessor = None

# Note: Memory analyzers removed from collector
# All analysis must be performed on the server side
# Collector only collects raw files without analysis


# Files that benefit from ForensicDiskAccessor
LOCKED_FILE_PATHS = {
    'registry': [
        '/Windows/System32/config/SYSTEM',
        '/Windows/System32/config/SOFTWARE',
        '/Windows/System32/config/SAM',
        '/Windows/System32/config/SECURITY',
        '/Windows/System32/config/DEFAULT',
    ],
    'amcache': [
        '/Windows/AppCompat/Programs/Amcache.hve',
    ],
    'pagefile': [
        '/pagefile.sys',
    ],
    'hiberfil': [
        '/hiberfil.sys',
    ],
    'srudb': [
        '/Windows/System32/sru/SRUDB.dat',
    ],
}


class ForensicDiskCollector:
    """
    계층화 폴백 포렌식 수집기

    ForensicDiskAccessor → MFTCollector → Legacy 순서로 수집을 시도합니다.

    Usage:
        with ForensicDiskCollector(output_dir, 'C') as collector:
            for path, metadata in collector.collect_registry():
                _debug_print(f"Collected: {path}")
    """

    def __init__(
        self,
        output_dir: str,
        volume: str = 'C',
        use_forensic_disk: bool = True
    ):
        """
        초기화

        Args:
            output_dir: 수집 결과 저장 경로
            volume: 대상 볼륨 (기본: 'C')
            use_forensic_disk: ForensicDiskAccessor 사용 여부
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.volume = volume.upper().rstrip(':')

        # Collection mode tracking
        self.collection_mode = 'legacy'
        self.accessor: Optional[ForensicDiskAccessor] = None

        # Initialize ForensicDiskAccessor if available
        if use_forensic_disk and FORENSIC_DISK_AVAILABLE:
            try:
                # Get physical drive number from volume letter
                drive_number = self._get_physical_drive_number()
                if drive_number is not None:
                    self.accessor = ForensicDiskAccessor.from_physical_disk(drive_number)
                    # Select partition for the volume
                    partition_idx = self._find_partition_for_volume()
                    if partition_idx is not None:
                        self.accessor.select_partition(partition_idx)
                        self.collection_mode = 'forensic_disk_accessor'
                        logger.info(f"ForensicDiskAccessor initialized for {self.volume}:")
            except Exception as e:
                logger.warning(f"ForensicDiskAccessor initialization failed: {e}")
                self.accessor = None

        if self.accessor is None:
            logger.info("Using fallback collection mode")

    def _get_physical_drive_number(self) -> Optional[int]:
        """볼륨 문자에서 물리 드라이브 번호 가져오기"""
        try:
            import ctypes
            from ctypes import wintypes

            # Get volume path
            volume_path = f"\\\\.\\{self.volume}:"

            # Open volume
            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.CreateFileW(
                volume_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )

            if handle == -1:
                # 일반적으로 C: 드라이브는 PhysicalDrive0
                return 0

            try:
                # IOCTL to get disk extents
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000

                class DISK_EXTENT(ctypes.Structure):
                    _fields_ = [
                        ("DiskNumber", wintypes.DWORD),
                        ("StartingOffset", ctypes.c_int64),
                        ("ExtentLength", ctypes.c_int64),
                    ]

                class VOLUME_DISK_EXTENTS(ctypes.Structure):
                    _fields_ = [
                        ("NumberOfDiskExtents", wintypes.DWORD),
                        ("Extents", DISK_EXTENT * 1),
                    ]

                extents = VOLUME_DISK_EXTENTS()
                bytes_returned = wintypes.DWORD()

                result = kernel32.DeviceIoControl(
                    handle,
                    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                    None, 0,
                    ctypes.byref(extents),
                    ctypes.sizeof(extents),
                    ctypes.byref(bytes_returned),
                    None
                )

                if result:
                    return extents.Extents[0].DiskNumber
            finally:
                kernel32.CloseHandle(handle)

            return 0  # Default to drive 0

        except Exception as e:
            logger.warning(f"Failed to get physical drive number: {e}")
            return 0  # Default

    def _find_partition_for_volume(self) -> Optional[int]:
        """볼륨에 해당하는 파티션 인덱스 찾기"""
        if self.accessor is None:
            return None

        try:
            partitions = self.accessor.list_partitions()

            # C: 드라이브는 일반적으로 첫 번째 NTFS 파티션
            for i, part in enumerate(partitions):
                if part.filesystem == 'NTFS':
                    # 기본적으로 첫 번째 NTFS 파티션 선택
                    # 더 정확한 매칭은 볼륨 시리얼 번호 비교 필요
                    return i

            # NTFS가 없으면 첫 번째 파티션
            if partitions:
                return 0

        except Exception as e:
            logger.warning(f"Failed to find partition: {e}")

        return 0

    def close(self):
        """리소스 정리"""
        if self.accessor:
            try:
                self.accessor.close()
            except:
                pass
            self.accessor = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def read_locked_file(self, path: str, max_size: int = None) -> Optional[bytes]:
        """
        잠긴 파일 읽기

        Args:
            path: 파일 경로 (예: '/Windows/System32/config/SYSTEM')
            max_size: 최대 읽기 크기

        Returns:
            파일 내용 (bytes) 또는 None
        """
        if self.accessor is None:
            return None

        try:
            return self.accessor.read_file(path, max_size=max_size)
        except Exception as e:
            logger.warning(f"Failed to read locked file {path}: {e}")
            return None

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        아티팩트 타입별 수집

        Args:
            artifact_type: 'registry', 'pagefile', 'hiberfil', 'srudb', 'amcache'
            progress_callback: 진행률 콜백

        Yields:
            (저장 경로, 메타데이터) 튜플
        """
        if artifact_type == 'registry':
            yield from self.collect_registry(progress_callback)
        elif artifact_type == 'pagefile':
            yield from self.collect_pagefile(progress_callback)
        elif artifact_type == 'hiberfil':
            yield from self.collect_hiberfil(progress_callback)
        elif artifact_type == 'amcache':
            yield from self.collect_amcache(progress_callback)
        elif artifact_type == 'srudb':
            yield from self.collect_srudb(progress_callback)
        else:
            logger.warning(f"Unknown artifact type: {artifact_type}")

    def collect_registry(
        self,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Registry hive 수집

        Yields:
            (저장 경로, 메타데이터) 튜플
        """
        registry_dir = self.output_dir / 'registry'
        registry_dir.mkdir(exist_ok=True)

        paths = LOCKED_FILE_PATHS['registry']
        total = len(paths)

        for i, path in enumerate(paths):
            if progress_callback:
                progress_callback(i + 1, total, f"Collecting {Path(path).name}")

            filename = Path(path).name
            dst_path = registry_dir / filename

            try:
                if self.accessor:
                    # ForensicDiskAccessor로 직접 읽기
                    data = self.accessor.read_file(path)
                    if data:
                        dst_path.write_bytes(data)
                        metadata = self._create_metadata(path, dst_path, 'registry', data)
                        metadata['collection_method'] = 'forensic_disk_accessor'
                        yield str(dst_path), metadata
                        continue
            except Exception as e:
                logger.warning(f"ForensicDiskAccessor failed for {path}: {e}")

            # Fallback: 일반 파일 복사 시도
            win_path = f"{self.volume}:{path.replace('/', os.sep)}"
            if Path(win_path).exists():
                try:
                    import shutil
                    shutil.copy2(win_path, dst_path)
                    metadata = self._create_metadata(path, dst_path, 'registry')
                    metadata['collection_method'] = 'legacy'
                    yield str(dst_path), metadata
                except (PermissionError, OSError) as e:
                    logger.warning(f"Legacy copy failed for {path}: {e}")

    def collect_pagefile(
        self,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        pagefile.sys 수집

        Yields:
            (저장 경로, 메타데이터) 튜플
        """
        pagefile_dir = self.output_dir / 'pagefile'
        pagefile_dir.mkdir(exist_ok=True)

        path = '/pagefile.sys'
        dst_path = pagefile_dir / 'pagefile.sys'

        if progress_callback:
            progress_callback(1, 1, "Collecting pagefile.sys")

        try:
            if self.accessor:
                # 스트리밍으로 대용량 파일 수집
                with open(dst_path, 'wb') as f:
                    for chunk in self.accessor.stream_file(path, chunk_size=64*1024*1024):
                        f.write(chunk)

                metadata = self._create_metadata(path, dst_path, 'pagefile')
                metadata['collection_method'] = 'forensic_disk_accessor'
                yield str(dst_path), metadata
                # Note: Analysis removed - performed on server side

        except Exception as e:
            logger.error(f"Failed to collect pagefile.sys: {e}")

    def collect_hiberfil(
        self,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        hiberfil.sys 수집 (하이버네이션 파일)

        Yields:
            (저장 경로, 메타데이터) 튜플
        """
        hiberfil_dir = self.output_dir / 'hiberfil'
        hiberfil_dir.mkdir(exist_ok=True)

        path = '/hiberfil.sys'
        dst_path = hiberfil_dir / 'hiberfil.sys'

        if progress_callback:
            progress_callback(1, 1, "Collecting hiberfil.sys")

        try:
            if self.accessor:
                with open(dst_path, 'wb') as f:
                    for chunk in self.accessor.stream_file(path, chunk_size=64*1024*1024):
                        f.write(chunk)

                metadata = self._create_metadata(path, dst_path, 'hiberfil')
                metadata['collection_method'] = 'forensic_disk_accessor'
                yield str(dst_path), metadata
                # Note: Analysis removed - performed on server side

        except Exception as e:
            logger.error(f"Failed to collect hiberfil.sys: {e}")

    def collect_amcache(
        self,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Amcache.hve 수집

        Yields:
            (저장 경로, 메타데이터) 튜플
        """
        amcache_dir = self.output_dir / 'amcache'
        amcache_dir.mkdir(exist_ok=True)

        path = '/Windows/AppCompat/Programs/Amcache.hve'
        dst_path = amcache_dir / 'Amcache.hve'

        if progress_callback:
            progress_callback(1, 1, "Collecting Amcache.hve")

        try:
            if self.accessor:
                data = self.accessor.read_file(path)
                if data:
                    dst_path.write_bytes(data)
                    metadata = self._create_metadata(path, dst_path, 'amcache', data)
                    metadata['collection_method'] = 'forensic_disk_accessor'
                    yield str(dst_path), metadata
                    return
        except Exception as e:
            logger.warning(f"ForensicDiskAccessor failed for Amcache: {e}")

        # Fallback
        win_path = f"{self.volume}:{path.replace('/', os.sep)}"
        if Path(win_path).exists():
            try:
                import shutil
                shutil.copy2(win_path, dst_path)
                metadata = self._create_metadata(path, dst_path, 'amcache')
                metadata['collection_method'] = 'legacy'
                yield str(dst_path), metadata
            except (PermissionError, OSError) as e:
                logger.warning(f"Legacy copy failed for Amcache: {e}")

    def collect_srudb(
        self,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        SRUDB.dat 수집 (System Resource Usage Monitor)

        Yields:
            (저장 경로, 메타데이터) 튜플
        """
        srudb_dir = self.output_dir / 'srudb'
        srudb_dir.mkdir(exist_ok=True)

        path = '/Windows/System32/sru/SRUDB.dat'
        dst_path = srudb_dir / 'SRUDB.dat'

        if progress_callback:
            progress_callback(1, 1, "Collecting SRUDB.dat")

        try:
            if self.accessor:
                data = self.accessor.read_file(path)
                if data:
                    dst_path.write_bytes(data)
                    metadata = self._create_metadata(path, dst_path, 'srudb', data)
                    metadata['collection_method'] = 'forensic_disk_accessor'
                    yield str(dst_path), metadata
                    return
        except Exception as e:
            logger.warning(f"ForensicDiskAccessor failed for SRUDB: {e}")

        # Fallback
        win_path = f"{self.volume}:{path.replace('/', os.sep)}"
        if Path(win_path).exists():
            try:
                import shutil
                shutil.copy2(win_path, dst_path)
                metadata = self._create_metadata(path, dst_path, 'srudb')
                metadata['collection_method'] = 'legacy'
                yield str(dst_path), metadata
            except (PermissionError, OSError) as e:
                logger.warning(f"Legacy copy failed for SRUDB: {e}")

    def collect_ads(
        self,
        file_path: str,
        stream_name: str = 'Zone.Identifier'
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        ADS (Alternate Data Stream) 수집

        Args:
            file_path: 파일 경로
            stream_name: ADS 스트림 이름 (기본: Zone.Identifier)

        Returns:
            (저장 경로, 메타데이터) 튜플 또는 None
        """
        if self.accessor is None:
            return None

        try:
            # 파일의 MFT entry 찾기
            normalized_path = file_path.replace('\\', '/')
            if not normalized_path.startswith('/'):
                # C:\path\file → /path/file
                if ':' in normalized_path:
                    normalized_path = '/' + normalized_path.split(':', 1)[1]

            # ADS 읽기
            inode = self.accessor._resolve_path_to_inode(normalized_path)
            if inode is None:
                return None

            ads_data = self.accessor.read_file_by_inode(inode, stream_name=stream_name)
            if ads_data:
                filename = Path(file_path).name
                dst_path = self.output_dir / 'ads' / f"{filename}_{stream_name}"
                dst_path.parent.mkdir(exist_ok=True)
                dst_path.write_bytes(ads_data)

                metadata = {
                    'original_file': file_path,
                    'stream_name': stream_name,
                    'size': len(ads_data),
                    'artifact_type': 'ads',
                    'collection_method': 'forensic_disk_accessor',
                    'collection_time': datetime.now().isoformat(),
                }
                return str(dst_path), metadata

        except Exception as e:
            logger.warning(f"Failed to collect ADS {stream_name} from {file_path}: {e}")

        return None

    def _create_metadata(
        self,
        original_path: str,
        dst_path: Path,
        artifact_type: str,
        data: bytes = None
    ) -> Dict[str, Any]:
        """메타데이터 생성"""
        metadata = {
            'original_path': original_path,
            'artifact_type': artifact_type,
            'collection_time': datetime.now().isoformat(),
            'volume': self.volume,
        }

        if dst_path.exists():
            stat = dst_path.stat()
            metadata['size'] = stat.st_size
            metadata['modified_time'] = datetime.fromtimestamp(stat.st_mtime).isoformat()

            # Hash 계산
            if data:
                metadata['md5'] = hashlib.md5(data).hexdigest()
                metadata['sha256'] = hashlib.sha256(data).hexdigest()
            else:
                with open(dst_path, 'rb') as f:
                    content = f.read()
                    metadata['md5'] = hashlib.md5(content).hexdigest()
                    metadata['sha256'] = hashlib.sha256(content).hexdigest()

        return metadata


# Module-level availability check
def is_forensic_disk_available() -> bool:
    """ForensicDiskAccessor 사용 가능 여부"""
    return FORENSIC_DISK_AVAILABLE


# Note: is_memory_analyzer_available() removed
# Analysis is performed on server side only
