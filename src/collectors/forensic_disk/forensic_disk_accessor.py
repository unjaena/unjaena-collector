# -*- coding: utf-8 -*-
"""
Forensic Disk Accessor - 통합 포렌식 디스크 접근 API

로컬 물리 디스크와 E01/RAW 이미지를 동일한 인터페이스로 접근합니다.
Windows 파일시스템을 완전히 우회하여 잠긴 파일도 읽을 수 있습니다.

Features:
- 물리 디스크 (\\\\.\\PhysicalDrive{N}) 접근
- E01/EWF 포렌식 이미지 접근
- RAW/DD 이미지 파일 접근
- 파티션 자동 탐지 (MBR/GPT)
- 파일시스템 자동 감지 (NTFS, FAT32, exFAT)
- MFT/FAT 기반 파일 읽기
- 삭제된 파일 복구
- ADS (Alternate Data Streams) 지원

Usage:
    from core.engine.collectors.filesystem.forensic_disk_accessor import ForensicDiskAccessor

    # 물리 디스크 접근
    with ForensicDiskAccessor.from_physical_disk(0) as disk:
        disk.select_partition(0)  # C:
        data = disk.read_file("/Windows/System32/config/SYSTEM")

    # E01 이미지 접근
    with ForensicDiskAccessor.from_e01("evidence.E01") as disk:
        disk.select_partition(0)
        for chunk in disk.stream_file("/pagefile.sys"):
            analyze(chunk)

    # 삭제된 파일 포함 전체 스캔
    catalog = disk.scan_all_files(include_deleted=True)
"""

import struct
import logging
from typing import Optional, List, Dict, Generator, Any, Union, Tuple
from pathlib import Path
from dataclasses import dataclass

from .unified_disk_reader import (
    UnifiedDiskReader,
    DiskInfo,
    PartitionInfo,
    DiskSourceType,
    DiskError,
    DiskNotFoundError,
    PartitionError,
    FilesystemError
)
from .disk_backends import (
    PhysicalDiskBackend,
    E01DiskBackend,
    RAWImageBackend,
    create_disk_backend
)
from .file_content_extractor import FileContentExtractor, FileMetadata, DataRun

logger = logging.getLogger(__name__)


# ==============================================================================
# Partition Table Parsing
# ==============================================================================

class PartitionTableType:
    """파티션 테이블 타입"""
    MBR = "mbr"
    GPT = "gpt"
    UNKNOWN = "unknown"


# GPT 파티션 타입 GUID (주요 타입만)
GPT_TYPE_GUIDS = {
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft Reserved",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Basic Data (NTFS/FAT)",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows Recovery",
    "AF9B60A0-1431-4F62-BC68-3311714A69AD": "LDM Metadata",
    "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": "LDM Data",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux Filesystem",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux RAID",
    "933AC7E1-2EB4-4F13-B844-0E14E2AEF915": "Linux home",
}

# MBR 파티션 타입
MBR_PARTITION_TYPES = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16 <32MB",
    0x05: "Extended",
    0x06: "FAT16",
    0x07: "NTFS/HPFS",
    0x0B: "FAT32 CHS",
    0x0C: "FAT32 LBA",
    0x0E: "FAT16 LBA",
    0x0F: "Extended LBA",
    0x11: "Hidden FAT12",
    0x14: "Hidden FAT16 <32MB",
    0x16: "Hidden FAT16",
    0x17: "Hidden NTFS",
    0x1B: "Hidden FAT32",
    0x1C: "Hidden FAT32 LBA",
    0x1E: "Hidden FAT16 LBA",
    0x27: "Windows RE",
    0x82: "Linux swap",
    0x83: "Linux",
    0x85: "Linux Extended",
    0x8E: "Linux LVM",
    0xEE: "GPT Protective",
    0xEF: "EFI System",
    0xFD: "Linux RAID",
}


@dataclass
class FileCatalogEntry:
    """파일 카탈로그 엔트리"""
    inode: int
    filename: str
    full_path: str = ""
    size: int = 0
    is_directory: bool = False
    is_deleted: bool = False
    parent_inode: int = 0
    created_time: int = 0
    modified_time: int = 0
    has_data_runs: bool = False
    ads_streams: List[str] = None

    def __post_init__(self):
        if self.ads_streams is None:
            self.ads_streams = []

    @property
    def name(self) -> str:
        """filename 별칭 (호환성)"""
        return self.filename


# ==============================================================================
# Forensic Disk Accessor
# ==============================================================================

class ForensicDiskAccessor:
    """
    통합 포렌식 디스크 접근 API

    로컬 디스크와 E01 이미지를 동일한 인터페이스로 접근합니다.
    Windows 파일시스템을 우회하여 raw sector 기반으로 파일을 읽습니다.

    Usage:
        # Factory methods
        disk = ForensicDiskAccessor.from_physical_disk(0)
        disk = ForensicDiskAccessor.from_e01("evidence.E01")
        disk = ForensicDiskAccessor.from_raw("disk.dd")

        # Partition selection
        partitions = disk.list_partitions()
        disk.select_partition(0)

        # File operations
        data = disk.read_file("/Windows/System32/config/SYSTEM")
        zone_id = disk.read_file_by_inode(12345, stream_name="Zone.Identifier")

        # Scan all files
        catalog = disk.scan_all_files(include_deleted=True)
    """

    def __init__(self, backend: UnifiedDiskReader):
        """
        Args:
            backend: UnifiedDiskReader 구현체
        """
        self._backend = backend
        self._partitions: List[PartitionInfo] = []
        self._partition_table_type: str = PartitionTableType.UNKNOWN
        self._selected_partition: Optional[int] = None
        self._extractor: Optional[FileContentExtractor] = None

        # MFT 인덱스 캐시 (경로 → inode)
        self._path_cache: Dict[str, int] = {}

        # MFT 부모-자식 인덱스 캐시 (parent_inode → [child_inodes])
        self._parent_child_index: Dict[int, List[int]] = {}
        self._parent_index_built: bool = False

        # 파일명 맵 캐시 ((parent_inode, lowercase_name) → inode)
        self._name_to_inode_map: Dict[tuple, int] = {}

        # 파티션 탐지
        self._detect_partitions()

    # ==========================================================================
    # Factory Methods
    # ==========================================================================

    @classmethod
    def from_physical_disk(cls, drive_number: int) -> 'ForensicDiskAccessor':
        """
        물리 디스크에서 접근자 생성

        Args:
            drive_number: 드라이브 번호 (0, 1, 2, ...)

        Returns:
            ForensicDiskAccessor 인스턴스

        Raises:
            DiskNotFoundError: 드라이브를 찾을 수 없음
            DiskPermissionError: 관리자 권한 필요
        """
        backend = PhysicalDiskBackend(drive_number)
        return cls(backend)

    @classmethod
    def from_e01(cls, e01_path: str) -> 'ForensicDiskAccessor':
        """
        E01 이미지에서 접근자 생성

        Args:
            e01_path: E01 파일 경로 (.E01, .E02, ... 자동 탐지)

        Returns:
            ForensicDiskAccessor 인스턴스

        Raises:
            DiskNotFoundError: 파일을 찾을 수 없음
        """
        backend = E01DiskBackend(e01_path)
        return cls(backend)

    @classmethod
    def from_raw(cls, raw_path: str) -> 'ForensicDiskAccessor':
        """
        RAW/DD 이미지에서 접근자 생성

        Args:
            raw_path: RAW 이미지 파일 경로

        Returns:
            ForensicDiskAccessor 인스턴스
        """
        backend = RAWImageBackend(raw_path)
        return cls(backend)

    @classmethod
    def auto_detect(cls, source: str) -> 'ForensicDiskAccessor':
        """
        소스 타입 자동 감지하여 접근자 생성

        Args:
            source: 디스크 번호(숫자) 또는 이미지 파일 경로

        Returns:
            ForensicDiskAccessor 인스턴스
        """
        backend = create_disk_backend(source)
        return cls(backend)

    # ==========================================================================
    # Partition Management
    # ==========================================================================

    def _detect_partitions(self):
        """파티션 테이블 탐지 (MBR/GPT)"""
        # MBR 읽기
        mbr = self._backend.read(0, 512)

        # MBR 시그니처 확인
        if mbr[510:512] != b'\x55\xAA':
            logger.warning("Invalid MBR signature")
            return

        # GPT 확인 (Protective MBR의 파티션 타입 0xEE)
        if mbr[450] == 0xEE:
            self._partition_table_type = PartitionTableType.GPT
            self._parse_gpt()
        else:
            self._partition_table_type = PartitionTableType.MBR
            self._parse_mbr(mbr)

        logger.info(f"Detected {self._partition_table_type.upper()} with {len(self._partitions)} partition(s)")

    def _parse_mbr(self, mbr: bytes):
        """MBR 파티션 테이블 파싱"""
        sector_size = 512

        for i in range(4):
            entry_offset = 446 + (i * 16)
            entry = mbr[entry_offset:entry_offset + 16]

            # 파티션 타입
            partition_type = entry[4]

            if partition_type == 0:
                continue

            # LBA 시작 및 섹터 수
            lba_start = struct.unpack('<I', entry[8:12])[0]
            sector_count = struct.unpack('<I', entry[12:16])[0]

            if lba_start == 0 or sector_count == 0:
                continue

            # 부팅 플래그
            bootable = entry[0] == 0x80

            # 파일시스템 감지
            fs_type = self._detect_filesystem(lba_start * sector_size)

            partition = PartitionInfo(
                index=i,
                partition_type=partition_type,
                type_name=MBR_PARTITION_TYPES.get(partition_type, f"Unknown (0x{partition_type:02X})"),
                offset=lba_start * sector_size,
                size=sector_count * sector_size,
                lba_start=lba_start,
                sector_count=sector_count,
                filesystem=fs_type,
                is_bootable=bootable
            )

            self._partitions.append(partition)

    def _parse_gpt(self):
        """GPT 파티션 테이블 파싱"""
        sector_size = 512

        # GPT 헤더 읽기 (LBA 1)
        gpt_header = self._backend.read(sector_size, sector_size)

        if gpt_header[:8] != b'EFI PART':
            logger.warning("Invalid GPT signature")
            return

        # 파티션 엔트리 정보
        partition_entry_lba = struct.unpack('<Q', gpt_header[72:80])[0]
        partition_entry_count = struct.unpack('<I', gpt_header[80:84])[0]
        partition_entry_size = struct.unpack('<I', gpt_header[84:88])[0]

        # 파티션 엔트리 읽기
        entries_per_sector = sector_size // partition_entry_size
        entry_index = 0

        for sector_offset in range(0, (partition_entry_count + entries_per_sector - 1) // entries_per_sector):
            sector_data = self._backend.read((partition_entry_lba + sector_offset) * sector_size, sector_size)

            for i in range(entries_per_sector):
                if entry_index >= partition_entry_count:
                    break

                entry_offset = i * partition_entry_size
                entry = sector_data[entry_offset:entry_offset + partition_entry_size]

                # 타입 GUID (빈 파티션은 모두 0)
                type_guid_raw = entry[0:16]
                if type_guid_raw == b'\x00' * 16:
                    entry_index += 1
                    continue

                # GUID를 문자열로 변환
                type_guid = self._bytes_to_guid(type_guid_raw)

                # LBA 시작/끝
                lba_start = struct.unpack('<Q', entry[32:40])[0]
                lba_end = struct.unpack('<Q', entry[40:48])[0]

                # 파티션 이름 (UTF-16LE)
                name_bytes = entry[56:128]
                try:
                    name = name_bytes.decode('utf-16-le').rstrip('\x00')
                except:
                    name = ""

                # 파일시스템 감지
                fs_type = self._detect_filesystem(lba_start * sector_size)

                partition = PartitionInfo(
                    index=entry_index,
                    partition_type=0,
                    type_guid=type_guid,
                    type_name=GPT_TYPE_GUIDS.get(type_guid.upper(), f"Unknown ({type_guid})"),
                    offset=lba_start * sector_size,
                    size=(lba_end - lba_start + 1) * sector_size,
                    lba_start=lba_start,
                    sector_count=lba_end - lba_start + 1,
                    filesystem=fs_type,
                    name=name
                )

                self._partitions.append(partition)
                entry_index += 1

    def _bytes_to_guid(self, data: bytes) -> str:
        """바이트를 GUID 문자열로 변환"""
        # GUID는 little-endian으로 저장됨
        part1 = struct.unpack('<I', data[0:4])[0]
        part2 = struct.unpack('<H', data[4:6])[0]
        part3 = struct.unpack('<H', data[6:8])[0]
        part4 = data[8:10].hex().upper()
        part5 = data[10:16].hex().upper()

        return f"{part1:08X}-{part2:04X}-{part3:04X}-{part4}-{part5}"

    def _detect_filesystem(self, partition_offset: int) -> str:
        """파일시스템 타입 감지"""
        try:
            vbr = self._backend.read(partition_offset, 512)

            # NTFS
            if vbr[3:11] == b'NTFS    ':
                return 'NTFS'

            # BitLocker
            if vbr[3:11] == b'-FVE-FS-':
                return 'BitLocker'

            # exFAT
            if vbr[3:11] == b'EXFAT   ':
                return 'exFAT'

            # FAT32
            if vbr[82:90] == b'FAT32   ':
                return 'FAT32'

            # FAT16
            if vbr[54:62] == b'FAT16   ':
                return 'FAT16'

            # FAT12
            if vbr[54:62] == b'FAT12   ':
                return 'FAT12'

            # ext2/3/4 (superblock at offset 1024)
            sb = self._backend.read(partition_offset + 1024, 100)
            if struct.unpack('<H', sb[56:58])[0] == 0xEF53:
                return 'ext4'

        except Exception as e:
            logger.debug(f"Filesystem detection failed: {e}")

        return "Unknown"

    def list_partitions(self) -> List[PartitionInfo]:
        """
        파티션 목록 반환

        Returns:
            PartitionInfo 리스트
        """
        return self._partitions.copy()

    def select_partition(self, index: int) -> None:
        """
        파티션 선택

        Args:
            index: 파티션 인덱스 (list_partitions의 순서)

        Raises:
            PartitionError: 잘못된 인덱스
            FilesystemError: BitLocker 암호화 파티션
        """
        if index < 0 or index >= len(self._partitions):
            raise PartitionError(f"Invalid partition index: {index}")

        partition = self._partitions[index]
        self._selected_partition = index

        # BitLocker 암호화 파티션 경고
        if partition.filesystem == 'BitLocker':
            from .unified_disk_reader import BitLockerError
            raise BitLockerError(
                f"Partition {index} is BitLocker encrypted. "
                f"Raw disk access cannot read encrypted data. "
                f"Use BitLocker unlock key or mount the volume first."
            )

        # FileContentExtractor 생성
        if partition.filesystem in ('NTFS', 'FAT32', 'FAT16', 'FAT12', 'exFAT'):
            self._extractor = FileContentExtractor(
                disk=self._backend,
                partition_offset=partition.offset,
                fs_type=partition.filesystem
            )
            logger.info(f"Selected partition {index}: {partition.filesystem} at offset {partition.offset}")
        else:
            self._extractor = None
            logger.warning(f"Unsupported filesystem: {partition.filesystem}")

        # 캐시 초기화
        self._path_cache.clear()

    def find_windows_partition(self) -> Optional[int]:
        """
        Windows 시스템 파티션 찾기 (BitLocker 제외)

        Recovery 파티션과 BitLocker 암호화 파티션을 제외하고
        Windows가 설치된 NTFS 파티션을 찾습니다.

        Returns:
            파티션 인덱스 또는 None

        Note:
            - BitLocker 암호화 파티션은 건너뜁니다
            - Recovery 파티션 (< 50GB)은 건너뜁니다
            - 가장 큰 NTFS 파티션을 반환합니다
        """
        candidates = []

        for i, p in enumerate(self._partitions):
            # BitLocker 제외
            if p.filesystem == 'BitLocker':
                logger.info(f"Partition {i}: BitLocker encrypted - skipping")
                continue

            # NTFS만 고려
            if p.filesystem != 'NTFS':
                continue

            # Recovery 파티션 제외 (보통 50GB 미만)
            size_gb = p.size / (1024 * 1024 * 1024)
            if size_gb < 50:
                # Recovery 여부 확인
                if 'Recovery' in p.name or 'recovery' in p.type_name.lower():
                    logger.info(f"Partition {i}: Recovery partition - skipping")
                    continue

            candidates.append((i, p.size))

        if not candidates:
            logger.warning("No suitable Windows partition found")
            return None

        # 가장 큰 파티션 선택
        candidates.sort(key=lambda x: x[1], reverse=True)
        best_idx = candidates[0][0]

        logger.info(f"Found Windows partition at index {best_idx}")
        return best_idx

    def has_bitlocker_partitions(self) -> bool:
        """BitLocker 암호화 파티션 존재 여부"""
        return any(p.filesystem == 'BitLocker' for p in self._partitions)

    def get_selected_partition(self) -> Optional[PartitionInfo]:
        """선택된 파티션 정보 반환"""
        if self._selected_partition is None:
            return None
        return self._partitions[self._selected_partition]

    # ==========================================================================
    # File Operations
    # ==========================================================================

    def read_file(self, path: str, max_size: int = None) -> bytes:
        """
        경로로 파일 읽기

        Args:
            path: 파일 경로 (예: "/Windows/System32/config/SYSTEM")
            max_size: 최대 읽기 크기

        Returns:
            파일 내용 (bytes)

        Raises:
            FilesystemError: 파일을 찾을 수 없음
        """
        if self._extractor is None:
            raise FilesystemError("No partition selected or unsupported filesystem")

        # 경로 정규화
        path = self._normalize_path(path)

        # 캐시에서 inode 찾기
        if path in self._path_cache:
            return self._extractor.read_file_by_inode(self._path_cache[path], max_size=max_size)

        # MFT에서 파일 찾기
        inode = self._resolve_path_to_inode(path)
        if inode is None:
            raise FilesystemError(f"File not found: {path}")

        self._path_cache[path] = inode
        return self._extractor.read_file_by_inode(inode, max_size=max_size)

    def read_file_by_inode(
        self,
        inode: int,
        stream_name: str = None,
        max_size: int = None
    ) -> bytes:
        """
        MFT entry 번호로 파일 읽기

        Args:
            inode: MFT entry 번호
            stream_name: ADS 이름 (예: "Zone.Identifier")
            max_size: 최대 읽기 크기

        Returns:
            파일 내용 (bytes)
        """
        if self._extractor is None:
            raise FilesystemError("No partition selected or unsupported filesystem")

        return self._extractor.read_file_by_inode(inode, stream_name=stream_name, max_size=max_size)

    def stream_file(
        self,
        path: str,
        chunk_size: int = 64 * 1024 * 1024
    ) -> Generator[bytes, None, None]:
        """
        대용량 파일 스트리밍

        Args:
            path: 파일 경로
            chunk_size: 청크 크기 (기본 64MB)

        Yields:
            파일 데이터 청크
        """
        if self._extractor is None:
            raise FilesystemError("No partition selected")

        path = self._normalize_path(path)
        inode = self._resolve_path_to_inode(path)

        if inode is None:
            raise FilesystemError(f"File not found: {path}")

        yield from self._extractor.stream_file_by_inode(inode, chunk_size=chunk_size)

    def stream_file_by_inode(
        self,
        inode: int,
        stream_name: str = None,
        chunk_size: int = 64 * 1024 * 1024
    ) -> Generator[bytes, None, None]:
        """
        MFT entry로 대용량 파일 스트리밍

        Args:
            inode: MFT entry 번호
            stream_name: ADS 이름
            chunk_size: 청크 크기

        Yields:
            파일 데이터 청크
        """
        if self._extractor is None:
            raise FilesystemError("No partition selected")

        yield from self._extractor.stream_file_by_inode(inode, stream_name, chunk_size)

    def get_file_metadata(self, inode: int) -> FileMetadata:
        """
        파일 메타데이터 조회

        Args:
            inode: MFT entry 번호

        Returns:
            FileMetadata 객체
        """
        if self._extractor is None:
            raise FilesystemError("No partition selected")

        return self._extractor.get_file_metadata(inode)

    def list_ads_streams(self, inode: int) -> List[str]:
        """
        파일의 ADS 목록 조회

        Args:
            inode: MFT entry 번호

        Returns:
            ADS 이름 리스트 (예: ["Zone.Identifier", "encryptable"])
        """
        if self._extractor is None:
            raise FilesystemError("No partition selected")

        return self._extractor.list_ads_streams(inode)

    def path_exists(self, path: str) -> bool:
        """
        경로 존재 여부 확인

        Args:
            path: 파일/디렉토리 경로

        Returns:
            존재 여부
        """
        if self._extractor is None:
            return False

        try:
            path = self._normalize_path(path)
            inode = self._resolve_path_to_inode(path)
            return inode is not None
        except Exception:
            return False

    def is_directory(self, path: str) -> bool:
        """
        경로가 디렉토리인지 확인

        Args:
            path: 경로

        Returns:
            디렉토리 여부
        """
        if self._extractor is None:
            return False

        try:
            path = self._normalize_path(path)
            inode = self._resolve_path_to_inode(path)
            if inode is None:
                return False

            metadata = self._extractor.get_file_metadata(inode)
            return metadata.is_directory
        except Exception:
            return False

    def _get_mft_entry_count(self) -> int:
        """
        MFT 전체 엔트리 수 추정

        $MFT 파일 크기를 기반으로 전체 엔트리 수를 계산합니다.
        """
        try:
            # $MFT 메타데이터에서 크기 가져오기
            mft_metadata = self._extractor.get_file_metadata(0)
            if mft_metadata and mft_metadata.size > 0:
                # MFT 엔트리 크기는 일반적으로 1024 바이트
                entry_count = mft_metadata.size // 1024
                logger.debug(f"MFT size: {mft_metadata.size} bytes, estimated entries: {entry_count}")
                return entry_count
        except Exception as e:
            logger.debug(f"Failed to get MFT size: {e}")

        # 기본값: 500만 엔트리 (대용량 이미지 지원)
        return 5000000

    def _build_parent_index(self) -> None:
        """
        MFT 부모-자식 인덱스 구축 (최초 1회만 실행)

        MFT 전체를 순회하여 parent_inode → [child_inodes] 맵을 생성합니다.
        이후 list_directory() 호출 시 O(1)로 자식을 조회할 수 있습니다.

        또한 파일명 → inode 맵도 구축하여 대소문자 무관 검색을 지원합니다.

        디지털 포렌식 원칙:
        - MFT 엔트리 수 제한 없음 (동적으로 전체 크기 감지)
        - 삭제되지 않은 파일만 인덱싱 (list_directory 용)
        """
        if self._parent_index_built or self._extractor is None:
            return

        logger.info("Building MFT parent-child index (this may take a moment)...")
        self._parent_child_index = {}
        self._name_to_inode_map = {}  # (parent_inode, lowercase_name) -> inode

        try:
            # MFT 전체 순회 - 동적 크기 감지 (제한 없음)
            max_entries = self._get_mft_entry_count()
            logger.info(f"MFT index building: scanning up to {max_entries:,} entries")
            consecutive_errors = 0
            max_consecutive_errors = 1000
            indexed_count = 0

            for entry_num in range(0, max_entries):
                try:
                    entry_data = self._extractor.read_mft_entry(entry_num)

                    # 유효하지 않은 엔트리 건너뛰기
                    if entry_data[:4] != b'FILE':
                        consecutive_errors += 1
                        if consecutive_errors > max_consecutive_errors:
                            logger.debug(f"Stopping index build at entry {entry_num} due to consecutive errors")
                            break
                        continue

                    consecutive_errors = 0
                    metadata = self._extractor.get_file_metadata(entry_num)

                    # 삭제되지 않은 항목만 인덱스에 추가
                    if not metadata.is_deleted:
                        parent = metadata.parent_ref
                        if parent not in self._parent_child_index:
                            self._parent_child_index[parent] = []
                        self._parent_child_index[parent].append(entry_num)

                        # 파일명 맵에 추가 (대소문자 무관 검색용)
                        key = (parent, metadata.filename.lower())
                        self._name_to_inode_map[key] = entry_num
                        indexed_count += 1

                except Exception:
                    consecutive_errors += 1
                    if consecutive_errors > max_consecutive_errors:
                        break
                    continue

            self._parent_index_built = True
            logger.info(f"MFT parent-child index built: {len(self._parent_child_index)} parent directories, {indexed_count} files indexed")

        except Exception as e:
            logger.warning(f"Failed to build parent index: {e}")
            self._parent_child_index = {}
            self._name_to_inode_map = {}

    def list_directory(self, path: str) -> List[FileCatalogEntry]:
        """
        디렉토리 내용 조회 (인덱스 기반 O(1) 조회)

        Args:
            path: 디렉토리 경로

        Returns:
            FileCatalogEntry 리스트
        """
        if self._extractor is None:
            return []

        try:
            path = self._normalize_path(path)
            dir_inode = self._resolve_path_to_inode(path)
            if dir_inode is None:
                return []

            # 부모-자식 인덱스가 없으면 구축 (최초 1회)
            if not self._parent_index_built:
                self._build_parent_index()

            # 인덱스에서 자식 inode 목록 조회 (O(1))
            child_inodes = self._parent_child_index.get(dir_inode, [])

            results = []
            for entry_num in child_inodes:
                try:
                    metadata = self._extractor.get_file_metadata(entry_num)

                    # 삭제되지 않은 항목만 추가
                    if not metadata.is_deleted:
                        results.append(FileCatalogEntry(
                            inode=entry_num,
                            filename=metadata.filename,
                            full_path=f"{path}/{metadata.filename}",
                            size=metadata.size,
                            is_directory=metadata.is_directory,
                            is_deleted=metadata.is_deleted,
                            parent_inode=metadata.parent_ref,
                            created_time=metadata.created_time,
                            modified_time=metadata.modified_time,
                            has_data_runs=len(metadata.data_runs) > 0 or metadata.is_resident
                        ))
                except Exception:
                    continue

            return results
        except Exception as e:
            logger.debug(f"Failed to list directory {path}: {e}")
            return []

    # ==========================================================================
    # File System Scanning
    # ==========================================================================

    def scan_all_files(
        self,
        include_deleted: bool = True,
        max_entries: int = None,
        progress_callback=None
    ) -> Dict[str, Any]:
        """
        MFT 전체 스캔 (삭제된 파일 포함)

        디지털 포렌식 원칙:
        - include_deleted=True (기본): 삭제 파일 포함
        - max_entries=None (기본): 제한 없음, MFT 전체 스캔

        Args:
            include_deleted: 삭제된 파일 포함 여부 (기본: True)
            max_entries: 최대 스캔할 엔트리 수 (기본: None=제한없음)
            progress_callback: 진행률 콜백 (current, total)

        Returns:
            {
                'total_entries': int,
                'active_files': List[FileCatalogEntry],
                'deleted_files': List[FileCatalogEntry],
                'directories': List[FileCatalogEntry],
                'special_files': Dict[str, int],  # $MFT, $LogFile 등의 inode
            }
        """
        if self._extractor is None:
            raise FilesystemError("No partition selected")

        result = {
            'total_entries': 0,
            'active_files': [],
            'deleted_files': [],
            'directories': [],
            'special_files': {},
            'errors': []
        }

        # inode -> (parent_inode, filename) 매핑 (full_path 계산용)
        inode_info: Dict[int, Tuple[int, str]] = {}

        # MFT 크기 추정 (entry 0에서)
        entry_0 = self._extractor.read_mft_entry(0)
        if entry_0[:4] != b'FILE':
            return result

        # MFT 전체 엔트리 수 계산 (동적)
        total_mft_entries = self._get_mft_entry_count()
        if max_entries:
            total_mft_entries = min(total_mft_entries, max_entries)

        logger.info(f"Scanning MFT: {total_mft_entries:,} entries (max)")

        # MFT 엔트리 순회
        entry_num = 0
        skip_count = 0  # 스킵된 빈 엔트리 수

        while entry_num < total_mft_entries:
            try:
                entry = self._extractor.read_mft_entry(entry_num)

                # 유효한 엔트리인지 확인 - 빈 엔트리는 스킵 (오류 아님)
                if entry[:4] != b'FILE':
                    skip_count += 1
                    entry_num += 1
                    continue
                result['total_entries'] += 1

                # 메타데이터 추출
                try:
                    metadata = self._extractor.get_file_metadata(entry_num)
                except Exception as e:
                    result['errors'].append((entry_num, str(e)))
                    entry_num += 1
                    continue

                # inode -> (parent, name) 맵에 저장 (full_path 계산용)
                inode_info[entry_num] = (metadata.parent_ref, metadata.filename)

                # 카탈로그 엔트리 생성
                catalog_entry = FileCatalogEntry(
                    inode=entry_num,
                    filename=metadata.filename,
                    size=metadata.size,
                    is_directory=metadata.is_directory,
                    is_deleted=metadata.is_deleted,
                    parent_inode=metadata.parent_ref,
                    created_time=metadata.created_time,
                    modified_time=metadata.modified_time,
                    has_data_runs=len(metadata.data_runs) > 0 or metadata.is_resident,
                    ads_streams=metadata.ads_streams
                )

                # 특수 시스템 파일 ($MFT, $LogFile 등)
                if metadata.filename.startswith('$') and entry_num < 24:
                    result['special_files'][metadata.filename] = entry_num
                elif metadata.is_directory:
                    result['directories'].append(catalog_entry)
                elif metadata.is_deleted:
                    if include_deleted:
                        result['deleted_files'].append(catalog_entry)
                else:
                    result['active_files'].append(catalog_entry)

                # 진행률 콜백
                if progress_callback and entry_num % 1000 == 0:
                    progress_callback(entry_num, max_entries or entry_num)

            except Exception as e:
                result['errors'].append((entry_num, str(e)))
                # 오류가 있어도 계속 진행 (디지털 포렌식 원칙: 완전 수집)

            entry_num += 1

        logger.info(f"Scanned {entry_num:,} MFT entries ({skip_count:,} empty/invalid skipped): "
                   f"{len(result['active_files'])} files, "
                   f"{len(result['directories'])} directories, "
                   f"{len(result['deleted_files'])} deleted")

        # full_path 계산 (inode 체인을 따라 경로 구축)
        def build_full_path(inode: int, max_depth: int = 50) -> str:
            """inode에서 전체 경로 구축"""
            parts = []
            current = inode
            depth = 0
            while current in inode_info and depth < max_depth:
                parent, name = inode_info[current]
                if name and not name.startswith('$'):
                    parts.append(name)
                if parent == current or parent == 5:  # 루트 도달
                    break
                current = parent
                depth += 1
            parts.reverse()
            return '/'.join(parts) if parts else ""

        # active_files와 deleted_files에 full_path 설정
        for entry in result['active_files']:
            entry.full_path = build_full_path(entry.inode)

        for entry in result['deleted_files']:
            entry.full_path = build_full_path(entry.inode)

        for entry in result['directories']:
            entry.full_path = build_full_path(entry.inode)

        return result

    def find_files_by_name(
        self,
        name_pattern: str,
        include_deleted: bool = True,
        max_results: int = 100
    ) -> List[FileCatalogEntry]:
        """
        파일명으로 검색

        Args:
            name_pattern: 파일명 패턴 (대소문자 무시)
            include_deleted: 삭제된 파일 포함
            max_results: 최대 결과 수

        Returns:
            FileCatalogEntry 리스트
        """
        results = []
        name_lower = name_pattern.lower()
        entry_num = 0
        errors = 0

        while len(results) < max_results:
            try:
                metadata = self._extractor.get_file_metadata(entry_num)

                if metadata.filename.lower().find(name_lower) >= 0:
                    if not metadata.is_deleted or include_deleted:
                        results.append(FileCatalogEntry(
                            inode=entry_num,
                            filename=metadata.filename,
                            size=metadata.size,
                            is_directory=metadata.is_directory,
                            is_deleted=metadata.is_deleted,
                            parent_inode=metadata.parent_ref,
                            has_data_runs=len(metadata.data_runs) > 0
                        ))
                errors = 0
            except Exception:
                errors += 1
                if errors > 1000:
                    break

            entry_num += 1

        return results

    # ==========================================================================
    # Path Resolution
    # ==========================================================================

    def _normalize_path(self, path: str) -> str:
        """경로 정규화"""
        # 백슬래시를 슬래시로 변환
        path = path.replace('\\', '/')

        # 드라이브 문자 제거 (C:/)
        if len(path) > 2 and path[1] == ':':
            path = path[2:]

        # 선행 슬래시 제거
        while path.startswith('/'):
            path = path[1:]

        return path

    def _resolve_path_to_inode(self, path: str) -> Optional[int]:
        """경로를 MFT entry 번호로 변환"""
        if not path:
            return 5  # Root directory

        parts = path.split('/')
        current_inode = 5  # Root directory is always entry 5

        for part in parts:
            if not part:
                continue

            # 현재 디렉토리의 인덱스에서 파일 찾기
            found = self._find_in_directory(current_inode, part)
            if found is None:
                return None
            current_inode = found

        return current_inode

    def _find_in_directory(self, dir_inode: int, name: str) -> Optional[int]:
        """
        디렉토리에서 파일 찾기 (인덱스 활용 - 대소문자 무시)

        파일명 맵을 활용하여 O(1)로 파일을 찾습니다.
        대소문자를 무시합니다.
        """
        name_lower = name.lower()

        # 부모-자식 인덱스가 없으면 구축 (최초 1회)
        if not self._parent_index_built:
            self._build_parent_index()

        # 파일명 맵에서 직접 조회 (O(1))
        if hasattr(self, '_name_to_inode_map'):
            key = (dir_inode, name_lower)
            if key in self._name_to_inode_map:
                return self._name_to_inode_map[key]

        # 인덱스에서 자식 inode 목록 조회
        child_inodes = self._parent_child_index.get(dir_inode, [])

        # 자식 목록에서 파일명 매칭 (대소문자 무시)
        for entry_num in child_inodes:
            try:
                metadata = self._extractor.get_file_metadata(entry_num)
                if metadata.filename.lower() == name_lower:
                    # 캐시 업데이트
                    if hasattr(self, '_name_to_inode_map'):
                        self._name_to_inode_map[(dir_inode, name_lower)] = entry_num
                    return entry_num
            except Exception:
                continue

        # 여전히 못 찾으면 limited fallback (10,000개만)
        logger.debug(f"File '{name}' not found in index for dir_inode={dir_inode}")
        return None

    # ==========================================================================
    # Special Files
    # ==========================================================================

    def read_mft_raw(self, max_size: int = None) -> bytes:
        """
        $MFT 파일 raw 데이터 읽기

        Args:
            max_size: 최대 크기 (None = 전체)

        Returns:
            MFT raw 데이터
        """
        return self.read_file_by_inode(0, max_size=max_size)

    def read_logfile_raw(self, max_size: int = None) -> bytes:
        """
        $LogFile raw 데이터 읽기 (NTFS 트랜잭션 로그)
        """
        return self.read_file_by_inode(2, max_size=max_size)

    def read_usnjrnl_raw(self, max_size: int = None) -> bytes:
        """
        $UsnJrnl:$J raw 데이터 읽기 (USN Journal)

        $UsnJrnl은 entry 번호가 고정되지 않음 - $Extend 디렉토리에서 찾아야 함
        """
        # $Extend 디렉토리 (보통 entry 11)
        extend_inode = 11

        # $Extend 아래에서 $UsnJrnl 찾기
        usnjrnl_inode = self._find_in_directory(extend_inode, '$UsnJrnl')
        if usnjrnl_inode is None:
            raise FilesystemError("$UsnJrnl not found")

        # $J 스트림 읽기
        return self.read_file_by_inode(usnjrnl_inode, stream_name='$J', max_size=max_size)

    # ==========================================================================
    # Disk Info
    # ==========================================================================

    def get_disk_info(self) -> DiskInfo:
        """디스크 정보 반환"""
        return self._backend.get_disk_info()

    def get_partition_table_type(self) -> str:
        """파티션 테이블 타입 반환 (MBR/GPT)"""
        return self._partition_table_type

    # ==========================================================================
    # Context Manager
    # ==========================================================================

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def close(self):
        """리소스 해제"""
        if self._backend:
            self._backend.close()
        self._extractor = None
        self._path_cache.clear()


# ==============================================================================
# Convenience Functions
# ==============================================================================

def read_locked_file(path: str, drive_number: int = 0) -> bytes:
    """
    잠긴 파일 읽기 (편의 함수)

    Windows가 잠근 파일(레지스트리, pagefile 등)을 raw disk 접근으로 읽습니다.

    Args:
        path: 파일 경로 (예: "C:/Windows/System32/config/SYSTEM")
        drive_number: 드라이브 번호 (기본 0)

    Returns:
        파일 내용

    Usage:
        system_hive = read_locked_file("C:/Windows/System32/config/SYSTEM")
    """
    with ForensicDiskAccessor.from_physical_disk(drive_number) as disk:
        # 드라이브 문자로 파티션 선택 추론
        partition_index = 0  # 기본적으로 첫 번째 파티션

        # 경로에서 드라이브 문자 추출
        if len(path) > 2 and path[1] == ':':
            drive_letter = path[0].upper()
            # C: = 파티션 0 (간단한 매핑, 실제로는 더 복잡함)
            partition_index = ord(drive_letter) - ord('C')
            partition_index = max(0, partition_index)

        partitions = disk.list_partitions()
        if partition_index >= len(partitions):
            partition_index = 0

        disk.select_partition(partition_index)
        return disk.read_file(path)


def stream_large_file(path: str, drive_number: int = 0, chunk_size: int = 64 * 1024 * 1024):
    """
    대용량 파일 스트리밍 (편의 함수)

    pagefile.sys, hiberfil.sys 같은 대용량 파일을 메모리 효율적으로 스트리밍합니다.

    Args:
        path: 파일 경로
        drive_number: 드라이브 번호
        chunk_size: 청크 크기 (기본 64MB)

    Yields:
        파일 데이터 청크
    """
    with ForensicDiskAccessor.from_physical_disk(drive_number) as disk:
        partition_index = 0
        if len(path) > 2 and path[1] == ':':
            drive_letter = path[0].upper()
            partition_index = ord(drive_letter) - ord('C')
            partition_index = max(0, partition_index)

        partitions = disk.list_partitions()
        if partition_index >= len(partitions):
            partition_index = 0

        disk.select_partition(partition_index)
        yield from disk.stream_file(path, chunk_size)
