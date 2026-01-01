# -*- coding: utf-8 -*-
"""
File Content Extractor - Data Runs 기반 파일 내용 추출

MFT data runs 또는 FAT cluster chain을 사용하여
raw disk에서 직접 파일 내용을 읽습니다.

핵심 기능:
- MFT entry → data runs → raw sectors → 파일 내용
- ADS (Alternate Data Streams) 지원
- 삭제된 파일 복구
- 대용량 파일 스트리밍

이 모듈은 Windows 파일시스템을 완전히 우회합니다.
따라서 잠긴 파일(pagefile.sys, registry hives 등)도 읽을 수 있습니다.

Usage:
    from core.engine.collectors.filesystem.disk_backends import PhysicalDiskBackend
    from core.engine.collectors.filesystem.file_content_extractor import FileContentExtractor

    with PhysicalDiskBackend(0) as disk:
        extractor = FileContentExtractor(disk, partition_offset=0x100000, fs_type='NTFS')

        # MFT entry로 파일 읽기
        data = extractor.read_file_by_inode(12345)

        # ADS 읽기
        zone_id = extractor.read_file_by_inode(12345, stream_name="Zone.Identifier")

        # 대용량 파일 스트리밍
        for chunk in extractor.stream_file_by_inode(12345):
            process(chunk)
"""

import struct
import logging
from typing import Optional, List, Tuple, Dict, Generator, Any
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from datetime import datetime

# =============================================================================
# Debug Logging to File
# =============================================================================
_DEBUG_LOG_FILE = None

def _debug_log(message: str):
    """콘솔과 파일 모두에 디버그 로그 출력"""
    global _DEBUG_LOG_FILE
    _debug_print(message, flush=True)

    # 파일에도 기록
    try:
        if _DEBUG_LOG_FILE is None:
            import tempfile
            log_path = Path(tempfile.gettempdir()) / "mft_collector_debug.log"
            _DEBUG_LOG_FILE = open(log_path, 'a', encoding='utf-8')

        _DEBUG_LOG_FILE.write(f"{datetime.now().isoformat()} {message}\n")
        _DEBUG_LOG_FILE.flush()
    except:
        pass

from .unified_disk_reader import UnifiedDiskReader, FilesystemError

logger = logging.getLogger(__name__)

# Debug output control
_DEBUG_OUTPUT = False
def _debug_print(msg): 
    if _DEBUG_OUTPUT: _debug_print(msg)


# ==============================================================================
# Data Classes
# ==============================================================================

@dataclass
class DataRun:
    """NTFS Data Run (클러스터 범위)"""
    lcn: Optional[int]  # Logical Cluster Number (None = sparse)
    length: int         # 클러스터 수
    vcn_start: int = 0  # Virtual Cluster Number (파일 내 오프셋)

    @property
    def is_sparse(self) -> bool:
        return self.lcn is None


@dataclass
class FileMetadata:
    """파일 메타데이터 (MFT entry에서 추출)"""
    inode: int
    filename: str = ""
    full_path: str = ""
    size: int = 0
    allocated_size: int = 0

    is_directory: bool = False
    is_deleted: bool = False
    is_resident: bool = False

    # Resident 파일의 경우 데이터가 MFT entry 내에 저장됨
    resident_data: bytes = field(default_factory=bytes)

    # Non-resident 파일의 data runs
    data_runs: List[DataRun] = field(default_factory=list)

    # ADS (Alternate Data Streams) 이름 목록
    ads_streams: List[str] = field(default_factory=list)

    # 타임스탬프 (FILETIME)
    created_time: int = 0
    modified_time: int = 0
    accessed_time: int = 0
    mft_changed_time: int = 0

    # 추가 속성
    parent_ref: int = 0  # 부모 디렉토리 MFT 참조
    flags: int = 0       # MFT entry 플래그


class MFTAttributeType(IntEnum):
    """NTFS MFT 속성 타입"""
    STANDARD_INFORMATION = 0x10
    ATTRIBUTE_LIST = 0x20
    FILE_NAME = 0x30
    OBJECT_ID = 0x40
    SECURITY_DESCRIPTOR = 0x50
    VOLUME_NAME = 0x60
    VOLUME_INFORMATION = 0x70
    DATA = 0x80
    INDEX_ROOT = 0x90
    INDEX_ALLOCATION = 0xA0
    BITMAP = 0xB0
    REPARSE_POINT = 0xC0
    EA_INFORMATION = 0xD0
    EA = 0xE0
    END_MARKER = 0xFFFFFFFF


# ==============================================================================
# File Content Extractor
# ==============================================================================

class FileContentExtractor:
    """
    Data Runs 기반 파일 내용 추출기

    raw disk에서 MFT data runs를 따라 파일 내용을 직접 읽습니다.
    Windows 파일시스템을 완전히 우회하므로 잠긴 파일도 읽을 수 있습니다.

    지원 파일시스템:
    - NTFS (data runs)
    - FAT32/exFAT (cluster chain)
    - ext4 (extents) - 부분 지원
    """

    # MFT Entry 크기 (보통 1024 바이트)
    MFT_RECORD_SIZE = 1024

    # 기본 청크 크기 (64MB)
    DEFAULT_CHUNK_SIZE = 64 * 1024 * 1024

    def __init__(
        self,
        disk: UnifiedDiskReader,
        partition_offset: int,
        fs_type: str = 'NTFS'
    ):
        """
        Args:
            disk: UnifiedDiskReader 백엔드
            partition_offset: 파티션 시작 오프셋 (바이트)
            fs_type: 파일시스템 타입 ('NTFS', 'FAT32', 'exFAT', 'ext4')
        """
        self.disk = disk
        self.partition_offset = partition_offset
        self.fs_type = fs_type.upper()

        # 파일시스템 파라미터 (VBR에서 읽음)
        self.bytes_per_sector = 512
        self.sectors_per_cluster = 8
        self.cluster_size = 4096

        # NTFS 전용
        self.mft_lcn = 0
        self.mft_record_size = 1024
        self._mft_runs: List[DataRun] = []

        # FAT 전용
        self.fat_offset = 0
        self.data_area_offset = 0
        self.root_cluster = 0

        # 초기화
        self._init_filesystem()

    def _init_filesystem(self):
        """파일시스템 파라미터 초기화 (VBR 읽기)"""
        vbr = self.disk.read(self.partition_offset, 512)

        if self.fs_type == 'NTFS':
            self._init_ntfs(vbr)
        elif self.fs_type in ('FAT32', 'FAT16', 'FAT12', 'FAT'):
            self._init_fat(vbr)
        elif self.fs_type == 'EXFAT':
            self._init_exfat(vbr)
        else:
            logger.warning(f"Unknown filesystem type: {self.fs_type}")

    def _init_ntfs(self, vbr: bytes):
        """NTFS 파라미터 초기화"""
        # OEM ID 확인
        if vbr[3:11] != b'NTFS    ':
            # BitLocker 확인
            if vbr[3:11] == b'-FVE-FS-':
                raise FilesystemError("BitLocker encrypted volume - cannot access raw data")
            raise FilesystemError(f"Not an NTFS partition (OEM: {vbr[3:11]})")

        # BPB (BIOS Parameter Block) 파싱
        self.bytes_per_sector = struct.unpack('<H', vbr[11:13])[0]
        self.sectors_per_cluster = vbr[13]
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster

        # MFT 위치 (클러스터 번호)
        self.mft_lcn = struct.unpack('<Q', vbr[48:56])[0]

        # MFT entry 크기
        mft_record_size_raw = struct.unpack('<b', vbr[64:65])[0]
        if mft_record_size_raw > 0:
            self.mft_record_size = mft_record_size_raw * self.cluster_size
        else:
            self.mft_record_size = 2 ** abs(mft_record_size_raw)

        logger.info(f"[NTFS] Cluster size: {self.cluster_size}, MFT LCN: {self.mft_lcn}, "
                   f"MFT record size: {self.mft_record_size}")

        # MFT 자체의 data runs 로드 (MFT entry 0)
        self._load_mft_runs()

    def _init_fat(self, vbr: bytes):
        """FAT32 파라미터 초기화"""
        self.bytes_per_sector = struct.unpack('<H', vbr[11:13])[0]
        self.sectors_per_cluster = vbr[13]
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster

        reserved_sectors = struct.unpack('<H', vbr[14:16])[0]
        num_fats = vbr[16]
        sectors_per_fat = struct.unpack('<I', vbr[36:40])[0]

        self.root_cluster = struct.unpack('<I', vbr[44:48])[0]
        self.fat_offset = reserved_sectors * self.bytes_per_sector
        self.data_area_offset = self.fat_offset + (num_fats * sectors_per_fat * self.bytes_per_sector)

        logger.info(f"[FAT32] Cluster size: {self.cluster_size}, Root cluster: {self.root_cluster}")

    def _init_exfat(self, vbr: bytes):
        """exFAT 파라미터 초기화"""
        if vbr[3:11] != b'EXFAT   ':
            raise FilesystemError("Not an exFAT partition")

        # exFAT BPB
        sector_size_shift = vbr[108]
        cluster_size_shift = vbr[109]

        self.bytes_per_sector = 1 << sector_size_shift
        self.sectors_per_cluster = 1 << cluster_size_shift
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster

        fat_offset_sectors = struct.unpack('<I', vbr[80:84])[0]
        cluster_heap_offset = struct.unpack('<I', vbr[88:92])[0]
        self.root_cluster = struct.unpack('<I', vbr[96:100])[0]

        self.fat_offset = fat_offset_sectors * self.bytes_per_sector
        self.data_area_offset = cluster_heap_offset * self.bytes_per_sector

        logger.info(f"[exFAT] Cluster size: {self.cluster_size}, Root cluster: {self.root_cluster}")

    # ==========================================================================
    # MFT Operations
    # ==========================================================================

    def _load_mft_runs(self):
        """MFT 자체의 data runs 로드 (entry 0)"""
        # MFT entry 0 읽기 (MFT 자신)
        mft_offset = self.partition_offset + (self.mft_lcn * self.cluster_size)
        entry_0 = self.disk.read(mft_offset, self.mft_record_size)

        if entry_0[:4] != b'FILE':
            raise FilesystemError("Invalid MFT entry 0 signature")

        # Fixup 적용
        entry_0 = self._apply_fixup(entry_0)

        # $DATA 속성에서 data runs 파싱
        self._mft_runs = self._parse_data_attribute(entry_0)

        if not self._mft_runs:
            # 폴백: 연속된 MFT 가정
            logger.warning("Could not parse MFT data runs, assuming contiguous MFT")
            self._mft_runs = [DataRun(lcn=self.mft_lcn, length=1000000, vcn_start=0)]

        logger.debug(f"MFT data runs: {len(self._mft_runs)}")

    def _apply_fixup(self, entry: bytes) -> bytes:
        """MFT entry의 fixup array 적용"""
        if len(entry) < 48:
            return entry

        # Update Sequence Array offset and count
        usa_offset = struct.unpack('<H', entry[4:6])[0]
        usa_count = struct.unpack('<H', entry[6:8])[0]

        if usa_offset == 0 or usa_count < 2:
            return entry

        entry = bytearray(entry)

        # USA 값 읽기
        usa_value = entry[usa_offset:usa_offset + 2]

        # 각 섹터 끝의 USA 적용
        for i in range(1, usa_count):
            sector_end = (i * 512) - 2
            if sector_end + 2 <= len(entry) and usa_offset + (i * 2) + 2 <= len(entry):
                # USA 검증 후 복원
                original_bytes = entry[usa_offset + (i * 2):usa_offset + (i * 2) + 2]
                entry[sector_end:sector_end + 2] = original_bytes

        return bytes(entry)

    def read_mft_entry(self, entry_number: int) -> bytes:
        """
        MFT entry 읽기 (단편화된 MFT 지원)

        Args:
            entry_number: MFT entry 번호

        Returns:
            MFT entry 데이터 (fixup 적용됨)
        """
        entries_per_cluster = self.cluster_size // self.mft_record_size
        target_entry = entry_number

        # Data runs를 따라 entry 위치 찾기
        for run in self._mft_runs:
            if run.is_sparse:
                continue

            entries_in_run = run.length * entries_per_cluster

            if target_entry < entries_in_run:
                cluster_offset = target_entry // entries_per_cluster
                entry_in_cluster = target_entry % entries_per_cluster

                disk_offset = self.partition_offset + ((run.lcn + cluster_offset) * self.cluster_size)
                disk_offset += entry_in_cluster * self.mft_record_size

                entry_data = self.disk.read(disk_offset, self.mft_record_size)

                # Fixup 적용
                if entry_data[:4] == b'FILE':
                    entry_data = self._apply_fixup(entry_data)

                return entry_data

            target_entry -= entries_in_run

        raise FilesystemError(f"MFT entry {entry_number} not found in data runs")

    def _parse_data_attribute(
        self,
        mft_entry: bytes,
        stream_name: str = None
    ) -> List[DataRun]:
        """
        MFT entry에서 $DATA 속성의 data runs 파싱

        Args:
            mft_entry: MFT entry 데이터
            stream_name: ADS 이름 (None = 기본 $DATA)

        Returns:
            DataRun 리스트
        """
        if mft_entry[:4] != b'FILE':
            return []

        runs = []
        attr_offset = struct.unpack('<H', mft_entry[0x14:0x16])[0]
        pos = attr_offset

        while pos < len(mft_entry) - 24:
            attr_type = struct.unpack('<I', mft_entry[pos:pos+4])[0]

            if attr_type == MFTAttributeType.END_MARKER:
                break

            attr_length = struct.unpack('<I', mft_entry[pos+4:pos+8])[0]
            if attr_length == 0 or attr_length > self.mft_record_size:
                break

            # $DATA 속성 (0x80)
            if attr_type == MFTAttributeType.DATA:
                # 속성 이름 확인
                name_length = mft_entry[pos+9]
                attr_name = ""

                if name_length > 0:
                    name_offset = struct.unpack('<H', mft_entry[pos+10:pos+12])[0]
                    attr_name = mft_entry[pos+name_offset:pos+name_offset+name_length*2].decode('utf-16-le', errors='ignore')

                # 스트림 이름 매칭
                if stream_name is not None:
                    if attr_name != stream_name:
                        pos += attr_length
                        continue
                elif name_length > 0:
                    # 기본 $DATA (이름 없음)를 찾는 경우 - named stream 건너뛰기
                    pos += attr_length
                    continue

                # Non-resident 플래그
                non_resident = mft_entry[pos+8]

                if non_resident:
                    runs = self._parse_data_runs_bytes(mft_entry, pos)
                    if runs:
                        return runs

            pos += attr_length

        return runs

    def _parse_data_runs_bytes(self, mft_entry: bytes, attr_pos: int) -> List[DataRun]:
        """Data runs 바이트 파싱"""
        runs = []

        data_runs_offset = struct.unpack('<H', mft_entry[attr_pos+0x20:attr_pos+0x22])[0]
        pos = attr_pos + data_runs_offset
        current_lcn = 0
        vcn = 0

        while pos < len(mft_entry) - 1:
            header = mft_entry[pos]

            if header == 0:
                break

            length_bytes = header & 0x0F
            offset_bytes = (header >> 4) & 0x0F

            if length_bytes == 0:
                break

            if pos + 1 + length_bytes > len(mft_entry):
                break

            # Run length (클러스터 수)
            run_length = int.from_bytes(
                mft_entry[pos+1:pos+1+length_bytes],
                byteorder='little'
            )

            # Run offset (상대 LCN)
            is_sparse = False
            if offset_bytes > 0:
                if pos + 1 + length_bytes + offset_bytes > len(mft_entry):
                    break

                run_offset = int.from_bytes(
                    mft_entry[pos+1+length_bytes:pos+1+length_bytes+offset_bytes],
                    byteorder='little',
                    signed=True
                )
                current_lcn += run_offset
            else:
                # Sparse run
                is_sparse = True

            runs.append(DataRun(
                lcn=None if is_sparse else current_lcn,
                length=run_length,
                vcn_start=vcn
            ))

            vcn += run_length
            pos += 1 + length_bytes + offset_bytes

        return runs

    # ==========================================================================
    # File Content Reading
    # ==========================================================================

    def read_file_by_inode(
        self,
        inode: int,
        stream_name: str = None,
        max_size: int = None
    ) -> bytes:
        """
        MFT entry 번호로 파일 내용 읽기

        Args:
            inode: MFT entry 번호
            stream_name: ADS 이름 (None = 기본 $DATA)
            max_size: 최대 읽기 크기

        Returns:
            파일 내용 (bytes)
        """
        # MFT entry 읽기
        entry = self.read_mft_entry(inode)

        if entry[:4] != b'FILE':
            raise FilesystemError(f"Invalid MFT entry at inode {inode}")

        # 파일 메타데이터 추출
        metadata = self._parse_mft_entry_metadata(entry, inode, stream_name)

        # Resident 데이터
        if metadata.is_resident:
            data = metadata.resident_data
            if max_size:
                data = data[:max_size]
            return data

        # Non-resident: data runs 따라 읽기
        return self._read_data_runs(metadata.data_runs, metadata.size, max_size)

    def stream_file_by_inode(
        self,
        inode: int,
        stream_name: str = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE
    ) -> Generator[bytes, None, None]:
        """
        대용량 파일 스트리밍

        Args:
            inode: MFT entry 번호
            stream_name: ADS 이름
            chunk_size: 청크 크기

        Yields:
            파일 데이터 청크
        """
        entry = self.read_mft_entry(inode)
        metadata = self._parse_mft_entry_metadata(entry, inode, stream_name)

        if metadata.is_resident:
            yield metadata.resident_data
            return

        yield from self._stream_data_runs(metadata.data_runs, metadata.size, chunk_size)

    def get_file_metadata(self, inode: int) -> FileMetadata:
        """
        파일 메타데이터 조회

        Args:
            inode: MFT entry 번호

        Returns:
            FileMetadata 객체
        """
        entry = self.read_mft_entry(inode)
        return self._parse_mft_entry_metadata(entry, inode)

    def list_ads_streams(self, inode: int) -> List[str]:
        """
        ADS 스트림 목록

        Args:
            inode: MFT entry 번호

        Returns:
            ADS 이름 리스트 (기본 $DATA 제외)
        """
        entry = self.read_mft_entry(inode)
        return self._extract_ads_list(entry)

    # ==========================================================================
    # Internal Methods
    # ==========================================================================

    def _parse_mft_entry_metadata(
        self,
        entry: bytes,
        inode: int,
        stream_name: str = None
    ) -> FileMetadata:
        """MFT entry에서 메타데이터 추출"""
        if entry[:4] != b'FILE':
            raise FilesystemError(f"Invalid MFT signature at inode {inode}")

        # 플래그
        flags = struct.unpack('<H', entry[0x16:0x18])[0]
        is_directory = (flags & 0x02) != 0
        is_deleted = (flags & 0x01) == 0

        # 파일명 추출
        filename = self._extract_filename(entry)

        # 타임스탬프 추출
        timestamps = self._extract_timestamps(entry)

        # 부모 디렉토리 참조
        parent_ref = self._extract_parent_ref(entry)

        # ADS 목록
        ads_streams = self._extract_ads_list(entry)

        # $DATA 속성 파싱
        is_resident, resident_data, data_runs, file_size = self._extract_data_info(entry, stream_name)

        return FileMetadata(
            inode=inode,
            filename=filename,
            size=file_size,
            is_directory=is_directory,
            is_deleted=is_deleted,
            is_resident=is_resident,
            resident_data=resident_data,
            data_runs=data_runs,
            ads_streams=ads_streams,
            created_time=timestamps.get('created', 0),
            modified_time=timestamps.get('modified', 0),
            accessed_time=timestamps.get('accessed', 0),
            mft_changed_time=timestamps.get('mft_changed', 0),
            parent_ref=parent_ref,
            flags=flags
        )

    def _extract_filename(self, entry: bytes) -> str:
        """$FILE_NAME 속성에서 파일명 추출"""
        attr_offset = struct.unpack('<H', entry[0x14:0x16])[0]
        pos = attr_offset

        filename = ""

        while pos < len(entry) - 24:
            attr_type = struct.unpack('<I', entry[pos:pos+4])[0]

            if attr_type == MFTAttributeType.END_MARKER:
                break

            attr_length = struct.unpack('<I', entry[pos+4:pos+8])[0]
            if attr_length == 0 or attr_length > self.mft_record_size:
                break

            # $FILE_NAME 속성 (0x30)
            if attr_type == MFTAttributeType.FILE_NAME:
                non_resident = entry[pos+8]

                if not non_resident:  # FILE_NAME은 항상 resident
                    content_offset = struct.unpack('<H', entry[pos+0x14:pos+0x16])[0]
                    content_pos = pos + content_offset

                    if content_pos + 66 <= len(entry):
                        # 파일명 길이 (문자 수)
                        name_length = entry[content_pos + 64]
                        namespace = entry[content_pos + 65]

                        # Win32 또는 POSIX 네임스페이스 선호
                        if namespace in (1, 3) or not filename:  # Win32, POSIX
                            name_bytes = entry[content_pos + 66:content_pos + 66 + name_length * 2]
                            try:
                                new_filename = name_bytes.decode('utf-16-le')
                                if namespace in (1, 3) or not filename:
                                    filename = new_filename
                            except:
                                pass

            pos += attr_length

        return filename

    def _extract_timestamps(self, entry: bytes) -> Dict[str, int]:
        """$STANDARD_INFORMATION에서 타임스탬프 추출"""
        timestamps = {}

        attr_offset = struct.unpack('<H', entry[0x14:0x16])[0]
        pos = attr_offset

        while pos < len(entry) - 24:
            attr_type = struct.unpack('<I', entry[pos:pos+4])[0]

            if attr_type == MFTAttributeType.END_MARKER:
                break

            attr_length = struct.unpack('<I', entry[pos+4:pos+8])[0]
            if attr_length == 0 or attr_length > self.mft_record_size:
                break

            # $STANDARD_INFORMATION (0x10)
            if attr_type == MFTAttributeType.STANDARD_INFORMATION:
                non_resident = entry[pos+8]

                if not non_resident:
                    content_offset = struct.unpack('<H', entry[pos+0x14:pos+0x16])[0]
                    content_pos = pos + content_offset

                    if content_pos + 32 <= len(entry):
                        timestamps['created'] = struct.unpack('<Q', entry[content_pos:content_pos+8])[0]
                        timestamps['modified'] = struct.unpack('<Q', entry[content_pos+8:content_pos+16])[0]
                        timestamps['mft_changed'] = struct.unpack('<Q', entry[content_pos+16:content_pos+24])[0]
                        timestamps['accessed'] = struct.unpack('<Q', entry[content_pos+24:content_pos+32])[0]

                    return timestamps

            pos += attr_length

        return timestamps

    def _extract_parent_ref(self, entry: bytes) -> int:
        """$FILE_NAME에서 부모 디렉토리 참조 추출"""
        attr_offset = struct.unpack('<H', entry[0x14:0x16])[0]
        pos = attr_offset

        while pos < len(entry) - 24:
            attr_type = struct.unpack('<I', entry[pos:pos+4])[0]

            if attr_type == MFTAttributeType.END_MARKER:
                break

            attr_length = struct.unpack('<I', entry[pos+4:pos+8])[0]
            if attr_length == 0 or attr_length > self.mft_record_size:
                break

            if attr_type == MFTAttributeType.FILE_NAME:
                non_resident = entry[pos+8]

                if not non_resident:
                    content_offset = struct.unpack('<H', entry[pos+0x14:pos+0x16])[0]
                    content_pos = pos + content_offset

                    if content_pos + 8 <= len(entry):
                        parent_ref = struct.unpack('<Q', entry[content_pos:content_pos+8])[0]
                        return parent_ref & 0xFFFFFFFFFFFF  # 하위 48비트만

            pos += attr_length

        return 0

    def _extract_data_info(
        self,
        entry: bytes,
        stream_name: str = None
    ) -> Tuple[bool, bytes, List[DataRun], int]:
        """$DATA 속성에서 데이터 정보 추출"""
        attr_offset = struct.unpack('<H', entry[0x14:0x16])[0]
        pos = attr_offset

        while pos < len(entry) - 24:
            attr_type = struct.unpack('<I', entry[pos:pos+4])[0]

            if attr_type == MFTAttributeType.END_MARKER:
                break

            attr_length = struct.unpack('<I', entry[pos+4:pos+8])[0]
            if attr_length == 0 or attr_length > self.mft_record_size:
                break

            if attr_type == MFTAttributeType.DATA:
                # 스트림 이름 확인
                name_length = entry[pos+9]
                attr_name = ""

                if name_length > 0:
                    name_offset = struct.unpack('<H', entry[pos+10:pos+12])[0]
                    attr_name = entry[pos+name_offset:pos+name_offset+name_length*2].decode('utf-16-le', errors='ignore')

                # 이름 매칭
                if stream_name is not None:
                    if attr_name != stream_name:
                        pos += attr_length
                        continue
                elif name_length > 0:
                    pos += attr_length
                    continue

                non_resident = entry[pos+8]

                if non_resident:
                    # Non-resident
                    real_size = struct.unpack('<Q', entry[pos+0x30:pos+0x38])[0]
                    data_runs = self._parse_data_runs_bytes(entry, pos)
                    return False, b'', data_runs, real_size
                else:
                    # Resident
                    content_length = struct.unpack('<I', entry[pos+0x10:pos+0x14])[0]
                    content_offset = struct.unpack('<H', entry[pos+0x14:pos+0x16])[0]
                    content_pos = pos + content_offset

                    if content_pos + content_length <= len(entry):
                        resident_data = entry[content_pos:content_pos+content_length]
                        return True, resident_data, [], content_length

            pos += attr_length

        return True, b'', [], 0

    def _extract_ads_list(self, entry: bytes) -> List[str]:
        """ADS 스트림 이름 목록 추출"""
        ads_names = []

        attr_offset = struct.unpack('<H', entry[0x14:0x16])[0]
        pos = attr_offset

        while pos < len(entry) - 24:
            attr_type = struct.unpack('<I', entry[pos:pos+4])[0]

            if attr_type == MFTAttributeType.END_MARKER:
                break

            attr_length = struct.unpack('<I', entry[pos+4:pos+8])[0]
            if attr_length == 0 or attr_length > self.mft_record_size:
                break

            if attr_type == MFTAttributeType.DATA:
                name_length = entry[pos+9]

                if name_length > 0:
                    name_offset = struct.unpack('<H', entry[pos+10:pos+12])[0]
                    try:
                        name = entry[pos+name_offset:pos+name_offset+name_length*2].decode('utf-16-le')
                        if name not in ads_names:
                            ads_names.append(name)
                    except:
                        pass

            pos += attr_length

        return ads_names

    def _read_data_runs(
        self,
        data_runs: List[DataRun],
        file_size: int,
        max_size: int = None
    ) -> bytes:
        """Data runs를 따라 파일 데이터 읽기"""
        if max_size is not None:
            target_size = min(file_size, max_size)
        else:
            target_size = file_size

        data = bytearray()
        bytes_read = 0

        for run in data_runs:
            if bytes_read >= target_size:
                break

            if run.is_sparse:
                # Sparse run - 0으로 채움
                sparse_size = min(run.length * self.cluster_size, target_size - bytes_read)
                data.extend(b'\x00' * sparse_size)
                bytes_read += sparse_size
            else:
                # 실제 클러스터 읽기
                run_offset = self.partition_offset + (run.lcn * self.cluster_size)
                run_size = min(run.length * self.cluster_size, target_size - bytes_read)

                chunk = self.disk.read(run_offset, run_size)
                data.extend(chunk)
                bytes_read += len(chunk)

        return bytes(data[:target_size])

    def _stream_data_runs(
        self,
        data_runs: List[DataRun],
        file_size: int,
        chunk_size: int
    ) -> Generator[bytes, None, None]:
        """Data runs를 따라 파일 데이터 스트리밍"""
        import time

        bytes_read = 0
        run_index = 0
        total_runs = len(data_runs)
        start_time = time.time()

        # 디버깅: 파일 크기 제한 (손상된 MFT로 인한 무한 루프 방지)
        MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB
        if file_size > MAX_FILE_SIZE:
            _debug_log(f"[SANITY CHECK] Abnormally large file_size: {file_size / 1024 / 1024 / 1024:.2f}GB - limiting to 10GB")
            file_size = MAX_FILE_SIZE

        for run in data_runs:
            if bytes_read >= file_size:
                break

            run_index += 1

            if run.is_sparse:
                # Sparse run
                sparse_remaining = run.length * self.cluster_size

                # 디버깅: sparse run 경고
                if sparse_remaining > 1024 * 1024 * 1024:  # 1GB 이상
                    _debug_log(f"[SPARSE] Large sparse run: {sparse_remaining / 1024 / 1024:.1f}MB")

                while sparse_remaining > 0 and bytes_read < file_size:
                    yield_size = min(chunk_size, sparse_remaining, file_size - bytes_read)
                    yield b'\x00' * yield_size
                    sparse_remaining -= yield_size
                    bytes_read += yield_size
            else:
                # 실제 클러스터
                run_offset = self.partition_offset + (run.lcn * self.cluster_size)
                run_size = run.length * self.cluster_size
                run_read = 0

                # 디버깅: 오프셋 검증
                if run_offset < 0 or run.lcn < 0:
                    _debug_log(f"[INVALID] Negative offset: lcn={run.lcn}, offset={run_offset}")
                    continue

                while run_read < run_size and bytes_read < file_size:
                    read_size = min(chunk_size, run_size - run_read, file_size - bytes_read)

                    # 디버깅: 읽기 전 시간 측정
                    read_start = time.time()
                    chunk = self.disk.read(run_offset + run_read, read_size)
                    read_elapsed = time.time() - read_start

                    # 느린 읽기 경고 (1초 이상)
                    if read_elapsed > 1.0:
                        _debug_log(f"[SLOW READ] {read_elapsed:.2f}s for {read_size} bytes at offset {run_offset + run_read}")

                    if not chunk:
                        _debug_log(f"[EMPTY CHUNK] run {run_index}/{total_runs}, offset={run_offset + run_read}")
                        break

                    yield chunk
                    run_read += len(chunk)
                    bytes_read += len(chunk)

                    # 타임아웃 체크 (단일 파일 최대 10분)
                    if time.time() - start_time > 600:
                        _debug_log(f"[STREAM TIMEOUT] 10min limit reached at {bytes_read / 1024 / 1024:.1f}MB")
                        return

    # ==========================================================================
    # FAT Support
    # ==========================================================================

    def get_fat_cluster_chain(self, start_cluster: int) -> List[int]:
        """FAT cluster chain 읽기"""
        chain = []
        cluster = start_cluster
        visited = set()

        while cluster >= 2 and cluster < 0x0FFFFFF8:
            if cluster in visited:
                logger.warning(f"Circular reference in FAT chain at cluster {cluster}")
                break
            visited.add(cluster)
            chain.append(cluster)

            # FAT 테이블에서 다음 클러스터 읽기
            fat_entry_offset = self.partition_offset + self.fat_offset + (cluster * 4)
            entry_data = self.disk.read(fat_entry_offset, 4)
            cluster = struct.unpack('<I', entry_data)[0] & 0x0FFFFFFF

        return chain

    def read_fat_file(self, start_cluster: int, file_size: int) -> bytes:
        """FAT 파일 읽기"""
        chain = self.get_fat_cluster_chain(start_cluster)

        data = bytearray()
        bytes_read = 0

        for cluster in chain:
            if bytes_read >= file_size:
                break

            # 클러스터 오프셋 계산
            cluster_offset = self.partition_offset + self.data_area_offset
            cluster_offset += (cluster - 2) * self.cluster_size

            read_size = min(self.cluster_size, file_size - bytes_read)
            chunk = self.disk.read(cluster_offset, read_size)
            data.extend(chunk)
            bytes_read += len(chunk)

        return bytes(data[:file_size])
