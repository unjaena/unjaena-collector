"""
hiberfil.sys 분석기

Windows Hibernation 파일(hiberfil.sys) 분석을 위한 모듈
- Hibernation 파일 타입 감지 (HIBR/WAKE)
- 헤더 파싱
- 압축 해제 (XPRESS/LZ77)
- 메모리 페이지 추출
- 문자열 및 아티팩트 검색

참조:
- Windows Hibernation 파일 구조
- XPRESS 압축 알고리즘 (MS-XCA)
- Volatility3 hibernation layer

Raw Disk Access 지원:
- ForensicDiskAccessor를 통한 raw sector 기반 hiberfil 읽기
- Windows 파일 잠금 완전 우회
- E01 이미지에서도 동일하게 동작
"""

import struct
import logging
import re
from typing import Dict, List, Optional, Generator, Tuple
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# Debug output control
_DEBUG_OUTPUT = False
def _debug_print(msg): 
    if _DEBUG_OUTPUT: _debug_print(msg)


class HiberfilAnalyzer:
    """hiberfil.sys 분석기"""

    # Hibernation 파일 시그니처
    HIBR_SIGNATURE = b'hibr'       # Full Hibernation
    RSTR_SIGNATURE = b'rstr'       # Resume (복원 중)
    WAKE_SIGNATURE = b'wake'       # Fast Startup (Windows 8+)

    # Windows 버전별 헤더 크기
    HEADER_SIZE_XP = 4096
    HEADER_SIZE_VISTA = 4096
    HEADER_SIZE_WIN7 = 4096
    HEADER_SIZE_WIN8 = 4096
    HEADER_SIZE_WIN10 = 4096

    # XPRESS 압축 관련
    XPRESS_MAGIC = b'\x81\x81'     # XPRESS 압축 블록 시그니처
    PAGE_SIZE = 4096

    # PO_MEMORY_IMAGE 구조 오프셋 (Windows 버전에 따라 다름)
    # Windows 10 기준
    HIBERNATION_HEADER_OFFSETS = {
        'signature': 0,           # 4 bytes
        'version': 4,             # 4 bytes
        'checksum': 8,            # 4 bytes
        'length': 12,             # 4 bytes (압축되지 않은 크기)
        'num_pages': 16,          # 8 bytes
        'highest_page': 24,       # 8 bytes
        'system_time': 48,        # 8 bytes (FILETIME)
    }

    def __init__(self, hiberfil_path: str = None, hiberfil_data: bytes = None):
        """
        Args:
            hiberfil_path: hiberfil.sys 파일 경로
            hiberfil_data: hiberfil 바이너리 데이터 (직접 제공 시)
        """
        self.hiberfil_path = hiberfil_path
        self.hiberfil_data = hiberfil_data
        self.file_size = 0

        # 헤더 정보
        self.signature = None
        self.version = 0
        self.num_pages = 0
        self.is_compressed = True
        self.hiberfil_type = 'UNKNOWN'

        if hiberfil_path:
            path = Path(hiberfil_path)
            if path.exists():
                self.file_size = path.stat().st_size

        if hiberfil_data:
            self.file_size = len(hiberfil_data)

    def _read(self, offset: int, size: int) -> bytes:
        """데이터 읽기"""
        if self.hiberfil_data:
            return self.hiberfil_data[offset:offset + size]

        with open(self.hiberfil_path, 'rb') as f:
            f.seek(offset)
            return f.read(size)

    def detect_type(self) -> str:
        """
        Hibernation 파일 타입 감지

        Returns:
            'HIBR': 전체 Hibernation
            'WAKE': Fast Startup (Windows 8+)
            'RSTR': Resume 중 (복원 중)
            'UNKNOWN': 알 수 없음
        """
        header = self._read(0, 8)

        if header[:4] == self.HIBR_SIGNATURE:
            self.hiberfil_type = 'HIBR'
        elif header[:4] == self.WAKE_SIGNATURE:
            self.hiberfil_type = 'WAKE'
        elif header[:4] == self.RSTR_SIGNATURE:
            self.hiberfil_type = 'RSTR'
        else:
            self.hiberfil_type = 'UNKNOWN'

        return self.hiberfil_type

    def parse_header(self) -> Dict:
        """
        Hibernation 헤더 파싱

        Returns:
            헤더 정보 딕셔너리
        """
        header = self._read(0, self.PAGE_SIZE)

        self.signature = header[:4]
        hiberfil_type = self.detect_type()

        # 버전
        self.version = struct.unpack('<I', header[4:8])[0]

        # 체크섬
        checksum = struct.unpack('<I', header[8:12])[0]

        # 압축되지 않은 길이
        length = struct.unpack('<I', header[12:16])[0]

        # 페이지 수 (Windows 버전에 따라 오프셋이 다름)
        # 일반적으로 오프셋 16 또는 24
        try:
            num_pages = struct.unpack('<Q', header[16:24])[0]
            self.num_pages = num_pages
        except:
            num_pages = 0

        # 최고 페이지 번호
        try:
            highest_page = struct.unpack('<Q', header[24:32])[0]
        except:
            highest_page = 0

        # 시스템 시간 (FILETIME)
        try:
            system_time = struct.unpack('<Q', header[48:56])[0]
            if system_time > 0:
                # FILETIME to datetime
                # FILETIME은 1601년 1월 1일부터 100나노초 단위
                epoch_diff = 116444736000000000  # 1601과 1970 사이의 100ns 단위 차이
                timestamp = (system_time - epoch_diff) / 10000000
                system_datetime = datetime.fromtimestamp(timestamp)
            else:
                system_datetime = None
        except:
            system_datetime = None

        return {
            'signature': self.signature.decode('ascii', errors='ignore'),
            'type': hiberfil_type,
            'version': self.version,
            'checksum': checksum,
            'length': length,
            'num_pages': num_pages,
            'highest_page': highest_page,
            'system_time': system_datetime,
            'file_size': self.file_size,
            'is_valid': hiberfil_type != 'UNKNOWN',
        }

    def decompress_xpress(self, compressed_data: bytes) -> Optional[bytes]:
        """
        XPRESS 압축 해제 (LZ77 기반)

        Windows Vista+ Hibernation 파일은 XPRESS 압축 사용
        압축 해제 구현이 복잡하여 외부 라이브러리 또는 직접 구현 필요

        Args:
            compressed_data: 압축된 데이터

        Returns:
            압축 해제된 데이터 또는 None
        """
        # 방법 1: 향상된 HiberfilDecompressor 시도 (Pure Python, 크로스 플랫폼)
        try:
            from .hiberfil_decompressor import HiberfilDecompressor
            decompressor = HiberfilDecompressor()
            result = decompressor.decompress(compressed_data)
            if result:
                return result
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"HiberfilDecompressor failed: {e}")

        # 방법 2: lznt1 라이브러리 시도
        try:
            import lznt1
            return lznt1.decompress(compressed_data)
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"lznt1 failed: {e}")

        # 방법 3: dissect.xpress 시도
        try:
            from dissect import xpress
            return xpress.decompress(compressed_data)
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"dissect.xpress failed: {e}")

        # 방법 4: Windows API 시도 (Windows에서만)
        try:
            import ctypes
            from ctypes import wintypes

            RtlDecompressBuffer = ctypes.windll.ntdll.RtlDecompressBuffer
            RtlDecompressBuffer.argtypes = [
                wintypes.USHORT,        # CompressionFormat
                ctypes.POINTER(ctypes.c_char),  # UncompressedBuffer
                wintypes.ULONG,         # UncompressedBufferSize
                ctypes.POINTER(ctypes.c_char),  # CompressedBuffer
                wintypes.ULONG,         # CompressedBufferSize
                ctypes.POINTER(wintypes.ULONG)  # FinalUncompressedSize
            ]
            RtlDecompressBuffer.restype = wintypes.LONG

            COMPRESSION_FORMAT_XPRESS = 0x0003

            # 예상 압축 해제 크기 (최대 4배)
            max_size = len(compressed_data) * 4
            decompressed = ctypes.create_string_buffer(max_size)
            final_size = wintypes.ULONG()

            result = RtlDecompressBuffer(
                COMPRESSION_FORMAT_XPRESS,
                decompressed,
                max_size,
                compressed_data,
                len(compressed_data),
                ctypes.byref(final_size)
            )

            if result == 0:  # STATUS_SUCCESS
                return decompressed.raw[:final_size.value]
        except:
            pass

        logger.warning("XPRESS 압축 해제 실패 - 모든 방법 시도됨")
        logger.warning("권장 설치: pip install dissect.xpress 또는 pip install lznt1")
        return None

    def extract_memory_pages(self, max_pages: int = 0) -> Generator[Tuple[int, bytes], None, None]:
        """
        메모리 페이지 추출

        주의: 완전한 구현을 위해서는 Windows 버전별 구조 파싱 필요
        Volatility3의 hibernation layer 참조 권장

        Args:
            max_pages: 최대 추출 페이지 수 (0 = 전체)

        Yields:
            (page_number, page_data) 튜플
        """
        _debug_print(f"[Hiberfil] 메모리 페이지 추출 (타입: {self.hiberfil_type})...")

        # 헤더 이후부터 시작
        offset = self.PAGE_SIZE
        page_count = 0

        while offset < self.file_size:
            if max_pages > 0 and page_count >= max_pages:
                break

            # 페이지 데이터 읽기
            page_data = self._read(offset, self.PAGE_SIZE)
            if len(page_data) < self.PAGE_SIZE:
                break

            # XPRESS 압축 여부 확인
            if page_data[:2] == self.XPRESS_MAGIC:
                # 압축 해제 시도
                decompressed = self.decompress_xpress(page_data)
                if decompressed:
                    yield (page_count, decompressed)
                else:
                    # 압축 해제 실패 시 원본 제공
                    yield (page_count, page_data)
            else:
                yield (page_count, page_data)

            page_count += 1
            offset += self.PAGE_SIZE

            if page_count % 10000 == 0:
                _debug_print(f"[Hiberfil] {page_count:,} 페이지 처리...")

        _debug_print(f"[Hiberfil] 총 {page_count:,} 페이지 추출")

    def find_strings(
        self,
        min_length: int = 8,
        max_pages: int = 10000
    ) -> Generator[Dict, None, None]:
        """
        hiberfil에서 문자열 검색

        Args:
            min_length: 최소 문자열 길이
            max_pages: 검색할 최대 페이지 수

        Yields:
            문자열 정보 딕셔너리
        """
        _debug_print(f"[Hiberfil] 문자열 검색 (최대 {max_pages} 페이지)...")

        ascii_pattern = re.compile(
            rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        )

        total_strings = 0

        for page_num, page_data in self.extract_memory_pages(max_pages):
            for match in ascii_pattern.finditer(page_data):
                string = match.group()
                yield {
                    'type': 'ascii',
                    'string': string.decode('ascii', errors='ignore'),
                    'page_num': page_num,
                    'offset_in_page': match.start(),
                }
                total_strings += 1

        _debug_print(f"[Hiberfil] {total_strings:,}개 문자열 발견")

    def find_urls(self, max_pages: int = 10000) -> List[Dict]:
        """
        hiberfil에서 URL 검색

        Args:
            max_pages: 검색할 최대 페이지 수

        Returns:
            URL 정보 리스트
        """
        _debug_print(f"[Hiberfil] URL 검색 중...")

        url_pattern = re.compile(
            rb'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
            re.IGNORECASE
        )

        urls = []
        seen = set()

        for page_num, page_data in self.extract_memory_pages(max_pages):
            for match in url_pattern.finditer(page_data):
                url = match.group()
                if url not in seen:
                    seen.add(url)
                    urls.append({
                        'url': url.decode('utf-8', errors='ignore'),
                        'page_num': page_num,
                        'offset_in_page': match.start(),
                    })

        _debug_print(f"[Hiberfil] {len(urls):,}개 URL 발견")
        return urls

    def find_processes(self, max_pages: int = 10000) -> List[Dict]:
        """
        hiberfil에서 프로세스 정보 검색

        EPROCESS 구조체 시그니처 검색
        주의: Windows 버전별로 구조가 다름

        Args:
            max_pages: 검색할 최대 페이지 수

        Returns:
            프로세스 정보 리스트 (기본적인 패턴 매칭)
        """
        _debug_print(f"[Hiberfil] 프로세스 정보 검색 중...")

        # .exe 파일명 패턴
        exe_pattern = re.compile(
            rb'[a-zA-Z0-9_\-]+\.exe',
            re.IGNORECASE
        )

        processes = []
        seen = set()

        for page_num, page_data in self.extract_memory_pages(max_pages):
            for match in exe_pattern.finditer(page_data):
                exe_name = match.group()
                if exe_name not in seen and len(exe_name) < 100:
                    seen.add(exe_name)
                    processes.append({
                        'exe_name': exe_name.decode('ascii', errors='ignore'),
                        'page_num': page_num,
                        'offset_in_page': match.start(),
                    })

        _debug_print(f"[Hiberfil] {len(processes):,}개 실행 파일명 발견")
        return processes

    def analyze_all(self, max_pages: int = 10000) -> Dict:
        """
        전체 분석 수행

        Args:
            max_pages: 분석할 최대 페이지 수

        Returns:
            분석 결과 딕셔너리
        """
        _debug_print(f"[Hiberfil] 전체 분석 시작 (크기: {self.file_size / 1024 / 1024:.1f} MB)...")

        # 헤더 파싱
        header_info = self.parse_header()

        if not header_info['is_valid']:
            _debug_print(f"[Hiberfil] 유효하지 않은 hiberfil: {header_info['signature']}")
            return {'error': 'Invalid hibernation file', 'header': header_info}

        results = {
            'file_path': self.hiberfil_path,
            'file_size': self.file_size,
            'header': header_info,
            'urls': self.find_urls(max_pages),
            'processes': self.find_processes(max_pages),
            'analysis_time': datetime.now().isoformat(),
        }

        # 요약
        results['summary'] = {
            'type': header_info['type'],
            'total_urls': len(results['urls']),
            'total_processes': len(results['processes']),
        }

        _debug_print(f"[Hiberfil] 분석 완료:")
        for key, value in results['summary'].items():
            _debug_print(f"  - {key}: {value}")

        return results


class SwapfileAnalyzer:
    """swapfile.sys 분석기 (Windows 10+ UWP 앱용)"""

    PAGE_SIZE = 4096

    def __init__(self, swapfile_path: str = None, swapfile_data: bytes = None):
        """
        Args:
            swapfile_path: swapfile.sys 파일 경로
            swapfile_data: swapfile 바이너리 데이터
        """
        self.swapfile_path = swapfile_path
        self.swapfile_data = swapfile_data
        self.file_size = 0

        if swapfile_path:
            path = Path(swapfile_path)
            if path.exists():
                self.file_size = path.stat().st_size

        if swapfile_data:
            self.file_size = len(swapfile_data)

    def analyze(self) -> Dict:
        """
        swapfile 기본 분석

        swapfile.sys는 pagefile.sys와 유사한 구조
        UWP 앱의 메모리 페이지 저장

        Returns:
            분석 결과
        """
        _debug_print(f"[Swapfile] 분석 시작 (크기: {self.file_size / 1024 / 1024:.1f} MB)...")

        # pagefile 분석기와 유사하게 처리
        from .pagefile_analyzer import PagefileAnalyzer

        if self.swapfile_path:
            analyzer = PagefileAnalyzer(pagefile_path=self.swapfile_path)
        else:
            analyzer = PagefileAnalyzer(pagefile_data=self.swapfile_data)

        # 기본 분석 수행
        results = {
            'file_path': self.swapfile_path,
            'file_size': self.file_size,
            'page_count': self.file_size // self.PAGE_SIZE,
            'urls': analyzer.find_urls(),
            'emails': analyzer.find_emails(),
            'analysis_time': datetime.now().isoformat(),
        }

        results['summary'] = {
            'total_urls': len(results['urls']),
            'total_emails': len(results['emails']),
        }

        _debug_print(f"[Swapfile] 분석 완료")
        return results


def analyze_hiberfil_from_image(img_info, hiberfil_offset: int, hiberfil_size: int) -> Dict:
    """
    디스크 이미지에서 hiberfil 분석

    Args:
        img_info: 이미지 핸들
        hiberfil_offset: hiberfil 시작 오프셋
        hiberfil_size: hiberfil 크기

    Returns:
        분석 결과
    """
    _debug_print(f"[Hiberfil] 이미지에서 hiberfil 읽기 (offset={hiberfil_offset})...")

    # 크기 제한 (메모리 보호)
    max_size = min(hiberfil_size, 1024 * 1024 * 1024)  # 최대 1GB

    hiberfil_data = img_info.read(hiberfil_offset, max_size)

    analyzer = HiberfilAnalyzer(hiberfil_data=hiberfil_data)
    return analyzer.analyze_all()


# ==============================================================================
# Raw Disk Access Factory Functions
# ==============================================================================

def create_hiberfil_analyzer_raw_disk(
    drive_number: int = 0,
    partition_index: int = None,
    max_size_mb: int = 1024
) -> Optional[HiberfilAnalyzer]:
    """
    Raw Disk Access로 HiberfilAnalyzer 생성

    Windows 파일 잠금을 완전히 우회하여 hiberfil.sys를 읽습니다.
    관리자 권한이 필요합니다.

    Args:
        drive_number: 물리 디스크 번호 (기본: 0)
        partition_index: 파티션 인덱스 (None이면 첫 번째 NTFS 파티션)
        max_size_mb: 최대 읽기 크기 (MB 단위, 기본 1024MB)

    Returns:
        HiberfilAnalyzer 인스턴스 또는 None

    Usage:
        analyzer = create_hiberfil_analyzer_raw_disk()
        if analyzer:
            results = analyzer.analyze_all()
    """
    try:
        from core.engine.collectors.filesystem.forensic_disk_accessor import ForensicDiskAccessor
    except ImportError:
        logger.error("ForensicDiskAccessor not available")
        return None

    _debug_print(f"[Hiberfil] Raw Disk Access로 hiberfil.sys 읽기 시작...")

    try:
        with ForensicDiskAccessor.from_physical_disk(drive_number) as disk:
            partitions = disk.list_partitions()

            if not partitions:
                logger.error("No partitions found")
                return None

            # 파티션 선택
            if partition_index is not None:
                if partition_index >= len(partitions):
                    logger.error(f"Invalid partition index: {partition_index}")
                    return None
                disk.select_partition(partition_index)
            else:
                # 첫 번째 NTFS 파티션 자동 선택
                ntfs_idx = None
                for i, p in enumerate(partitions):
                    if p.filesystem == 'NTFS':
                        ntfs_idx = i
                        break

                if ntfs_idx is None:
                    logger.error("No NTFS partition found")
                    return None

                disk.select_partition(ntfs_idx)
                _debug_print(f"[Hiberfil] 파티션 {ntfs_idx} 선택 (NTFS)")

            # hiberfil.sys 스트리밍 읽기 (크기 제한)
            hiberfil_path = '/hiberfil.sys'
            max_size = max_size_mb * 1024 * 1024

            _debug_print(f"[Hiberfil] hiberfil.sys 데이터 스트리밍 중 (최대 {max_size_mb} MB)...")

            chunks = []
            total_size = 0

            for chunk in disk.stream_file(hiberfil_path, chunk_size=64 * 1024 * 1024):
                chunks.append(chunk)
                total_size += len(chunk)
                _debug_print(f"[Hiberfil] 읽기 진행: {total_size / 1024 / 1024:.1f} MB")

                if total_size >= max_size:
                    _debug_print(f"[Hiberfil] 최대 크기 도달 ({max_size_mb} MB)")
                    break

            hiberfil_data = b''.join(chunks)
            _debug_print(f"[Hiberfil] 총 {len(hiberfil_data) / 1024 / 1024:.1f} MB 읽기 완료 [raw disk]")

            return HiberfilAnalyzer(hiberfil_data=hiberfil_data)

    except Exception as e:
        logger.error(f"Raw disk hiberfil read error: {e}")
        _debug_print(f"[Hiberfil] Raw disk error: {e}")
        return None


def create_hiberfil_analyzer_e01(
    e01_path: str,
    partition_index: int = None,
    max_size_mb: int = 1024
) -> Optional[HiberfilAnalyzer]:
    """
    E01 이미지에서 HiberfilAnalyzer 생성

    Args:
        e01_path: E01 파일 경로
        partition_index: 파티션 인덱스 (None이면 첫 번째 NTFS 파티션)
        max_size_mb: 최대 읽기 크기 (MB 단위)

    Returns:
        HiberfilAnalyzer 인스턴스 또는 None

    Usage:
        analyzer = create_hiberfil_analyzer_e01("evidence.E01")
        if analyzer:
            results = analyzer.analyze_all()
    """
    try:
        from core.engine.collectors.filesystem.forensic_disk_accessor import ForensicDiskAccessor
    except ImportError:
        logger.error("ForensicDiskAccessor not available")
        return None

    _debug_print(f"[Hiberfil] E01 이미지에서 hiberfil.sys 읽기 시작...")
    _debug_print(f"[Hiberfil] E01 경로: {e01_path}")

    try:
        with ForensicDiskAccessor.from_e01(e01_path) as disk:
            partitions = disk.list_partitions()

            if not partitions:
                logger.error("No partitions found in E01 image")
                return None

            # 파티션 선택
            if partition_index is not None:
                if partition_index >= len(partitions):
                    logger.error(f"Invalid partition index: {partition_index}")
                    return None
                disk.select_partition(partition_index)
            else:
                ntfs_idx = None
                for i, p in enumerate(partitions):
                    if p.filesystem == 'NTFS':
                        ntfs_idx = i
                        break

                if ntfs_idx is None:
                    logger.error("No NTFS partition found in E01 image")
                    return None

                disk.select_partition(ntfs_idx)
                _debug_print(f"[Hiberfil] 파티션 {ntfs_idx} 선택 (NTFS)")

            hiberfil_path = '/hiberfil.sys'
            max_size = max_size_mb * 1024 * 1024

            _debug_print(f"[Hiberfil] hiberfil.sys 데이터 스트리밍 중 (최대 {max_size_mb} MB)...")

            chunks = []
            total_size = 0

            for chunk in disk.stream_file(hiberfil_path, chunk_size=64 * 1024 * 1024):
                chunks.append(chunk)
                total_size += len(chunk)
                _debug_print(f"[Hiberfil] 읽기 진행: {total_size / 1024 / 1024:.1f} MB")

                if total_size >= max_size:
                    _debug_print(f"[Hiberfil] 최대 크기 도달 ({max_size_mb} MB)")
                    break

            hiberfil_data = b''.join(chunks)
            _debug_print(f"[Hiberfil] 총 {len(hiberfil_data) / 1024 / 1024:.1f} MB 읽기 완료 [E01]")

            return HiberfilAnalyzer(hiberfil_data=hiberfil_data)

    except Exception as e:
        logger.error(f"E01 hiberfil read error: {e}")
        _debug_print(f"[Hiberfil] E01 error: {e}")
        return None


def create_swapfile_analyzer_raw_disk(
    drive_number: int = 0,
    partition_index: int = None
) -> Optional[SwapfileAnalyzer]:
    """
    Raw Disk Access로 SwapfileAnalyzer 생성

    Windows 10+ UWP 앱용 swapfile.sys를 읽습니다.

    Args:
        drive_number: 물리 디스크 번호
        partition_index: 파티션 인덱스

    Returns:
        SwapfileAnalyzer 인스턴스 또는 None
    """
    try:
        from core.engine.collectors.filesystem.forensic_disk_accessor import ForensicDiskAccessor
    except ImportError:
        logger.error("ForensicDiskAccessor not available")
        return None

    _debug_print(f"[Swapfile] Raw Disk Access로 swapfile.sys 읽기 시작...")

    try:
        with ForensicDiskAccessor.from_physical_disk(drive_number) as disk:
            partitions = disk.list_partitions()

            if not partitions:
                return None

            if partition_index is not None:
                disk.select_partition(partition_index)
            else:
                for i, p in enumerate(partitions):
                    if p.filesystem == 'NTFS':
                        disk.select_partition(i)
                        break
                else:
                    return None

            swapfile_path = '/swapfile.sys'

            _debug_print(f"[Swapfile] swapfile.sys 데이터 읽기 중...")

            chunks = []
            total_size = 0

            for chunk in disk.stream_file(swapfile_path, chunk_size=64 * 1024 * 1024):
                chunks.append(chunk)
                total_size += len(chunk)
                _debug_print(f"[Swapfile] 읽기 진행: {total_size / 1024 / 1024:.1f} MB")

            swapfile_data = b''.join(chunks)
            _debug_print(f"[Swapfile] 총 {len(swapfile_data) / 1024 / 1024:.1f} MB 읽기 완료 [raw disk]")

            return SwapfileAnalyzer(swapfile_data=swapfile_data)

    except Exception as e:
        logger.error(f"Raw disk swapfile read error: {e}")
        return None


if __name__ == "__main__":
    print("=" * 60)
    print("Hiberfil Analyzer Test")
    print("=" * 60)

    print("Usage:")
    print("  # Hibernation 파일 분석")
    print("  analyzer = HiberfilAnalyzer('C:\\hiberfil.sys')")
    print("  header = analyzer.parse_header()")
    print("  results = analyzer.analyze_all()")
    print()
    print("  # Swapfile 분석")
    print("  analyzer = SwapfileAnalyzer('C:\\swapfile.sys')")
    print("  results = analyzer.analyze()")
