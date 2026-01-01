# -*- coding: utf-8 -*-
"""
Disk Backends - UnifiedDiskReader 구현체들

세 가지 디스크 소스에 대한 구체적인 구현:
1. PhysicalDiskBackend - Windows 물리 디스크 (\\\\.\\PhysicalDrive{N})
2. E01DiskBackend - E01/EWF 포렌식 이미지 (pyewf)
3. RAWImageBackend - RAW/DD 이미지 파일

Usage:
    # 물리 디스크
    with PhysicalDiskBackend(0) as disk:
        mbr = disk.read(0, 512)

    # E01 이미지
    with E01DiskBackend("evidence.E01") as disk:
        mbr = disk.read(0, 512)

    # RAW 이미지
    with RAWImageBackend("disk.dd") as disk:
        mbr = disk.read(0, 512)
"""

import os
import sys
import struct
import logging
from pathlib import Path
from typing import Optional, List

from .unified_disk_reader import (
    UnifiedDiskReader,
    DiskInfo,
    DiskSourceType,
    DiskError,
    DiskNotFoundError,
    DiskPermissionError,
    DiskReadError
)

logger = logging.getLogger(__name__)

# Debug output control
_DEBUG_OUTPUT = False
def _debug_print(msg): 
    if _DEBUG_OUTPUT: _debug_print(msg)


# ==============================================================================
# Physical Disk Backend (Windows)
# ==============================================================================

class PhysicalDiskBackend(UnifiedDiskReader):
    """
    Windows 물리 디스크 백엔드

    \\\\.\\PhysicalDrive{N}을 통해 raw sector에 직접 접근합니다.
    관리자 권한이 필요합니다.

    Features:
    - Raw sector 읽기 (MBR, VBR, MFT 등)
    - 파일 잠금 우회 (pagefile.sys, registry 등)
    - 섹터 정렬 자동 처리

    Usage:
        with PhysicalDiskBackend(0) as disk:  # PhysicalDrive0
            mbr = disk.read(0, 512)
            vbr = disk.read(2048 * 512, 512)  # 첫 번째 파티션 VBR
    """

    def __init__(self, drive_number: int = 0):
        """
        Args:
            drive_number: 물리 드라이브 번호 (0 = PhysicalDrive0)
        """
        super().__init__()

        if sys.platform != 'win32':
            raise DiskError("PhysicalDiskBackend is Windows-only")

        self.drive_number = drive_number
        self.drive_path = f"\\\\.\\PhysicalDrive{drive_number}"
        self._handle = None

        self._open()

    def _open(self):
        """물리 드라이브 열기"""
        try:
            import win32file
            import win32con
            import pywintypes

            logger.info(f"Opening physical disk: {self.drive_path}")

            # 물리 드라이브 열기 (읽기 전용)
            self._handle = win32file.CreateFile(
                self.drive_path,
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                0,
                None
            )

            # 디스크 지오메트리 조회
            self._get_disk_geometry()

            self._is_open = True
            logger.info(f"Physical disk opened successfully: {self._disk_size / (1024**3):.2f} GB")

        except ImportError:
            raise DiskError("pywin32 not installed. Run: pip install pywin32")
        except pywintypes.error as e:
            error_code = e.winerror if hasattr(e, 'winerror') else e.args[0]
            if error_code == 5:  # ERROR_ACCESS_DENIED
                raise DiskPermissionError(
                    f"Access denied to {self.drive_path}. "
                    "Run as Administrator."
                )
            elif error_code == 2:  # ERROR_FILE_NOT_FOUND
                raise DiskNotFoundError(f"Disk not found: {self.drive_path}")
            else:
                raise DiskError(f"Failed to open {self.drive_path}: {e}")

    def _get_disk_geometry(self):
        """디스크 지오메트리 및 크기 조회"""
        try:
            import win32file
            import winioctlcon

            # IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
            geometry = win32file.DeviceIoControl(
                self._handle,
                winioctlcon.IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                None,
                256
            )

            # DISK_GEOMETRY_EX 구조체 파싱
            # Offset 0-24: DISK_GEOMETRY
            # Offset 24-32: DiskSize (LARGE_INTEGER)
            if len(geometry) >= 32:
                self._disk_size = struct.unpack('<Q', geometry[24:32])[0]

            # 섹터 크기 (offset 20-24 in DISK_GEOMETRY)
            if len(geometry) >= 24:
                self._sector_size = struct.unpack('<I', geometry[20:24])[0]
                if self._sector_size == 0:
                    self._sector_size = 512

        except Exception as e:
            logger.warning(f"Could not get disk geometry: {e}")
            self._sector_size = 512
            self._disk_size = 0

    def read(self, offset: int, size: int) -> bytes:
        """Raw 바이트 읽기"""
        if not self._is_open or not self._handle:
            raise DiskError("Disk not open")

        try:
            import win32file

            # 섹터 정렬
            aligned_offset = (offset // self._sector_size) * self._sector_size
            offset_in_sector = offset - aligned_offset
            aligned_size = ((offset_in_sector + size + self._sector_size - 1) //
                           self._sector_size) * self._sector_size

            # Seek
            win32file.SetFilePointer(self._handle, aligned_offset, win32file.FILE_BEGIN)

            # Read
            _, data = win32file.ReadFile(self._handle, aligned_size)

            # 요청된 범위 추출
            result = bytes(data[offset_in_sector:offset_in_sector + size])
            return result

        except Exception as e:
            raise DiskReadError(f"Read failed at offset {offset}: {e}")

    def get_disk_info(self) -> DiskInfo:
        """디스크 메타데이터 반환"""
        return DiskInfo(
            source_type=DiskSourceType.PHYSICAL_DISK,
            total_size=self._disk_size,
            sector_size=self._sector_size,
            source_path=self.drive_path,
            is_readonly=True
        )

    def get_size(self) -> int:
        """디스크 전체 크기"""
        return self._disk_size

    def close(self):
        """리소스 해제"""
        if self._handle:
            try:
                import win32file
                win32file.CloseHandle(self._handle)
                logger.debug(f"Closed physical disk: {self.drive_path}")
            except Exception as e:
                logger.warning(f"Error closing disk: {e}")
            finally:
                self._handle = None
                self._is_open = False


# ==============================================================================
# E01 Disk Backend (pyewf)
# ==============================================================================

class E01DiskBackend(UnifiedDiskReader):
    """
    E01/EWF 포렌식 이미지 백엔드

    pyewf 라이브러리를 사용하여 E01 이미지에 접근합니다.
    압축/분할된 E01 파일을 투명하게 처리합니다.

    Features:
    - E01, Ex01 다중 세그먼트 지원
    - 압축된 이미지 자동 해제
    - Raw sector 접근

    Usage:
        with E01DiskBackend("evidence.E01") as disk:
            mbr = disk.read(0, 512)
    """

    def __init__(self, e01_path: str):
        """
        Args:
            e01_path: 첫 번째 E01 세그먼트 파일 경로
        """
        super().__init__()

        self.e01_path = e01_path
        self._ewf_handle = None

        self._open()

    def _open(self):
        """E01 이미지 열기"""
        try:
            import pyewf

            # 모든 세그먼트 파일 찾기
            segments = self._find_segments(self.e01_path)
            if not segments:
                raise DiskNotFoundError(f"E01 file not found: {self.e01_path}")

            logger.info(f"Opening E01 image: {self.e01_path} ({len(segments)} segments)")

            # pyewf 핸들 열기
            self._ewf_handle = pyewf.handle()
            self._ewf_handle.open(segments)

            # 메타데이터 조회
            self._disk_size = self._ewf_handle.get_media_size()
            self._sector_size = 512  # EWF는 보통 512바이트 섹터

            self._is_open = True
            logger.info(f"E01 image opened: {self._disk_size / (1024**3):.2f} GB")

        except ImportError:
            raise DiskError("pyewf not installed. Run: pip install libewf-python")
        except Exception as e:
            raise DiskError(f"Failed to open E01: {e}")

    def _find_segments(self, e01_path: str) -> List[str]:
        """
        E01 세그먼트 파일 찾기

        E01, E02, E03... 또는 Ex01, Ex02... 패턴
        """
        import glob

        e01_path = str(e01_path)
        path = Path(e01_path)

        if not path.exists():
            return []

        # 확장자 패턴 분석
        ext = path.suffix.lower()
        base = str(path.with_suffix(''))

        if ext.startswith('.e') and len(ext) == 4:
            # .E01 패턴
            pattern = f"{base}.[Ee]*"
        elif ext.startswith('.ex') or ext.startswith('.Ex'):
            # .Ex01 패턴
            pattern = f"{base}.[Ee][Xx]*"
        else:
            # 단일 파일
            return [e01_path]

        segments = sorted(glob.glob(pattern))
        return segments if segments else [e01_path]

    def read(self, offset: int, size: int) -> bytes:
        """Raw 바이트 읽기"""
        if not self._is_open or not self._ewf_handle:
            raise DiskError("E01 image not open")

        try:
            self._ewf_handle.seek(offset)
            data = self._ewf_handle.read(size)
            return data
        except Exception as e:
            raise DiskReadError(f"E01 read failed at offset {offset}: {e}")

    def get_disk_info(self) -> DiskInfo:
        """디스크 메타데이터 반환"""
        info = DiskInfo(
            source_type=DiskSourceType.E01_IMAGE,
            total_size=self._disk_size,
            sector_size=self._sector_size,
            source_path=self.e01_path,
            is_readonly=True
        )

        # EWF 메타데이터 추가
        if self._ewf_handle:
            try:
                # 가능한 경우 추가 메타데이터 조회
                pass  # pyewf 버전에 따라 다름
            except:
                pass

        return info

    def get_size(self) -> int:
        """디스크 전체 크기"""
        return self._disk_size

    def close(self):
        """리소스 해제"""
        if self._ewf_handle:
            try:
                self._ewf_handle.close()
                logger.debug(f"Closed E01 image: {self.e01_path}")
            except Exception as e:
                logger.warning(f"Error closing E01: {e}")
            finally:
                self._ewf_handle = None
                self._is_open = False


# ==============================================================================
# RAW Image Backend
# ==============================================================================

class RAWImageBackend(UnifiedDiskReader):
    """
    RAW/DD 이미지 파일 백엔드

    dd로 생성된 raw 디스크 이미지 파일에 접근합니다.

    Features:
    - 단순 파일 I/O
    - .dd, .raw, .img, .bin 등 지원
    - 메모리 매핑 옵션 (대용량 파일)

    Usage:
        with RAWImageBackend("disk.dd") as disk:
            mbr = disk.read(0, 512)
    """

    def __init__(self, image_path: str, use_mmap: bool = False):
        """
        Args:
            image_path: RAW 이미지 파일 경로
            use_mmap: 메모리 매핑 사용 여부 (대용량 파일에 유용)
        """
        super().__init__()

        self.image_path = image_path
        self._file = None
        self._mmap = None
        self._use_mmap = use_mmap

        self._open()

    def _open(self):
        """이미지 파일 열기"""
        if not os.path.exists(self.image_path):
            raise DiskNotFoundError(f"Image file not found: {self.image_path}")

        try:
            logger.info(f"Opening RAW image: {self.image_path}")

            self._file = open(self.image_path, 'rb')

            # 파일 크기 조회
            self._file.seek(0, 2)
            self._disk_size = self._file.tell()
            self._file.seek(0)

            # 메모리 매핑 (선택적)
            if self._use_mmap and self._disk_size > 0:
                import mmap
                self._mmap = mmap.mmap(
                    self._file.fileno(),
                    0,
                    access=mmap.ACCESS_READ
                )

            self._sector_size = 512
            self._is_open = True
            logger.info(f"RAW image opened: {self._disk_size / (1024**3):.2f} GB")

        except Exception as e:
            raise DiskError(f"Failed to open RAW image: {e}")

    def read(self, offset: int, size: int) -> bytes:
        """Raw 바이트 읽기"""
        if not self._is_open:
            raise DiskError("Image not open")

        try:
            if self._mmap:
                # 메모리 매핑 사용
                end = min(offset + size, self._disk_size)
                return bytes(self._mmap[offset:end])
            else:
                # 일반 파일 I/O
                self._file.seek(offset)
                return self._file.read(size)
        except Exception as e:
            raise DiskReadError(f"RAW read failed at offset {offset}: {e}")

    def get_disk_info(self) -> DiskInfo:
        """디스크 메타데이터 반환"""
        return DiskInfo(
            source_type=DiskSourceType.RAW_IMAGE,
            total_size=self._disk_size,
            sector_size=self._sector_size,
            source_path=self.image_path,
            is_readonly=True
        )

    def get_size(self) -> int:
        """디스크 전체 크기"""
        return self._disk_size

    def close(self):
        """리소스 해제"""
        if self._mmap:
            try:
                self._mmap.close()
            except:
                pass
            self._mmap = None

        if self._file:
            try:
                self._file.close()
                logger.debug(f"Closed RAW image: {self.image_path}")
            except:
                pass
            self._file = None

        self._is_open = False


# ==============================================================================
# Factory Function
# ==============================================================================

def create_disk_backend(source: str) -> UnifiedDiskReader:
    """
    디스크 백엔드 자동 생성

    소스 타입을 자동 감지하여 적절한 백엔드를 생성합니다.

    Args:
        source: 디스크 소스
            - 숫자 문자열: 물리 드라이브 번호 (예: "0", "1")
            - .e01/.ex01 파일: E01 이미지
            - 기타 파일: RAW 이미지

    Returns:
        UnifiedDiskReader 인스턴스

    Usage:
        with create_disk_backend("0") as disk:  # PhysicalDrive0
            ...

        with create_disk_backend("evidence.E01") as disk:  # E01
            ...
    """
    source = str(source)

    # 숫자 = 물리 드라이브
    if source.isdigit():
        return PhysicalDiskBackend(int(source))

    # 파일 확장자 확인
    ext = Path(source).suffix.lower()

    if ext in ('.e01', '.ex01', '.s01', '.l01'):
        return E01DiskBackend(source)
    else:
        return RAWImageBackend(source)


# ==============================================================================
# Test
# ==============================================================================

if __name__ == '__main__':
    import sys

    print("=" * 60)
    print("Disk Backend Test")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python disk_backends.py 0              # PhysicalDrive0")
        print("  python disk_backends.py evidence.E01   # E01 image")
        print("  python disk_backends.py disk.dd        # RAW image")
        sys.exit(1)

    source = sys.argv[1]

    try:
        with create_disk_backend(source) as disk:
            info = disk.get_disk_info()
            print(f"\n[Disk Info]")
            print(f"  Type: {info.source_type.value}")
            print(f"  Size: {info.total_size / (1024**3):.2f} GB")
            print(f"  Sector Size: {info.sector_size} bytes")
            print(f"  Path: {info.source_path}")

            # MBR 읽기
            print(f"\n[MBR Test]")
            mbr = disk.read(0, 512)
            print(f"  Read {len(mbr)} bytes")

            # MBR 시그니처 확인
            if len(mbr) >= 512:
                signature = struct.unpack('<H', mbr[510:512])[0]
                print(f"  MBR Signature: 0x{signature:04X} ({'OK' if signature == 0xAA55 else 'INVALID'})")

                # 파티션 타입 확인
                for i in range(4):
                    ptype = mbr[446 + i*16 + 4]
                    if ptype != 0:
                        print(f"  Partition {i}: Type 0x{ptype:02X}")

            print("\n[Test Complete]")

    except Exception as e:
        print(f"\n[Error] {e}")
        import traceback
        traceback.print_exc()
