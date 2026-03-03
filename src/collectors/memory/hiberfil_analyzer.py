"""
hiberfil.sys Analyzer

Module for analyzing Windows Hibernation files (hiberfil.sys)
- Hibernation file type detection (HIBR/WAKE)
- Header parsing
- Decompression (XPRESS/LZ77)
- Memory page extraction
- String and artifact searching

References:
- Windows Hibernation file structure
- XPRESS compression algorithm (MS-XCA)
- Volatility3 hibernation layer

Raw Disk Access Support:
- Raw sector-based hiberfil reading via ForensicDiskAccessor
- Complete bypass of Windows file locks
- Works identically with E01 images
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
    """hiberfil.sys Analyzer"""

    # Hibernation file signatures
    HIBR_SIGNATURE = b'hibr'       # Full Hibernation
    RSTR_SIGNATURE = b'rstr'       # Resume (restoring)
    WAKE_SIGNATURE = b'wake'       # Fast Startup (Windows 8+)

    # Header sizes by Windows version
    HEADER_SIZE_XP = 4096
    HEADER_SIZE_VISTA = 4096
    HEADER_SIZE_WIN7 = 4096
    HEADER_SIZE_WIN8 = 4096
    HEADER_SIZE_WIN10 = 4096

    # XPRESS compression related
    XPRESS_MAGIC = b'\x81\x81'     # XPRESS compressed block signature
    PAGE_SIZE = 4096

    # PO_MEMORY_IMAGE structure offsets (varies by Windows version)
    # Based on Windows 10
    HIBERNATION_HEADER_OFFSETS = {
        'signature': 0,           # 4 bytes
        'version': 4,             # 4 bytes
        'checksum': 8,            # 4 bytes
        'length': 12,             # 4 bytes (uncompressed size)
        'num_pages': 16,          # 8 bytes
        'highest_page': 24,       # 8 bytes
        'system_time': 48,        # 8 bytes (FILETIME)
    }

    def __init__(self, hiberfil_path: str = None, hiberfil_data: bytes = None):
        """
        Args:
            hiberfil_path: Path to hiberfil.sys file
            hiberfil_data: hiberfil binary data (when provided directly)
        """
        self.hiberfil_path = hiberfil_path
        self.hiberfil_data = hiberfil_data
        self.file_size = 0

        # Header information
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
        """Read data"""
        if self.hiberfil_data:
            return self.hiberfil_data[offset:offset + size]

        with open(self.hiberfil_path, 'rb') as f:
            f.seek(offset)
            return f.read(size)

    def detect_type(self) -> str:
        """
        Detect hibernation file type

        Returns:
            'HIBR': Full Hibernation
            'WAKE': Fast Startup (Windows 8+)
            'RSTR': Resume in progress (restoring)
            'UNKNOWN': Unknown
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
        Parse hibernation header

        Returns:
            Header information dictionary
        """
        header = self._read(0, self.PAGE_SIZE)

        self.signature = header[:4]
        hiberfil_type = self.detect_type()

        # Version
        self.version = struct.unpack('<I', header[4:8])[0]

        # Checksum
        checksum = struct.unpack('<I', header[8:12])[0]

        # Uncompressed length
        length = struct.unpack('<I', header[12:16])[0]

        # Page count (offset varies by Windows version)
        # Typically at offset 16 or 24
        try:
            num_pages = struct.unpack('<Q', header[16:24])[0]
            self.num_pages = num_pages
        except:
            num_pages = 0

        # Highest page number
        try:
            highest_page = struct.unpack('<Q', header[24:32])[0]
        except:
            highest_page = 0

        # System time (FILETIME)
        try:
            system_time = struct.unpack('<Q', header[48:56])[0]
            if system_time > 0:
                # FILETIME to datetime
                # FILETIME is in 100-nanosecond units since January 1, 1601
                epoch_diff = 116444736000000000  # Difference between 1601 and 1970 in 100ns units
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
        XPRESS decompression (LZ77-based)

        Windows Vista+ Hibernation files use XPRESS compression
        Decompression implementation is complex, requiring external library or custom implementation

        Args:
            compressed_data: Compressed data

        Returns:
            Decompressed data or None
        """
        # Method 1: Try enhanced HiberfilDecompressor (Pure Python, cross-platform)
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

        # Method 2: Try lznt1 library
        try:
            import lznt1
            return lznt1.decompress(compressed_data)
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"lznt1 failed: {e}")

        # Method 3: Try dissect.xpress
        try:
            from dissect import xpress
            return xpress.decompress(compressed_data)
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"dissect.xpress failed: {e}")

        # Method 4: Try Windows API (Windows only)
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

            # Expected decompressed size (up to 4x)
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

        logger.warning("XPRESS decompression failed - all methods attempted")
        logger.warning("Recommended install: pip install dissect.xpress or pip install lznt1")
        return None

    def extract_memory_pages(self, max_pages: int = 0) -> Generator[Tuple[int, bytes], None, None]:
        """
        Extract memory pages

        Note: Complete implementation requires Windows version-specific structure parsing
        Reference to Volatility3's hibernation layer is recommended

        Args:
            max_pages: Maximum number of pages to extract (0 = all)

        Yields:
            (page_number, page_data) tuple
        """
        _debug_print(f"[Hiberfil] Extracting memory pages (type: {self.hiberfil_type})...")

        # Start after header
        offset = self.PAGE_SIZE
        page_count = 0

        while offset < self.file_size:
            if max_pages > 0 and page_count >= max_pages:
                break

            # Read page data
            page_data = self._read(offset, self.PAGE_SIZE)
            if len(page_data) < self.PAGE_SIZE:
                break

            # Check for XPRESS compression
            if page_data[:2] == self.XPRESS_MAGIC:
                # Attempt decompression
                decompressed = self.decompress_xpress(page_data)
                if decompressed:
                    yield (page_count, decompressed)
                else:
                    # Provide original data if decompression fails
                    yield (page_count, page_data)
            else:
                yield (page_count, page_data)

            page_count += 1
            offset += self.PAGE_SIZE

            if page_count % 10000 == 0:
                _debug_print(f"[Hiberfil] {page_count:,} pages processed...")

        _debug_print(f"[Hiberfil] Total {page_count:,} pages extracted")

    def find_strings(
        self,
        min_length: int = 8,
        max_pages: int = 10000
    ) -> Generator[Dict, None, None]:
        """
        Search for strings in hiberfil

        Args:
            min_length: Minimum string length
            max_pages: Maximum number of pages to search

        Yields:
            String information dictionary
        """
        _debug_print(f"[Hiberfil] Searching for strings (max {max_pages} pages)...")

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

        _debug_print(f"[Hiberfil] {total_strings:,} strings found")

    def find_urls(self, max_pages: int = 10000) -> List[Dict]:
        """
        Search for URLs in hiberfil

        Args:
            max_pages: Maximum number of pages to search

        Returns:
            List of URL information
        """
        _debug_print(f"[Hiberfil] Searching for URLs...")

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

        _debug_print(f"[Hiberfil] {len(urls):,} URLs found")
        return urls

    def find_processes(self, max_pages: int = 10000) -> List[Dict]:
        """
        Search for process information in hiberfil

        Searches for EPROCESS structure signatures
        Note: Structure varies by Windows version

        Args:
            max_pages: Maximum number of pages to search

        Returns:
            List of process information (basic pattern matching)
        """
        _debug_print(f"[Hiberfil] Searching for process information...")

        # .exe filename pattern
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

        _debug_print(f"[Hiberfil] {len(processes):,} executable filenames found")
        return processes

    def analyze_all(self, max_pages: int = 10000) -> Dict:
        """
        Perform full analysis

        Args:
            max_pages: Maximum number of pages to analyze

        Returns:
            Analysis results dictionary
        """
        _debug_print(f"[Hiberfil] Starting full analysis (size: {self.file_size / 1024 / 1024:.1f} MB)...")

        # Parse header
        header_info = self.parse_header()

        if not header_info['is_valid']:
            _debug_print(f"[Hiberfil] Invalid hiberfil: {header_info['signature']}")
            return {'error': 'Invalid hibernation file', 'header': header_info}

        results = {
            'file_path': self.hiberfil_path,
            'file_size': self.file_size,
            'header': header_info,
            'urls': self.find_urls(max_pages),
            'processes': self.find_processes(max_pages),
            'analysis_time': datetime.now().isoformat(),
        }

        # Summary
        results['summary'] = {
            'type': header_info['type'],
            'total_urls': len(results['urls']),
            'total_processes': len(results['processes']),
        }

        _debug_print(f"[Hiberfil] Analysis complete:")
        for key, value in results['summary'].items():
            _debug_print(f"  - {key}: {value}")

        return results


class SwapfileAnalyzer:
    """swapfile.sys Analyzer (for Windows 10+ UWP apps)"""

    PAGE_SIZE = 4096

    def __init__(self, swapfile_path: str = None, swapfile_data: bytes = None):
        """
        Args:
            swapfile_path: Path to swapfile.sys file
            swapfile_data: swapfile binary data
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
        Basic swapfile analysis

        swapfile.sys has a similar structure to pagefile.sys
        Stores memory pages for UWP apps

        Returns:
            Analysis results
        """
        _debug_print(f"[Swapfile] Starting analysis (size: {self.file_size / 1024 / 1024:.1f} MB)...")

        # Process similarly to pagefile analyzer
        from .pagefile_analyzer import PagefileAnalyzer

        if self.swapfile_path:
            analyzer = PagefileAnalyzer(pagefile_path=self.swapfile_path)
        else:
            analyzer = PagefileAnalyzer(pagefile_data=self.swapfile_data)

        # Perform basic analysis
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

        _debug_print(f"[Swapfile] Analysis complete")
        return results


def analyze_hiberfil_from_image(img_info, hiberfil_offset: int, hiberfil_size: int) -> Dict:
    """
    Analyze hiberfil from disk image

    Args:
        img_info: Image handle
        hiberfil_offset: hiberfil start offset
        hiberfil_size: hiberfil size

    Returns:
        Analysis results
    """
    _debug_print(f"[Hiberfil] Reading hiberfil from image (offset={hiberfil_offset})...")

    # Size limit (memory protection)
    max_size = min(hiberfil_size, 1024 * 1024 * 1024)  # Max 1GB

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
    Create HiberfilAnalyzer via Raw Disk Access

    Completely bypasses Windows file locks to read hiberfil.sys.
    Administrator privileges required.

    Args:
        drive_number: Physical disk number (default: 0)
        partition_index: Partition index (None for first NTFS partition)
        max_size_mb: Maximum read size in MB (default: 1024MB)

    Returns:
        HiberfilAnalyzer instance or None

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

    _debug_print(f"[Hiberfil] Starting hiberfil.sys read via Raw Disk Access...")

    try:
        with ForensicDiskAccessor.from_physical_disk(drive_number) as disk:
            partitions = disk.list_partitions()

            if not partitions:
                logger.error("No partitions found")
                return None

            # Select partition
            if partition_index is not None:
                if partition_index >= len(partitions):
                    logger.error(f"Invalid partition index: {partition_index}")
                    return None
                disk.select_partition(partition_index)
            else:
                # Auto-select first NTFS partition
                ntfs_idx = None
                for i, p in enumerate(partitions):
                    if p.filesystem == 'NTFS':
                        ntfs_idx = i
                        break

                if ntfs_idx is None:
                    logger.error("No NTFS partition found")
                    return None

                disk.select_partition(ntfs_idx)
                _debug_print(f"[Hiberfil] Selected partition {ntfs_idx} (NTFS)")

            # Stream read hiberfil.sys (with size limit)
            hiberfil_path = '/hiberfil.sys'
            max_size = max_size_mb * 1024 * 1024

            _debug_print(f"[Hiberfil] Streaming hiberfil.sys data (max {max_size_mb} MB)...")

            chunks = []
            total_size = 0

            for chunk in disk.stream_file(hiberfil_path, chunk_size=64 * 1024 * 1024):
                chunks.append(chunk)
                total_size += len(chunk)
                _debug_print(f"[Hiberfil] Read progress: {total_size / 1024 / 1024:.1f} MB")

                if total_size >= max_size:
                    _debug_print(f"[Hiberfil] Max size reached ({max_size_mb} MB)")
                    break

            hiberfil_data = b''.join(chunks)
            _debug_print(f"[Hiberfil] Total {len(hiberfil_data) / 1024 / 1024:.1f} MB read complete [raw disk]")

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
    Create HiberfilAnalyzer from E01 image

    Args:
        e01_path: E01 file path
        partition_index: Partition index (None for first NTFS partition)
        max_size_mb: Maximum read size in MB

    Returns:
        HiberfilAnalyzer instance or None

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

    _debug_print(f"[Hiberfil] Starting hiberfil.sys read from E01 image...")
    _debug_print(f"[Hiberfil] E01 path: {e01_path}")

    try:
        with ForensicDiskAccessor.from_e01(e01_path) as disk:
            partitions = disk.list_partitions()

            if not partitions:
                logger.error("No partitions found in E01 image")
                return None

            # Select partition
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
                _debug_print(f"[Hiberfil] Selected partition {ntfs_idx} (NTFS)")

            hiberfil_path = '/hiberfil.sys'
            max_size = max_size_mb * 1024 * 1024

            _debug_print(f"[Hiberfil] Streaming hiberfil.sys data (max {max_size_mb} MB)...")

            chunks = []
            total_size = 0

            for chunk in disk.stream_file(hiberfil_path, chunk_size=64 * 1024 * 1024):
                chunks.append(chunk)
                total_size += len(chunk)
                _debug_print(f"[Hiberfil] Read progress: {total_size / 1024 / 1024:.1f} MB")

                if total_size >= max_size:
                    _debug_print(f"[Hiberfil] Max size reached ({max_size_mb} MB)")
                    break

            hiberfil_data = b''.join(chunks)
            _debug_print(f"[Hiberfil] Total {len(hiberfil_data) / 1024 / 1024:.1f} MB read complete [E01]")

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
    Create SwapfileAnalyzer via Raw Disk Access

    Reads swapfile.sys for Windows 10+ UWP apps.

    Args:
        drive_number: Physical disk number
        partition_index: Partition index

    Returns:
        SwapfileAnalyzer instance or None
    """
    try:
        from core.engine.collectors.filesystem.forensic_disk_accessor import ForensicDiskAccessor
    except ImportError:
        logger.error("ForensicDiskAccessor not available")
        return None

    _debug_print(f"[Swapfile] Starting swapfile.sys read via Raw Disk Access...")

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

            _debug_print(f"[Swapfile] Reading swapfile.sys data...")

            chunks = []
            total_size = 0

            for chunk in disk.stream_file(swapfile_path, chunk_size=64 * 1024 * 1024):
                chunks.append(chunk)
                total_size += len(chunk)
                _debug_print(f"[Swapfile] Read progress: {total_size / 1024 / 1024:.1f} MB")

            swapfile_data = b''.join(chunks)
            _debug_print(f"[Swapfile] Total {len(swapfile_data) / 1024 / 1024:.1f} MB read complete [raw disk]")

            return SwapfileAnalyzer(swapfile_data=swapfile_data)

    except Exception as e:
        logger.error(f"Raw disk swapfile read error: {e}")
        return None


if __name__ == "__main__":
    print("=" * 60)
    print("Hiberfil Analyzer Test")
    print("=" * 60)

    print("Usage:")
    print("  # Hibernation file analysis")
    print("  analyzer = HiberfilAnalyzer('C:\\hiberfil.sys')")
    print("  header = analyzer.parse_header()")
    print("  results = analyzer.analyze_all()")
    print()
    print("  # Swapfile analysis")
    print("  analyzer = SwapfileAnalyzer('C:\\swapfile.sys')")
    print("  results = analyzer.analyze()")
