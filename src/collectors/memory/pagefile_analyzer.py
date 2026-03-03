"""
pagefile.sys Analyzer

Module for analyzing Windows Page Files (pagefile.sys)
- String extraction (ASCII/Unicode)
- URL pattern search
- Email address search
- IP address search
- File path search
- Registry key search

Reference: Windows Page File structure
- 4KB page units
- Contains data swapped from memory
- Deleted data recovery possible

Raw Disk Access Support:
- Raw sector-based pagefile reading via ForensicDiskAccessor
- Complete bypass of Windows file locks
- Works identically with E01 images
"""

import re
import mmap
import struct
import logging
from typing import Dict, List, Optional, Generator, Set
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

# Debug output control
_DEBUG_OUTPUT = False
def _debug_print(msg): 
    if _DEBUG_OUTPUT: _debug_print(msg)


class PagefileAnalyzer:
    """pagefile.sys Analyzer"""

    PAGE_SIZE = 4096  # Windows default page size
    CHUNK_SIZE = 1024 * 1024 * 64  # 64MB chunk processing (memory efficient)

    # Regular expression patterns
    PATTERNS = {
        'url': re.compile(
            rb'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
            re.IGNORECASE
        ),
        'email': re.compile(
            rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            re.IGNORECASE
        ),
        'ipv4': re.compile(
            rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            rb'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        'ipv6': re.compile(
            rb'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        ),
        'windows_path': re.compile(
            rb'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
            re.IGNORECASE
        ),
        'registry_key': re.compile(
            rb'(?:HKEY_[A-Z_]+|HK[CLMCU]{2})\\[^\x00\r\n]+',
            re.IGNORECASE
        ),
        'guid': re.compile(
            rb'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-'
            rb'[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'
        ),
        'credit_card': re.compile(
            rb'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|'
            rb'3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
        ),
        'ssn': re.compile(
            rb'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'
        ),
    }

    # Common system URLs to exclude
    EXCLUDED_URLS = {
        b'http://www.w3.org',
        b'http://schemas.microsoft.com',
        b'http://schemas.xmlsoap.org',
        b'http://www.microsoft.com',
        b'https://www.microsoft.com',
    }

    def __init__(self, pagefile_path: str = None, pagefile_data: bytes = None):
        """
        Args:
            pagefile_path: Path to pagefile.sys file
            pagefile_data: pagefile binary data (when provided directly)
        """
        self.pagefile_path = pagefile_path
        self.pagefile_data = pagefile_data
        self.file_size = 0
        self._mmap = None

        if pagefile_path:
            path = Path(pagefile_path)
            if path.exists():
                self.file_size = path.stat().st_size
            else:
                logger.warning(f"Pagefile not found: {pagefile_path}")

        if pagefile_data:
            self.file_size = len(pagefile_data)

    def __enter__(self):
        """Context manager entry"""
        if self.pagefile_path and Path(self.pagefile_path).exists():
            self._file = open(self.pagefile_path, 'rb')
            try:
                self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
            except Exception as e:
                logger.warning(f"Memory mapping failed, using file read: {e}")
                self._mmap = None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if self._mmap:
            self._mmap.close()
        if hasattr(self, '_file'):
            self._file.close()

    def _read_chunk(self, offset: int, size: int) -> bytes:
        """Read data chunk"""
        if self.pagefile_data:
            return self.pagefile_data[offset:offset + size]

        if self._mmap:
            return self._mmap[offset:offset + size]

        with open(self.pagefile_path, 'rb') as f:
            f.seek(offset)
            return f.read(size)

    def extract_strings(
        self,
        min_length: int = 8,
        max_length: int = 1024,
        string_type: str = 'both'
    ) -> Generator[Dict, None, None]:
        """
        Extract strings from pagefile

        Args:
            min_length: Minimum string length
            max_length: Maximum string length
            string_type: 'ascii', 'unicode', 'both'

        Yields:
            {
                'type': 'ascii' | 'unicode',
                'string': str,
                'offset': int,
                'page_num': int,
            }
        """
        _debug_print(f"[Pagefile] Starting string extraction (min_len={min_length})...")

        # ASCII string pattern
        ascii_pattern = re.compile(
            rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        )

        # Unicode (UTF-16-LE) string pattern
        unicode_pattern = re.compile(
            rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
        )

        total_strings = 0
        offset = 0

        while offset < self.file_size:
            chunk = self._read_chunk(offset, self.CHUNK_SIZE)
            if not chunk:
                break

            # ASCII strings
            if string_type in ['ascii', 'both']:
                for match in ascii_pattern.finditer(chunk):
                    string = match.group()
                    if len(string) <= max_length:
                        abs_offset = offset + match.start()
                        yield {
                            'type': 'ascii',
                            'string': string.decode('ascii', errors='ignore'),
                            'offset': abs_offset,
                            'page_num': abs_offset // self.PAGE_SIZE,
                        }
                        total_strings += 1

            # Unicode strings
            if string_type in ['unicode', 'both']:
                for match in unicode_pattern.finditer(chunk):
                    string = match.group()
                    if len(string) <= max_length * 2:
                        try:
                            decoded = string.decode('utf-16-le', errors='ignore')
                            if len(decoded) >= min_length:
                                abs_offset = offset + match.start()
                                yield {
                                    'type': 'unicode',
                                    'string': decoded,
                                    'offset': abs_offset,
                                    'page_num': abs_offset // self.PAGE_SIZE,
                                }
                                total_strings += 1
                        except:
                            pass

            offset += self.CHUNK_SIZE - 1024  # Handle boundary overlap

        _debug_print(f"[Pagefile] Total {total_strings:,} strings extracted")

    def find_urls(self, unique_only: bool = True) -> List[Dict]:
        """
        Search for URL patterns

        Args:
            unique_only: Whether to remove duplicates

        Returns:
            List of URL information
        """
        _debug_print("[Pagefile] Searching for URLs...")

        urls = []
        seen: Set[bytes] = set()

        offset = 0
        while offset < self.file_size:
            chunk = self._read_chunk(offset, self.CHUNK_SIZE)
            if not chunk:
                break

            for match in self.PATTERNS['url'].finditer(chunk):
                url = match.group()

                # Check exclusion list
                if any(url.startswith(exc) for exc in self.EXCLUDED_URLS):
                    continue

                # Check for duplicates
                if unique_only and url in seen:
                    continue

                seen.add(url)
                abs_offset = offset + match.start()

                urls.append({
                    'url': url.decode('utf-8', errors='ignore'),
                    'offset': abs_offset,
                    'page_num': abs_offset // self.PAGE_SIZE,
                })

            offset += self.CHUNK_SIZE - 2048

        _debug_print(f"[Pagefile] {len(urls):,} URLs found")
        return urls

    def find_emails(self, unique_only: bool = True) -> List[Dict]:
        """
        Search for email addresses

        Args:
            unique_only: Whether to remove duplicates

        Returns:
            List of email information
        """
        _debug_print("[Pagefile] Searching for email addresses...")

        emails = []
        seen: Set[bytes] = set()

        offset = 0
        while offset < self.file_size:
            chunk = self._read_chunk(offset, self.CHUNK_SIZE)
            if not chunk:
                break

            for match in self.PATTERNS['email'].finditer(chunk):
                email = match.group()

                if unique_only and email in seen:
                    continue

                seen.add(email)
                abs_offset = offset + match.start()

                emails.append({
                    'email': email.decode('utf-8', errors='ignore'),
                    'offset': abs_offset,
                    'page_num': abs_offset // self.PAGE_SIZE,
                })

            offset += self.CHUNK_SIZE - 512

        _debug_print(f"[Pagefile] {len(emails):,} email addresses found")
        return emails

    def find_ip_addresses(self, unique_only: bool = True) -> List[Dict]:
        """
        Search for IP addresses (IPv4, IPv6)

        Returns:
            List of IP address information
        """
        _debug_print("[Pagefile] Searching for IP addresses...")

        ips = []
        seen: Set[bytes] = set()

        offset = 0
        while offset < self.file_size:
            chunk = self._read_chunk(offset, self.CHUNK_SIZE)
            if not chunk:
                break

            # IPv4
            for match in self.PATTERNS['ipv4'].finditer(chunk):
                ip = match.group()

                # Exclude common internal IPs (optional)
                ip_str = ip.decode('ascii')
                # if ip_str.startswith(('127.', '0.', '255.')):
                #     continue

                if unique_only and ip in seen:
                    continue

                seen.add(ip)
                abs_offset = offset + match.start()

                ips.append({
                    'ip': ip_str,
                    'type': 'IPv4',
                    'offset': abs_offset,
                    'page_num': abs_offset // self.PAGE_SIZE,
                })

            # IPv6
            for match in self.PATTERNS['ipv6'].finditer(chunk):
                ip = match.group()

                if unique_only and ip in seen:
                    continue

                seen.add(ip)
                abs_offset = offset + match.start()

                ips.append({
                    'ip': ip.decode('ascii'),
                    'type': 'IPv6',
                    'offset': abs_offset,
                    'page_num': abs_offset // self.PAGE_SIZE,
                })

            offset += self.CHUNK_SIZE - 256

        _debug_print(f"[Pagefile] {len(ips):,} IP addresses found")
        return ips

    def find_file_paths(self, unique_only: bool = True) -> List[Dict]:
        """
        Search for Windows file paths

        Returns:
            List of file path information
        """
        _debug_print("[Pagefile] Searching for file paths...")

        paths = []
        seen: Set[bytes] = set()

        offset = 0
        while offset < self.file_size:
            chunk = self._read_chunk(offset, self.CHUNK_SIZE)
            if not chunk:
                break

            for match in self.PATTERNS['windows_path'].finditer(chunk):
                path = match.group()

                if len(path) < 10:  # Exclude paths that are too short
                    continue

                if unique_only and path in seen:
                    continue

                seen.add(path)
                abs_offset = offset + match.start()

                try:
                    path_str = path.decode('utf-8', errors='ignore')
                except:
                    path_str = path.decode('cp949', errors='ignore')

                paths.append({
                    'path': path_str,
                    'offset': abs_offset,
                    'page_num': abs_offset // self.PAGE_SIZE,
                })

            offset += self.CHUNK_SIZE - 1024

        _debug_print(f"[Pagefile] {len(paths):,} file paths found")
        return paths

    def find_registry_keys(self, unique_only: bool = True) -> List[Dict]:
        """
        Search for registry keys

        Returns:
            List of registry key information
        """
        _debug_print("[Pagefile] Searching for registry keys...")

        keys = []
        seen: Set[bytes] = set()

        offset = 0
        while offset < self.file_size:
            chunk = self._read_chunk(offset, self.CHUNK_SIZE)
            if not chunk:
                break

            for match in self.PATTERNS['registry_key'].finditer(chunk):
                key = match.group()

                if len(key) < 15:  # Exclude keys that are too short
                    continue

                if unique_only and key in seen:
                    continue

                seen.add(key)
                abs_offset = offset + match.start()

                keys.append({
                    'key': key.decode('utf-8', errors='ignore'),
                    'offset': abs_offset,
                    'page_num': abs_offset // self.PAGE_SIZE,
                })

            offset += self.CHUNK_SIZE - 1024

        _debug_print(f"[Pagefile] {len(keys):,} registry keys found")
        return keys

    def find_sensitive_data(self) -> Dict[str, List]:
        """
        Search for sensitive data (credit cards, SSN, etc.)

        Returns:
            List of sensitive data by category
        """
        _debug_print("[Pagefile] Searching for sensitive data...")

        results = {
            'credit_cards': [],
            'ssn': [],
            'guids': [],
        }

        offset = 0
        while offset < self.file_size:
            chunk = self._read_chunk(offset, self.CHUNK_SIZE)
            if not chunk:
                break

            # Credit card numbers
            for match in self.PATTERNS['credit_card'].finditer(chunk):
                cc = match.group()
                abs_offset = offset + match.start()
                results['credit_cards'].append({
                    'number': cc.decode('ascii'),
                    'offset': abs_offset,
                    'page_num': abs_offset // self.PAGE_SIZE,
                })

            # SSN (US Social Security Number)
            for match in self.PATTERNS['ssn'].finditer(chunk):
                ssn = match.group()
                abs_offset = offset + match.start()
                results['ssn'].append({
                    'ssn': ssn.decode('ascii'),
                    'offset': abs_offset,
                    'page_num': abs_offset // self.PAGE_SIZE,
                })

            # GUID
            for match in self.PATTERNS['guid'].finditer(chunk):
                guid = match.group()
                abs_offset = offset + match.start()
                results['guids'].append({
                    'guid': guid.decode('ascii'),
                    'offset': abs_offset,
                    'page_num': abs_offset // self.PAGE_SIZE,
                })

            offset += self.CHUNK_SIZE - 256

        _debug_print(f"[Pagefile] Sensitive data: CC={len(results['credit_cards'])}, "
              f"SSN={len(results['ssn'])}, GUID={len(results['guids'])}")

        return results

    def analyze_all(self) -> Dict:
        """
        Perform full analysis

        Returns:
            Analysis results dictionary
        """
        _debug_print(f"[Pagefile] Starting full analysis (size: {self.file_size / 1024 / 1024:.1f} MB)...")

        results = {
            'file_path': self.pagefile_path,
            'file_size': self.file_size,
            'page_count': self.file_size // self.PAGE_SIZE,
            'urls': self.find_urls(),
            'emails': self.find_emails(),
            'ip_addresses': self.find_ip_addresses(),
            'file_paths': self.find_file_paths(),
            'registry_keys': self.find_registry_keys(),
            'sensitive_data': self.find_sensitive_data(),
            'analysis_time': datetime.now().isoformat(),
        }

        # Summary statistics
        results['summary'] = {
            'total_urls': len(results['urls']),
            'total_emails': len(results['emails']),
            'total_ips': len(results['ip_addresses']),
            'total_paths': len(results['file_paths']),
            'total_registry_keys': len(results['registry_keys']),
            'total_credit_cards': len(results['sensitive_data']['credit_cards']),
            'total_ssns': len(results['sensitive_data']['ssn']),
        }

        _debug_print(f"[Pagefile] Analysis complete:")
        for key, value in results['summary'].items():
            _debug_print(f"  - {key}: {value:,}")

        return results

    def scan_with_yara(
        self,
        custom_rules_path: Optional[str] = None,
        include_default: bool = True,
        progress_callback=None
    ) -> Dict:
        """
        IOC scanning using YARA rules

        Args:
            custom_rules_path: Path to custom YARA rules directory
            include_default: Whether to include default rules (default: True)
            progress_callback: Progress callback (message, progress 0.0-1.0)

        Returns:
            YARA scan results:
            - total_matches: Total number of matches
            - matches_by_rule: Matches by rule
            - matches_by_severity: Matches by severity
            - critical_matches: List of critical matches
            - high_matches: List of high severity matches
            - medium_matches: List of medium severity matches
            - low_matches: List of low severity matches
        """
        try:
            from .yara_scanner import YaraScanner

            scanner = YaraScanner(
                custom_rules_path=custom_rules_path,
                include_default=include_default
            )

            if not scanner.is_available():
                logger.warning("YARA not available. Install with: pip install yara-python")
                return {'error': 'YARA not available', 'total_matches': 0}

            rules_count = scanner.load_rules()
            if rules_count == 0:
                return {'error': 'No YARA rules loaded', 'total_matches': 0}

            _debug_print(f"[Pagefile] Starting YARA scan ({rules_count} rule files)...")

            results = scanner.scan_pagefile(
                self,
                progress_callback=progress_callback
            )

            # Output results summary
            total = results.get('total_matches', 0)
            critical = len(results.get('critical_matches', []))
            high = len(results.get('high_matches', []))
            medium = len(results.get('medium_matches', []))

            _debug_print(f"[Pagefile] YARA scan complete: {total} matches")
            if critical > 0:
                _debug_print(f"  [CRITICAL] {critical} critical detections")
            if high > 0:
                _debug_print(f"  [HIGH] {high} high severity detections")
            if medium > 0:
                _debug_print(f"  [MEDIUM] {medium} medium severity detections")

            return results

        except ImportError as e:
            logger.warning(f"YARA scanner not available: {e}")
            return {'error': str(e), 'total_matches': 0}
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            return {'error': str(e), 'total_matches': 0}


def analyze_pagefile_from_image(img_info, pagefile_offset: int, pagefile_size: int) -> Dict:
    """
    Analyze pagefile from disk image

    Args:
        img_info: Image handle
        pagefile_offset: pagefile start offset
        pagefile_size: pagefile size

    Returns:
        Analysis results
    """
    _debug_print(f"[Pagefile] Reading pagefile from image (offset={pagefile_offset}, size={pagefile_size})...")

    # Read data
    pagefile_data = img_info.read(pagefile_offset, pagefile_size)

    # Analyze
    analyzer = PagefileAnalyzer(pagefile_data=pagefile_data)
    return analyzer.analyze_all()


# ==============================================================================
# Raw Disk Access Factory Functions
# ==============================================================================

def create_pagefile_analyzer_raw_disk(
    drive_number: int = 0,
    partition_index: int = None,
    pagefile_name: str = 'pagefile.sys'
) -> Optional[PagefileAnalyzer]:
    """
    Create PagefileAnalyzer via Raw Disk Access

    Completely bypasses Windows file locks to read pagefile.sys.
    Administrator privileges required.

    Args:
        drive_number: Physical disk number (default: 0)
        partition_index: Partition index (None for first NTFS partition)
        pagefile_name: Pagefile name (default: pagefile.sys)

    Returns:
        PagefileAnalyzer instance or None

    Usage:
        analyzer = create_pagefile_analyzer_raw_disk()
        if analyzer:
            results = analyzer.analyze_all()
    """
    try:
        from core.engine.collectors.filesystem.forensic_disk_accessor import ForensicDiskAccessor
    except ImportError:
        logger.error("ForensicDiskAccessor not available")
        return None

    _debug_print(f"[Pagefile] Starting {pagefile_name} read via Raw Disk Access...")

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
                _debug_print(f"[Pagefile] Selected partition {ntfs_idx} (NTFS)")

            # Stream read pagefile.sys
            pagefile_path = f'/{pagefile_name}'

            _debug_print(f"[Pagefile] Streaming {pagefile_name} data...")

            # Stream read for large files
            chunks = []
            total_size = 0

            for chunk in disk.stream_file(pagefile_path, chunk_size=64 * 1024 * 1024):
                chunks.append(chunk)
                total_size += len(chunk)
                _debug_print(f"[Pagefile] Read progress: {total_size / 1024 / 1024:.1f} MB")

            pagefile_data = b''.join(chunks)
            _debug_print(f"[Pagefile] Total {len(pagefile_data) / 1024 / 1024:.1f} MB read complete [raw disk]")

            return PagefileAnalyzer(pagefile_data=pagefile_data)

    except Exception as e:
        logger.error(f"Raw disk pagefile read error: {e}")
        _debug_print(f"[Pagefile] Raw disk error: {e}")
        return None


def create_pagefile_analyzer_e01(
    e01_path: str,
    partition_index: int = None,
    pagefile_name: str = 'pagefile.sys'
) -> Optional[PagefileAnalyzer]:
    """
    Create PagefileAnalyzer from E01 image

    Args:
        e01_path: E01 file path
        partition_index: Partition index (None for first NTFS partition)
        pagefile_name: Pagefile name (default: pagefile.sys)

    Returns:
        PagefileAnalyzer instance or None

    Usage:
        analyzer = create_pagefile_analyzer_e01("evidence.E01")
        if analyzer:
            results = analyzer.analyze_all()
    """
    try:
        from core.engine.collectors.filesystem.forensic_disk_accessor import ForensicDiskAccessor
    except ImportError:
        logger.error("ForensicDiskAccessor not available")
        return None

    _debug_print(f"[Pagefile] Starting {pagefile_name} read from E01 image...")
    _debug_print(f"[Pagefile] E01 path: {e01_path}")

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
                # Auto-select first NTFS partition
                ntfs_idx = None
                for i, p in enumerate(partitions):
                    if p.filesystem == 'NTFS':
                        ntfs_idx = i
                        break

                if ntfs_idx is None:
                    logger.error("No NTFS partition found in E01 image")
                    return None

                disk.select_partition(ntfs_idx)
                _debug_print(f"[Pagefile] Selected partition {ntfs_idx} (NTFS)")

            # Stream read pagefile.sys
            pagefile_path = f'/{pagefile_name}'

            _debug_print(f"[Pagefile] Streaming {pagefile_name} data...")

            chunks = []
            total_size = 0

            for chunk in disk.stream_file(pagefile_path, chunk_size=64 * 1024 * 1024):
                chunks.append(chunk)
                total_size += len(chunk)
                _debug_print(f"[Pagefile] Read progress: {total_size / 1024 / 1024:.1f} MB")

            pagefile_data = b''.join(chunks)
            _debug_print(f"[Pagefile] Total {len(pagefile_data) / 1024 / 1024:.1f} MB read complete [E01]")

            return PagefileAnalyzer(pagefile_data=pagefile_data)

    except Exception as e:
        logger.error(f"E01 pagefile read error: {e}")
        _debug_print(f"[Pagefile] E01 error: {e}")
        return None


def stream_pagefile_raw_disk(
    drive_number: int = 0,
    partition_index: int = None,
    pagefile_name: str = 'pagefile.sys',
    chunk_size: int = 64 * 1024 * 1024
):
    """
    Stream pagefile via Raw Disk Access (memory efficient)

    Use this to analyze large pagefiles chunk by chunk without loading entirely into memory.

    Args:
        drive_number: Physical disk number
        partition_index: Partition index
        pagefile_name: Pagefile name
        chunk_size: Chunk size (default 64MB)

    Yields:
        (chunk_data: bytes, offset: int, total_size: int)

    Usage:
        for chunk, offset, total in stream_pagefile_raw_disk():
            # Analyze per chunk
            analyze_chunk(chunk, offset)
    """
    try:
        from core.engine.collectors.filesystem.forensic_disk_accessor import ForensicDiskAccessor
    except ImportError:
        logger.error("ForensicDiskAccessor not available")
        return

    try:
        with ForensicDiskAccessor.from_physical_disk(drive_number) as disk:
            partitions = disk.list_partitions()

            if not partitions:
                return

            # Select partition
            if partition_index is not None:
                disk.select_partition(partition_index)
            else:
                for i, p in enumerate(partitions):
                    if p.filesystem == 'NTFS':
                        disk.select_partition(i)
                        break
                else:
                    return

            pagefile_path = f'/{pagefile_name}'
            offset = 0

            for chunk in disk.stream_file(pagefile_path, chunk_size=chunk_size):
                yield chunk, offset, -1  # total_size is not known in advance
                offset += len(chunk)

    except Exception as e:
        logger.error(f"Pagefile streaming error: {e}")


if __name__ == "__main__":
    print("=" * 60)
    print("Pagefile Analyzer Test")
    print("=" * 60)

    print("Usage:")
    print("  # Analyze from file")
    print("  analyzer = PagefileAnalyzer('C:\\pagefile.sys')")
    print("  with analyzer:")
    print("      results = analyzer.analyze_all()")
    print()
    print("  # Analyze from image")
    print("  results = analyze_pagefile_from_image(img_info, offset, size)")
