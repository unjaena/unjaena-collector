"""
pagefile.sys 분석기

Windows 페이지 파일(pagefile.sys) 분석을 위한 모듈
- 문자열 추출 (ASCII/Unicode)
- URL 패턴 검색
- 이메일 주소 검색
- IP 주소 검색
- 파일 경로 검색
- 레지스트리 키 검색

참조: Windows 페이지 파일 구조
- 4KB 페이지 단위
- 메모리에서 스왑된 데이터 포함
- 삭제된 데이터 복구 가능

Raw Disk Access 지원:
- ForensicDiskAccessor를 통한 raw sector 기반 pagefile 읽기
- Windows 파일 잠금 완전 우회
- E01 이미지에서도 동일하게 동작
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
    """pagefile.sys 분석기"""

    PAGE_SIZE = 4096  # Windows 기본 페이지 크기
    CHUNK_SIZE = 1024 * 1024 * 64  # 64MB 단위 처리 (메모리 효율)

    # 정규표현식 패턴
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

    # 제외할 일반적인 시스템 URL
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
            pagefile_path: pagefile.sys 파일 경로
            pagefile_data: pagefile 바이너리 데이터 (직접 제공 시)
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
        """Context manager 진입"""
        if self.pagefile_path and Path(self.pagefile_path).exists():
            self._file = open(self.pagefile_path, 'rb')
            try:
                self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
            except Exception as e:
                logger.warning(f"Memory mapping failed, using file read: {e}")
                self._mmap = None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager 종료"""
        if self._mmap:
            self._mmap.close()
        if hasattr(self, '_file'):
            self._file.close()

    def _read_chunk(self, offset: int, size: int) -> bytes:
        """데이터 청크 읽기"""
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
        pagefile에서 문자열 추출

        Args:
            min_length: 최소 문자열 길이
            max_length: 최대 문자열 길이
            string_type: 'ascii', 'unicode', 'both'

        Yields:
            {
                'type': 'ascii' | 'unicode',
                'string': str,
                'offset': int,
                'page_num': int,
            }
        """
        _debug_print(f"[Pagefile] 문자열 추출 시작 (min_len={min_length})...")

        # ASCII 문자열 패턴
        ascii_pattern = re.compile(
            rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        )

        # Unicode (UTF-16-LE) 문자열 패턴
        unicode_pattern = re.compile(
            rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
        )

        total_strings = 0
        offset = 0

        while offset < self.file_size:
            chunk = self._read_chunk(offset, self.CHUNK_SIZE)
            if not chunk:
                break

            # ASCII 문자열
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

            # Unicode 문자열
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

            offset += self.CHUNK_SIZE - 1024  # 경계 중복 처리

        _debug_print(f"[Pagefile] 총 {total_strings:,}개 문자열 추출")

    def find_urls(self, unique_only: bool = True) -> List[Dict]:
        """
        URL 패턴 검색

        Args:
            unique_only: 중복 제거 여부

        Returns:
            URL 정보 리스트
        """
        _debug_print("[Pagefile] URL 검색 중...")

        urls = []
        seen: Set[bytes] = set()

        offset = 0
        while offset < self.file_size:
            chunk = self._read_chunk(offset, self.CHUNK_SIZE)
            if not chunk:
                break

            for match in self.PATTERNS['url'].finditer(chunk):
                url = match.group()

                # 제외 목록 확인
                if any(url.startswith(exc) for exc in self.EXCLUDED_URLS):
                    continue

                # 중복 확인
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

        _debug_print(f"[Pagefile] {len(urls):,}개 URL 발견")
        return urls

    def find_emails(self, unique_only: bool = True) -> List[Dict]:
        """
        이메일 주소 검색

        Args:
            unique_only: 중복 제거 여부

        Returns:
            이메일 정보 리스트
        """
        _debug_print("[Pagefile] 이메일 주소 검색 중...")

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

        _debug_print(f"[Pagefile] {len(emails):,}개 이메일 주소 발견")
        return emails

    def find_ip_addresses(self, unique_only: bool = True) -> List[Dict]:
        """
        IP 주소 검색 (IPv4, IPv6)

        Returns:
            IP 주소 정보 리스트
        """
        _debug_print("[Pagefile] IP 주소 검색 중...")

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

                # 일반적인 내부 IP 제외 (선택적)
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

        _debug_print(f"[Pagefile] {len(ips):,}개 IP 주소 발견")
        return ips

    def find_file_paths(self, unique_only: bool = True) -> List[Dict]:
        """
        Windows 파일 경로 검색

        Returns:
            파일 경로 정보 리스트
        """
        _debug_print("[Pagefile] 파일 경로 검색 중...")

        paths = []
        seen: Set[bytes] = set()

        offset = 0
        while offset < self.file_size:
            chunk = self._read_chunk(offset, self.CHUNK_SIZE)
            if not chunk:
                break

            for match in self.PATTERNS['windows_path'].finditer(chunk):
                path = match.group()

                if len(path) < 10:  # 너무 짧은 경로 제외
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

        _debug_print(f"[Pagefile] {len(paths):,}개 파일 경로 발견")
        return paths

    def find_registry_keys(self, unique_only: bool = True) -> List[Dict]:
        """
        레지스트리 키 검색

        Returns:
            레지스트리 키 정보 리스트
        """
        _debug_print("[Pagefile] 레지스트리 키 검색 중...")

        keys = []
        seen: Set[bytes] = set()

        offset = 0
        while offset < self.file_size:
            chunk = self._read_chunk(offset, self.CHUNK_SIZE)
            if not chunk:
                break

            for match in self.PATTERNS['registry_key'].finditer(chunk):
                key = match.group()

                if len(key) < 15:  # 너무 짧은 키 제외
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

        _debug_print(f"[Pagefile] {len(keys):,}개 레지스트리 키 발견")
        return keys

    def find_sensitive_data(self) -> Dict[str, List]:
        """
        민감한 데이터 검색 (신용카드, SSN 등)

        Returns:
            민감 데이터 카테고리별 리스트
        """
        _debug_print("[Pagefile] 민감 데이터 검색 중...")

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

            # 신용카드 번호
            for match in self.PATTERNS['credit_card'].finditer(chunk):
                cc = match.group()
                abs_offset = offset + match.start()
                results['credit_cards'].append({
                    'number': cc.decode('ascii'),
                    'offset': abs_offset,
                    'page_num': abs_offset // self.PAGE_SIZE,
                })

            # SSN (미국 사회보장번호)
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

        _debug_print(f"[Pagefile] 민감 데이터: CC={len(results['credit_cards'])}, "
              f"SSN={len(results['ssn'])}, GUID={len(results['guids'])}")

        return results

    def analyze_all(self) -> Dict:
        """
        전체 분석 수행

        Returns:
            분석 결과 딕셔너리
        """
        _debug_print(f"[Pagefile] 전체 분석 시작 (크기: {self.file_size / 1024 / 1024:.1f} MB)...")

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

        # 요약 통계
        results['summary'] = {
            'total_urls': len(results['urls']),
            'total_emails': len(results['emails']),
            'total_ips': len(results['ip_addresses']),
            'total_paths': len(results['file_paths']),
            'total_registry_keys': len(results['registry_keys']),
            'total_credit_cards': len(results['sensitive_data']['credit_cards']),
            'total_ssns': len(results['sensitive_data']['ssn']),
        }

        _debug_print(f"[Pagefile] 분석 완료:")
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
        YARA 룰을 사용한 IOC 스캔

        Args:
            custom_rules_path: 사용자 정의 YARA 룰 디렉토리 경로
            include_default: 기본 룰 포함 여부 (default: True)
            progress_callback: 진행률 콜백 (message, progress 0.0-1.0)

        Returns:
            YARA 스캔 결과:
            - total_matches: 전체 매치 수
            - matches_by_rule: 룰별 매치 수
            - matches_by_severity: 심각도별 매치
            - critical_matches: 치명적 매치 목록
            - high_matches: 높음 심각도 매치 목록
            - medium_matches: 중간 심각도 매치 목록
            - low_matches: 낮음 심각도 매치 목록
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

            _debug_print(f"[Pagefile] YARA 스캔 시작 ({rules_count}개 룰 파일)...")

            results = scanner.scan_pagefile(
                self,
                progress_callback=progress_callback
            )

            # 결과 요약 출력
            total = results.get('total_matches', 0)
            critical = len(results.get('critical_matches', []))
            high = len(results.get('high_matches', []))
            medium = len(results.get('medium_matches', []))

            _debug_print(f"[Pagefile] YARA 스캔 완료: {total}개 매치")
            if critical > 0:
                _debug_print(f"  [CRITICAL] {critical}개 치명적 탐지")
            if high > 0:
                _debug_print(f"  [HIGH] {high}개 높음 심각도 탐지")
            if medium > 0:
                _debug_print(f"  [MEDIUM] {medium}개 중간 심각도 탐지")

            return results

        except ImportError as e:
            logger.warning(f"YARA scanner not available: {e}")
            return {'error': str(e), 'total_matches': 0}
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            return {'error': str(e), 'total_matches': 0}


def analyze_pagefile_from_image(img_info, pagefile_offset: int, pagefile_size: int) -> Dict:
    """
    디스크 이미지에서 pagefile 분석

    Args:
        img_info: 이미지 핸들
        pagefile_offset: pagefile 시작 오프셋
        pagefile_size: pagefile 크기

    Returns:
        분석 결과
    """
    _debug_print(f"[Pagefile] 이미지에서 pagefile 읽기 (offset={pagefile_offset}, size={pagefile_size})...")

    # 데이터 읽기
    pagefile_data = img_info.read(pagefile_offset, pagefile_size)

    # 분석
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
    Raw Disk Access로 PagefileAnalyzer 생성

    Windows 파일 잠금을 완전히 우회하여 pagefile.sys를 읽습니다.
    관리자 권한이 필요합니다.

    Args:
        drive_number: 물리 디스크 번호 (기본: 0)
        partition_index: 파티션 인덱스 (None이면 첫 번째 NTFS 파티션)
        pagefile_name: 페이지파일 이름 (기본: pagefile.sys)

    Returns:
        PagefileAnalyzer 인스턴스 또는 None

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

    _debug_print(f"[Pagefile] Raw Disk Access로 {pagefile_name} 읽기 시작...")

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
                _debug_print(f"[Pagefile] 파티션 {ntfs_idx} 선택 (NTFS)")

            # pagefile.sys 스트리밍 읽기
            pagefile_path = f'/{pagefile_name}'

            _debug_print(f"[Pagefile] {pagefile_name} 데이터 스트리밍 중...")

            # 대용량 파일이므로 스트리밍으로 읽기
            chunks = []
            total_size = 0

            for chunk in disk.stream_file(pagefile_path, chunk_size=64 * 1024 * 1024):
                chunks.append(chunk)
                total_size += len(chunk)
                _debug_print(f"[Pagefile] 읽기 진행: {total_size / 1024 / 1024:.1f} MB")

            pagefile_data = b''.join(chunks)
            _debug_print(f"[Pagefile] 총 {len(pagefile_data) / 1024 / 1024:.1f} MB 읽기 완료 [raw disk]")

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
    E01 이미지에서 PagefileAnalyzer 생성

    Args:
        e01_path: E01 파일 경로
        partition_index: 파티션 인덱스 (None이면 첫 번째 NTFS 파티션)
        pagefile_name: 페이지파일 이름 (기본: pagefile.sys)

    Returns:
        PagefileAnalyzer 인스턴스 또는 None

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

    _debug_print(f"[Pagefile] E01 이미지에서 {pagefile_name} 읽기 시작...")
    _debug_print(f"[Pagefile] E01 경로: {e01_path}")

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
                # 첫 번째 NTFS 파티션 자동 선택
                ntfs_idx = None
                for i, p in enumerate(partitions):
                    if p.filesystem == 'NTFS':
                        ntfs_idx = i
                        break

                if ntfs_idx is None:
                    logger.error("No NTFS partition found in E01 image")
                    return None

                disk.select_partition(ntfs_idx)
                _debug_print(f"[Pagefile] 파티션 {ntfs_idx} 선택 (NTFS)")

            # pagefile.sys 스트리밍 읽기
            pagefile_path = f'/{pagefile_name}'

            _debug_print(f"[Pagefile] {pagefile_name} 데이터 스트리밍 중...")

            chunks = []
            total_size = 0

            for chunk in disk.stream_file(pagefile_path, chunk_size=64 * 1024 * 1024):
                chunks.append(chunk)
                total_size += len(chunk)
                _debug_print(f"[Pagefile] 읽기 진행: {total_size / 1024 / 1024:.1f} MB")

            pagefile_data = b''.join(chunks)
            _debug_print(f"[Pagefile] 총 {len(pagefile_data) / 1024 / 1024:.1f} MB 읽기 완료 [E01]")

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
    Raw Disk Access로 pagefile 스트리밍 (메모리 효율적)

    대용량 pagefile을 메모리에 전부 로드하지 않고 청크 단위로 분석할 때 사용합니다.

    Args:
        drive_number: 물리 디스크 번호
        partition_index: 파티션 인덱스
        pagefile_name: 페이지파일 이름
        chunk_size: 청크 크기 (기본 64MB)

    Yields:
        (chunk_data: bytes, offset: int, total_size: int)

    Usage:
        for chunk, offset, total in stream_pagefile_raw_disk():
            # 청크별 분석
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

            # 파티션 선택
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
                yield chunk, offset, -1  # total_size는 미리 알 수 없음
                offset += len(chunk)

    except Exception as e:
        logger.error(f"Pagefile streaming error: {e}")


if __name__ == "__main__":
    print("=" * 60)
    print("Pagefile Analyzer Test")
    print("=" * 60)

    print("Usage:")
    print("  # 파일에서 분석")
    print("  analyzer = PagefileAnalyzer('C:\\pagefile.sys')")
    print("  with analyzer:")
    print("      results = analyzer.analyze_all()")
    print()
    print("  # 이미지에서 분석")
    print("  results = analyze_pagefile_from_image(img_info, offset, size)")
