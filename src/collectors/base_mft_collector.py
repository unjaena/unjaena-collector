# -*- coding: utf-8 -*-
"""
Base MFT Collector Module

MFT-based artifact collector that works with both E01 images and local disks.

Digital Forensics Principles:
- MFT parsing-based collection (minimizing directory traversal)
- No file count limits
- Includes deleted files
- Includes system folders

Supported Operating Systems:
- Windows (NTFS/FAT/exFAT)
- Linux (ext2/3/4)
- macOS (APFS/HFS+)

Usage:
    # E01 image
    collector = E01ArtifactCollector(e01_path, output_dir)

    # Local disk
    collector = LocalArtifactCollector(output_dir, volume='C')

    # Common interface
    for path, metadata in collector.collect('document'):
        print(f"Collected: {path}")
"""

import os
import re
import hashlib
import itertools
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Generator, Tuple

# Import OS-specific artifact definitions
try:
    from .linux_artifacts import LINUX_ARTIFACT_FILTERS
except ImportError:
    LINUX_ARTIFACT_FILTERS = {}

try:
    from .macos_artifacts import MACOS_ARTIFACT_FILTERS
except ImportError:
    MACOS_ARTIFACT_FILTERS = {}

logger = logging.getLogger(__name__)


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class CollectedArtifact:
    """Collected artifact information"""
    local_path: str           # Extracted local file path
    original_path: str        # Original path
    filename: str             # Filename
    size: int                 # File size
    md5: str                  # MD5 hash
    sha256: str               # SHA256 hash
    artifact_type: str        # Artifact type
    inode: Optional[int] = None
    is_deleted: bool = False
    created_time: Optional[str] = None
    modified_time: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# OS Detection and Artifact Routing
# =============================================================================

def detect_os_type(filesystem: str, root_entries: List[str] = None) -> str:
    """
    Detect OS type based on filesystem and root directory structure

    Args:
        filesystem: Filesystem type (NTFS, ext4, APFS, etc.)
        root_entries: List of files/folders in root directory

    Returns:
        'windows', 'linux', 'macos', 'unknown'
    """
    filesystem_lower = filesystem.lower()

    # Filesystem-based primary detection
    if filesystem_lower in ('ntfs', 'fat32', 'fat16', 'fat12', 'exfat'):
        return 'windows'
    elif filesystem_lower in ('apfs', 'hfs+', 'hfsx', 'hfs'):
        return 'macos'
    elif filesystem_lower in ('ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'zfs'):
        return 'linux'

    # Root directory structure-based secondary detection
    if root_entries:
        entries_lower = {e.lower() for e in root_entries}

        # Windows characteristics
        if 'windows' in entries_lower or 'program files' in entries_lower:
            return 'windows'

        # macOS characteristics
        if 'applications' in entries_lower or 'library' in entries_lower:
            if 'system' in entries_lower:
                return 'macos'

        # Linux characteristics
        if 'etc' in entries_lower and 'var' in entries_lower:
            if 'home' in entries_lower or 'root' in entries_lower:
                return 'linux'

    return 'unknown'


def get_artifact_filters_for_os(os_type: str) -> Dict[str, Any]:
    """
    Return artifact filters for the specified OS type

    Args:
        os_type: 'windows', 'linux', 'macos'

    Returns:
        Artifact filter dictionary for the OS
    """
    if os_type == 'linux':
        return LINUX_ARTIFACT_FILTERS
    elif os_type == 'macos':
        return MACOS_ARTIFACT_FILTERS
    else:
        return ARTIFACT_MFT_FILTERS  # Windows default


def get_all_artifact_filters() -> Dict[str, Dict[str, Any]]:
    """Return combined artifact filters for all operating systems"""
    all_filters = {}

    # Windows artifacts (default)
    for key, value in ARTIFACT_MFT_FILTERS.items():
        all_filters[f'windows_{key}'] = {**value, 'os_type': 'windows'}

    # Linux artifacts
    for key, value in LINUX_ARTIFACT_FILTERS.items():
        all_filters[key] = {**value, 'os_type': 'linux'}

    # macOS artifacts
    for key, value in MACOS_ARTIFACT_FILTERS.items():
        all_filters[key] = {**value, 'os_type': 'macos'}

    return all_filters


def _normalize_paths_for_mft(paths: List[str]) -> List[str]:
    normalized = []
    seen = set()
    for path in paths:
        if not path:
            continue
        p = str(path).replace('\\', '/')
        drive_match = re.match(r'^[A-Za-z]:/(.*)$', p)
        if drive_match:
            p = '/' + drive_match.group(1)
        while p.startswith('//'):
            p = p[1:]
        if p not in seen:
            seen.add(p)
            normalized.append(p)
    return normalized


def _get_ai_artifact_filter(artifact_type: str) -> Optional[Dict[str, Any]]:
    if not artifact_type.startswith('ai_'):
        return None
    try:
        from collectors.artifact_collector import ARTIFACT_TYPES
    except Exception:
        return None

    config = ARTIFACT_TYPES.get(artifact_type)
    if not config:
        return None
    paths = _normalize_paths_for_mft(config.get('paths', []))
    if not paths:
        return None
    return {
        'paths': paths,
        'include_deleted': True,
        'description': config.get('description', artifact_type),
        'forensic_value': config.get('forensic_value', 'medium'),
        'category': config.get('category', 'ai_activity'),
    }


# =============================================================================
# MFT Filter Definitions (E01 + Local combined) - Windows
# =============================================================================

DOCUMENT_EXTENSIONS = frozenset({
    '.doc', '.docx',
    '.xls', '.xlsx',
    '.ppt', '.pptx',
    '.pdf',
    '.hwp', '.hwpx',
    '.txt', '.csv', '.rtf',
})
EMAIL_EXTENSIONS = frozenset({'.eml', '.msg', '.pst', '.ost'})
IMAGE_EXTENSIONS = frozenset({
    '.jpg', '.jpeg', '.png', '.gif', '.bmp',
    '.tiff', '.tif', '.heic', '.heif', '.webp',
    '.raw',
})
VIDEO_EXTENSIONS = frozenset({
    '.mp4', '.avi', '.mov', '.mkv', '.wmv', '.flv',
    '.webm', '.m4v', '.mpg', '.mpeg', '.3gp',
})
SOURCE_CODE_EXTENSIONS = frozenset({
    '.py', '.pyw', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    '.java', '.kt', '.kts', '.go', '.rs', '.cs', '.cpp', '.cc',
    '.c', '.h', '.hpp', '.php', '.rb', '.swift', '.scala',
    '.ps1', '.psm1', '.bat', '.cmd', '.sh', '.bash', '.zsh',
    '.sql', '.r', '.lua', '.pl', '.json', '.toml', '.yaml', '.yml',
    '.xml', '.gradle', '.lock', '.ini', '.cfg', '.conf', '.properties',
})
USER_FILE_EXTENSION_POLICY = {
    'document': DOCUMENT_EXTENSIONS,
    'email': EMAIL_EXTENSIONS,
    'image': IMAGE_EXTENSIONS,
    'video': VIDEO_EXTENSIONS,
    'source_code': SOURCE_CODE_EXTENSIONS,
}

ARTIFACT_MFT_FILTERS: Dict[str, Dict[str, Any]] = {}

class BaseMFTCollector(ABC):
    """
    Base class for MFT-based artifact collectors

    Provides a common interface for both E01 images and local disks.

    Digital Forensics Principles:
    - MFT parsing-based collection (minimizing directory traversal)
    - No file count limits
    - Includes deleted files (by default)
    - Includes system folders
    """

    _DEFAULT_MAX_SCAN_ENTRIES = 2_000_000  # 2M files max to prevent OOM

    def __init__(self, output_dir: str):
        """
        Args:
            output_dir: Directory to store extracted artifacts
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # MFT index cache
        self._mft_indexed: bool = False
        self._mft_cache: Dict[str, List[Any]] = {
            'active_files': [],
            'deleted_files': [],
            'directories': [],
        }
        # Extension -> file entry map (for fast lookup)
        self._extension_index: Dict[str, List[Any]] = {}

        # Set by subclass
        self._accessor = None

    @abstractmethod
    def _initialize_accessor(self) -> bool:
        """
        Initialize ForensicDiskAccessor (implemented by subclass)

        Returns:
            Whether initialization was successful
        """
        pass

    @abstractmethod
    def _get_source_description(self) -> str:
        """
        Return source description (e.g., "E01: image.E01" or "Local: C:")
        """
        pass

    def close(self):
        """Clean up resources"""
        if self._accessor:
            try:
                self._accessor.close()
            except Exception:
                pass
            self._accessor = None

        self._mft_indexed = False
        self._mft_cache = {'active_files': [], 'deleted_files': [], 'directories': []}
        self._extension_index = {}

    def release_scan_cache(self):
        """Release memory held by scan cache after collection is complete."""
        self._mft_cache = {'active_files': [], 'deleted_files': [], 'directories': []}
        self._extension_index.clear()
        self._mft_indexed = False
        logger.info("Scan cache released")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # =========================================================================
    # MFT Index Building
    # =========================================================================

    def _build_mft_index(self) -> None:
        """
        Build complete MFT index (first time only)

        Digital Forensics Principles:
        - No file count limits
        - Includes deleted files
        - Includes system folders
        """
        if self._mft_indexed or not self._accessor:
            return

        source = self._get_source_description()
        logger.info(f"[{source}] Building MFT index (Digital Forensics: Complete collection)...")

        try:
            # Full MFT scan - capped to prevent OOM, includes deleted files
            scan_result = self._accessor.scan_all_files(
                include_deleted=True,
                max_entries=self._DEFAULT_MAX_SCAN_ENTRIES,
            )

            self._mft_cache['active_files'] = scan_result.get('active_files', [])
            self._mft_cache['deleted_files'] = scan_result.get('deleted_files', [])
            self._mft_cache['directories'] = scan_result.get('directories', [])

            total_files = len(self._mft_cache['active_files']) + len(self._mft_cache['deleted_files'])
            logger.info(f"[{source}] MFT index built: {total_files:,} files "
                       f"({len(self._mft_cache['active_files']):,} active, "
                       f"{len(self._mft_cache['deleted_files']):,} deleted)")

            # Build extension index
            self._build_extension_index()

            self._mft_indexed = True

        except Exception as e:
            logger.error(f"[{source}] Failed to build MFT index: {e}", exc_info=True)
            self._mft_indexed = False

    def _build_extension_index(self) -> None:
        """Build extension-based index (for fast lookup)"""
        self._extension_index = {}

        all_files = itertools.chain(self._mft_cache['active_files'], self._mft_cache['deleted_files'])

        for entry in all_files:
            filename = entry.filename if hasattr(entry, 'filename') else str(entry)
            if '.' in filename:
                ext = '.' + filename.rsplit('.', 1)[-1].lower()
                if ext not in self._extension_index:
                    self._extension_index[ext] = []
                self._extension_index[ext].append(entry)

        logger.debug(f"Extension index built: {len(self._extension_index)} unique extensions")

    # =========================================================================
    # MFT-Based Collection
    # =========================================================================

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None,
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts (MFT-based)

        Digital Forensics Principles:
        - Uses only MFT parsing (no directory traversal)
        - No file count limits
        - Includes deleted files
        - Includes system folders

        Args:
            artifact_type: Type of artifact to collect
            progress_callback: Progress callback function

        Yields:
            (local_path, metadata) tuple
        """
        if not self._accessor:
            logger.error("Accessor not initialized")
            return

        ai_filter = _get_ai_artifact_filter(artifact_type)

        # Check all filter sets: Windows + Linux + macOS
        all_filters = {**ARTIFACT_MFT_FILTERS, **LINUX_ARTIFACT_FILTERS, **MACOS_ARTIFACT_FILTERS}
        if artifact_type not in all_filters and not ai_filter:
            logger.debug(f"Skipping unsupported artifact type: {artifact_type}")
            return

        mft_filter = dict(ai_filter or all_filters[artifact_type])  # shallow copy to allow override
        # UI include_deleted override
        if 'include_deleted' in kwargs:
            mft_filter['include_deleted'] = kwargs['include_deleted']
        source = self._get_source_description()

        # USB/removable images often use FAT/exFAT and store user files directly
        # at the volume root. Profile-scoped path filters are too narrow there.
        fs_type = (getattr(self._accessor, '_dissect_fs_type', '') or '').lower()
        if fs_type in {'fat12', 'fat16', 'fat32', 'exfat'} and artifact_type in {
            'document', 'email', 'image', 'video', 'source_code',
        }:
            if mft_filter.get('extensions'):
                mft_filter['full_disk_scan'] = True
                mft_filter['path_optional'] = True
                mft_filter.pop('path_pattern', None)
                mft_filter.pop('path_patterns', None)

        logger.info(f"[{source}] Collecting {artifact_type}, filter={mft_filter}")

        # Per-artifact output directory
        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)

        # Handle special artifacts ($MFT, $LogFile, $UsnJrnl) — NTFS only
        if 'special' in mft_filter:
            os_type = mft_filter.get('os_type', 'windows')
            if os_type != 'windows':
                logger.debug(f"[{source}] Skipping NTFS special artifact {artifact_type} on {os_type}")
                return
            logger.info(f"[{source}] Detected special artifact: {mft_filter.get('special')}")
            yield from self._collect_special_artifact(
                artifact_type, mft_filter, artifact_dir, progress_callback
            )
            return

        # For non-NTFS filesystems with 'paths' filter, use direct path access
        # BEFORE building MFT index (skip the expensive full scan entirely)
        # instead of full scan + pattern matching (which fails on large volumes
        # because DFS scan may not reach target paths within the entry limit)
        artifact_paths = mft_filter.get('paths', [])
        use_direct_access = (
            artifact_paths
            and self._accessor
            and getattr(self._accessor, '_dissect_fs', None) is not None
            and getattr(self._accessor, '_extractor', None) is None  # Not NTFS
        )

        if use_direct_access:
            logger.info(f"[{source}] Collecting {artifact_type} via direct path access ({len(artifact_paths)} paths)")
            extracted_count = 0
            for result in self._collect_by_direct_paths(artifact_type, artifact_paths, artifact_dir):
                extracted_count += 1
                yield result
                if progress_callback:
                    progress_callback(result[0])
            logger.info(f"[{source}] Collected {extracted_count:,} {artifact_type} artifacts (direct access)")
            return

        # NTFS: Build MFT index (first time only) then filter-based collection
        if not self._mft_indexed:
            self._build_mft_index()

        logger.info(f"[{source}] Collecting {artifact_type} using MFT filter...")

        extracted_count = 0
        for result in self._collect_by_mft_filter(artifact_type, mft_filter, artifact_dir):
            extracted_count += 1
            yield result
            if progress_callback:
                progress_callback(result[0])

        logger.info(f"[{source}] Collected {extracted_count:,} {artifact_type} artifacts")

    def _collect_by_direct_paths(
        self,
        artifact_type: str,
        artifact_paths: list,
        artifact_dir: Path
    ):
        """
        Collect artifacts by directly accessing known paths on non-NTFS filesystems.

        Instead of scanning the entire filesystem and pattern-matching (which fails
        on large APFS/HFS+ volumes because DFS traversal may never reach target paths
        within the scan entry limit), this method uses fs.get(path) to directly
        access each known artifact path.

        For glob patterns like '/Users/*/.zsh_history', it lists the parent directory
        and iterates matching entries.
        """
        import glob as _glob_mod

        accessor = self._accessor
        collected = 0

        for path_pattern in artifact_paths:
            path_pattern = path_pattern.rstrip('/')

            # Check if pattern contains glob wildcards
            if '*' in path_pattern:
                # Split into fixed prefix and glob suffix
                # e.g. '/Users/*/.zsh_history' -> parent='/Users', pattern='*/.zsh_history'
                parts = path_pattern.lstrip('/').split('/')
                fixed_parts = []
                for p in parts:
                    if '*' in p:
                        break
                    fixed_parts.append(p)

                parent_path = '/' + '/'.join(fixed_parts) if fixed_parts else '/'
                glob_suffix = '/'.join(parts[len(fixed_parts):])

                try:
                    if not accessor.path_exists(parent_path):
                        continue

                    parent_entries = accessor.list_directory(parent_path)

                    # File-level glob (no '/' in suffix, e.g. '*.plist'):
                    # match against FILES in parent_path, not directories.
                    if '/' not in glob_suffix:
                        import fnmatch
                        for entry in parent_entries:
                            if entry.is_directory:
                                continue
                            if fnmatch.fnmatch(entry.filename, glob_suffix):
                                full_path = f"{parent_path}/{entry.filename}".replace('//', '/')
                                try:
                                    yield from self._extract_direct_path(
                                        accessor, full_path, artifact_type, artifact_dir
                                    )
                                    collected += 1
                                except Exception:
                                    continue
                        continue

                    for entry in parent_entries:
                        if not entry.is_directory:
                            continue
                        # For '/Users/*/.zsh_history' with parent='/Users' and entry='john':
                        # try '/Users/john/.zsh_history'
                        remaining = glob_suffix.replace('*', entry.filename, 1)
                        full_path = f"{parent_path}/{remaining}".replace('//', '/')

                        if '*' in full_path:
                            # Still has wildcards (nested glob) — list and match
                            dir_path = '/'.join(full_path.split('/')[:-1])
                            file_pattern = full_path.split('/')[-1]
                            try:
                                if not accessor.path_exists(dir_path):
                                    continue
                                dir_entries = accessor.list_directory(dir_path)
                                for de in dir_entries:
                                    if de.is_directory:
                                        continue
                                    import fnmatch
                                    if fnmatch.fnmatch(de.filename, file_pattern):
                                        target = f"{dir_path}/{de.filename}"
                                        yield from self._extract_direct_path(
                                            accessor, target, artifact_type, artifact_dir
                                        )
                                        collected += 1
                            except Exception:
                                continue
                        else:
                            # Fully resolved path
                            try:
                                if accessor.path_exists(full_path):
                                    yield from self._extract_direct_path(
                                        accessor, full_path, artifact_type, artifact_dir
                                    )
                                    collected += 1
                            except Exception:
                                continue
                except Exception as e:
                    logger.debug(f"[direct_paths] Glob expansion failed for {path_pattern}: {e}")
                    continue
            else:
                # Exact path — direct access
                try:
                    if accessor.path_exists(path_pattern):
                        yield from self._extract_direct_path(
                            accessor, path_pattern, artifact_type, artifact_dir
                        )
                        collected += 1
                except Exception as e:
                    logger.debug(f"[direct_paths] Access failed for {path_pattern}: {e}")

        logger.info(f"[direct_paths] {artifact_type}: {collected} file(s) collected from {len(artifact_paths)} path(s)")

    def _extract_direct_path(self, accessor, file_path: str, artifact_type: str, artifact_dir: Path):
        """Extract a single file by direct path access and yield (local_path, metadata)."""
        import hashlib
        from datetime import datetime, timezone

        try:
            filename = file_path.split('/')[-1]
            safe_subdir = file_path.lstrip('/').replace('/', os.sep)
            local_path = artifact_dir / safe_subdir
            local_path.parent.mkdir(parents=True, exist_ok=True)

            # Stream file content
            md5 = hashlib.md5(usedforsecurity=False)
            sha256 = hashlib.sha256()
            total_bytes = 0

            try:
                with open(local_path, 'wb') as out_f:
                    for chunk in accessor.stream_file(file_path):
                        out_f.write(chunk)
                        md5.update(chunk)
                        sha256.update(chunk)
                        total_bytes += len(chunk)
            except Exception:
                # Fallback to read_file for small files
                data = accessor.read_file(file_path)
                if data:
                    local_path.write_bytes(data)
                    md5.update(data)
                    sha256.update(data)
                    total_bytes = len(data)

            if total_bytes == 0:
                if local_path.exists():
                    local_path.unlink()
                return

            metadata = {
                'artifact_type': artifact_type,
                'name': filename,
                'original_path': file_path,
                'size': total_bytes,
                'hash_md5': md5.hexdigest(),
                'hash_sha256': sha256.hexdigest(),
                'collection_method': 'direct_path_access',
                'collected_at': datetime.now(timezone.utc).isoformat(),
                'source': self._get_source_description(),
            }

            yield (str(local_path), metadata)

        except Exception as e:
            logger.debug(f"[direct_paths] Extract failed for {file_path}: {e}")

    def _collect_by_mft_filter(
        self,
        artifact_type: str,
        mft_filter: Dict[str, Any],
        artifact_dir: Path
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts using MFT filter

        Args:
            artifact_type: Artifact type
            mft_filter: MFT filter configuration
            artifact_dir: Output directory

        Yields:
            (local_path, metadata) tuple
        """
        include_deleted = mft_filter.get('include_deleted', True)
        full_disk_scan = mft_filter.get('full_disk_scan', False)
        max_file_size = mft_filter.get('max_file_size', 0)  # 0 = unlimited

        # Files to collect — iterate cache directly, no copy
        files_to_check = self._mft_cache['active_files']
        if include_deleted:
            files_to_check = itertools.chain(files_to_check, self._mft_cache['deleted_files'])

        # Filter conditions
        extensions = {str(ext).lower() for ext in (mft_filter.get('extensions') or set())}
        exclude_extensions = {str(ext).lower() for ext in (mft_filter.get('exclude_extensions') or set())}
        target_files = {str(name).lower() for name in (mft_filter.get('files') or set())}
        path_pattern = mft_filter.get('path_pattern')
        path_patterns = mft_filter.get('path_patterns', [])
        name_pattern = mft_filter.get('name_pattern')
        path_optional = mft_filter.get('path_optional', False)  # Collect by filename only even without path
        exclude_path_patterns = mft_filter.get('exclude_path_patterns', [])

        # Convert Linux/macOS 'paths' list into path_patterns + target_files
        # 'paths' entries are absolute paths like '/var/log/auth.log' or
        # glob patterns like '/home/*/.bash_history', '/etc/cron.d/*'
        artifact_paths = _normalize_paths_for_mft(mft_filter.get('paths', []))
        if artifact_paths:
            target_files = set(target_files) if target_files else set()
            path_patterns = list(path_patterns)
            for p in artifact_paths:
                # Strip leading slash for matching against MFT paths
                p_stripped = p.lstrip('/')
                # Convert glob wildcards to regex
                # e.g. '/home/*/.bash_history' -> dir='home/[^/]+', file='.bash_history'
                if '/' in p_stripped:
                    dir_part, file_part = p_stripped.rsplit('/', 1)
                else:
                    dir_part, file_part = '', p_stripped
                if dir_part:
                    # Convert glob * to regex [^/]+ (match within single directory)
                    dir_regex = re.escape(dir_part).replace(r'\*', '[^/]+')
                    path_patterns.append(dir_regex + '/')
                if file_part and file_part != '*':
                    if '*' in file_part:
                        # Glob pattern in filename -> name_pattern
                        # e.g. '*.tracev3' -> '.*\.tracev3'
                        file_regex = re.escape(file_part).replace(r'\*', '.*')
                        if not name_pattern:
                            name_pattern = file_regex
                        else:
                            name_pattern = f'({name_pattern}|{file_regex})'
                    else:
                        target_files.add(file_part.lower())
            if artifact_paths and not path_optional:
                path_optional = mft_filter.get('path_optional', bool(target_files))

        # Compile path patterns
        compiled_patterns = []
        if path_pattern:
            compiled_patterns.append(re.compile(path_pattern, re.IGNORECASE))
        for pp in path_patterns:
            compiled_patterns.append(re.compile(pp, re.IGNORECASE))

        # Compile name pattern
        compiled_name_pattern = None
        if name_pattern:
            compiled_name_pattern = re.compile(name_pattern, re.IGNORECASE)

        compiled_exclude_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in exclude_path_patterns
        ]

        def _excluded_path(value: str) -> bool:
            if not value or not compiled_exclude_patterns:
                return False
            normalized = value.lower().replace('\\', '/')
            return any(pattern.search(normalized) for pattern in compiled_exclude_patterns)

        # Extension-based fast filtering (for full disk scan)
        if extensions and full_disk_scan:
            file_counter = 0
            for ext in extensions:
                ext_lower = ext.lower()
                ext_count = len(self._extension_index.get(ext_lower, []))
                logger.debug(f"[SCAN] Extension {ext_lower}: {ext_count} files to process")

                for entry in self._extension_index.get(ext_lower, []):
                    if not include_deleted and getattr(entry, 'is_deleted', False):
                        continue

                    # max_file_size check (0 = unlimited)
                    if max_file_size > 0:
                        entry_size = getattr(entry, 'size', 0)
                        if entry_size > max_file_size:
                            continue

                    file_counter += 1
                    filename = entry.filename if hasattr(entry, 'filename') else str(entry)
                    full_path = entry.full_path if hasattr(entry, 'full_path') else ""
                    full_path_lower = full_path.lower().replace('\\', '/') if full_path else ""
                    if compiled_patterns:
                        if not full_path_lower:
                            continue
                        if not any(pattern.search(full_path_lower) for pattern in compiled_patterns):
                            continue
                    if _excluded_path(full_path_lower):
                        continue
                    path_name_lower = full_path_lower.rsplit('/', 1)[-1] if full_path_lower else filename.lower()
                    if artifact_type in {'document', 'email', 'image', 'video'} and (
                        filename.lower().startswith('._') or path_name_lower.startswith('._')
                    ):
                        continue
                    if file_counter % 500 == 0:
                        logger.debug(f"[PROGRESS] {artifact_type}: Processing file #{file_counter} - {filename}")

                    yield from self._extract_entry(artifact_type, entry, artifact_dir)
            return

        # Full scan (path/filename based)
        for entry in files_to_check:
            filename = entry.filename if hasattr(entry, 'filename') else str(entry)
            filename_lower = filename.lower()
            full_path = entry.full_path if hasattr(entry, 'full_path') else ""
            # Normalize path separators (backslash -> forward slash)
            full_path_lower = full_path.lower().replace('\\', '/') if full_path else ""
            if _excluded_path(full_path_lower):
                continue

            if not include_deleted and getattr(entry, 'is_deleted', False):
                continue
            path_name_lower = full_path_lower.rsplit('/', 1)[-1] if full_path_lower else filename_lower
            if artifact_type in {'document', 'email', 'image', 'video'} and (
                filename_lower.startswith('._') or path_name_lower.startswith('._')
            ):
                continue

            matched = False

            # 1. Filename match check
            if target_files and filename_lower in target_files:
                if compiled_patterns and full_path_lower:
                    # If path exists, also verify path pattern
                    for pattern in compiled_patterns:
                        if pattern.search(full_path_lower):
                            matched = True
                            break
                elif path_optional:
                    # If path_optional=True, collect by filename only (when MFT path not recovered)
                    matched = True
                elif not compiled_patterns:
                    # If no path pattern, collect by filename only
                    matched = True

            # 2. Extension match check
            if not matched and extensions:
                if '.' in filename_lower:
                    ext = '.' + filename_lower.rsplit('.', 1)[-1]
                    if ext in extensions:
                        if compiled_patterns and full_path_lower:
                            for pattern in compiled_patterns:
                                if pattern.search(full_path_lower):
                                    matched = True
                                    break
                        elif path_optional or not compiled_patterns:
                            matched = True

            # 3. Path pattern only check
            if not matched and compiled_patterns and not extensions and not target_files and not compiled_name_pattern:
                for pattern in compiled_patterns:
                    if pattern.search(full_path_lower):
                        matched = True
                        break

            # 4. Name pattern check
            if compiled_name_pattern and not matched:
                if compiled_name_pattern.match(filename_lower):
                    if compiled_patterns and full_path_lower:
                        for pattern in compiled_patterns:
                            if pattern.search(full_path_lower):
                                matched = True
                                break
                    elif compiled_patterns:
                        matched = bool(path_optional and not full_path_lower)
                    else:
                        matched = True

            if matched:
                # exclude_extensions check (skip image/video files for messenger artifacts)
                if exclude_extensions and '.' in filename_lower:
                    ext = '.' + filename_lower.rsplit('.', 1)[-1]
                    if ext in exclude_extensions:
                        continue
                # max_file_size check (0 = unlimited)
                if max_file_size > 0:
                    entry_size = getattr(entry, 'size', 0)
                    if entry_size > max_file_size:
                        logger.debug(f"[SKIP] {filename} exceeds max size ({entry_size / 1024 / 1024:.1f}MB > {max_file_size / 1024 / 1024:.0f}MB)")
                        continue
                yield from self._extract_entry(artifact_type, entry, artifact_dir)

    def _extract_entry(
        self,
        artifact_type: str,
        entry: Any,
        artifact_dir: Path
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Extract file from MFT entry (chunk streaming)

        Args:
            artifact_type: Artifact type
            entry: FileCatalogEntry
            artifact_dir: Output directory

        Yields:
            (local_path, metadata) tuple
        """
        import time

        inode = entry.inode if hasattr(entry, 'inode') else None
        filename = entry.filename if hasattr(entry, 'filename') else str(entry)
        full_path = entry.full_path if hasattr(entry, 'full_path') else (f"MFT_{inode}" if inode is not None else "")
        is_deleted = getattr(entry, 'is_deleted', False)
        file_size = getattr(entry, 'size', 0)
        can_stream_by_path = getattr(self._accessor, '_dissect_fs', None) is not None and bool(full_path)

        if inode is None and not can_stream_by_path:
            return

        # Large file diagnostic — useful when a single MFT entry expands
        # to a multi-GB resident file via $DATA streams.
        if file_size > 100 * 1024 * 1024:  # 100MB or larger
            logger.debug("Large file detected: %s (%.1fMB)", filename, file_size / 1024 / 1024)

        try:
            # Generate output filename
            safe_filename = self._sanitize_filename(filename)
            if is_deleted:
                safe_filename = f"[DELETED]_{safe_filename}"

            output_file = artifact_dir / safe_filename

            # Prevent duplicates
            if output_file.exists():
                base = output_file.stem
                suffix = output_file.suffix
                counter = 1
                while output_file.exists():
                    output_file = artifact_dir / f"{base}_{counter}{suffix}"
                    counter += 1

            # Write file with chunk streaming + hash calculation
            md5_hash = hashlib.md5(usedforsecurity=False)
            sha256_hash = hashlib.sha256()
            total_size = 0
            has_data = False

            # Timeout settings (max 5 minutes per file, 30 seconds per chunk)
            FILE_TIMEOUT = 300  # 5 minutes
            CHUNK_TIMEOUT = 30  # 30 seconds
            start_time = time.time()
            last_chunk_time = start_time

            # Dissect-backed filesystems such as FAT/ext/APFS do not always
            # support stable inode lookup. Prefer catalog paths when present.
            if can_stream_by_path:
                try:
                    logger.debug(f"[EXTRACT START] {filename} (path={full_path}, size={file_size})")
                    with open(output_file, 'wb') as f:
                        for chunk in self._accessor.stream_file(full_path):
                            current_time = time.time()
                            if current_time - start_time > FILE_TIMEOUT:
                                logger.debug(f"[TIMEOUT] File extraction timeout ({FILE_TIMEOUT}s): {filename}")
                                break

                            if chunk:
                                f.write(chunk)
                                md5_hash.update(chunk)
                                sha256_hash.update(chunk)
                                total_size += len(chunk)
                                has_data = True
                                last_chunk_time = current_time
                except Exception as path_error:
                    logger.debug(f"[PATH STREAM ERROR] {filename}: {path_error}")

            # Check for streaming method
            if not has_data and inode is not None and hasattr(self._accessor, 'stream_file_by_inode'):
                # Chunk streaming (supports large files)
                try:
                    logger.debug(f"[EXTRACT START] {filename} (inode={inode}, size={file_size})")
                    with open(output_file, 'wb') as f:
                        chunk_count = 0
                        stream_generator = self._accessor.stream_file_by_inode(inode)
                        logger.debug(f"[STREAM READY] {filename}")
                        for chunk in stream_generator:
                            current_time = time.time()

                            # Check overall file timeout
                            if current_time - start_time > FILE_TIMEOUT:
                                logger.debug(f"[TIMEOUT] File extraction timeout ({FILE_TIMEOUT}s): {filename}")
                                break

                            if chunk:
                                f.write(chunk)
                                md5_hash.update(chunk)
                                sha256_hash.update(chunk)
                                total_size += len(chunk)
                                has_data = True
                                chunk_count += 1
                                last_chunk_time = current_time

                                # Progress log (every 100MB)
                                if total_size % (100 * 1024 * 1024) < len(chunk):
                                    logger.debug(f"[PROGRESS] {filename}: {total_size / 1024 / 1024:.1f}MB written")

                except Exception as stream_error:
                    logger.debug(f"[STREAM ERROR] {filename}: {stream_error}")
                    # Delete partially written file
                    if output_file.exists() and total_size == 0:
                        output_file.unlink()
                    return

            if not has_data and inode is not None:
                # Fallback: full read (for small files)
                data = self._accessor.read_file_by_inode(inode)
                if data:
                    output_file.write_bytes(data)
                    md5_hash.update(data)
                    sha256_hash.update(data)
                    total_size = len(data)
                    has_data = True

            if has_data:
                # Generate metadata
                metadata = {
                    'artifact_type': artifact_type,
                    'name': filename,
                    'original_path': full_path,
                    'size': total_size,
                    'hash_md5': md5_hash.hexdigest(),
                    'hash_sha256': sha256_hash.hexdigest(),
                    'collection_method': 'mft_based',
                    'source': self._get_source_description(),
                    'mft_inode': inode,
                    'is_deleted': is_deleted,
                    'created_time': getattr(entry, 'created_time', None),
                    'modified_time': getattr(entry, 'modified_time', None),
                    'collected_at': datetime.now().isoformat(),
                }

                yield str(output_file), metadata
            else:
                # Delete empty file
                if output_file.exists():
                    output_file.unlink()

        except Exception as e:
            logger.debug(f"Cannot extract {full_path}: {e}")

    def _collect_special_artifact(
        self,
        artifact_type: str,
        mft_filter: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect special system artifacts ($MFT, $LogFile, $UsnJrnl)
        """
        special_method = mft_filter.get('special')
        source = self._get_source_description()

        try:
            if special_method == 'collect_mft_raw':
                # $MFT (inode 0) — streaming to avoid loading entire MFT into memory
                logger.info(f"[{source}] Collecting $MFT (inode 0)...")
                output_file = artifact_dir / '$MFT'
                md5_hash = hashlib.md5(usedforsecurity=False)
                sha256_hash = hashlib.sha256()
                total_size = 0

                if hasattr(self._accessor, 'stream_file_by_inode'):
                    with open(output_file, 'wb') as f:
                        for chunk in self._accessor.stream_file_by_inode(0):
                            if chunk:
                                f.write(chunk)
                                md5_hash.update(chunk)
                                sha256_hash.update(chunk)
                                total_size += len(chunk)
                else:
                    data = self._accessor.read_file_by_inode(0)
                    if data:
                        output_file.write_bytes(data)
                        md5_hash.update(data)
                        sha256_hash.update(data)
                        total_size = len(data)

                if total_size > 0:
                    metadata = {
                        'artifact_type': artifact_type,
                        'name': '$MFT',
                        'original_path': '$MFT',
                        'size': total_size,
                        'hash_md5': md5_hash.hexdigest(),
                        'hash_sha256': sha256_hash.hexdigest(),
                        'collection_method': 'mft_based',
                        'source': source,
                        'mft_inode': 0,
                        'collected_at': datetime.now().isoformat(),
                    }

                    yield str(output_file), metadata
                    if progress_callback:
                        progress_callback(str(output_file))
                else:
                    # Clean up empty file if created
                    if output_file.exists():
                        output_file.unlink()

            elif special_method == 'collect_logfile':
                # $LogFile (inode 2) — streaming to avoid loading entire LogFile into memory
                logger.info(f"[{source}] Collecting $LogFile (inode 2)...")
                output_file = artifact_dir / '$LogFile'
                md5_hash = hashlib.md5(usedforsecurity=False)
                sha256_hash = hashlib.sha256()
                total_size = 0

                if hasattr(self._accessor, 'stream_file_by_inode'):
                    with open(output_file, 'wb') as f:
                        for chunk in self._accessor.stream_file_by_inode(2):
                            if chunk:
                                f.write(chunk)
                                md5_hash.update(chunk)
                                sha256_hash.update(chunk)
                                total_size += len(chunk)
                else:
                    data = self._accessor.read_file_by_inode(2)
                    if data:
                        output_file.write_bytes(data)
                        md5_hash.update(data)
                        sha256_hash.update(data)
                        total_size = len(data)

                if total_size > 0:
                    metadata = {
                        'artifact_type': artifact_type,
                        'name': '$LogFile',
                        'original_path': '$LogFile',
                        'size': total_size,
                        'hash_md5': md5_hash.hexdigest(),
                        'hash_sha256': sha256_hash.hexdigest(),
                        'collection_method': 'mft_based',
                        'source': source,
                        'mft_inode': 2,
                        'collected_at': datetime.now().isoformat(),
                    }

                    yield str(output_file), metadata
                    if progress_callback:
                        progress_callback(str(output_file))
                else:
                    # Clean up empty file if created
                    if output_file.exists():
                        output_file.unlink()

            elif special_method == 'collect_usn_journal':
                # $UsnJrnl:$J
                logger.info(f"[{source}] Collecting $UsnJrnl:$J...")
                data = None

                try:
                    # Skip sparse regions (solves memory/size issues)
                    data = self._accessor.read_usnjrnl_raw(skip_sparse=True)
                except Exception as e:
                    logger.warning(f"[{source}] read_usnjrnl_raw failed: {e}")
                    # Fallback: find in $Extend directory
                    try:
                        usnjrnl_inode = self._accessor._find_in_directory(11, '$UsnJrnl')
                        if usnjrnl_inode:
                            # Fallback method also uses sparse skip
                            data = self._accessor._read_file_skip_sparse(
                                usnjrnl_inode, stream_name='$J'
                            )
                        else:
                            logger.warning(f"[{source}] $UsnJrnl not found in $Extend directory")
                    except Exception as e2:
                        logger.warning(f"[{source}] Fallback USN collection failed: {e2}")

                # Clear log when USN Journal is not available
                if not data or len(data) == 0:
                    logger.warning(f"[{source}] $UsnJrnl:$J not available (may be disabled or empty)")

                if data and len(data) > 0:
                    output_file = artifact_dir / '$UsnJrnl_J'
                    output_file.write_bytes(data)

                    metadata = {
                        'artifact_type': artifact_type,
                        'name': '$UsnJrnl:$J',
                        'original_path': '$Extend/$UsnJrnl:$J',
                        'size': len(data),
                        'hash_md5': hashlib.md5(data, usedforsecurity=False).hexdigest(),
                        'hash_sha256': hashlib.sha256(data).hexdigest(),
                        'collection_method': 'mft_based',
                        'source': source,
                        'ads_stream': '$J',
                        'collected_at': datetime.now().isoformat(),
                    }

                    yield str(output_file), metadata
                    if progress_callback:
                        progress_callback(str(output_file))

            elif special_method == 'collect_zone_identifier':
                # Zone.Identifier ADS - download file origin information
                logger.info(f"[{source}] Collecting Zone.Identifier ADS streams...")

                # Build MFT index (first time only)
                if not self._mft_indexed:
                    self._build_mft_index()

                # Target user directories (case insensitive)
                user_paths = ['downloads', 'desktop', 'documents']
                ads_stream_name = 'Zone.Identifier'
                collected_count = 0
                checked_count = 0

                all_files = self._mft_cache.get('active_files', [])
                logger.info(f"[{source}] Scanning {len(all_files)} active files for Zone.Identifier...")

                for entry in all_files:
                    try:
                        full_path = getattr(entry, 'full_path', '') or ''
                        filename = getattr(entry, 'filename', '') or ''
                        inode = getattr(entry, 'inode', None)
                        # ads_streams is already included in FileCatalogEntry
                        entry_ads = getattr(entry, 'ads_streams', []) or []

                        if not inode or not full_path:
                            continue

                        full_path_lower = full_path.lower()

                        # Filter for user directories (under Users folder)
                        is_user_path = False
                        for user_path in user_paths:
                            # '/users/' or 'users/' (handles both root-starting and non-root paths)
                            if ('users/' in full_path_lower or '/users/' in full_path_lower) and \
                               f'/{user_path}/' in full_path_lower:
                                is_user_path = True
                                break

                        if not is_user_path:
                            continue

                        checked_count += 1

                        # Check for Zone.Identifier ADS presence (using cached ads_streams)
                        if ads_stream_name not in entry_ads:
                            continue

                        # Read Zone.Identifier ADS
                        ads_data = self._accessor.read_file_by_inode(
                            inode, stream_name=ads_stream_name
                        )

                        if ads_data:
                            # Output filename: originalfilename_Zone.Identifier.txt
                            safe_filename = self._sanitize_filename(filename)
                            output_filename = f"{safe_filename}_Zone.Identifier.txt"
                            output_file = artifact_dir / output_filename

                            # Prevent duplicates
                            if output_file.exists():
                                counter = 1
                                while output_file.exists():
                                    output_file = artifact_dir / f"{safe_filename}_{counter}_Zone.Identifier.txt"
                                    counter += 1

                            output_file.write_bytes(ads_data)
                            collected_count += 1

                            metadata = {
                                'artifact_type': artifact_type,
                                'name': f"{filename}:Zone.Identifier",
                                'original_path': f"{full_path}:Zone.Identifier",
                                'parent_file': filename,
                                'parent_path': full_path,
                                'size': len(ads_data),
                                'hash_md5': hashlib.md5(ads_data, usedforsecurity=False).hexdigest(),
                                'hash_sha256': hashlib.sha256(ads_data).hexdigest(),
                                'collection_method': 'mft_based',
                                'source': source,
                                'ads_stream': ads_stream_name,
                                'mft_inode': inode,
                                'collected_at': datetime.now().isoformat(),
                            }

                            # Parse Zone.Identifier content
                            try:
                                ads_text = ads_data.decode('utf-8', errors='ignore')
                                for line in ads_text.split('\n'):
                                    line = line.strip()
                                    if '=' in line:
                                        key, value = line.split('=', 1)
                                        key = key.strip()
                                        value = value.strip()
                                        if key == 'ZoneId':
                                            metadata['zone_id'] = int(value)
                                            zone_names = {
                                                0: 'Local Machine',
                                                1: 'Local Intranet',
                                                2: 'Trusted Sites',
                                                3: 'Internet',
                                                4: 'Restricted Sites'
                                            }
                                            metadata['zone_name'] = zone_names.get(int(value), 'Unknown')
                                        elif key == 'ReferrerUrl':
                                            metadata['referrer_url'] = value
                                        elif key == 'HostUrl':
                                            metadata['host_url'] = value
                            except Exception:
                                pass

                            yield str(output_file), metadata
                            if progress_callback:
                                progress_callback(str(output_file))

                    except Exception as entry_err:
                        logger.debug(f"Zone.Identifier entry error: {entry_err}")
                        continue

                logger.info(f"[{source}] Zone.Identifier: checked {checked_count} user files, collected {collected_count} ADS streams")

        except Exception as e:
            logger.error(f"[{source}] Special artifact collection failed ({special_method}): {e}")

    # =========================================================================
    # Utilities
    # =========================================================================

    def _sanitize_filename(self, filename: str) -> str:
        """Remove invalid characters from filename"""
        sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
        sanitized = re.sub(r'_+', '_', sanitized)
        sanitized = sanitized.strip(' _.')
        if not sanitized:
            sanitized = 'unnamed_file'
        return sanitized

    def get_available_artifacts(self) -> List[Dict[str, Any]]:
        """Return list of available artifacts"""
        artifacts = []
        for type_id, mft_filter in ARTIFACT_MFT_FILTERS.items():
            artifacts.append({
                'type': type_id,
                'description': mft_filter.get('description', ''),
                'include_deleted': mft_filter.get('include_deleted', True),
                'full_disk_scan': mft_filter.get('full_disk_scan', False),
            })
        return artifacts
