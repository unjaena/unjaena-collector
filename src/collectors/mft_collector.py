"""
MFT-based Artifact Collector Module

NTFS MFT (Master File Table) Entry-based artifact collection.
Collection method aligned with digital forensics standards:
- Deleted file recovery capable
- File lock bypass
- MFT Entry metadata preservation
- Chain of Custody established

Note: Administrator privileges required (Raw Disk Access)
"""
import os
import sys
import struct
import hashlib
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Generator, Tuple, Dict, Any, Optional, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


def _debug_print(message: str):
    """Debug output for MFT collection (mirrors artifact_collector._debug_print)."""
    logger.debug(message)


# Check for pytsk3 availability
try:
    import pytsk3
    PYTSK3_AVAILABLE = True
except ImportError:
    PYTSK3_AVAILABLE = False
    _debug_print("[WARNING] pytsk3 not installed. MFT collection will be disabled.")
    _debug_print("[INFO] Install with: pip install pytsk3")


@dataclass
class MFTEntryInfo:
    """MFT Entry information"""
    entry_number: int
    sequence_number: int
    parent_entry: int
    filename: str
    full_path: str
    file_size: int
    is_directory: bool
    is_deleted: bool
    is_allocated: bool

    # NTFS Timestamps (FILETIME -> datetime)
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    accessed: Optional[datetime] = None
    mft_modified: Optional[datetime] = None

    # Additional forensic metadata
    data_runs: List[Tuple[int, int]] = field(default_factory=list)
    resident_data: bool = False
    file_attributes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'mft_entry_number': self.entry_number,
            'mft_sequence_number': self.sequence_number,
            'mft_parent_entry': self.parent_entry,
            'filename': self.filename,
            'full_path': self.full_path,
            'file_size': self.file_size,
            'is_directory': self.is_directory,
            'is_deleted': self.is_deleted,
            'is_allocated': self.is_allocated,
            'created': self.created.isoformat() if self.created else None,
            'modified': self.modified.isoformat() if self.modified else None,
            'accessed': self.accessed.isoformat() if self.accessed else None,
            'mft_modified': self.mft_modified.isoformat() if self.mft_modified else None,
            'data_runs': self.data_runs,
            'resident_data': self.resident_data,
            'file_attributes': self.file_attributes,
        }


class MFTCollector:
    """
    MFT (Master File Table) based artifact collector.

    Collects files by directly reading MFT Entries from NTFS file system.
    Since it does not use regular file APIs:
    - Deleted file recovery capable
    - OS-locked file collection capable
    - Complete metadata preservation

    Note: Administrator privileges required
    """

    # NTFS constants
    FILE_ATTRIBUTE_READONLY = 0x0001
    FILE_ATTRIBUTE_HIDDEN = 0x0002
    FILE_ATTRIBUTE_SYSTEM = 0x0004
    FILE_ATTRIBUTE_DIRECTORY = 0x0010
    FILE_ATTRIBUTE_ARCHIVE = 0x0020
    FILE_ATTRIBUTE_ENCRYPTED = 0x4000
    FILE_ATTRIBUTE_COMPRESSED = 0x0800

    # Buffer size for file reading
    CHUNK_SIZE = 1024 * 1024  # 1MB chunks

    def __init__(self, volume: str, output_dir: str, disk_reader=None):
        """
        Initialize MFT Collector.

        Args:
            volume: Drive letter (e.g., 'C')
            output_dir: Directory to store collected artifacts
            disk_reader: Optional UnifiedDiskReader for BitLocker decrypted volumes
                         Note: Currently not directly integrated with pytsk3,
                         will fall back to standard volume access if provided.
        """
        if not PYTSK3_AVAILABLE:
            raise RuntimeError("pytsk3 library is required for MFT collection")

        self.volume = volume.upper().rstrip(':')
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.disk_reader = disk_reader  # BitLocker decrypted reader (for future use)

        self.img = None
        self.fs = None

        # If disk_reader is provided (BitLocker decrypted), skip direct pytsk3 access
        # TODO: Implement custom pytsk3 Img_Info wrapper for decrypted readers
        if disk_reader:
            _debug_print("[INFO] BitLocker decrypted reader provided - MFT collection may be limited")
            _debug_print("[INFO] Will attempt standard volume access after decryption")

        self._open_volume()

    def _open_volume(self):
        """Open volume for raw access"""
        try:
            # Windows raw disk access
            device_path = rf"\\.\{self.volume}:"
            self.img = pytsk3.Img_Info(device_path)
            self.fs = pytsk3.FS_Info(self.img)
        except Exception as e:
            raise RuntimeError(
                f"Cannot open volume {self.volume}: {e}\n"
                "Ensure you have administrator privileges."
            )

    def close(self):
        """Close volume handles"""
        self.img = None
        self.fs = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _filetime_to_datetime(self, filetime: int) -> Optional[datetime]:
        """
        Convert Windows FILETIME to datetime.

        FILETIME: 100-nanosecond intervals since January 1, 1601
        """
        if not filetime or filetime <= 0:
            return None

        try:
            # FILETIME epoch offset (1601-01-01 to 1970-01-01 in 100ns intervals)
            EPOCH_DIFF = 116444736000000000
            timestamp = (filetime - EPOCH_DIFF) / 10000000
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (OSError, ValueError, OverflowError):
            return None

    def _get_entry_name_bytes(self, name_info) -> Optional[bytes]:
        """
        Safely extract filename bytes from entry.info.name.

        Depending on pytsk3 version, name_info can be:
        - TSK_FS_NAME object (has .name attribute)
        - bytes object (use directly)

        Args:
            name_info: entry.info.name value

        Returns:
            Filename bytes or None
        """
        if name_info is None:
            return None

        # Return directly if bytes
        if isinstance(name_info, bytes):
            return name_info

        # Use .name attribute if object
        if hasattr(name_info, 'name'):
            return name_info.name

        return None

    def get_mft_entry_info(self, entry) -> Optional[MFTEntryInfo]:
        """
        Extract MFT entry information from pytsk3 file object.

        Args:
            entry: pytsk3.File object

        Returns:
            MFTEntryInfo object or None if entry is invalid
        """
        try:
            meta = entry.info.meta
            name_info = entry.info.name

            if meta is None or name_info is None:
                return None

            # Safely extract filename bytes
            name_bytes = self._get_entry_name_bytes(name_info)
            if name_bytes is None:
                return None

            # Skip special entries
            if name_bytes in [b'.', b'..']:
                return None

            # Decode filename
            filename = name_bytes.decode('utf-8', errors='replace')

            # Determine if deleted
            is_allocated = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC)
            is_deleted = not is_allocated

            # Get timestamps
            created = self._filetime_to_datetime(getattr(meta, 'crtime', 0) * 10000000 + 116444736000000000) if hasattr(meta, 'crtime') and meta.crtime else None
            modified = self._filetime_to_datetime(getattr(meta, 'mtime', 0) * 10000000 + 116444736000000000) if hasattr(meta, 'mtime') and meta.mtime else None
            accessed = self._filetime_to_datetime(getattr(meta, 'atime', 0) * 10000000 + 116444736000000000) if hasattr(meta, 'atime') and meta.atime else None
            mft_modified = self._filetime_to_datetime(getattr(meta, 'ctime', 0) * 10000000 + 116444736000000000) if hasattr(meta, 'ctime') and meta.ctime else None

            # Check if directory
            is_directory = bool(meta.type == pytsk3.TSK_FS_META_TYPE_DIR)

            # Get parent entry number
            parent_entry = name_info.par_addr if hasattr(name_info, 'par_addr') else 0

            return MFTEntryInfo(
                entry_number=meta.addr,
                sequence_number=getattr(meta, 'seq', 0),
                parent_entry=parent_entry,
                filename=filename,
                full_path="",  # Will be set later
                file_size=meta.size if hasattr(meta, 'size') else 0,
                is_directory=is_directory,
                is_deleted=is_deleted,
                is_allocated=is_allocated,
                created=created,
                modified=modified,
                accessed=accessed,
                mft_modified=mft_modified,
                file_attributes=getattr(meta, 'mode', 0),
                resident_data=meta.size < 700 if hasattr(meta, 'size') else False,
            )

        except Exception as e:
            _debug_print(f"[MFT] Error reading entry: {e}")
            return None

    def collect_by_path(
        self,
        path: str,
        artifact_type: str = "unknown",
        include_deleted: bool = True
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect file by path using MFT.

        Args:
            path: File path relative to volume root (e.g., "Windows/Prefetch")
            artifact_type: Type of artifact for metadata
            include_deleted: Include deleted files

        Yields:
            Tuple of (output_path, metadata)
        """
        try:
            # Normalize path
            path = path.replace('\\', '/').lstrip('/')

            # Open file through filesystem
            file_obj = self.fs.open(path)

            if file_obj.info.meta and file_obj.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                # It's a directory - collect all files (use open_dir for proper listing)
                dir_obj = self.fs.open_dir(f"/{path}")
                for entry in self._walk_directory(dir_obj, path):
                    if hasattr(entry.info, 'meta') and entry.info.meta:
                        if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                            for result in self._extract_file(entry, f"/{path}", artifact_type):
                                yield result
            else:
                # Single file
                for result in self._extract_file(file_obj, path, artifact_type):
                    yield result

        except Exception as e:
            _debug_print(f"[MFT] Error collecting {path}: {e}")

    def collect_by_pattern(
        self,
        base_path: str,
        pattern: str,
        artifact_type: str = "unknown",
        include_deleted: bool = True,
        recursive: bool = True
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect files matching a pattern using MFT scan.

        Args:
            base_path: Base directory to search (e.g., "Windows/Prefetch")
            pattern: Filename pattern to match (e.g., "*.pf")
            artifact_type: Type of artifact for metadata
            include_deleted: Include deleted files
            recursive: Recursively walk subdirectories (default: True)

        Yields:
            Tuple of (output_path, metadata)
        """
        import fnmatch

        try:
            # Normalize path
            base_path = base_path.replace('\\', '/').strip('/')

            # Open directory (use open_dir for proper directory listing)
            dir_obj = self.fs.open_dir(f"/{base_path}")

            for entry in self._walk_directory(dir_obj, base_path, include_deleted, recursive=recursive):
                # Check meta attribute existence
                if not hasattr(entry.info, 'meta') or entry.info.meta is None:
                    continue

                if entry.info.meta.type != pytsk3.TSK_FS_META_TYPE_REG:
                    continue

                # Safely extract filename bytes
                name_bytes = self._get_entry_name_bytes(entry.info.name)
                if name_bytes is None:
                    continue
                filename = name_bytes.decode('utf-8', errors='replace')

                # Match pattern
                if fnmatch.fnmatch(filename.lower(), pattern.lower()):
                    # Check deleted status
                    is_allocated = bool(entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC)
                    if not include_deleted and not is_allocated:
                        continue

                    for result in self._extract_file(entry, f"/{base_path}", artifact_type):
                        yield result

        except Exception as e:
            _debug_print(f"[MFT] Error scanning {base_path}/{pattern}: {e}")

    def _walk_directory(
        self,
        directory,
        path: str,
        include_deleted: bool = True,
        recursive: bool = False
    ) -> Generator:
        """
        Walk through directory entries.

        Args:
            directory: pytsk3 directory object
            path: Current path
            include_deleted: Include deleted entries
            recursive: Recursively walk subdirectories

        Yields:
            pytsk3.File objects
        """
        try:
            for entry in directory:
                # pytsk3.TSK_FS_ATTR objects don't have info.name attribute - skip
                if not hasattr(entry, 'info') or entry.info is None:
                    continue

                if not hasattr(entry.info, 'name') or entry.info.name is None:
                    continue

                # Safely extract filename bytes
                name_bytes = self._get_entry_name_bytes(entry.info.name)
                if name_bytes is None:
                    continue

                name = name_bytes.decode('utf-8', errors='replace')

                # Skip special entries
                if name in ['.', '..']:
                    continue

                # Check if deleted (only if meta exists)
                if hasattr(entry.info, 'meta') and entry.info.meta:
                    is_allocated = bool(entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC)
                    if not include_deleted and not is_allocated:
                        continue

                yield entry

                # Recursive subdirectory walk
                if recursive and hasattr(entry.info, 'meta') and entry.info.meta:
                    if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        subdir_path = f"{path}/{name}"
                        try:
                            subdir = self.fs.open_dir(f"/{subdir_path}")
                            yield from self._walk_directory(subdir, subdir_path, include_deleted, recursive)
                        except Exception:
                            continue

        except Exception as e:
            _debug_print(f"[MFT] Error walking directory {path}: {e}")

    def _extract_file(
        self,
        file_obj,
        parent_path: str,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Extract file content to output directory.

        Args:
            file_obj: pytsk3.File object
            parent_path: Parent directory path
            artifact_type: Type of artifact

        Yields:
            Tuple of (output_path, metadata)
        """
        try:
            mft_info = self.get_mft_entry_info(file_obj)
            if mft_info is None:
                return

            # Build output path
            artifact_dir = self.output_dir / artifact_type
            artifact_dir.mkdir(exist_ok=True)

            # Add deleted marker to filename if applicable
            output_filename = mft_info.filename
            if mft_info.is_deleted:
                output_filename = f"[DELETED]_{output_filename}"

            # Add MFT entry number for uniqueness
            output_filename = f"{mft_info.entry_number}_{output_filename}"
            output_path = artifact_dir / output_filename

            # Build full path
            mft_info.full_path = f"{self.volume}:{parent_path}/{mft_info.filename}"

            # Read file content
            sha256 = hashlib.sha256()
            md5 = hashlib.md5()
            bytes_written = 0

            with open(output_path, 'wb') as out_file:
                offset = 0
                while offset < mft_info.file_size:
                    chunk_size = min(self.CHUNK_SIZE, mft_info.file_size - offset)
                    data = file_obj.read_random(offset, chunk_size)

                    if not data:
                        break

                    out_file.write(data)
                    sha256.update(data)
                    md5.update(data)
                    bytes_written += len(data)
                    offset += len(data)

            # Build metadata
            metadata = {
                'artifact_type': artifact_type,
                'original_path': mft_info.full_path,
                'filename': mft_info.filename,
                'size': bytes_written,
                'sha256': sha256.hexdigest(),
                'md5': md5.hexdigest(),
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'mft_raw_read',

                # MFT-specific metadata
                'mft_entry_number': mft_info.entry_number,
                'mft_sequence_number': mft_info.sequence_number,
                'mft_parent_entry': mft_info.parent_entry,
                'is_deleted': mft_info.is_deleted,
                'is_allocated': mft_info.is_allocated,
                'resident_data': mft_info.resident_data,
                'file_attributes': mft_info.file_attributes,

                # Timestamps
                'timestamps': {
                    'created': mft_info.created.isoformat() if mft_info.created else None,
                    'modified': mft_info.modified.isoformat() if mft_info.modified else None,
                    'accessed': mft_info.accessed.isoformat() if mft_info.accessed else None,
                    'mft_modified': mft_info.mft_modified.isoformat() if mft_info.mft_modified else None,
                },
            }

            yield str(output_path), metadata

        except Exception as e:
            _debug_print(f"[MFT] Error extracting file: {e}")

    def collect_mft_raw(self, output_path: Optional[str] = None) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Collect raw $MFT file.

        The $MFT file contains the entire file table and is crucial for
        forensic analysis. It can reveal deleted files and file history.

        Args:
            output_path: Custom output path (default: output_dir/$MFT)

        Returns:
            Tuple of (output_path, metadata) or None on failure
        """
        try:
            mft_file = self.fs.open("/$MFT")

            if output_path is None:
                output_path = str(self.output_dir / "$MFT")

            sha256 = hashlib.sha256()
            md5 = hashlib.md5()
            total_size = mft_file.info.meta.size
            bytes_written = 0

            with open(output_path, 'wb') as out_file:
                offset = 0
                while offset < total_size:
                    chunk_size = min(self.CHUNK_SIZE, total_size - offset)
                    data = mft_file.read_random(offset, chunk_size)

                    if not data:
                        break

                    out_file.write(data)
                    sha256.update(data)
                    md5.update(data)
                    bytes_written += len(data)
                    offset += len(data)

            metadata = {
                'artifact_type': 'mft',
                'original_path': f"{self.volume}:/$MFT",
                'filename': '$MFT',
                'size': bytes_written,
                'sha256': sha256.hexdigest(),
                'md5': md5.hexdigest(),
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'mft_raw_read',
                'description': 'Master File Table - contains all file metadata',
            }

            return output_path, metadata

        except Exception as e:
            _debug_print(f"[MFT] Error collecting $MFT: {e}")
            return None

    def collect_usn_journal(self, output_path: Optional[str] = None) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Collect USN Journal ($UsnJrnl:$J).

        The USN Journal records all changes to files and folders.
        Critical for timeline analysis.

        Args:
            output_path: Custom output path

        Returns:
            Tuple of (output_path, metadata) or None on failure
        """
        try:
            # USN Journal is stored in $Extend/$UsnJrnl:$J
            usn_file = self.fs.open("/$Extend/$UsnJrnl")

            if output_path is None:
                output_path = str(self.output_dir / "$UsnJrnl_J")

            # Get the $J data stream
            sha256 = hashlib.sha256()
            md5 = hashlib.md5()
            bytes_written = 0

            # Find the $J attribute (ADS)
            for attr in usn_file:
                if hasattr(attr, 'info') and hasattr(attr.info, 'name'):
                    if attr.info.name and b'$J' in attr.info.name:
                        size = attr.info.size

                        with open(output_path, 'wb') as out_file:
                            offset = 0
                            while offset < size:
                                chunk_size = min(self.CHUNK_SIZE, size - offset)
                                try:
                                    data = attr.read_random(offset, chunk_size)
                                    if not data:
                                        break
                                    out_file.write(data)
                                    sha256.update(data)
                                    md5.update(data)
                                    bytes_written += len(data)
                                except Exception:
                                    pass
                                offset += chunk_size

                        break

            if bytes_written == 0:
                _debug_print("[MFT] USN Journal is empty or sparse")
                return None

            metadata = {
                'artifact_type': 'usn_journal',
                'original_path': f"{self.volume}:/$Extend/$UsnJrnl:$J",
                'filename': '$UsnJrnl_J',
                'size': bytes_written,
                'sha256': sha256.hexdigest(),
                'md5': md5.hexdigest(),
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'mft_raw_read',
                'description': 'USN Journal - file change history',
            }

            return output_path, metadata

        except Exception as e:
            _debug_print(f"[MFT] Error collecting USN Journal: {e}")
            return None

    def collect_logfile(self, output_path: Optional[str] = None) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Collect NTFS $LogFile (Transaction Log).

        $LogFile contains transaction records for all metadata changes.
        Critical for forensic analysis:
        - File creation/deletion details
        - Attribute modifications
        - Data run changes (anti-forensics detection)
        - Short-term timeline reconstruction

        Args:
            output_path: Custom output path (default: output_dir/$LogFile)

        Returns:
            Tuple of (output_path, metadata) or None on failure
        """
        try:
            logfile = self.fs.open("/$LogFile")

            if output_path is None:
                output_path = str(self.output_dir / "$LogFile")

            sha256 = hashlib.sha256()
            md5 = hashlib.md5()
            total_size = logfile.info.meta.size
            bytes_written = 0

            with open(output_path, 'wb') as out_file:
                offset = 0
                while offset < total_size:
                    chunk_size = min(self.CHUNK_SIZE, total_size - offset)
                    data = logfile.read_random(offset, chunk_size)

                    if not data:
                        break

                    out_file.write(data)
                    sha256.update(data)
                    md5.update(data)
                    bytes_written += len(data)
                    offset += len(data)

            metadata = {
                'artifact_type': 'logfile',
                'original_path': f"{self.volume}:/$LogFile",
                'filename': '$LogFile',
                'size': bytes_written,
                'sha256': sha256.hexdigest(),
                'md5': md5.hexdigest(),
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'mft_raw_read',
                'description': 'NTFS Transaction Log - metadata change history',
                'forensic_value': {
                    'high_priority_operations': [
                        'InitializeFileRecordSegment (file creation)',
                        'DeallocateFileRecordSegment (file deletion)',
                        'DeleteAttribute (anti-forensics indicator)',
                        'UpdateMappingPairs (data hiding)',
                    ],
                    'retention': 'hours to days (circular log)',
                    'kill_chain_phase': 'defense_evasion',
                },
            }

            return output_path, metadata

        except Exception as e:
            _debug_print(f"[MFT] Error collecting $LogFile: {e}")
            return None

    def scan_deleted_files(
        self,
        extensions: Optional[List[str]] = None,
        min_size: int = 0,
        max_size: int = 100 * 1024 * 1024  # 100MB default max
    ) -> Generator[MFTEntryInfo, None, None]:
        """
        Scan for deleted files in MFT.

        Args:
            extensions: List of file extensions to look for (e.g., ['.docx', '.pdf'])
            min_size: Minimum file size
            max_size: Maximum file size

        Yields:
            MFTEntryInfo for each deleted file found
        """
        try:
            # Walk entire filesystem
            root = self.fs.open("/")

            for entry in self._walk_directory(root, "", include_deleted=True, recursive=True):
                if entry.info.meta is None:
                    continue

                # Check if deleted
                is_allocated = bool(entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC)
                if is_allocated:
                    continue

                # Check if regular file
                if entry.info.meta.type != pytsk3.TSK_FS_META_TYPE_REG:
                    continue

                # Check size
                size = entry.info.meta.size if hasattr(entry.info.meta, 'size') else 0
                if size < min_size or size > max_size:
                    continue

                # Check extension
                if extensions:
                    name_bytes = self._get_entry_name_bytes(entry.info.name)
                    if name_bytes is None:
                        continue
                    filename = name_bytes.decode('utf-8', errors='replace')
                    ext = Path(filename).suffix.lower()
                    if ext not in [e.lower() for e in extensions]:
                        continue

                mft_info = self.get_mft_entry_info(entry)
                if mft_info:
                    yield mft_info

        except Exception as e:
            _debug_print(f"[MFT] Error scanning deleted files: {e}")


# Artifact type definitions for MFT-based collection
MFT_ARTIFACT_TYPES = {
    'prefetch': {
        'name': 'Prefetch Files',
        'description': 'Program execution history',
        'base_path': 'Windows/Prefetch',
        'pattern': '*.pf',
        'requires_admin': True,
    },
    'eventlog': {
        'name': 'Event Logs',
        'description': 'Windows event logs',
        'base_path': 'Windows/System32/winevt/Logs',
        'pattern': '*.evtx',
        'requires_admin': True,
    },
    'registry_system': {
        'name': 'SYSTEM Registry',
        'description': 'System registry hive',
        'base_path': 'Windows/System32/config',
        'files': ['SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY'],
        'requires_admin': True,
    },
    'amcache': {
        'name': 'Amcache',
        'description': 'Application compatibility cache',
        'base_path': 'Windows/AppCompat/Programs',
        'files': ['Amcache.hve'],
        'requires_admin': True,
    },
    'srum': {
        'name': 'SRUM Database',
        'description': 'System Resource Usage Monitor',
        'base_path': 'Windows/System32/sru',
        'files': ['SRUDB.dat'],
        'requires_admin': True,
    },
    'recycle_bin': {
        'name': 'Recycle Bin',
        'description': 'Deleted files metadata',
        'base_path': '$Recycle.Bin',
        'pattern': '$I*',
        'recursive': True,
        'requires_admin': True,
    },
    'recent': {
        'name': 'Recent Documents',
        'description': 'Recently accessed files',
        'user_path': 'AppData/Roaming/Microsoft/Windows/Recent',
        'pattern': '*.lnk',
        'requires_admin': False,
    },
    'mft': {
        'name': 'Master File Table',
        'description': 'NTFS file table containing all file metadata',
        'special': 'collect_mft_raw',
        'requires_admin': True,
    },
    'usn_journal': {
        'name': 'USN Journal',
        'description': 'File change journal',
        'special': 'collect_usn_journal',
        'requires_admin': True,
    },
    'logfile': {
        'name': 'NTFS $LogFile',
        'description': 'NTFS Transaction Log - metadata change history',
        'special': 'collect_logfile',
        'requires_admin': True,
        'forensic_value': 'defense_evasion detection, file creation/deletion timeline',
    },
}


def is_mft_available() -> bool:
    """Check if MFT collection is available"""
    return PYTSK3_AVAILABLE


def check_admin_privileges() -> bool:
    """Check if running with administrator privileges"""
    try:
        if sys.platform == 'win32':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


if __name__ == "__main__":
    # Test MFT collection
    if not PYTSK3_AVAILABLE:
        print("pytsk3 not available")
        sys.exit(1)

    if not check_admin_privileges():
        print("Administrator privileges required")
        sys.exit(1)

    import tempfile

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            collector = MFTCollector('C', temp_dir)

            # Test collecting prefetch files
            print("Collecting Prefetch files...")
            for path, metadata in collector.collect_by_pattern(
                "Windows/Prefetch", "*.pf", "prefetch"
            ):
                print(f"  Collected: {metadata['filename']} (MFT#{metadata['mft_entry_number']})")

            # Test $MFT collection
            print("\nCollecting $MFT...")
            result = collector.collect_mft_raw()
            if result:
                print(f"  $MFT size: {result[1]['size']:,} bytes")

            collector.close()

        except Exception as e:
            print(f"Error: {e}")
