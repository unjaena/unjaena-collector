"""
MFT-based Artifact Collector Module

NTFS MFT (Master File Table) Entry-based artifact collection.
Collection method aligned with digital forensics standards:
- Deleted file recovery capable
- File lock bypass
- MFT Entry metadata preservation
- Chain of Custody established

Now uses ForensicDiskAccessor (dissect/native MFT parser) instead of pytsk3.

Note: Administrator privileges required (Raw Disk Access)
"""
import os
import sys
import hashlib
import logging
import fnmatch
from pathlib import Path
from datetime import datetime, timezone
from typing import Generator, Tuple, Dict, Any, Optional, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


def _debug_print(message: str):
    """Debug output for MFT collection (mirrors artifact_collector._debug_print)."""
    logger.debug(message)


# Check for ForensicDiskAccessor availability
try:
    from collectors.forensic_disk import ForensicDiskAccessor, FORENSIC_DISK_AVAILABLE
    MFT_BACKEND_AVAILABLE = FORENSIC_DISK_AVAILABLE
except ImportError:
    try:
        from .forensic_disk import ForensicDiskAccessor, FORENSIC_DISK_AVAILABLE
        MFT_BACKEND_AVAILABLE = FORENSIC_DISK_AVAILABLE
    except ImportError:
        MFT_BACKEND_AVAILABLE = False
        ForensicDiskAccessor = None
        _debug_print("[WARNING] ForensicDiskAccessor not available. MFT collection will be disabled.")

# Legacy compatibility flag
PYTSK3_AVAILABLE = MFT_BACKEND_AVAILABLE


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

    Collects files by directly reading MFT Entries from NTFS file system
    via ForensicDiskAccessor (native MFT parser + dissect).

    Capabilities:
    - Deleted file recovery capable
    - OS-locked file collection capable
    - Complete metadata preservation

    Note: Administrator privileges required
    """

    # Buffer size for file reading
    CHUNK_SIZE = 1024 * 1024  # 1MB chunks

    def __init__(self, volume: str, output_dir: str, disk_reader=None):
        """
        Initialize MFT Collector.

        Args:
            volume: Drive letter (e.g., 'C')
            output_dir: Directory to store collected artifacts
            disk_reader: Optional UnifiedDiskReader for BitLocker decrypted volumes
        """
        if not MFT_BACKEND_AVAILABLE:
            raise RuntimeError(
                "ForensicDiskAccessor is required for MFT collection. "
                "Ensure forensic_disk package is available."
            )

        self.volume = volume.upper().rstrip(':')
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._accessor = None
        self._partition_selected = False

        self._open_volume(disk_reader)

    def _open_volume(self, disk_reader=None):
        """Open volume for raw access using ForensicDiskAccessor"""
        try:
            if disk_reader:
                # BitLocker decrypted reader
                self._accessor = ForensicDiskAccessor(disk_reader)
                _debug_print("[INFO] MFTCollector using BitLocker decrypted reader")
            else:
                # Physical disk access -- find the correct drive and partition
                drive_number = self._get_physical_drive_number()
                if drive_number is None:
                    raise RuntimeError(
                        f"Cannot determine physical drive for volume {self.volume}:"
                    )
                self._accessor = ForensicDiskAccessor.from_physical_disk(drive_number)
                _debug_print(f"[INFO] MFTCollector opened PhysicalDrive{drive_number}")

            # Find and select the correct partition
            self._select_volume_partition()

        except Exception as e:
            if self._accessor:
                try:
                    self._accessor.close()
                except Exception:
                    pass
                self._accessor = None
            raise RuntimeError(
                f"Cannot open volume {self.volume}: {e}\n"
                "Ensure you have administrator privileges."
            )

    def _get_physical_drive_number(self) -> Optional[int]:
        """Get physical drive number from volume letter (Windows only)"""
        if sys.platform != 'win32':
            return 0  # On non-Windows, assume drive 0

        try:
            import ctypes
            from ctypes import wintypes

            volume_path = f"\\\\.\\{self.volume}:"

            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000

            handle = ctypes.windll.kernel32.CreateFileW(
                volume_path, GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None, OPEN_EXISTING, 0, None
            )

            if handle == -1:
                return 0  # Default to drive 0

            class DISK_EXTENT(ctypes.Structure):
                _fields_ = [
                    ("DiskNumber", wintypes.DWORD),
                    ("StartingOffset", ctypes.c_longlong),
                    ("ExtentLength", ctypes.c_longlong),
                ]

            class VOLUME_DISK_EXTENTS(ctypes.Structure):
                _fields_ = [
                    ("NumberOfDiskExtents", wintypes.DWORD),
                    ("Extents", DISK_EXTENT * 1),
                ]

            extents = VOLUME_DISK_EXTENTS()
            bytes_returned = wintypes.DWORD()

            result = ctypes.windll.kernel32.DeviceIoControl(
                handle, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                None, 0,
                ctypes.byref(extents), ctypes.sizeof(extents),
                ctypes.byref(bytes_returned), None
            )

            ctypes.windll.kernel32.CloseHandle(handle)

            if result:
                return extents.Extents[0].DiskNumber
            return 0

        except Exception:
            return 0

    def _select_volume_partition(self):
        """Find and select the partition matching self.volume"""
        partitions = self._accessor.list_partitions()
        if not partitions:
            raise RuntimeError(f"No partitions found on disk for volume {self.volume}:")

        # Try to find NTFS partition
        ntfs_partitions = [
            (i, p) for i, p in enumerate(partitions)
            if p.filesystem in ('NTFS', 'BitLocker')
        ]

        if len(ntfs_partitions) == 1:
            idx = ntfs_partitions[0][0]
            self._accessor.select_partition(idx)
            self._partition_selected = True
            return

        # If multiple NTFS partitions, select the first non-system one,
        # or just the first one
        if ntfs_partitions:
            # Default to first NTFS partition
            idx = ntfs_partitions[0][0]
            self._accessor.select_partition(idx)
            self._partition_selected = True
            return

        # No NTFS found, try first partition
        self._accessor.select_partition(0)
        self._partition_selected = True

    def close(self):
        """Close volume handles"""
        if self._accessor:
            try:
                self._accessor.close()
            except Exception:
                pass
            self._accessor = None
        self._partition_selected = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _filetime_to_datetime(self, timestamp_int: int) -> Optional[datetime]:
        """
        Convert Unix timestamp (from ForensicDiskAccessor) to datetime.

        Args:
            timestamp_int: Unix timestamp (seconds since epoch)

        Returns:
            datetime object or None
        """
        if not timestamp_int or timestamp_int <= 0:
            return None

        try:
            return datetime.fromtimestamp(timestamp_int, tz=timezone.utc)
        except (OSError, ValueError, OverflowError):
            return None

    def collect_by_path(
        self,
        path: str,
        artifact_type: str = "unknown",
        include_deleted: bool = True
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect file by path using ForensicDiskAccessor.

        Args:
            path: File path relative to volume root (e.g., "Windows/Prefetch")
            artifact_type: Type of artifact for metadata
            include_deleted: Include deleted files

        Yields:
            Tuple of (output_path, metadata)
        """
        try:
            path = path.replace('\\', '/').lstrip('/')

            # Try reading as a single file first
            try:
                content = self._accessor.read_file(f"/{path}")
                yield from self._save_file_content(
                    content, path, artifact_type
                )
                return
            except Exception:
                pass

            # If that fails, treat it as a directory
            try:
                entries = self._accessor.list_directory(f"/{path}")
                for entry in entries:
                    if entry.is_directory:
                        continue
                    if not include_deleted and entry.is_deleted:
                        continue
                    try:
                        content = self._accessor.read_file_by_inode(entry.inode)
                        yield from self._save_file_content(
                            content, f"{path}/{entry.filename}", artifact_type,
                            entry=entry
                        )
                    except Exception as e:
                        _debug_print(f"[MFT] Error reading {entry.filename}: {e}")
            except Exception as e:
                _debug_print(f"[MFT] Error listing directory {path}: {e}")

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
        Collect files matching a pattern using ForensicDiskAccessor.

        Args:
            base_path: Base directory to search (e.g., "Windows/Prefetch")
            pattern: Filename pattern to match (e.g., "*.pf")
            artifact_type: Type of artifact for metadata
            include_deleted: Include deleted files
            recursive: Recursively walk subdirectories (default: True)

        Yields:
            Tuple of (output_path, metadata)
        """
        try:
            base_path = base_path.replace('\\', '/').strip('/')
            yield from self._walk_and_collect(
                f"/{base_path}", pattern, artifact_type, include_deleted, recursive
            )
        except Exception as e:
            _debug_print(f"[MFT] Error scanning {base_path}/{pattern}: {e}")

    def _walk_and_collect(
        self,
        dir_path: str,
        pattern: str,
        artifact_type: str,
        include_deleted: bool,
        recursive: bool,
        depth: int = 0,
        max_depth: int = 20
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Walk directory tree and collect files matching pattern."""
        if depth > max_depth:
            return

        try:
            entries = self._accessor.list_directory(dir_path)
        except Exception as e:
            _debug_print(f"[MFT] Cannot list directory {dir_path}: {e}")
            return

        for entry in entries:
            if entry.filename in ('.', '..'):
                continue

            if not include_deleted and entry.is_deleted:
                continue

            full_path = f"{dir_path.rstrip('/')}/{entry.filename}"

            if entry.is_directory and recursive:
                yield from self._walk_and_collect(
                    full_path, pattern, artifact_type,
                    include_deleted, recursive, depth + 1, max_depth
                )
            elif not entry.is_directory:
                # Match pattern
                if fnmatch.fnmatch(entry.filename.lower(), pattern.lower()):
                    try:
                        content = self._accessor.read_file_by_inode(entry.inode)
                        rel_path = full_path.lstrip('/')
                        yield from self._save_file_content(
                            content, rel_path, artifact_type, entry=entry
                        )
                    except Exception as e:
                        _debug_print(f"[MFT] Error reading {full_path}: {e}")

    def _save_file_content(
        self,
        content: bytes,
        rel_path: str,
        artifact_type: str,
        entry=None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Save file content and yield (output_path, metadata)."""
        try:
            filename = Path(rel_path).name

            # Build output path
            artifact_dir = self.output_dir / artifact_type
            artifact_dir.mkdir(exist_ok=True)

            output_filename = filename
            is_deleted = entry.is_deleted if entry else False

            if is_deleted:
                output_filename = f"[DELETED]_{output_filename}"

            if entry:
                output_filename = f"{entry.inode}_{output_filename}"

            output_path = artifact_dir / output_filename

            # Calculate hashes
            sha256 = hashlib.sha256(content).hexdigest()
            md5 = hashlib.md5(content, usedforsecurity=False).hexdigest()

            # Write content
            with open(output_path, 'wb') as out_file:
                out_file.write(content)

            # Build metadata
            metadata = {
                'artifact_type': artifact_type,
                'original_path': f"{self.volume}:/{rel_path}",
                'filename': filename,
                'size': len(content),
                'sha256': sha256,
                'md5': md5,
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'mft_raw_read',
                'is_deleted': is_deleted,
                'is_allocated': not is_deleted,
            }

            if entry:
                metadata['mft_entry_number'] = entry.inode
                metadata['mft_parent_entry'] = entry.parent_inode
                metadata['timestamps'] = {
                    'created': self._filetime_to_datetime(entry.created_time).isoformat()
                              if self._filetime_to_datetime(entry.created_time) else None,
                    'modified': self._filetime_to_datetime(entry.modified_time).isoformat()
                               if self._filetime_to_datetime(entry.modified_time) else None,
                }

            yield str(output_path), metadata

        except Exception as e:
            _debug_print(f"[MFT] Error saving file {rel_path}: {e}")

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
            if output_path is None:
                output_path = str(self.output_dir / "$MFT")

            sha256 = hashlib.sha256()
            md5 = hashlib.md5(usedforsecurity=False)
            bytes_written = 0

            with open(output_path, 'wb') as out_file:
                for chunk in self._accessor.stream_file("/$MFT"):
                    out_file.write(chunk)
                    sha256.update(chunk)
                    md5.update(chunk)
                    bytes_written += len(chunk)

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
            if output_path is None:
                output_path = str(self.output_dir / "$UsnJrnl_J")

            # Read the $J ADS via ForensicDiskAccessor
            # The USN Journal inode is typically at MFT entry for $Extend/$UsnJrnl
            sha256 = hashlib.sha256()
            md5 = hashlib.md5(usedforsecurity=False)
            bytes_written = 0

            try:
                # Try reading via ADS stream name
                content = self._accessor.read_file("/$Extend/$UsnJrnl:$J")
                sha256.update(content)
                md5.update(content)
                bytes_written = len(content)
                with open(output_path, 'wb') as out_file:
                    out_file.write(content)
            except Exception:
                # Fallback: try streaming the main file
                try:
                    with open(output_path, 'wb') as out_file:
                        for chunk in self._accessor.stream_file("/$Extend/$UsnJrnl"):
                            out_file.write(chunk)
                            sha256.update(chunk)
                            md5.update(chunk)
                            bytes_written += len(chunk)
                except Exception as e2:
                    _debug_print(f"[MFT] USN Journal read failed: {e2}")
                    return None

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
            if output_path is None:
                output_path = str(self.output_dir / "$LogFile")

            sha256 = hashlib.sha256()
            md5 = hashlib.md5(usedforsecurity=False)
            bytes_written = 0

            with open(output_path, 'wb') as out_file:
                for chunk in self._accessor.stream_file("/$LogFile"):
                    out_file.write(chunk)
                    sha256.update(chunk)
                    md5.update(chunk)
                    bytes_written += len(chunk)

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
            catalog = self._accessor.scan_all_files(include_deleted=True)

            for entry in catalog.get('deleted_files', []):
                size = entry.size
                if size < min_size or size > max_size:
                    continue

                # Check extension
                if extensions:
                    ext = Path(entry.filename).suffix.lower()
                    if ext not in [e.lower() for e in extensions]:
                        continue

                yield MFTEntryInfo(
                    entry_number=entry.inode,
                    sequence_number=0,
                    parent_entry=entry.parent_inode,
                    filename=entry.filename,
                    full_path=entry.full_path,
                    file_size=size,
                    is_directory=entry.is_directory,
                    is_deleted=True,
                    is_allocated=False,
                    created=self._filetime_to_datetime(entry.created_time),
                    modified=self._filetime_to_datetime(entry.modified_time),
                    resident_data=size < 700,
                )

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
    return MFT_BACKEND_AVAILABLE


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
    if not MFT_BACKEND_AVAILABLE:
        print("ForensicDiskAccessor not available")
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
                print(f"  Collected: {metadata['filename']} (inode#{metadata.get('mft_entry_number', '?')})")

            # Test $MFT collection
            print("\nCollecting $MFT...")
            result = collector.collect_mft_raw()
            if result:
                print(f"  $MFT size: {result[1]['size']:,} bytes")

            collector.close()

        except Exception as e:
            print(f"Error: {e}")
