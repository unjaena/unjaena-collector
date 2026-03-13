# -*- coding: utf-8 -*-
"""
Forensic Disk Collector - Layered Fallback Collector

Collects locked files using ForensicDiskAccessor,
with fallback in order: MFT -> Legacy on failure.

Collection Priority:
1. ForensicDiskAccessor (raw sector access) - Direct locked file reading
2. MFTCollector (pytsk3) - MFT-based collection
3. Legacy (shutil) - Standard file copy

Features:
- Direct Registry hive reading (SYSTEM, SAM, SOFTWARE, SECURITY)
- pagefile.sys collection (analysis performed on server)
- hiberfil.sys collection (analysis performed on server)
- ADS (Alternate Data Streams) extraction
- Deleted file recovery

Note: This collector only performs file collection.
      All analysis logic is handled server-side.
"""

import os
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Generator, Tuple, Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# Debug output control
_DEBUG_OUTPUT = False
def _debug_print(msg):
    if _DEBUG_OUTPUT: print(msg)

# Try to import ForensicDiskAccessor
try:
    from collectors.forensic_disk import (
        ForensicDiskAccessor,
        FORENSIC_DISK_AVAILABLE
    )
except ImportError:
    FORENSIC_DISK_AVAILABLE = False
    ForensicDiskAccessor = None

# Note: Memory analyzers removed from collector
# All analysis must be performed on the server side
# Collector only collects raw files without analysis


# Files that benefit from ForensicDiskAccessor
LOCKED_FILE_PATHS = {
    'registry': [
        '/Windows/System32/config/SYSTEM',
        '/Windows/System32/config/SOFTWARE',
        '/Windows/System32/config/SAM',
        '/Windows/System32/config/SECURITY',
        '/Windows/System32/config/DEFAULT',
    ],
    'amcache': [
        '/Windows/AppCompat/Programs/Amcache.hve',
    ],
    'pagefile': [
        '/pagefile.sys',
    ],
    'hiberfil': [
        '/hiberfil.sys',
    ],
    'srudb': [
        '/Windows/System32/sru/SRUDB.dat',
    ],
}


class ForensicDiskCollector:
    """
    Layered Fallback Forensic Collector

    Attempts collection in order: ForensicDiskAccessor -> MFTCollector -> Legacy.

    Usage:
        with ForensicDiskCollector(output_dir, 'C') as collector:
            for path, metadata in collector.collect_registry():
                _debug_print(f"Collected: {path}")
    """

    def __init__(
        self,
        output_dir: str,
        volume: str = 'C',
        use_forensic_disk: bool = True
    ):
        """
        Initialize

        Args:
            output_dir: Path to store collection results
            volume: Target volume (default: 'C')
            use_forensic_disk: Whether to use ForensicDiskAccessor
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.volume = volume.upper().rstrip(':')

        # Collection mode tracking
        self.collection_mode = 'legacy'
        self.accessor: Optional[ForensicDiskAccessor] = None

        # Initialize ForensicDiskAccessor if available
        if use_forensic_disk and FORENSIC_DISK_AVAILABLE:
            try:
                # Get physical drive number from volume letter
                drive_number = self._get_physical_drive_number()
                if drive_number is not None:
                    self.accessor = ForensicDiskAccessor.from_physical_disk(drive_number)
                    # Select partition for the volume
                    partition_idx = self._find_partition_for_volume()
                    if partition_idx is not None:
                        self.accessor.select_partition(partition_idx)
                        self.collection_mode = 'forensic_disk_accessor'
                        logger.info(f"ForensicDiskAccessor initialized for {self.volume}:")
            except Exception as e:
                logger.warning(f"ForensicDiskAccessor initialization failed: {e}")
                self.accessor = None

        if self.accessor is None:
            logger.info("Using fallback collection mode")

    def _get_physical_drive_number(self) -> Optional[int]:
        """Get physical drive number from volume letter"""
        try:
            import ctypes
            from ctypes import wintypes

            # Get volume path
            volume_path = f"\\\\.\\{self.volume}:"

            # Open volume
            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.CreateFileW(
                volume_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )

            if handle == -1:
                # Typically C: drive is PhysicalDrive0
                return 0

            try:
                # IOCTL to get disk extents
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000

                class DISK_EXTENT(ctypes.Structure):
                    _fields_ = [
                        ("DiskNumber", wintypes.DWORD),
                        ("StartingOffset", ctypes.c_int64),
                        ("ExtentLength", ctypes.c_int64),
                    ]

                class VOLUME_DISK_EXTENTS(ctypes.Structure):
                    _fields_ = [
                        ("NumberOfDiskExtents", wintypes.DWORD),
                        ("Extents", DISK_EXTENT * 1),
                    ]

                extents = VOLUME_DISK_EXTENTS()
                bytes_returned = wintypes.DWORD()

                result = kernel32.DeviceIoControl(
                    handle,
                    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                    None, 0,
                    ctypes.byref(extents),
                    ctypes.sizeof(extents),
                    ctypes.byref(bytes_returned),
                    None
                )

                if result:
                    return extents.Extents[0].DiskNumber
            finally:
                kernel32.CloseHandle(handle)

            return 0  # Default to drive 0

        except Exception as e:
            logger.warning(f"Failed to get physical drive number: {e}")
            return 0  # Default

    def _find_partition_for_volume(self) -> Optional[int]:
        """Find partition index for volume"""
        if self.accessor is None:
            return None

        try:
            partitions = self.accessor.list_partitions()

            # C: drive is typically the first NTFS partition
            for i, part in enumerate(partitions):
                if part.filesystem == 'NTFS':
                    # Select first NTFS partition by default
                    # More accurate matching requires volume serial number comparison
                    return i

            # If no NTFS, select first partition
            if partitions:
                return 0

        except Exception as e:
            logger.warning(f"Failed to find partition: {e}")

        return 0

    def close(self):
        """Cleanup resources"""
        if self.accessor:
            try:
                self.accessor.close()
            except:
                pass
            self.accessor = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def read_locked_file(self, path: str, max_size: int = None) -> Optional[bytes]:
        """
        Read locked file

        Args:
            path: File path (e.g., '/Windows/System32/config/SYSTEM')
            max_size: Maximum read size

        Returns:
            File content (bytes) or None
        """
        if self.accessor is None:
            return None

        try:
            return self.accessor.read_file(path, max_size=max_size)
        except Exception as e:
            logger.warning(f"Failed to read locked file {path}: {e}")
            return None

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None,
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect by artifact type

        Args:
            artifact_type: 'registry', 'pagefile', 'hiberfil', 'srudb', 'amcache'
            progress_callback: Progress callback
            **kwargs: Additional arguments (e.g. include_deleted) - accepted for interface compatibility

        Yields:
            (storage_path, metadata) tuple
        """
        if artifact_type == 'registry':
            yield from self.collect_registry(progress_callback)
        elif artifact_type == 'pagefile':
            yield from self.collect_pagefile(progress_callback)
        elif artifact_type == 'hiberfil':
            yield from self.collect_hiberfil(progress_callback)
        elif artifact_type == 'amcache':
            yield from self.collect_amcache(progress_callback)
        elif artifact_type == 'srudb':
            yield from self.collect_srudb(progress_callback)
        else:
            logger.debug(f"Skipping unsupported artifact type: {artifact_type}")

    def collect_registry(
        self,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect Registry hives

        Yields:
            (storage_path, metadata) tuple
        """
        registry_dir = self.output_dir / 'registry'
        registry_dir.mkdir(exist_ok=True)

        paths = LOCKED_FILE_PATHS['registry']
        total = len(paths)

        for i, path in enumerate(paths):
            if progress_callback:
                progress_callback(i + 1, total, f"Collecting {Path(path).name}")

            filename = Path(path).name
            dst_path = registry_dir / filename

            try:
                if self.accessor:
                    # Direct read via ForensicDiskAccessor
                    data = self.accessor.read_file(path)
                    if data:
                        dst_path.write_bytes(data)
                        metadata = self._create_metadata(path, dst_path, 'registry', data)
                        metadata['collection_method'] = 'forensic_disk_accessor'
                        yield str(dst_path), metadata
                        continue
            except Exception as e:
                logger.warning(f"ForensicDiskAccessor failed for {path}: {e}")

            # Fallback: Try standard file copy
            win_path = f"{self.volume}:{path.replace('/', os.sep)}"
            if Path(win_path).exists():
                try:
                    import shutil
                    shutil.copy2(win_path, dst_path)
                    metadata = self._create_metadata(path, dst_path, 'registry')
                    metadata['collection_method'] = 'legacy'
                    yield str(dst_path), metadata
                except (PermissionError, OSError) as e:
                    logger.warning(f"Legacy copy failed for {path}: {e}")

    def collect_pagefile(
        self,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect pagefile.sys

        Yields:
            (storage_path, metadata) tuple
        """
        pagefile_dir = self.output_dir / 'pagefile'
        pagefile_dir.mkdir(exist_ok=True)

        path = '/pagefile.sys'
        dst_path = pagefile_dir / 'pagefile.sys'

        if progress_callback:
            progress_callback(1, 1, "Collecting pagefile.sys")

        try:
            if self.accessor:
                # Collect large file via streaming
                with open(dst_path, 'wb') as f:
                    for chunk in self.accessor.stream_file(path, chunk_size=64*1024*1024):
                        f.write(chunk)

                metadata = self._create_metadata(path, dst_path, 'pagefile')
                metadata['collection_method'] = 'forensic_disk_accessor'
                yield str(dst_path), metadata
                # Note: Analysis removed - performed on server side

        except Exception as e:
            logger.error(f"Failed to collect pagefile.sys: {e}")

    def collect_hiberfil(
        self,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect hiberfil.sys (hibernation file)

        Yields:
            (storage_path, metadata) tuple
        """
        hiberfil_dir = self.output_dir / 'hiberfil'
        hiberfil_dir.mkdir(exist_ok=True)

        path = '/hiberfil.sys'
        dst_path = hiberfil_dir / 'hiberfil.sys'

        if progress_callback:
            progress_callback(1, 1, "Collecting hiberfil.sys")

        try:
            if self.accessor:
                with open(dst_path, 'wb') as f:
                    for chunk in self.accessor.stream_file(path, chunk_size=64*1024*1024):
                        f.write(chunk)

                metadata = self._create_metadata(path, dst_path, 'hiberfil')
                metadata['collection_method'] = 'forensic_disk_accessor'
                yield str(dst_path), metadata
                # Note: Analysis removed - performed on server side

        except Exception as e:
            logger.error(f"Failed to collect hiberfil.sys: {e}")

    def collect_amcache(
        self,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect Amcache.hve

        Yields:
            (storage_path, metadata) tuple
        """
        amcache_dir = self.output_dir / 'amcache'
        amcache_dir.mkdir(exist_ok=True)

        path = '/Windows/AppCompat/Programs/Amcache.hve'
        dst_path = amcache_dir / 'Amcache.hve'

        if progress_callback:
            progress_callback(1, 1, "Collecting Amcache.hve")

        try:
            if self.accessor:
                data = self.accessor.read_file(path)
                if data:
                    dst_path.write_bytes(data)
                    metadata = self._create_metadata(path, dst_path, 'amcache', data)
                    metadata['collection_method'] = 'forensic_disk_accessor'
                    yield str(dst_path), metadata
                    return
        except Exception as e:
            logger.warning(f"ForensicDiskAccessor failed for Amcache: {e}")

        # Fallback
        win_path = f"{self.volume}:{path.replace('/', os.sep)}"
        if Path(win_path).exists():
            try:
                import shutil
                shutil.copy2(win_path, dst_path)
                metadata = self._create_metadata(path, dst_path, 'amcache')
                metadata['collection_method'] = 'legacy'
                yield str(dst_path), metadata
            except (PermissionError, OSError) as e:
                logger.warning(f"Legacy copy failed for Amcache: {e}")

    def collect_srudb(
        self,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect SRUDB.dat (System Resource Usage Monitor)

        Yields:
            (storage_path, metadata) tuple
        """
        srudb_dir = self.output_dir / 'srudb'
        srudb_dir.mkdir(exist_ok=True)

        path = '/Windows/System32/sru/SRUDB.dat'
        dst_path = srudb_dir / 'SRUDB.dat'

        if progress_callback:
            progress_callback(1, 1, "Collecting SRUDB.dat")

        try:
            if self.accessor:
                data = self.accessor.read_file(path)
                if data:
                    dst_path.write_bytes(data)
                    metadata = self._create_metadata(path, dst_path, 'srudb', data)
                    metadata['collection_method'] = 'forensic_disk_accessor'
                    yield str(dst_path), metadata
                    return
        except Exception as e:
            logger.warning(f"ForensicDiskAccessor failed for SRUDB: {e}")

        # Fallback
        win_path = f"{self.volume}:{path.replace('/', os.sep)}"
        if Path(win_path).exists():
            try:
                import shutil
                shutil.copy2(win_path, dst_path)
                metadata = self._create_metadata(path, dst_path, 'srudb')
                metadata['collection_method'] = 'legacy'
                yield str(dst_path), metadata
            except (PermissionError, OSError) as e:
                logger.warning(f"Legacy copy failed for SRUDB: {e}")

    def collect_ads(
        self,
        file_path: str,
        stream_name: str = 'Zone.Identifier'
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Collect ADS (Alternate Data Stream)

        Args:
            file_path: File path
            stream_name: ADS stream name (default: Zone.Identifier)

        Returns:
            (storage_path, metadata) tuple or None
        """
        if self.accessor is None:
            return None

        try:
            # Find file's MFT entry
            normalized_path = file_path.replace('\\', '/')
            if not normalized_path.startswith('/'):
                # C:\path\file → /path/file
                if ':' in normalized_path:
                    normalized_path = '/' + normalized_path.split(':', 1)[1]

            # Read ADS
            inode = self.accessor._resolve_path_to_inode(normalized_path)
            if inode is None:
                return None

            ads_data = self.accessor.read_file_by_inode(inode, stream_name=stream_name)
            if ads_data:
                filename = Path(file_path).name
                dst_path = self.output_dir / 'ads' / f"{filename}_{stream_name}"
                dst_path.parent.mkdir(exist_ok=True)
                dst_path.write_bytes(ads_data)

                metadata = {
                    'original_file': file_path,
                    'stream_name': stream_name,
                    'size': len(ads_data),
                    'artifact_type': 'ads',
                    'collection_method': 'forensic_disk_accessor',
                    'collection_time': datetime.now().isoformat(),
                }
                return str(dst_path), metadata

        except Exception as e:
            logger.warning(f"Failed to collect ADS {stream_name} from {file_path}: {e}")

        return None

    def _create_metadata(
        self,
        original_path: str,
        dst_path: Path,
        artifact_type: str,
        data: bytes = None
    ) -> Dict[str, Any]:
        """Create metadata"""
        metadata = {
            'original_path': original_path,
            'artifact_type': artifact_type,
            'collection_time': datetime.now().isoformat(),
            'volume': self.volume,
        }

        if dst_path.exists():
            stat = dst_path.stat()
            metadata['size'] = stat.st_size
            metadata['modified_time'] = datetime.fromtimestamp(stat.st_mtime).isoformat()

            # Calculate hash
            if data:
                metadata['md5'] = hashlib.md5(data).hexdigest()
                metadata['sha256'] = hashlib.sha256(data).hexdigest()
            else:
                with open(dst_path, 'rb') as f:
                    content = f.read()
                    metadata['md5'] = hashlib.md5(content).hexdigest()
                    metadata['sha256'] = hashlib.sha256(content).hexdigest()

        return metadata


# Module-level availability check
def is_forensic_disk_available() -> bool:
    """Check if ForensicDiskAccessor is available"""
    return FORENSIC_DISK_AVAILABLE


# Note: is_memory_analyzer_available() removed
# Analysis is performed on server side only
