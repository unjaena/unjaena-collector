# -*- coding: utf-8 -*-
"""
E01 Artifact Collector

Collector for extracting artifacts from E01 evidence images.
Inherits from BaseMFTCollector to use MFT-based collection.

Digital Forensics Principles:
- MFT parsing-based collection (no directory traversal)
- No file count limit
- Includes deleted files
- Includes system folders

Usage:
    collector = E01ArtifactCollector("evidence.E01", output_dir="./extracted")
    partitions = collector.list_partitions()
    collector.select_partition(0)

    for file_path, metadata in collector.collect("registry"):
        _debug_print(f"Extracted: {file_path}")
"""

import logging
import tempfile
from pathlib import Path
from typing import Generator, Tuple, Dict, Any, List, Optional
from dataclasses import dataclass

# Import base class
from collectors.base_mft_collector import BaseMFTCollector, ARTIFACT_MFT_FILTERS

# Import ForensicDiskAccessor
try:
    from collectors.forensic_disk import ForensicDiskAccessor, FORENSIC_DISK_AVAILABLE
except ImportError:
    FORENSIC_DISK_AVAILABLE = False
    ForensicDiskAccessor = None

logger = logging.getLogger(__name__)

# Debug output control
_DEBUG_OUTPUT = False
def _debug_print(msg):
    if _DEBUG_OUTPUT: print(msg)


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class PartitionInfo:
    """Partition information"""
    index: int
    offset: int
    size: int
    filesystem: str
    type_name: str
    bootable: bool = False


@dataclass
class ExtractedArtifact:
    """Extracted artifact information"""
    local_path: str           # Local storage path
    original_path: str        # Original path (within image)
    artifact_type: str        # Artifact type
    filename: str             # Filename
    size: int                 # Size
    sha256: str               # SHA256 hash
    md5: str                  # MD5 hash
    metadata: Dict[str, Any]  # Additional metadata


# =============================================================================
# Legacy Artifact Path Mappings (backward compatibility)
# =============================================================================

ARTIFACT_PATHS = {
    'registry': {
        'description': 'Windows Registry Hives',
        'paths': [
            ('Windows/System32/config/SYSTEM', 'System Registry'),
            ('Windows/System32/config/SOFTWARE', 'Software Registry'),
            ('Windows/System32/config/SAM', 'SAM Registry'),
            ('Windows/System32/config/SECURITY', 'Security Registry'),
            ('Windows/System32/config/DEFAULT', 'Default Registry'),
        ],
        'user_paths': [
            ('NTUSER.DAT', 'User Registry Hive'),
        ],
        'pattern': None,
    },
    'prefetch': {
        'description': 'Windows Prefetch Files',
        'paths': [
            ('Windows/Prefetch', 'Prefetch Directory'),
        ],
        'pattern': '*.pf',
    },
    'eventlog': {
        'description': 'Windows Event Logs',
        'paths': [
            ('Windows/System32/winevt/Logs', 'Event Logs'),
        ],
        'pattern': '*.evtx',
    },
    'browser': {
        'description': 'Browser Data',
        'user_paths': [
            ('AppData/Local/Google/Chrome/User Data/Default/History', 'Chrome History'),
            ('AppData/Local/Google/Chrome/User Data/Default/Cookies', 'Chrome Cookies'),
            ('AppData/Local/Microsoft/Edge/User Data/Default/History', 'Edge History'),
            ('AppData/Roaming/Mozilla/Firefox/Profiles', 'Firefox Profiles'),
        ],
        'pattern': None,
    },
    'usb': {
        'description': 'USB Device History',
        'paths': [
            ('Windows/INF/setupapi.dev.log', 'SetupAPI Device Log'),
            ('Windows/inf/setupapi.dev.log', 'SetupAPI Device Log (lowercase)'),
        ],
        'pattern': None,
    },
    'recent': {
        'description': 'Recent Files',
        'user_paths': [
            ('AppData/Roaming/Microsoft/Windows/Recent', 'Recent Files'),
        ],
        'pattern': '*.lnk',
    },
    'mft': {
        'description': 'Master File Table',
        'special': 'collect_mft_raw',
    },
    'logfile': {
        'description': 'NTFS $LogFile',
        'special': 'collect_logfile',
    },
    'usn_journal': {
        'description': 'USN Journal',
        'special': 'collect_usn_journal',
    },
    'amcache': {
        'description': 'Amcache.hve',
        'paths': [
            ('Windows/AppCompat/Programs/Amcache.hve', 'Amcache'),
        ],
        'pattern': None,
    },
    'userassist': {
        'description': 'UserAssist (NTUSER.DAT)',
        'user_paths': [
            ('NTUSER.DAT', 'User Registry'),
        ],
        'pattern': None,
    },
    'recycle_bin': {
        'description': 'Recycle Bin',
        'paths': [
            ('$Recycle.Bin', 'Recycle Bin'),
        ],
        'pattern': '$I*',
    },
    'srum': {
        'description': 'SRUM Database',
        'paths': [
            ('Windows/System32/sru/SRUDB.dat', 'SRUM'),
            ('Windows/System32/SRU/SRUDB.dat', 'SRUM (uppercase)'),
        ],
        'pattern': None,
    },
    'jumplist': {
        'description': 'Jump Lists',
        'user_paths': [
            ('AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations', 'Auto Destinations'),
            ('AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations', 'Custom Destinations'),
        ],
        'pattern': '*.automaticDestinations-ms,*.customDestinations-ms',
    },
    'shortcut': {
        'description': 'Shortcut Files',
        'user_paths': [
            ('Desktop', 'Desktop Shortcuts'),
        ],
        'pattern': '*.lnk',
    },
    'scheduled_task': {
        'description': 'Scheduled Tasks',
        'paths': [
            ('Windows/System32/Tasks', 'Scheduled Tasks'),
        ],
        'pattern': '*',
    },
    'shellbags': {
        'description': 'ShellBags',
        'user_paths': [
            ('NTUSER.DAT', 'NTUSER.DAT'),
            ('AppData/Local/Microsoft/Windows/UsrClass.dat', 'UsrClass.dat'),
        ],
        'pattern': None,
    },
    'thumbcache': {
        'description': 'Thumbnail Cache',
        'user_paths': [
            ('AppData/Local/Microsoft/Windows/Explorer', 'Explorer Cache'),
        ],
        'pattern': 'thumbcache_*.db',
    },
    'document': {
        'description': 'Documents',
        'pattern': '*.doc,*.docx,*.pdf,*.xls,*.xlsx,*.ppt,*.pptx,*.hwp,*.hwpx,*.txt,*.rtf',
    },
    'email': {
        'description': 'Email Files',
        'pattern': '*.pst,*.ost,*.eml,*.msg',
    },
    'image': {
        'description': 'Image Files',
        'pattern': '*.jpg,*.jpeg,*.png,*.gif,*.bmp,*.tiff,*.webp,*.heic,*.raw',
    },
    'video': {
        'description': 'Video Files',
        'pattern': '*.mp4,*.avi,*.mkv,*.mov,*.wmv,*.flv,*.webm,*.mpeg',
    },
    # Mobile artifacts (skip for E01)
    'mobile_android_sms': {'skip': True},
    'mobile_android_call': {'skip': True},
    'mobile_android_contacts': {'skip': True},
    'mobile_android_app': {'skip': True},
    'mobile_android_wifi': {'skip': True},
    'mobile_android_location': {'skip': True},
    'mobile_android_media': {'skip': True},
    'mobile_ios_sms': {'skip': True},
    'mobile_ios_call': {'skip': True},
    'mobile_ios_contacts': {'skip': True},
    'mobile_ios_safari': {'skip': True},
    'mobile_ios_location': {'skip': True},
    'mobile_ios_backup': {'skip': True},
}


# =============================================================================
# E01 Artifact Collector
# =============================================================================

class E01ArtifactCollector(BaseMFTCollector):
    """
    E01 Image Artifact Collector

    Inherits from BaseMFTCollector to use MFT-based collection.

    Digital Forensics Principles:
    - MFT parsing-based collection (no directory traversal)
    - No file count limit
    - Includes deleted files
    - Includes system folders
    """

    def __init__(self, e01_path: str, output_dir: str = None):
        """
        Args:
            e01_path: E01 image file path (first segment)
            output_dir: Directory to store extracted artifacts
                       (Uses system temp directory if None)
        """
        self.e01_path = Path(e01_path)
        self._owns_temp_dir = False

        if output_dir is None:
            # Use temp directory (to avoid including E01 files during local collection)
            output_dir = tempfile.mkdtemp(prefix="e01_extract_")
            self._owns_temp_dir = True

        super().__init__(output_dir)

        self._selected_partition: Optional[int] = None
        self._partitions: List[PartitionInfo] = []
        self._user_folders: List[str] = []

        self._initialize_accessor()

    def _initialize_accessor(self) -> bool:
        """Initialize ForensicDiskAccessor"""
        if not FORENSIC_DISK_AVAILABLE or ForensicDiskAccessor is None:
            logger.error("ForensicDiskAccessor not available")
            return False

        try:
            self._accessor = ForensicDiskAccessor.from_e01(str(self.e01_path))
            logger.info(f"E01 image loaded: {self.e01_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load E01 image: {e}")
            self._accessor = None
            return False

    def _get_source_description(self) -> str:
        """Return source description"""
        return f"E01: {self.e01_path.name}"

    # =========================================================================
    # Partition Management
    # =========================================================================

    def list_partitions(self) -> List[PartitionInfo]:
        """List partitions"""
        if not self._accessor:
            return []

        try:
            raw_partitions = self._accessor.list_partitions()
            self._partitions = []

            for i, p in enumerate(raw_partitions):
                self._partitions.append(PartitionInfo(
                    index=i,
                    offset=p.offset,
                    size=p.size,
                    filesystem=p.filesystem,
                    type_name=p.type_name,
                    bootable=getattr(p, 'is_bootable', False),
                ))

            return self._partitions

        except Exception as e:
            logger.error(f"Failed to list partitions: {e}")
            return []

    def select_partition(self, index: int) -> bool:
        """Select partition"""
        if not self._accessor:
            return False

        try:
            self._accessor.select_partition(index)
            self._selected_partition = index
            logger.info(f"Selected partition {index}")

            # Discover user folders
            self._discover_user_folders()

            # Initialize MFT index
            self._mft_indexed = False
            self._mft_cache = {'active_files': [], 'deleted_files': [], 'directories': []}
            self._extension_index = {}

            return True

        except Exception as e:
            logger.error(f"Failed to select partition {index}: {e}")
            return False

    def get_windows_partition(self) -> Optional[int]:
        """Auto-detect Windows partition"""
        if not self._partitions:
            self.list_partitions()

        for p in self._partitions:
            if p.filesystem.upper() == 'NTFS' and p.size > 20 * 1024 * 1024 * 1024:
                # Select NTFS partition larger than 20GB
                return p.index

        # Select largest NTFS partition
        ntfs_partitions = [p for p in self._partitions if p.filesystem.upper() == 'NTFS']
        if ntfs_partitions:
            largest = max(ntfs_partitions, key=lambda p: p.size)
            return largest.index

        return None

    def _discover_user_folders(self) -> None:
        """Discover user directories within Users folder"""
        if not self._accessor:
            return

        self._user_folders = []
        system_folders = {'public', 'default', 'default user', 'all users', 'desktop.ini'}

        try:
            # Find Users directory
            users_inode = self._accessor.resolve_path('/Users')
            if users_inode is None:
                users_inode = self._accessor.resolve_path('/users')

            if users_inode is None:
                logger.warning("Users directory not found")
                return

            # List user folders
            entries = self._accessor.list_directory(users_inode)
            for entry in entries:
                name = entry.filename if hasattr(entry, 'filename') else str(entry)
                is_dir = entry.is_directory if hasattr(entry, 'is_directory') else False

                if is_dir and name.lower() not in system_folders:
                    self._user_folders.append(name)

            logger.info(f"Found {len(self._user_folders)} user folders: {self._user_folders}")

        except Exception as e:
            logger.debug(f"Error discovering user folders: {e}")

    # =========================================================================
    # Collection (inherits from BaseMFTCollector)
    # =========================================================================

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None,
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts (MFT-based)

        Args:
            artifact_type: Type of artifact to collect
            progress_callback: Progress callback

        Yields:
            (local_path, metadata) tuple
        """
        if self._selected_partition is None:
            logger.error("No partition selected. Call select_partition() first.")
            return

        # Skip mobile artifacts
        if artifact_type in ARTIFACT_PATHS and ARTIFACT_PATHS[artifact_type].get('skip'):
            logger.debug(f"Skipping {artifact_type} (not applicable for E01)")
            return

        # Use base class implementation
        yield from super().collect(artifact_type, progress_callback, **kwargs)

    # =========================================================================
    # Utilities
    # =========================================================================

    def get_image_info(self) -> Dict[str, Any]:
        """Return E01 image information"""
        if not self._accessor:
            return {}

        return {
            'path': str(self.e01_path),
            'partitions': len(self._partitions),
            'selected_partition': self._selected_partition,
            'user_folders': self._user_folders,
        }

    def close(self):
        """Cleanup resources"""
        super().close()
        self._selected_partition = None
        self._partitions = []
        self._user_folders = []

        # Cleanup temp directory (only if we created it)
        if self._owns_temp_dir and self.output_dir.exists():
            try:
                import shutil
                shutil.rmtree(self.output_dir)
                logger.debug(f"Cleaned up temp directory: {self.output_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup temp directory {self.output_dir}: {e}")
