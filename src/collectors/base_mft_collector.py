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

import re
import hashlib
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
# Debug Logging (disabled in production)
# =============================================================================

def _debug_log(message: str):
    """Debug logging (disabled in production)"""
    # Disabled in production
    # Uncomment below for debugging
    # logger.debug(message)
    pass

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
    elif filesystem_lower in ('ext2', 'ext3', 'ext4'):
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


# =============================================================================
# MFT Filter Definitions (E01 + Local combined) - Windows
# =============================================================================

ARTIFACT_MFT_FILTERS = {
    # =========================================================================
    # Windows System Artifacts
    # =========================================================================
    'prefetch': {
        'path_pattern': r'windows/prefetch/',
        'extensions': {'.pf'},
        'include_deleted': True,
        'description': 'Program execution history',
    },
    'eventlog': {
        'path_pattern': r'windows/system32/winevt/logs/',
        'extensions': {'.evtx'},
        'include_deleted': True,
        'description': 'Windows event logs',
    },
    'registry': {
        'files': {'system', 'software', 'sam', 'security', 'default', 'ntuser.dat',
                  'usrclass.dat', 'amcache.hve'},
        'path_patterns': [r'windows/system32/config/', r'users/'],
        'include_deleted': True,
        'description': 'Windows registry hives',
    },
    'amcache': {
        'files': {'amcache.hve'},
        'path_pattern': r'windows/appcompat/programs/',
        'path_optional': True,  # Unique filename - collect even without path
        'include_deleted': True,
        'description': 'Application compatibility cache',
    },
    'userassist': {
        'files': {'ntuser.dat'},
        'path_pattern': r'users/',
        'include_deleted': True,
        'description': 'User activity tracking',
    },

    # =========================================================================
    # NTFS System Files
    # =========================================================================
    'mft': {
        'special': 'collect_mft_raw',
        'inode': 0,
        'include_deleted': False,
        'description': 'Master File Table',
    },
    'logfile': {
        'special': 'collect_logfile',
        'inode': 2,
        'include_deleted': False,
        'description': 'NTFS Transaction Log',
    },
    'usn_journal': {
        'special': 'collect_usn_journal',
        'path_pattern': r'\$extend/',
        'files': {'$usnjrnl'},
        'include_deleted': False,
        'description': 'USN Journal ($UsnJrnl:$J)',
    },

    # =========================================================================
    # Browser Artifacts
    # =========================================================================
    'browser': {
        'files': {'history', 'cookies', 'login data', 'web data', 'places.sqlite',
                  'cookies.sqlite', 'formhistory.sqlite', 'downloads'},
        'path_patterns': [
            r'appdata/local/google/chrome/',
            r'appdata/local/microsoft/edge/',
            r'appdata/roaming/mozilla/firefox/',
        ],
        'path_optional': True,  # Collect by filename only during MFT scan even without path
        'include_deleted': True,
        'description': 'Browser history, cookies, credentials',
    },

    # =========================================================================
    # USB & External Devices
    # =========================================================================
    'usb': {
        'files': {'setupapi.dev.log'},
        'path_pattern': r'windows/inf/',
        'path_optional': True,  # Unique filename - collect even without path
        'include_deleted': True,
        'description': 'USB device connection history',
    },

    # =========================================================================
    # Recent Activity
    # =========================================================================
    'recent': {
        'path_patterns': [
            r'appdata/roaming/microsoft/windows/recent/',
            r'appdata/roaming/microsoft/office/recent/',
        ],
        'extensions': {'.lnk'},
        'include_deleted': True,
        'description': 'Recently accessed files',
    },
    'jumplist': {
        'path_patterns': [
            r'appdata/roaming/microsoft/windows/recent/automaticdestinations/',
            r'appdata/roaming/microsoft/windows/recent/customdestinations/',
        ],
        'extensions': {'.automaticdestinations-ms', '.customdestinations-ms'},
        'include_deleted': True,
        'description': 'Jump lists (taskbar history)',
    },
    'shortcut': {
        'extensions': {'.lnk'},
        'include_deleted': True,
        'description': 'Shortcut files',
    },

    # =========================================================================
    # Recycle Bin
    # =========================================================================
    'recycle_bin': {
        # Recycle Bin path patterns (only forward slashes after path normalization)
        'path_patterns': [
            r'\$recycle\.bin/',         # Standard: $Recycle.Bin/
            r'recycle\.bin/',           # Without $ prefix
            r'\$recycle\.bin$',         # Path ends with $Recycle.Bin
        ],
        'include_deleted': True,
        'description': 'Deleted files in Recycle Bin ($I metadata + $R files)',
    },

    # =========================================================================
    # System Resources
    # =========================================================================
    'srum': {
        'files': {'srudb.dat'},
        'path_patterns': [r'windows/system32/sru/'],
        'path_optional': True,  # Unique filename - collect even without path
        'include_deleted': True,
        'description': 'System Resource Usage Monitor',
    },
    'scheduled_task': {
        'path_pattern': r'windows/system32/tasks/',
        'include_deleted': True,
        'description': 'Scheduled tasks',
    },

    # =========================================================================
    # User Profile
    # =========================================================================
    'shellbags': {
        'files': {'ntuser.dat', 'usrclass.dat'},
        'path_pattern': r'users/',
        'include_deleted': True,
        'description': 'Explorer folder browsing history',
    },
    'thumbcache': {
        'path_pattern': r'appdata/local/microsoft/windows/explorer/',
        'name_pattern': r'thumbcache_.*\.db',
        'include_deleted': True,
        'description': 'Thumbnail cache',
    },

    # =========================================================================
    # User Files - Server-parseable extensions only (based on server parser config)
    # =========================================================================
    'document': {
        'extensions': {
            '.doc', '.docx',      # Word (python-docx, olefile)
            '.xls', '.xlsx',      # Excel (openpyxl, olefile)
            '.ppt', '.pptx',      # PowerPoint (olefile)
            '.pdf',               # PDF (pypdf)
            '.hwp', '.hwpx',      # Hangul (olefile)
        },
        'include_deleted': True,
        'include_system_folders': True,
        'full_disk_scan': True,
        'description': 'Office documents, PDFs (server-parseable only)',
    },
    'email': {
        'extensions': {'.eml', '.msg', '.pst', '.ost'},  # email, extract_msg, pypff
        'include_deleted': True,
        'include_system_folders': True,
        'full_disk_scan': True,
        'description': 'Email files (.eml, .msg, .pst, .ost)',
    },

    # =========================================================================
    # Command History & Execution Artifacts (Phase 2)
    # =========================================================================
    'powershell_history': {
        'files': {'consolehost_history.txt'},
        'path_pattern': r'appdata/roaming/microsoft/windows/powershell/psreadline/',
        'path_optional': True,  # Unique filename - collect even without path
        'include_deleted': True,
        'description': 'PowerShell command history (PSReadLine)',
    },
    'wer': {
        'path_patterns': [
            r'programdata/microsoft/windows/wer/',
            r'appdata/local/microsoft/windows/wer/',
        ],
        'extensions': {'.wer', '.txt', '.hdmp', '.mdmp'},
        'include_deleted': True,
        'description': 'Windows Error Reporting (crash dumps, reports)',
    },
    'rdp_cache': {
        'path_pattern': r'appdata/local/microsoft/terminal server client/cache/',
        'name_pattern': r'(bcache|cache).*\.(bmc|bin)',
        'include_deleted': True,
        'description': 'RDP Bitmap Cache (remote desktop thumbnails)',
    },

    # =========================================================================
    # Phase 3: Supplementary Artifacts
    # =========================================================================
    'wlan_event': {
        'files': {'microsoft-windows-wlan-autoconfig%4operational.evtx'},
        'path_pattern': r'windows/system32/winevt/logs/',
        'path_optional': True,  # Unique filename - collect even without path
        'include_deleted': True,
        'description': 'WLAN Auto-Config event log (WiFi connection history)',
    },
    'profile_list': {
        # ProfileList is included in SOFTWARE registry
        # Automatically handled during registry collection
        'files': {'software'},
        'path_pattern': r'windows/system32/config/',
        'include_deleted': True,
        'description': 'User profile list (SOFTWARE registry)',
    },
    # [2026-01-29] Added image, video - server parsing support (EXIF, ffprobe)
    'image': {
        'path_patterns': [
            r'users/[^/]+/pictures/',
            r'users/[^/]+/downloads/',
            r'users/[^/]+/desktop/',
            r'users/[^/]+/documents/',
        ],
        'extensions': {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.heic', '.heif', '.webp'},
        'include_deleted': False,  # Exclude deleted images (storage concerns)
        'max_file_size': 50 * 1024 * 1024,  # 50MB limit
        'description': 'Image files with EXIF/GPS metadata',
    },
    'video': {
        'path_patterns': [
            r'users/[^/]+/videos/',
            r'users/[^/]+/downloads/',
            r'users/[^/]+/desktop/',
        ],
        'extensions': {'.mp4', '.avi', '.mov', '.mkv', '.wmv', '.flv', '.webm', '.m4v', '.mpg', '.mpeg', '.3gp'},
        'include_deleted': False,  # Exclude deleted videos (storage concerns)
        'max_file_size': 500 * 1024 * 1024,  # 500MB limit
        'description': 'Video files with metadata (ffprobe)',
    },

    # =========================================================================
    # [2026-01] P0 New Artifacts - High Forensic Value
    # =========================================================================
    'activities_cache': {
        'path_pattern': r'appdata/local/connecteddevicesplatform/',
        'files': {'activitiescache.db', 'activitiescache.db-wal', 'activitiescache.db-shm'},
        'path_optional': True,
        'include_deleted': True,
        'description': 'Windows Timeline (ActivitiesCache.db) - includes app execution duration',
    },
    'pca_launch': {
        'path_pattern': r'windows/appcompat/pca/',
        'name_pattern': r'pca.*\.txt',
        'include_deleted': True,
        'description': 'Program Compatibility Assistant (Win11+) - execution records',
    },
    'etl_log': {
        'path_patterns': [
            r'windows/system32/wdi/logfiles/',
            r'windows/system32/logfiles/wmi/',
            r'windows/panther/',
        ],
        'extensions': {'.etl'},
        'include_deleted': True,
        'description': 'ETW AutoLogger - persists even after event log deletion',
    },
    'wmi_subscription': {
        'path_pattern': r'windows/system32/wbem/repository/',
        'files': {'objects.data', 'index.btr'},
        'name_pattern': r'mapping.*\.map',
        'include_deleted': True,
        'description': 'WMI Event Subscription - persistence mechanism detection (MITRE T1546.003)',
    },
    'defender_detection': {
        'path_patterns': [
            r'programdata/microsoft/windows defender/scans/history/service/detectionhistory/',
            r'programdata/microsoft/windows defender/support/',
        ],
        'name_pattern': r'(mpdetection.*\.bin|mplog.*\.log)',
        'include_deleted': True,
        'description': 'Windows Defender detection history',
    },
    'zone_identifier': {
        # Zone.Identifier is an Alternate Data Stream (ADS)
        # Cannot collect directly via MFT - use artifact_collector's collect_zone_identifier
        'special': 'collect_zone_identifier',
        'include_deleted': False,
        'description': 'Zone.Identifier (ADS) - download file origin information',
    },
    'bits_jobs': {
        'path_pattern': r'programdata/microsoft/network/downloader/',
        'files': {'qmgr0.dat', 'qmgr1.dat'},
        'path_optional': True,
        'include_deleted': True,
        'description': 'BITS Transfer Jobs - malware download detection (MITRE T1197)',
    },

    # =========================================================================
    # [2026-01] Network/RDP/Share Artifacts
    # =========================================================================
    'rdp_history': {
        # RDP connection history (Terminal Server Client)
        # Registry: NTUSER.DAT\Software\Microsoft\Terminal Server Client
        'files': {'ntuser.dat'},
        'path_pattern': r'users/',
        'include_deleted': True,
        'description': 'RDP connection history (Terminal Server Client MRU)',
    },
    'wireless_profile': {
        # WiFi profiles (NetworkList)
        # Registry: SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList
        'files': {'software'},
        'path_pattern': r'windows/system32/config/',
        'include_deleted': True,
        'description': 'WiFi profiles (NetworkList - SSID, MAC, connection time)',
    },
    'shared_folder': {
        # Shared folder settings (LanmanServer\Shares)
        # Registry: SYSTEM\CurrentControlSet\Services\LanmanServer\Shares
        'files': {'system'},
        'path_pattern': r'windows/system32/config/',
        'include_deleted': True,
        'description': 'Shared folder settings (LanmanServer\\Shares)',
    },
    'mapped_drive': {
        # Network drive mapping (HKCU\Network)
        # Registry: NTUSER.DAT\Network, Map Network Drive MRU
        'files': {'ntuser.dat'},
        'path_pattern': r'users/',
        'include_deleted': True,
        'description': 'Network drive mapping (HKCU\\Network)',
    },

    # =========================================================================
    # [2026-01] Cloud Storage Artifacts
    # =========================================================================
    'cloud_onedrive': {
        'path_patterns': [
            r'appdata/local/microsoft/onedrive/',
            r'appdata/local/microsoft/windows/onedrive/',
        ],
        'files': {'settings.dat', 'syncengine.db', 'syncdiagnostics.txt'},
        'extensions': {'.odl', '.etl'},
        'path_optional': True,
        'include_deleted': True,
        'description': 'Microsoft OneDrive sync logs and settings',
    },
    'cloud_google_drive': {
        'path_patterns': [
            r'appdata/local/google/drive/',
            r'appdata/local/google/drivefilesync/',
        ],
        'files': {'sync_log.log', 'sync_config.db', 'cloud_graph.db', 'metadata_sqlite_db'},
        'path_optional': True,
        'include_deleted': True,
        'description': 'Google Drive sync logs (includes file hashes, emails)',
    },
    'cloud_dropbox': {
        'path_patterns': [
            r'appdata/local/dropbox/',
            r'appdata/roaming/dropbox/',
        ],
        'files': {'filecache.db', 'host.db', 'config.dbx', 'sync_history.db', 'aggregation.dbx'},
        'path_optional': True,
        'include_deleted': True,
        'description': 'Dropbox sync DB and cache',
    },
    'cloud_naver_mybox': {
        'path_patterns': [
            r'appdata/local/naver/navercloud/',
            r'appdata/local/naver/naverbox/',
            r'appdata/local/naverbox/',
        ],
        'files': {'sync.db', 'naverbox.db', 'sync_log.db'},
        'extensions': {'.db', '.log'},
        'path_optional': True,
        'include_deleted': True,
        'description': 'Naver MyBox (Naver Cloud) sync DB',
    },
    'cloud_icloud': {
        'path_patterns': [
            r'appdata/local/apple inc/clouddocs/',
            r'appdata/local/apple computer/clouddocs/',
            r'appdata/roaming/apple computer/mobilesync/',
        ],
        'files': {'cloudkit.db', 'sqlite3'},
        'path_optional': True,
        'include_deleted': True,
        'description': 'iCloud Drive sync data',
    },

    # =========================================================================
    # [2026-01] Office MRU and Application MRU
    # =========================================================================
    'office_mru': {
        # Office MRU is parsed from NTUSER.DAT
        # Path: NTUSER.DAT\Software\Microsoft\Office\{version}\{app}\File MRU
        'files': {'ntuser.dat'},
        'path_pattern': r'users/',
        'include_deleted': True,
        'description': 'Office document MRU (Word, Excel, PowerPoint recent files)',
    },
    'comdlg_mru': {
        # ComDlg32 MRU (common dialog boxes)
        # Path: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32
        'files': {'ntuser.dat'},
        'path_pattern': r'users/',
        'include_deleted': True,
        'description': 'Common dialog MRU (OpenSavePidlMRU, LastVisitedPidlMRU)',
    },
    'application_mru': {
        # Application-specific MRU (Paint, ALZip, Acrobat, etc.)
        # Path: NTUSER.DAT\Software\{app_path}\Recent File List
        'files': {'ntuser.dat'},
        'path_pattern': r'users/',
        'include_deleted': True,
        'description': 'Per-application MRU (Paint, ALZip, Acrobat, etc. recent files)',
    },

    # =========================================================================
    # [2026-02-15] PC Messengers & Programs
    # Collect only parser-required file types (not entire directories)
    # =========================================================================
    'windows_kakaotalk': {
        'path_pattern': r'appdata/local/kakao/kakaotalk/',
        'extensions': {'.edb', '.dat', '.ini'},
        'include_deleted': False,
        'description': 'KakaoTalk PC (*.edb, profile.dat, appstate.dat)',
    },
    'windows_line': {
        'path_pattern': r'appdata/local/line/data/',
        'extensions': {'.edb'},
        'include_deleted': False,
        'description': 'LINE PC encrypted databases (*.edb)',
    },
    'windows_telegram': {
        'path_pattern': r'appdata/roaming/telegram desktop/tdata/',
        # tdata files are extensionless binary; exclude media/stickers
        'exclude_extensions': {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.svg',
                               '.tiff', '.heic', '.tgs', '.mp4', '.avi', '.mov', '.webm',
                               '.mp3', '.ogg', '.wav', '.html', '.css', '.js'},
        'include_deleted': False,
        'description': 'Telegram Desktop tdata (keys + encrypted data)',
    },
    'windows_wechat': {
        'path_patterns': [r'documents/xwechat_files/', r'documents/wechat files/'],
        'extensions': {'.db', '.db-wal', '.db-shm'},
        'include_deleted': False,
        'description': 'WeChat Desktop encrypted databases (*.db)',
    },
    'windows_whatsapp': {
        'path_pattern': r'appdata/local/packages/5319275a.whatsappdesktop.*localstate/',
        'extensions': {'.db', '.db-wal', '.db-shm', '.dat', '.ldb', '.log'},
        'include_deleted': False,
        'description': 'WhatsApp Desktop (SEE DBs, DPAPI keys, IndexedDB)',
    },
    'windows_discord': {
        'path_patterns': [
            r'appdata/roaming/discord/local storage/leveldb/',
            r'appdata/roaming/discord/userdatacache\.json',
        ],
        'include_deleted': False,
        'description': 'Discord Desktop LevelDB + user data cache',
    },
    'windows_teamviewer': {
        'path_patterns': [r'appdata/roaming/teamviewer/', r'programdata/teamviewer/'],
        'extensions': {'.txt', '.log'},
        'include_deleted': False,
        'description': 'TeamViewer connection logs (*.txt, *.log)',
    },
    'windows_anydesk': {
        'path_patterns': [r'appdata/roaming/anydesk/', r'programdata/anydesk/'],
        'extensions': {'.trace', '.conf', '.txt'},
        'include_deleted': False,
        'description': 'AnyDesk trace and config files',
    },
    'windows_google_drive': {
        'path_pattern': r'appdata/local/google/drivefs/',
        'extensions': {'.db', '.db-wal', '.db-shm'},
        'include_deleted': False,
        'description': 'Google Drive Desktop sync databases (*.db)',
    },
    'windows_thunderbird': {
        'path_pattern': r'appdata/roaming/thunderbird/',
        'extensions': {'.sqlite', '.js'},
        'include_deleted': False,
        'description': 'Thunderbird email databases and config (*.sqlite, prefs.js)',
    },
}


# =============================================================================
# Base MFT Collector (Abstract)
# =============================================================================

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
            # Full MFT scan - no limits, includes deleted files
            scan_result = self._accessor.scan_all_files(
                include_deleted=True,
                max_entries=None,
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

        all_files = self._mft_cache['active_files'] + self._mft_cache['deleted_files']

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

        # Check all filter sets: Windows + Linux + macOS
        all_filters = {**ARTIFACT_MFT_FILTERS, **LINUX_ARTIFACT_FILTERS, **MACOS_ARTIFACT_FILTERS}
        if artifact_type not in all_filters:
            logger.debug(f"Skipping unsupported artifact type: {artifact_type}")
            return

        mft_filter = dict(all_filters[artifact_type])  # shallow copy to allow override
        # UI include_deleted override
        if 'include_deleted' in kwargs:
            mft_filter['include_deleted'] = kwargs['include_deleted']
        source = self._get_source_description()
        logger.info(f"[{source}] Collecting {artifact_type}, filter={mft_filter}")

        # Build MFT index (first time only)
        if not self._mft_indexed:
            self._build_mft_index()

        # Per-artifact output directory
        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)

        # Handle special artifacts ($MFT, $LogFile, $UsnJrnl) — NTFS only
        if 'special' in mft_filter:
            # Skip NTFS-specific special artifacts on non-NTFS filesystems
            os_type = mft_filter.get('os_type', 'windows')
            if os_type != 'windows':
                logger.debug(f"[{source}] Skipping NTFS special artifact {artifact_type} on {os_type}")
                return
            logger.info(f"[{source}] Detected special artifact: {mft_filter.get('special')}")
            yield from self._collect_special_artifact(
                artifact_type, mft_filter, artifact_dir, progress_callback
            )
            return

        # Regular artifact collection (MFT filter-based)
        logger.info(f"[{source}] Collecting {artifact_type} using MFT filter...")

        extracted_count = 0
        for result in self._collect_by_mft_filter(artifact_type, mft_filter, artifact_dir):
            extracted_count += 1
            yield result
            if progress_callback:
                progress_callback(result[0])

        logger.info(f"[{source}] Collected {extracted_count:,} {artifact_type} artifacts")

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

        # Files to collect
        files_to_check = list(self._mft_cache['active_files'])
        if include_deleted:
            files_to_check.extend(self._mft_cache['deleted_files'])

        # Filter conditions
        extensions = mft_filter.get('extensions', set())
        exclude_extensions = mft_filter.get('exclude_extensions', set())
        target_files = mft_filter.get('files', set())
        path_pattern = mft_filter.get('path_pattern')
        path_patterns = mft_filter.get('path_patterns', [])
        name_pattern = mft_filter.get('name_pattern')
        path_optional = mft_filter.get('path_optional', False)  # Collect by filename only even without path

        # Convert Linux/macOS 'paths' list into path_patterns + target_files
        # 'paths' entries are absolute paths like '/var/log/auth.log' or
        # glob patterns like '/home/*/.bash_history', '/etc/cron.d/*'
        artifact_paths = mft_filter.get('paths', [])
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

        # Extension-based fast filtering (for full disk scan)
        if extensions and full_disk_scan:
            file_counter = 0
            for ext in extensions:
                ext_lower = ext.lower()
                ext_count = len(self._extension_index.get(ext_lower, []))
                _debug_log(f"[SCAN] Extension {ext_lower}: {ext_count} files to process")

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
                    if file_counter % 500 == 0:
                        _debug_log(f"[PROGRESS] {artifact_type}: Processing file #{file_counter} - {filename}")

                    yield from self._extract_entry(artifact_type, entry, artifact_dir)
            return

        # Full scan (path/filename based)
        for entry in files_to_check:
            filename = entry.filename if hasattr(entry, 'filename') else str(entry)
            filename_lower = filename.lower()
            full_path = entry.full_path if hasattr(entry, 'full_path') else ""
            # [2026-01-29] Normalize path separators (backslash -> forward slash)
            full_path_lower = full_path.lower().replace('\\', '/') if full_path else ""

            if not include_deleted and getattr(entry, 'is_deleted', False):
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
            if not matched and compiled_patterns and not extensions and not target_files:
                for pattern in compiled_patterns:
                    if pattern.search(full_path_lower):
                        matched = True
                        break

            # 4. Name pattern check
            if compiled_name_pattern and not matched:
                if compiled_name_pattern.match(filename_lower):
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
                        _debug_log(f"[SKIP] {filename} exceeds max size ({entry_size / 1024 / 1024:.1f}MB > {max_file_size / 1024 / 1024:.0f}MB)")
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
        full_path = entry.full_path if hasattr(entry, 'full_path') else f"MFT_{inode}"
        is_deleted = getattr(entry, 'is_deleted', False)
        file_size = getattr(entry, 'size', 0)

        if inode is None:
            return

        # Debug: Large file warning
        if file_size > 100 * 1024 * 1024:  # 100MB or larger
            _debug_log(f"[DEBUG] Large file detected: {filename} ({file_size / 1024 / 1024:.1f}MB)")

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
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            total_size = 0
            has_data = False

            # Timeout settings (max 5 minutes per file, 30 seconds per chunk)
            FILE_TIMEOUT = 300  # 5 minutes
            CHUNK_TIMEOUT = 30  # 30 seconds
            start_time = time.time()
            last_chunk_time = start_time

            # Check for streaming method
            if hasattr(self._accessor, 'stream_file_by_inode'):
                # Chunk streaming (supports large files)
                try:
                    _debug_log(f"[EXTRACT START] {filename} (inode={inode}, size={file_size})")
                    with open(output_file, 'wb') as f:
                        chunk_count = 0
                        stream_generator = self._accessor.stream_file_by_inode(inode)
                        _debug_log(f"[STREAM READY] {filename}")
                        for chunk in stream_generator:
                            current_time = time.time()

                            # Check overall file timeout
                            if current_time - start_time > FILE_TIMEOUT:
                                _debug_log(f"[TIMEOUT] File extraction timeout ({FILE_TIMEOUT}s): {filename}")
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
                                    _debug_log(f"[PROGRESS] {filename}: {total_size / 1024 / 1024:.1f}MB written")

                except Exception as stream_error:
                    _debug_log(f"[STREAM ERROR] {filename}: {stream_error}")
                    # Delete partially written file
                    if output_file.exists() and total_size == 0:
                        output_file.unlink()
                    return

            else:
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
                md5_hash = hashlib.md5()
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
                md5_hash = hashlib.md5()
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
                    # [2026-01] Skip sparse regions (solves memory/size issues)
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

                # [2026-01-29] Clear log when USN Journal is not available
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
                        'hash_md5': hashlib.md5(data).hexdigest(),
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
                                'hash_md5': hashlib.md5(ads_data).hexdigest(),
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
