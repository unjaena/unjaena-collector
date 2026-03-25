"""
Artifact Collector Module

Digital forensics artifact collection module.
MFT (Master File Table) based collection is used by default,
falling back to legacy methods when MFT is unavailable.

Collection methods:
- BaseMFTCollector: Unified MFT-based collection (shared for E01/Local)
- ForensicDiskAccessor: Pure Python raw disk access (recommended)
- Legacy: glob.glob + shutil.copy2 (fallback)

Note: MFT-based collection requires administrator privileges
"""
import os
import re
import sys
import glob
import shutil
import hashlib
import logging
import fnmatch
from pathlib import Path
from datetime import datetime
from typing import Generator, Tuple, Dict, Any, Optional, List

# macOS artifact filters for auto-registration in ARTIFACT_TYPES
try:
    from collectors.macos_artifacts import MACOS_ARTIFACT_FILTERS as _MACOS_FILTERS
except ImportError:
    _MACOS_FILTERS = {}

logger = logging.getLogger(__name__)

# =============================================================================
# Debug Output Control (disabled in production)
# =============================================================================
_DEBUG_OUTPUT = False  # Set to True to enable debug message output

def _debug_print(message: str):
    """Debug output (disabled in production)"""
    if _DEBUG_OUTPUT:
        print(message)

# Try to import BaseMFTCollector (unified base class)
try:
    from collectors.base_mft_collector import (
        BaseMFTCollector,
        ARTIFACT_MFT_FILTERS,
    )
    BASE_MFT_AVAILABLE = True
except ImportError:
    BASE_MFT_AVAILABLE = False
    BaseMFTCollector = None
    ARTIFACT_MFT_FILTERS = {}

# Try to import ForensicDiskAccessor (pure Python - preferred)
try:
    from collectors.forensic_disk import (
        ForensicDiskAccessor,
        FORENSIC_DISK_AVAILABLE
    )
except ImportError:
    FORENSIC_DISK_AVAILABLE = False
    ForensicDiskAccessor = None

# Try to import MFT collector (ForensicDiskAccessor-based fallback)
try:
    from collectors.mft_collector import (
        MFTCollector, MFT_ARTIFACT_TYPES,
        is_mft_available, check_admin_privileges
    )
    MFT_AVAILABLE = is_mft_available()
except ImportError:
    MFT_AVAILABLE = False
    MFTCollector = None

# Try to import Android collector
try:
    from collectors.android_collector import (
        AndroidCollector, ANDROID_ARTIFACT_TYPES,
        ADBDeviceMonitor, DeviceInfo,
        ADB_AVAILABLE,
    )
except ImportError:
    ADB_AVAILABLE = False
    ANDROID_ARTIFACT_TYPES = {}
    AndroidCollector = None
    ADBDeviceMonitor = None
    DeviceInfo = None

# Try to import iOS collector
try:
    from collectors.ios_collector import (
        iOSCollector, IOS_ARTIFACT_TYPES,
        find_ios_backups,
    )
    IOS_AVAILABLE = True
except ImportError:
    IOS_AVAILABLE = False
    IOS_ARTIFACT_TYPES = {}
    iOSCollector = None
    find_ios_backups = None

# Try to import Linux collector
try:
    from collectors.linux_collector import (
        LinuxCollector, LINUX_ARTIFACT_TYPES,
        check_linux_target
    )
    LINUX_AVAILABLE = True
except ImportError:
    LINUX_AVAILABLE = False
    LINUX_ARTIFACT_TYPES = {}
    LinuxCollector = None
    check_linux_target = None

# Try to import macOS collector
try:
    from collectors.macos_collector import (
        macOSCollector, MACOS_ARTIFACT_TYPES,
        check_macos_target
    )
    MACOS_AVAILABLE = True
except ImportError:
    MACOS_AVAILABLE = False
    MACOS_ARTIFACT_TYPES = {}
    macOSCollector = None
    check_macos_target = None

# =============================================================================
# C4 Security: Path Traversal Attack Defense Utilities
# =============================================================================

def validate_safe_path(base_dir: Path, target_path: Path) -> Path:
    """
    Verify that a path is inside base_dir

    Args:
        base_dir: Allowed base directory
        target_path: Target path to verify

    Returns:
        Verified path (in resolved state)

    Raises:
        ValueError: If path is outside base_dir
    """
    resolved_base = base_dir.resolve()
    resolved_target = target_path.resolve()

    try:
        resolved_target.relative_to(resolved_base)
    except ValueError:
        raise ValueError(
            f"[SECURITY] Path traversal detected: '{target_path}' "
            f"is outside allowed directory '{base_dir}'"
        )

    return resolved_target

def sanitize_path_component(name: str) -> str:
    """
    Remove dangerous characters from path component

    Args:
        name: Path component (filename or directory name)

    Returns:
        Safe name
    """
    # Remove path separators and parent directory references
    dangerous_chars = ['/', '\\', '..', '\x00']
    safe_name = name
    for char in dangerous_chars:
        safe_name = safe_name.replace(char, '_')

    # Use default if empty string
    if not safe_name.strip():
        safe_name = 'unnamed'

    return safe_name

# Artifact type definitions
ARTIFACT_TYPES = {
    'prefetch': {
        'name': 'Prefetch Files',
        'description': 'Program execution history',
        'paths': [r'C:\Windows\Prefetch\*.pf'],
        'mft_config': {
            'base_path': 'Windows/Prefetch',
            'pattern': '*.pf',
        },
        'requires_admin': True,
        'collector': 'collect_glob',
    },
    'eventlog': {
        'name': 'Event Logs',
        'description': 'Windows event logs (Security, System, Application)',
        'paths': [
            r'C:\Windows\System32\winevt\Logs\Security.evtx',
            r'C:\Windows\System32\winevt\Logs\System.evtx',
            r'C:\Windows\System32\winevt\Logs\Application.evtx',
            r'C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx',
        ],
        'mft_config': {
            'base_path': 'Windows/System32/winevt/Logs',
            'pattern': '*.evtx',
        },
        'requires_admin': True,
        'collector': 'collect_files',
    },
    'registry': {
        'name': 'Registry Hives',
        'description': 'System registry hives (SYSTEM, SOFTWARE, SAM)',
        'paths': [
            r'C:\Windows\System32\config\SYSTEM',
            r'C:\Windows\System32\config\SOFTWARE',
            r'C:\Windows\System32\config\SAM',
            r'C:\Windows\System32\config\SECURITY',
        ],
        'mft_config': {
            'base_path': 'Windows/System32/config',
            'files': ['SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY'],
        },
        'requires_admin': True,
        'collector': 'collect_locked_files',
    },
    'amcache': {
        'name': 'Amcache',
        'description': 'Application compatibility cache',
        'paths': [r'C:\Windows\AppCompat\Programs\Amcache.hve'],
        'mft_config': {
            'base_path': 'Windows/AppCompat/Programs',
            'files': ['Amcache.hve'],
        },
        'requires_admin': True,
        'collector': 'collect_locked_files',
    },
    'userassist': {
        'name': 'UserAssist',
        'description': 'User activity tracking (NTUSER.DAT)',
        'paths': [],  # Dynamic paths per user
        'mft_config': {
            'user_path': 'NTUSER.DAT',
        },
        'requires_admin': False,
        'collector': 'collect_ntuser',
    },
    'browser': {
        'name': 'Browser Data',
        'description': 'Chrome, Edge, Firefox history, downloads, and cookies',
        'browsers': {
            'chrome': {
                'name': 'Google Chrome',
                'paths': [
                    r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\History',
                    r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Downloads',
                    r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies',
                    r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data',
                ],
                'mft_path': 'AppData/Local/Google/Chrome/User Data/Default',
                'files': ['History', 'Downloads', 'Cookies', 'Login Data'],
            },
            'edge': {
                'name': 'Microsoft Edge',
                'paths': [
                    r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History',
                    r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Downloads',
                    r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies',
                    r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data',
                ],
                'mft_path': 'AppData/Local/Microsoft/Edge/User Data/Default',
                'files': ['History', 'Downloads', 'Cookies', 'Login Data'],
            },
            'firefox': {
                'name': 'Mozilla Firefox',
                'paths': [
                    r'%APPDATA%\Mozilla\Firefox\Profiles\*\places.sqlite',
                    r'%APPDATA%\Mozilla\Firefox\Profiles\*\cookies.sqlite',
                    r'%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json',
                    r'%APPDATA%\Mozilla\Firefox\Profiles\*\formhistory.sqlite',
                ],
                'mft_path': 'AppData/Roaming/Mozilla/Firefox/Profiles',
                'files': ['places.sqlite', 'cookies.sqlite', 'logins.json', 'formhistory.sqlite'],
                'profile_based': True,
            },
        },
        'requires_admin': False,
        'collector': 'collect_all_browsers',
    },
    'recent': {
        'name': 'Recent Documents',
        'description': 'Recently accessed files',
        'paths': [r'%APPDATA%\Microsoft\Windows\Recent\*.lnk'],
        'mft_config': {
            'user_path': 'AppData/Roaming/Microsoft/Windows/Recent',
            'pattern': '*.lnk',
        },
        'requires_admin': False,
        'collector': 'collect_user_glob',
    },
    'recycle_bin': {
        'name': 'Recycle Bin',
        'description': 'Deleted files metadata',
        'paths': [r'C:\$Recycle.Bin'],  # Recycle Bin root path
        'mft_config': {
            'base_path': '$Recycle.Bin',
            'pattern': '$I*',
            'recursive': True,
        },
        'requires_admin': True,
        'collector': 'collect_recycle_bin',  # [2026-01] Use dedicated collector
    },
    'usb': {
        'name': 'USB History',
        'description': 'USB device connection history',
        'paths': [
            r'C:\Windows\INF\setupapi.dev.log',
            r'C:\Windows\System32\config\SYSTEM',  # USB device info (USBSTOR, MountedDevices, etc.)
        ],
        'mft_config': {
            'base_path': 'Windows/INF',
            'files': ['setupapi.dev.log'],
            'additional_paths': [
                {'base_path': 'Windows/System32/config', 'files': ['SYSTEM']}
            ],
        },
        'requires_admin': True,
        'collector': 'collect_files',
    },
    'srum': {
        'name': 'SRUM Database',
        'description': 'System Resource Usage Monitor',
        'paths': [r'C:\Windows\System32\sru\SRUDB.dat'],
        'mft_config': {
            'base_path': 'Windows/System32/sru',
            'files': ['SRUDB.dat'],
        },
        'requires_admin': True,
        'collector': 'collect_locked_files',
    },
    # MFT-specific artifacts (only available with MFT collection)
    'mft': {
        'name': 'Master File Table',
        'description': 'NTFS MFT containing all file metadata',
        'paths': [],  # Not collectable via legacy method
        'mft_config': {
            'special': 'collect_mft_raw',
        },
        'requires_admin': True,
        'requires_mft': True,
        'subcategory': 'filesystem',
        'collector': None,
    },
    'usn_journal': {
        'name': 'USN Journal',
        'description': 'File change journal ($UsnJrnl:$J)',
        'paths': [],  # Not collectable via legacy method
        'mft_config': {
            'special': 'collect_usn_journal',
        },
        'requires_admin': True,
        'requires_mft': True,
        'subcategory': 'filesystem',
        'collector': None,
    },
    'logfile': {
        'name': 'NTFS $LogFile',
        'description': 'NTFS Transaction Log - metadata change history',
        'paths': [],  # Not collectable via legacy method
        'mft_config': {
            'special': 'collect_logfile',
        },
        'requires_admin': True,
        'requires_mft': True,
        'subcategory': 'filesystem',
        'collector': None,
        'forensic_value': 'defense_evasion detection, file creation/deletion timeline',
    },

    # =========================================================================
    # Android Forensics Artifacts (Phase 2.1)
    # =========================================================================
    'mobile_android_sms': {
        'name': 'Android SMS/MMS',
        'description': 'Text messages and multimedia messages',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_system',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'sms',
    },
    'mobile_android_call': {
        'name': 'Android Call History',
        'description': 'Incoming, outgoing, and missed calls',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_system',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'call',
    },
    'mobile_android_contacts': {
        'name': 'Android Contacts',
        'description': 'Contact list and details',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_system',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'contacts',
    },
    'mobile_android_app': {
        'name': 'Android App Data',
        'description': 'Installed applications and their data',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_system',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'app',
    },
    'mobile_android_wifi': {
        'name': 'Android WiFi Settings',
        'description': 'Saved WiFi networks and credentials',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_system',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'wifi',
    },
    'mobile_android_location': {
        'name': 'Android Location History',
        'description': 'GPS and location data',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_system',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'location',
    },
    'mobile_android_media': {
        'name': 'Android Media Files',
        'description': 'Photos, videos, and audio files from DCIM/Pictures/Download',
        'paths': [],
        'category': 'android',
        'subcategory': 'basic',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'media',
    },
    'mobile_android_sms_provider': {
        'name': 'SMS/MMS (Content Provider)',
        'description': 'Text messages via Content Provider (non-root)',
        'paths': [],
        'category': 'android',
        'subcategory': 'basic',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'sms_provider',
    },
    'mobile_android_call_provider': {
        'name': 'Call History (Content Provider)',
        'description': 'Call logs via Content Provider (non-root)',
        'paths': [],
        'category': 'android',
        'subcategory': 'basic',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'call_provider',
    },
    'mobile_android_contacts_provider': {
        'name': 'Contacts (Content Provider)',
        'description': 'Contacts via Content Provider (non-root)',
        'paths': [],
        'category': 'android',
        'subcategory': 'basic',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'contacts_provider',
    },
    'mobile_android_calendar_provider': {
        'name': 'Calendar (Content Provider)',
        'description': 'Calendar events via Content Provider (non-root)',
        'paths': [],
        'category': 'android',
        'subcategory': 'basic',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'calendar_provider',
    },
    # =========================================================================
    # System Information (Combined - 8 sub-types)
    # =========================================================================
    'mobile_android_system_info': {
        'name': 'System Information',
        'description': 'System logs, installed packages, device settings, notifications, accounts, app usage, network connectivity',
        'paths': [],
        'category': 'android',
        'subcategory': 'basic',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'system_info',
    },

    # =========================================================================
    # iOS Forensics Artifacts (Phase 2.1)
    # =========================================================================
    'mobile_ios_sms': {
        'name': 'iOS iMessage/SMS',
        'description': 'Text messages and iMessages from iTunes/Finder backup',
        'paths': [],
        'category': 'ios',
        'subcategory': 'core',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'sms',
    },
    'mobile_ios_call': {
        'name': 'iOS Call History',
        'description': 'Phone call records from backup',
        'paths': [],
        'category': 'ios',
        'subcategory': 'core',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'call',
    },
    'mobile_ios_contacts': {
        'name': 'iOS Contacts',
        'description': 'Address book contacts from backup',
        'paths': [],
        'category': 'ios',
        'subcategory': 'core',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'contacts',
    },
    'mobile_ios_safari': {
        'name': 'iOS Safari',
        'description': 'Browser history, bookmarks, and tabs from backup',
        'paths': [],
        'category': 'ios',
        'subcategory': 'core',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'safari',
    },
    'mobile_ios_location': {
        'name': 'iOS Location History',
        'description': 'GPS and location data from backup',
        'paths': [],
        'category': 'ios',
        'subcategory': 'core',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'location',
    },
    'mobile_ios_backup': {
        'name': 'iOS Backup Metadata',
        'description': 'Backup configuration and device info (Info.plist, Manifest.plist)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'core',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'backup',
    },

    # =========================================================================
    # [2026-02-15] Windows PC Messenger Apps
    # Collect only parser-required artifacts (not entire directories)
    # =========================================================================
    'windows_kakaotalk': {
        'name': 'KakaoTalk PC',
        'description': 'KakaoTalk PC messages, user data, and process memory',
        'paths': [
            r'%LOCALAPPDATA%\Kakao\KakaoTalk\users\**\*.edb',      # chatLogs, TalkUserDB, chatListInfo
            r'%LOCALAPPDATA%\Kakao\KakaoTalk\users\**\*.dat',      # profile.dat, appstate.dat
            r'%LOCALAPPDATA%\Kakao\KakaoTalk\*.ini',               # config
            r'%LOCALAPPDATA%\Kakao\KakaoTalk\*.dat',               # config
        ],
        'mft_config': {
            'user_path': 'AppData/Local/Kakao/KakaoTalk',
            'pattern': '*',
            'extensions': ['.edb', '.dat', '.ini'],
        },
        'category': 'windows',
        'subcategory': 'pc_messenger',
        'requires_admin': False,
        'collector': 'collect_messenger_with_memory',
        'artifact_key': 'kakaotalk_pc',
        'forensic_value': 'chat messages, friend lists, chat rooms',
        'process_name': 'KakaoTalk.exe',
    },
    'windows_line': {
        'name': 'LINE PC',
        'description': 'LINE PC messages, user data, and process memory',
        'paths': [
            r'%LOCALAPPDATA%\LINE\Data\**\*.edb',                  # encrypted databases
        ],
        'mft_config': {
            'user_path': 'AppData/Local/LINE/Data',
            'pattern': '*',
            'extensions': ['.edb'],
        },
        'category': 'windows',
        'subcategory': 'pc_messenger',
        'requires_admin': False,
        'collector': 'collect_messenger_with_memory',
        'artifact_key': 'line_pc',
        'forensic_value': 'chat messages, friend lists, chat rooms',
        'process_name': 'LINE.exe',
    },
    'windows_telegram': {
        'name': 'Telegram Desktop',
        'description': 'Telegram Desktop tdata, session keys, and process memory',
        'paths': [
            r'%APPDATA%\Telegram Desktop\tdata\key_datas',         # encryption key (TDF$ binary)
            r'%APPDATA%\Telegram Desktop\tdata\settingss',         # settings (TDF$ binary)
            r'%APPDATA%\Telegram Desktop\tdata\*\*',               # hex user folders (maps + encrypted data)
        ],
        # tdata files are extensionless; exclude media/stickers that may exist in subdirs
        'exclude_extensions': ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.svg',
                               '.tiff', '.heic', '.tgs', '.mp4', '.avi', '.mov', '.webm',
                               '.mp3', '.ogg', '.wav', '.html', '.css', '.js'],
        'mft_config': {
            'user_path': 'AppData/Roaming/Telegram Desktop/tdata',
            'pattern': '*',
            'exclude_extensions': ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.svg',
                                   '.tiff', '.heic', '.tgs', '.mp4', '.avi', '.mov', '.webm',
                                   '.mp3', '.ogg', '.wav', '.html', '.css', '.js'],
        },
        'category': 'windows',
        'subcategory': 'pc_messenger',
        'requires_admin': False,
        'collector': 'collect_messenger_with_memory',
        'artifact_key': 'telegram_pc',
        'forensic_value': 'messages (from memory), session keys, settings',
        'process_name': 'Telegram.exe',
    },
    'windows_wechat': {
        'name': 'WeChat Desktop',
        'description': 'WeChat Desktop encrypted databases and process memory',
        'paths': [
            r'%USERPROFILE%\Documents\xwechat_files\**\*.db',      # encrypted DB files
            r'%USERPROFILE%\Documents\xwechat_files\**\*.db-wal',  # WAL files
            r'%USERPROFILE%\Documents\xwechat_files\**\*.db-shm',  # SHM files
            r'%USERPROFILE%\Documents\WeChat Files\**\*.db',       # legacy layout
            r'%USERPROFILE%\Documents\WeChat Files\**\*.db-wal',
            r'%USERPROFILE%\Documents\WeChat Files\**\*.db-shm',
        ],
        'mft_config': {
            'user_path': ['Documents/xwechat_files', 'Documents/WeChat Files'],
            'pattern': '*',
            'extensions': ['.db', '.db-wal', '.db-shm'],
        },
        'category': 'windows',
        'subcategory': 'pc_messenger',
        'requires_admin': False,
        'collector': 'collect_messenger_with_memory',
        'artifact_key': 'wechat_pc',
        'forensic_value': 'chat messages, contacts, chat rooms',
        'process_name': 'Weixin.exe',
    },
    'windows_whatsapp': {
        'name': 'WhatsApp Desktop',
        'description': 'WhatsApp Desktop encrypted databases, DPAPI keys, and process memory',
        'paths': [
            r'%LOCALAPPDATA%\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalState\**\*.db',      # SEE encrypted DBs
            r'%LOCALAPPDATA%\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalState\**\*.db-wal',  # WAL (contacts data!)
            r'%LOCALAPPDATA%\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalState\**\*.db-shm',  # SHM
            r'%LOCALAPPDATA%\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalState\*.dat',        # nondb_settings (DPAPI key)
            r'%LOCALAPPDATA%\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalState\IndexedDB\**\*',  # LevelDB (contacts+messages)
        ],
        'mft_config': {
            'user_path': 'AppData/Local/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalState',
            'pattern': '*',
            'extensions': ['.db', '.db-wal', '.db-shm', '.dat', '.ldb', '.log', '.sst'],
        },
        'category': 'windows',
        'subcategory': 'pc_messenger',
        'requires_admin': False,
        'collector': 'collect_messenger_with_memory',
        'artifact_key': 'whatsapp_pc',
        'forensic_value': 'chat messages, contacts, call history',
        'process_name': 'WhatsApp.exe',
    },

    # =========================================================================
    # [2026-02-15] Phase 1 PC Programs - Remote Access, Email, Cloud Storage
    # Collect only parser-required artifacts
    # =========================================================================
    'windows_discord': {
        'name': 'Discord Desktop',
        'description': 'Discord Desktop LevelDB data and user cache',
        'paths': [
            r'%APPDATA%\discord\Local Storage\leveldb\*',          # LevelDB (messages, tokens, activity)
            r'%APPDATA%\discord\userDataCache.json',               # user data cache
        ],
        'mft_config': {
            'user_path': 'AppData/Roaming/discord',
            'pattern': '*',
            'extensions': ['.ldb', '.log', '.sst', '.json'],
        },
        'category': 'windows',
        'subcategory': 'pc_apps',
        'requires_admin': False,
        'collector': 'collect_user_glob',
        'artifact_key': 'discord_pc',
        'forensic_value': 'user ID, auth token, server/channel activity, draft messages',
    },
    'windows_teamviewer': {
        'name': 'TeamViewer',
        'description': 'TeamViewer connection logs and session history',
        'paths': [
            r'%APPDATA%\TeamViewer\Connections_incoming.txt',      # incoming connections
            r'%APPDATA%\TeamViewer\Connections.txt',               # outgoing connections
            r'%APPDATA%\TeamViewer\TeamViewer*_Logfile.log',       # operation logs
            r'%PROGRAMDATA%\TeamViewer\Connections_incoming.txt',
            r'%PROGRAMDATA%\TeamViewer\Connections.txt',
            r'%PROGRAMDATA%\TeamViewer\TeamViewer*_Logfile.log',
        ],
        'mft_config': {
            'user_path': 'AppData/Roaming/TeamViewer',
            'pattern': '*',
            'extensions': ['.txt', '.log'],
            'system_base_paths': ['ProgramData/TeamViewer'],
        },
        'category': 'windows',
        'subcategory': 'pc_apps',
        'requires_admin': False,
        'collector': 'collect_user_glob',
        'artifact_key': 'teamviewer_pc',
        'forensic_value': 'connection timestamps, partner IDs, session duration',
    },
    'windows_anydesk': {
        'name': 'AnyDesk',
        'description': 'AnyDesk connection trace and config files',
        'paths': [
            r'%APPDATA%\AnyDesk\*.trace',                         # ad.trace, ad_svc.trace
            r'%APPDATA%\AnyDesk\*.conf',                          # system.conf, user.conf
            r'%APPDATA%\AnyDesk\connection_trace.txt',             # connection history (UTF-16)
            r'%PROGRAMDATA%\AnyDesk\*.trace',
            r'%PROGRAMDATA%\AnyDesk\*.conf',
            r'%PROGRAMDATA%\AnyDesk\connection_trace.txt',
        ],
        'mft_config': {
            'user_path': 'AppData/Roaming/AnyDesk',
            'pattern': '*',
            'extensions': ['.trace', '.conf', '.txt'],
            'system_base_paths': ['ProgramData/AnyDesk'],
        },
        'category': 'windows',
        'subcategory': 'pc_apps',
        'requires_admin': False,
        'collector': 'collect_user_glob',
        'artifact_key': 'anydesk_pc',
        'forensic_value': 'connection timestamps, remote IDs, session events',
    },
    'windows_google_drive': {
        'name': 'Google Drive Desktop',
        'description': 'Google Drive Desktop sync metadata databases',
        'paths': [
            r'%LOCALAPPDATA%\Google\DriveFS\**\*.db',              # snapshot.db, cloud_graph.db, etc.
            r'%LOCALAPPDATA%\Google\DriveFS\**\*.db-wal',
            r'%LOCALAPPDATA%\Google\DriveFS\**\*.db-shm',
        ],
        'mft_config': {
            'user_path': 'AppData/Local/Google/DriveFS',
            'pattern': '*',
            'extensions': ['.db', '.db-wal', '.db-shm'],
        },
        'category': 'windows',
        'subcategory': 'pc_apps',
        'requires_admin': False,
        'collector': 'collect_user_glob',
        'artifact_key': 'google_drive_pc',
        'forensic_value': 'synced files, cloud storage activity, account info',
    },
    'windows_thunderbird': {
        'name': 'Mozilla Thunderbird',
        'description': 'Thunderbird email databases, contacts, and calendar',
        'paths': [
            r'%APPDATA%\Thunderbird\Profiles\**\global-messages-db.sqlite',  # indexed emails
            r'%APPDATA%\Thunderbird\Profiles\**\abook.sqlite',              # address book
            r'%APPDATA%\Thunderbird\Profiles\**\prefs.js',                  # account config
            r'%APPDATA%\Thunderbird\Profiles\**\calendar-data\local.sqlite', # calendar events
        ],
        'mft_config': {
            'user_path': 'AppData/Roaming/Thunderbird/Profiles',
            'pattern': '*',
            'extensions': ['.sqlite', '.js'],
        },
        'category': 'windows',
        'subcategory': 'pc_apps',
        'requires_admin': False,
        'collector': 'collect_user_glob',
        'artifact_key': 'thunderbird_pc',
        'forensic_value': 'emails, contacts, calendar, account settings',
    },

    # =========================================================================
    # [2026-02-03] Android Messenger Apps (Global)
    # =========================================================================
    'mobile_android_kakaotalk': {
        'name': 'KakaoTalk',
        'description': 'KakaoTalk messages (encrypted)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_messenger',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'kakaotalk',
    },
    'mobile_android_whatsapp': {
        'name': 'WhatsApp',
        'description': 'WhatsApp messages (3B MAU)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_messenger',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'whatsapp',
    },
    'mobile_android_wechat': {
        'name': 'WeChat',
        'description': 'WeChat messages (1.41B MAU, SQLCipher encrypted)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_messenger',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'wechat',
    },
    'mobile_android_telegram': {
        'name': 'Telegram',
        'description': 'Telegram messages (950M MAU)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_messenger',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'telegram',
    },
    'mobile_android_facebook_messenger': {
        'name': 'Facebook Messenger',
        'description': 'Messenger messages (1B+ MAU)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_messenger',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'facebook_messenger',
    },
    'mobile_android_line': {
        'name': 'LINE',
        'description': 'LINE messages (196M MAU)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_messenger',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'line',
    },
    'mobile_android_discord': {
        'name': 'Discord',
        'description': 'Discord cache (200M+ MAU, cloud-based)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_messenger',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'discord',
    },
    'mobile_android_viber': {
        'name': 'Viber',
        'description': 'Viber messages (230M MAU)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_messenger',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'viber',
    },
    'mobile_android_signal': {
        'name': 'Signal',
        'description': 'Signal messages (100M MAU, encrypted)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_messenger',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'signal',
    },
    'mobile_android_band': {
        'name': 'BAND',
        'description': 'BAND group media and posts',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_messenger',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'band',
    },

    # =========================================================================
    # [2026-02-03] Android SNS Apps (Global)
    # =========================================================================
    'mobile_android_instagram': {
        'name': 'Instagram',
        'description': 'Instagram DMs and posts (2B MAU)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_sns',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'instagram',
    },
    'mobile_android_facebook': {
        'name': 'Facebook',
        'description': 'Facebook posts and timeline (3.05B MAU)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_sns',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'facebook',
    },
    'mobile_android_tiktok': {
        'name': 'TikTok',
        'description': 'TikTok videos and DMs (1.5B MAU)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_sns',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'tiktok',
    },
    'mobile_android_twitter': {
        'name': 'Twitter/X',
        'description': 'Twitter tweets and DMs (586M MAU)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_sns',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'twitter',
    },
    'mobile_android_reddit': {
        'name': 'Reddit',
        'description': 'Reddit posts and messages (1.1B MAU)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_sns',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'reddit',
    },
    'mobile_android_snapchat': {
        'name': 'Snapchat',
        'description': 'Snapchat messages (800M MAU)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_sns',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'snapchat',
    },
    'mobile_android_pinterest': {
        'name': 'Pinterest',
        'description': 'Pinterest pins and boards (553M MAU)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_sns',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'pinterest',
    },
    'mobile_android_linkedin': {
        'name': 'LinkedIn',
        'description': 'LinkedIn connections and messages (386M MAU)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_sns',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'linkedin',
    },
    'mobile_android_threads': {
        'name': 'Threads',
        'description': 'Threads posts (320M MAU, Meta)',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_sns',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'threads',
    },
    'mobile_android_baemin': {
        'name': 'Baemin',
        'description': 'Baemin order history, payment info, delivery addresses',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_korean',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'baemin',
    },
    'mobile_android_coupang': {
        'name': 'Coupang',
        'description': 'Coupang purchase history, payment info, delivery addresses',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_korean',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'coupang',
    },
    'mobile_android_karrot': {
        'name': 'Karrot',
        'description': 'Karrot chat history, transaction records, location data',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_korean',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'karrot',
    },
    'mobile_android_coupangeats': {
        'name': 'Coupang Eats',
        'description': 'Coupang Eats order history, payment info, delivery addresses',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_korean',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'coupangeats',
    },
    'mobile_android_yanolja': {
        'name': 'Yanolja',
        'description': 'Yanolja booking history, payment info, location data',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_korean',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'yanolja',
    },
    'mobile_android_kakaobank': {
        'name': 'KakaoBank',
        'description': 'KakaoBank transaction history, account info, transfer records',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_korean',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'kakaobank',
    },
    'mobile_android_toss': {
        'name': 'Toss',
        'description': 'Toss transfer history, payment records, account info',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_korean',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'toss',
    },
    'mobile_android_upbit': {
        'name': 'Upbit',
        'description': 'Upbit cryptocurrency trading history, wallet info',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_korean',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'upbit',
    },
    'mobile_android_banksalad': {
        'name': 'BankSalad',
        'description': 'BankSalad aggregated financial data, asset summary',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_korean',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'banksalad',
    },
    'mobile_android_kakaopay': {
        'name': 'KakaoPay',
        'description': 'KakaoPay payment history, transfer records',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_korean',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'kakaopay',
    },
    'mobile_android_tmap': {
        'name': 'TMAP',
        'description': 'TMAP navigation history, route records, location data',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_korean',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'tmap',
    },
    'mobile_android_kakaomap': {
        'name': 'KakaoMap',
        'description': 'KakaoMap search history, bookmarks, route records',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_korean',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'kakaomap',
    },
    'mobile_android_navermap': {
        'name': 'Naver Map',
        'description': 'Naver Map search history, bookmarks, route records',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_korean',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'navermap',
    },
    'mobile_android_kakaotaxi': {
        'name': 'Kakao T',
        'description': 'Kakao T ride history, pickup/dropoff locations, payment records',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_korean',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'kakaotaxi',
    },
    'mobile_android_hiworks': {
        'name': 'Hiworks',
        'description': 'Hiworks email, calendar, attendance records',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_korean',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'hiworks',
    },
    'mobile_android_gmail': {
        'name': 'Gmail',
        'description': 'Gmail email databases, contacts, attachments',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_email_browser',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'gmail',
    },
    'mobile_android_samsung_email': {
        'name': 'Samsung Email',
        'description': 'Samsung Email databases, contacts, attachments',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_email_browser',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'samsung_email',
    },
    'mobile_android_chrome': {
        'name': 'Chrome',
        'description': 'Chrome browsing history, cookies, saved passwords, downloads',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_email_browser',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'chrome',
    },
    'mobile_android_samsung_browser': {
        'name': 'Samsung Browser',
        'description': 'Samsung Browser history, bookmarks, saved passwords',
        'paths': [],
        'category': 'android',
        'subcategory': 'app_email_browser',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'samsung_browser',
    },

    # =========================================================================
    # [2026-02-24] Screen Scraping (Non-Root Accessibility Service)
    # Agent APK가 Accessibility Service로 앱 화면을 자동 스크래핑
    # =========================================================================
    'mobile_android_screen_scrape': {
        'name': 'Screen Scraping',
        'description': 'App screen data via Accessibility Service - KakaoTalk, WhatsApp, Telegram, etc.',
        'paths': [],
        'category': 'android',
        'subcategory': 'screen_scrape',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'screen_scrape',
    },

    # =========================================================================
    # [2026-02-03] iOS Messenger Apps (Global)
    # =========================================================================
    'mobile_ios_kakaotalk': {
        'name': 'KakaoTalk',
        'description': 'KakaoTalk messages (encrypted)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'kakaotalk',
    },
    'mobile_ios_whatsapp': {
        'name': 'WhatsApp',
        'description': 'WhatsApp messages (3B MAU)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'whatsapp',
    },
    'mobile_ios_wechat': {
        'name': 'WeChat',
        'description': 'WeChat messages (1.41B MAU, encrypted)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'wechat',
    },
    'mobile_ios_telegram': {
        'name': 'Telegram',
        'description': 'Telegram messages (950M MAU)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'telegram',
    },
    'mobile_ios_fb_messenger': {
        'name': 'Facebook Messenger',
        'description': 'Messenger messages (1B+ MAU)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'fb_messenger',
    },
    'mobile_ios_line': {
        'name': 'LINE',
        'description': 'LINE messages (196M MAU)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'line',
    },
    'mobile_ios_discord': {
        'name': 'Discord',
        'description': 'Discord cache (200M+ MAU, cloud-based)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'discord',
    },
    'mobile_ios_viber': {
        'name': 'Viber',
        'description': 'Viber messages (230M MAU)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'viber',
    },
    'mobile_ios_signal': {
        'name': 'Signal',
        'description': 'Signal messages (100M MAU, encrypted)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'signal',
    },
    'mobile_ios_skype': {
        'name': 'Skype',
        'description': 'Skype messages (300M MAU)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'skype',
    },

    # =========================================================================
    # [2026-02-03] iOS SNS Apps (Global)
    # =========================================================================
    'mobile_ios_instagram': {
        'name': 'Instagram',
        'description': 'Instagram DMs and posts (2B MAU)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'sns',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'instagram',
    },
    'mobile_ios_facebook': {
        'name': 'Facebook',
        'description': 'Facebook posts and timeline (3.05B MAU)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'sns',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'facebook',
    },
    'mobile_ios_tiktok': {
        'name': 'TikTok',
        'description': 'TikTok videos and DMs (1.5B MAU)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'sns',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'tiktok',
    },
    'mobile_ios_twitter': {
        'name': 'Twitter/X',
        'description': 'Twitter tweets and DMs (586M MAU)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'sns',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'twitter',
    },
    'mobile_ios_reddit': {
        'name': 'Reddit',
        'description': 'Reddit posts and messages (1.1B MAU)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'sns',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'reddit',
    },
    'mobile_ios_snapchat': {
        'name': 'Snapchat',
        'description': 'Snapchat messages (800M MAU)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'sns',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'snapchat',
    },
    'mobile_ios_pinterest': {
        'name': 'Pinterest',
        'description': 'Pinterest pins and boards (553M MAU)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'sns',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'pinterest',
    },
    'mobile_ios_linkedin': {
        'name': 'LinkedIn',
        'description': 'LinkedIn connections and messages (386M MAU)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'sns',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'linkedin',
    },
    'mobile_ios_threads': {
        'name': 'Threads',
        'description': 'Threads posts (320M MAU, Meta)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'sns',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'threads',
    },

    # =========================================================================
    # [2026-02-14] iOS Browser Tracking
    # =========================================================================
    'mobile_ios_safari_tracking': {
        'name': 'Safari Tracking Data',
        'description': 'Safari browsing tracking (cookies, local storage, sessions)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'email_browser',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'safari_tracking',
    },
    'mobile_ios_chrome_tracking': {
        'name': 'Chrome Tracking Data',
        'description': 'Chrome browsing tracking (cookies, local storage)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'email_browser',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'chrome_tracking',
    },
    'mobile_ios_naver_search': {
        'name': 'Naver Search History',
        'description': 'Naver app search history',
        'paths': [],
        'category': 'ios',
        'subcategory': 'email_browser',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'naver_search',
    },
    'mobile_ios_navermap_history': {
        'name': 'NaverMap History',
        'description': 'NaverMap search and navigation history',
        'paths': [],
        'category': 'ios',
        'subcategory': 'email_browser',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'navermap_history',
    },

    # =========================================================================
    # [2026-02-14] iOS System Artifacts - P0 (High Forensic Value)
    # =========================================================================
    'mobile_ios_notes': {
        'name': 'Notes',
        'description': 'Apple Notes (text, attachments, shared notes)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'notes',
    },
    'mobile_ios_photos': {
        'name': 'Photos Metadata',
        'description': 'Photos library metadata (GPS, timestamps, albums)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'photos',
    },
    'mobile_ios_calendar': {
        'name': 'Calendar',
        'description': 'Calendar events and reminders',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'calendar',
    },
    'mobile_ios_reminders': {
        'name': 'Reminders',
        'description': 'Apple Reminders lists and items',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'reminders',
    },
    'mobile_ios_knowledgec': {
        'name': 'KnowledgeC Activity',
        'description': 'App usage, device activity, and interaction history',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'knowledgec',
    },

    # =========================================================================
    # [2026-02-14] iOS System Artifacts - P1 (Medium Forensic Value)
    # =========================================================================
    'mobile_ios_health': {
        'name': 'Health Data',
        'description': 'Health app data (steps, heart rate, sleep)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'health',
    },
    'mobile_ios_screentime': {
        'name': 'Screen Time',
        'description': 'Screen time usage and app limits',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'screentime',
    },
    'mobile_ios_voicememos': {
        'name': 'Voice Memos',
        'description': 'Voice memo recordings metadata',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'voicememos',
    },
    'mobile_ios_maps': {
        'name': 'Apple Maps History',
        'description': 'Apple Maps search and navigation history',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'maps',
    },
    'mobile_ios_safari_bookmarks': {
        'name': 'Safari Bookmarks',
        'description': 'Safari bookmarks and reading list',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'safari_bookmarks',
    },

    # =========================================================================
    # [2026-02-14] iOS System Artifacts - P2 (Supplementary)
    # =========================================================================
    'mobile_ios_wifi': {
        'name': 'WiFi Networks',
        'description': 'Known WiFi networks and connection history',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'wifi',
    },
    'mobile_ios_bluetooth': {
        'name': 'Bluetooth Devices',
        'description': 'Paired Bluetooth devices history',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'bluetooth',
    },
    'mobile_ios_findmy': {
        'name': 'Find My',
        'description': 'Find My device/people location data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'findmy',
    },
    'mobile_ios_wallet': {
        'name': 'Wallet / Apple Pay',
        'description': 'Wallet passes and Apple Pay transaction metadata',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'wallet',
    },
    'mobile_ios_spotlight': {
        'name': 'Spotlight Index',
        'description': 'Spotlight search index and recent queries',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'spotlight',
    },
    'mobile_ios_siri': {
        'name': 'Siri Activity',
        'description': 'Siri queries and suggestions',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'siri',
    },

    # =========================================================================
    # [2026-02-14] iOS Messenger Auxiliary (Attachments / Profiles)
    # =========================================================================
    'mobile_ios_kakaotalk_profile': {
        'name': 'KakaoTalk Profile',
        'description': 'KakaoTalk user profile and contact data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'kakaotalk_profile',
    },
    'mobile_ios_kakaotalk_links': {
        'name': 'KakaoTalk Shared Links',
        'description': 'URLs shared in KakaoTalk chats',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'kakaotalk_links',
    },
    'mobile_ios_kakaotalk_search': {
        'name': 'KakaoTalk Search History',
        'description': 'In-chat search keyword history',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'kakaotalk_search',
    },
    'mobile_ios_whatsapp_attachments': {
        'name': 'WhatsApp Attachments',
        'description': 'WhatsApp media files (images, videos, voice)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'whatsapp_attachments',
    },
    'mobile_ios_whatsapp_calls': {
        'name': 'WhatsApp Call History',
        'description': 'WhatsApp voice/video call records',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'whatsapp_calls',
    },
    'mobile_ios_whatsapp_contacts': {
        'name': 'WhatsApp Contacts',
        'description': 'WhatsApp contact list',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'whatsapp_contacts',
    },
    'mobile_ios_whatsapp_media': {
        'name': 'WhatsApp Media',
        'description': 'WhatsApp shared media metadata',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'whatsapp_media',
    },
    'mobile_ios_fb_messenger_attachments': {
        'name': 'FB Messenger Attachments',
        'description': 'Facebook Messenger media and file attachments',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'fb_messenger_attachments',
    },
    'mobile_ios_telegram_attachments': {
        'name': 'Telegram Attachments',
        'description': 'Telegram media and file attachments',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'telegram_attachments',
    },
    'mobile_ios_line_attachments': {
        'name': 'LINE Attachments',
        'description': 'LINE media files and attachments',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'line_attachments',
    },
    'mobile_ios_line_events': {
        'name': 'LINE Events',
        'description': 'LINE calendar events and reminders',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'line_events',
    },
    'mobile_ios_line_openchat': {
        'name': 'LINE OpenChat',
        'description': 'LINE OpenChat group participation data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'line_openchat',
    },
    'mobile_ios_wechat_channels': {
        'name': 'WeChat Channels',
        'description': 'WeChat Channels (video feed) activity',
        'paths': [],
        'category': 'ios',
        'subcategory': 'messenger',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'wechat_channels',
    },
    'mobile_ios_snapchat_memories': {
        'name': 'Snapchat Memories',
        'description': 'Snapchat saved snaps and memories',
        'paths': [],
        'category': 'ios',
        'subcategory': 'sns',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'snapchat_memories',
    },

    # =========================================================================
    # [2026-02-23] iOS Korean Apps - Financial
    # =========================================================================
    'mobile_ios_kakaobank': {
        'name': 'KakaoBank',
        'description': 'KakaoBank mobile banking app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'kakaobank',
    },
    'mobile_ios_upbit': {
        'name': 'Upbit',
        'description': 'Upbit cryptocurrency exchange app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'upbit',
    },
    'mobile_ios_banksalad': {
        'name': 'BankSalad',
        'description': 'BankSalad financial management app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'banksalad',
    },
    'mobile_ios_shinhan': {
        'name': 'ShinhanBank',
        'description': 'Shinhan Bank mobile banking app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'shinhan',
    },
    'mobile_ios_wooribank': {
        'name': 'WooriBank',
        'description': 'Woori Bank mobile banking app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'wooribank',
    },
    'mobile_ios_kbstar': {
        'name': 'KB Star',
        'description': 'KB Kookmin Bank mobile banking app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'kbstar',
    },
    'mobile_ios_hanabank': {
        'name': 'HanaBank',
        'description': 'Hana Bank mobile banking app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'hanabank',
    },
    'mobile_ios_ibk': {
        'name': 'IBK',
        'description': 'IBK Industrial Bank app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'ibk',
    },
    'mobile_ios_nhbank': {
        'name': 'NH Bank',
        'description': 'NH Nonghyup Bank app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'nhbank',
    },
    'mobile_ios_kbank': {
        'name': 'K bank',
        'description': 'K bank digital bank app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'kbank',
    },
    'mobile_ios_kakaopay': {
        'name': 'KakaoPay',
        'description': 'KakaoPay mobile payment app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'kakaopay',
    },
    'mobile_ios_monimo': {
        'name': 'monimo',
        'description': 'Samsung Card monimo app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'monimo',
    },
    'mobile_ios_hyundaicard': {
        'name': 'Hyundai Card',
        'description': 'Hyundai Card app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'hyundaicard',
    },
    'mobile_ios_kbpay': {
        'name': 'KB Pay',
        'description': 'KB Pay card app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'kbpay',
    },
    'mobile_ios_oksavings': {
        'name': 'OK Savings',
        'description': 'OK Savings Bank app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'oksavings',
    },
    'mobile_ios_dbsavings': {
        'name': 'DB Savings',
        'description': 'DB Savings Bank app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'dbsavings',
    },
    'mobile_ios_fint': {
        'name': 'Fint',
        'description': 'Fint investment app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'fint',
    },
    'mobile_ios_hantu': {
        'name': 'Korea Investment',
        'description': 'Korea Investment & Securities app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'hantu',
    },

    # =========================================================================
    # [2026-02-23] iOS Korean Apps - Navigation/Transportation
    # =========================================================================
    'mobile_ios_tmap': {
        'name': 'TMAP',
        'description': 'TMAP navigation history and GPS data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'tmap',
    },
    'mobile_ios_kakaomap': {
        'name': 'KakaoMap',
        'description': 'KakaoMap navigation and location data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'kakaomap',
    },
    'mobile_ios_navermap': {
        'name': 'NaverMap',
        'description': 'NaverMap navigation history and GPS coordinates',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'navermap',
    },
    'mobile_ios_kakaobus': {
        'name': 'KakaoBus',
        'description': 'KakaoBus transit favorites and stops',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'kakaobus',
    },
    'mobile_ios_kakaotaxi': {
        'name': 'Kakao T',
        'description': 'Kakao T ride history with GPS coordinates',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'kakaotaxi',
    },
    'mobile_ios_kakaometro': {
        'name': 'KakaoMetro',
        'description': 'KakaoMetro subway station usage and favorites',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'kakaometro',
    },
    'mobile_ios_kpass': {
        'name': 'K-Pass',
        'description': 'K-Pass transit card data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'kpass',
    },
    'mobile_ios_asiana': {
        'name': 'Asiana Airlines',
        'description': 'Asiana Airlines app flight data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'asiana',
    },

    # =========================================================================
    # [2026-02-23] iOS Korean Apps - Shopping/Delivery
    # =========================================================================
    'mobile_ios_coupang': {
        'name': 'Coupang',
        'description': 'Coupang shopping app user and group data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'coupang',
    },
    'mobile_ios_baemin': {
        'name': 'Baemin',
        'description': 'Baemin delivery order history',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'baemin',
    },
    'mobile_ios_karrot': {
        'name': 'Karrot',
        'description': 'Karrot (Danggeun Market) trading data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'karrot',
    },
    'mobile_ios_coupangeats': {
        'name': 'Coupang Eats',
        'description': 'Coupang Eats food delivery data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'coupangeats',
    },
    'mobile_ios_yanolja': {
        'name': 'Yanolja',
        'description': 'Yanolja accommodation booking data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'korean',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'yanolja',
    },

    # =========================================================================
    # [2026-02-23] iOS Apps - Browser/Email/Office
    # =========================================================================
    'mobile_ios_chrome': {
        'name': 'Chrome',
        'description': 'Chrome iOS browsing history, searches, downloads',
        'paths': [],
        'category': 'ios',
        'subcategory': 'email_browser',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'chrome',
    },
    'mobile_ios_gmail': {
        'name': 'Gmail',
        'description': 'Gmail iOS email metadata',
        'paths': [],
        'category': 'ios',
        'subcategory': 'email_browser',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'gmail',
    },
    'mobile_ios_excel': {
        'name': 'Excel',
        'description': 'Microsoft Excel iOS data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'excel',
    },
    'mobile_ios_pages': {
        'name': 'Pages',
        'description': 'Apple Pages document data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'pages',
    },
    'mobile_ios_numbers': {
        'name': 'Numbers',
        'description': 'Apple Numbers spreadsheet data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'numbers',
    },
    'mobile_ios_keynote': {
        'name': 'Keynote',
        'description': 'Apple Keynote presentation data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'keynote',
    },
    'mobile_ios_m365': {
        'name': 'Microsoft 365',
        'description': 'Microsoft 365 mobile app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'email_browser',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'm365',
    },
    'mobile_ios_gdrive': {
        'name': 'Google Drive',
        'description': 'Google Drive cloud storage data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'gdrive',
    },
    'mobile_ios_polaris': {
        'name': 'Polaris Office',
        'description': 'Polaris Office document data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'polaris',
    },

    # =========================================================================
    # [2026-02-23] iOS Apps - Streaming
    # =========================================================================
    'mobile_ios_youtube': {
        'name': 'YouTube',
        'description': 'YouTube watch and upload history',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'youtube',
    },
    'mobile_ios_netflix': {
        'name': 'Netflix',
        'description': 'Netflix viewing history',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'netflix',
    },
    'mobile_ios_coupangplay': {
        'name': 'Coupang Play',
        'description': 'Coupang Play streaming history',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'coupangplay',
    },

    # =========================================================================
    # [2026-02-23] iOS Korean Apps - Utility
    # =========================================================================
    'mobile_ios_jikbang': {
        'name': 'Jikbang',
        'description': 'Jikbang real estate search data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'jikbang',
    },
    'mobile_ios_dabang': {
        'name': 'Dabang',
        'description': 'Dabang real estate search data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'dabang',
    },
    'mobile_ios_govt24': {
        'name': 'Government 24',
        'description': 'Government 24 service data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'govt24',
    },
    'mobile_ios_wetax': {
        'name': 'Wetax',
        'description': 'Smart Wetax tax service data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'wetax',
    },
    'mobile_ios_nhis': {
        'name': 'NHIS',
        'description': 'National Health Insurance Service data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'nhis',
    },
    'mobile_ios_whowho': {
        'name': 'WhoWho',
        'description': 'WhoWho caller ID data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'whowho',
    },
    'mobile_ios_aparteye': {
        'name': 'ApartEye',
        'description': 'ApartEye apartment management data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'aparteye',
    },
    'mobile_ios_millie': {
        'name': 'Millie',
        'description': 'Millie e-book reading data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'millie',
    },
    'mobile_ios_metlife': {
        'name': 'MetLife',
        'description': 'MetLife insurance app data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'metlife',
    },
    'mobile_ios_papago': {
        'name': 'Papago',
        'description': 'Naver Papago translation history',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'papago',
    },
    'mobile_ios_strava': {
        'name': 'Strava',
        'description': 'Strava fitness activity and GPS data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'productivity',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'strava',
    },

    # =========================================================================
    # [2026-02-23] iOS Apps - Email/Office (Additional)
    # =========================================================================
    'mobile_ios_outlook': {
        'name': 'Outlook',
        'description': 'Microsoft Outlook iOS email and calendar data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'email_browser',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'outlook',
    },
    'mobile_ios_ms_teams': {
        'name': 'Microsoft Teams',
        'description': 'Microsoft Teams chat and meeting data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'email_browser',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'ms_teams',
    },
    'mobile_ios_ms_authenticator': {
        'name': 'MS Authenticator',
        'description': 'Microsoft Authenticator account data',
        'paths': [],
        'category': 'ios',
        'subcategory': 'email_browser',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'ms_authenticator',
    },
    'mobile_ios_google_search': {
        'name': 'Google Search',
        'description': 'Google app search history',
        'paths': [],
        'category': 'ios',
        'subcategory': 'email_browser',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'google_search',
    },

    # =========================================================================
    # [2026-02-23] iOS System Artifacts (Additional)
    # =========================================================================
    'mobile_ios_installed_apps': {
        'name': 'Installed Apps',
        'description': 'List of all installed applications',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'installed_apps',
    },
    'mobile_ios_accounts': {
        'name': 'User Accounts',
        'description': 'Configured email/social accounts on device',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'accounts',
    },
    'mobile_ios_voicemail': {
        'name': 'Voicemail',
        'description': 'Visual voicemail recordings metadata',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'voicemail',
    },
    'mobile_ios_vpn': {
        'name': 'VPN Configurations',
        'description': 'VPN connection profiles and history',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'vpn',
    },
    'mobile_ios_tcc': {
        'name': 'TCC Privacy Database',
        'description': 'App permission grants (camera, microphone, location)',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'tcc',
    },
    'mobile_ios_location_services': {
        'name': 'Location Services',
        'description': 'Per-app location access history',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'location_services',
    },
    'mobile_ios_device_info': {
        'name': 'Device Info',
        'description': 'Device hardware and software information',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'device_info',
    },
    'mobile_ios_device_backup': {
        'name': 'Device Backup Info',
        'description': 'Backup configuration and timestamps',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'device_backup',
    },
    'mobile_ios_data_usage': {
        'name': 'Data Usage',
        'description': 'Per-app cellular and WiFi data consumption',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'data_usage',
    },
    'mobile_ios_app_state': {
        'name': 'App State',
        'description': 'App state snapshots and saved sessions',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'app_state',
    },
    'mobile_ios_crash_logs': {
        'name': 'Crash Logs',
        'description': 'App crash reports with timestamps',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'crash_logs',
    },
    'mobile_ios_syslog': {
        'name': 'System Log',
        'description': 'iOS system diagnostic logs',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'syslog',
    },
    'mobile_ios_unified_logs': {
        'name': 'Unified Logs',
        'description': 'iOS unified logging system entries',
        'paths': [],
        'category': 'ios',
        'subcategory': 'system',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'unified_logs',
    },

    # =========================================================================
    # Additional Windows Artifacts (Phase 6)
    # =========================================================================
    'jumplist': {
        'name': 'Jump Lists',
        'description': 'Recent/pinned items in taskbar (AutomaticDestinations, CustomDestinations)',
        'paths': [
            r'%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms',
            r'%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms',
        ],
        'mft_config': {
            'user_path': 'AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations',
            'pattern': '*.automaticDestinations-ms',
        },
        'requires_admin': False,
        'collector': 'collect_user_glob',
    },
    'shortcut': {
        'name': 'Shortcut Files (LNK)',
        'description': 'Desktop, Start Menu, Startup shortcuts',
        'paths': [
            r'%USERPROFILE%\Desktop\*.lnk',
            r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\*.lnk',
            r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\**\*.lnk',
            r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk',
            r'%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\*.lnk',
            r'%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\**\*.lnk',
        ],
        'mft_config': {
            'user_path': 'Desktop',
            'pattern': '*.lnk',
        },
        'requires_admin': False,
        'collector': 'collect_user_glob',
    },
    'scheduled_task': {
        'name': 'Scheduled Tasks',
        'description': 'Windows Task Scheduler XML definitions',
        'paths': [
            r'C:\Windows\System32\Tasks\*',
            r'C:\Windows\System32\Tasks\**\*',
        ],
        'mft_config': {
            'base_path': 'Windows/System32/Tasks',
            'pattern': '*',
            'recursive': True,
        },
        'requires_admin': True,
        'collector': 'collect_glob',
    },
    'shellbags': {
        'name': 'ShellBags (USRCLASS.DAT)',
        'description': 'Explorer folder browsing history from UsrClass.dat',
        'paths': [],  # Dynamic per user
        'mft_config': {
            'user_path': 'AppData/Local/Microsoft/Windows/UsrClass.dat',
        },
        'requires_admin': False,
        'collector': 'collect_usrclass',
    },
    'thumbcache': {
        'name': 'Thumbnail Cache',
        'description': 'Windows thumbnail cache (thumbcache_*.db)',
        'paths': [
            r'%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db',
        ],
        'mft_config': {
            'user_path': 'AppData/Local/Microsoft/Windows/Explorer',
            'pattern': 'thumbcache_*.db',
        },
        'requires_admin': False,
        'collector': 'collect_user_glob',
    },
    # =========================================================================
    # User Files - Server-parseable extensions only (per server parser config)
    # =========================================================================
    'document': {
        'name': 'Documents',
        'description': 'Office documents, PDFs, HWP files (server-parseable only)',
        'paths': [
            r'%USERPROFILE%\Documents\**\*.doc',
            r'%USERPROFILE%\Documents\**\*.docx',
            r'%USERPROFILE%\Documents\**\*.pdf',
            r'%USERPROFILE%\Documents\**\*.hwp',
            r'%USERPROFILE%\Documents\**\*.xls',
            r'%USERPROFILE%\Documents\**\*.xlsx',
            r'%USERPROFILE%\Documents\**\*.ppt',
            r'%USERPROFILE%\Documents\**\*.pptx',
        ],
        'mft_config': {
            # Server-parseable: python-docx, openpyxl, pypdf, olefile
            'extensions': ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                          '.pdf', '.hwp', '.hwpx'],
        },
        'requires_admin': True,  # MFT access required
        'collector': 'collect_user_glob',
    },
    'email': {
        'name': 'Email Files',
        'description': 'Outlook PST/OST, EML, MSG files',
        'paths': [
            r'%USERPROFILE%\Documents\Outlook Files\*.pst',
            r'%USERPROFILE%\AppData\Local\Microsoft\Outlook\*.ost',
            r'%USERPROFILE%\**\*.eml',
            r'%USERPROFILE%\**\*.msg',
        ],
        'mft_config': {
            # Server-parseable: email, extract_msg, pypff
            'extensions': ['.pst', '.ost', '.eml', '.msg'],
        },
        'requires_admin': True,  # MFT access required
        'collector': 'collect_user_glob',
    },

    # =========================================================================
    # Phase 2: Command execution and crash artifacts
    # =========================================================================
    'powershell_history': {
        'name': 'PowerShell History',
        'description': 'PowerShell command history (PSReadLine ConsoleHost_history.txt)',
        'paths': [
            r'%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt',
        ],
        'mft_config': {
            'user_path': 'AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine',
            'files': ['ConsoleHost_history.txt'],
        },
        'requires_admin': False,
        'collector': 'collect_user_files',
    },
    'wer': {
        'name': 'Windows Error Reports',
        'description': 'Windows Error Reporting (crash dumps, app crash reports)',
        'paths': [
            r'C:\ProgramData\Microsoft\Windows\WER\**\*.wer',
            r'%LOCALAPPDATA%\Microsoft\Windows\WER\**\*.wer',
        ],
        'mft_config': {
            'path_patterns': [
                'ProgramData/Microsoft/Windows/WER',
                'AppData/Local/Microsoft/Windows/WER',
            ],
            'extensions': ['.wer', '.txt', '.hdmp', '.mdmp'],
        },
        'requires_admin': True,
        'collector': 'collect_glob',
    },
    'rdp_cache': {
        'name': 'RDP Bitmap Cache',
        'description': 'Remote Desktop bitmap cache (bcache*.bmc)',
        'paths': [
            r'%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\bcache*.bmc',
        ],
        'mft_config': {
            'user_path': 'AppData/Local/Microsoft/Terminal Server Client/Cache',
            'pattern': 'bcache*.bmc',
        },
        'requires_admin': False,
        'collector': 'collect_user_glob',
    },

    # =========================================================================
    # Phase 3: Supplementary artifacts (network, profiles)
    # =========================================================================
    'wlan_event': {
        'name': 'WLAN Event Log',
        'description': 'WiFi connection history (WLAN-AutoConfig event log)',
        'paths': [
            r'C:\Windows\System32\winevt\Logs\Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx',
        ],
        'mft_config': {
            'base_path': 'Windows/System32/winevt/Logs',
            'files': ['Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx'],
        },
        'requires_admin': True,
        'collector': 'collect_files',
    },
    'profile_list': {
        'name': 'User Profile List',
        'description': 'User profile enumeration (ProfileList in SOFTWARE registry)',
        'paths': [
            r'C:\Windows\System32\config\SOFTWARE',
        ],
        'mft_config': {
            'base_path': 'Windows/System32/config',
            'files': ['SOFTWARE'],
        },
        'requires_admin': True,
        'collector': 'collect_locked_files',
    },

    # =========================================================================
    # [2026-01] Media Artifacts - Server parsing support
    # =========================================================================
    'image': {
        'name': 'Image Files',
        'description': 'JPEG, PNG, GIF images with EXIF/GPS metadata (server-parseable)',
        'paths': [
            r'%USERPROFILE%\Pictures\**\*.jpg',
            r'%USERPROFILE%\Pictures\**\*.jpeg',
            r'%USERPROFILE%\Pictures\**\*.png',
            r'%USERPROFILE%\Pictures\**\*.gif',
            r'%USERPROFILE%\Pictures\**\*.bmp',
            r'%USERPROFILE%\Pictures\**\*.heic',
            r'%USERPROFILE%\Downloads\**\*.jpg',
            r'%USERPROFILE%\Downloads\**\*.jpeg',
            r'%USERPROFILE%\Downloads\**\*.png',
        ],
        'mft_config': {
            # Server-parseable: PIL (EXIF, GPS)
            'extensions': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.heic', '.heif', '.webp'],
            'user_paths': ['Pictures', 'Downloads', 'Desktop'],
        },
        'requires_admin': True,  # MFT access required
        'collector': 'collect_user_glob',
        'forensic_value': 'EXIF metadata, GPS location, capture time, camera info',
    },
    'video': {
        'name': 'Video Files',
        'description': 'MP4, AVI, MOV videos with metadata (server-parseable, requires ffprobe)',
        'paths': [
            r'%USERPROFILE%\Videos\**\*.mp4',
            r'%USERPROFILE%\Videos\**\*.avi',
            r'%USERPROFILE%\Videos\**\*.mov',
            r'%USERPROFILE%\Videos\**\*.mkv',
            r'%USERPROFILE%\Downloads\**\*.mp4',
            r'%USERPROFILE%\Downloads\**\*.avi',
        ],
        'mft_config': {
            # Server-parseable: ffprobe
            'extensions': ['.mp4', '.avi', '.mov', '.mkv', '.wmv', '.flv', '.webm', '.m4v', '.mpg', '.mpeg', '.3gp'],
            'user_paths': ['Videos', 'Downloads', 'Desktop'],
        },
        'requires_admin': True,  # MFT access required
        'collector': 'collect_user_glob',
        'forensic_value': 'Duration, resolution, codec info, creation time',
    },

    # =========================================================================
    # [2026-01] P0 New Artifacts - High forensic value
    # =========================================================================
    'activities_cache': {
        'name': 'Windows Timeline (ActivitiesCache.db)',
        'description': 'Windows Timeline - includes app execution duration (Win10 1803+)',
        'paths': [
            r'%LOCALAPPDATA%\ConnectedDevicesPlatform\*\ActivitiesCache.db',
            r'%LOCALAPPDATA%\ConnectedDevicesPlatform\*\ActivitiesCache.db-wal',
            r'%LOCALAPPDATA%\ConnectedDevicesPlatform\*\ActivitiesCache.db-shm',
        ],
        'mft_config': {
            'user_path': 'AppData/Local/ConnectedDevicesPlatform',
            'pattern': 'ActivitiesCache.db*',
            'recursive': True,
        },
        'requires_admin': False,
        'collector': 'collect_user_glob',
        'forensic_value': 'App execution time/duration, clipboard history, file access history',
    },
    'pca_launch': {
        'name': 'Program Compatibility Assistant (Win11+)',
        'description': 'Windows 11 22H2+ program execution records (PcaAppLaunchDic.txt)',
        'paths': [
            r'C:\Windows\appcompat\pca\PcaAppLaunchDic.txt',
            r'C:\Windows\appcompat\pca\PcaGeneralDb0.txt',
            r'C:\Windows\appcompat\pca\PcaGeneralDb1.txt',
        ],
        'mft_config': {
            'base_path': 'Windows/appcompat/pca',
            'pattern': 'Pca*.txt',
        },
        'requires_admin': True,
        'collector': 'collect_files',
        'forensic_value': 'Executable path, execution time (supplements AmCache)',
    },
    'etl_log': {
        'name': 'ETW AutoLogger (.etl)',
        'description': 'ETW AutoLogger traces (persists even after event log deletion)',
        'paths': [
            r'C:\Windows\System32\WDI\LogFiles\*.etl',
            r'C:\Windows\System32\LogFiles\WMI\*.etl',
            r'C:\Windows\Panther\*.etl',
        ],
        'mft_config': {
            'path_patterns': [
                'Windows/System32/WDI/LogFiles',
                'Windows/System32/LogFiles/WMI',
                'Windows/Panther',
            ],
            'extensions': ['.etl'],
        },
        'requires_admin': True,
        'collector': 'collect_glob',
        'forensic_value': 'Process tracking, boot records (bypasses log deletion)',
    },
    'wmi_subscription': {
        'name': 'WMI Repository (OBJECTS.DATA)',
        'description': 'WMI event subscriptions - persistence mechanism detection (MITRE T1546.003)',
        'paths': [
            r'C:\Windows\System32\wbem\Repository\OBJECTS.DATA',
            r'C:\Windows\System32\wbem\Repository\INDEX.BTR',
            r'C:\Windows\System32\wbem\Repository\MAPPING*.MAP',
        ],
        'mft_config': {
            'base_path': 'Windows/System32/wbem/Repository',
            'files': ['OBJECTS.DATA', 'INDEX.BTR'],
            'pattern': 'MAPPING*.MAP',
        },
        'requires_admin': True,
        'collector': 'collect_locked_files',
        'forensic_value': 'WMI persistence, malicious event subscription detection',
    },
    'defender_detection': {
        'name': 'Windows Defender Detection History',
        'description': 'Defender detection records (MpDetection-*.bin)',
        'paths': [
            r'C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\*\*.bin',
            r'C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log',
        ],
        'mft_config': {
            'path_patterns': [
                'ProgramData/Microsoft/Windows Defender/Scans/History/Service/DetectionHistory',
                'ProgramData/Microsoft/Windows Defender/Support',
            ],
            'pattern': '*',
            'recursive': True,
        },
        'requires_admin': True,
        'collector': 'collect_glob',
        'forensic_value': 'Malware detection records, quarantined file info',
    },
    'zone_identifier': {
        'name': 'Zone.Identifier (ADS)',
        'description': 'Downloaded file source URL and security zone info (Alternate Data Stream)',
        'paths': [
            r'%USERPROFILE%\Downloads\*:Zone.Identifier',
            r'%USERPROFILE%\Desktop\*:Zone.Identifier',
            r'%USERPROFILE%\Documents\*:Zone.Identifier',
        ],
        'mft_config': {
            'user_paths': ['Downloads', 'Desktop', 'Documents'],
            'ads_stream': 'Zone.Identifier',
            'recursive': False,
        },
        'requires_admin': False,
        'collector': 'collect_zone_identifier',
        'forensic_value': 'Download source URL, security zone (Internet/Intranet), original host',
    },
    'bits_jobs': {
        'name': 'BITS Transfer Jobs',
        'description': 'Background Intelligent Transfer Service job records (malware download detection)',
        'paths': [
            r'C:\ProgramData\Microsoft\Network\Downloader\qmgr0.dat',
            r'C:\ProgramData\Microsoft\Network\Downloader\qmgr1.dat',
        ],
        'mft_config': {
            'base_path': 'ProgramData/Microsoft/Network/Downloader',
            'pattern': 'qmgr*.dat',
        },
        'requires_admin': True,
        'collector': 'collect_locked_files',
        'forensic_value': 'BITS download URL, job creation time (MITRE T1197)',
    },

    # =========================================================================
    # Linux Forensics Artifacts (Phase 3.1)
    # =========================================================================
    'linux_auth_log': {
        'name': 'Linux Authentication Log',
        'description': 'Authentication events (login, sudo, ssh)',
        'category': 'linux',
        'paths': [],
        'forensic_value': 'critical',
        'mitre_attack': 'T1078',
        'kill_chain_phase': 'initial_access',
        'collector': 'collect_linux',
    },
    'linux_bash_history': {
        'name': 'Linux Bash History',
        'description': 'Bash command history per user',
        'category': 'linux',
        'paths': [],
        'forensic_value': 'critical',
        'mitre_attack': 'T1059.004',
        'kill_chain_phase': 'execution',
        'collector': 'collect_linux',
    },
    'linux_crontab': {
        'name': 'Linux Crontab',
        'description': 'Scheduled tasks via cron',
        'category': 'linux',
        'paths': [],
        'forensic_value': 'critical',
        'mitre_attack': 'T1053.003',
        'kill_chain_phase': 'persistence',
        'collector': 'collect_linux',
    },
    'linux_ssh_authorized_keys': {
        'name': 'SSH Authorized Keys',
        'description': 'Authorized public keys for SSH access',
        'category': 'linux',
        'paths': [],
        'forensic_value': 'critical',
        'mitre_attack': 'T1098.004',
        'kill_chain_phase': 'persistence',
        'collector': 'collect_linux',
    },
    'linux_syslog': {
        'name': 'Linux System Log',
        'description': 'General system events and daemon logs',
        'category': 'linux',
        'paths': [],
        'forensic_value': 'high',
        'mitre_attack': 'T1070.002',
        'kill_chain_phase': 'defense_evasion',
        'collector': 'collect_linux',
    },
    'linux_passwd': {
        'name': 'Linux Passwd File',
        'description': 'User account information',
        'category': 'linux',
        'paths': [],
        'forensic_value': 'critical',
        'mitre_attack': 'T1087.001',
        'kill_chain_phase': 'discovery',
        'collector': 'collect_linux',
    },
    'linux_systemd_service': {
        'name': 'Linux Systemd Services',
        'description': 'Systemd service unit files',
        'category': 'linux',
        'paths': [],
        'forensic_value': 'critical',
        'mitre_attack': 'T1543.002',
        'kill_chain_phase': 'persistence',
        'collector': 'collect_linux',
    },
    'linux_wtmp': {
        'name': 'Linux Login Records',
        'description': 'Login/logout history (wtmp)',
        'category': 'linux',
        'paths': [],
        'forensic_value': 'critical',
        'mitre_attack': 'T1078',
        'kill_chain_phase': 'initial_access',
        'collector': 'collect_linux',
    },

    # =========================================================================
    # macOS Forensics Artifacts (Phase 3.1)
    # =========================================================================
    'macos_unified_log': {
        'name': 'macOS Unified Log',
        'description': 'Unified logging system (log show)',
        'category': 'macos',
        'paths': [],
        'forensic_value': 'critical',
        'mitre_attack': 'T1070.002',
        'kill_chain_phase': 'defense_evasion',
        'collector': 'collect_macos',
    },
    'macos_launch_agent': {
        'name': 'macOS Launch Agents',
        'description': 'User-level LaunchAgent plist files',
        'category': 'macos',
        'paths': [],
        'forensic_value': 'critical',
        'mitre_attack': 'T1543.001',
        'kill_chain_phase': 'persistence',
        'collector': 'collect_macos',
    },
    'macos_launch_daemon': {
        'name': 'macOS Launch Daemons',
        'description': 'System-level LaunchDaemon plist files',
        'category': 'macos',
        'paths': [],
        'forensic_value': 'critical',
        'mitre_attack': 'T1543.004',
        'kill_chain_phase': 'persistence',
        'collector': 'collect_macos',
    },
    'macos_zsh_history': {
        'name': 'macOS Zsh History',
        'description': 'Zsh shell command history',
        'category': 'macos',
        'paths': [],
        'forensic_value': 'critical',
        'mitre_attack': 'T1059.004',
        'kill_chain_phase': 'execution',
        'collector': 'collect_macos',
    },
    'macos_tcc_db': {
        'name': 'macOS TCC Database',
        'description': 'Transparency, Consent, and Control permissions',
        'category': 'macos',
        'paths': [],
        'forensic_value': 'critical',
        'mitre_attack': 'T1548.004',
        'kill_chain_phase': 'privilege_escalation',
        'collector': 'collect_macos',
    },
    'macos_knowledgec': {
        'name': 'macOS KnowledgeC Database',
        'description': 'User activity, app usage tracking',
        'category': 'macos',
        'paths': [],
        'forensic_value': 'critical',
        'mitre_attack': 'T1087.001',
        'kill_chain_phase': 'discovery',
        'collector': 'collect_macos',
    },
    'macos_fseventsd': {
        'name': 'macOS FSEvents',
        'description': 'File system events log',
        'category': 'macos',
        'paths': [],
        'forensic_value': 'critical',
        'mitre_attack': 'T1070.004',
        'kill_chain_phase': 'defense_evasion',
        'collector': 'collect_macos',
    },
    'macos_safari_history': {
        'name': 'macOS Safari History',
        'description': 'Safari browser history database',
        'category': 'macos',
        'paths': [],
        'forensic_value': 'high',
        'mitre_attack': 'T1185',
        'kill_chain_phase': 'collection',
        'collector': 'collect_macos',
    },
    'macos_keychain': {
        'name': 'macOS Keychain',
        'description': 'User and system keychain files',
        'category': 'macos',
        'paths': [],
        'forensic_value': 'critical',
        'mitre_attack': 'T1555.001',
        'kill_chain_phase': 'credential_access',
        'collector': 'collect_macos',
    },

    # =========================================================================
    # macOS Extended Artifacts (from MACOS_ARTIFACT_FILTERS — auto-registered)
    # =========================================================================
    **{k: {'name': v.get('description', k), 'description': v.get('description', ''),
           'category': 'macos', 'paths': [], 'forensic_value': v.get('forensic_value', 'medium'),
           'collector': 'collect_macos'}
       for k, v in _MACOS_FILTERS.items()
       if k not in {
           'macos_unified_log', 'macos_launch_agent', 'macos_launch_daemon',
           'macos_zsh_history', 'macos_tcc_db', 'macos_knowledgec',
           'macos_fseventsd', 'macos_safari_history', 'macos_keychain',
       }},
}

# =============================================================================
# Local MFT Collector (inherits from BaseMFTCollector)
# =============================================================================

# BitLocker module import
try:
    from utils.bitlocker import (
        detect_bitlocker_on_system_drive,
        BitLockerDecryptor,
        is_pybde_installed,
        BitLockerVolumeDetectionResult
    )
    BITLOCKER_MODULE_AVAILABLE = True
except ImportError:
    BITLOCKER_MODULE_AVAILABLE = False
    BitLockerDecryptor = None

# Dynamic base class determination
_LocalMFTBase = BaseMFTCollector if (BASE_MFT_AVAILABLE and BaseMFTCollector) else object

class LocalMFTCollector(_LocalMFTBase):
    """
    Local disk MFT-based collector

    Inherits from BaseMFTCollector to use the same MFT-based collection as E01.

    Collection priority:
    1. MFT parsing-based collection (ForensicDiskAccessor)
    2. BitLocker encrypted -> attempt decryption -> MFT collection
    3. Decryption failed -> directory traversal fallback (Windows API)

    Digital forensics principles:
    - No file count limit
    - Include deleted files (MFT mode only)
    - Include system folders
    """

    def __init__(self, output_dir: str, volume: str = 'C', decrypted_reader=None):
        """
        Args:
            output_dir: Directory to store extracted artifacts
            volume: Volume to collect from (default: 'C')
            decrypted_reader: Pre-decrypted BitLocker/LUKS volume reader (optional)
        """
        if not BASE_MFT_AVAILABLE:
            raise ImportError("BaseMFTCollector not available")

        super().__init__(output_dir)

        self.volume = volume
        self._partition_index: Optional[int] = None
        self._drive_number: Optional[int] = None

        # BitLocker and fallback related
        self._bitlocker_detected: bool = False
        self._bitlocker_decrypted: bool = False
        self._use_directory_fallback: bool = False
        self._decrypted_reader = decrypted_reader

        self._initialize_accessor()

    def _initialize_accessor(self) -> bool:
        """
        Initialize ForensicDiskAccessor

        Collection priority:
        1. Normal NTFS partition -> MFT collection
        2. BitLocker partition -> attempt decryption -> MFT collection
        3. Decryption failed -> directory traversal fallback
        """
        if not FORENSIC_DISK_AVAILABLE or ForensicDiskAccessor is None:
            logger.warning("ForensicDiskAccessor not available, using directory fallback")
            self._use_directory_fallback = True
            return False

        try:
            # Get physical drive number
            self._drive_number = self._get_physical_drive_number()
            if self._drive_number is None:
                logger.warning("Cannot determine physical drive number, using directory fallback")
                self._use_directory_fallback = True
                return False

            self._accessor = ForensicDiskAccessor.from_physical_disk(self._drive_number)

            # Find partition for volume
            partition_result = self._find_partition_for_volume()

            if partition_result['found']:
                if partition_result['is_bitlocker']:
                    # BitLocker encrypted partition found
                    self._bitlocker_detected = True
                    logger.info(f"BitLocker encrypted partition detected at index {partition_result['index']}")

                    # Use pre-decrypted reader if available (from GUI dialog)
                    if self._decrypted_reader:
                        try:
                            self._accessor = ForensicDiskAccessor(self._decrypted_reader)
                            self._accessor.select_partition(0)
                            self._partition_index = 0
                            self._bitlocker_decrypted = True
                            logger.info("Using pre-decrypted BitLocker volume for MFT collection")
                            return True
                        except Exception as e:
                            logger.warning(f"Decrypted reader initialization failed: {e}")

                    # Attempt auto-decryption
                    if self._try_bitlocker_decryption(partition_result['index']):
                        self._bitlocker_decrypted = True
                        logger.info("BitLocker decryption successful, using MFT collection")
                        return True
                    else:
                        # Decryption failed -> directory traversal fallback
                        logger.warning("BitLocker decryption failed, falling back to directory traversal")
                        self._use_directory_fallback = True
                        self._accessor = None
                        return False
                else:
                    # Normal NTFS partition
                    self._accessor.select_partition(partition_result['index'])
                    self._partition_index = partition_result['index']
                    logger.info(f"LocalMFTCollector initialized: {self.volume}: (Drive {self._drive_number}, Partition {partition_result['index']})")
                    return True
            else:
                # Cannot find partition -> directory traversal fallback
                logger.warning("Cannot find partition for volume, using directory fallback")
                self._use_directory_fallback = True
                return False

        except Exception as e:
            logger.warning(f"LocalMFTCollector initialization failed: {e}, using directory fallback")
            self._accessor = None
            self._use_directory_fallback = True
            return False

    def _try_bitlocker_decryption(self, partition_index: int) -> bool:
        """
        Attempt BitLocker decryption

        If Windows has already mounted the volume (logged in state),
        it can be accessed via OS, so collection is possible via directory fallback.

        Args:
            partition_index: BitLocker partition index

        Returns:
            Whether decryption was successful
        """
        if not BITLOCKER_MODULE_AVAILABLE:
            logger.debug("BitLocker module not available")
            return False

        if not is_pybde_installed():
            logger.debug("pybde not installed, cannot decrypt BitLocker")
            return False

        decryptor = None
        try:
            # Initialize BitLocker decryptor
            decryptor = BitLockerDecryptor.from_physical_disk(
                self._drive_number,
                partition_index
            )

            # Attempt auto-unlock (TPM, auto-unlock key, etc.)
            # User input may actually be required
            # Here we check if Windows has already mounted the volume

            # Windows-mounted volumes can be accessed via directory traversal
            volume_path = f"{self.volume}:\\"
            if os.path.exists(volume_path) and os.path.isdir(volume_path):
                logger.info(f"Volume {self.volume}: is mounted and accessible via Windows API")
                # Use directory fallback (already mounted)
                return False  # MFT still inaccessible, fallback needed

            return False

        except Exception as e:
            logger.debug(f"BitLocker decryption attempt failed: {e}")
            return False
        finally:
            if decryptor is not None:
                try:
                    decryptor.close()
                except Exception:
                    pass

    def _get_source_description(self) -> str:
        """Return source description"""
        if self._use_directory_fallback:
            return f"Local: {self.volume}: (Directory Fallback)"
        return f"Local: {self.volume}:"

    def _get_physical_drive_number(self) -> Optional[int]:
        """Get physical drive number from volume letter"""
        try:
            import ctypes
            from ctypes import wintypes

            volume_path = f"\\\\.\\{self.volume}:"

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
                return None

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

            kernel32.CloseHandle(handle)

            if result and extents.NumberOfDiskExtents > 0:
                return extents.Extents[0].DiskNumber

            return None

        except Exception as e:
            logger.debug(f"Cannot get physical drive number: {e}")
            return None

    def _find_partition_for_volume(self) -> Dict[str, Any]:
        """
        Find partition index for current volume

        Returns:
            {
                'found': bool,
                'index': Optional[int],
                'is_bitlocker': bool,
                'filesystem': str
            }
        """
        result = {'found': False, 'index': None, 'is_bitlocker': False, 'filesystem': ''}

        if not self._accessor:
            return result

        try:
            partitions = self._accessor.list_partitions()

            best_partition = None
            best_size = 0
            bitlocker_partition = None

            for i, part in enumerate(partitions):
                # Skip Recovery partition
                if 'recovery' in part.type_name.lower():
                    continue

                # Record BitLocker encrypted partition
                if part.filesystem in ('BitLocker', 'bitlocker'):
                    # Select largest BitLocker partition (usually main Windows partition)
                    if bitlocker_partition is None or part.size > best_size:
                        bitlocker_partition = i
                        best_size = part.size
                    continue

                # Select largest NTFS partition
                if part.filesystem in ('NTFS', 'ntfs'):
                    if part.size > best_size:
                        best_size = part.size
                        best_partition = i

            # NTFS partition takes priority
            if best_partition is not None:
                result['found'] = True
                result['index'] = best_partition
                result['is_bitlocker'] = False
                result['filesystem'] = 'NTFS'
            # If no NTFS, use BitLocker partition
            elif bitlocker_partition is not None:
                result['found'] = True
                result['index'] = bitlocker_partition
                result['is_bitlocker'] = True
                result['filesystem'] = 'BitLocker'

            return result

        except Exception as e:
            logger.debug(f"Cannot find partition: {e}")
            return result

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None,
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts

        Uses MFT mode or directory traversal fallback.

        Args:
            artifact_type: Type of artifact to collect
            progress_callback: Progress callback

        Yields:
            (local path, metadata) tuple
        """
        if self._use_directory_fallback:
            # BitLocker or MFT inaccessible -> directory traversal
            logger.info(f"[{self._get_source_description()}] Collecting {artifact_type} via directory traversal...")
            yield from self._collect_directory_fallback(artifact_type, progress_callback)
        else:
            # [2026-02-15] MFT mode: if artifact is NOT in MFT filters but IS in ARTIFACT_TYPES
            # (e.g., PC messengers with glob-based collection), use directory fallback for those
            # zone_identifier: MFT ADS scan doesn't work on live disk (ads_streams not populated),
            # use Windows API to read ADS directly instead
            if artifact_type not in ARTIFACT_MFT_FILTERS and artifact_type in ARTIFACT_TYPES:
                logger.info(f"[{self._get_source_description()}] {artifact_type} not in MFT filters, using directory fallback...")
                yield from self._collect_directory_fallback(artifact_type, progress_callback)
            elif artifact_type == 'zone_identifier':
                logger.info(f"[{self._get_source_description()}] zone_identifier: using Windows API for ADS collection...")
                yield from self._collect_directory_fallback(artifact_type, progress_callback)
            else:
                # MFT-based collection (parent class)
                yield from super().collect(artifact_type, progress_callback, **kwargs)

                # [2026-02-16] Memory dump for PC messengers collected via MFT mode
                # MFT mode collects files only; messenger decryption needs process memory
                if artifact_type in ARTIFACT_TYPES:
                    at_config = ARTIFACT_TYPES[artifact_type]
                    if at_config.get('collector') == 'collect_messenger_with_memory':
                        process_name = at_config.get('process_name')
                        already_dumped = getattr(self, f'_memory_dumped_{artifact_type}', False)
                        logger.info(f"[MFT+Memory] {artifact_type}: process_name={process_name}, already_dumped={already_dumped}")
                        if process_name and not already_dumped:
                            setattr(self, f'_memory_dumped_{artifact_type}', True)
                            try:
                                from collectors.process_memory_dumper import ProcessMemoryDumper
                                dumper = ProcessMemoryDumper()
                                artifact_dir = self.output_dir / artifact_type
                                artifact_dir.mkdir(exist_ok=True)
                                dump_filename = f"{process_name.replace('.exe', '').lower()}_memory.dmp"
                                dump_path = str(artifact_dir / dump_filename)
                                logger.info(f"[MFT+Memory] Dumping {process_name} -> {dump_path}")
                                dump_result = dumper.dump_process_lightweight(process_name, dump_path)
                                if dump_result.get('success'):
                                    size_mb = dump_result.get('size', 0) / 1024 / 1024
                                    logger.info(f"[MFT+Memory] Dump SUCCESS: {dump_filename} ({size_mb:.1f} MB, PID={dump_result.get('pid')})")
                                    yield dump_path, {
                                        'artifact_type': artifact_type,
                                        'original_path': dump_path,
                                        'type': artifact_type,
                                        'name': dump_filename,
                                        'path': dump_path,
                                        'size': dump_result.get('size', 0),
                                        'process_pid': dump_result.get('pid'),
                                        'is_memory_dump': True,
                                        'collection_method': 'process_memory_dump',
                                    }
                                else:
                                    logger.warning(f"[MFT+Memory] Dump FAILED for {process_name}: {dump_result.get('error')}")
                            except ImportError:
                                logger.warning("[MFT+Memory] ProcessMemoryDumper not available (ImportError)")
                            except Exception as e:
                                logger.error(f"[MFT+Memory] Error dumping {process_name}: {type(e).__name__}: {e}")
                    else:
                        logger.debug(f"[MFT+Memory] {artifact_type}: collector={at_config.get('collector')}, skipping dump")

    def _collect_directory_fallback(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Directory traversal-based collection (BitLocker/MFT fallback)

        Collects files using paths from ARTIFACT_TYPES.
        Cannot collect deleted files.
        """
        if artifact_type not in ARTIFACT_TYPES:
            # Handle MFT-only artifacts (document, image, video, etc.)
            if artifact_type in ARTIFACT_MFT_FILTERS:
                yield from self._collect_full_disk_scan(artifact_type, progress_callback)
            else:
                logger.debug(f"Skipping unsupported artifact type: {artifact_type}")
            return

        config = ARTIFACT_TYPES[artifact_type]
        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)

        source = self._get_source_description()
        collected_count = 0

        # [2026-01-29] Special artifacts ($MFT, $UsnJrnl, $LogFile) require MFT-based collection
        # Delegate to mft_collector if available, otherwise skip
        if artifact_type in ARTIFACT_MFT_FILTERS:
            mft_filter = ARTIFACT_MFT_FILTERS[artifact_type]
            if mft_filter.get('special'):
                if hasattr(self, 'mft_collector') and self.mft_collector:
                    yield from self._collect_mft(
                        artifact_type, config, artifact_dir,
                        progress_callback, include_deleted=True
                    )
                else:
                    logger.warning(f"Cannot collect {artifact_type} - requires MFT-based collection")
                return

        # Special artifacts cannot be collected via directory fallback
        if config.get('requires_mft'):
            logger.warning(f"Cannot collect {artifact_type} via directory fallback (requires raw disk access)")
            return

        # Skip mobile artifacts
        if config.get('category') in ('android', 'ios'):
            logger.debug(f"Skipping mobile artifact: {artifact_type}")
            return

        # Handle aliases
        if 'alias_of' in config:
            artifact_type = config['alias_of']
            config = ARTIFACT_TYPES[artifact_type]

        # Full disk scan artifacts use _collect_full_disk_scan
        # (document, email, image, video, etc.)
        if artifact_type in ARTIFACT_MFT_FILTERS:
            mft_filter = ARTIFACT_MFT_FILTERS[artifact_type]
            if mft_filter.get('full_disk_scan'):
                yield from self._collect_full_disk_scan(artifact_type, progress_callback)
                return

        collector_type = config.get('collector')
        paths = config.get('paths', [])

        # User folder list
        users_dir = Path(f"{self.volume}:/Users")
        user_folders = []
        if users_dir.exists():
            for entry in users_dir.iterdir():
                if entry.is_dir() and entry.name.lower() not in {'public', 'default', 'default user', 'all users'}:
                    user_folders.append(entry)

        if collector_type == 'collect_glob':
            # Glob pattern collection
            for path_pattern in paths:
                expanded = self._expand_path(path_pattern)
                for match in glob.glob(expanded, recursive=True):
                    result = self._copy_file_with_metadata(match, artifact_dir, artifact_type)
                    if result:
                        collected_count += 1
                        yield result
                        if progress_callback:
                            progress_callback(result[0])

        elif collector_type == 'collect_files':
            # Specific file collection
            for file_path in paths:
                expanded = self._expand_path(file_path)
                if os.path.exists(expanded):
                    result = self._copy_file_with_metadata(expanded, artifact_dir, artifact_type)
                    if result:
                        collected_count += 1
                        yield result
                        if progress_callback:
                            progress_callback(result[0])

        elif collector_type == 'collect_locked_files':
            # Locked file collection (attempt normal copy)
            for file_path in paths:
                expanded = self._expand_path(file_path)
                if os.path.exists(expanded):
                    result = self._copy_file_with_metadata(expanded, artifact_dir, artifact_type)
                    if result:
                        collected_count += 1
                        yield result
                        if progress_callback:
                            progress_callback(result[0])

        elif collector_type in ('collect_ntuser', 'collect_usrclass'):
            # Per-user registry collection
            mft_config = config.get('mft_config', {})
            user_file = mft_config.get('user_path', '')
            for user_folder in user_folders:
                file_path = user_folder / user_file
                if file_path.exists():
                    result = self._copy_file_with_metadata(str(file_path), artifact_dir, artifact_type)
                    if result:
                        collected_count += 1
                        yield result
                        if progress_callback:
                            progress_callback(result[0])

        elif collector_type == 'collect_user_glob':
            # Per-user glob collection (+ system-wide %PROGRAMDATA% support)
            for path_pattern in paths:
                # System-wide paths (not per-user)
                if '%PROGRAMDATA%' in path_pattern or '%SYSTEMROOT%' in path_pattern:
                    expanded = self._expand_path(path_pattern)
                    for match in glob.glob(expanded, recursive=True):
                        if os.path.isdir(match):
                            continue
                        result = self._copy_file_with_metadata(match, artifact_dir, artifact_type)
                        if result:
                            collected_count += 1
                            yield result
                            if progress_callback:
                                progress_callback(result[0])
                    continue

                # Per-user paths
                for user_folder in user_folders:
                    # %APPDATA% -> Users/xxx/AppData/Roaming
                    expanded = path_pattern.replace('%APPDATA%', str(user_folder / 'AppData' / 'Roaming'))
                    expanded = expanded.replace('%LOCALAPPDATA%', str(user_folder / 'AppData' / 'Local'))
                    expanded = expanded.replace('%USERPROFILE%', str(user_folder))
                    for match in glob.glob(expanded, recursive=True):
                        if os.path.isdir(match):
                            continue
                        result = self._copy_file_with_metadata(match, artifact_dir, artifact_type)
                        if result:
                            collected_count += 1
                            yield result
                            if progress_callback:
                                progress_callback(result[0])

        elif collector_type == 'collect_messenger_with_memory':
            # Messenger app collection with process memory dump
            # 1. Collect user data folders (same as collect_user_glob)
            exclude_exts = config.get('exclude_extensions', [])
            for path_pattern in paths:
                for user_folder in user_folders:
                    expanded = path_pattern.replace('%APPDATA%', str(user_folder / 'AppData' / 'Roaming'))
                    expanded = expanded.replace('%LOCALAPPDATA%', str(user_folder / 'AppData' / 'Local'))
                    expanded = expanded.replace('%USERPROFILE%', str(user_folder))
                    for match in glob.glob(expanded, recursive=True):
                        if os.path.isdir(match):
                            continue
                        # Skip excluded extensions
                        if exclude_exts and any(match.lower().endswith(ext.lower()) for ext in exclude_exts):
                            continue
                        result = self._copy_file_with_metadata(match, artifact_dir, artifact_type)
                        if result:
                            collected_count += 1
                            yield result
                            if progress_callback:
                                progress_callback(result[0])

            # 2. Collect process memory dump (if process is running)
            process_name = config.get('process_name')
            logger.info(f"[DirFallback+Memory] {artifact_type}: process_name={process_name}, collected={collected_count} files")
            if process_name:
                try:
                    from collectors.process_memory_dumper import ProcessMemoryDumper
                    dumper = ProcessMemoryDumper()
                    dump_filename = f"{process_name.replace('.exe', '').lower()}_memory.dmp"
                    dump_path = str(artifact_dir / dump_filename)
                    logger.info(f"[DirFallback+Memory] Dumping {process_name} -> {dump_path}")
                    dump_result = dumper.dump_process_lightweight(process_name, dump_path)
                    if dump_result.get('success'):
                        size_mb = dump_result.get('size', 0) / 1024 / 1024
                        logger.info(f"[DirFallback+Memory] Dump SUCCESS: {dump_filename} ({size_mb:.1f} MB, PID={dump_result.get('pid')})")
                        yield dump_path, {
                            'artifact_type': artifact_type,
                            'original_path': dump_path,
                            'type': artifact_type,
                            'name': dump_filename,
                            'path': dump_path,
                            'size': dump_result.get('size', 0),
                            'process_pid': dump_result.get('pid'),
                            'is_memory_dump': True,
                        }
                        collected_count += 1
                    else:
                        logger.warning(f"[DirFallback+Memory] Dump FAILED for {process_name}: {dump_result.get('error')}")
                except ImportError:
                    logger.warning("[DirFallback+Memory] ProcessMemoryDumper not available (ImportError)")
                except Exception as e:
                    logger.error(f"[DirFallback+Memory] Error dumping {process_name}: {type(e).__name__}: {e}")

        elif collector_type == 'collect_all_browsers':
            # Browser data collection
            browsers = config.get('browsers', {})
            for browser_name, browser_config in browsers.items():
                browser_paths = browser_config.get('paths', [])
                for path_pattern in browser_paths:
                    for user_folder in user_folders:
                        expanded = path_pattern.replace('%LOCALAPPDATA%', str(user_folder / 'AppData' / 'Local'))
                        expanded = expanded.replace('%APPDATA%', str(user_folder / 'AppData' / 'Roaming'))
                        for match in glob.glob(expanded, recursive=True):
                            result = self._copy_file_with_metadata(match, artifact_dir, artifact_type)
                            if result:
                                collected_count += 1
                                yield result
                                if progress_callback:
                                    progress_callback(result[0])

        elif collector_type == 'collect_scheduled_tasks':
            # Scheduled task collection
            tasks_dir = Path(f"{self.volume}:/Windows/System32/Tasks")
            if tasks_dir.exists():
                for root, dirs, files in os.walk(tasks_dir):
                    for filename in files:
                        file_path = os.path.join(root, filename)
                        result = self._copy_file_with_metadata(file_path, artifact_dir, artifact_type)
                        if result:
                            collected_count += 1
                            yield result
                            if progress_callback:
                                progress_callback(result[0])

        elif collector_type == 'collect_recycle_bin':
            # [2026-01-20] Recycle Bin dedicated collection - improved system folder permission handling
            # Use Windows path format (backslash)
            recycle_bin_path = None

            # Try case variations (Windows is case-insensitive, but try explicitly)
            variants = ['$Recycle.Bin', '$RECYCLE.BIN', '$recycle.bin', 'RECYCLER']
            for variant in variants:
                # Use backslash
                test_path = Path(f"{self.volume}:\\{variant}")
                logger.debug(f"[RecycleBin] Checking path: {test_path}")
                try:
                    if test_path.exists():
                        recycle_bin_path = test_path
                        logger.info(f"[RecycleBin] Found at: {recycle_bin_path}")
                        break
                except (PermissionError, OSError) as e:
                    logger.debug(f"[RecycleBin] Cannot check {test_path}: {e}")
                    continue

            if recycle_bin_path is None:
                logger.warning(f"[RecycleBin] $Recycle.Bin not found on {self.volume}:")
                _debug_print(f"[RecycleBin] $Recycle.Bin not found on {self.volume}:")
            else:
                try:
                    # Traverse each user SID folder
                    sid_folders = list(recycle_bin_path.iterdir())
                    logger.info(f"[RecycleBin] Found {len(sid_folders)} folders in Recycle Bin")

                    for sid_folder in sid_folders:
                        if sid_folder.is_dir() and sid_folder.name.startswith('S-1-'):
                            logger.debug(f"[RecycleBin] Processing SID folder: {sid_folder.name}")
                            _debug_print(f"[RecycleBin] Processing SID folder: {sid_folder.name}")
                            try:
                                # Collect $I files (metadata) and $R files
                                entries = list(sid_folder.iterdir())
                                logger.debug(f"[RecycleBin] Found {len(entries)} entries in {sid_folder.name}")

                                for entry in entries:
                                    # Collect $I file (metadata)
                                    if entry.name.startswith('$I') and entry.is_file():
                                        try:
                                            result = self._copy_file_with_metadata(
                                                str(entry), artifact_dir, artifact_type
                                            )
                                            if result:
                                                collected_count += 1
                                                logger.info(f"[RecycleBin] Collected: {entry.name}")
                                                yield result
                                                if progress_callback:
                                                    progress_callback(result[0])

                                                # Also try to collect corresponding $R file
                                                r_file = sid_folder / entry.name.replace('$I', '$R')
                                                if r_file.exists():
                                                    r_result = self._copy_file_with_metadata(
                                                        str(r_file), artifact_dir, artifact_type
                                                    )
                                                    if r_result:
                                                        collected_count += 1
                                                        logger.info(f"[RecycleBin] Collected: {r_file.name}")
                                                        yield r_result
                                        except PermissionError as pe:
                                            logger.warning(f"[RecycleBin] Permission denied: {entry} - {pe}")
                                            _debug_print(f"[RecycleBin] Permission denied: {entry} - {pe}")
                                            continue
                                        except OSError as oe:
                                            logger.warning(f"[RecycleBin] OS error: {entry} - {oe}")
                                            _debug_print(f"[RecycleBin] OS error: {entry} - {oe}")
                                            continue
                            except PermissionError as pe:
                                logger.warning(f"[RecycleBin] Cannot access SID folder: {sid_folder} - {pe}")
                                _debug_print(f"[RecycleBin] Cannot access SID folder: {sid_folder}")
                                continue
                            except OSError as oe:
                                logger.warning(f"[RecycleBin] OS error on SID folder: {sid_folder} - {oe}")
                                continue

                    logger.info(f"[RecycleBin] Collection complete: {collected_count} files")

                except PermissionError as e:
                    logger.error(f"[RecycleBin] Cannot access Recycle Bin: {e} - requires admin privileges")
                    _debug_print(f"[RecycleBin] Cannot access Recycle Bin: {e}")
                except OSError as e:
                    logger.error(f"[RecycleBin] OS error accessing Recycle Bin: {e}")

        elif collector_type == 'collect_zone_identifier':
            # [2026-02-15] Zone.Identifier ADS collection via Windows API
            # MFT-based ADS scan doesn't work on live disk, read ADS directly
            user_dirs_to_scan = ['Downloads', 'Desktop', 'Documents']
            for user_folder in user_folders:
                for subdir in user_dirs_to_scan:
                    scan_dir = user_folder / subdir
                    if not scan_dir.exists():
                        continue
                    try:
                        for entry in scan_dir.iterdir():
                            if not entry.is_file():
                                continue
                            ads_path = str(entry) + ':Zone.Identifier'
                            try:
                                with open(ads_path, 'r', encoding='utf-8', errors='replace') as f:
                                    ads_data = f.read()
                                if ads_data.strip():
                                    safe_name = entry.name.replace(':', '_').replace('/', '_').replace('\\', '_')
                                    output_file = artifact_dir / f"{safe_name}_Zone.Identifier.txt"
                                    output_file.write_text(ads_data, encoding='utf-8')
                                    collected_count += 1
                                    metadata = self._get_metadata(str(entry), str(output_file), artifact_type)
                                    metadata['original_path'] = f"{entry}:Zone.Identifier"
                                    metadata['ads_content'] = ads_data[:500]
                                    yield str(output_file), metadata
                                    if progress_callback:
                                        progress_callback(str(output_file))
                            except (OSError, PermissionError):
                                # No Zone.Identifier ADS on this file
                                continue
                    except (PermissionError, OSError) as e:
                        logger.debug(f"[ZoneId] Cannot access {scan_dir}: {e}")
                        continue
            logger.info(f"[ZoneId] Collected {collected_count} Zone.Identifier ADS streams")

        else:
            # Default: try to collect if paths exist
            for path_pattern in paths:
                expanded = self._expand_path(path_pattern)
                if '*' in expanded or '?' in expanded:
                    for match in glob.glob(expanded, recursive=True):
                        result = self._copy_file_with_metadata(match, artifact_dir, artifact_type)
                        if result:
                            collected_count += 1
                            yield result
                            if progress_callback:
                                progress_callback(result[0])
                elif os.path.exists(expanded):
                    result = self._copy_file_with_metadata(expanded, artifact_dir, artifact_type)
                    if result:
                        collected_count += 1
                        yield result
                        if progress_callback:
                            progress_callback(result[0])

        logger.info(f"[{source}] Collected {collected_count} {artifact_type} artifacts (directory fallback)")

    def _expand_path(self, path: str) -> str:
        """Expand environment variables"""
        volume_root = f"{self.volume}:"
        # Expand environment variables
        path = path.replace('%SYSTEMROOT%', f'{volume_root}\\Windows')
        path = path.replace('%WINDIR%', f'{volume_root}\\Windows')
        path = path.replace('%PROGRAMDATA%', f'{volume_root}\\ProgramData')
        # User-specific paths are based on current user
        path = os.path.expandvars(path)
        # Change C: drive to current volume
        if path.startswith('C:'):
            path = volume_root + path[2:]
        return path

    def _collect_full_disk_scan(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Full disk scan (document, image, video, etc.)"""
        if artifact_type not in ARTIFACT_MFT_FILTERS:
            return

        mft_filter = ARTIFACT_MFT_FILTERS[artifact_type]
        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)

        extensions = mft_filter.get('extensions', set())
        if not extensions:
            return

        volume_root = f"{self.volume}:\\"
        source = self._get_source_description()
        collected_count = 0

        # Slow directories to exclude from scan
        SKIP_DIRS = {
            'windows', '$recycle.bin', 'system volume information',
            'programdata', '$windows.~bt', '$windows.~ws',
            'recovery', 'boot', 'perflogs',
        }
        SKIP_SUBDIRS = {
            'winsxs', 'installer', 'assembly', 'servicing',
            'softwaredistribution', 'catroot', 'catroot2',
            # Exclude forensic collection temp directories (prevent E01 extracted files from being included in local collection)
            'e01_extract', 'e01_preview_',
        }
        # Exclude directories starting with specific patterns
        SKIP_PREFIXES = ('forensic_', 'e01_preview_')

        # Prioritize user folder collection
        users_dir = os.path.join(volume_root, 'Users')
        scan_dirs = []

        if os.path.exists(users_dir):
            scan_dirs.append(users_dir)

        try:
            for entry in os.scandir(volume_root):
                if entry.is_dir():
                    name_lower = entry.name.lower()
                    if name_lower in SKIP_DIRS:
                        continue
                    if entry.path != users_dir:
                        scan_dirs.append(entry.path)
        except PermissionError:
            pass

        total_dirs = len(scan_dirs)
        logger.info(f"[{source}] Full disk scan for {artifact_type} ({len(extensions)} extensions)")

        for dir_idx, scan_dir in enumerate(scan_dirs, 1):
            logger.info(f"[{source}] Scanning [{dir_idx}/{total_dirs}] {scan_dir}")

            for root, dirs, files in os.walk(scan_dir):
                # Filter out excluded directories
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in SKIP_SUBDIRS
                    and not any(d.lower().startswith(prefix) for prefix in SKIP_PREFIXES)
                ]

                try:
                    for filename in files:
                        ext = os.path.splitext(filename)[1].lower()
                        if ext in extensions:
                            src_path = os.path.join(root, filename)
                            result = self._copy_file_with_metadata(src_path, artifact_dir, artifact_type)
                            if result:
                                collected_count += 1
                                yield result
                                if progress_callback:
                                    progress_callback(result[0])
                except PermissionError:
                    continue
                except Exception as e:
                    logger.debug(f"Error scanning {root}: {e}")
                    continue

        logger.info(f"[{source}] Collected {collected_count} {artifact_type} artifacts (directory fallback)")

    def _copy_file_with_metadata(
        self,
        src_path: str,
        artifact_dir: Path,
        artifact_type: str
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Copy file and generate metadata

        Args:
            src_path: Source file path
            artifact_dir: Output directory
            artifact_type: Artifact type

        Returns:
            (local path, metadata) or None
        """
        try:
            src = Path(src_path)
            if not src.exists() or not src.is_file():
                return None

            # Generate output filename
            safe_filename = src.name
            output_file = artifact_dir / safe_filename

            # Prevent duplicates
            if output_file.exists():
                base = output_file.stem
                suffix = output_file.suffix
                counter = 1
                while output_file.exists():
                    output_file = artifact_dir / f"{base}_{counter}{suffix}"
                    counter += 1

            # Copy file
            shutil.copy2(src_path, output_file)

            # Calculate hash
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            with open(output_file, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)

            # Generate metadata
            stat = src.stat()
            metadata = {
                'artifact_type': artifact_type,
                'name': src.name,
                'original_path': str(src),
                'size': stat.st_size,
                'hash_md5': md5_hash.hexdigest(),
                'hash_sha256': sha256_hash.hexdigest(),
                'collection_method': 'directory_fallback',
                'source': self._get_source_description(),
                'is_deleted': False,  # Directory fallback cannot collect deleted files
                'created_time': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'collected_at': datetime.now().isoformat(),
                'warning': 'Collected via directory fallback - deleted files not recoverable',
            }

            if self._bitlocker_detected:
                metadata['bitlocker_status'] = 'encrypted_but_mounted'

            return str(output_file), metadata

        except PermissionError:
            logger.debug(f"Permission denied: {src_path}")
            return None
        except Exception as e:
            logger.debug(f"Cannot copy {src_path}: {e}")
            return None

    def get_collection_mode(self) -> str:
        """Return current collection mode"""
        if self._use_directory_fallback:
            if self._bitlocker_detected:
                return "directory_fallback (BitLocker)"
            return "directory_fallback"
        return "mft_based"

class ArtifactCollector:
    """
    Forensic artifact collector with ForensicDiskAccessor and MFT support.

    Collection priority:
    1. ForensicDiskAccessor (pure Python, raw sector access) - direct read of locked files
    2. MFTCollector (ForensicDiskAccessor-based) - MFT-based collection
    3. Legacy (shutil) - normal file copy

    ForensicDiskAccessor advantages:
    - Pure Python implementation (no external dependencies)
    - Direct parsing of MBR/GPT -> VBR -> MFT -> Cluster Run
    - Can collect OS-locked files
    - ADS (Alternate Data Streams) support
    - Deleted file recovery possible

    BitLocker support:
    - Pass decrypted volume via decrypted_reader parameter
    """

    def __init__(
        self,
        output_dir: str,
        use_mft: bool = True,
        volume: str = 'C',
        decrypted_reader=None  # BitLocker decrypted UnifiedDiskReader
    ):
        """
        Initialize the collector.

        Args:
            output_dir: Directory to store collected artifacts
            use_mft: Whether to use MFT-based collection (default: True)
            volume: Volume to collect from (default: 'C')
            decrypted_reader: BitLocker decrypted disk reader (optional)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.volume = volume
        self.decrypted_reader = decrypted_reader

        # Collectors
        self.forensic_disk_accessor: Optional[ForensicDiskAccessor] = None
        self.mft_collector: Optional[MFTCollector] = None
        self.collection_mode = 'legacy'

        # ==========================================================
        # Priority 1: ForensicDiskAccessor (pure Python)
        # ==========================================================
        if use_mft and FORENSIC_DISK_AVAILABLE and ForensicDiskAccessor is not None:
            # Use decrypted reader directly (BitLocker/LUKS already unlocked)
            if self.decrypted_reader:
                try:
                    self.forensic_disk_accessor = ForensicDiskAccessor(self.decrypted_reader)
                    self.forensic_disk_accessor.select_partition(0)
                    self.collection_mode = 'forensic_disk_accessor'
                    _debug_print("[INFO] ForensicDiskAccessor initialized from decrypted volume")
                except Exception as e:
                    _debug_print(f"[WARNING] Decrypted volume ForensicDiskAccessor failed: {e}")
                    self.forensic_disk_accessor = None
            else:
                try:
                    drive_number = self._get_physical_drive_number()
                    if drive_number is not None:
                        self.forensic_disk_accessor = ForensicDiskAccessor.from_physical_disk(drive_number)
                        partition_idx = self._find_partition_for_volume()
                        if partition_idx is not None:
                            self.forensic_disk_accessor.select_partition(partition_idx)
                            self.collection_mode = 'forensic_disk_accessor'
                            _debug_print(f"[INFO] ForensicDiskAccessor initialized for {self.volume}: (Drive {drive_number}, Partition {partition_idx})")
                except Exception as e:
                    _debug_print(f"[WARNING] ForensicDiskAccessor unavailable: {e}")
                    self.forensic_disk_accessor = None

        # ==========================================================
        # Priority 2: MFTCollector (ForensicDiskAccessor) - fallback
        # ==========================================================
        if self.collection_mode != 'forensic_disk_accessor' and use_mft and MFT_AVAILABLE:
            try:
                if self.decrypted_reader:
                    _debug_print("[INFO] Using BitLocker decrypted volume for MFT collection")
                    self.mft_collector = MFTCollector(
                        volume,
                        str(output_dir),
                        disk_reader=self.decrypted_reader
                    )
                else:
                    self.mft_collector = MFTCollector(volume, str(output_dir))
                self.collection_mode = 'mft'
                _debug_print("[INFO] MFTCollector initialized")
            except Exception as e:
                _debug_print(f"[WARNING] MFT collection unavailable: {e}")
                self.mft_collector = None

        # ==========================================================
        # Priority 3: Legacy (shutil)
        # ==========================================================
        if self.collection_mode == 'legacy':
            _debug_print("[INFO] Using legacy collection method (shutil)")

        # Flag for compatibility
        self.use_mft = self.collection_mode in ('forensic_disk_accessor', 'mft')

        # Cache for scan_all_files() results — avoids repeated full MFT scans
        self._scan_cache = None

    def _get_physical_drive_number(self) -> Optional[int]:
        """Get physical drive number from volume letter"""
        try:
            import ctypes
            from ctypes import wintypes

            # Volume path
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
                return None

            # Get disk extent info via IOCTL
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

            kernel32.CloseHandle(handle)

            if result and extents.NumberOfDiskExtents > 0:
                return extents.Extents[0].DiskNumber

            return None

        except Exception as e:
            _debug_print(f"[WARNING] Cannot get physical drive number: {e}")
            return None

    def _find_partition_for_volume(self) -> Optional[int]:
        """
        Find partition index for current volume

        BitLocker encrypted partitions are skipped.
        Non-decrypted BitLocker volumes cannot be accessed via raw sector access.
        """
        if not self.forensic_disk_accessor:
            return None

        try:
            partitions = self.forensic_disk_accessor.list_partitions()

            # 1. Find largest NTFS partition by volume size (usually main Windows partition)
            # 2. Skip BitLocker encrypted partitions
            best_partition = None
            best_size = 0

            for i, part in enumerate(partitions):
                # Skip BitLocker encrypted partition
                if part.filesystem in ('BitLocker', 'bitlocker'):
                    _debug_print(f"[INFO] Partition {i} is BitLocker encrypted - skipping for ForensicDiskAccessor")
                    continue

                # Skip Recovery partition (no Windows folder)
                if 'recovery' in part.type_name.lower():
                    continue

                # Select largest NTFS partition
                if part.filesystem in ('NTFS', 'ntfs'):
                    if part.size > best_size:
                        best_size = part.size
                        best_partition = i

            if best_partition is not None:
                # Check if selected partition has Windows folder
                try:
                    self.forensic_disk_accessor.select_partition(best_partition)
                    # Check for Windows folder existence (find Windows among root's children)
                    has_windows = False
                    for entry_num in range(0, 200):
                        try:
                            metadata = self.forensic_disk_accessor._extractor.get_file_metadata(entry_num)
                            if (metadata.parent_ref == 5 and
                                metadata.is_directory and
                                metadata.filename.lower() == 'windows'):
                                has_windows = True
                                break
                        except Exception:
                            continue

                    if has_windows:
                        return best_partition
                    else:
                        _debug_print(f"[INFO] Partition {best_partition} has no Windows folder - trying MFTCollector")
                        return None
                except Exception as e:
                    _debug_print(f"[WARNING] Cannot verify partition {best_partition}: {e}")
                    return None

            # If no NTFS, return None (fallback to MFTCollector)
            _debug_print("[INFO] No suitable NTFS partition found for ForensicDiskAccessor")
            return None

        except Exception as e:
            _debug_print(f"[WARNING] Cannot find partition: {e}")
            return None

    def close(self):
        """Clean up resources"""
        # Release scan cache to free memory
        self._scan_cache = None

        if self.forensic_disk_accessor:
            try:
                self.forensic_disk_accessor.close()
            except Exception:
                pass
            self.forensic_disk_accessor = None

        if self.mft_collector:
            self.mft_collector.close()
            self.mft_collector = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get_available_artifacts(self) -> List[Dict[str, Any]]:
        """
        Get list of available artifact types.

        Returns:
            List of artifact info dictionaries
        """
        artifacts = []
        for type_id, info in ARTIFACT_TYPES.items():
            available = True
            unavailable_reason = None

            # Check if requires MFT
            if info.get('requires_mft', False) and not self.use_mft:
                available = False
                unavailable_reason = 'MFT collection required'

            # Check if requires ADB
            if info.get('requires_adb', False) and not ADB_AVAILABLE:
                available = False
                unavailable_reason = 'ADB not installed or not in PATH'

            # Check if requires iOS backup
            if info.get('requires_backup', False) and not IOS_AVAILABLE:
                available = False
                unavailable_reason = 'iOS backup support not available'

            artifacts.append({
                'type': type_id,
                'name': info['name'],
                'description': info['description'],
                'category': info.get('category', 'windows'),
                'requires_admin': info.get('requires_admin', False),
                'requires_mft': info.get('requires_mft', False),
                'requires_adb': info.get('requires_adb', False),
                'requires_root': info.get('requires_root', False),
                'requires_backup': info.get('requires_backup', False),
                'available': available,
                'unavailable_reason': unavailable_reason,
            })

        return artifacts

    def get_artifacts_by_category(self, category: str) -> List[Dict[str, Any]]:
        """
        Get available artifacts filtered by category.

        Args:
            category: 'windows', 'android', or 'ios'

        Returns:
            List of artifact info dictionaries for the category
        """
        all_artifacts = self.get_available_artifacts()
        return [a for a in all_artifacts if a.get('category', 'windows') == category]

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None,
        include_deleted: bool = True,
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts of a specific type.

        Args:
            artifact_type: Type of artifact to collect (e.g., 'prefetch')
            progress_callback: Optional callback for progress updates
            include_deleted: Include deleted files (MFT mode only)
            **kwargs: Additional arguments for specific collectors
                - device_serial: Android device serial (for android category)
                - backup_path: iOS backup path (for ios category)

        Yields:
            Tuple of (file_path, metadata) for each collected file
        """
        if artifact_type not in ARTIFACT_TYPES:
            raise ValueError(f"Unknown artifact type: {artifact_type}")

        artifact_info = ARTIFACT_TYPES[artifact_type]

        # Handle alias types (e.g., browser_chrome -> browser)
        if 'alias_of' in artifact_info:
            actual_type = artifact_info['alias_of']
            browser_filter = artifact_info.get('filter_browser')
            artifact_info = ARTIFACT_TYPES[actual_type]
            artifact_type = actual_type
        else:
            browser_filter = None

        # Get category for routing
        category = artifact_info.get('category', 'windows')

        # Check availability based on category
        if artifact_info.get('requires_mft', False) and not self.use_mft:
            _debug_print(f"[WARNING] {artifact_type} requires MFT collection")
            return

        if artifact_info.get('requires_adb', False) and not ADB_AVAILABLE:
            _debug_print(f"[WARNING] {artifact_type} requires ADB (not in PATH)")
            return

        if artifact_info.get('requires_backup', False) and not IOS_AVAILABLE:
            _debug_print(f"[WARNING] {artifact_type} requires iOS backup support")
            return

        # Create artifact-specific output directory
        # C4 Security: Path traversal attack defense - verify with utility functions
        artifact_dir = self.output_dir / sanitize_path_component(artifact_type)
        validate_safe_path(self.output_dir, artifact_dir)
        artifact_dir.mkdir(exist_ok=True)

        # Route to appropriate collector based on category
        if category == 'android':
            yield from self._collect_android(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, **kwargs
            )
        elif category == 'ios':
            yield from self._collect_ios(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, **kwargs
            )
        elif category == 'linux':
            yield from self._collect_linux(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, **kwargs
            )
        elif category == 'macos':
            yield from self._collect_macos(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, **kwargs
            )
        elif artifact_type == 'browser':
            # Special handling for browser type
            yield from self._collect_browsers(
                artifact_info, artifact_dir, progress_callback,
                browser_filter, include_deleted
            )
        elif self.collection_mode == 'forensic_disk_accessor' and self.forensic_disk_accessor:
            # Priority 1: ForensicDiskAccessor (pure Python)
            yield from self._collect_forensic_disk(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, include_deleted
            )
        elif self.collection_mode == 'mft' and self.mft_collector:
            # Priority 2: MFTCollector (ForensicDiskAccessor)
            yield from self._collect_mft(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, include_deleted
            )
        else:
            # Priority 3: Legacy (shutil)
            yield from self._collect_legacy(
                artifact_type, artifact_info, artifact_dir,
                progress_callback
            )

    def _collect_browsers(
        self,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        browser_filter: Optional[str],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect browser data from Chrome, Edge, and Firefox.

        Args:
            artifact_info: Browser artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            browser_filter: Optional filter for specific browser (e.g., 'chrome')
            include_deleted: Include deleted files (MFT mode only)
        """
        browsers = artifact_info.get('browsers', {})

        for browser_id, browser_config in browsers.items():
            # Skip if filter is set and doesn't match
            if browser_filter and browser_id != browser_filter:
                continue

            browser_name = browser_config.get('name', browser_id)
            # C4 Security: Path traversal defense
            browser_dir = artifact_dir / sanitize_path_component(browser_id)
            validate_safe_path(self.output_dir, browser_dir)
            browser_dir.mkdir(exist_ok=True)

            # Use MFT collection if available
            if self.use_mft and self.mft_collector:
                yield from self._collect_browser_mft(
                    browser_id, browser_config, browser_dir,
                    progress_callback, include_deleted
                )
            else:
                yield from self._collect_browser_legacy(
                    browser_id, browser_config, browser_dir,
                    progress_callback
                )

    def _collect_browser_mft(
        self,
        browser_id: str,
        browser_config: Dict[str, Any],
        browser_dir: Path,
        progress_callback: Optional[callable],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect browser data using MFT"""
        browser_name = browser_config.get('name', browser_id)
        mft_path = browser_config.get('mft_path', '')
        files = browser_config.get('files', [])
        profile_based = browser_config.get('profile_based', False)

        users_dir = Path(r'C:\Users')

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue
            if user_dir.name.lower() in ['public', 'default', 'default user', 'all users']:
                continue

            if profile_based:
                # Firefox: search for profiles
                profiles_path = f"Users/{user_dir.name}/{mft_path}"
                try:
                    for result in self.mft_collector.collect_by_pattern(
                        profiles_path, "*.sqlite", "browser", include_deleted
                    ):
                        result[1]['browser'] = browser_name
                        result[1]['browser_id'] = browser_id
                        result[1]['username'] = user_dir.name
                        yield result
                        if progress_callback:
                            progress_callback(result[0])
                except Exception as e:
                    _debug_print(f"[MFT BROWSER] Firefox profiles error for {user_dir.name}: {e}")
            else:
                # Chrome/Edge: specific files
                full_base_path = f"Users/{user_dir.name}/{mft_path}"
                for filename in files:
                    file_path = f"{full_base_path}/{filename}"
                    try:
                        for result in self.mft_collector.collect_by_path(
                            file_path, "browser", include_deleted
                        ):
                            result[1]['browser'] = browser_name
                            result[1]['browser_id'] = browser_id
                            result[1]['username'] = user_dir.name
                            yield result
                            if progress_callback:
                                progress_callback(result[0])
                    except Exception as e:
                        _debug_print(f"[MFT BROWSER] Error collecting {filename} for {user_dir.name}: {e}")

    def _collect_browser_legacy(
        self,
        browser_id: str,
        browser_config: Dict[str, Any],
        browser_dir: Path,
        progress_callback: Optional[callable]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect browser data using legacy method"""
        browser_name = browser_config.get('name', browser_id)
        profile_based = browser_config.get('profile_based', False)

        if profile_based:
            # Firefox
            yield from self._collect_firefox_profiles(
                browser_config, browser_dir, 'browser', browser_name
            )
        else:
            # Chrome/Edge
            for path_pattern in browser_config.get('paths', []):
                expanded_path = os.path.expandvars(path_pattern)
                src_path = Path(expanded_path)

                if src_path.exists():
                    try:
                        dst_path = browser_dir / src_path.name
                        shutil.copy2(src_path, dst_path)
                        metadata = self._get_metadata(
                            str(src_path), dst_path, 'browser'
                        )
                        metadata['browser'] = browser_name
                        metadata['browser_id'] = browser_id
                        yield str(dst_path), metadata
                        if progress_callback:
                            progress_callback(str(dst_path))
                    except (PermissionError, OSError) as e:
                        _debug_print(f"[BROWSER] Cannot access {expanded_path}: {e}")

    def _collect_forensic_disk(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts using ForensicDiskAccessor.

        Follows MBR/GPT -> VBR -> MFT -> Data Runs -> Cluster chain
        to read files directly from disk, bypassing the file system.

        Digital forensics principles:
        - document, image, video, email: full disk scan (MFT-based)
        - No file count limit
        - Include deleted files
        - Include system folders

        Advantages:
        - Direct collection of OS-locked files (SYSTEM, SAM, NTUSER.DAT, etc.)
        - Deleted file recovery possible
        - ADS (Alternate Data Streams) support
        - System file collection ($MFT, $UsnJrnl:$J, $LogFile, etc.)
        """
        mft_config = artifact_info.get('mft_config', {})

        # ==========================================================
        # No mft_config → use legacy fallback
        # ==========================================================
        if not mft_config:
            logger.info(f"[ForensicDisk] {artifact_type}: no mft_config, using legacy fallback")
            yield from self._collect_legacy(
                artifact_type, artifact_info, artifact_dir, progress_callback
            )
            return

        # ==========================================================
        # Special MFT artifacts ($MFT, $UsnJrnl, $LogFile)
        # ==========================================================
        if 'special' in mft_config:
            method_name = mft_config['special']
            yield from self._collect_forensic_disk_special(
                method_name, artifact_type, artifact_dir, progress_callback
            )
            return

        # ==========================================================
        # Digital forensics: full disk scan for document, image, video, email
        # ==========================================================
        if artifact_type in {'document', 'image', 'video', 'email'}:
            extensions = mft_config.get('extensions', None)
            if extensions:
                _debug_print(f"[ForensicDisk] Full disk scan for {artifact_type} (Digital Forensics mode)")
                yield from self._collect_forensic_disk_pattern(
                    '',  # Ignore base_path
                    '*.*',  # pattern
                    artifact_type,
                    artifact_dir,
                    progress_callback,
                    include_deleted=include_deleted,
                    extensions=extensions,
                    full_disk_scan=True  # Full disk scan
                )
                return

        # ==========================================================
        # User-specific paths (NTUSER.DAT, browser profiles, messengers, etc.)
        # ==========================================================
        if 'user_path' in mft_config:
            yield from self._collect_forensic_disk_user_paths(
                artifact_type, mft_config, artifact_dir,
                progress_callback, include_deleted
            )
            # Don't return - may also have system_base_paths or process_name
        else:
            # ==========================================================
            # Pattern-based or file list collection (system paths)
            # ==========================================================
            base_path = mft_config.get('base_path', '')
            pattern = mft_config.get('pattern', None)
            files = mft_config.get('files', None)
            extensions = mft_config.get('extensions', None)

            if pattern:
                # Pattern-based collection (with extension filter)
                yield from self._collect_forensic_disk_pattern(
                    base_path, pattern, artifact_type, artifact_dir,
                    progress_callback, include_deleted,
                    extensions=extensions
                )
            elif files:
                # Specific file list collection
                for filename in files:
                    file_path = f"{base_path}/{filename}" if base_path else filename
                    yield from self._collect_forensic_disk_file(
                        file_path, artifact_type, artifact_dir, progress_callback
                    )

        # ==========================================================
        # System-wide paths (TeamViewer/AnyDesk ProgramData, etc.)
        # ==========================================================
        for sys_path in mft_config.get('system_base_paths', []):
            extensions = mft_config.get('extensions', None)
            exclude_extensions = mft_config.get('exclude_extensions', None)
            _debug_print(f"[ForensicDisk] System path scan: {sys_path}")
            yield from self._collect_forensic_disk_pattern(
                sys_path, '*', artifact_type, artifact_dir,
                progress_callback, include_deleted,
                extensions=extensions,
                exclude_extensions=exclude_extensions,
            )

        # ==========================================================
        # Process memory dump (live system only, for PC messengers)
        # ==========================================================
        process_name = artifact_info.get('process_name')
        if process_name:
            yield from self._dump_process_memory(
                artifact_type, process_name, artifact_dir
            )

    def _collect_forensic_disk_special(
        self,
        method_name: str,
        artifact_type: str,
        artifact_dir: Path,
        progress_callback: Optional[callable]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect system MFT artifacts ($MFT, $UsnJrnl:$J, $LogFile)

        NTFS system file inodes:
        - $MFT: inode 0
        - $MFTMirr: inode 1
        - $LogFile: inode 2
        - $Volume: inode 3
        - $AttrDef: inode 4
        - . (Root): inode 5
        - $Bitmap: inode 6
        - $Boot: inode 7
        - $UsnJrnl: $Extend/$UsnJrnl (inode varies, ADS stream "$J")
        """
        try:
            if method_name == 'collect_mft_raw':
                # $MFT (inode 0) — streaming to avoid loading entire MFT into memory
                _debug_print("[ForensicDisk] Collecting $MFT (inode 0)...")
                output_file = artifact_dir / '$MFT'
                md5_hash = hashlib.md5()
                sha256_hash = hashlib.sha256()
                total_size = 0

                if hasattr(self.forensic_disk_accessor, 'stream_file_by_inode'):
                    with open(output_file, 'wb') as f:
                        for chunk in self.forensic_disk_accessor.stream_file_by_inode(0):
                            if chunk:
                                f.write(chunk)
                                md5_hash.update(chunk)
                                sha256_hash.update(chunk)
                                total_size += len(chunk)
                else:
                    data = self.forensic_disk_accessor.read_file_by_inode(0)
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
                        'collection_method': 'forensic_disk_accessor',
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

            elif method_name == 'collect_usn_journal':
                # $UsnJrnl:$J - $J ADS of $UsnJrnl file in $Extend folder
                _debug_print("[ForensicDisk] Collecting $UsnJrnl:$J...")

                # Collect $UsnJrnl - use dedicated method
                data = None
                try:
                    # [2026-01] Skip sparse regions (fix memory/size issues)
                    data = self.forensic_disk_accessor.read_usnjrnl_raw(skip_sparse=True)
                except Exception as e1:
                    _debug_print(f"[DEBUG] read_usnjrnl_raw failed: {e1}")
                    # Alternative: find directly in $Extend directory
                    try:
                        # Find $UsnJrnl in $Extend directory (inode 11)
                        usnjrnl_inode = self.forensic_disk_accessor._find_in_directory(11, '$UsnJrnl')
                        if usnjrnl_inode:
                            # [2026-01] Alternative method also skips sparse
                            data = self.forensic_disk_accessor._read_file_skip_sparse(
                                usnjrnl_inode, stream_name='$J'
                            )
                    except Exception as e2:
                        _debug_print(f"[DEBUG] Alternative USN Journal collection failed: {e2}")

                if data and len(data) > 0:
                    # USN Journal is sparse file, mostly filled with zeros
                    # Check if there's actual data
                    non_zero_bytes = sum(1 for b in data[:min(len(data), 1024*1024)] if b != 0)
                    _debug_print(f"[ForensicDisk] $UsnJrnl:$J size={len(data)} bytes, non-zero (first 1MB)={non_zero_bytes}")

                    output_file = artifact_dir / '$UsnJrnl_J'
                    output_file.write_bytes(data)

                    metadata = {
                        'artifact_type': artifact_type,
                        'name': '$UsnJrnl:$J',
                        'original_path': '$Extend/$UsnJrnl:$J',
                        'size': len(data),
                        'hash_md5': hashlib.md5(data).hexdigest(),
                        'hash_sha256': hashlib.sha256(data).hexdigest(),
                        'collection_method': 'forensic_disk_accessor',
                        'ads_stream': '$J',
                        'collected_at': datetime.now().isoformat(),
                    }

                    yield str(output_file), metadata
                    if progress_callback:
                        progress_callback(str(output_file))
                else:
                    _debug_print("[WARNING] $UsnJrnl:$J not found or empty (data is None or 0 bytes)")

            elif method_name == 'collect_logfile':
                # $LogFile (inode 2) — streaming to avoid loading entire LogFile into memory
                _debug_print("[ForensicDisk] Collecting $LogFile (inode 2)...")
                output_file = artifact_dir / '$LogFile'
                md5_hash = hashlib.md5()
                sha256_hash = hashlib.sha256()
                total_size = 0

                if hasattr(self.forensic_disk_accessor, 'stream_file_by_inode'):
                    with open(output_file, 'wb') as f:
                        for chunk in self.forensic_disk_accessor.stream_file_by_inode(2):
                            if chunk:
                                f.write(chunk)
                                md5_hash.update(chunk)
                                sha256_hash.update(chunk)
                                total_size += len(chunk)
                else:
                    data = self.forensic_disk_accessor.read_file_by_inode(2)
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
                        'collection_method': 'forensic_disk_accessor',
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

            elif method_name == 'collect_zone_identifier':
                # Zone.Identifier ADS - download file source info
                _debug_print("[ForensicDisk] Collecting Zone.Identifier ADS streams...")

                # Target user directories (case-insensitive)
                user_paths = ['downloads', 'desktop', 'documents']
                ads_stream_name = 'Zone.Identifier'
                collected_count = 0
                checked_count = 0

                # Use cached scan result (active_files only for Zone.Identifier)
                if self._scan_cache is None:
                    self._scan_cache = self.forensic_disk_accessor.scan_all_files(include_deleted=True)
                all_files = self._scan_cache.get('active_files', [])
                _debug_print(f"[ForensicDisk] Scanning {len(all_files)} active files for Zone.Identifier...")

                for entry in all_files:
                    try:
                        full_path = getattr(entry, 'full_path', '') or ''
                        filename = getattr(entry, 'filename', '') or ''
                        inode = getattr(entry, 'inode', None)
                        # ads_streams already included in FileCatalogEntry
                        entry_ads = getattr(entry, 'ads_streams', []) or []

                        if not inode or not full_path:
                            continue

                        full_path_lower = full_path.lower()

                        # Filter user directories (under Users folder)
                        is_user_path = False
                        for user_path in user_paths:
                            # '/users/' or 'users/' (handle both with and without root prefix)
                            if ('users/' in full_path_lower or '/users/' in full_path_lower) and \
                               f'/{user_path}/' in full_path_lower:
                                is_user_path = True
                                break

                        if not is_user_path:
                            continue

                        checked_count += 1

                        # Check Zone.Identifier ADS existence (use cached ads_streams)
                        if ads_stream_name not in entry_ads:
                            continue

                        # Read Zone.Identifier ADS
                        ads_data = self.forensic_disk_accessor.read_file_by_inode(
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
                                'collection_method': 'forensic_disk_accessor',
                                'ads_stream': ads_stream_name,
                                'mft_inode': inode,
                                'collected_at': datetime.now().isoformat(),
                            }

                            # Parse Zone.Identifier content (ZoneId, ReferrerUrl, HostUrl)
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
                                            # Zone ID meaning:
                                            # 0 = Local Machine, 1 = Local Intranet
                                            # 2 = Trusted Sites, 3 = Internet, 4 = Restricted Sites
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
                        _debug_print(f"[DEBUG] Zone.Identifier entry error: {entry_err}")
                        continue

                _debug_print(f"[ForensicDisk] Zone.Identifier: checked {checked_count} user files, collected {collected_count} ADS streams")

        except Exception as e:
            _debug_print(f"[ERROR] ForensicDisk special collection failed ({method_name}): {e}")

    def _collect_forensic_disk_file(
        self,
        file_path: str,
        artifact_type: str,
        artifact_dir: Path,
        progress_callback: Optional[callable]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Single file collection (ForensicDiskAccessor)
        """
        try:
            # Normalize path (Windows -> Unix style)
            normalized_path = file_path.replace('\\', '/')
            if not normalized_path.startswith('/'):
                normalized_path = '/' + normalized_path

            _debug_print(f"[ForensicDisk] Reading: {normalized_path}")
            data = self.forensic_disk_accessor.read_file(normalized_path)

            if data:
                # Generate output filename
                filename = Path(file_path).name
                output_file = artifact_dir / filename

                # Prevent duplicates
                if output_file.exists():
                    base = output_file.stem
                    suffix = output_file.suffix
                    counter = 1
                    while output_file.exists():
                        output_file = artifact_dir / f"{base}_{counter}{suffix}"
                        counter += 1

                output_file.write_bytes(data)

                metadata = {
                    'artifact_type': artifact_type,
                    'name': filename,
                    'original_path': file_path,
                    'size': len(data),
                    'hash_md5': hashlib.md5(data).hexdigest(),
                    'hash_sha256': hashlib.sha256(data).hexdigest(),
                    'collection_method': 'forensic_disk_accessor',
                    'collected_at': datetime.now().isoformat(),
                }

                yield str(output_file), metadata
                if progress_callback:
                    progress_callback(str(output_file))

        except Exception as e:
            _debug_print(f"[WARNING] ForensicDisk cannot read {file_path}: {e}")

    def _collect_forensic_disk_pattern(
        self,
        base_path: str,
        pattern: str,
        artifact_type: str,
        artifact_dir: Path,
        progress_callback: Optional[callable],
        include_deleted: bool,
        extensions: Optional[List[str]] = None,
        exclude_extensions: Optional[List[str]] = None,
        full_disk_scan: bool = False
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Pattern-based collection (ForensicDiskAccessor)

        Scans MFT to collect files matching the pattern.

        Digital forensics principles:
        - No file count limit
        - Include deleted files
        - Include system folders (when full_disk_scan=True)

        Args:
            base_path: Base path (e.g., 'Users/username/Documents')
            pattern: Filename pattern (e.g., '*.pf', '*.*')
            artifact_type: Artifact type
            artifact_dir: Output directory
            progress_callback: Progress callback
            include_deleted: Whether to include deleted files
            extensions: Extension include filter (e.g., ['.doc', '.docx', '.pdf'])
            exclude_extensions: Extension exclude filter (e.g., ['.png', '.jpg'])
            full_disk_scan: If True, scan entire disk (ignore base_path)
        """
        try:
            # MFT scan
            if full_disk_scan:
                _debug_print(f"[ForensicDisk] Full disk scan for {artifact_type} (extensions: {extensions})")
            else:
                _debug_print(f"[ForensicDisk] Scanning for pattern: {base_path}/{pattern}")

            # Use cached scan result to avoid repeated full MFT scans (OOM prevention)
            if self._scan_cache is None:
                self._scan_cache = self.forensic_disk_accessor.scan_all_files(
                    include_deleted=True
                )
            scan_result = self._scan_cache

            # Normalize path
            base_normalized = base_path.replace('\\', '/').strip('/') if not full_disk_scan else ''

            # Combine active files and deleted files (copy to avoid mutating cache)
            all_files = list(scan_result.get('active_files', []))
            if include_deleted:
                all_files.extend(scan_result.get('deleted_files', []))

            collected_count = 0

            # Normalize extensions (lowercase, include '.')
            if extensions:
                normalized_extensions = set()
                for ext in extensions:
                    ext_lower = ext.lower()
                    if not ext_lower.startswith('.'):
                        ext_lower = '.' + ext_lower
                    normalized_extensions.add(ext_lower)
                extensions = normalized_extensions

            # Normalize exclude_extensions
            normalized_exclude_ext = None
            if exclude_extensions:
                normalized_exclude_ext = set()
                for ext in exclude_extensions:
                    ext_lower = ext.lower()
                    if not ext_lower.startswith('.'):
                        ext_lower = '.' + ext_lower
                    normalized_exclude_ext.add(ext_lower)

            for entry in all_files:
                if entry.is_directory:
                    continue

                filename = entry.filename
                filename_lower = filename.lower()

                # Extension include filter (apply first - fast filtering)
                if extensions:
                    has_ext = False
                    if '.' in filename_lower:
                        file_ext = '.' + filename_lower.rsplit('.', 1)[-1]
                        if file_ext in extensions:
                            has_ext = True
                    if not has_ext:
                        continue

                # Extension exclude filter (e.g., Telegram: skip media files)
                if normalized_exclude_ext and '.' in filename_lower:
                    file_ext = '.' + filename_lower.rsplit('.', 1)[-1]
                    if file_ext in normalized_exclude_ext:
                        continue

                # Path matching (only when not full_disk_scan)
                if not full_disk_scan and base_normalized:
                    entry_path = entry.full_path.replace('\\', '/').strip('/')
                    if not entry_path.lower().startswith(base_normalized.lower()):
                        continue

                # Pattern matching (only when no extension filter)
                if not extensions and not normalized_exclude_ext and pattern:
                    if not fnmatch.fnmatch(filename_lower, pattern.lower()):
                        continue

                # Collect file
                try:
                    data = self.forensic_disk_accessor.read_file_by_inode(entry.inode)

                    if data:
                        # Output filename (add prefix for deleted files)
                        if entry.is_deleted:
                            output_filename = f"[DELETED]_{filename}"
                        else:
                            output_filename = filename

                        output_file = artifact_dir / output_filename

                        # Prevent duplicates
                        if output_file.exists():
                            base = output_file.stem
                            suffix = output_file.suffix
                            counter = 1
                            while output_file.exists():
                                output_file = artifact_dir / f"{base}_{counter}{suffix}"
                                counter += 1

                        output_file.write_bytes(data)

                        metadata = {
                            'artifact_type': artifact_type,
                            'name': filename,
                            'original_path': entry.full_path,
                            'size': len(data),
                            'hash_md5': hashlib.md5(data).hexdigest(),
                            'hash_sha256': hashlib.sha256(data).hexdigest(),
                            'collection_method': 'forensic_disk_accessor',
                            'mft_inode': entry.inode,
                            'is_deleted': entry.is_deleted,
                            'created_time': entry.created_time,
                            'modified_time': entry.modified_time,
                            'collected_at': datetime.now().isoformat(),
                        }

                        yield str(output_file), metadata
                        collected_count += 1

                        if progress_callback:
                            progress_callback(str(output_file))

                except Exception as e:
                    _debug_print(f"[WARNING] Cannot read {entry.full_path}: {e}")

            _debug_print(f"[ForensicDisk] Pattern collection completed: {collected_count} files (no limits)")

        except Exception as e:
            _debug_print(f"[ERROR] ForensicDisk pattern collection failed: {e}")

    def _collect_forensic_disk_user_paths(
        self,
        artifact_type: str,
        mft_config: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Per-user path collection (NTUSER.DAT, browser profiles, messengers, etc.)

        Digital forensics principles:
        - Apply extension filter (include or exclude)
        - Include deleted files
        - Support user_path as string or list (e.g., WeChat dual layout)
        """
        users_dir = Path(r'C:\Users')

        # Support user_path as string or list
        raw_user_path = mft_config.get('user_path', '')
        if isinstance(raw_user_path, str):
            user_path_list = [raw_user_path]
        else:
            user_path_list = raw_user_path

        pattern = mft_config.get('pattern', None)
        files = mft_config.get('files', None)
        extensions = mft_config.get('extensions', None)
        exclude_extensions = mft_config.get('exclude_extensions', None)

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue

            # Exclude system directories
            if user_dir.name.lower() in ['public', 'default', 'default user', 'all users']:
                continue

            # Per-user output directory
            user_output_dir = artifact_dir / user_dir.name
            user_output_dir.mkdir(exist_ok=True)

            for user_path in user_path_list:
                try:
                    if pattern:
                        # Pattern-based collection (with extension filter)
                        full_base_path = f"Users/{user_dir.name}/{user_path}"
                        for result in self._collect_forensic_disk_pattern(
                            full_base_path, pattern, artifact_type,
                            user_output_dir, progress_callback, include_deleted,
                            extensions=extensions,
                            exclude_extensions=exclude_extensions,
                        ):
                            result[1]['username'] = user_dir.name
                            yield result

                    elif files:
                        # File list collection
                        for filename in files:
                            file_path = f"Users/{user_dir.name}/{user_path}/{filename}"
                            for result in self._collect_forensic_disk_file(
                                file_path, artifact_type, user_output_dir, progress_callback
                            ):
                                result[1]['username'] = user_dir.name
                                yield result

                    elif user_path:
                        # Single file (e.g., NTUSER.DAT)
                        full_path = f"Users/{user_dir.name}/{user_path}"
                        for result in self._collect_forensic_disk_file(
                            full_path, artifact_type, user_output_dir, progress_callback
                        ):
                            result[1]['username'] = user_dir.name
                            yield result

                except Exception as e:
                    _debug_print(f"[WARNING] ForensicDisk error for user {user_dir.name}/{user_path}: {e}")

    def _collect_mft(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts using MFT-based method.
        """
        mft_config = artifact_info.get('mft_config', {})

        # No mft_config → use legacy fallback
        if not mft_config:
            logger.info(f"[MFT] {artifact_type}: no mft_config, using legacy fallback")
            yield from self._collect_legacy(
                artifact_type, artifact_info, artifact_dir, progress_callback
            )
            return

        # Handle special collection methods
        if 'special' in mft_config:
            method_name = mft_config['special']
            method = getattr(self.mft_collector, method_name)
            result = method()
            if result:
                yield result
                if progress_callback:
                    progress_callback(result[0])
            return

        # Handle user-specific paths
        if 'user_path' in mft_config:
            yield from self._collect_mft_user_paths(
                artifact_type, mft_config, artifact_dir,
                progress_callback, include_deleted
            )
            # Don't return - may also have system_base_paths or process_name
        else:
            # Handle pattern-based collection (system paths)
            base_path = mft_config.get('base_path', '')
            pattern = mft_config.get('pattern', None)
            files = mft_config.get('files', None)

            if pattern:
                for result in self.mft_collector.collect_by_pattern(
                    base_path, pattern, artifact_type, include_deleted
                ):
                    yield result
                    if progress_callback:
                        progress_callback(result[0])

            elif files:
                for filename in files:
                    file_path = f"{base_path}/{filename}" if base_path else filename
                    for result in self.mft_collector.collect_by_path(
                        file_path, artifact_type, include_deleted
                    ):
                        yield result
                        if progress_callback:
                            progress_callback(result[0])

        # System-wide paths (TeamViewer/AnyDesk ProgramData, etc.)
        for sys_path in mft_config.get('system_base_paths', []):
            extensions = mft_config.get('extensions', None)
            logger.debug(f"[MFT] System path scan: {sys_path}")
            try:
                for result in self.mft_collector.collect_by_pattern(
                    sys_path, '*', artifact_type, include_deleted
                ):
                    # Apply extension filter manually for MFT mode
                    if extensions:
                        filename = result[0].lower() if isinstance(result[0], str) else str(result[0]).lower()
                        if not any(filename.endswith(ext.lower()) for ext in extensions):
                            continue
                    yield result
                    if progress_callback:
                        progress_callback(result[0])
            except Exception as e:
                logger.debug(f"[MFT] System path {sys_path} not found or inaccessible: {e}")

        # Process memory dump (live system only, for PC messengers)
        process_name = artifact_info.get('process_name')
        if process_name:
            yield from self._dump_process_memory(
                artifact_type, process_name, artifact_dir
            )

    def _collect_mft_user_paths(
        self,
        artifact_type: str,
        mft_config: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts from user profile directories using MFT.
        Supports user_path as string or list (e.g., WeChat dual layout).
        """
        users_dir = Path(r'C:\Users')

        # Support user_path as string or list
        raw_user_path = mft_config.get('user_path', '')
        if isinstance(raw_user_path, str):
            user_path_list = [raw_user_path]
        else:
            user_path_list = raw_user_path

        pattern = mft_config.get('pattern', None)
        files = mft_config.get('files', None)
        extensions = mft_config.get('extensions', None)
        exclude_extensions = mft_config.get('exclude_extensions', None)

        # Normalize exclude_extensions for fast lookup
        exclude_ext_set = None
        if exclude_extensions:
            exclude_ext_set = {
                ext.lower() if ext.startswith('.') else f'.{ext.lower()}'
                for ext in exclude_extensions
            }

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue

            # Skip system directories
            if user_dir.name.lower() in ['public', 'default', 'default user', 'all users']:
                continue

            for user_path in user_path_list:
                full_base_path = f"Users/{user_dir.name}/{user_path}"

                try:
                    if pattern:
                        for result in self.mft_collector.collect_by_pattern(
                            full_base_path, pattern, artifact_type, include_deleted
                        ):
                            file_name = result[0].lower() if isinstance(result[0], str) else str(result[0]).lower()

                            # Extension include filter
                            if extensions:
                                if not any(file_name.endswith(ext.lower()) for ext in extensions):
                                    continue

                            # Extension exclude filter (e.g., Telegram media)
                            if exclude_ext_set and '.' in file_name:
                                file_ext = '.' + file_name.rsplit('.', 1)[-1]
                                if file_ext in exclude_ext_set:
                                    continue

                            result[1]['username'] = user_dir.name
                            yield result
                            if progress_callback:
                                progress_callback(result[0])

                    elif files:
                        for filename in files:
                            file_path = f"{full_base_path}/{filename}"
                            for result in self.mft_collector.collect_by_path(
                                file_path, artifact_type, include_deleted
                            ):
                                result[1]['username'] = user_dir.name
                                yield result
                                if progress_callback:
                                    progress_callback(result[0])

                    elif user_path:
                        # Single file (like NTUSER.DAT)
                        for result in self.mft_collector.collect_by_path(
                            f"Users/{user_dir.name}/{user_path}",
                            artifact_type, include_deleted
                        ):
                            result[1]['username'] = user_dir.name
                            yield result
                            if progress_callback:
                                progress_callback(result[0])

                except Exception as e:
                    _debug_print(f"[MFT] Error collecting from {user_dir.name}/{user_path}: {e}")

    def _dump_process_memory(
        self,
        artifact_type: str,
        process_name: str,
        artifact_dir: Path,
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Dump process memory for encryption key extraction (live system only).
        Gracefully fails on dead disk (E01) or when process is not running.
        """
        if getattr(self, f'_memory_dumped_{artifact_type}', False):
            return  # Already dumped in this session
        setattr(self, f'_memory_dumped_{artifact_type}', True)

        try:
            from collectors.process_memory_dumper import ProcessMemoryDumper
            dumper = ProcessMemoryDumper()
            dump_filename = f"{process_name.replace('.exe', '').lower()}_memory.dmp"
            dump_path = str(artifact_dir / dump_filename)

            _debug_print(f"[MEMORY] Dumping {process_name}...")
            dump_result = dumper.dump_process_lightweight(process_name, dump_path)

            if dump_result.get('success'):
                size_mb = dump_result.get('size', 0) / 1024 / 1024
                _debug_print(f"[MEMORY] Dump success: {dump_filename} ({size_mb:.1f} MB)")
                yield dump_path, {
                    'type': artifact_type,
                    'name': dump_filename,
                    'path': dump_path,
                    'size': dump_result.get('size', 0),
                    'process_pid': dump_result.get('pid'),
                    'is_memory_dump': True,
                    'collection_method': 'process_memory_dump',
                }
            else:
                _debug_print(f"[MEMORY] Dump skipped: {dump_result.get('error', 'process not found')}")
        except ImportError:
            _debug_print("[MEMORY] ProcessMemoryDumper not available")
        except Exception as e:
            _debug_print(f"[MEMORY] Error: {e}")

    def _collect_legacy(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts using legacy file API (fallback).

        Note: This method cannot:
        - Recover deleted files
        - Access locked files
        - Preserve MFT metadata
        """
        collector_method_name = artifact_info.get('collector')
        if not collector_method_name:
            return

        collector_method = getattr(self, collector_method_name)

        # Get exclude extensions if specified
        exclude_extensions = artifact_info.get('exclude_extensions')

        for path_pattern in artifact_info['paths']:
            # Pass exclude_extensions for methods that support it
            if collector_method_name in ('collect_user_glob', 'collect_messenger_with_memory') and exclude_extensions:
                results = collector_method(path_pattern, artifact_dir, artifact_type, exclude_extensions)
            else:
                results = collector_method(path_pattern, artifact_dir, artifact_type)

            for result in results:
                # Mark as legacy collection
                result[1]['collection_method'] = 'legacy_file_api'
                result[1]['warning'] = 'Collected via legacy method - limited forensic value'
                yield result
                if progress_callback:
                    progress_callback(result[0])

    def collect_deleted_files(
        self,
        extensions: Optional[List[str]] = None,
        min_size: int = 0,
        max_size: int = 100 * 1024 * 1024
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Scan and collect deleted files (MFT mode only).

        Args:
            extensions: List of file extensions to look for
            min_size: Minimum file size
            max_size: Maximum file size

        Yields:
            Tuple of (file_path, metadata) for each recovered file
        """
        if not self.use_mft or not self.mft_collector:
            _debug_print("[WARNING] Deleted file recovery requires MFT collection")
            return

        deleted_dir = self.output_dir / 'deleted_files'
        deleted_dir.mkdir(exist_ok=True)

        for entry_info in self.mft_collector.scan_deleted_files(extensions, min_size, max_size):
            # Try to extract the file
            try:
                file_obj = self.mft_collector.fs.open_meta(inode=entry_info.entry_number)
                for result in self.mft_collector._extract_file(
                    file_obj, "", "deleted_recovery"
                ):
                    yield result
            except Exception as e:
                _debug_print(f"[MFT] Cannot recover deleted file {entry_info.filename}: {e}")

    # =========================================================================
    # Legacy Collection Methods (Fallback)
    # =========================================================================

    def collect_glob(
        self,
        pattern: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files matching a glob pattern (legacy)"""
        for src_path in glob.glob(pattern, recursive=True):
            try:
                dst_path = output_dir / Path(src_path).name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(src_path, dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                _debug_print(f"[LEGACY] Cannot access {src_path}: {e}")
                continue

    def collect_files(
        self,
        file_path: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect a specific file (legacy)"""
        src_path = Path(file_path)
        if src_path.exists():
            try:
                dst_path = output_dir / src_path.name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(str(src_path), dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                _debug_print(f"[LEGACY] Cannot access {file_path}: {e}")

    def collect_locked_files(
        self,
        file_path: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect files that may be locked by the OS (legacy).

        Uses Volume Shadow Copy or raw file read.
        """
        src_path = Path(file_path)
        if not src_path.exists():
            return

        dst_path = output_dir / src_path.name

        # Try direct copy first
        try:
            shutil.copy2(src_path, dst_path)
            yield str(dst_path), self._get_metadata(str(src_path), dst_path, artifact_type)
            return
        except (PermissionError, OSError):
            pass

        # Try using Volume Shadow Copy
        try:
            vss_path = self._get_vss_path(str(src_path))
            if vss_path and Path(vss_path).exists():
                shutil.copy2(vss_path, dst_path)
                metadata = self._get_metadata(str(src_path), dst_path, artifact_type)
                metadata['collection_method'] = 'vss'
                yield str(dst_path), metadata
                return
        except Exception:
            pass

        _debug_print(f"[LEGACY] Cannot collect locked file {file_path}")
        _debug_print("[INFO] Consider using MFT collection for locked files")

    def collect_user_files(
        self,
        path_pattern: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files from user profile with environment variable expansion (legacy)"""
        expanded_path = os.path.expandvars(path_pattern)
        src_path = Path(expanded_path)

        if src_path.exists():
            try:
                dst_path = output_dir / src_path.name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(expanded_path, dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                _debug_print(f"[LEGACY] Cannot access {expanded_path}: {e}")

    def collect_user_glob(
        self,
        pattern: str,
        output_dir: Path,
        artifact_type: str,
        exclude_extensions: Optional[List[str]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files matching a glob pattern with environment variable expansion (legacy)

        Args:
            pattern: Glob pattern with environment variables
            output_dir: Output directory path
            artifact_type: Artifact type identifier
            exclude_extensions: List of file extensions to exclude (e.g., ['.png', '.jpg'])
        """
        expanded_pattern = os.path.expandvars(pattern)

        # Normalize exclude extensions to lowercase with leading dot
        if exclude_extensions:
            exclude_set = {ext.lower() if ext.startswith('.') else f'.{ext.lower()}'
                          for ext in exclude_extensions}
        else:
            exclude_set = set()

        for src_path in glob.glob(expanded_pattern, recursive=True):
            # Skip directories
            if os.path.isdir(src_path):
                continue

            # Check extension exclusion
            if exclude_set:
                _, ext = os.path.splitext(src_path)
                if ext.lower() in exclude_set:
                    continue

            try:
                dst_path = output_dir / Path(src_path).name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(src_path, dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                _debug_print(f"[LEGACY] Cannot access {src_path}: {e}")
                continue

    def collect_messenger_with_memory(
        self,
        pattern: str,
        output_dir: Path,
        artifact_type: str,
        exclude_extensions: Optional[List[str]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect messenger app data with process memory dump.
        Preserves directory structure for parser compatibility.

        This collector:
        1. Collects user data files (preserving directory structure)
        2. Creates a process memory dump (if process is running)

        Args:
            pattern: Glob pattern with environment variables
            output_dir: Output directory path
            artifact_type: Artifact type identifier
            exclude_extensions: List of file extensions to exclude
        """
        # 1. Collect user data files (preserving directory structure)
        expanded_pattern = os.path.expandvars(pattern)

        # Normalize exclude extensions
        if exclude_extensions:
            exclude_set = {ext.lower() if ext.startswith('.') else f'.{ext.lower()}'
                          for ext in exclude_extensions}
        else:
            exclude_set = set()

        # Find base directory from pattern (e.g., %LOCALAPPDATA%\Kakao\KakaoTalk\users)
        # We want to preserve structure from 'users' directory onwards
        base_marker = None
        for marker in ['users', 'Users', 'AppData']:
            if marker in expanded_pattern:
                base_idx = expanded_pattern.find(marker)
                base_marker = expanded_pattern[:base_idx + len(marker)]
                break

        for src_path in glob.glob(expanded_pattern, recursive=True):
            # Skip directories
            if os.path.isdir(src_path):
                continue

            # Check extension exclusion
            if exclude_set:
                _, ext = os.path.splitext(src_path)
                if ext.lower() in exclude_set:
                    continue

            try:
                # Preserve directory structure from base_marker
                if base_marker and base_marker in src_path:
                    rel_path = src_path[len(base_marker):].lstrip(os.sep).lstrip('/')
                    dst_path = output_dir / rel_path
                else:
                    dst_path = output_dir / Path(src_path).name

                # Create parent directories
                dst_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(src_path, dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                _debug_print(f"[LEGACY] Cannot access {src_path}: {e}")
                continue

        # 2. Collect process memory dump (only once per artifact type)
        artifact_info = ARTIFACT_TYPES.get(artifact_type, {})
        process_name = artifact_info.get('process_name')

        if process_name and not getattr(self, f'_memory_dumped_{artifact_type}', False):
            setattr(self, f'_memory_dumped_{artifact_type}', True)

            try:
                from collectors.process_memory_dumper import ProcessMemoryDumper
                dumper = ProcessMemoryDumper()
                dump_filename = f"{process_name.replace('.exe', '').lower()}_memory.dmp"
                dump_path = str(output_dir / dump_filename)

                _debug_print(f"[MEMORY] Dumping {process_name}...")
                dump_result = dumper.dump_process_lightweight(process_name, dump_path)

                if dump_result.get('success'):
                    size_mb = dump_result.get('size', 0) / 1024 / 1024
                    _debug_print(f"[MEMORY] Dump success: {dump_filename} ({size_mb:.1f} MB)")
                    yield dump_path, {
                        'type': artifact_type,
                        'name': dump_filename,
                        'path': dump_path,
                        'size': dump_result.get('size', 0),
                        'process_pid': dump_result.get('pid'),
                        'is_memory_dump': True,
                        'collection_method': 'process_memory_dump',
                    }
                else:
                    _debug_print(f"[MEMORY] Dump failed: {dump_result.get('error')}")
            except ImportError:
                _debug_print("[MEMORY] ProcessMemoryDumper not available")
            except Exception as e:
                _debug_print(f"[MEMORY] Error: {e}")

    def collect_recycle_bin(
        self,
        _: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect Recycle Bin metadata files ($I files).

        Collects metadata ($I) and original file contents ($R) of deleted files from Recycle Bin.
        $I file: Metadata including original path, deletion time, etc.
        $R file: Actual deleted file contents

        Note: Requires admin privileges for full access.
        """
        collected_count = 0

        # Try case variations (Windows is case-insensitive)
        variants = ['$Recycle.Bin', '$RECYCLE.BIN', '$recycle.bin', 'RECYCLER']
        recycle_bin_path = None

        for variant in variants:
            test_path = Path(f"{self.volume}:\\{variant}")
            _debug_print(f"[RecycleBin] Checking path: {test_path}")
            try:
                if test_path.exists():
                    recycle_bin_path = test_path
                    _debug_print(f"[RecycleBin] Found at: {recycle_bin_path}")
                    break
            except (PermissionError, OSError) as e:
                _debug_print(f"[RecycleBin] Cannot check {test_path}: {e}")
                continue

        if recycle_bin_path is None:
            _debug_print(f"[RecycleBin] $Recycle.Bin not found on {self.volume}:")
            return

        try:
            # Traverse each user SID folder
            sid_folders = list(recycle_bin_path.iterdir())
            _debug_print(f"[RecycleBin] Found {len(sid_folders)} folders in Recycle Bin")

            for sid_folder in sid_folders:
                if sid_folder.is_dir() and sid_folder.name.startswith('S-1-'):
                    _debug_print(f"[RecycleBin] Processing SID folder: {sid_folder.name}")

                    # Create per-SID output directory
                    sid_output_dir = output_dir / sid_folder.name
                    sid_output_dir.mkdir(exist_ok=True)

                    try:
                        entries = list(sid_folder.iterdir())
                        _debug_print(f"[RecycleBin] Found {len(entries)} entries in {sid_folder.name}")

                        for entry in entries:
                            # Collect $I file (metadata)
                            if entry.name.startswith('$I') and entry.is_file():
                                try:
                                    dst_path = sid_output_dir / entry.name
                                    shutil.copy2(entry, dst_path)
                                    metadata = self._get_metadata(str(entry), dst_path, artifact_type)
                                    metadata['user_sid'] = sid_folder.name
                                    metadata['file_type'] = 'metadata'
                                    collected_count += 1
                                    _debug_print(f"[RecycleBin] Collected: {entry.name}")
                                    yield str(dst_path), metadata

                                    # Also try to collect corresponding $R file
                                    r_file = sid_folder / entry.name.replace('$I', '$R')
                                    if r_file.exists():
                                        try:
                                            r_dst_path = sid_output_dir / r_file.name
                                            shutil.copy2(r_file, r_dst_path)
                                            r_metadata = self._get_metadata(str(r_file), r_dst_path, artifact_type)
                                            r_metadata['user_sid'] = sid_folder.name
                                            r_metadata['file_type'] = 'content'
                                            collected_count += 1
                                            _debug_print(f"[RecycleBin] Collected: {r_file.name}")
                                            yield str(r_dst_path), r_metadata
                                        except (PermissionError, OSError) as e:
                                            _debug_print(f"[RecycleBin] Cannot access $R file {r_file}: {e}")

                                except (PermissionError, OSError) as e:
                                    _debug_print(f"[RecycleBin] Permission denied: {entry} - {e}")
                                    continue

                    except PermissionError as e:
                        _debug_print(f"[RecycleBin] Cannot access SID folder: {sid_folder} - {e}")
                        continue
                    except OSError as e:
                        _debug_print(f"[RecycleBin] OS error on SID folder: {sid_folder} - {e}")
                        continue

            _debug_print(f"[RecycleBin] Collection complete: {collected_count} files")

        except PermissionError as e:
            _debug_print(f"[RecycleBin] Cannot access Recycle Bin: {e} - requires admin privileges")
        except OSError as e:
            _debug_print(f"[RecycleBin] OS error accessing Recycle Bin: {e}")

    def collect_ntuser(
        self,
        _: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect NTUSER.DAT files for all users (legacy)"""
        users_dir = Path(r'C:\Users')

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue

            ntuser_path = user_dir / 'NTUSER.DAT'
            if ntuser_path.exists():
                dst_path = output_dir / f"NTUSER.DAT_{user_dir.name}"

                # NTUSER.DAT is usually locked
                for result in self.collect_locked_files(
                    str(ntuser_path), output_dir, artifact_type
                ):
                    # Rename to include username
                    if Path(result[0]).exists():
                        final_path = output_dir / f"NTUSER.DAT_{user_dir.name}"
                        Path(result[0]).rename(final_path)
                        result[1]['username'] = user_dir.name
                        yield str(final_path), result[1]

    def collect_usrclass(
        self,
        _: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect UsrClass.dat files for all users.

        UsrClass.dat contains ShellBags information for folder browsing history.
        Located at: %LOCALAPPDATA%\\Microsoft\\Windows\\UsrClass.dat
        """
        users_dir = Path(r'C:\Users')

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue

            # Skip system directories
            if user_dir.name.lower() in ('public', 'default', 'default user', 'all users'):
                continue

            usrclass_path = user_dir / 'AppData' / 'Local' / 'Microsoft' / 'Windows' / 'UsrClass.dat'
            if usrclass_path.exists():
                # UsrClass.dat is usually locked, use locked file collection
                for result in self.collect_locked_files(
                    str(usrclass_path), output_dir, artifact_type
                ):
                    # Rename to include username
                    if Path(result[0]).exists():
                        final_path = output_dir / f"UsrClass.dat_{user_dir.name}"
                        try:
                            Path(result[0]).rename(final_path)
                            result[1]['username'] = user_dir.name
                            result[1]['artifact_type'] = 'shellbags'
                            yield str(final_path), result[1]
                        except Exception as e:
                            _debug_print(f"[WARNING] Failed to rename UsrClass.dat for {user_dir.name}: {e}")
                            yield result[0], result[1]

    def collect_all_browsers(
        self,
        _: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect browser data from Chrome, Edge, and Firefox (legacy).

        Collects: History, Downloads, Cookies, Login Data
        """
        browser_info = ARTIFACT_TYPES.get('browser', {})
        browsers = browser_info.get('browsers', {})

        for browser_id, browser_config in browsers.items():
            browser_name = browser_config.get('name', browser_id)
            browser_dir = output_dir / browser_id
            browser_dir.mkdir(exist_ok=True)

            # Handle Firefox profile-based structure
            if browser_config.get('profile_based', False):
                yield from self._collect_firefox_profiles(
                    browser_config, browser_dir, artifact_type, browser_name
                )
            else:
                # Chrome/Edge - standard paths
                for path_pattern in browser_config.get('paths', []):
                    expanded_path = os.path.expandvars(path_pattern)
                    src_path = Path(expanded_path)

                    if src_path.exists():
                        try:
                            dst_path = browser_dir / src_path.name
                            shutil.copy2(src_path, dst_path)
                            metadata = self._get_metadata(
                                str(src_path), dst_path, artifact_type
                            )
                            metadata['browser'] = browser_name
                            metadata['browser_id'] = browser_id
                            yield str(dst_path), metadata
                        except (PermissionError, OSError) as e:
                            _debug_print(f"[BROWSER] Cannot access {expanded_path}: {e}")

    def _collect_firefox_profiles(
        self,
        browser_config: Dict[str, Any],
        output_dir: Path,
        artifact_type: str,
        browser_name: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect Firefox data from all profiles"""
        firefox_profiles_dir = Path(os.path.expandvars(
            r'%APPDATA%\Mozilla\Firefox\Profiles'
        ))

        if not firefox_profiles_dir.exists():
            return

        for profile_dir in firefox_profiles_dir.iterdir():
            if not profile_dir.is_dir():
                continue

            profile_name = profile_dir.name
            profile_output = output_dir / profile_name
            profile_output.mkdir(exist_ok=True)

            for filename in browser_config.get('files', []):
                src_path = profile_dir / filename
                if src_path.exists():
                    try:
                        dst_path = profile_output / filename
                        shutil.copy2(src_path, dst_path)
                        metadata = self._get_metadata(
                            str(src_path), dst_path, artifact_type
                        )
                        metadata['browser'] = browser_name
                        metadata['browser_id'] = 'firefox'
                        metadata['profile'] = profile_name
                        yield str(dst_path), metadata
                    except (PermissionError, OSError) as e:
                        _debug_print(f"[FIREFOX] Cannot access {src_path}: {e}")

    def _sanitize_filename(self, filename: str) -> str:
        """Remove invalid characters from filename"""
        sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
        sanitized = re.sub(r'_+', '_', sanitized)
        sanitized = sanitized.strip(' _.')
        if not sanitized:
            sanitized = 'unnamed_file'
        return sanitized

    def _get_metadata(
        self,
        src_path: str,
        dst_path: Path,
        artifact_type: str
    ) -> Dict[str, Any]:
        """Generate metadata for a collected file (legacy)"""
        src = Path(src_path)

        # Calculate hash
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(dst_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
                md5.update(chunk)

        try:
            stat = src.stat()
            timestamps = {
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
            }
        except (OSError, ValueError):
            timestamps = {}

        return {
            'artifact_type': artifact_type,
            'original_path': str(src_path),
            'filename': src.name,
            'size': dst_path.stat().st_size,
            'sha256': sha256.hexdigest(),
            'md5': md5.hexdigest(),
            'timestamps': timestamps,
            'collected_at': datetime.utcnow().isoformat(),
            'collection_method': 'legacy_file_api',
        }

    # =========================================================================
    # Android Forensics Collection Methods
    # =========================================================================

    def _collect_android(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect Android forensics artifacts via USB (adb-shell).

        Args:
            artifact_type: Type of Android artifact (e.g., 'mobile_android_kakaotalk')
            artifact_info: Artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            **kwargs: device_serial for specific device
        """
        from collectors.android_collector import AndroidCollector, ANDROID_ARTIFACT_TYPES

        device_serial = kwargs.get('device_serial')

        # Check if artifact_type is supported by AndroidCollector
        if artifact_type not in ANDROID_ARTIFACT_TYPES:
            _debug_print(f"[ANDROID] Artifact type not in ANDROID_ARTIFACT_TYPES: {artifact_type}")
            return

        try:
            # Use context manager for automatic cleanup
            # AndroidCollector(output_dir, device_serial) - correct order
            with AndroidCollector(str(artifact_dir), device_serial) as collector:
                # Connect to device
                collector.connect(device_serial)
                _debug_print(f"[ANDROID] Connected to device: {collector.device_serial}")

                # Use generic collect() method - handles all artifact types
                for result in collector.collect(artifact_type, progress_callback):
                    file_path, file_metadata = result

                    # Skip error results (empty path)
                    if not file_path:
                        if file_metadata.get('status') == 'error':
                            _debug_print(f"[ANDROID] Collection error: {file_metadata.get('error', 'Unknown')}")
                        continue

                    # Add standard fields if not already present
                    if 'artifact_type' not in file_metadata:
                        file_metadata['artifact_type'] = artifact_type
                    if 'device_serial' not in file_metadata:
                        file_metadata['device_serial'] = device_serial or collector.device_serial
                    if 'collected_at' not in file_metadata:
                        file_metadata['collected_at'] = datetime.utcnow().isoformat()

                    yield file_path, file_metadata

        except RuntimeError as e:
            # USB/device connection errors
            _debug_print(f"[ANDROID] Connection failed: {e}")
        except ValueError as e:
            # Invalid artifact type or device not found
            _debug_print(f"[ANDROID] Invalid configuration: {e}")
        except Exception as e:
            _debug_print(f"[ANDROID] Collection failed for {artifact_type}: {e}")

    # =========================================================================
    # iOS Forensics Collection Methods
    # =========================================================================

    def _collect_ios(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect iOS forensics artifacts from iTunes/Finder backup.

        Args:
            artifact_type: Type of iOS artifact (e.g., 'mobile_ios_kakaotalk')
            artifact_info: Artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            **kwargs: backup_path for specific backup
        """
        from collectors.ios_collector import iOSCollector, find_ios_backups, IOS_ARTIFACT_TYPES

        backup_path = kwargs.get('backup_path')

        # Check if artifact_type is supported by iOSCollector
        if artifact_type not in IOS_ARTIFACT_TYPES:
            _debug_print(f"[iOS] Artifact type not in IOS_ARTIFACT_TYPES: {artifact_type}")
            return

        # If no backup path specified, try to find one
        if not backup_path:
            backups = find_ios_backups()
            if not backups:
                _debug_print("[iOS] No iOS backups found on this system")
                return
            # Use the most recent backup
            backup_path = str(backups[0].path)
            _debug_print(f"[iOS] Using backup: {backups[0].device_name} ({backups[0].ios_version})")

        try:
            # iOSCollector(output_dir, backup_path) - correct order
            collector = iOSCollector(str(artifact_dir), backup_path)

            # Select backup first
            if not collector.select_backup(backup_path):
                _debug_print(f"[iOS] Failed to select backup: {backup_path}")
                return

            # Check if backup is encrypted without decryptor
            if collector.is_encrypted and not getattr(collector, '_encrypted_backup', None):
                _debug_print("[iOS] Backup is encrypted - decryptor not provided, skipping")
                return

            # Use generic collect() method - handles all artifact types
            for result in collector.collect(artifact_type, progress_callback):
                file_path, file_metadata = result

                # Skip error results (empty path)
                if not file_path:
                    if file_metadata.get('status') == 'error':
                        _debug_print(f"[iOS] Collection error: {file_metadata.get('error', 'Unknown')}")
                    continue

                # Add standard fields if not already present
                if 'artifact_type' not in file_metadata:
                    file_metadata['artifact_type'] = artifact_type
                if 'collection_method' not in file_metadata:
                    file_metadata['collection_method'] = 'ios_backup'
                if 'backup_path' not in file_metadata:
                    file_metadata['backup_path'] = backup_path
                if 'collected_at' not in file_metadata:
                    file_metadata['collected_at'] = datetime.utcnow().isoformat()

                yield file_path, file_metadata

        except RuntimeError as e:
            # Backup selection errors
            _debug_print(f"[iOS] Backup error: {e}")
        except ValueError as e:
            # Invalid artifact type
            _debug_print(f"[iOS] Invalid configuration: {e}")
        except Exception as e:
            _debug_print(f"[iOS] Collection failed for {artifact_type}: {e}")

    # =========================================================================
    # Linux Forensics Collection Methods
    # =========================================================================

    def _collect_linux(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect Linux forensics artifacts.

        Args:
            artifact_type: Type of Linux artifact (e.g., 'linux_auth_log')
            artifact_info: Artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            **kwargs: target_root for mounted filesystem (default: '/')
        """
        if not LINUX_AVAILABLE or LinuxCollector is None:
            _debug_print(f"[LINUX] LinuxCollector not available")
            return

        target_root = kwargs.get('target_root', '/')

        try:
            collector = LinuxCollector(str(artifact_dir), target_root=target_root)

            for relative_path, content, metadata in collector.collect(artifact_type):
                # Write content to output directory
                output_path = artifact_dir / relative_path.replace('/', os.sep)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(content)

                # Build result metadata
                file_metadata = {
                    'artifact_type': artifact_type,
                    'collection_method': 'linux_collector',
                    'target_root': target_root,
                    'collected_at': datetime.utcnow().isoformat(),
                    'file_size': len(content),
                    **metadata
                }

                yield str(output_path), file_metadata

                if progress_callback:
                    progress_callback(f"Collected: {relative_path}")

        except Exception as e:
            _debug_print(f"[LINUX] Collection failed for {artifact_type}: {e}")

    # =========================================================================
    # macOS Forensics Collection Methods
    # =========================================================================

    def _collect_macos(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect macOS forensics artifacts.

        Args:
            artifact_type: Type of macOS artifact (e.g., 'macos_launch_agent')
            artifact_info: Artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            **kwargs: target_root for mounted filesystem (default: '/')
        """
        if not MACOS_AVAILABLE or macOSCollector is None:
            _debug_print(f"[MACOS] macOSCollector not available")
            return

        target_root = kwargs.get('target_root', '/')

        try:
            collector = macOSCollector(str(artifact_dir), target_root=target_root)

            for relative_path, content, metadata in collector.collect(artifact_type):
                # Write content to output directory
                output_path = artifact_dir / relative_path.replace('/', os.sep)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(content)

                # Build result metadata
                file_metadata = {
                    'artifact_type': artifact_type,
                    'collection_method': 'macos_collector',
                    'target_root': target_root,
                    'collected_at': datetime.utcnow().isoformat(),
                    'file_size': len(content),
                    **metadata
                }

                yield str(output_path), file_metadata

                if progress_callback:
                    progress_callback(f"Collected: {relative_path}")

        except Exception as e:
            _debug_print(f"[MACOS] Collection failed for {artifact_type}: {e}")

    def _get_vss_path(self, file_path: str) -> Optional[str]:
        """Get path to file in latest Volume Shadow Copy

        [SECURITY] Validates VSS path to prevent path traversal attacks.
        """
        try:
            import subprocess

            result = subprocess.run(
                ['vssadmin', 'list', 'shadows'],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )

            # Parse VSS output to find latest shadow copy
            for line in result.stdout.split('\n'):
                if 'Shadow Copy Volume' in line:
                    vss_volume = line.split(':')[-1].strip()

                    # [SECURITY] Validate VSS volume format
                    # Expected: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{N}\
                    if not re.match(r'^\\\\[\?\.]\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+\\?$', vss_volume):
                        logger.warning(f"[SECURITY] Invalid VSS volume format: {vss_volume}")
                        continue

                    # [SECURITY] Validate file_path format (must be absolute Windows path)
                    if len(file_path) < 3 or file_path[1] != ':':
                        logger.warning(f"[SECURITY] Invalid file path format: {file_path}")
                        return None

                    drive = file_path[0].upper()
                    relative_path = file_path[2:]  # Remove 'C:'

                    # [SECURITY] Check for path traversal attempts
                    if '..' in relative_path or relative_path.startswith('/'):
                        logger.warning(f"[SECURITY] Path traversal detected: {relative_path}")
                        return None

                    # Construct and validate final path
                    vss_path = f"{vss_volume}{relative_path}"

                    # [SECURITY] Verify path stays within VSS volume
                    try:
                        resolved = Path(vss_path).resolve()
                        if not str(resolved).startswith(vss_volume.rstrip('\\')):
                            logger.warning(f"[SECURITY] Path escape detected: {resolved}")
                            return None
                    except (OSError, ValueError):
                        # Path resolution failed - reject for safety
                        return None

                    return vss_path

        except Exception as e:
            logger.debug(f"VSS path resolution failed: {e}")

        return None

def get_collection_mode() -> str:
    """
    Get current collection mode.

    Returns:
        'mft' if MFT collection available, 'legacy' otherwise
    """
    if MFT_AVAILABLE:
        try:
            if check_admin_privileges():
                return 'mft'
            else:
                return 'legacy (no admin)'
        except Exception:
            return 'legacy'
    return 'legacy (no MFT backend)'

if __name__ == "__main__":
    import sys

    _debug_print(f"Collection mode: {get_collection_mode()}")
    _debug_print(f"MFT available: {MFT_AVAILABLE}")

    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            collector = ArtifactCollector(temp_dir)
            _debug_print(f"\nUsing {collector.collection_mode} collection method")

            _debug_print("\nAvailable artifacts:")
            for artifact in collector.get_available_artifacts():
                status = "OK" if artifact['available'] else "N/A"
                admin = " [ADMIN]" if artifact['requires_admin'] else ""
                _debug_print(f"  [{status}] {artifact['type']}: {artifact['name']}{admin}")

            collector.close()
