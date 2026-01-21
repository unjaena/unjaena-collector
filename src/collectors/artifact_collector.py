"""
Artifact Collector Module

디지털 포렌식 아티팩트 수집 모듈.
MFT (Master File Table) 기반 수집을 우선 사용하며,
MFT 사용이 불가능한 경우 레거시 방식으로 폴백합니다.

수집 방식:
- BaseMFTCollector: 통합 MFT 기반 수집 (E01/Local 공용)
- MFT 기반: pytsk3를 이용한 raw disk 접근 (권장)
- 레거시: glob.glob + shutil.copy2 (폴백)

Note: MFT 기반 수집은 관리자 권한 필요
"""
import os
import glob
import shutil
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Generator, Tuple, Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# =============================================================================
# Debug Output Control (프로덕션에서는 비활성화)
# =============================================================================
_DEBUG_OUTPUT = False  # True로 변경하면 디버그 메시지 출력

def _debug_print(message: str):
    """디버그 출력 (프로덕션에서는 비활성화)"""
    if _DEBUG_OUTPUT:
        print(message)

# Try to import BaseMFTCollector (통합 베이스 클래스)
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

# Try to import ForensicDiskAccessor (순수 Python - 우선)
try:
    from collectors.forensic_disk import (
        ForensicDiskAccessor,
        FORENSIC_DISK_AVAILABLE
    )
except ImportError:
    FORENSIC_DISK_AVAILABLE = False
    ForensicDiskAccessor = None

# Try to import MFT collector (pytsk3 - 폴백)
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
        check_adb_available, ADB_AVAILABLE
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
        find_ios_backups, BackupInfo, BIPLIST_AVAILABLE
    )
    IOS_AVAILABLE = True
except ImportError:
    IOS_AVAILABLE = False
    IOS_ARTIFACT_TYPES = {}
    iOSCollector = None
    find_ios_backups = None
    BackupInfo = None

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
# C4 보안: 경로 탈출 공격 방어 유틸리티
# =============================================================================

def validate_safe_path(base_dir: Path, target_path: Path) -> Path:
    """
    경로가 base_dir 내부에 있는지 검증

    Args:
        base_dir: 허용된 기본 디렉토리
        target_path: 검증할 대상 경로

    Returns:
        검증된 경로 (resolve된 상태)

    Raises:
        ValueError: 경로가 base_dir 외부인 경우
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
    경로 구성 요소에서 위험한 문자 제거

    Args:
        name: 경로 구성 요소 (파일명 또는 디렉토리명)

    Returns:
        안전한 이름
    """
    # 경로 구분자 및 상위 디렉토리 참조 제거
    dangerous_chars = ['/', '\\', '..', '\x00']
    safe_name = name
    for char in dangerous_chars:
        safe_name = safe_name.replace(char, '_')

    # 빈 문자열이면 기본값
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
        'paths': [r'C:\$Recycle.Bin'],  # 휴지통 루트 경로
        'mft_config': {
            'base_path': '$Recycle.Bin',
            'pattern': '$I*',
            'recursive': True,
        },
        'requires_admin': True,
        'collector': 'collect_recycle_bin',  # [2026-01] 전용 콜렉터 사용
    },
    'usb': {
        'name': 'USB History',
        'description': 'USB device connection history',
        'paths': [
            r'C:\Windows\INF\setupapi.dev.log',
            r'C:\Windows\System32\config\SYSTEM',  # USB 장치 정보 (USBSTOR, MountedDevices 등)
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
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'media',
    },

    # =========================================================================
    # iOS Forensics Artifacts (Phase 2.1)
    # =========================================================================
    'mobile_ios_sms': {
        'name': 'iOS iMessage/SMS',
        'description': 'Text messages and iMessages from iTunes/Finder backup',
        'paths': [],
        'category': 'ios',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'sms',
    },
    'mobile_ios_call': {
        'name': 'iOS Call History',
        'description': 'Phone call records from backup',
        'paths': [],
        'category': 'ios',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'call',
    },
    'mobile_ios_contacts': {
        'name': 'iOS Contacts',
        'description': 'Address book contacts from backup',
        'paths': [],
        'category': 'ios',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'contacts',
    },
    'mobile_ios_app': {
        'name': 'iOS App Data',
        'description': 'Application data and preferences from backup',
        'paths': [],
        'category': 'ios',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'app',
    },
    'mobile_ios_safari': {
        'name': 'iOS Safari',
        'description': 'Browser history, bookmarks, and tabs from backup',
        'paths': [],
        'category': 'ios',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'safari',
    },
    'mobile_ios_location': {
        'name': 'iOS Location History',
        'description': 'GPS and location data from backup',
        'paths': [],
        'category': 'ios',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'location',
    },
    'mobile_ios_backup': {
        'name': 'iOS Backup Metadata',
        'description': 'Backup configuration and device info (Info.plist, Manifest.plist)',
        'paths': [],
        'category': 'ios',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'backup',
    },

    # =========================================================================
    # 추가 Windows 아티팩트 (Phase 6)
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
    # User Files - 서버 분석 가능한 확장자만 (server_parsing_service.py 기준)
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
            # 서버 분석 가능: python-docx, openpyxl, pypdf, olefile
            'extensions': ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                          '.pdf', '.hwp', '.hwpx'],
        },
        'requires_admin': True,  # MFT 접근 필요
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
            # 서버 분석 가능: email, extract_msg, pypff
            'extensions': ['.pst', '.ost', '.eml', '.msg'],
        },
        'requires_admin': True,  # MFT 접근 필요
        'collector': 'collect_user_glob',
    },

    # =========================================================================
    # Phase 2: 명령어 실행 및 크래시 아티팩트
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
    # Phase 3: 보완 아티팩트 (네트워크, 프로필)
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
    # image, video 제외됨 - 포렌식 관점에서 중요도 낮음 + 해시 계산으로 인한 속도 저하

    # =========================================================================
    # [2026-01] P0 신규 아티팩트 - 높은 포렌식 가치
    # =========================================================================
    'activities_cache': {
        'name': 'Windows Timeline (ActivitiesCache.db)',
        'description': 'Windows Timeline - 앱 실행 지속시간 포함 (Win10 1803+)',
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
        'forensic_value': '앱 실행 시간/지속시간, 클립보드 기록, 파일 열람 기록',
    },
    'pca_launch': {
        'name': 'Program Compatibility Assistant (Win11+)',
        'description': 'Windows 11 22H2+ 프로그램 실행 기록 (PcaAppLaunchDic.txt)',
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
        'forensic_value': '실행 파일 경로, 실행 시간 (AmCache 보완)',
    },
    'etl_log': {
        'name': 'ETW AutoLogger (.etl)',
        'description': 'ETW AutoLogger 트레이스 (이벤트 로그 삭제 후에도 유지)',
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
        'forensic_value': '프로세스 추적, 부팅 기록 (로그 삭제 우회)',
    },
    'wmi_subscription': {
        'name': 'WMI Repository (OBJECTS.DATA)',
        'description': 'WMI 이벤트 구독 - 지속성 메커니즘 탐지 (MITRE T1546.003)',
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
        'forensic_value': 'WMI 지속성, 악성 이벤트 구독 탐지',
    },
    'defender_detection': {
        'name': 'Windows Defender Detection History',
        'description': 'Defender 탐지 기록 (MpDetection-*.bin)',
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
        'forensic_value': '악성코드 탐지 기록, 격리된 파일 정보',
    },
    'zone_identifier': {
        'name': 'Zone.Identifier (ADS)',
        'description': '다운로드 파일 출처 URL 및 보안 영역 정보 (Alternate Data Stream)',
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
        'forensic_value': '다운로드 출처 URL, 보안 영역 (Internet/Intranet), 원본 호스트',
    },
    'bits_jobs': {
        'name': 'BITS Transfer Jobs',
        'description': 'Background Intelligent Transfer Service 작업 기록 (악성코드 다운로드 탐지)',
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
        'forensic_value': 'BITS 다운로드 URL, 작업 생성 시간 (MITRE T1197)',
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
}


# =============================================================================
# Local MFT Collector (BaseMFTCollector 상속)
# =============================================================================

# BitLocker 모듈 import
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

# 동적 베이스 클래스 결정
_LocalMFTBase = BaseMFTCollector if (BASE_MFT_AVAILABLE and BaseMFTCollector) else object


class LocalMFTCollector(_LocalMFTBase):
    """
    로컬 디스크 MFT 기반 수집기

    BaseMFTCollector를 상속하여 E01과 동일한 MFT 기반 수집을 사용합니다.

    수집 우선순위:
    1. MFT 파싱 기반 수집 (ForensicDiskAccessor)
    2. BitLocker 암호화 시 → 복호화 시도 → MFT 수집
    3. 복호화 실패 시 → 디렉토리 탐색 폴백 (Windows API)

    디지털 포렌식 원칙:
    - 파일 수 제한 없음
    - 삭제 파일 포함 (MFT 모드에서만)
    - 시스템 폴더 포함
    """

    def __init__(self, output_dir: str, volume: str = 'C'):
        """
        Args:
            output_dir: 추출된 아티팩트 저장 디렉토리
            volume: 수집할 볼륨 (기본: 'C')
        """
        if not BASE_MFT_AVAILABLE:
            raise ImportError("BaseMFTCollector not available")

        super().__init__(output_dir)

        self.volume = volume
        self._partition_index: Optional[int] = None
        self._drive_number: Optional[int] = None

        # BitLocker 및 폴백 관련
        self._bitlocker_detected: bool = False
        self._bitlocker_decrypted: bool = False
        self._use_directory_fallback: bool = False
        self._decrypted_reader = None

        self._initialize_accessor()

    def _initialize_accessor(self) -> bool:
        """
        ForensicDiskAccessor 초기화

        수집 우선순위:
        1. 일반 NTFS 파티션 → MFT 수집
        2. BitLocker 파티션 → 복호화 시도 → MFT 수집
        3. 복호화 실패 → 디렉토리 탐색 폴백
        """
        if not FORENSIC_DISK_AVAILABLE or ForensicDiskAccessor is None:
            logger.warning("ForensicDiskAccessor not available, using directory fallback")
            self._use_directory_fallback = True
            return False

        try:
            # 물리 드라이브 번호 가져오기
            self._drive_number = self._get_physical_drive_number()
            if self._drive_number is None:
                logger.warning("Cannot determine physical drive number, using directory fallback")
                self._use_directory_fallback = True
                return False

            self._accessor = ForensicDiskAccessor.from_physical_disk(self._drive_number)

            # 볼륨에 해당하는 파티션 찾기
            partition_result = self._find_partition_for_volume()

            if partition_result['found']:
                if partition_result['is_bitlocker']:
                    # BitLocker 암호화 파티션 발견
                    self._bitlocker_detected = True
                    logger.info(f"BitLocker encrypted partition detected at index {partition_result['index']}")

                    # 복호화 시도
                    if self._try_bitlocker_decryption(partition_result['index']):
                        self._bitlocker_decrypted = True
                        logger.info("BitLocker decryption successful, using MFT collection")
                        return True
                    else:
                        # 복호화 실패 → 디렉토리 탐색 폴백
                        logger.warning("BitLocker decryption failed, falling back to directory traversal")
                        self._use_directory_fallback = True
                        self._accessor = None
                        return False
                else:
                    # 일반 NTFS 파티션
                    self._accessor.select_partition(partition_result['index'])
                    self._partition_index = partition_result['index']
                    logger.info(f"LocalMFTCollector initialized: {self.volume}: (Drive {self._drive_number}, Partition {partition_result['index']})")
                    return True
            else:
                # 파티션을 찾을 수 없음 → 디렉토리 탐색 폴백
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
        BitLocker 복호화 시도

        Windows가 이미 볼륨을 마운트했다면 (로그인 상태),
        OS를 통해 접근 가능하므로 디렉토리 폴백으로 수집 가능.

        Args:
            partition_index: BitLocker 파티션 인덱스

        Returns:
            복호화 성공 여부
        """
        if not BITLOCKER_MODULE_AVAILABLE:
            logger.debug("BitLocker module not available")
            return False

        if not is_pybde_installed():
            logger.debug("pybde not installed, cannot decrypt BitLocker")
            return False

        try:
            # BitLocker 복호화기 초기화
            decryptor = BitLockerDecryptor.from_physical_disk(
                self._drive_number,
                partition_index
            )

            # 자동 잠금 해제 시도 (TPM, 자동 잠금 해제 키 등)
            # 실제로는 사용자 입력이 필요할 수 있음
            # 여기서는 Windows가 이미 마운트한 볼륨인지 확인

            # Windows가 마운트한 볼륨은 디렉토리 탐색으로 접근 가능
            volume_path = f"{self.volume}:\\"
            if os.path.exists(volume_path) and os.path.isdir(volume_path):
                logger.info(f"Volume {self.volume}: is mounted and accessible via Windows API")
                # 디렉토리 폴백 사용 (이미 마운트됨)
                return False  # MFT는 여전히 접근 불가, 폴백 필요

            return False

        except Exception as e:
            logger.debug(f"BitLocker decryption attempt failed: {e}")
            return False

    def _get_source_description(self) -> str:
        """소스 설명 반환"""
        if self._use_directory_fallback:
            return f"Local: {self.volume}: (Directory Fallback)"
        return f"Local: {self.volume}:"

    def _get_physical_drive_number(self) -> Optional[int]:
        """볼륨 문자에서 물리 드라이브 번호 가져오기"""
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
        현재 볼륨에 해당하는 파티션 인덱스 찾기

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
                # Recovery 파티션 건너뛰기
                if 'recovery' in part.type_name.lower():
                    continue

                # BitLocker 암호화된 파티션 기록
                if part.filesystem in ('BitLocker', 'bitlocker'):
                    # 가장 큰 BitLocker 파티션 선택 (보통 메인 Windows 파티션)
                    if bitlocker_partition is None or part.size > best_size:
                        bitlocker_partition = i
                        best_size = part.size
                    continue

                # NTFS 파티션 중 가장 큰 것 선택
                if part.filesystem in ('NTFS', 'ntfs'):
                    if part.size > best_size:
                        best_size = part.size
                        best_partition = i

            # NTFS 파티션 우선
            if best_partition is not None:
                result['found'] = True
                result['index'] = best_partition
                result['is_bitlocker'] = False
                result['filesystem'] = 'NTFS'
            # NTFS가 없으면 BitLocker 파티션
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
        아티팩트 수집

        MFT 모드 또는 디렉토리 탐색 폴백 사용.

        Args:
            artifact_type: 수집할 아티팩트 유형
            progress_callback: 진행률 콜백

        Yields:
            (로컬 경로, 메타데이터) 튜플
        """
        if self._use_directory_fallback:
            # BitLocker 또는 MFT 접근 불가 → 디렉토리 탐색
            logger.info(f"[{self._get_source_description()}] Collecting {artifact_type} via directory traversal...")
            yield from self._collect_directory_fallback(artifact_type, progress_callback)
        else:
            # MFT 기반 수집 (부모 클래스)
            yield from super().collect(artifact_type, progress_callback, **kwargs)

    def _collect_directory_fallback(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        디렉토리 탐색 기반 수집 (BitLocker/MFT 폴백)

        ARTIFACT_TYPES의 paths를 사용하여 파일 수집.
        삭제된 파일은 수집 불가.
        """
        if artifact_type not in ARTIFACT_TYPES:
            # MFT-only 아티팩트 처리 (document, image, video 등)
            if artifact_type in ARTIFACT_MFT_FILTERS:
                yield from self._collect_full_disk_scan(artifact_type, progress_callback)
            else:
                logger.warning(f"Unknown artifact type: {artifact_type}")
            return

        config = ARTIFACT_TYPES[artifact_type]
        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)

        source = self._get_source_description()
        collected_count = 0

        # 특수 아티팩트는 디렉토리 폴백으로 수집 불가
        if config.get('requires_mft'):
            logger.warning(f"Cannot collect {artifact_type} via directory fallback (requires raw disk access)")
            return

        # 모바일 아티팩트는 스킵
        if config.get('category') in ('android', 'ios'):
            logger.debug(f"Skipping mobile artifact: {artifact_type}")
            return

        # 별칭 처리
        if 'alias_of' in config:
            artifact_type = config['alias_of']
            config = ARTIFACT_TYPES[artifact_type]

        # 전체 디스크 스캔 아티팩트는 _collect_full_disk_scan 사용
        # (document, email, image, video 등)
        if artifact_type in ARTIFACT_MFT_FILTERS:
            mft_filter = ARTIFACT_MFT_FILTERS[artifact_type]
            if mft_filter.get('full_disk_scan'):
                yield from self._collect_full_disk_scan(artifact_type, progress_callback)
                return

        collector_type = config.get('collector')
        paths = config.get('paths', [])

        # 사용자 폴더 목록
        users_dir = Path(f"{self.volume}:/Users")
        user_folders = []
        if users_dir.exists():
            for entry in users_dir.iterdir():
                if entry.is_dir() and entry.name.lower() not in {'public', 'default', 'default user', 'all users'}:
                    user_folders.append(entry)

        if collector_type == 'collect_glob':
            # glob 패턴 수집
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
            # 특정 파일 수집
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
            # 잠긴 파일 수집 (일반 복사 시도)
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
            # 사용자별 레지스트리 수집
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
            # 사용자별 glob 수집
            for path_pattern in paths:
                for user_folder in user_folders:
                    # %APPDATA% -> Users/xxx/AppData/Roaming
                    expanded = path_pattern.replace('%APPDATA%', str(user_folder / 'AppData' / 'Roaming'))
                    expanded = expanded.replace('%LOCALAPPDATA%', str(user_folder / 'AppData' / 'Local'))
                    expanded = expanded.replace('%USERPROFILE%', str(user_folder))
                    for match in glob.glob(expanded, recursive=True):
                        result = self._copy_file_with_metadata(match, artifact_dir, artifact_type)
                        if result:
                            collected_count += 1
                            yield result
                            if progress_callback:
                                progress_callback(result[0])

        elif collector_type == 'collect_all_browsers':
            # 브라우저 데이터 수집
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
            # 예약 작업 수집
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
            # [2026-01-20] 휴지통 전용 수집 - 시스템 폴더 권한 처리 개선
            # Windows 경로 형식 사용 (백슬래시)
            recycle_bin_path = None

            # 대소문자 변형 시도 (Windows는 대소문자 구분 안함, 하지만 명시적으로 시도)
            variants = ['$Recycle.Bin', '$RECYCLE.BIN', '$recycle.bin', 'RECYCLER']
            for variant in variants:
                # 백슬래시 사용
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
                    # 각 사용자 SID 폴더 순회
                    sid_folders = list(recycle_bin_path.iterdir())
                    logger.info(f"[RecycleBin] Found {len(sid_folders)} folders in Recycle Bin")

                    for sid_folder in sid_folders:
                        if sid_folder.is_dir() and sid_folder.name.startswith('S-1-'):
                            logger.debug(f"[RecycleBin] Processing SID folder: {sid_folder.name}")
                            _debug_print(f"[RecycleBin] Processing SID folder: {sid_folder.name}")
                            try:
                                # $I 파일 (메타데이터) 및 $R 파일 수집
                                entries = list(sid_folder.iterdir())
                                logger.debug(f"[RecycleBin] Found {len(entries)} entries in {sid_folder.name}")

                                for entry in entries:
                                    # $I 파일 (메타데이터) 수집
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

                                                # 해당 $R 파일도 수집 시도
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

        else:
            # 기본: paths 있으면 수집 시도
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
        """환경 변수 확장"""
        volume_root = f"{self.volume}:"
        # 환경 변수 확장
        path = path.replace('%SYSTEMROOT%', f'{volume_root}\\Windows')
        path = path.replace('%WINDIR%', f'{volume_root}\\Windows')
        path = path.replace('%PROGRAMDATA%', f'{volume_root}\\ProgramData')
        # 사용자별 경로는 현재 사용자 기준
        path = os.path.expandvars(path)
        # C: 드라이브를 현재 볼륨으로 변경
        if path.startswith('C:'):
            path = volume_root + path[2:]
        return path

    def _collect_full_disk_scan(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """전체 디스크 스캔 (document, image, video 등)"""
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

        # 스캔에서 제외할 느린 디렉토리
        SKIP_DIRS = {
            'windows', '$recycle.bin', 'system volume information',
            'programdata', '$windows.~bt', '$windows.~ws',
            'recovery', 'boot', 'perflogs',
        }
        SKIP_SUBDIRS = {
            'winsxs', 'installer', 'assembly', 'servicing',
            'softwaredistribution', 'catroot', 'catroot2',
            # 포렌식 수집 임시 디렉토리 제외 (E01 추출 파일이 로컬 수집에 포함되지 않도록)
            'e01_extract', 'e01_preview_',
        }
        # 특정 패턴으로 시작하는 디렉토리 제외
        SKIP_PREFIXES = ('forensic_', 'e01_preview_')

        # 사용자 폴더 우선 수집
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
                # 제외할 디렉토리 필터링
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
        파일 복사 및 메타데이터 생성

        Args:
            src_path: 원본 파일 경로
            artifact_dir: 출력 디렉토리
            artifact_type: 아티팩트 유형

        Returns:
            (로컬 경로, 메타데이터) 또는 None
        """
        try:
            src = Path(src_path)
            if not src.exists() or not src.is_file():
                return None

            # 출력 파일명 생성
            safe_filename = src.name
            output_file = artifact_dir / safe_filename

            # 중복 방지
            if output_file.exists():
                base = output_file.stem
                suffix = output_file.suffix
                counter = 1
                while output_file.exists():
                    output_file = artifact_dir / f"{base}_{counter}{suffix}"
                    counter += 1

            # 파일 복사
            shutil.copy2(src_path, output_file)

            # 해시 계산
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            with open(output_file, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)

            # 메타데이터 생성
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
                'is_deleted': False,  # 디렉토리 폴백은 삭제 파일 수집 불가
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
        """현재 수집 모드 반환"""
        if self._use_directory_fallback:
            if self._bitlocker_detected:
                return "directory_fallback (BitLocker)"
            return "directory_fallback"
        return "mft_based"


class ArtifactCollector:
    """
    Forensic artifact collector with ForensicDiskAccessor and MFT support.

    수집 우선순위:
    1. ForensicDiskAccessor (순수 Python, raw sector access) - 잠긴 파일 직접 읽기
    2. MFTCollector (pytsk3) - MFT 기반 수집
    3. Legacy (shutil) - 일반 파일 복사

    ForensicDiskAccessor 장점:
    - 순수 Python 구현 (외부 의존성 없음)
    - MBR/GPT → VBR → MFT → Cluster Run 직접 파싱
    - OS 잠금 파일 수집 가능
    - ADS (Alternate Data Streams) 지원
    - 삭제된 파일 복구 가능

    BitLocker 지원:
    - decrypted_reader 파라미터로 복호화된 볼륨 전달 가능
    """

    def __init__(
        self,
        output_dir: str,
        use_mft: bool = True,
        volume: str = 'C',
        decrypted_reader=None  # BitLocker 복호화된 UnifiedDiskReader
    ):
        """
        Initialize the collector.

        Args:
            output_dir: Directory to store collected artifacts
            use_mft: Whether to use MFT-based collection (default: True)
            volume: Volume to collect from (default: 'C')
            decrypted_reader: BitLocker 복호화된 디스크 리더 (선택적)
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
        # 우선순위 1: ForensicDiskAccessor (순수 Python)
        # ==========================================================
        if use_mft and FORENSIC_DISK_AVAILABLE and ForensicDiskAccessor is not None:
            try:
                # 물리 드라이브 번호 가져오기
                drive_number = self._get_physical_drive_number()
                if drive_number is not None:
                    self.forensic_disk_accessor = ForensicDiskAccessor.from_physical_disk(drive_number)
                    # 볼륨에 해당하는 파티션 선택
                    partition_idx = self._find_partition_for_volume()
                    if partition_idx is not None:
                        self.forensic_disk_accessor.select_partition(partition_idx)
                        self.collection_mode = 'forensic_disk_accessor'
                        _debug_print(f"[INFO] ForensicDiskAccessor initialized for {self.volume}: (Drive {drive_number}, Partition {partition_idx})")
            except Exception as e:
                _debug_print(f"[WARNING] ForensicDiskAccessor unavailable: {e}")
                self.forensic_disk_accessor = None

        # ==========================================================
        # 우선순위 2: MFTCollector (pytsk3) - 폴백
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
                _debug_print("[INFO] MFTCollector (pytsk3) initialized")
            except Exception as e:
                _debug_print(f"[WARNING] MFT collection unavailable: {e}")
                self.mft_collector = None

        # ==========================================================
        # 우선순위 3: Legacy (shutil)
        # ==========================================================
        if self.collection_mode == 'legacy':
            _debug_print("[INFO] Using legacy collection method (shutil)")

        # 호환성을 위한 플래그
        self.use_mft = self.collection_mode in ('forensic_disk_accessor', 'mft')

    def _get_physical_drive_number(self) -> Optional[int]:
        """볼륨 문자에서 물리 드라이브 번호 가져오기"""
        try:
            import ctypes
            from ctypes import wintypes

            # 볼륨 경로
            volume_path = f"\\\\.\\{self.volume}:"

            # 볼륨 열기
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

            # IOCTL로 디스크 익스텐트 정보 가져오기
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
        현재 볼륨에 해당하는 파티션 인덱스 찾기

        BitLocker 암호화된 파티션은 건너뜁니다.
        복호화되지 않은 BitLocker 볼륨은 raw sector 접근이 불가능합니다.
        """
        if not self.forensic_disk_accessor:
            return None

        try:
            partitions = self.forensic_disk_accessor.list_partitions()

            # 1. 볼륨 크기로 가장 큰 NTFS 파티션 찾기 (보통 메인 Windows 파티션)
            # 2. BitLocker 암호화 파티션은 건너뜀
            best_partition = None
            best_size = 0

            for i, part in enumerate(partitions):
                # BitLocker 암호화된 파티션 건너뛰기
                if part.filesystem in ('BitLocker', 'bitlocker'):
                    _debug_print(f"[INFO] Partition {i} is BitLocker encrypted - skipping for ForensicDiskAccessor")
                    continue

                # Recovery 파티션 건너뛰기 (Windows 폴더가 없음)
                if 'recovery' in part.type_name.lower():
                    continue

                # NTFS 파티션 중 가장 큰 것 선택
                if part.filesystem in ('NTFS', 'ntfs'):
                    if part.size > best_size:
                        best_size = part.size
                        best_partition = i

            if best_partition is not None:
                # 선택한 파티션에 Windows 폴더가 있는지 확인
                try:
                    self.forensic_disk_accessor.select_partition(best_partition)
                    # Windows 폴더 존재 확인 (root의 자식 중 Windows 찾기)
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

            # NTFS가 없으면 None 반환 (MFTCollector로 폴백)
            _debug_print("[INFO] No suitable NTFS partition found for ForensicDiskAccessor")
            return None

        except Exception as e:
            _debug_print(f"[WARNING] Cannot find partition: {e}")
            return None

    def close(self):
        """Clean up resources"""
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
                unavailable_reason = 'MFT collection required (pytsk3)'

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
            _debug_print(f"[WARNING] {artifact_type} requires MFT collection (pytsk3)")
            return

        if artifact_info.get('requires_adb', False) and not ADB_AVAILABLE:
            _debug_print(f"[WARNING] {artifact_type} requires ADB (not in PATH)")
            return

        if artifact_info.get('requires_backup', False) and not IOS_AVAILABLE:
            _debug_print(f"[WARNING] {artifact_type} requires iOS backup support")
            return

        # Create artifact-specific output directory
        # C4 보안: 경로 탈출 공격 방어 - 유틸리티 함수로 검증
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
            # 우선순위 1: ForensicDiskAccessor (순수 Python)
            yield from self._collect_forensic_disk(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, include_deleted
            )
        elif self.collection_mode == 'mft' and self.mft_collector:
            # 우선순위 2: MFTCollector (pytsk3)
            yield from self._collect_mft(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, include_deleted
            )
        else:
            # 우선순위 3: Legacy (shutil)
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
            # C4 보안: 경로 탈출 방어
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
        ForensicDiskAccessor를 사용한 아티팩트 수집.

        MBR/GPT → VBR → MFT → Data Runs → Cluster 체인을 따라
        파일 시스템을 우회하여 직접 디스크에서 파일을 읽습니다.

        디지털 포렌식 원칙:
        - document, image, video, email: 전체 디스크 스캔 (MFT 기반)
        - 파일 수 제한 없음
        - 삭제 파일 포함
        - 시스템 폴더 포함

        장점:
        - OS 잠금 파일 (SYSTEM, SAM, NTUSER.DAT 등) 직접 수집
        - 삭제된 파일 복구 가능
        - ADS (Alternate Data Streams) 지원
        - $MFT, $UsnJrnl:$J, $LogFile 등 시스템 파일 수집
        """
        mft_config = artifact_info.get('mft_config', {})

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
        # 디지털 포렌식: document, image, video, email은 전체 디스크 스캔
        # ==========================================================
        if artifact_type in {'document', 'image', 'video', 'email'}:
            extensions = mft_config.get('extensions', None)
            if extensions:
                _debug_print(f"[ForensicDisk] Full disk scan for {artifact_type} (Digital Forensics mode)")
                yield from self._collect_forensic_disk_pattern(
                    '',  # base_path 무시
                    '*.*',  # pattern
                    artifact_type,
                    artifact_dir,
                    progress_callback,
                    include_deleted=True,  # 삭제 파일 포함
                    extensions=extensions,
                    full_disk_scan=True  # 전체 디스크 스캔
                )
                return

        # ==========================================================
        # User-specific paths (NTUSER.DAT, browser profiles, etc.)
        # ==========================================================
        if 'user_path' in mft_config:
            yield from self._collect_forensic_disk_user_paths(
                artifact_type, mft_config, artifact_dir,
                progress_callback, include_deleted
            )
            return

        # ==========================================================
        # Pattern-based or file list collection
        # ==========================================================
        base_path = mft_config.get('base_path', '')
        pattern = mft_config.get('pattern', None)
        files = mft_config.get('files', None)
        extensions = mft_config.get('extensions', None)

        if pattern:
            # 패턴 기반 수집 (확장자 필터 포함)
            yield from self._collect_forensic_disk_pattern(
                base_path, pattern, artifact_type, artifact_dir,
                progress_callback, include_deleted,
                extensions=extensions
            )
        elif files:
            # 특정 파일 목록 수집
            for filename in files:
                file_path = f"{base_path}/{filename}" if base_path else filename
                yield from self._collect_forensic_disk_file(
                    file_path, artifact_type, artifact_dir, progress_callback
                )

    def _collect_forensic_disk_special(
        self,
        method_name: str,
        artifact_type: str,
        artifact_dir: Path,
        progress_callback: Optional[callable]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        시스템 MFT 아티팩트 수집 ($MFT, $UsnJrnl:$J, $LogFile)

        NTFS 시스템 파일 inode:
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
                # $MFT (inode 0)
                _debug_print("[ForensicDisk] Collecting $MFT (inode 0)...")
                data = self.forensic_disk_accessor.read_file_by_inode(0)

                if data:
                    output_file = artifact_dir / '$MFT'
                    output_file.write_bytes(data)

                    metadata = {
                        'artifact_type': artifact_type,
                        'name': '$MFT',
                        'original_path': '$MFT',
                        'size': len(data),
                        'hash_md5': hashlib.md5(data).hexdigest(),
                        'hash_sha256': hashlib.sha256(data).hexdigest(),
                        'collection_method': 'forensic_disk_accessor',
                        'mft_inode': 0,
                        'collected_at': datetime.now().isoformat(),
                    }

                    yield str(output_file), metadata
                    if progress_callback:
                        progress_callback(str(output_file))

            elif method_name == 'collect_usn_journal':
                # $UsnJrnl:$J - $Extend 폴더 내 $UsnJrnl 파일의 $J ADS
                _debug_print("[ForensicDisk] Collecting $UsnJrnl:$J...")

                # $UsnJrnl 수집 - 전용 메서드 사용
                data = None
                try:
                    # 전용 메서드 사용 (올바른 $J 스트림 처리)
                    data = self.forensic_disk_accessor.read_usnjrnl_raw()
                except Exception as e1:
                    _debug_print(f"[DEBUG] read_usnjrnl_raw failed: {e1}")
                    # 대체 방법: $Extend 디렉토리에서 직접 찾기
                    try:
                        # $Extend 디렉토리 (inode 11)에서 $UsnJrnl 찾기
                        usnjrnl_inode = self.forensic_disk_accessor._find_in_directory(11, '$UsnJrnl')
                        if usnjrnl_inode:
                            data = self.forensic_disk_accessor.read_file_by_inode(
                                usnjrnl_inode, stream_name='$J'
                            )
                    except Exception as e2:
                        _debug_print(f"[DEBUG] Alternative USN Journal collection failed: {e2}")

                if data and len(data) > 0:
                    # USN Journal이 스파스 파일인 경우 대부분 0으로 채워짐
                    # 실제 데이터가 있는지 확인
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
                # $LogFile (inode 2)
                _debug_print("[ForensicDisk] Collecting $LogFile (inode 2)...")
                data = self.forensic_disk_accessor.read_file_by_inode(2)

                if data:
                    output_file = artifact_dir / '$LogFile'
                    output_file.write_bytes(data)

                    metadata = {
                        'artifact_type': artifact_type,
                        'name': '$LogFile',
                        'original_path': '$LogFile',
                        'size': len(data),
                        'hash_md5': hashlib.md5(data).hexdigest(),
                        'hash_sha256': hashlib.sha256(data).hexdigest(),
                        'collection_method': 'forensic_disk_accessor',
                        'mft_inode': 2,
                        'collected_at': datetime.now().isoformat(),
                    }

                    yield str(output_file), metadata
                    if progress_callback:
                        progress_callback(str(output_file))

            elif method_name == 'collect_zone_identifier':
                # Zone.Identifier ADS - 다운로드 파일 출처 정보
                _debug_print("[ForensicDisk] Collecting Zone.Identifier ADS streams...")

                # 대상 사용자 디렉토리 (대소문자 무시)
                user_paths = ['downloads', 'desktop', 'documents']
                ads_stream_name = 'Zone.Identifier'
                collected_count = 0
                checked_count = 0

                # MFT 전체 스캔 (ads_streams 포함)
                scan_result = self.forensic_disk_accessor.scan_all_files(include_deleted=False)
                all_files = scan_result.get('active_files', [])
                _debug_print(f"[ForensicDisk] Scanning {len(all_files)} active files for Zone.Identifier...")

                for entry in all_files:
                    try:
                        full_path = getattr(entry, 'full_path', '') or ''
                        filename = getattr(entry, 'filename', '') or ''
                        inode = getattr(entry, 'inode', None)
                        # ads_streams가 이미 FileCatalogEntry에 포함됨
                        entry_ads = getattr(entry, 'ads_streams', []) or []

                        if not inode or not full_path:
                            continue

                        full_path_lower = full_path.lower()

                        # 사용자 디렉토리 필터링 (Users 폴더 하위)
                        is_user_path = False
                        for user_path in user_paths:
                            # '/users/' 또는 'users/' (루트 시작 유무 모두 처리)
                            if ('users/' in full_path_lower or '/users/' in full_path_lower) and \
                               f'/{user_path}/' in full_path_lower:
                                is_user_path = True
                                break

                        if not is_user_path:
                            continue

                        checked_count += 1

                        # Zone.Identifier ADS 존재 여부 확인 (캐시된 ads_streams 사용)
                        if ads_stream_name not in entry_ads:
                            continue

                        # Zone.Identifier ADS 읽기
                        ads_data = self.forensic_disk_accessor.read_file_by_inode(
                            inode, stream_name=ads_stream_name
                        )

                        if ads_data:
                            # 출력 파일명: 원본파일명_Zone.Identifier.txt
                            safe_filename = self._sanitize_filename(filename)
                            output_filename = f"{safe_filename}_Zone.Identifier.txt"
                            output_file = artifact_dir / output_filename

                            # 중복 방지
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

                            # Zone.Identifier 내용 파싱 (ZoneId, ReferrerUrl, HostUrl)
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
                                            # Zone ID 의미:
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
        단일 파일 수집 (ForensicDiskAccessor)
        """
        try:
            # 경로 정규화 (Windows → Unix 스타일)
            normalized_path = file_path.replace('\\', '/')
            if not normalized_path.startswith('/'):
                normalized_path = '/' + normalized_path

            _debug_print(f"[ForensicDisk] Reading: {normalized_path}")
            data = self.forensic_disk_accessor.read_file(normalized_path)

            if data:
                # 출력 파일 이름 생성
                filename = Path(file_path).name
                output_file = artifact_dir / filename

                # 중복 방지
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
        full_disk_scan: bool = False
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        패턴 기반 수집 (ForensicDiskAccessor)

        MFT를 스캔하여 패턴과 일치하는 파일을 수집합니다.

        디지털 포렌식 원칙:
        - 파일 수 제한 없음
        - 삭제 파일 포함
        - 시스템 폴더 포함 (full_disk_scan=True 시)

        Args:
            base_path: 기본 경로 (예: 'Users/username/Documents')
            pattern: 파일명 패턴 (예: '*.pf', '*.*')
            artifact_type: 아티팩트 유형
            artifact_dir: 출력 디렉토리
            progress_callback: 진행률 콜백
            include_deleted: 삭제 파일 포함 여부
            extensions: 확장자 필터 (예: ['.doc', '.docx', '.pdf'])
            full_disk_scan: True면 전체 디스크 스캔 (base_path 무시)
        """
        import fnmatch

        try:
            # MFT 스캔
            if full_disk_scan:
                _debug_print(f"[ForensicDisk] Full disk scan for {artifact_type} (extensions: {extensions})")
            else:
                _debug_print(f"[ForensicDisk] Scanning for pattern: {base_path}/{pattern}")

            scan_result = self.forensic_disk_accessor.scan_all_files(
                include_deleted=include_deleted
            )

            # 경로 정규화
            base_normalized = base_path.replace('\\', '/').strip('/') if not full_disk_scan else ''

            # 활성 파일과 삭제된 파일 합치기
            all_files = scan_result.get('active_files', [])
            if include_deleted:
                all_files.extend(scan_result.get('deleted_files', []))

            collected_count = 0

            # 확장자 정규화 (소문자, '.' 포함)
            if extensions:
                normalized_extensions = set()
                for ext in extensions:
                    ext_lower = ext.lower()
                    if not ext_lower.startswith('.'):
                        ext_lower = '.' + ext_lower
                    normalized_extensions.add(ext_lower)
                extensions = normalized_extensions

            for entry in all_files:
                if entry.is_directory:
                    continue

                filename = entry.filename
                filename_lower = filename.lower()

                # 확장자 필터 (우선 적용 - 빠른 필터링)
                if extensions:
                    has_ext = False
                    if '.' in filename_lower:
                        file_ext = '.' + filename_lower.rsplit('.', 1)[-1]
                        if file_ext in extensions:
                            has_ext = True
                    if not has_ext:
                        continue

                # 경로 매칭 (full_disk_scan이 아닌 경우에만)
                if not full_disk_scan and base_normalized:
                    entry_path = entry.full_path.replace('\\', '/').strip('/')
                    if not entry_path.lower().startswith(base_normalized.lower()):
                        continue

                # 패턴 매칭 (확장자 필터가 없는 경우에만)
                if not extensions and pattern:
                    if not fnmatch.fnmatch(filename_lower, pattern.lower()):
                        continue

                # 파일 수집
                try:
                    data = self.forensic_disk_accessor.read_file_by_inode(entry.inode)

                    if data:
                        # 출력 파일 이름 (삭제된 파일은 접두사 추가)
                        if entry.is_deleted:
                            output_filename = f"[DELETED]_{filename}"
                        else:
                            output_filename = filename

                        output_file = artifact_dir / output_filename

                        # 중복 방지
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
        사용자별 경로 수집 (NTUSER.DAT, browser profiles 등)

        디지털 포렌식 원칙:
        - 확장자 필터 적용
        - 삭제 파일 포함
        """
        users_dir = Path(r'C:\Users')

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue

            # 시스템 디렉토리 제외
            if user_dir.name.lower() in ['public', 'default', 'default user', 'all users']:
                continue

            user_path = mft_config.get('user_path', '')
            pattern = mft_config.get('pattern', None)
            files = mft_config.get('files', None)
            extensions = mft_config.get('extensions', None)  # 확장자 필터

            # 사용자별 출력 디렉토리
            user_output_dir = artifact_dir / user_dir.name
            user_output_dir.mkdir(exist_ok=True)

            try:
                if pattern:
                    # 패턴 기반 수집 (확장자 필터 포함)
                    full_base_path = f"Users/{user_dir.name}/{user_path}"
                    for result in self._collect_forensic_disk_pattern(
                        full_base_path, pattern, artifact_type,
                        user_output_dir, progress_callback, include_deleted,
                        extensions=extensions  # 확장자 필터 전달
                    ):
                        result[1]['username'] = user_dir.name
                        yield result

                elif files:
                    # 파일 목록 수집
                    for filename in files:
                        file_path = f"Users/{user_dir.name}/{user_path}/{filename}"
                        for result in self._collect_forensic_disk_file(
                            file_path, artifact_type, user_output_dir, progress_callback
                        ):
                            result[1]['username'] = user_dir.name
                            yield result

                elif user_path:
                    # 단일 파일 (예: NTUSER.DAT)
                    full_path = f"Users/{user_dir.name}/{user_path}"
                    for result in self._collect_forensic_disk_file(
                        full_path, artifact_type, user_output_dir, progress_callback
                    ):
                        result[1]['username'] = user_dir.name
                        yield result

            except Exception as e:
                _debug_print(f"[WARNING] ForensicDisk error for user {user_dir.name}: {e}")

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
            return

        # Handle pattern-based collection
        base_path = mft_config.get('base_path', '')
        pattern = mft_config.get('pattern', None)
        files = mft_config.get('files', None)

        if pattern:
            # Pattern-based collection
            for result in self.mft_collector.collect_by_pattern(
                base_path, pattern, artifact_type, include_deleted
            ):
                yield result
                if progress_callback:
                    progress_callback(result[0])

        elif files:
            # Specific files collection
            for filename in files:
                file_path = f"{base_path}/{filename}" if base_path else filename
                for result in self.mft_collector.collect_by_path(
                    file_path, artifact_type, include_deleted
                ):
                    yield result
                    if progress_callback:
                        progress_callback(result[0])

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
        """
        users_dir = Path(r'C:\Users')

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue

            # Skip system directories
            if user_dir.name.lower() in ['public', 'default', 'default user', 'all users']:
                continue

            user_path = mft_config.get('user_path', '')
            pattern = mft_config.get('pattern', None)
            files = mft_config.get('files', None)
            extensions = mft_config.get('extensions', None)  # [버그 수정] 확장자 필터 추가

            full_base_path = f"Users/{user_dir.name}/{user_path}"

            try:
                if pattern:
                    for result in self.mft_collector.collect_by_pattern(
                        full_base_path, pattern, artifact_type, include_deleted
                    ):
                        # [버그 수정] 확장자 필터 적용
                        if extensions:
                            file_name = result[0].lower()
                            if not any(file_name.endswith(ext.lower()) for ext in extensions):
                                continue  # 확장자 불일치 시 건너뛰기

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
                _debug_print(f"[MFT] Error collecting from {user_dir.name}: {e}")

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

        for path_pattern in artifact_info['paths']:
            for result in collector_method(path_pattern, artifact_dir, artifact_type):
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
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files matching a glob pattern with environment variable expansion (legacy)"""
        expanded_pattern = os.path.expandvars(pattern)
        for src_path in glob.glob(expanded_pattern, recursive=True):
            try:
                dst_path = output_dir / Path(src_path).name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(src_path, dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                _debug_print(f"[LEGACY] Cannot access {src_path}: {e}")
                continue

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
        """파일명에서 유효하지 않은 문자 제거"""
        import re
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
        Collect Android forensics artifacts via ADB.

        Args:
            artifact_type: Type of Android artifact
            artifact_info: Artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            **kwargs: device_serial for specific device
        """
        from collectors.android_collector import AndroidCollector

        device_serial = kwargs.get('device_serial')
        artifact_key = artifact_info.get('artifact_key', '')

        try:
            collector = AndroidCollector(device_serial, str(artifact_dir))

            # Map artifact_key to collector method
            method_map = {
                'sms': collector.collect_sms,
                'call': collector.collect_call_history,
                'contacts': collector.collect_contacts,
                'app': collector.collect_app_data,
                'wifi': collector.collect_wifi_settings,
                'location': collector.collect_location_data,
                'media': collector.collect_media_files,
            }

            if artifact_key not in method_map:
                _debug_print(f"[ANDROID] Unknown artifact key: {artifact_key}")
                return

            method = method_map[artifact_key]

            for result in method(progress_callback=progress_callback):
                file_path, file_metadata = result
                # Add standard fields
                file_metadata['artifact_type'] = artifact_type
                file_metadata['collection_method'] = 'adb'
                file_metadata['device_serial'] = device_serial or 'auto-detected'
                file_metadata['collected_at'] = datetime.utcnow().isoformat()
                yield file_path, file_metadata

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
            artifact_type: Type of iOS artifact
            artifact_info: Artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            **kwargs: backup_path for specific backup
        """
        from collectors.ios_collector import iOSCollector, find_ios_backups

        backup_path = kwargs.get('backup_path')
        artifact_key = artifact_info.get('artifact_key', '')

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
            collector = iOSCollector(backup_path, str(artifact_dir))

            # Check if backup is encrypted
            if collector.is_encrypted:
                _debug_print(f"[iOS] Backup is encrypted - cannot extract artifacts")
                _debug_print("[iOS] Please create an unencrypted backup or provide decryption key")
                return

            # Map artifact_key to collector method
            method_map = {
                'sms': collector.collect_sms,
                'call': collector.collect_call_history,
                'contacts': collector.collect_contacts,
                'app': collector.collect_app_data,
                'safari': collector.collect_safari_data,
                'location': collector.collect_location_data,
                'backup': collector.collect_backup_metadata,
            }

            if artifact_key not in method_map:
                _debug_print(f"[iOS] Unknown artifact key: {artifact_key}")
                return

            method = method_map[artifact_key]

            for result in method(progress_callback=progress_callback):
                file_path, file_metadata = result
                # Add standard fields
                file_metadata['artifact_type'] = artifact_type
                file_metadata['collection_method'] = 'ios_backup'
                file_metadata['backup_path'] = backup_path
                file_metadata['collected_at'] = datetime.utcnow().isoformat()
                yield file_path, file_metadata

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
        """Get path to file in latest Volume Shadow Copy"""
        try:
            import subprocess
            result = subprocess.run(
                ['vssadmin', 'list', 'shadows'],
                capture_output=True,
                text=True
            )

            # Parse VSS output to find latest shadow copy
            for line in result.stdout.split('\n'):
                if 'Shadow Copy Volume' in line:
                    vss_volume = line.split(':')[-1].strip()
                    drive = file_path[0]
                    relative_path = file_path[2:]  # Remove 'C:'
                    return f"{vss_volume}{relative_path}"

        except Exception:
            pass

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
    return 'legacy (no pytsk3)'


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
