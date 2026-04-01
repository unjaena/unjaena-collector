"""
Android Forensics Collector Module

Android device forensic collection module.
Supports real-time connection detection and artifact collection via direct USB connection.
Uses adb-shell[usb] library without external ADB binary dependency.

Collectible artifacts:
- mobile_android_sms: SMS/MMS messages
- mobile_android_call: Call history
- mobile_android_contacts: Contacts
- mobile_android_app: App data
- mobile_android_wifi: WiFi settings
- mobile_android_location: Location history
- mobile_android_media: Photos/Videos

Requirements:
    - adb-shell[usb]>=0.4.4
    - libusb1>=3.0.0
    - Windows: libusb-1.0.dll required
    - Linux: sudo apt-get install libusb-1.0-0
    - macOS: brew install libusb
"""
from __future__ import annotations

import os
import re
import json
import shutil
import subprocess
import sys
import threading
import time
import hashlib
import logging
import shlex
from pathlib import Path
from datetime import datetime
from typing import Generator, Tuple, Dict, Any, Optional, List, Callable
from dataclasses import dataclass

# USB direct connection imports
try:
    from adb_shell.adb_device import AdbDeviceUsb
    from adb_shell.auth.sign_pythonrsa import PythonRSASigner
    from adb_shell.auth.keygen import keygen
    from adb_shell.exceptions import (
        TcpTimeoutException,
        UsbReadFailedError,
        UsbWriteFailedError,
        DeviceAuthError,
    )
    import usb1
    USB_AVAILABLE = True
except ImportError as e:
    USB_AVAILABLE = False
    _import_error = str(e)

    # Provide stub types for type hints when libraries not available
    class AdbDeviceUsb:  # type: ignore
        pass

    class PythonRSASigner:  # type: ignore
        pass

    def keygen(path: str) -> None:  # type: ignore
        pass

    class TcpTimeoutException(Exception):  # type: ignore
        pass

    class UsbReadFailedError(Exception):  # type: ignore
        pass

    class UsbWriteFailedError(Exception):  # type: ignore
        pass

    class DeviceAuthError(Exception):  # type: ignore
        pass

    class usb1:  # type: ignore
        class USBContext:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def getDeviceIterator(self, **kwargs): return []
        class USBError(Exception):
            pass

logger = logging.getLogger(__name__)


# Android ADB USB interface identifiers
ADB_CLASS = 0xFF
ADB_SUBCLASS = 0x42
ADB_PROTOCOL = 0x01


def _debug_print(msg: str):
    """Debug print helper"""
    logger.debug(msg)


def _mask_serial(serial: str) -> str:
    """[SECURITY] Mask device serial for logging (show only last 8 chars)"""
    if not serial:
        return "(unknown)"
    if len(serial) <= 8:
        return serial
    return f"...{serial[-8:]}"


def check_usb_available() -> bool:
    """Check if USB libraries are available and libusb is accessible"""
    if not USB_AVAILABLE:
        return False
    try:
        with usb1.USBContext() as ctx:
            # Just test if we can create a context
            return True
    except Exception:
        return False


def check_adb_available() -> bool:
    """Check if ADB (USB or system) is available for Android device detection"""
    # USB direct connection via adb-shell library
    if USB_AVAILABLE:
        return True
    # Fallback: system adb binary
    try:
        result = subprocess.run(
            ['adb', 'version'], capture_output=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return False


# Module-level flag for device_enumerators.py and artifact_collector.py
ADB_AVAILABLE = check_adb_available()


def _create_adb_signer(key_path: Path) -> PythonRSASigner:
    """
    Create PythonRSASigner from ADB key files.

    Generates new keys if they don't exist.

    Note: PythonRSASigner constructor takes (pub, priv) - public key first!
    """
    if not key_path.exists():
        key_path.parent.mkdir(parents=True, exist_ok=True)
        keygen(str(key_path))
        _debug_print(f"[ADB Key] Generated new key at {key_path}")

    with open(key_path, 'rb') as f:
        priv_key = f.read()
    with open(f"{key_path}.pub", 'rb') as f:
        pub_key = f.read()

    # Note: PythonRSASigner(pub, priv) - public key is first parameter!
    return PythonRSASigner(pub_key, priv_key)


@dataclass
class DeviceInfo:
    """Android device information"""
    serial: str
    model: str
    manufacturer: str
    android_version: str
    sdk_version: int
    usb_debugging: bool
    security_patch: str = ''
    rooted: bool = False
    storage_available: int = 0
    vendor_id: int = 0
    product_id: int = 0


# Android artifact type definitions
ANDROID_ARTIFACT_TYPES = {
    # ==========================================================================
    # Content Provider (Non-Root)
    # ==========================================================================

    'mobile_android_sms_provider': {
        'name': 'SMS/MMS (Content Provider)',
        'description': 'Text messages via Content Provider (non-root)',
        'content_uri': 'content://sms',
        'requires_root': False,
        'collection_method': 'content_provider',
    },
    'mobile_android_call_provider': {
        'name': 'Call History (Content Provider)',
        'description': 'Call logs via Content Provider (non-root)',
        'content_uri': 'content://call_log/calls',
        'requires_root': False,
        'collection_method': 'content_provider',
    },
    'mobile_android_contacts_provider': {
        'name': 'Contacts (Content Provider)',
        'description': 'Contacts via Content Provider (non-root)',
        'content_uri': 'content://contacts/people',
        'requires_root': False,
        'collection_method': 'content_provider',
    },
    'mobile_android_calendar_provider': {
        'name': 'Calendar (Content Provider)',
        'description': 'Calendar events via Content Provider (non-root)',
        'content_uri': 'content://com.android.calendar/events',
        'requires_root': False,
        'collection_method': 'content_provider',
    },

    # ==========================================================================
    # System Information (Non-Root, 8 sub-types combined)
    # ==========================================================================

    'mobile_android_system_info': {
        'name': 'System Information',
        'description': 'System logs, packages, settings, usage, accounts, connectivity, bugreport',
        'collection_method': 'system_info',
        'requires_root': False,
        'forensic_value': 'high',
        'sub_types': {
            'logcat': {'name': 'System Logs'},
            'packages': {'name': 'Installed Apps'},
            'dumpsys': {
                'name': 'System Service Dumps',
                'services': ['battery', 'wifi', 'netpolicy', 'usagestats', 'activity'],
            },
            'settings': {'name': 'Device Settings'},
            'notifications': {'name': 'Notification History'},
            'accounts': {'name': 'Registered Accounts'},
            'app_usage': {'name': 'App Usage Statistics'},
            'connectivity': {'name': 'Network Connectivity'},
            'bugreport': {'name': 'System Bugreport'},
            'app_install_history': {'name': 'App Installation History'},
            'wifi_history': {'name': 'WiFi Connection History'},
            'bluetooth_history': {'name': 'Bluetooth Pairing History'},
        },
    },

    # ==========================================================================
    # Media Files (Non-Root)
    # ==========================================================================

    'mobile_android_media': {
        'name': 'Media Files',
        'description': 'Photos, videos, and audio files',
        'collection_method': 'sdcard',
        'requires_root': False,
        'nonroot': {
            'sdcard_paths': [
                '/sdcard/DCIM/',
                '/sdcard/Pictures/',
                '/sdcard/Download/',
                '/sdcard/Movies/',
                '/sdcard/Music/',
            ],
        },
    },

    # ==========================================================================
    # Root-Only System Artifacts
    # ==========================================================================

    'mobile_android_sms': {
        'name': 'SMS/MMS Database',
        'description': 'SMS database file (root required)',
        'collection_method': 'root_db',
        'requires_root': True,
        'root': {
            'db_paths': ['/data/data/com.android.providers.telephony/databases/mmssms.db'],
        },
    },
    'mobile_android_call': {
        'name': 'Call History Database',
        'description': 'Call log database (root required)',
        'collection_method': 'root_db',
        'requires_root': True,
        'root': {
            'db_paths': ['/data/data/com.android.providers.contacts/databases/contacts2.db'],
        },
    },
    'mobile_android_contacts': {
        'name': 'Contacts Database',
        'description': 'Contacts database file (root required)',
        'collection_method': 'root_db',
        'requires_root': True,
        'root': {
            'db_paths': ['/data/data/com.android.providers.contacts/databases/contacts2.db'],
        },
    },
    'mobile_android_app': {
        'name': 'App Data',
        'description': 'Installed applications data (root required)',
        'collection_method': 'root_db',
        'requires_root': True,
        'root': {
            'db_paths': ['/data/data/'],
        },
    },
    'mobile_android_wifi': {
        'name': 'WiFi Settings',
        'description': 'Saved WiFi networks (root required)',
        'collection_method': 'root_db',
        'requires_root': True,
        'root': {
            'db_paths': [
                '/data/misc/wifi/wpa_supplicant.conf',
                '/data/misc/wifi/WifiConfigStore.xml',
            ],
        },
    },
    'mobile_android_location': {
        'name': 'Location History',
        'description': 'GPS and location data (root required)',
        'collection_method': 'root_db',
        'requires_root': True,
        'root': {
            'db_paths': [
                '/data/data/com.google.android.gms/databases/herrevad*',
                '/data/data/com.google.android.gms/databases/location*',
            ],
        },
    },

    # ==========================================================================
    # Messenger Apps (Root/Non-Root Auto-Adaptive)
    # When root available: extract DB from /data/data/
    # When non-root: collect sdcard files + try run-as for debuggable apps
    # ==========================================================================

    'mobile_android_kakaotalk': {
        'name': 'KakaoTalk',
        'description': 'KakaoTalk message databases',
        'package': 'com.kakao.talk',
        'forensic_value': 'critical',
        'subcategory': 'app_messenger',
        'root': {
            'db_paths': [
                '/data/data/com.kakao.talk/databases/KakaoTalk.db',
                '/data/data/com.kakao.talk/databases/KakaoTalk2.db',
                '/data/data/com.kakao.talk/shared_prefs/KakaoTalk.perferences.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': [
                '/sdcard/KakaoTalk/',
                '/sdcard/KakaoTalkDownload/',
                '/sdcard/Android/data/com.kakao.talk/',
                '/sdcard/Pictures/KakaoTalk/',
            ],
            'run_as_paths': [
                'databases/KakaoTalk.db',
                'databases/KakaoTalk2.db',
                'shared_prefs/KakaoTalk.perferences.xml',
            ],
        },
    },
    'mobile_android_whatsapp': {
        'name': 'WhatsApp',
        'description': 'WhatsApp message databases',
        'package': 'com.whatsapp',
        'forensic_value': 'critical',
        'subcategory': 'app_messenger',
        'root': {
            'db_paths': [
                '/data/data/com.whatsapp/databases/msgstore.db',
                '/data/data/com.whatsapp/databases/wa.db',
                '/data/data/com.whatsapp/files/key',
                '/data/data/com.whatsapp/files/encrypted_backup.key',
            ],
        },
        'nonroot': {
            'sdcard_paths': [
                '/sdcard/WhatsApp/',
                '/sdcard/Android/media/com.whatsapp/',
                '/sdcard/Android/data/com.whatsapp/',
            ],
            'run_as_paths': [
                'databases/msgstore.db',
                'databases/wa.db',
                'files/key',
                'files/encrypted_backup.key',
            ],
        },
    },
    'mobile_android_telegram': {
        'name': 'Telegram',
        'description': 'Telegram messages (TDS serialized, not encrypted)',
        'package': 'org.telegram.messenger',
        'forensic_value': 'critical',
        'subcategory': 'app_messenger',
        'root': {
            'db_paths': [
                '/data/data/org.telegram.messenger/files/cache4.db',
                '/data/data/org.telegram.messenger/shared_prefs/userconfig.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': [
                '/sdcard/Telegram/',
                '/sdcard/Android/data/org.telegram.messenger/files/',
            ],
            'run_as_paths': [
                'files/cache4.db',
                'shared_prefs/userconfig.xml',
            ],
        },
    },
    'mobile_android_line': {
        'name': 'LINE',
        'description': 'LINE message databases',
        'package': 'jp.naver.line.android',
        'forensic_value': 'critical',
        'subcategory': 'app_messenger',
        'root': {
            'db_paths': [
                '/data/data/jp.naver.line.android/databases/naver_line',
                '/data/data/jp.naver.line.android/databases/call_history.db',
            ],
        },
        'nonroot': {
            'sdcard_paths': [
                '/sdcard/LINE/',
                '/sdcard/Android/data/jp.naver.line.android/',
                '/sdcard/Pictures/LINE/',
            ],
            'run_as_paths': [
                'databases/naver_line',
                'databases/call_history.db',
            ],
        },
    },
    'mobile_android_signal': {
        'name': 'Signal',
        'description': 'Signal message databases',
        'package': 'org.thoughtcrime.securesms',
        'forensic_value': 'critical',
        'subcategory': 'app_messenger',
        'root': {
            'db_paths': [
                '/data/data/org.thoughtcrime.securesms/databases/signal.db',
                '/data/data/org.thoughtcrime.securesms/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': [
                '/sdcard/Android/data/org.thoughtcrime.securesms/',
            ],
            'run_as_paths': [
                'databases/signal.db',
            ],
        },
    },
    'mobile_android_facebook_messenger': {
        'name': 'Facebook Messenger',
        'description': 'Facebook Messenger messages (unencrypted)',
        'package': 'com.facebook.orca',
        'forensic_value': 'critical',
        'subcategory': 'app_messenger',
        'root': {
            'db_paths': [
                '/data/data/com.facebook.orca/databases/threads_db2',
                '/data/data/com.facebook.orca/databases/contacts_db2',
            ],
        },
        'nonroot': {
            'sdcard_paths': [
                '/sdcard/Android/data/com.facebook.orca/',
            ],
            'run_as_paths': [
                'databases/threads_db2',
                'databases/contacts_db2',
            ],
        },
    },
    'mobile_android_wechat': {
        'name': 'WeChat',
        'description': 'WeChat message databases',
        'package': 'com.tencent.mm',
        'forensic_value': 'critical',
        'subcategory': 'app_messenger',
        'root': {
            'db_paths': [
                '/data/data/com.tencent.mm/MicroMsg/*/EnMicroMsg.db',
                '/data/data/com.tencent.mm/MicroMsg/*/WxFileIndex.db',
                '/data/data/com.tencent.mm/shared_prefs/auth_info_key_prefs.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': [
                '/sdcard/tencent/MicroMsg/',
                '/sdcard/Android/data/com.tencent.mm/',
            ],
            'run_as_paths': [
                'MicroMsg/*/EnMicroMsg.db',
                'shared_prefs/auth_info_key_prefs.xml',
            ],
        },
    },
    'mobile_android_discord': {
        'name': 'Discord',
        'description': 'Discord local cache (cloud-based, 200M+ MAU)',
        'package': 'com.discord',
        'forensic_value': 'medium',
        'subcategory': 'app_messenger',
        'root': {
            'db_paths': [
                '/data/data/com.discord/cache/',
                '/data/data/com.discord/files/',
                '/data/data/com.discord/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': [
                '/sdcard/Android/data/com.discord/',
            ],
            'run_as_paths': [
                'cache/',
                'files/',
            ],
        },
    },
    'mobile_android_viber': {
        'name': 'Viber',
        'description': 'Viber messages and calls (230M MAU)',
        'collection_method': 'root_db',
        'requires_root': True,
        'forensic_value': 'high',
        'subcategory': 'app_messenger',
        'root': {
            'db_paths': [
                '/data/data/com.viber.voip/databases/viber_data',
                '/data/data/com.viber.voip/databases/viber_messages',
            ],
        },
    },
    'mobile_android_band': {
        'name': 'BAND',
        'description': 'BAND media and downloads',
        'package': 'com.nhn.android.band',
        'collection_method': 'sdcard',
        'requires_root': False,
        'forensic_value': 'medium',
        'subcategory': 'app_messenger',
        'nonroot': {
            'sdcard_paths': [
                '/sdcard/Android/data/com.nhn.android.band/',
                '/sdcard/BAND/',
            ],
        },
    },

    # ==========================================================================
    # SNS Apps (Root-Only)
    # ==========================================================================

    'mobile_android_instagram': {
        'name': 'Instagram',
        'description': 'Instagram direct messages and profile data',
        'collection_method': 'root_db',
        'requires_root': True,
        'forensic_value': 'high',
        'subcategory': 'app_sns',
        'root': {
            'db_paths': [
                '/data/data/com.instagram.android/databases/direct.db',
                '/data/data/com.instagram.android/databases/*.db',
            ],
        },
    },
    'mobile_android_twitter': {
        'name': 'Twitter/X',
        'description': 'Twitter/X tweets, DMs, and profile data',
        'collection_method': 'root_db',
        'requires_root': True,
        'forensic_value': 'high',
        'subcategory': 'app_sns',
        'root': {
            'db_paths': [
                '/data/data/com.twitter.android/databases/*.db',
                '/data/data/com.twitter.android/cache/',
            ],
        },
    },
    'mobile_android_tiktok': {
        'name': 'TikTok',
        'description': 'TikTok videos metadata, messages, and profile',
        'collection_method': 'root_db',
        'requires_root': True,
        'forensic_value': 'high',
        'subcategory': 'app_sns',
        'root': {
            'db_paths': [
                '/data/data/com.zhiliaoapp.musically/databases/*.db',
                '/data/data/com.ss.android.ugc.trill/databases/*.db',
            ],
        },
    },
    'mobile_android_snapchat': {
        'name': 'Snapchat',
        'description': 'Snapchat messages and friend list',
        'collection_method': 'root_db',
        'requires_root': True,
        'forensic_value': 'high',
        'subcategory': 'app_sns',
        'root': {
            'db_paths': [
                '/data/data/com.snapchat.android/databases/arroyo.db',
                '/data/data/com.snapchat.android/databases/main.db',
            ],
        },
    },
    'mobile_android_facebook': {
        'name': 'Facebook',
        'description': 'Facebook posts, profile, timeline (3.05B MAU)',
        'collection_method': 'root_db',
        'requires_root': True,
        'forensic_value': 'high',
        'subcategory': 'app_sns',
        'root': {
            'db_paths': [
                '/data/data/com.facebook.katana/databases/*.db',
                '/data/data/com.facebook.katana/shared_prefs/*.xml',
            ],
        },
    },
    'mobile_android_reddit': {
        'name': 'Reddit',
        'description': 'Reddit posts, comments, DMs (1.1B MAU)',
        'collection_method': 'root_db',
        'requires_root': True,
        'forensic_value': 'high',
        'subcategory': 'app_sns',
        'root': {
            'db_paths': [
                '/data/data/com.reddit.frontpage/databases/*.db',
                '/data/data/com.reddit.frontpage/shared_prefs/*.xml',
            ],
        },
    },
    'mobile_android_pinterest': {
        'name': 'Pinterest',
        'description': 'Pinterest pins, boards, messages (553M MAU)',
        'collection_method': 'root_db',
        'requires_root': True,
        'forensic_value': 'medium',
        'subcategory': 'app_sns',
        'root': {
            'db_paths': [
                '/data/data/com.pinterest/databases/*.db',
                '/data/data/com.pinterest/cache/',
            ],
        },
    },
    'mobile_android_linkedin': {
        'name': 'LinkedIn',
        'description': 'LinkedIn connections, messages (386M MAU)',
        'collection_method': 'root_db',
        'requires_root': True,
        'forensic_value': 'high',
        'subcategory': 'app_sns',
        'root': {
            'db_paths': [
                '/data/data/com.linkedin.android/databases/*.db',
                '/data/data/com.linkedin.android/shared_prefs/*.xml',
            ],
        },
    },
    'mobile_android_threads': {
        'name': 'Threads',
        'description': 'Threads posts, replies (320M MAU, Meta)',
        'collection_method': 'root_db',
        'requires_root': True,
        'forensic_value': 'high',
        'subcategory': 'app_sns',
        'root': {
            'db_paths': [
                '/data/data/com.instagram.barcelona/databases/*.db',
                '/data/data/com.instagram.barcelona/shared_prefs/*.xml',
            ],
        },
    },

    # ==========================================================================
    # Korean Shopping Apps (Root/Non-Root Auto-Adaptive)
    # ==========================================================================

    'mobile_android_baemin': {
        'name': 'Baemin',
        'description': 'Baemin order history, payment info, delivery addresses',
        'package': 'com.spr.baemin',
        'forensic_value': 'high',
        'subcategory': 'app_korean',
        'root': {
            'db_paths': [
                '/data/data/com.spr.baemin/databases/*.db',
                '/data/data/com.spr.baemin/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.spr.baemin/'],
        },
    },
    'mobile_android_coupang': {
        'name': 'Coupang',
        'description': 'Coupang purchase history, payment info, delivery addresses',
        'package': 'com.coupang.mobile',
        'forensic_value': 'high',
        'subcategory': 'app_korean',
        'root': {
            'db_paths': [
                '/data/data/com.coupang.mobile/databases/*.db',
                '/data/data/com.coupang.mobile/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.coupang.mobile/'],
        },
    },
    'mobile_android_karrot': {
        'name': 'Karrot',
        'description': 'Karrot chat history, transaction records, location data',
        'package': 'com.towneers.www',
        'forensic_value': 'high',
        'subcategory': 'app_korean',
        'root': {
            'db_paths': [
                '/data/data/com.towneers.www/databases/*.db',
                '/data/data/com.towneers.www/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.towneers.www/'],
        },
    },
    'mobile_android_coupangeats': {
        'name': 'Coupang Eats',
        'description': 'Coupang Eats order history, payment info, delivery addresses',
        'package': 'com.coupang.coupangeats',
        'forensic_value': 'high',
        'subcategory': 'app_korean',
        'root': {
            'db_paths': [
                '/data/data/com.coupang.coupangeats/databases/*.db',
                '/data/data/com.coupang.coupangeats/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.coupang.coupangeats/'],
        },
    },
    'mobile_android_yanolja': {
        'name': 'Yanolja',
        'description': 'Yanolja booking history, payment info, location data',
        'package': 'com.yanolja.motel',
        'forensic_value': 'high',
        'subcategory': 'app_korean',
        'root': {
            'db_paths': [
                '/data/data/com.yanolja.motel/databases/*.db',
                '/data/data/com.yanolja.motel/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.yanolja.motel/'],
        },
    },

    # ==========================================================================
    # Korean Financial Apps (Root/Non-Root Auto-Adaptive)
    # ==========================================================================

    'mobile_android_kakaobank': {
        'name': 'KakaoBank',
        'description': 'KakaoBank transaction history, account info, transfer records',
        'package': 'com.kakaobank.channel',
        'forensic_value': 'critical',
        'subcategory': 'app_korean',
        'root': {
            'db_paths': [
                '/data/data/com.kakaobank.channel/databases/*.db',
                '/data/data/com.kakaobank.channel/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.kakaobank.channel/'],
        },
    },
    'mobile_android_toss': {
        'name': 'Toss',
        'description': 'Toss transfer history, payment records, account info',
        'package': 'viva.republica.toss',
        'forensic_value': 'critical',
        'subcategory': 'app_korean',
        'root': {
            'db_paths': [
                '/data/data/viva.republica.toss/databases/*.db',
                '/data/data/viva.republica.toss/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/viva.republica.toss/'],
        },
    },
    'mobile_android_upbit': {
        'name': 'Upbit',
        'description': 'Upbit cryptocurrency trading history, wallet info',
        'package': 'com.dunamu.exchange',
        'forensic_value': 'critical',
        'subcategory': 'app_korean',
        'root': {
            'db_paths': [
                '/data/data/com.dunamu.exchange/databases/*.db',
                '/data/data/com.dunamu.exchange/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.dunamu.exchange/'],
        },
    },
    'mobile_android_banksalad': {
        'name': 'BankSalad',
        'description': 'BankSalad aggregated financial data, asset summary',
        'package': 'com.rainist.banksalad',
        'forensic_value': 'high',
        'subcategory': 'app_korean',
        'root': {
            'db_paths': [
                '/data/data/com.rainist.banksalad/databases/*.db',
                '/data/data/com.rainist.banksalad/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.rainist.banksalad/'],
        },
    },
    'mobile_android_kakaopay': {
        'name': 'KakaoPay',
        'description': 'KakaoPay payment history, transfer records',
        'package': 'com.kakaopay.app',
        'forensic_value': 'high',
        'subcategory': 'app_korean',
        'root': {
            'db_paths': [
                '/data/data/com.kakaopay.app/databases/*.db',
                '/data/data/com.kakaopay.app/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.kakaopay.app/'],
        },
    },

    # ==========================================================================
    # Korean Navigation Apps (Root/Non-Root Auto-Adaptive)
    # ==========================================================================

    'mobile_android_tmap': {
        'name': 'TMAP',
        'description': 'TMAP navigation history, route records, location data',
        'package': 'com.skt.tmap.ku',
        'forensic_value': 'high',
        'subcategory': 'app_korean',
        'root': {
            'db_paths': [
                '/data/data/com.skt.tmap.ku/databases/*.db',
                '/data/data/com.skt.tmap.ku/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.skt.tmap.ku/'],
        },
    },
    'mobile_android_kakaomap': {
        'name': 'KakaoMap',
        'description': 'KakaoMap search history, bookmarks, route records',
        'package': 'net.daum.android.map',
        'forensic_value': 'high',
        'subcategory': 'app_korean',
        'root': {
            'db_paths': [
                '/data/data/net.daum.android.map/databases/*.db',
                '/data/data/net.daum.android.map/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/net.daum.android.map/'],
        },
    },
    'mobile_android_navermap': {
        'name': 'Naver Map',
        'description': 'Naver Map search history, bookmarks, route records',
        'package': 'com.nhn.android.nmap',
        'forensic_value': 'high',
        'subcategory': 'app_korean',
        'root': {
            'db_paths': [
                '/data/data/com.nhn.android.nmap/databases/*.db',
                '/data/data/com.nhn.android.nmap/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.nhn.android.nmap/'],
        },
    },
    'mobile_android_kakaotaxi': {
        'name': 'Kakao T',
        'description': 'Kakao T ride history, pickup/dropoff locations, payment records',
        'package': 'com.kakao.taxi',
        'forensic_value': 'high',
        'subcategory': 'app_korean',
        'root': {
            'db_paths': [
                '/data/data/com.kakao.taxi/databases/*.db',
                '/data/data/com.kakao.taxi/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.kakao.taxi/'],
        },
    },

    # ==========================================================================
    # Korean Business Apps (Root/Non-Root Auto-Adaptive)
    # ==========================================================================

    'mobile_android_hiworks': {
        'name': 'Hiworks',
        'description': 'Hiworks email, calendar, attendance records',
        'package': 'kr.co.gabia.hiworks',
        'forensic_value': 'high',
        'subcategory': 'app_korean',
        'root': {
            'db_paths': [
                '/data/data/kr.co.gabia.hiworks/databases/*.db',
                '/data/data/kr.co.gabia.hiworks/shared_prefs/*.xml',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/kr.co.gabia.hiworks/'],
        },
    },

    # ==========================================================================
    # Email Apps (Root/Non-Root Auto-Adaptive)
    # ==========================================================================

    'mobile_android_gmail': {
        'name': 'Gmail',
        'description': 'Gmail email databases, contacts, attachments',
        'package': 'com.google.android.gm',
        'forensic_value': 'critical',
        'subcategory': 'app_email_browser',
        'root': {
            'db_paths': [
                '/data/data/com.google.android.gm/databases/EmailProvider.db',
                '/data/data/com.google.android.gm/databases/mailstore.*.db',
                '/data/data/com.google.android.gm/databases/EmailProviderBody.db',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.google.android.gm/'],
        },
    },
    'mobile_android_samsung_email': {
        'name': 'Samsung Email',
        'description': 'Samsung Email databases, contacts, attachments',
        'package': 'com.samsung.android.email.provider',
        'forensic_value': 'critical',
        'subcategory': 'app_email_browser',
        'root': {
            'db_paths': [
                '/data/data/com.samsung.android.email.provider/databases/*.db',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.samsung.android.email.provider/'],
        },
    },

    # ==========================================================================
    # Browser Apps (Root/Non-Root Auto-Adaptive)
    # ==========================================================================

    'mobile_android_chrome': {
        'name': 'Chrome',
        'description': 'Chrome browsing history, cookies, saved passwords, downloads',
        'package': 'com.android.chrome',
        'forensic_value': 'critical',
        'subcategory': 'app_email_browser',
        'root': {
            'db_paths': [
                '/data/data/com.android.chrome/app_chrome/Default/History',
                '/data/data/com.android.chrome/app_chrome/Default/Cookies',
                '/data/data/com.android.chrome/app_chrome/Default/Login Data',
                '/data/data/com.android.chrome/app_chrome/Default/Web Data',
                '/data/data/com.android.chrome/app_chrome/Default/Bookmarks',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.android.chrome/'],
        },
    },
    'mobile_android_samsung_browser': {
        'name': 'Samsung Browser',
        'description': 'Samsung Browser history, bookmarks, saved passwords',
        'package': 'com.sec.android.app.sbrowser',
        'forensic_value': 'critical',
        'subcategory': 'app_email_browser',
        'root': {
            'db_paths': [
                '/data/data/com.sec.android.app.sbrowser/databases/*.db',
                '/data/data/com.sec.android.app.sbrowser/app_sbrowser/Default/History',
                '/data/data/com.sec.android.app.sbrowser/app_sbrowser/Default/Cookies',
            ],
        },
        'nonroot': {
            'sdcard_paths': ['/sdcard/Android/data/com.sec.android.app.sbrowser/'],
        },
    },

    # ==========================================================================
    # Screen Scraping (Non-Root Accessibility Service)
    # Agent APK uses Accessibility Service to auto-scrape app screens
    # ==========================================================================

    'mobile_android_screen_scrape': {
        'name': 'Screen Scraping',
        'description': 'App screen data via Accessibility Service Agent APK (non-root)',
        'requires_root': False,
        'collection_method': 'screen_scrape',
        'forensic_value': 'critical',
    },
}


class ADBDeviceMonitor:
    """
    Real-time Android device connection detection (USB direct connection)

    Monitors USB cable connections in the background and
    delivers connect/disconnect events via callbacks.
    Detects USB devices directly through libusb without external ADB binary.
    """

    def __init__(
        self,
        on_connect: Optional[Callable[[DeviceInfo], None]] = None,
        on_disconnect: Optional[Callable[[str], None]] = None
    ):
        """
        Initialize device monitor.

        Args:
            on_connect: Callback when device connects
            on_disconnect: Callback when device disconnects (receives serial)
        """
        self.on_connect = on_connect
        self.on_disconnect = on_disconnect

        self._monitoring = False
        self._thread: Optional[threading.Thread] = None
        self._known_devices: Dict[str, DeviceInfo] = {}
        self._stop_event = threading.Event()
        self._adb_key_path = Path.home() / ".android" / "adbkey"
        self._signer: Optional[PythonRSASigner] = None

    def _get_or_create_adb_key(self) -> PythonRSASigner:
        """Generate or load ADB RSA key"""
        if self._signer is not None:
            return self._signer

        self._signer = _create_adb_signer(self._adb_key_path)
        return self._signer

    def start_monitoring(self, poll_interval: float = 1.0):
        """
        Start background device monitoring.

        Args:
            poll_interval: Seconds between device checks
        """
        if self._monitoring:
            return

        if not USB_AVAILABLE:
            raise RuntimeError("USB libraries not available. Install adb-shell[usb] and libusb1.")

        self._monitoring = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            args=(poll_interval,),
            daemon=True
        )
        self._thread.start()

    def stop_monitoring(self):
        """Stop device monitoring"""
        self._monitoring = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _monitor_loop(self, poll_interval: float):
        """Background monitoring loop"""
        while self._monitoring and not self._stop_event.is_set():
            try:
                current_devices = self._enumerate_usb_devices()
                current_serials = set(d['serial'] for d in current_devices if d.get('serial'))
                known_serials = set(self._known_devices.keys())

                # Check for new devices
                for device_dict in current_devices:
                    serial = device_dict.get('serial')
                    if serial and serial not in known_serials:
                        device_info = self._get_device_info_usb(device_dict)
                        if device_info:
                            self._known_devices[serial] = device_info
                            if self.on_connect:
                                self.on_connect(device_info)

                # Check for disconnected devices
                for serial in known_serials - current_serials:
                    del self._known_devices[serial]
                    if self.on_disconnect:
                        self.on_disconnect(serial)

            except Exception as e:
                _debug_print(f"[ADB Monitor] Error: {e}")

            self._stop_event.wait(poll_interval)

    def _enumerate_usb_devices(self) -> List[Dict[str, Any]]:
        """
        Return list of USB-connected Android devices (using libusb)

        Android ADB interface: class=0xFF, subclass=0x42, protocol=0x01
        """
        devices = []

        if not USB_AVAILABLE:
            return devices

        try:
            with usb1.USBContext() as ctx:
                for usb_device in ctx.getDeviceIterator(skip_on_error=True):
                    try:
                        # Check each configuration and interface for ADB
                        for config in usb_device:
                            for interface in config:
                                for setting in interface:
                                    if (setting.getClass() == ADB_CLASS and
                                        setting.getSubClass() == ADB_SUBCLASS and
                                        setting.getProtocol() == ADB_PROTOCOL):

                                        try:
                                            serial = usb_device.getSerialNumber()
                                        except Exception:
                                            serial = f"{usb_device.getVendorID():04x}:{usb_device.getProductID():04x}"

                                        try:
                                            manufacturer = usb_device.getManufacturer()
                                        except Exception:
                                            manufacturer = "Unknown"

                                        try:
                                            product = usb_device.getProduct()
                                        except Exception:
                                            product = "Unknown"

                                        devices.append({
                                            'serial': serial,
                                            'vendor_id': usb_device.getVendorID(),
                                            'product_id': usb_device.getProductID(),
                                            'manufacturer': manufacturer,
                                            'product': product,
                                        })
                                        break
                    except usb1.USBError:
                        continue

        except Exception as e:
            _debug_print(f"[USB Enumerate] Error: {e}")

        return devices

    def _connect_device_usb(self, serial: str = None) -> Optional[AdbDeviceUsb]:
        """
        Connect to Android device via USB

        Args:
            serial: Specific device serial (first device if None)

        Returns:
            AdbDeviceUsb instance or None
        """
        if not USB_AVAILABLE:
            return None

        try:
            signer = self._get_or_create_adb_key()
            device = AdbDeviceUsb(serial=serial)
            device.connect(rsa_keys=[signer], auth_timeout_s=30.0)
            return device
        except DeviceAuthError:
            _debug_print(f"[USB Connect] Auth failed for {_mask_serial(serial)}. Please accept USB debugging on device.")
            return None
        except Exception as e:
            _debug_print(f"[USB Connect] Error connecting to {_mask_serial(serial)}: {e}")
            return None

    def _get_device_info_usb(self, device_dict: Dict[str, Any]) -> Optional[DeviceInfo]:
        """Get detailed device information via USB connection"""
        serial = device_dict.get('serial')
        if not serial:
            return None

        device = None
        try:
            device = self._connect_device_usb(serial)
            if not device:
                # Return basic info even without full connection
                return DeviceInfo(
                    serial=serial,
                    model=device_dict.get('product', 'Unknown'),
                    manufacturer=device_dict.get('manufacturer', 'Unknown'),
                    android_version='Unknown',
                    sdk_version=0,
                    usb_debugging=False,  # Couldn't connect - auth pending
                    rooted=False,
                    vendor_id=device_dict.get('vendor_id', 0),
                    product_id=device_dict.get('product_id', 0),
                )

            def shell_cmd(cmd: str) -> str:
                try:
                    result = device.shell(cmd, timeout_s=10)
                    return result.strip() if result else ''
                except Exception:
                    return ''

            model = shell_cmd('getprop ro.product.model')
            manufacturer = shell_cmd('getprop ro.product.manufacturer')
            android_version = shell_cmd('getprop ro.build.version.release')
            sdk_str = shell_cmd('getprop ro.build.version.sdk')
            sdk_version = int(sdk_str) if sdk_str.isdigit() else 0
            security_patch = shell_cmd('getprop ro.build.version.security_patch')

            # Check root status
            root_check = shell_cmd('which su')
            rooted = bool(root_check and 'su' in root_check)

            return DeviceInfo(
                serial=serial,
                model=model or device_dict.get('product', 'Unknown'),
                manufacturer=manufacturer or device_dict.get('manufacturer', 'Unknown'),
                android_version=android_version or 'Unknown',
                sdk_version=sdk_version,
                security_patch=security_patch or '',
                usb_debugging=True,  # Successfully connected
                rooted=rooted,
                vendor_id=device_dict.get('vendor_id', 0),
                product_id=device_dict.get('product_id', 0),
            )

        except Exception as e:
            _debug_print(f"[Device Info] Error getting info for {_mask_serial(serial)}: {e}")
            return None
        finally:
            if device:
                try:
                    device.close()
                except Exception:
                    pass

    def get_connected_devices(self) -> List[DeviceInfo]:
        """Get list of currently connected devices via USB (libusb) or system adb fallback"""
        devices = []

        # Method 1: USB direct connection via libusb
        for device_dict in self._enumerate_usb_devices():
            device_info = self._get_device_info_usb(device_dict)
            if device_info:
                devices.append(device_info)

        # Method 2: System adb fallback or enrichment
        # If libusb found devices but couldn't get details (model=Unknown),
        # or if libusb found nothing, try system adb
        needs_fallback = (
            not devices or
            any(d.model == 'Unknown' and d.android_version == 'Unknown' for d in devices)
        )
        if needs_fallback:
            system_devices = self._enumerate_system_adb()
            if system_devices:
                if not devices:
                    # No libusb devices, use system adb entirely
                    devices = system_devices
                else:
                    # Enrich libusb devices with system adb info
                    # Replace incomplete entries with matching system adb data
                    enriched = []
                    system_serials = {d.serial: d for d in system_devices}
                    for dev in devices:
                        if dev.model == 'Unknown' and dev.android_version == 'Unknown':
                            # Find matching system adb device by serial
                            replacement = system_serials.get(dev.serial)
                            if replacement:
                                enriched.append(replacement)
                                continue
                        enriched.append(dev)
                    devices = enriched

        return devices

    def _enumerate_system_adb(self) -> List[DeviceInfo]:
        """Fallback: enumerate devices using system adb binary"""
        devices = []
        adb_paths = ['adb']

        # Try common adb locations on Windows
        if os.name == 'nt':
            common_paths = [
                Path(os.environ.get('LOCALAPPDATA', '')) / 'Android' / 'Sdk' / 'platform-tools' / 'adb.exe',
                Path('C:/Program Files/ASUS/GlideX/adb.exe'),
                Path('C:/Program Files (x86)/ASUS/GlideX/adb.exe'),
            ]
            for p in common_paths:
                if p.exists():
                    adb_paths.insert(0, str(p))

        for adb_cmd in adb_paths:
            try:
                result = subprocess.run(
                    [adb_cmd, 'devices', '-l'],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0,
                )
                if result.returncode != 0:
                    continue

                for line in result.stdout.strip().split('\n')[1:]:
                    line = line.strip()
                    if not line or 'offline' in line or 'unauthorized' in line:
                        continue

                    parts = line.split()
                    if len(parts) < 2 or parts[1] != 'device':
                        continue

                    serial = parts[0]
                    # Parse key:value pairs
                    props = {}
                    for part in parts[2:]:
                        if ':' in part:
                            k, v = part.split(':', 1)
                            props[k] = v

                    # Get detailed info via adb shell
                    device_info = self._get_device_info_system_adb(
                        adb_cmd, serial, props
                    )
                    if device_info:
                        devices.append(device_info)

                if devices:
                    _debug_print(f"[ADB Fallback] Found {len(devices)} device(s) via system adb: {adb_cmd}")
                    break

            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
            except Exception as e:
                _debug_print(f"[ADB Fallback] Error with {adb_cmd}: {e}")
                continue

        return devices

    def _get_device_info_system_adb(
        self, adb_cmd: str, serial: str, props: Dict[str, str]
    ) -> Optional[DeviceInfo]:
        """Get device info using system adb shell commands"""
        try:
            def adb_shell(cmd: str) -> str:
                try:
                    result = subprocess.run(
                        [adb_cmd, '-s', serial, 'shell', cmd],
                        capture_output=True, text=True, timeout=10,
                        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0,
                    )
                    return result.stdout.strip() if result.returncode == 0 else ''
                except (subprocess.TimeoutExpired, Exception):
                    return ''

            model = adb_shell('getprop ro.product.model') or props.get('model', 'Unknown')
            manufacturer = adb_shell('getprop ro.product.manufacturer') or 'Unknown'
            android_version = adb_shell('getprop ro.build.version.release') or 'Unknown'
            sdk_str = adb_shell('getprop ro.build.version.sdk')
            sdk_version = int(sdk_str) if sdk_str.isdigit() else 0

            root_check = adb_shell('which su')
            rooted = bool(root_check and 'su' in root_check)

            return DeviceInfo(
                serial=serial,
                model=model,
                manufacturer=manufacturer,
                android_version=android_version,
                sdk_version=sdk_version,
                usb_debugging=True,
                rooted=rooted,
            )
        except Exception as e:
            _debug_print(f"[ADB Fallback] Error getting info for {_mask_serial(serial)}: {e}")
            return None

    def wait_for_device(
        self,
        timeout: Optional[float] = None
    ) -> Optional[DeviceInfo]:
        """
        Wait for a device to connect.

        Args:
            timeout: Maximum seconds to wait (None for infinite)

        Returns:
            DeviceInfo if device connected, None if timeout
        """
        start_time = time.time()

        while True:
            devices = self.get_connected_devices()
            if devices:
                return devices[0]

            if timeout and (time.time() - start_time) > timeout:
                return None

            time.sleep(1.0)


# =============================================================================
# Security Validation Functions
# =============================================================================

# Whitelist of allowed content URIs (immutable)
ALLOWED_CONTENT_URIS = frozenset([
    'content://sms',
    'content://call_log/calls',
    'content://contacts/people',
    'content://com.android.calendar/events',
])

# Whitelist of allowed dumpsys services (immutable)
ALLOWED_DUMPSYS_SERVICES = frozenset([
    'battery', 'wifi', 'netpolicy', 'usagestats', 'activity',
    'package', 'meminfo', 'cpuinfo', 'procstats', 'diskstats',
    'telecom',           # call log fallback (Android 10+ restricts READ_CALL_LOG)
    'bluetooth_manager',  # BT pairing history, connected devices
    'connectivity',       # Network connection states
    'deviceidle',         # Doze mode history (usage patterns)
    'notification',       # Notification history (message previews)
    'input',              # Input device info
    'mount',              # Storage mount points
    'alarm',              # Scheduled alarms (app behavior)
    'jobscheduler',       # Background job history
    'accessibility',      # Accessibility services state
    'content',            # Content provider registry
])

# Whitelist of allowed settings namespaces (immutable)
ALLOWED_SETTINGS_NAMESPACES = frozenset(['secure', 'system', 'global'])


def validate_content_uri(uri: str) -> bool:
    """Validate content URI against whitelist to prevent command injection."""
    if not uri:
        return False
    # Must be in whitelist
    if uri not in ALLOWED_CONTENT_URIS:
        logging.warning(f"[SECURITY] Blocked unauthorized content URI: {uri}")
        return False
    return True


def validate_dumpsys_service(service: str) -> bool:
    """Validate dumpsys service name against whitelist to prevent command injection."""
    if not service:
        return False
    # Must be alphanumeric (no special chars)
    if not re.match(r'^[a-zA-Z0-9_]+$', service):
        logging.warning(f"[SECURITY] Blocked invalid service name: {service}")
        return False
    # Must be in whitelist
    if service not in ALLOWED_DUMPSYS_SERVICES:
        logging.warning(f"[SECURITY] Blocked unauthorized service: {service}")
        return False
    return True


def validate_settings_namespace(namespace: str) -> bool:
    """Validate settings namespace against whitelist to prevent command injection."""
    return namespace in ALLOWED_SETTINGS_NAMESPACES


def _load_advanced_plugin():
    """Load optional pro plugin for advanced collection methods.

    Returns plugin instance if installed, None otherwise.
    The pro plugin provides additional extraction methods for licensed forensic use.
    Install separately: pip install unjaena-collector-pro
    """
    try:
        from unjaena_collector_pro import AdvancedPlugin
        return AdvancedPlugin()
    except ImportError:
        return None


class AndroidCollector:
    """
    Android forensic collection unified class

    Performs Android device artifact collection via direct USB connection.
    Uses adb-shell[usb] library without external ADB binary.
    """

    # Maximum retries for USB connection errors
    MAX_RETRIES = 3

    def __init__(self, output_dir: str, device_serial: Optional[str] = None):
        """
        Initialize Android collector.

        Args:
            output_dir: Directory to store collected artifacts
            device_serial: Optional specific device serial (auto-detect if None)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.device_serial = device_serial
        self.device_info: Optional[DeviceInfo] = None
        self.monitor = ADBDeviceMonitor()

        # Active USB device connection
        self._device: Optional[AdbDeviceUsb] = None
        self._adb_key_path = Path.home() / ".android" / "adbkey"
        self._signer: Optional[PythonRSASigner] = None

    def _get_or_create_adb_key(self) -> PythonRSASigner:
        """Generate or load ADB RSA key"""
        if self._signer is not None:
            return self._signer

        self._signer = _create_adb_signer(self._adb_key_path)
        return self._signer

    def _connect_device_usb(self, serial: str = None) -> AdbDeviceUsb:
        """
        Connect to Android device via USB

        Args:
            serial: Specific device serial

        Returns:
            AdbDeviceUsb instance

        Raises:
            RuntimeError: On connection failure
        """
        if not USB_AVAILABLE:
            raise RuntimeError("USB libraries not available. Install adb-shell[usb] and libusb1.")

        signer = self._get_or_create_adb_key()

        try:
            device = AdbDeviceUsb(serial=serial)
            device.connect(rsa_keys=[signer], auth_timeout_s=30.0)
            return device
        except DeviceAuthError:
            raise RuntimeError(f"Auth failed for {serial}. Please accept USB debugging on device.")
        except Exception as e:
            raise RuntimeError(f"libusb: {e}")

    def _ensure_connection(self) -> Optional[AdbDeviceUsb]:
        """
        Verify device connection and reconnect if necessary.

        Returns None in system-adb-fallback mode (callers should
        handle None by falling back to _run_system_adb).

        Returns:
            Active AdbDeviceUsb connection, or None in system adb mode
        """
        if self._device is not None:
            try:
                # Test if connection is still alive
                self._device.shell('echo test', timeout_s=5)
                return self._device
            except Exception:
                # Connection lost, need to reconnect
                try:
                    self._device.close()
                except Exception:
                    pass
                self._device = None

        if not self.device_serial:
            raise RuntimeError("No device serial set. Call connect() first.")

        # Try libusb reconnect
        try:
            self._device = self._connect_device_usb(self.device_serial)
        except RuntimeError:
            # System adb fallback mode — return None
            self._device = None

        return self._device

    def is_available(self) -> Dict[str, Any]:
        """Check availability of Android forensics"""
        usb_available = check_usb_available()
        devices = self.monitor.get_connected_devices() if usb_available else []

        return {
            'usb': usb_available,
            'adb': usb_available,  # Backward compatibility
            'device_connected': len(devices) > 0,
            'devices': [
                {
                    'serial': d.serial,
                    'model': d.model,
                    'android_version': d.android_version,
                    'rooted': d.rooted,
                    'usb_debugging': d.usb_debugging,
                }
                for d in devices
            ],
        }

    def connect(self, serial: Optional[str] = None) -> bool:
        """
        Connect to an Android device via USB.

        Tries libusb direct connection first. If that fails (e.g., driver
        incompatibility on Windows), falls back to system adb mode where
        _shell_cmd() and _pull_file() use subprocess calls to adb.exe.

        Args:
            serial: Device serial (uses first available if None)

        Returns:
            True if connected successfully
        """
        # Try libusb direct connection first
        if USB_AVAILABLE:
            try:
                devices = self.monitor.get_connected_devices()
                if serial:
                    matching = [d for d in devices if d.serial == serial]
                    if matching:
                        self.device_info = matching[0]
                elif devices:
                    self.device_info = devices[0]

                if self.device_info:
                    self.device_serial = self.device_info.serial
                    try:
                        self._device = self._connect_device_usb(self.device_serial)
                        logger.info(f"[Android] Connected via libusb: {_mask_serial(self.device_serial)}")
                        return True
                    except RuntimeError as e:
                        logger.warning(f"[Android] libusb connection failed: {e}")
                else:
                    logger.info(f"[Android] Device not found via libusb, trying system adb")
            except Exception as e:
                logger.warning(f"[Android] libusb enumeration failed: {e}")

        # Use provided serial for system adb fallback
        if serial:
            self.device_serial = serial

        if not self.device_serial:
            raise RuntimeError("No Android device connected via USB and no serial specified")

        # Fallback: system adb mode
        adb_path = self._find_system_adb()
        if not adb_path:
            raise RuntimeError(
                f"Cannot connect to {self.device_serial}. "
                f"libusb driver not compatible and system adb not found. "
                f"Install Android SDK Platform-Tools (adb.exe)."
            )

        # Check device status via system adb
        try:
            result = subprocess.run(
                [adb_path, 'devices'],
                capture_output=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            devices_output = result.stdout.decode('utf-8', errors='replace')
            # Parse "serial\tstatus" lines
            for line in devices_output.strip().splitlines():
                parts = line.split('\t')
                if len(parts) == 2 and self.device_serial in parts[0]:
                    status = parts[1].strip()
                    if status == 'unauthorized':
                        raise RuntimeError(
                            f"Device {self.device_serial} is unauthorized. "
                            f"Please check the device screen and tap 'Allow' on the "
                            f"'Allow USB debugging?' dialog."
                        )
                    elif status == 'offline':
                        raise RuntimeError(
                            f"Device {self.device_serial} is offline. "
                            f"Please reconnect the USB cable."
                        )
        except RuntimeError:
            raise
        except Exception as e2:
            logger.warning(f"[Android] adb devices check failed: {e2}")

        # Verify actual shell access
        try:
            result = subprocess.run(
                [adb_path, '-s', self.device_serial, 'shell', 'echo', 'ok'],
                capture_output=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            if result.returncode == 0 and b'ok' in result.stdout:
                self._device = None  # No libusb device, use system adb fallback
                self._system_adb_path = adb_path

                # Populate device_info if not set (libusb enumeration may have skipped it)
                if not self.device_info:
                    self.device_info = self._build_device_info_from_adb(adb_path)

                logger.info(
                    f"[Android] Connected via system adb fallback: {_mask_serial(self.device_serial)} "
                    f"(adb={adb_path})"
                )
                return True
        except Exception as e2:
            logger.warning(f"[Android] System adb shell test failed: {e2}")

        raise RuntimeError(
            f"Cannot connect to {self.device_serial}. "
            f"libusb driver not compatible and system adb connection failed. "
            f"Check USB debugging is enabled and authorized on the device."
        )

    def _build_device_info_from_adb(self, adb_path: str) -> DeviceInfo:
        """Build DeviceInfo from system adb getprop (fallback when libusb unavailable)"""
        def _getprop(key: str) -> str:
            try:
                r = subprocess.run(
                    [adb_path, '-s', self.device_serial, 'shell', 'getprop', key],
                    capture_output=True, timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                )
                return r.stdout.decode('utf-8', errors='replace').strip()
            except Exception:
                return ''

        # Check root
        rooted = False
        try:
            r = subprocess.run(
                [adb_path, '-s', self.device_serial, 'shell', 'su', '-c', 'id'],
                capture_output=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            rooted = r.returncode == 0 and b'uid=0' in r.stdout
        except Exception:
            pass

        sdk_str = _getprop('ro.build.version.sdk')
        return DeviceInfo(
            serial=self.device_serial,
            model=_getprop('ro.product.model') or 'Unknown',
            manufacturer=_getprop('ro.product.manufacturer') or 'Unknown',
            android_version=_getprop('ro.build.version.release') or 'Unknown',
            sdk_version=int(sdk_str) if sdk_str.isdigit() else 0,
            usb_debugging=True,
            security_patch=_getprop('ro.build.version.security_patch'),
            rooted=rooted,
        )

    def close(self):
        """Close and cleanup resources (alias for disconnect)"""
        self.disconnect()

    def disconnect(self):
        """Disconnect from the device"""
        if self._device:
            try:
                self._device.close()
            except Exception:
                pass
            self._device = None

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure cleanup"""
        self.disconnect()
        return False

    def __del__(self):
        """Destructor - ensure cleanup"""
        self.disconnect()

    def _adb_shell(self, cmd: str, use_su: bool = False) -> Tuple[str, int]:
        """
        Execute shell command via USB connection, with system adb fallback.

        Args:
            cmd: Command to execute
            use_su: Whether to use superuser (root)

        Returns:
            Tuple of (output, return_code)
        """
        if use_su:
            cmd = f'su -c {shlex.quote(cmd)}'

        for attempt in range(self.MAX_RETRIES):
            try:
                device = self._ensure_connection()
                if device is None:
                    # System adb fallback mode
                    return self._run_system_adb(['shell', cmd], timeout=60)
                output = device.shell(cmd, timeout_s=60)
                return output if output else '', 0
            except (TcpTimeoutException, UsbReadFailedError, UsbWriteFailedError) as e:
                if attempt < self.MAX_RETRIES - 1:
                    _debug_print(f"[ADB Shell] Retry {attempt + 1}: {e}")
                    self._device = None  # Force reconnect
                else:
                    return f'USB error: {e}', -1
            except Exception as e:
                return str(e), -1

        return 'Max retries exceeded', -1

    def _adb_pull(
        self,
        remote_path: str,
        local_path: str,
        use_su: bool = False
    ) -> bool:
        """
        Pull file from device via USB connection.

        Args:
            remote_path: Path on device
            local_path: Local destination path
            use_su: Whether to use root for access

        Returns:
            True if successful
        """
        local_path = Path(local_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)

        actual_remote_path = remote_path
        temp_path = None

        if use_su:
            # For root-protected files, copy to temp location first
            temp_path = f'/data/local/tmp/forensic_temp_{hashlib.md5(remote_path.encode()).hexdigest()[:8]}'
            self._adb_shell(f'cp {shlex.quote(remote_path)} {shlex.quote(temp_path)}', use_su=True)
            self._adb_shell(f'chmod 644 {shlex.quote(temp_path)}', use_su=True)
            actual_remote_path = temp_path

        try:
            for attempt in range(self.MAX_RETRIES):
                try:
                    device = self._ensure_connection()
                    if device is None:
                        # System adb fallback mode
                        output, rc = self._run_system_adb(
                            ['pull', actual_remote_path, str(local_path)], timeout=120
                        )
                        success = rc == 0 and local_path.is_file()
                        return success
                    device.pull(actual_remote_path, str(local_path))

                    return True

                except (TcpTimeoutException, UsbReadFailedError, UsbWriteFailedError) as e:
                    if attempt < self.MAX_RETRIES - 1:
                        _debug_print(f"[ADB Pull] Retry {attempt + 1}: {e}")
                        self._device = None  # Force reconnect
                    else:
                        _debug_print(f"[ADB Pull] Failed after {self.MAX_RETRIES} attempts: {e}")
                        return False
                except Exception as e:
                    _debug_print(f"[ADB Pull] Error: {e}")
                    return False

            return False
        finally:
            if temp_path:
                try:
                    self._adb_shell(f'rm {shlex.quote(temp_path)}', use_su=True)
                except Exception:
                    pass

    # Mapping: collector artifact_type → server-recognized artifact_type
    # Server only has base types (e.g., mobile_android_kakaotalk), not
    # _nonroot/_external variants. This maps for auto-parsing.
    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[Callable[[str], None]] = None,
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect specific artifact type from device.

        Args:
            artifact_type: Type of artifact to collect
            progress_callback: Callback for progress updates
            **kwargs: Additional arguments - accepted for interface compatibility

        Yields:
            Tuple of (local_path, metadata)
        """
        if not self.device_info:
            raise RuntimeError("Not connected to device. Call connect() first.")

        if artifact_type not in ANDROID_ARTIFACT_TYPES:
            raise ValueError(f"Unknown artifact type: {artifact_type}")

        artifact_info = ANDROID_ARTIFACT_TYPES[artifact_type]

        yield from self._collect_impl(
            artifact_type, artifact_info, progress_callback
        )

    def _collect_impl(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Unified dispatch with 5 collection methods:
        1. Dual-mode (root/nonroot auto-adaptive)
        2. content_provider
        3. system_info (8 sub-types)
        4. root_db
        5. sdcard
        6. screen_scrape
        """
        has_root = self.device_info.rooted

        # Create artifact output directory
        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)

        # --- 1) Dual-mode apps: auto-select root or nonroot ---
        if 'root' in artifact_info and 'nonroot' in artifact_info:
            if has_root:
                yield from self._collect_root_db(
                    artifact_type, artifact_info, artifact_dir, progress_callback
                )
            else:
                yield from self._collect_sdcard(
                    artifact_type, artifact_info, artifact_dir, progress_callback
                )
            return

        # --- 2) Single-mode: collection_method based ---
        collection_method = artifact_info.get('collection_method', '')

        # Check root requirement for single-mode entries
        requires_root = artifact_info.get('requires_root', False)
        if requires_root and not has_root:
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': 'Root access required but device is not rooted',
                'device': self.device_info.serial,
            }
            return

        if collection_method == 'content_provider':
            yield from self._collect_content_provider(
                artifact_type,
                artifact_info.get('content_uri', ''),
                artifact_dir,
                progress_callback
            )

        elif collection_method == 'system_info':
            yield from self._collect_system_info(
                artifact_type, artifact_info, artifact_dir, progress_callback
            )

        elif collection_method == 'root_db':
            yield from self._collect_root_db(
                artifact_type, artifact_info, artifact_dir, progress_callback
            )

        elif collection_method == 'sdcard':
            yield from self._collect_sdcard(
                artifact_type, artifact_info, artifact_dir, progress_callback
            )

        elif collection_method == 'screen_scrape':
            yield from self._collect_screen_scrape(
                artifact_type, artifact_info, artifact_dir, progress_callback
            )

    def _collect_root_db(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Root DB collection: extract files from /data/data/ via root access.
        Handles both dual-mode (artifact_info['root']['db_paths']) and
        single-mode (artifact_info['root']['db_paths']) entries.
        """
        root_config = artifact_info.get('root', {})
        db_paths = root_config.get('db_paths', [])

        if not db_paths:
            return

        if progress_callback:
            progress_callback(f"[Root] Collecting {artifact_info.get('name', artifact_type)}...")

        for path_pattern in db_paths:
            # Use existing path collection logic (handles globs, directories)
            if path_pattern.endswith('/'):
                yield from self._collect_directory(
                    artifact_type, path_pattern, output_dir, True, progress_callback
                )
            else:
                yield from self._collect_path(
                    artifact_type, path_pattern, output_dir, True, progress_callback
                )

    def _collect_sdcard(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Non-root sdcard collection (merged nonroot_app_data + messenger_external).

        Collects from external storage paths with:
        - Chatroom metadata extraction
        - Content-type classification (image/video/audio/document/database)
        - 50MB file size limit (metadata only for larger files)
        - Optional run-as for debuggable apps
        """
        nonroot_config = artifact_info.get('nonroot', {})
        sdcard_paths = nonroot_config.get('sdcard_paths', [])
        run_as_paths = nonroot_config.get('run_as_paths', [])
        package = artifact_info.get('package', '')
        app_name = artifact_info.get('name', artifact_type)

        if not sdcard_paths:
            return

        if progress_callback:
            progress_callback(f"[Non-Root] Collecting {app_name}...")

        # Check if package is installed (if specified)
        if package:
            check_cmd = f'pm list packages {shlex.quote(package)}'
            check_output, rc = self._adb_shell(check_cmd)
            if rc != 0 or package not in (check_output or ''):
                yield '', {
                    'artifact_type': artifact_type,
                    'status': 'skipped',
                    'error': f'Package {package} not installed on device',
                    'collection_method': 'sdcard',
                }
                return

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        total_files = 0
        total_size = 0

        # --- Phase 1: Chatroom structure metadata (messenger-specific) ---
        if package:
            chatroom_metadata = self._extract_chatroom_metadata(package)
            if chatroom_metadata and chatroom_metadata.get('chatroom_count', 0) > 0:
                meta_path = output_dir / 'chatroom_metadata.json'
                with open(meta_path, 'w', encoding='utf-8') as f:
                    json.dump(chatroom_metadata, f, ensure_ascii=False, indent=2)

                yield str(meta_path), {
                    'artifact_type': artifact_type,
                    'filename': 'chatroom_metadata.json',
                    'size': meta_path.stat().st_size,
                    'device_serial': self.device_info.serial if self.device_info else '',
                    'device_model': self.device_info.model if self.device_info else '',
                    'collected_at': datetime.utcnow().isoformat(),
                    'collection_method': 'sdcard',
                    'root_used': False,
                    'package': package,
                    'content_type': 'chatroom_structure',
                    'chatroom_count': chatroom_metadata.get('chatroom_count', 0),
                }
                total_files += 1

        # --- Phase 2: Pull files from each sdcard path ---
        for sdcard_path in sdcard_paths:
            if progress_callback:
                progress_callback(f"[Non-Root] {app_name}: Scanning {sdcard_path}...")

            # Check if path exists
            result = self._shell_cmd(f'ls -d {shlex.quote(sdcard_path)} 2>/dev/null')
            if not result or 'No such file' in result:
                continue

            # Get file listing
            file_list = self._shell_cmd(f'find {shlex.quote(sdcard_path)} -type f 2>/dev/null')
            if not file_list:
                # Fallback: try ls -R
                ls_output = self._shell_cmd(f'ls -R {shlex.quote(sdcard_path)} 2>/dev/null')
                if ls_output and ls_output.strip():
                    file_list = self._parse_ls_recursive(sdcard_path, ls_output)
                if not file_list:
                    continue

            files = [f.strip() for f in file_list.strip().split('\n') if f.strip()]

            # Limit per-path file count
            MAX_FILES_PER_PATH = 500
            if len(files) > MAX_FILES_PER_PATH:
                logger.warning(
                    f"[Non-Root] Truncating {len(files)} files to {MAX_FILES_PER_PATH} in {sdcard_path}"
                )
                files = files[:MAX_FILES_PER_PATH]

            if progress_callback:
                progress_callback(
                    f"[Non-Root] {app_name}: Found {len(files)} files in {sdcard_path}"
                )

            # Create subdirectory matching external path structure
            path_suffix = sdcard_path.replace('/sdcard/', '').replace('/', '_').rstrip('_')
            path_output = output_dir / path_suffix
            path_output.mkdir(parents=True, exist_ok=True)

            for idx, remote_file in enumerate(files):
                if not remote_file or remote_file.startswith('find:'):
                    continue

                # [SECURITY] Validate path — must be under sdcard_path
                if not remote_file.startswith(sdcard_path.rstrip('/')):
                    continue

                try:
                    # Get file info (size + timestamp)
                    stat_output = self._shell_cmd(
                        f'stat -c "%s %Y" {shlex.quote(remote_file)} 2>/dev/null'
                    )
                    file_size = 0
                    file_mtime = ''
                    if stat_output and stat_output.strip():
                        parts = stat_output.strip().split()
                        if len(parts) >= 2:
                            try:
                                file_size = int(parts[0])
                            except ValueError:
                                pass
                            try:
                                ts = int(parts[1])
                                file_mtime = datetime.utcfromtimestamp(ts).isoformat()
                            except (ValueError, OSError):
                                pass

                    # Skip very large files (>50MB) — record metadata only
                    if file_size > 50 * 1024 * 1024:
                        yield '', {
                            'artifact_type': artifact_type,
                            'original_path': remote_file,
                            'filename': Path(remote_file).name,
                            'size': file_size,
                            'modified_at': file_mtime,
                            'device_serial': self.device_info.serial if self.device_info else '',
                            'collected_at': datetime.utcnow().isoformat(),
                            'collection_method': 'sdcard',
                            'root_used': False,
                            'package': package,
                            'note': f'Large file (>{file_size // (1024*1024)}MB) — metadata only',
                            'skipped': True,
                        }
                        continue

                    # Preserve subdirectory structure
                    rel = remote_file[len(sdcard_path):].lstrip('/')
                    if not rel:
                        continue

                    # [SECURITY] Sanitize filename
                    safe_rel = re.sub(r'[<>:"|?*\x00-\x1f]', '_', rel)
                    if '..' in safe_rel:
                        continue

                    local_file = path_output / safe_rel.replace('/', os.sep)
                    local_file.parent.mkdir(parents=True, exist_ok=True)

                    # [SECURITY] Verify local_path stays within output_dir
                    try:
                        local_file.resolve().relative_to(output_dir.resolve())
                    except ValueError:
                        continue

                    # Pull file (try USB first, then system adb)
                    success = self._pull_file(remote_file, str(local_file))
                    if not success or not local_file.is_file():
                        # Fallback to _adb_pull
                        success = self._adb_pull(remote_file, str(local_file))
                        if not success or not local_file.is_file():
                            continue

                    # Calculate hash
                    sha256 = hashlib.sha256()
                    with open(local_file, 'rb') as f:
                        for chunk in iter(lambda: f.read(65536), b''):
                            sha256.update(chunk)

                    # Detect content type from extension
                    ext = local_file.suffix.lower()
                    content_type = 'unknown'
                    if ext in ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'):
                        content_type = 'image'
                    elif ext in ('.mp4', '.avi', '.mov', '.3gp', '.mkv', '.webm'):
                        content_type = 'video'
                    elif ext in ('.mp3', '.aac', '.ogg', '.wav', '.m4a', '.opus'):
                        content_type = 'audio'
                    elif ext in ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.hwp'):
                        content_type = 'document'
                    elif ext in ('.db', '.sqlite', '.sqlite3'):
                        content_type = 'database'
                    elif ext in ('.xml', '.json', '.log', '.txt'):
                        content_type = 'config'
                    elif ext == '' and file_size > 1000:
                        content_type = 'media_cache'

                    # Extract chatroom ID if present
                    chatroom_id = self._extract_chatroom_id(remote_file, package) if package else None

                    metadata = {
                        'artifact_type': artifact_type,
                        'original_path': remote_file,
                        'filename': local_file.name,
                        'size': local_file.stat().st_size,
                        'sha256': sha256.hexdigest(),
                        'modified_at': file_mtime,
                        'device_serial': self.device_info.serial if self.device_info else '',
                        'device_model': self.device_info.model if self.device_info else '',
                        'android_version': self.device_info.android_version if self.device_info else '',
                        'collected_at': datetime.utcnow().isoformat(),
                        'collection_method': 'sdcard',
                        'root_used': False,
                        'package': package,
                        'content_type': content_type,
                    }
                    if chatroom_id:
                        metadata['chatroom_id'] = chatroom_id

                    yield str(local_file), metadata

                    total_files += 1
                    total_size += local_file.stat().st_size

                    if progress_callback and (idx + 1) % 50 == 0:
                        progress_callback(
                            f"[Non-Root] {app_name}: {total_files} files "
                            f"({total_size // (1024*1024)}MB) collected..."
                        )

                except Exception as e:
                    logger.error(f"[Non-Root] Error pulling {remote_file}: {e}")
                    continue

        # --- Phase 3: run-as for debuggable apps (optional) ---
        if run_as_paths and package:
            yield from self._collect_runas_app_data(
                artifact_type, package, run_as_paths, output_dir, progress_callback
            )

        if progress_callback:
            progress_callback(
                f"[Non-Root] {app_name}: Complete - {total_files} files, "
                f"{total_size // (1024*1024)}MB total"
            )

    def _collect_system_info(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        System information batch collection (12 sub-types).
        Each sub-type yields with its own artifact_type for server parser compatibility.
        """
        sub_types = artifact_info.get('sub_types', {})

        for sub_key, sub_config in sub_types.items():
            sub_dir = output_dir / sub_key
            sub_dir.mkdir(exist_ok=True)
            sub_artifact_type = f'mobile_android_{sub_key}'

            if progress_callback:
                progress_callback(f"[System] Collecting {sub_config.get('name', sub_key)}...")

            if sub_key == 'logcat':
                yield from self._collect_logcat(sub_artifact_type, sub_dir, progress_callback)
            elif sub_key == 'packages':
                yield from self._collect_package_list(sub_artifact_type, sub_dir, progress_callback)
            elif sub_key == 'dumpsys':
                yield from self._collect_dumpsys(
                    sub_artifact_type, sub_config.get('services', []),
                    sub_dir, progress_callback
                )
            elif sub_key == 'settings':
                yield from self._collect_settings(sub_artifact_type, sub_dir, progress_callback)
            elif sub_key == 'notifications':
                yield from self._collect_notification_log(
                    sub_artifact_type, sub_dir, progress_callback
                )
            elif sub_key == 'accounts':
                yield from self._collect_account_info(
                    'mobile_android_accounts', sub_dir, progress_callback
                )
            elif sub_key == 'app_usage':
                yield from self._collect_app_usage(
                    'mobile_android_app_usage', sub_dir, progress_callback
                )
            elif sub_key == 'connectivity':
                yield from self._collect_connectivity_info(
                    'mobile_android_connectivity', sub_dir, progress_callback
                )
            elif sub_key == 'bugreport':
                yield from self._collect_bugreport(
                    'mobile_android_bugreport', sub_dir, progress_callback
                )
            elif sub_key == 'app_install_history':
                yield from self._collect_app_install_history(
                    'mobile_android_app_install_history', sub_dir, progress_callback
                )
            elif sub_key == 'wifi_history':
                yield from self._collect_wifi_history(
                    'mobile_android_wifi_history', sub_dir, progress_callback
                )
            elif sub_key == 'bluetooth_history':
                yield from self._collect_bluetooth_history(
                    'mobile_android_bluetooth_history', sub_dir, progress_callback
                )

    def _collect_db(
        self,
        artifact_type: str,
        db_path: str,
        output_dir: Path,
        use_root: bool,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect a database file"""
        filename = Path(db_path).name
        local_path = output_dir / filename

        if progress_callback:
            progress_callback(f"Collecting {filename}")

        success = self._adb_pull(db_path, str(local_path), use_su=use_root)

        if success and local_path.exists():
            # Calculate hash
            sha256 = hashlib.sha256()
            with open(local_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)

            yield str(local_path), {
                'artifact_type': artifact_type,
                'original_path': db_path,
                'filename': filename,
                'size': local_path.stat().st_size,
                'sha256': sha256.hexdigest(),
                'device_serial': self.device_info.serial,
                'device_model': self.device_info.model,
                'android_version': self.device_info.android_version,
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'adb_pull',
                'root_used': use_root,
            }
        else:
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': f'Failed to pull {db_path}',
                'original_path': db_path,
            }

    def _collect_path(
        self,
        artifact_type: str,
        path_pattern: str,
        output_dir: Path,
        use_root: bool,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files matching a path pattern"""
        # List files matching pattern
        ls_cmd = f'ls -la {path_pattern} 2>/dev/null'
        output, _ = self._adb_shell(ls_cmd, use_su=use_root)

        for line in output.strip().split('\n'):
            if not line or line.startswith('total'):
                continue

            # Parse ls output to get filename
            parts = line.split()
            if len(parts) < 8:
                continue

            filename = ' '.join(parts[7:])  # Filename might have spaces
            if not filename or filename in ('.', '..'):
                continue

            # [SECURITY] Validate filename to prevent path traversal
            if '/' in filename or '\\' in filename or '..' in filename:
                logging.warning(f"[SECURITY] Skipping suspicious filename: {filename}")
                continue

            # [SECURITY] Sanitize filename - remove any remaining dangerous chars
            safe_filename = re.sub(r'[<>:"|?*\x00-\x1f]', '_', filename)

            remote_path = str(Path(path_pattern).parent / filename)
            local_path = output_dir / safe_filename

            # [SECURITY] Verify local_path stays within output_dir
            try:
                local_path.resolve().relative_to(output_dir.resolve())
            except ValueError:
                logging.warning(f"[SECURITY] Path escape detected: {local_path}")
                continue

            if progress_callback:
                progress_callback(f"Collecting {filename}")

            success = self._adb_pull(remote_path, str(local_path), use_su=use_root)

            if success and local_path.exists():
                sha256 = hashlib.sha256()
                with open(local_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        sha256.update(chunk)

                yield str(local_path), {
                    'artifact_type': artifact_type,
                    'original_path': remote_path,
                    'filename': filename,
                    'size': local_path.stat().st_size,
                    'sha256': sha256.hexdigest(),
                    'device_serial': self.device_info.serial,
                    'device_model': self.device_info.model,
                    'collected_at': datetime.utcnow().isoformat(),
                    'collection_method': 'adb_pull',
                    'root_used': use_root,
                }

    def _collect_directory(
        self,
        artifact_type: str,
        dir_path: str,
        output_dir: Path,
        use_root: bool,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect directory listing and optionally files"""
        # Get directory listing
        ls_cmd = f'ls -la {dir_path} 2>/dev/null'
        output, _ = self._adb_shell(ls_cmd, use_su=use_root)

        listing_file = output_dir / 'directory_listing.txt'
        listing_file.write_text(output)

        yield str(listing_file), {
            'artifact_type': artifact_type,
            'type': 'directory_listing',
            'original_path': dir_path,
            'device_serial': self.device_info.serial,
            'collected_at': datetime.utcnow().isoformat(),
        }

    # ==========================================================================
    # Non-Root Collection Methods
    # ==========================================================================

    def _collect_content_provider(
        self,
        artifact_type: str,
        content_uri: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Data collection via Content Provider (non-root)"""
        # [SECURITY] Validate content URI against whitelist
        if not validate_content_uri(content_uri):
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': f'Unauthorized content URI: {content_uri}',
            }
            return

        if progress_callback:
            progress_callback(f"Querying {content_uri}")

        # Query data with content command (escape with shlex.quote)
        cmd = f'content query --uri {shlex.quote(content_uri)}'
        output, returncode = self._adb_shell(cmd)

        if returncode != 0 or not output.strip():
            # Call log: Android 10+ restricts READ_CALL_LOG → try dumpsys fallback
            if 'call_log' in content_uri:
                error_detail = output.strip()[:200] if output.strip() else 'Empty response'
                logging.info(
                    f"[ContentProvider] Call log access denied "
                    f"(likely Android 10+ restriction): {error_detail}"
                )
                if progress_callback:
                    progress_callback("Call log restricted — trying dumpsys telecom fallback")
                yield from self._collect_call_log_fallback(
                    artifact_type, output_dir, progress_callback
                )
                return

            # Other content providers: report error as-is
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': f'Failed to query {content_uri} (returncode={returncode})',
                'content_uri': content_uri,
            }
            return

        # Save results to file
        filename = f"{artifact_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
        local_path = output_dir / filename
        local_path.write_text(output, encoding='utf-8')

        sha256 = hashlib.sha256(output.encode('utf-8')).hexdigest()

        yield str(local_path), {
            'artifact_type': artifact_type,
            'content_uri': content_uri,
            'filename': filename,
            'size': local_path.stat().st_size,
            'sha256': sha256,
            'device_serial': self.device_info.serial,
            'device_model': self.device_info.model,
            'android_version': self.device_info.android_version,
            'collected_at': datetime.utcnow().isoformat(),
            'collection_method': 'content_provider',
            'root_used': False,
        }

    def _collect_call_log_fallback(
        self,
        artifact_type: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Fallback: collect call info from dumpsys telecom
        when content://call_log/calls is restricted (Android 10+)."""

        if progress_callback:
            progress_callback("Fallback: querying dumpsys telecom")

        cmd = f'dumpsys {shlex.quote("telecom")}'
        output, returncode = self._adb_shell(cmd)

        if returncode != 0 or not output.strip():
            logging.warning("[CallLog] dumpsys telecom fallback returned empty")
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': (
                    'Call log access denied (Android 10+ restriction). '
                    'dumpsys telecom fallback also empty. '
                    'Root access required for full call log collection.'
                ),
            }
            return

        # Prefix with marker so server parser can detect format
        content = f"=== dumpsys telecom fallback ===\n{output}"

        filename = (
            f"{artifact_type}_dumpsys_fallback_"
            f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        local_path = output_dir / filename
        local_path.write_text(content, encoding='utf-8', errors='replace')

        sha256 = hashlib.sha256(
            content.encode('utf-8', errors='replace')
        ).hexdigest()

        logging.info(
            f"[CallLog] Fallback collected {len(content)} bytes "
            f"from dumpsys telecom"
        )

        yield str(local_path), {
            'artifact_type': artifact_type,
            'filename': filename,
            'size': local_path.stat().st_size,
            'sha256': sha256,
            'device_serial': self.device_info.serial,
            'device_model': self.device_info.model,
            'android_version': self.device_info.android_version,
            'collected_at': datetime.utcnow().isoformat(),
            'collection_method': 'dumpsys_fallback',
            'root_used': False,
        }

    def _collect_logcat(
        self,
        artifact_type: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Logcat system log collection (non-root)"""
        if progress_callback:
            progress_callback("Collecting system logs (logcat)")

        # Collect multiple logcat buffers
        buffers = ['main', 'system', 'crash', 'events']

        for buffer_name in buffers:
            cmd = f'logcat -d -b {buffer_name} -v threadtime'
            output, returncode = self._adb_shell(cmd)

            if returncode == 0 and output.strip():
                filename = f"logcat_{buffer_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
                local_path = output_dir / filename
                local_path.write_text(output, encoding='utf-8', errors='replace')

                sha256 = hashlib.sha256(output.encode('utf-8', errors='replace')).hexdigest()

                yield str(local_path), {
                    'artifact_type': artifact_type,
                    'buffer': buffer_name,
                    'filename': filename,
                    'size': local_path.stat().st_size,
                    'sha256': sha256,
                    'device_serial': self.device_info.serial,
                    'collected_at': datetime.utcnow().isoformat(),
                    'collection_method': 'logcat',
                    'root_used': False,
                }

    def _collect_package_list(
        self,
        artifact_type: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Installed package list collection (non-root)"""
        if progress_callback:
            progress_callback("Collecting installed packages")

        # Collect various package information
        commands = {
            'all_packages': 'pm list packages -f',
            'system_packages': 'pm list packages -s',
            'third_party_packages': 'pm list packages -3',
            'disabled_packages': 'pm list packages -d',
            'permissions': 'pm list permissions -g',
        }

        for info_type, cmd in commands.items():
            output, returncode = self._adb_shell(cmd)

            if returncode == 0 and output.strip():
                filename = f"{info_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
                local_path = output_dir / filename
                local_path.write_text(output, encoding='utf-8')

                sha256 = hashlib.sha256(output.encode('utf-8')).hexdigest()

                yield str(local_path), {
                    'artifact_type': artifact_type,
                    'info_type': info_type,
                    'filename': filename,
                    'size': local_path.stat().st_size,
                    'sha256': sha256,
                    'device_serial': self.device_info.serial,
                    'collected_at': datetime.utcnow().isoformat(),
                    'collection_method': 'package_list',
                    'root_used': False,
                }

    def _collect_dumpsys(
        self,
        artifact_type: str,
        services: List[str],
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Dumpsys system information collection (non-root)"""
        for service in services:
            # [SECURITY] Validate service name against whitelist
            if not validate_dumpsys_service(service):
                logging.warning(f"[SECURITY] Skipping unauthorized service: {service}")
                continue

            if progress_callback:
                progress_callback(f"Collecting dumpsys {service}")

            # Escape with shlex.quote (defense in depth)
            cmd = f'dumpsys {shlex.quote(service)}'
            output, returncode = self._adb_shell(cmd)

            if returncode == 0 and output.strip():
                filename = f"dumpsys_{service}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
                local_path = output_dir / filename
                local_path.write_text(output, encoding='utf-8', errors='replace')

                sha256 = hashlib.sha256(output.encode('utf-8', errors='replace')).hexdigest()

                yield str(local_path), {
                    'artifact_type': artifact_type,
                    'service': service,
                    'filename': filename,
                    'size': local_path.stat().st_size,
                    'sha256': sha256,
                    'device_serial': self.device_info.serial,
                    'collected_at': datetime.utcnow().isoformat(),
                    'collection_method': 'dumpsys',
                    'root_used': False,
                }

    def _collect_settings(
        self,
        artifact_type: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Device settings collection (non-root)"""
        if progress_callback:
            progress_callback("Collecting device settings")

        # Collect three settings namespaces (whitelist validation)
        namespaces = ['secure', 'system', 'global']

        for namespace in namespaces:
            # [SECURITY] Validate namespace (defense in depth)
            if not validate_settings_namespace(namespace):
                continue

            cmd = f'settings list {shlex.quote(namespace)}'
            output, returncode = self._adb_shell(cmd)

            if returncode == 0 and output.strip():
                filename = f"settings_{namespace}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
                local_path = output_dir / filename
                local_path.write_text(output, encoding='utf-8')

                sha256 = hashlib.sha256(output.encode('utf-8')).hexdigest()

                yield str(local_path), {
                    'artifact_type': artifact_type,
                    'namespace': namespace,
                    'filename': filename,
                    'size': local_path.stat().st_size,
                    'sha256': sha256,
                    'device_serial': self.device_info.serial,
                    'collected_at': datetime.utcnow().isoformat(),
                    'collection_method': 'settings',
                    'root_used': False,
                }

        # Additional: getprop system properties collection
        cmd = 'getprop'
        output, returncode = self._adb_shell(cmd)

        if returncode == 0 and output.strip():
            filename = f"system_properties_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
            local_path = output_dir / filename
            local_path.write_text(output, encoding='utf-8')

            sha256 = hashlib.sha256(output.encode('utf-8')).hexdigest()

            yield str(local_path), {
                'artifact_type': artifact_type,
                'info_type': 'system_properties',
                'filename': filename,
                'size': local_path.stat().st_size,
                'sha256': sha256,
                'device_serial': self.device_info.serial,
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'getprop',
                'root_used': False,
            }

    # ==========================================================================
    # [2026-02-22] Non-Root Advanced Collection Methods
    # ==========================================================================

    def _collect_runas_app_data(
        self,
        artifact_type: str,
        package: str,
        db_paths: List[str],
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Try to extract app private data using `run-as` command.

        Only works for apps with android:debuggable="true" in manifest.
        Most production apps are NOT debuggable, so this is best-effort.
        """
        if progress_callback:
            progress_callback(f"[run-as] Testing debuggable access for {package}")

        # Test if run-as works for this package
        test_cmd = f'run-as {shlex.quote(package)} ls 2>&1'
        test_output, rc = self._adb_shell(test_cmd)

        if rc != 0 or 'not debuggable' in (test_output or '').lower() or \
           'unknown package' in (test_output or '').lower() or \
           'is not debuggable' in (test_output or ''):
            logger.info(f"[run-as] {package} is not debuggable (expected for production apps)")
            return

        logger.info(f"[run-as] {package} IS debuggable! Extracting private data...")

        if progress_callback:
            progress_callback(f"[run-as] {package} is debuggable — extracting data")

        for db_rel_path in db_paths:
            # [SECURITY] Validate relative path
            if '..' in db_rel_path or db_rel_path.startswith('/'):
                continue

            # Use run-as to copy file to a temp location accessible without root
            temp_name = f'forensic_{hashlib.md5(db_rel_path.encode()).hexdigest()[:8]}'
            temp_path = f'/data/local/tmp/{temp_name}'

            # Copy file via run-as
            copy_cmd = (
                f'run-as {shlex.quote(package)} '
                f'cat {shlex.quote(db_rel_path)} > {shlex.quote(temp_path)} 2>/dev/null'
            )
            _, rc = self._adb_shell(copy_cmd)

            if rc != 0:
                # Try alternative: run-as cp
                copy_cmd2 = (
                    f'run-as {shlex.quote(package)} '
                    f'cp {shlex.quote(db_rel_path)} {shlex.quote(temp_path)} 2>/dev/null'
                )
                _, rc = self._adb_shell(copy_cmd2)

            if rc != 0:
                continue

            # Make temp file readable
            self._adb_shell(f'chmod 644 {shlex.quote(temp_path)}')

            # Pull the temp file
            safe_name = re.sub(r'[<>:"|?*\x00-\x1f/\\]', '_', db_rel_path)
            local_path = output_dir / 'runas' / safe_name
            local_path.parent.mkdir(parents=True, exist_ok=True)

            try:
                success = self._adb_pull(temp_path, str(local_path))
            finally:
                # Clean up temp file
                try:
                    self._adb_shell(f'rm {shlex.quote(temp_path)}')
                except Exception:
                    pass

            if success and local_path.exists() and local_path.stat().st_size > 0:
                sha256 = hashlib.sha256()
                with open(local_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        sha256.update(chunk)

                if progress_callback:
                    progress_callback(f"[run-as] Extracted {db_rel_path}")

                yield str(local_path), {
                    'artifact_type': artifact_type,
                    'original_path': f'/data/data/{package}/{db_rel_path}',
                    'filename': Path(db_rel_path).name,
                    'size': local_path.stat().st_size,
                    'sha256': sha256.hexdigest(),
                    'device_serial': self.device_info.serial,
                    'device_model': self.device_info.model,
                    'android_version': self.device_info.android_version,
                    'collected_at': datetime.utcnow().isoformat(),
                    'collection_method': 'runas',
                    'root_used': False,
                    'package': package,
                    'source': 'debuggable_app',
                }
    def _parse_ls_recursive(self, base_path: str, ls_output: str) -> str:
        """Parse `ls -R` output into a newline-separated list of full file paths."""
        lines = ls_output.strip().split('\n')
        current_dir = base_path.rstrip('/')
        files = []

        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.endswith(':'):
                # Directory header
                current_dir = line[:-1]
            elif line.startswith('total '):
                continue
            elif line.startswith('-') or line.startswith('l'):
                # File entry from ls -la format
                parts = line.split(None, 7)
                if len(parts) >= 8:
                    fname = parts[7].split(' -> ')[0].strip()
                    if fname and fname not in ('.', '..'):
                        files.append(f"{current_dir}/{fname}")
            else:
                # Simple ls format (just filename)
                if line not in ('.', '..') and '/' not in line:
                    files.append(f"{current_dir}/{line}")

        return '\n'.join(files)

    def _collect_notification_log(
        self,
        artifact_type: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Extract notification history from dumpsys.

        Captures recent notifications including message previews and sender info.
        Forensically valuable for recovering message content without root access.
        """
        if progress_callback:
            progress_callback("[Non-Root] Collecting notification log")

        # dumpsys notification -- contains recent notification entries
        cmd = 'dumpsys notification --noredact 2>/dev/null || dumpsys notification'
        output, rc = self._adb_shell(cmd)

        if rc != 0 or not output or not output.strip():
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': 'Failed to collect notification log',
            }
            return

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"notification_log_{timestamp}.txt"
        local_path = output_dir / filename
        local_path.write_text(output, encoding='utf-8', errors='replace')

        sha256 = hashlib.sha256(output.encode('utf-8', errors='replace')).hexdigest()

        yield str(local_path), {
            'artifact_type': artifact_type,
            'filename': filename,
            'size': local_path.stat().st_size,
            'sha256': sha256,
            'device_serial': self.device_info.serial,
            'device_model': self.device_info.model,
            'android_version': self.device_info.android_version,
            'collected_at': datetime.utcnow().isoformat(),
            'collection_method': 'notification_log',
            'root_used': False,
        }

        # Also try notification history via cmd (Android 11+)
        cmd2 = 'cmd notification history 2>/dev/null'
        output2, rc2 = self._adb_shell(cmd2)

        if rc2 == 0 and output2 and output2.strip() and len(output2.strip()) > 10:
            filename2 = f"notification_history_{timestamp}.txt"
            local_path2 = output_dir / filename2
            local_path2.write_text(output2, encoding='utf-8', errors='replace')

            sha256_2 = hashlib.sha256(output2.encode('utf-8', errors='replace')).hexdigest()

            yield str(local_path2), {
                'artifact_type': artifact_type,
                'filename': filename2,
                'size': local_path2.stat().st_size,
                'sha256': sha256_2,
                'device_serial': self.device_info.serial,
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'notification_history',
                'root_used': False,
            }

    def _collect_account_info(
        self,
        artifact_type: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect registered account information.

        Extracts Google accounts, Samsung accounts, and app-specific accounts
        registered on the device. No root required.
        """
        if progress_callback:
            progress_callback("[Non-Root] Collecting registered accounts")

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

        # Method 1: dumpsys account
        cmd = 'dumpsys account'
        output, rc = self._adb_shell(cmd)

        if rc == 0 and output and output.strip():
            filename = f"accounts_{timestamp}.txt"
            local_path = output_dir / filename
            local_path.write_text(output, encoding='utf-8', errors='replace')

            sha256 = hashlib.sha256(output.encode('utf-8', errors='replace')).hexdigest()

            yield str(local_path), {
                'artifact_type': artifact_type,
                'filename': filename,
                'size': local_path.stat().st_size,
                'sha256': sha256,
                'device_serial': self.device_info.serial,
                'device_model': self.device_info.model,
                'android_version': self.device_info.android_version,
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'dumpsys_account',
                'root_used': False,
            }

        # Method 2: content query for contacts/accounts
        # This may be restricted on Android 11+
        acct_cmd = 'content query --uri content://com.android.contacts/raw_contacts --projection account_name,account_type 2>/dev/null'
        acct_output, rc2 = self._adb_shell(acct_cmd)

        if rc2 == 0 and acct_output and acct_output.strip() and 'Error' not in acct_output:
            filename2 = f"contact_accounts_{timestamp}.txt"
            local_path2 = output_dir / filename2
            local_path2.write_text(acct_output, encoding='utf-8', errors='replace')

            sha256_2 = hashlib.sha256(acct_output.encode('utf-8', errors='replace')).hexdigest()

            yield str(local_path2), {
                'artifact_type': artifact_type,
                'filename': filename2,
                'size': local_path2.stat().st_size,
                'sha256': sha256_2,
                'device_serial': self.device_info.serial,
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'content_query_accounts',
                'root_used': False,
            }

    def _collect_app_usage(
        self,
        artifact_type: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect app usage statistics.

        Extracts app launch times, foreground duration, and last-used timestamps.
        Useful for establishing timeline of app activity without root.
        """
        if progress_callback:
            progress_callback("[Non-Root] Collecting app usage statistics")

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

        # dumpsys usagestats (detailed usage)
        cmd = 'dumpsys usagestats'
        output, rc = self._adb_shell(cmd)

        if rc == 0 and output and output.strip():
            filename = f"app_usage_{timestamp}.txt"
            local_path = output_dir / filename
            local_path.write_text(output, encoding='utf-8', errors='replace')

            sha256 = hashlib.sha256(output.encode('utf-8', errors='replace')).hexdigest()

            yield str(local_path), {
                'artifact_type': artifact_type,
                'filename': filename,
                'size': local_path.stat().st_size,
                'sha256': sha256,
                'device_serial': self.device_info.serial,
                'device_model': self.device_info.model,
                'android_version': self.device_info.android_version,
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'dumpsys_usagestats',
                'root_used': False,
            }

        # cmd appops (Android 6+) — app operation history
        cmd2 = 'dumpsys appops'
        output2, rc2 = self._adb_shell(cmd2)

        if rc2 == 0 and output2 and output2.strip():
            filename2 = f"appops_{timestamp}.txt"
            local_path2 = output_dir / filename2
            local_path2.write_text(output2, encoding='utf-8', errors='replace')

            sha256_2 = hashlib.sha256(output2.encode('utf-8', errors='replace')).hexdigest()

            yield str(local_path2), {
                'artifact_type': artifact_type,
                'filename': filename2,
                'size': local_path2.stat().st_size,
                'sha256': sha256_2,
                'device_serial': self.device_info.serial,
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'dumpsys_appops',
                'root_used': False,
            }

    def _collect_connectivity_info(
        self,
        artifact_type: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect network connectivity information.

        Extracts WiFi networks, Bluetooth paired devices, and network statistics.
        """
        if progress_callback:
            progress_callback("[Non-Root] Collecting connectivity info")

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

        # Collect multiple connectivity sources
        sources = {
            'wifi': 'dumpsys wifi',
            'bluetooth': 'dumpsys bluetooth_manager',
            'connectivity': 'dumpsys connectivity',
            'netstats': 'dumpsys netstats',
            'telephony': 'dumpsys telephony.registry',
        }

        for source_name, cmd in sources.items():
            output, rc = self._adb_shell(cmd)

            if rc == 0 and output and output.strip():
                filename = f"{source_name}_{timestamp}.txt"
                local_path = output_dir / filename
                local_path.write_text(output, encoding='utf-8', errors='replace')

                sha256 = hashlib.sha256(output.encode('utf-8', errors='replace')).hexdigest()

                yield str(local_path), {
                    'artifact_type': artifact_type,
                    'source': source_name,
                    'filename': filename,
                    'size': local_path.stat().st_size,
                    'sha256': sha256,
                    'device_serial': self.device_info.serial,
                    'device_model': self.device_info.model,
                    'android_version': self.device_info.android_version,
                    'collected_at': datetime.utcnow().isoformat(),
                    'collection_method': f'dumpsys_{source_name}',
                    'root_used': False,
                }

    def _collect_bugreport(
        self,
        artifact_type: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect bugreport: comprehensive system state dump.

        Captures WiFi history, battery stats, BT pairing, all dumpsys outputs,
        logcat, kernel logs, and more in a single zip file. Equivalent to
        20+ individual dumpsys calls.

        Uses system adb binary (bugreport requires host-side adb command).
        Timeout set to 300s (5 minutes) as bugreport typically takes 60-90 seconds
        but can take 2-3 minutes on older devices.
        """
        if progress_callback:
            progress_callback("[Non-Root] Collecting bugreport (this may take 60-90 seconds)...")

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        bugreport_path = output_dir / f"bugreport_{timestamp}.zip"

        # adb bugreport must be run as a host-side adb command, not via shell
        # bugreport takes 2-3 minutes on older devices
        output, rc = self._run_system_adb(
            ['bugreport', str(bugreport_path)],
            timeout=300
        )

        if rc == 0 and bugreport_path.exists():
            stat_result = bugreport_path.stat()
            if stat_result.st_size > 0:
                sha256 = hashlib.sha256()
                with open(bugreport_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        sha256.update(chunk)

                logger.info(
                    f"[Bugreport] Collected successfully: "
                    f"{stat_result.st_size // 1024}KB"
                )

                yield str(bugreport_path), {
                    'artifact_type': artifact_type,
                    'filename': bugreport_path.name,
                    'size': stat_result.st_size,
                    'sha256': sha256.hexdigest(),
                    'device_serial': self.device_info.serial,
                    'device_model': self.device_info.model,
                    'android_version': self.device_info.android_version,
                    'collected_at': datetime.utcnow().isoformat(),
                    'collection_method': 'adb_bugreport',
                    'root_used': False,
                }
                return

        error_msg = output.strip()[:200] if output else 'Unknown error'
        logger.warning(f"[Bugreport] Collection failed: {error_msg}")
        yield '', {
            'artifact_type': artifact_type,
            'status': 'error',
            'error': f'Bugreport collection failed: {error_msg}',
        }

    def _collect_app_install_history(
        self,
        artifact_type: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Extract app installation and update timeline from package manager.

        Collects firstInstallTime, lastUpdateTime, and versionName for each
        third-party package. Useful for establishing software installation
        timeline without root access.

        Output: app_install_history.jsonl (one JSON object per line)
        """
        if progress_callback:
            progress_callback("[Non-Root] Collecting app installation history")

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

        # Step 1: Get list of third-party packages with file paths
        cmd = 'pm list packages -3'
        output, rc = self._adb_shell(cmd)

        if rc != 0 or not output or not output.strip():
            logger.warning("[AppInstallHistory] Failed to list packages")
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': 'Failed to list third-party packages',
            }
            return

        packages = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if line.startswith('package:'):
                pkg_name = line[len('package:'):]
                if pkg_name and re.match(r'^[a-zA-Z0-9._]+$', pkg_name):
                    packages.append(pkg_name)

        if not packages:
            logger.info("[AppInstallHistory] No third-party packages found")
            return

        if progress_callback:
            progress_callback(
                f"[Non-Root] Extracting install timestamps for {len(packages)} apps"
            )

        # Step 2: For each package, extract install/update timestamps
        records = []
        for pkg in packages:
            # pm dump is safe — only reads package metadata
            cmd = (
                f'pm dump {shlex.quote(pkg)} '
                f'| grep -E "firstInstallTime|lastUpdateTime|versionName"'
            )
            pkg_output, pkg_rc = self._adb_shell(cmd)

            if pkg_rc != 0 or not pkg_output or not pkg_output.strip():
                continue

            record = {'package': pkg}
            for info_line in pkg_output.strip().split('\n'):
                info_line = info_line.strip()
                if 'firstInstallTime=' in info_line:
                    record['first_install'] = info_line.split('=', 1)[1].strip()
                elif 'lastUpdateTime=' in info_line:
                    record['last_update'] = info_line.split('=', 1)[1].strip()
                elif 'versionName=' in info_line:
                    record['version'] = info_line.split('=', 1)[1].strip()

            if 'first_install' in record or 'last_update' in record:
                records.append(record)

        if not records:
            logger.info("[AppInstallHistory] No install timestamps extracted")
            return

        # Step 3: Write JSONL output
        filename = f"app_install_history_{timestamp}.jsonl"
        local_path = output_dir / filename

        jsonl_content = '\n'.join(json.dumps(r, ensure_ascii=False) for r in records)
        local_path.write_text(jsonl_content, encoding='utf-8')

        sha256 = hashlib.sha256(jsonl_content.encode('utf-8')).hexdigest()

        logger.info(
            f"[AppInstallHistory] Collected {len(records)} app records"
        )

        yield str(local_path), {
            'artifact_type': artifact_type,
            'filename': filename,
            'size': local_path.stat().st_size,
            'sha256': sha256,
            'record_count': len(records),
            'device_serial': self.device_info.serial,
            'device_model': self.device_info.model,
            'android_version': self.device_info.android_version,
            'collected_at': datetime.utcnow().isoformat(),
            'collection_method': 'pm_dump',
            'root_used': False,
        }

    def _collect_wifi_history(
        self,
        artifact_type: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Extract saved WiFi networks and connection history.

        Parses dumpsys wifi output for configured networks including
        SSID, security type, and last connected timestamps.

        Output: wifi_history.jsonl (one JSON object per line)
        """
        if progress_callback:
            progress_callback("[Non-Root] Collecting WiFi connection history")

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

        # Collect full dumpsys wifi output
        cmd = 'dumpsys wifi'
        output, rc = self._adb_shell(cmd)

        if rc != 0 or not output or not output.strip():
            logger.warning("[WiFiHistory] Failed to collect dumpsys wifi")
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': 'Failed to collect WiFi information',
            }
            return

        # Save raw dumpsys wifi output
        raw_filename = f"wifi_dumpsys_{timestamp}.txt"
        raw_path = output_dir / raw_filename
        raw_path.write_text(output, encoding='utf-8', errors='replace')

        raw_sha256 = hashlib.sha256(
            output.encode('utf-8', errors='replace')
        ).hexdigest()

        yield str(raw_path), {
            'artifact_type': artifact_type,
            'source': 'wifi_dumpsys_raw',
            'filename': raw_filename,
            'size': raw_path.stat().st_size,
            'sha256': raw_sha256,
            'device_serial': self.device_info.serial,
            'device_model': self.device_info.model,
            'android_version': self.device_info.android_version,
            'collected_at': datetime.utcnow().isoformat(),
            'collection_method': 'dumpsys_wifi',
            'root_used': False,
        }

        # Parse configured networks from dumpsys wifi output
        # Look for ConfiguredNetworks or WifiConfigStore sections
        networks = []
        current_network = {}
        in_config_section = False

        for line in output.split('\n'):
            stripped = line.strip()

            # Detect start of configured networks section
            if 'ConfiguredNetworks' in stripped or 'WifiConfigStore' in stripped:
                in_config_section = True
                continue

            if not in_config_section:
                continue

            # Detect end of section (empty line or new section header)
            if stripped == '' and current_network:
                if 'ssid' in current_network:
                    networks.append(current_network)
                current_network = {}
                continue

            # Parse network fields
            if 'SSID' in stripped and '=' in stripped:
                val = stripped.split('=', 1)[1].strip().strip('"')
                if val:
                    current_network['ssid'] = val
            elif 'BSSID' in stripped and '=' in stripped:
                val = stripped.split('=', 1)[1].strip()
                if val and val != 'any':
                    current_network['bssid'] = val
            elif 'KeyMgmt' in stripped or 'security' in stripped.lower():
                val = stripped.split('=', 1)[1].strip() if '=' in stripped else stripped
                current_network['security_type'] = val
            elif 'lastConnected' in stripped or 'lastUpdated' in stripped:
                val = stripped.split('=', 1)[1].strip() if '=' in stripped else stripped
                key = 'last_connected' if 'lastConnected' in stripped else 'last_updated'
                current_network[key] = val
            elif 'status' in stripped.lower() and '=' in stripped:
                val = stripped.split('=', 1)[1].strip()
                current_network['status'] = val

        # Flush last network if pending
        if current_network and 'ssid' in current_network:
            networks.append(current_network)

        if networks:
            jsonl_filename = f"wifi_history_{timestamp}.jsonl"
            jsonl_path = output_dir / jsonl_filename

            jsonl_content = '\n'.join(
                json.dumps(n, ensure_ascii=False) for n in networks
            )
            jsonl_path.write_text(jsonl_content, encoding='utf-8')

            jsonl_sha256 = hashlib.sha256(jsonl_content.encode('utf-8')).hexdigest()

            logger.info(f"[WiFiHistory] Parsed {len(networks)} saved networks")

            yield str(jsonl_path), {
                'artifact_type': artifact_type,
                'source': 'wifi_parsed',
                'filename': jsonl_filename,
                'size': jsonl_path.stat().st_size,
                'sha256': jsonl_sha256,
                'network_count': len(networks),
                'device_serial': self.device_info.serial,
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'wifi_history_parsed',
                'root_used': False,
            }
        else:
            logger.debug("[WiFiHistory] No configured networks parsed from dumpsys output")

    def _collect_bluetooth_history(
        self,
        artifact_type: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Extract Bluetooth paired devices and connection history.

        Parses dumpsys bluetooth_manager output for bonded devices
        including device name, MAC address, device type, and bond state.

        Output: bluetooth_history.jsonl (one JSON object per line)
        """
        if progress_callback:
            progress_callback("[Non-Root] Collecting Bluetooth pairing history")

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

        # Collect dumpsys bluetooth_manager
        cmd = 'dumpsys bluetooth_manager'
        output, rc = self._adb_shell(cmd)

        if rc != 0 or not output or not output.strip():
            logger.warning("[BTHistory] Failed to collect dumpsys bluetooth_manager")
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': 'Failed to collect Bluetooth information',
            }
            return

        # Save raw dumpsys bluetooth_manager output
        raw_filename = f"bluetooth_dumpsys_{timestamp}.txt"
        raw_path = output_dir / raw_filename
        raw_path.write_text(output, encoding='utf-8', errors='replace')

        raw_sha256 = hashlib.sha256(
            output.encode('utf-8', errors='replace')
        ).hexdigest()

        yield str(raw_path), {
            'artifact_type': artifact_type,
            'source': 'bluetooth_dumpsys_raw',
            'filename': raw_filename,
            'size': raw_path.stat().st_size,
            'sha256': raw_sha256,
            'device_serial': self.device_info.serial,
            'device_model': self.device_info.model,
            'android_version': self.device_info.android_version,
            'collected_at': datetime.utcnow().isoformat(),
            'collection_method': 'dumpsys_bluetooth',
            'root_used': False,
        }

        # Parse bonded/paired devices from bluetooth_manager output
        devices = []
        current_device = {}

        for line in output.split('\n'):
            stripped = line.strip()

            # Detect bonded devices section
            if ('Bonded devices' in stripped or 'bonded devices' in stripped
                    or 'Paired devices' in stripped):
                continue

            # Detect device entry by MAC address pattern (XX:XX:XX:XX:XX:XX)
            mac_match = re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', stripped)
            if mac_match:
                # Save previous device if exists
                if current_device and 'mac_address' in current_device:
                    devices.append(current_device)
                current_device = {'mac_address': mac_match.group(1)}
                # Check if device name follows on same line
                remainder = stripped.replace(mac_match.group(1), '').strip(' -:')
                if remainder:
                    current_device['device_name'] = remainder
                continue

            if not current_device:
                continue

            # Parse device attributes
            if 'name' in stripped.lower() and '=' in stripped:
                val = stripped.split('=', 1)[1].strip().strip('"')
                if val:
                    current_device['device_name'] = val
            elif 'deviceType' in stripped or 'device_type' in stripped:
                val = stripped.split('=', 1)[1].strip() if '=' in stripped else stripped
                current_device['device_type'] = val
            elif 'bondState' in stripped or 'bond_state' in stripped:
                val = stripped.split('=', 1)[1].strip() if '=' in stripped else stripped
                current_device['bond_state'] = val
            elif 'BluetoothClass' in stripped or 'deviceClass' in stripped:
                val = stripped.split('=', 1)[1].strip() if '=' in stripped else stripped
                current_device['device_class'] = val
            elif 'uuids' in stripped.lower() and '=' in stripped:
                val = stripped.split('=', 1)[1].strip()
                current_device['uuids'] = val

        # Flush last device
        if current_device and 'mac_address' in current_device:
            devices.append(current_device)

        if devices:
            jsonl_filename = f"bluetooth_history_{timestamp}.jsonl"
            jsonl_path = output_dir / jsonl_filename

            jsonl_content = '\n'.join(
                json.dumps(d, ensure_ascii=False) for d in devices
            )
            jsonl_path.write_text(jsonl_content, encoding='utf-8')

            jsonl_sha256 = hashlib.sha256(jsonl_content.encode('utf-8')).hexdigest()

            logger.info(f"[BTHistory] Parsed {len(devices)} paired devices")

            yield str(jsonl_path), {
                'artifact_type': artifact_type,
                'source': 'bluetooth_parsed',
                'filename': jsonl_filename,
                'size': jsonl_path.stat().st_size,
                'sha256': jsonl_sha256,
                'device_count': len(devices),
                'device_serial': self.device_info.serial,
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'bluetooth_history_parsed',
                'root_used': False,
            }
        else:
            logger.debug("[BTHistory] No paired devices parsed from dumpsys output")

    # ======================================================================
    # System ADB Helpers (for shell/pull fallback and external storage)
    # ======================================================================

    def _find_system_adb(self) -> Optional[str]:
        """
        Locate adb binary: bundled first, then system fallback.
        Results are cached in self._system_adb_path to avoid repeated filesystem scans.

        Search order:
        1. Cached path (if previously found and still exists)
        2. Bundled adb (PyInstaller _MEIPASS/resources/adb/)
        3. Bundled adb (source tree resources/adb/)
        4. Common system installation paths
        5. PATH environment variable

        Returns:
            Path to adb executable, or None if not found
        """
        # Use cached path if still valid
        cached = getattr(self, '_system_adb_path', None)
        if cached and os.path.isfile(cached):
            return cached
        search_paths = []

        # Priority 1: Bundled adb (inside PyInstaller EXE or source tree)
        bundled_dirs = []
        # PyInstaller runtime temp directory
        meipass = getattr(sys, '_MEIPASS', None)
        if meipass:
            bundled_dirs.append(os.path.join(meipass, 'resources', 'adb'))
        # Source tree (development mode)
        src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bundled_dirs.append(os.path.join(src_dir, '..', 'resources', 'adb'))
        bundled_dirs.append(os.path.join(src_dir, 'resources', 'adb'))

        for d in bundled_dirs:
            adb_path = os.path.join(d, 'adb.exe' if sys.platform == 'win32' else 'adb')
            if os.path.isfile(adb_path):
                search_paths.insert(0, adb_path)

        # Priority 2: Common system paths (Windows)
        search_paths.extend([
            r'C:\Program Files\ASUS\GlideX\adb.exe',
            r'C:\Program Files (x86)\ASUS\GlideX\adb.exe',
            os.path.expandvars(r'%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe'),
            os.path.expandvars(r'%USERPROFILE%\AppData\Local\Android\Sdk\platform-tools\adb.exe'),
            r'C:\Android\platform-tools\adb.exe',
            r'C:\Program Files (x86)\Samsung\Smart Switch PC\adb.exe',
            r'C:\adb\adb.exe',
            r'C:\platform-tools\adb.exe',
        ])

        for path in search_paths:
            if os.path.isfile(path):
                logger.info(f"Found system adb: {path}")
                self._system_adb_path = path
                return path

        # Try PATH
        adb_in_path = shutil.which('adb')
        if adb_in_path:
            logger.info(f"Found adb in PATH: {adb_in_path}")
            self._system_adb_path = adb_in_path
            return adb_in_path

        return None

    def _run_system_adb(
        self,
        args: List[str],
        timeout: int = 300,
        input_data: Optional[bytes] = None
    ) -> Tuple[str, int]:
        """
        Run system adb command with specified arguments.

        Args:
            args: Arguments to pass to adb (e.g., ['backup', '-f', 'out.ab', 'pkg'])
            timeout: Timeout in seconds
            input_data: Optional stdin data

        Returns:
            Tuple of (stdout, return_code)
        """
        adb_path = self._find_system_adb()
        if not adb_path:
            return 'System adb binary not found', -1

        serial = self.device_info.serial if self.device_info else None
        cmd = [adb_path]
        if serial:
            cmd.extend(['-s', serial])
        cmd.extend(args)

        logger.info(f"[ADB] Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                input=input_data,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0,
            )
            stdout = result.stdout.decode('utf-8', errors='replace')
            stderr = result.stderr.decode('utf-8', errors='replace')
            if result.returncode != 0 and stderr:
                stdout = f"{stdout}\nSTDERR: {stderr}"
            return stdout, result.returncode
        except subprocess.TimeoutExpired:
            return 'Command timed out', -2
        except FileNotFoundError:
            return f'adb not found at {adb_path}', -1
        except Exception as e:
            return str(e), -1

    # ==================================================================
    # [2026-02-22] External Storage Messenger Data Collection
    # Collects media, chatroom metadata, downloads from /sdcard/ paths
    # Always works without root — external storage is adb-accessible
    # ==================================================================

    def _shell_cmd(self, cmd: str) -> str:
        """
        Execute shell command on device, returning output string.

        Uses USB library first, falls back to system adb if USB fails.
        This is a convenience wrapper that unpacks the tuple from _adb_shell.
        """
        try:
            result, rc = self._adb_shell(cmd)
            if rc == 0 and result:
                return result
        except Exception:
            pass

        # Fallback to system adb
        try:
            output, rc = self._run_system_adb(['shell', cmd], timeout=60)
            if rc == 0:
                return output
            return output  # Return even on error for parsing
        except Exception:
            return ''

    def _pull_file(self, remote_path: str, local_path: str) -> bool:
        """
        Pull file from device, with system adb fallback.
        """
        # Try USB library first
        try:
            if self._adb_pull(remote_path, local_path):
                return True
        except Exception:
            pass

        # Fallback to system adb
        try:
            output, rc = self._run_system_adb(
                ['pull', remote_path, local_path], timeout=120
            )
            return rc == 0 and Path(local_path).is_file()
        except Exception:
            return False

    def _extract_chatroom_metadata(self, package: str) -> Dict[str, Any]:
        """
        Extract chatroom structure from external storage directory listing.

        Analyzes the directory structure of messenger external data to identify
        chatroom IDs, activity periods, and communication patterns.

        Returns dict with chatroom_count, chatrooms list (id, file_count, dates).
        """
        metadata: Dict[str, Any] = {
            'package': package,
            'extracted_at': datetime.utcnow().isoformat(),
            'chatrooms': [],
            'chatroom_count': 0,
        }

        # Package-specific content paths
        content_paths = {
            'com.kakao.talk': '/sdcard/Android/data/com.kakao.talk/contents/',
            'com.whatsapp': '/sdcard/Android/media/com.whatsapp/WhatsApp/Media/',
            'org.telegram.messenger': '/sdcard/Telegram/',
            'com.tencent.mm': '/sdcard/tencent/MicroMsg/',
            'jp.naver.line.android': '/sdcard/Android/data/jp.naver.line.android/storage/',
        }

        content_path = content_paths.get(package)
        if not content_path:
            return metadata

        # List first-level directories (chatroom IDs or categories)
        result = self._shell_cmd(
            f'ls -la {content_path} 2>/dev/null'
        )
        if not result:
            return metadata

        chatrooms = []
        for line in result.strip().split('\n'):
            parts = line.split()
            if len(parts) < 7:
                continue
            if parts[0].startswith('d') and parts[-1] not in ('.', '..'):
                dir_name = parts[-1]
                # Get date from listing
                date_str = ' '.join(parts[4:6]) if len(parts) >= 7 else ''

                # Count files in this chatroom directory
                count_result = self._shell_cmd(
                    f'find {content_path}{dir_name}/ -type f 2>/dev/null | wc -l'
                )
                file_count = 0
                if count_result:
                    try:
                        file_count = int(count_result.strip())
                    except ValueError:
                        pass

                # Get first and last file timestamps
                first_file = self._shell_cmd(
                    f'find {content_path}{dir_name}/ -type f -exec stat -c "%Y" {{}} \\; 2>/dev/null | sort -n | head -1'
                )
                last_file = self._shell_cmd(
                    f'find {content_path}{dir_name}/ -type f -exec stat -c "%Y" {{}} \\; 2>/dev/null | sort -n | tail -1'
                )

                room_info = {
                    'chatroom_id': dir_name,
                    'file_count': file_count,
                    'last_modified': date_str,
                }
                if first_file and first_file.strip().isdigit():
                    try:
                        room_info['earliest_activity'] = datetime.utcfromtimestamp(
                            int(first_file.strip())
                        ).isoformat()
                    except (ValueError, OSError):
                        pass
                if last_file and last_file.strip().isdigit():
                    try:
                        room_info['latest_activity'] = datetime.utcfromtimestamp(
                            int(last_file.strip())
                        ).isoformat()
                    except (ValueError, OSError):
                        pass

                chatrooms.append(room_info)

        # For KakaoTalk, also scan nested Mg== directory
        if package == 'com.kakao.talk':
            nested_result = self._shell_cmd(
                f'ls {content_path}Mg==/ 2>/dev/null'
            )
            if nested_result:
                for dir_name in nested_result.strip().split('\n'):
                    dir_name = dir_name.strip()
                    if not dir_name:
                        continue
                    count_result = self._shell_cmd(
                        f'find {content_path}Mg==/{dir_name}/ -type f 2>/dev/null | wc -l'
                    )
                    file_count = 0
                    if count_result:
                        try:
                            file_count = int(count_result.strip())
                        except ValueError:
                            pass

                    chatrooms.append({
                        'chatroom_id': dir_name,
                        'chatroom_type': 'Mg== (group)',
                        'file_count': file_count,
                    })

        metadata['chatrooms'] = chatrooms
        metadata['chatroom_count'] = len(chatrooms)
        metadata['total_files'] = sum(r.get('file_count', 0) for r in chatrooms)

        return metadata

    def _extract_chatroom_id(self, file_path: str, package: str) -> Optional[str]:
        """
        Extract chatroom ID from a file path based on messenger-specific patterns.

        KakaoTalk: /sdcard/Android/data/com.kakao.talk/contents/Mg==/123456789/xx/hash
                   → chatroom_id = "123456789"
        WhatsApp:  /sdcard/Android/media/com.whatsapp/WhatsApp/Media/group_name/
                   → chatroom_id = "group_name"
        """
        if package == 'com.kakao.talk':
            # Pattern: contents/<type>/<chatroom_id>/<hash_prefix>/<hash>
            if '/contents/' in file_path:
                parts = file_path.split('/contents/')
                if len(parts) > 1:
                    segments = parts[1].split('/')
                    if len(segments) >= 2:
                        # If first segment is "Mg==", chatroom is second
                        if segments[0] == 'Mg==' and len(segments) >= 3:
                            return segments[1]
                        else:
                            return segments[0]
        elif package == 'com.whatsapp':
            if '/Media/' in file_path:
                parts = file_path.split('/Media/')
                if len(parts) > 1:
                    segments = parts[1].split('/')
                    if segments:
                        return segments[0]

        return None

    def create_backup(
        self,
        output_path: Optional[str] = None,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Create ADB backup of device.

        Note: ADB backup requires user interaction on the device.
        This method uses a shell-based approach since adb-shell library
        doesn't directly support the backup command.

        Args:
            output_path: Path for backup file
            progress_callback: Progress callback

        Returns:
            Tuple of (backup_path, metadata)
        """
        if not self.device_info:
            raise RuntimeError("Not connected to device")

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"android_backup_{self.device_info.serial}_{timestamp}.ab"
        backup_path = Path(output_path) if output_path else self.output_dir / backup_filename

        if progress_callback:
            progress_callback("Creating ADB backup (user confirmation required on device)...")

        # Note: Full device backup requires the adb backup command which isn't
        # directly supported by adb-shell library. We collect individual artifacts instead.
        # This is a limitation of USB-only mode.
        return '', {
            'artifact_type': 'android_backup',
            'status': 'not_supported',
            'error': 'Full device backup not supported in USB-only mode. Use individual artifact collection instead.',
            'device_serial': self.device_info.serial,
            'recommended_alternative': 'Collect individual artifact types (sms, call, contacts, etc.) instead.',
        }

    def get_available_artifacts(self) -> List[Dict[str, Any]]:
        """Get list of available Android artifact types"""
        artifacts = []
        is_rooted = self.device_info.rooted if self.device_info else False

        for type_id, info in ANDROID_ARTIFACT_TYPES.items():
            available = True
            reasons = []

            # Dual-mode apps: always available (auto-adapts to root status)
            is_dual_mode = 'root' in info and 'nonroot' in info
            requires_root = info.get('requires_root', False)

            if requires_root and not is_rooted and not is_dual_mode:
                available = False
                reasons.append('Root access required')

            mode = 'dual' if is_dual_mode else ('root' if requires_root else 'nonroot')
            if is_dual_mode and not is_rooted:
                mode = 'nonroot (auto-fallback)'

            artifacts.append({
                'type': type_id,
                'name': info['name'],
                'description': info.get('description', ''),
                'available': available,
                'reasons': reasons,
                'requires_root': requires_root and not is_dual_mode,
                'mode': mode,
            })

        return artifacts

    # ==========================================================================
    # Screen Scraping (Non-Root Accessibility Service)
    # ==========================================================================

    # Agent APK 경로 (collector/resources/agent_apk/)
    AGENT_APK_PATH = Path(__file__).parent.parent.parent / 'resources' / 'agent_apk' / 'ForensicAgent.apk'
    AGENT_APK_VERSION_PATH = Path(__file__).parent.parent.parent / 'resources' / 'agent_apk' / 'version.txt'
    AGENT_PACKAGE = 'com.unjaena.agent'
    AGENT_RECEIVER = f'{AGENT_PACKAGE}/.receiver.CommandReceiver'

    # Polling interval for scraping completion (seconds)
    SCRAPING_POLL_INTERVAL = 5
    SCRAPING_MAX_WAIT = 1800  # 30 minutes

    # Agent result paths on device
    AGENT_RESULT_DIR = f'/sdcard/Android/data/{AGENT_PACKAGE}/files/results'
    AGENT_MANIFEST_FILE = f'{AGENT_RESULT_DIR}/result_manifest.json'

    def _check_screen_unlocked(self) -> bool:
        """
        Check if device screen is ON and UNLOCKED.

        Uses 'dumpsys power' to detect:
          - mWakefulness=Awake  → screen is on
          - mHoldingDisplaySuspendBlocker=true → display active
        Uses 'dumpsys window' to detect:
          - mDreamingLockscreen=false or mShowingLockscreen=false → unlocked

        Returns True only when screen is on AND unlocked.
        """
        try:
            power_output = self._shell_cmd('dumpsys power | grep -E "mWakefulness|mHoldingDisplaySuspendBlocker"')
            _debug_print(f'[SCRAPE] Power state: {power_output.strip()}')

            # Check screen is awake
            screen_on = 'Awake' in power_output

            if not screen_on:
                _debug_print('[SCRAPE] Screen is OFF (mWakefulness != Awake)')
                return False

            # Check screen is unlocked via window policy
            window_output = self._shell_cmd(
                'dumpsys window | grep -E "mDreamingLockscreen|mShowingLockscreen|isStatusBarKeyguard|showing="'
            )
            _debug_print(f'[SCRAPE] Window state: {window_output.strip()}')

            # Any of these indicate the lock screen is showing
            locked = (
                'mDreamingLockscreen=true' in window_output
                or 'mShowingLockscreen=true' in window_output
                or 'isStatusBarKeyguard=true' in window_output
            )

            if locked:
                _debug_print('[SCRAPE] Screen is ON but LOCKED')
                return False

            _debug_print('[SCRAPE] Screen is ON and UNLOCKED')
            return True

        except Exception as e:
            _debug_print(f'[SCRAPE] Screen state check failed: {e}')
            # On failure, assume not ready (safer than proceeding blind)
            return False

    def _collect_screen_scrape(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Screen scraping collection via Agent APK.

        Workflow:
        1. Install/update Agent APK on device
        2. Request scraping session from server (get scraping_token)
        3. Launch Agent via ADB broadcast (pass server_url + token)
        4. Poll for completion (check result_manifest.json)
        5. Pull results via ADB
        6. Clean up device results

        Args:
            artifact_type: Artifact type identifier
            artifact_info: Artifact configuration
            output_dir: Local output directory
            progress_callback: Progress callback function
        """
        if not self.device_info:
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': 'Not connected to device',
            }
            return

        try:
            # Step 0: Check device screen is ON and UNLOCKED
            # Screen scraping requires Accessibility Service to navigate app UI,
            # which only works when the device is unlocked with screen on.
            if progress_callback:
                progress_callback('Checking device screen state...')

            screen_ready = self._check_screen_unlocked()
            if not screen_ready:
                _debug_print('[SCRAPE] Device screen is off or locked — cannot proceed')
                yield '', {
                    'artifact_type': artifact_type,
                    'status': 'error',
                    'error': (
                        'Screen Scraping requires the device screen to be ON and UNLOCKED. '
                        'Please unlock the device and retry collection.'
                    ),
                }
                return

            # Step 1: Install/update Agent APK
            if progress_callback:
                progress_callback('Installing Agent APK...')

            apk_installed = self._install_agent_apk(progress_callback)
            if not apk_installed:
                yield '', {
                    'artifact_type': artifact_type,
                    'status': 'error',
                    'error': 'Failed to install Agent APK',
                }
                return

            # Step 2: Enable Accessibility Service
            if progress_callback:
                progress_callback('Enabling Accessibility Service...')

            self._enable_accessibility_service(progress_callback)

            # Step 3: Get installed apps for collection profile matching (서버에서 지원 목록 동적 조회)
            supported_packages = self._get_supported_packages()
            if not supported_packages:
                yield '', {
                    'artifact_type': artifact_type,
                    'status': 'error',
                    'error': 'Cannot retrieve supported apps from server',
                }
                return
            installed_apps = self._get_installed_apps_for_scraping(supported_packages)
            if not installed_apps:
                yield '', {
                    'artifact_type': artifact_type,
                    'status': 'error',
                    'error': 'No supported apps installed on device',
                }
                return

            # Step 4: Request scraping session from server
            if progress_callback:
                progress_callback('Requesting scraping session...')

            session_info = self._request_scraping_session(installed_apps)
            if not session_info:
                yield '', {
                    'artifact_type': artifact_type,
                    'status': 'error',
                    'error': 'Failed to create scraping session (server unreachable or no collection profiles available)',
                }
                return

            scraping_token = session_info.get('scraping_token', '')
            available_apps = session_info.get('available_apps', [])

            if not available_apps:
                if progress_callback:
                    progress_callback('No collection profiles available for installed apps')
                yield '', {
                    'artifact_type': artifact_type,
                    'status': 'skipped',
                    'error': 'No collection profiles available for installed apps',
                }
                return

            # Step 5: Launch Agent APK via broadcast
            if progress_callback:
                progress_callback(f'Starting scraping ({len(available_apps)} apps)...')

            target_packages = [app['package'] for app in available_apps]
            self._start_agent_scraping(
                scraping_token=scraping_token,
                session_id=session_info.get('session_id', ''),
                target_apps=target_packages,
            )

            # Step 6: Poll for completion
            if progress_callback:
                progress_callback('Waiting for scraping to complete...')

            completed = self._wait_for_scraping_completion(
                session_id=session_info.get('session_id', ''),
                progress_callback=progress_callback,
            )

            if not completed:
                yield '', {
                    'artifact_type': artifact_type,
                    'status': 'error',
                    'error': 'Scraping timed out or failed',
                }
                return

            # Step 7: Pull results from device
            if progress_callback:
                progress_callback('Pulling scraping results...')

            pulled_files = self._pull_scraping_results(output_dir)

            for local_path in pulled_files:
                yield str(local_path), {
                    'artifact_type': artifact_type,
                    'original_path': f'{self.AGENT_RESULT_DIR}/{Path(local_path).name}',
                    'status': 'success',
                    'device': self.device_info.serial,
                    'model': self.device_info.model,
                    'collection_method': 'screen_scrape',
                    'scraped_apps': target_packages,
                    'file_count': len(pulled_files),
                }

            # Step 8: Clean up device results
            self._cleanup_device_results()

            # Step 9: [보안] Agent APK 제거 (포렌식 원칙: 디바이스 최소 수정)
            if progress_callback:
                progress_callback('Removing Agent APK from device...')
            self._uninstall_agent_apk()

            if progress_callback:
                progress_callback(f'Screen scraping complete: {len(pulled_files)} files')

        except Exception as e:
            _debug_print(f'[SCRAPE] Error: {e}')
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': str(e),
            }

    def _install_agent_apk(
        self, progress_callback: Optional[Callable[[str], None]] = None
    ) -> bool:
        """
        Install or update Agent APK on device.

        Returns True if installation succeeded.
        """
        if not self.AGENT_APK_PATH.exists():
            _debug_print(f'[SCRAPE] Agent APK not found: {self.AGENT_APK_PATH}')
            return False

        # [보안] APK 무결성 검증 (SHA256)
        hash_file = self.AGENT_APK_PATH.with_suffix('.apk.sha256')
        if hash_file.exists():
            expected = hash_file.read_text().strip().split()[0].lower()
            sha256 = hashlib.sha256()
            with open(self.AGENT_APK_PATH, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)
            if sha256.hexdigest() != expected:
                _debug_print('[SCRAPE] APK integrity check FAILED — possible tampering')
                if progress_callback:
                    progress_callback('Agent APK integrity check failed')
                return False
            _debug_print('[SCRAPE] APK integrity verified')

        try:
            # Check if already installed
            output, rc = self._adb_shell(
                f'dumpsys package {self.AGENT_PACKAGE} | grep versionName'
            )
            installed_version = output.strip()

            # Read bundled version
            bundled_version = ''
            if self.AGENT_APK_VERSION_PATH.exists():
                bundled_version = self.AGENT_APK_VERSION_PATH.read_text().strip()

            if installed_version and bundled_version:
                # Extract version from dumpsys output (e.g., "    versionName=1.0.0")
                current = installed_version.split('=')[-1].strip() if '=' in installed_version else ''
                if current == bundled_version:
                    _debug_print(f'[SCRAPE] Agent APK already up to date: v{current}')
                    return True

            # Install APK (replace existing) via system adb
            if progress_callback:
                progress_callback('Installing Agent APK on device...')

            output, rc = self._run_system_adb(
                ['install', '-r', str(self.AGENT_APK_PATH)], timeout=120
            )
            if rc == 0 and 'Success' in output:
                _debug_print(f'[SCRAPE] Agent APK installed successfully')
                return True
            else:
                _debug_print(f'[SCRAPE] APK install result: {output}')
                return False

        except Exception as e:
            _debug_print(f'[SCRAPE] APK install error: {e}')
            return False

    def _uninstall_agent_apk(self):
        """수집 완료 후 Agent APK 제거 + ADB reverse 해제 (포렌식 원칙: 디바이스 최소 수정)"""
        try:
            output, rc = self._run_system_adb(
                ['uninstall', self.AGENT_PACKAGE], timeout=30
            )
            if rc == 0 and 'Success' in output:
                _debug_print('[SCRAPE] Agent APK uninstalled')
            else:
                _debug_print(f'[SCRAPE] APK uninstall: {output.strip()}')
        except Exception as e:
            _debug_print(f'[SCRAPE] APK uninstall error: {e}')

        # Remove ADB reverse port forwarding
        try:
            self._run_system_adb(['reverse', '--remove-all'], timeout=10)
            _debug_print('[SCRAPE] ADB reverse proxy removed')
        except Exception:
            pass

    def _enable_accessibility_service(
        self, progress_callback: Optional[Callable[[str], None]] = None
    ):
        """
        Attempt to enable Accessibility Service via ADB settings.

        If ADB method fails (common on locked devices), the GUI should
        display manual instructions.
        """
        service_name = f'{self.AGENT_PACKAGE}/{self.AGENT_PACKAGE}.service.ScrapingAccessibilityService'

        try:
            # Try ADB settings put
            output, rc = self._adb_shell(
                'settings get secure enabled_accessibility_services'
            )
            current = output.strip()

            if service_name in current:
                _debug_print('[SCRAPE] Accessibility service already enabled')
                return

            # Append our service to existing ones
            if current and current != 'null':
                new_value = f'{current}:{service_name}'
            else:
                new_value = service_name

            self._adb_shell(
                f'settings put secure enabled_accessibility_services {new_value}'
            )
            self._adb_shell(
                'settings put secure accessibility_enabled 1'
            )
            _debug_print('[SCRAPE] Accessibility service enabled via ADB')

        except Exception as e:
            _debug_print(f'[SCRAPE] Could not enable accessibility via ADB: {e}')
            if progress_callback:
                progress_callback(
                    'Please enable Accessibility Service manually: '
                    'Settings > Accessibility > Installed Services > ForensicAgent'
                )

    def _get_installed_apps_for_scraping(
        self, supported_packages: List[str]
    ) -> List[Dict[str, str]]:
        """Get installed apps that match supported packages, with version info."""
        installed = []
        for package in supported_packages:
            try:
                output, rc = self._adb_shell(
                    f'dumpsys package {package} | grep -E "versionName|versionCode"'
                )
                output = output.strip()

                if 'versionName' in output:
                    version_name = ''
                    version_code = ''
                    for line in output.split('\n'):
                        line = line.strip()
                        if 'versionName=' in line:
                            version_name = line.split('=')[-1].strip()
                        elif 'versionCode=' in line:
                            version_code = line.split('=')[1].strip().split()[0]

                    installed.append({
                        'package': package,
                        'version_name': version_name,
                        'version_code': version_code,
                    })
            except Exception:
                pass

        return installed

    def _get_supported_packages(self) -> List[str]:
        """서버에서 지원 앱 패키지 목록 동적 조회 (역공학 시 지원 범위 노출 방지)"""
        try:
            import urllib.request
            import urllib.error

            server_url = getattr(self, '_server_url', '')
            collection_token = getattr(self, '_collection_token', '')
            if not server_url or not collection_token:
                _debug_print('[SCRAPE] No server_url or collection_token for supported apps query')
                return []

            url = f'{server_url}/api/v1/collector/scraping/supported-apps'
            _debug_print(f'[SCRAPE] Supported apps GET → {url}')
            req = urllib.request.Request(url, headers={
                'Authorization': f'Bearer {collection_token}',
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                packages = data.get('supported_packages', [])
                _debug_print(f'[SCRAPE] Supported packages from server: {len(packages)}')
                return packages
        except Exception as e:
            _debug_print(f'[SCRAPE] Failed to get supported apps: {e}')
            return []

    def _request_scraping_session(
        self, installed_apps: List[Dict[str, str]]
    ) -> Optional[Dict[str, Any]]:
        """
        Request scraping session from server.

        Uses the existing uploader's server URL and collection token.
        Returns session info with scraping_token and available_apps.
        """
        try:
            import urllib.request
            import urllib.error

            # Get server URL and token from uploader config
            server_url = getattr(self, '_server_url', None)
            collection_token = getattr(self, '_collection_token', None)
            case_id = getattr(self, '_case_id', None)
            session_id = getattr(self, '_session_id', None)

            if not server_url or not collection_token:
                _debug_print('[SCRAPE] Server URL or collection token not configured')
                return None

            # Device fingerprint = Agent APK's SHA256(ANDROID_ID)
            # Android 8+ assigns per-app ANDROID_ID, so we must query the Agent
            device_fingerprint = self._get_agent_fingerprint()
            if not device_fingerprint:
                # Fallback: shell ANDROID_ID (may differ from Agent's)
                android_id_out, _ = self._adb_shell(
                    'settings get secure android_id'
                )
                android_id = android_id_out.strip()
                device_fingerprint = hashlib.sha256(android_id.encode()).hexdigest()
                _debug_print('[SCRAPE] WARNING: Using shell ANDROID_ID (may mismatch Agent)')

            # Device serial hash
            device_serial_hash = hashlib.sha256(
                self.device_info.serial.encode()
            ).hexdigest()

            # Request body
            body = json.dumps({
                'case_id': case_id or 'unknown',
                'session_id': session_id or f'scrp_sess_{int(time.time())}',
                'device_serial_hash': device_serial_hash,
                'installed_apps': installed_apps,
                'android_version': self.device_info.sdk_version,
                'device_fingerprint': device_fingerprint,
            }).encode()

            url = f'{server_url}/api/v1/collector/scraping/session'
            _debug_print(f'[SCRAPE] Session POST → {url}')
            req = urllib.request.Request(
                url,
                data=body,
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {collection_token}',
                },
                method='POST',
            )

            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())

            # Store device_fingerprint for later use by Agent
            self._device_fingerprint = device_fingerprint

            result['session_id'] = session_id or result.get('session_id', '')
            return result

        except Exception as e:
            _debug_print(f'[SCRAPE] Session request error: {e}')
            return None

    def _get_agent_fingerprint(self) -> Optional[str]:
        """
        Query Agent APK's device fingerprint.

        Android 8+ assigns per-app ANDROID_ID, so the Agent's fingerprint
        (SHA256 of its own ANDROID_ID) differs from shell's.
        We trigger a broadcast to have the Agent write its fingerprint to a file,
        then read it via adb shell cat.
        """
        try:
            AGENT_PKG = getattr(self, 'AGENT_PACKAGE', 'com.unjaena.agent')
            AGENT_FP_PATH = f'/sdcard/Android/data/{AGENT_PKG}/files/device_fingerprint.txt'

            # Trigger Agent to write fingerprint
            cmd = (
                'am broadcast '
                '-a com.unjaena.agent.ACTION_GET_FINGERPRINT '
                f'-n {self.AGENT_RECEIVER}'
            )
            self._adb_shell(cmd)
            time.sleep(1)  # Wait for Agent to write file

            # Read fingerprint file
            output, rc = self._adb_shell(f'cat {shlex.quote(AGENT_FP_PATH)}')
            fp = output.strip()

            if len(fp) == 64 and all(c in '0123456789abcdef' for c in fp):
                _debug_print(f'[SCRAPE] Agent fingerprint: {fp[:16]}...')
                return fp
            else:
                _debug_print(f'[SCRAPE] Invalid fingerprint from Agent: {fp[:50]}')
                return None

        except Exception as e:
            _debug_print(f'[SCRAPE] Failed to get Agent fingerprint: {e}')
            return None

    def _start_agent_scraping(
        self,
        scraping_token: str,
        session_id: str,
        target_apps: List[str],
    ):
        """Launch Agent APK scraping via ADB broadcast."""
        server_url = getattr(self, '_server_url', '')
        target_str = ','.join(target_apps)

        # Setup ADB reverse port forwarding so Agent can reach PC's server
        # Agent runs on-device: 127.0.0.1:PORT on device → PC's 127.0.0.1:PORT
        try:
            from urllib.parse import urlparse
            parsed = urlparse(server_url)
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            reverse_cmd = f'reverse tcp:{port} tcp:{port}'
            self._run_system_adb(['reverse', f'tcp:{port}', f'tcp:{port}'], timeout=10)
            _debug_print(f'[SCRAPE] ADB reverse proxy: device:{port} → PC:{port}')
        except Exception as e:
            _debug_print(f'[SCRAPE] ADB reverse setup failed (non-fatal): {e}')

        # [보안] 토큰을 파일로 전달 (broadcast extras 노출 방지)
        # logcat ActivityManager 로그에 토큰이 평문으로 기록되는 것을 방지
        token_path = f'/sdcard/Android/data/{self.AGENT_PACKAGE}/files/.scraping_token'
        token_dir = f'/sdcard/Android/data/{self.AGENT_PACKAGE}/files'
        self._adb_shell(f'mkdir -p {shlex.quote(token_dir)}')
        self._adb_shell(f"echo {shlex.quote(scraping_token)} > {shlex.quote(token_path)}")

        # Agent APK appends /scraping/profiles, /scraping/status to server_url.
        # Server routes are at /api/v1/collector/scraping/*, so we pass the
        # base URL including the prefix so Agent hits the correct endpoints.
        agent_server_url = f"{server_url.rstrip('/')}/api/v1/collector"

        # Send broadcast to CommandReceiver (토큰은 파일로 전달, broadcast에 미포함)
        cmd = (
            f'am broadcast '
            f'-a com.unjaena.agent.ACTION_START_SCRAPING '
            f'-n {self.AGENT_RECEIVER} '
            f'--es server_url {shlex.quote(agent_server_url)} '
            f'--es session_id {shlex.quote(session_id)} '
            f'--es target_apps {shlex.quote(target_str)}'
        )
        output, rc = self._adb_shell(cmd)

        # Clear logcat buffer so _wait_for_scraping_completion doesn't
        # pick up stale error messages from previous runs
        try:
            self._run_system_adb(['logcat', '-c'], timeout=5)
        except Exception:
            pass

        _debug_print(f'[SCRAPE] Broadcast sent (token via file, logcat cleared)')

    def _wait_for_scraping_completion(
        self,
        session_id: str,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> bool:
        """
        Poll for scraping completion.

        Checks both device-side manifest and server-side status.
        Returns True if scraping completed successfully.
        """
        start_time = time.time()

        while time.time() - start_time < self.SCRAPING_MAX_WAIT:
            # Check device-side manifest
            try:
                manifest_out, _ = self._adb_shell(
                    f'cat {self.AGENT_MANIFEST_FILE} 2>/dev/null'
                )
                manifest_content = manifest_out.strip()

                if manifest_content and manifest_content != '':
                    try:
                        manifest = json.loads(manifest_content)
                        status = manifest.get('status', '')
                        if status in ('completed', 'error'):
                            total_records = manifest.get('total_records', 0)
                            if progress_callback:
                                progress_callback(
                                    f'Scraping {status}: {total_records} records collected'
                                )
                            return status == 'completed'
                    except json.JSONDecodeError:
                        pass

            except Exception:
                pass

            # Check Agent logcat for fatal errors (profile download failure, crash, etc.)
            try:
                logcat_out, _ = self._adb_shell(
                    f'logcat -d -t 20 -s RecipeExecutor RecipeDownloader 2>/dev/null'
                )
                if logcat_out and ('Failed to download collection profiles' in logcat_out
                                   or 'FATAL EXCEPTION' in logcat_out):
                    _debug_print(f'[SCRAPE] Agent error detected in logcat')
                    if progress_callback:
                        progress_callback('Screen scraping failed: Agent cannot reach server')
                    return False
            except Exception:
                pass

            # Progress update
            elapsed = int(time.time() - start_time)
            if progress_callback and elapsed % 30 == 0:
                progress_callback(f'Scraping in progress... ({elapsed}s elapsed)')

            time.sleep(self.SCRAPING_POLL_INTERVAL)

        _debug_print('[SCRAPE] Scraping timed out')
        return False

    def _pull_scraping_results(self, output_dir: Path) -> List[Path]:
        """Pull all JSONL result files from device to local output directory."""
        pulled = []
        try:
            # List result files
            listing_out, _ = self._adb_shell(f'ls {shlex.quote(self.AGENT_RESULT_DIR + "/")} 2>/dev/null')
            listing = listing_out.strip()
            if not listing:
                return pulled

            for filename in listing.split('\n'):
                filename = filename.strip()
                if not filename or filename == 'result_manifest.json':
                    continue

                if filename.endswith('.jsonl') or filename.endswith('.json'):
                    remote_path = f'{self.AGENT_RESULT_DIR}/{filename}'
                    local_path = output_dir / filename

                    success = self._adb_pull(remote_path, str(local_path))
                    if success:
                        pulled.append(local_path)
                        _debug_print(f'[SCRAPE] Pulled: {filename}')

            # Also pull manifest
            manifest_local = output_dir / 'result_manifest.json'
            success = self._adb_pull(self.AGENT_MANIFEST_FILE, str(manifest_local))
            if success and manifest_local.exists():
                pulled.append(manifest_local)

        except Exception as e:
            _debug_print(f'[SCRAPE] Pull error: {e}')

        return pulled

    def _cleanup_device_results(self):
        """Remove scraping results from device."""
        try:
            output, rc = self._adb_shell(f'rm -rf {shlex.quote(self.AGENT_RESULT_DIR)}/*')
            _debug_print('[SCRAPE] Device results cleaned up')
        except Exception as e:
            _debug_print(f'[SCRAPE] Cleanup error: {e}')


def check_usb_debugging_guide() -> str:
    """Return USB debugging enable guide"""
    return """
How to enable Android USB debugging:

1. Go to Settings > About phone > Tap Build number 7 times
   - Confirm message "Developer mode has been enabled"

2. Go to Settings > System > Developer options
   - Or Settings > Developer options (varies by device)

3. Enable "USB debugging" option

4. Connect to PC via USB cable

5. When prompted "Allow USB debugging for this computer?", select "Allow"
   - Recommended: Check "Always allow from this computer"

6. Verify device connection in Collector

Troubleshooting:
- If device is not recognized, USB driver installation required
- OEM USB driver: Download from manufacturer website
- Google USB driver: Included in Android SDK
"""


if __name__ == "__main__":
    print("Android Forensics Collector (USB Direct Mode)")
    print("=" * 50)

    print("\n[USB Status]")
    print(f"  USB Libraries Available: {USB_AVAILABLE}")

    if not USB_AVAILABLE:
        print("\n[Error] USB libraries not available.")
        print("Install required packages:")
        print("  pip install adb-shell[usb] libusb1")
        print("\nPlatform-specific requirements:")
        print("  - Windows: libusb-1.0.dll required")
        print("  - Linux: sudo apt-get install libusb-1.0-0")
        print("  - macOS: brew install libusb")
    else:
        usb_ok = check_usb_available()
        print(f"  libusb Accessible: {usb_ok}")

        if usb_ok:
            monitor = ADBDeviceMonitor()
            devices = monitor.get_connected_devices()

            print(f"\n[Connected Devices: {len(devices)}]")
            for device in devices:
                # [SECURITY] Mask device serial (only show last 8 chars)
                masked_serial = f"...{device.serial[-8:]}" if len(device.serial) > 8 else device.serial
                print(f"  - {masked_serial}")
                print(f"    Model: {device.model}")
                print(f"    Manufacturer: {device.manufacturer}")
                print(f"    Android: {device.android_version} (SDK {device.sdk_version})")
                print(f"    USB Debugging: {device.usb_debugging}")
                print(f"    Rooted: {device.rooted}")
                if device.vendor_id:
                    print(f"    USB ID: {device.vendor_id:04x}:{device.product_id:04x}")

            if not devices:
                print("\n[USB Debugging Guide]")
                print(check_usb_debugging_guide())
        else:
            print("\n[Error] Cannot access USB devices.")
            print("Check libusb installation and permissions.")
