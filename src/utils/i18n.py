# -*- coding: utf-8 -*-
"""
Strings Module for Collector (English Only)

All UI strings in one place for consistency.
"""

from typing import Dict


# =============================================================================
# UI Strings (English Only)
# =============================================================================

STRINGS: Dict[str, str] = {
    # -------------------------------------------------------------------------
    # Open Source License Notices
    # -------------------------------------------------------------------------
    'license_notice_title': 'Open Source License Notice',

    # pymobiledevice3 (GPL-3.0)
    'pymobiledevice3_notice': (
        'iOS USB direct connection uses pymobiledevice3 library.\n\n'
        '  License: GPL-3.0 (GNU General Public License v3)\n'
        '  Project: https://github.com/doronz88/pymobiledevice3\n'
        '  Authors: Hector Martin, Mathieu Renard, doronz88, matan1008, et al.\n\n'
        'This software uses pymobiledevice3 under GPL-3.0 license terms.\n'
        'Source code available at: https://github.com/doronz88/pymobiledevice3'
    ),
    'pymobiledevice3_available': 'pymobiledevice3 available',
    'pymobiledevice3_not_found': 'pymobiledevice3 not installed',

    # License Info dialog text
    'ios_license_notice': (
        '=== iOS Collection Library ===\n\n'
        'pymobiledevice3\n'
        '    License: GPL-3.0 (GNU General Public License v3)\n'
        '    Project: https://github.com/doronz88/pymobiledevice3\n'
        '    Authors: Hector Martin, Mathieu Renard, doronz88, matan1008, et al.\n\n'
        'Features:\n'
        '    • Pure Python implementation (no external binaries)\n'
        '    • iTunes-free backup creation\n'
        '    • Device information retrieval\n'
        '    • System log collection\n'
        '    • Crash reports extraction\n'
        '    • Installed apps listing\n'
        '    • AFC file system access\n\n'
        'This collector is open source and complies with GPL-3.0 license requirements.\n'
        'Install: pip install pymobiledevice3'
    ),

    # -------------------------------------------------------------------------
    # iOS Tab Labels
    # -------------------------------------------------------------------------
    'ios_usb_device': 'USB Connected Device',
    'ios_backup': 'iTunes/Finder Backup',
    'ios_select_device': '-- Select Device --',
    'ios_select_backup': '-- Select Backup --',
    'ios_no_device': 'No USB device connected',
    'ios_no_backup': 'No backup selected',
    'ios_device_locked': 'Device locked (enter passcode)',
    'ios_backup_encrypted': '[Encrypted]',

    # -------------------------------------------------------------------------
    # iOS Guide
    # -------------------------------------------------------------------------
    'ios_guide_usb': 'USB: Connect iPhone/iPad via USB and tap "Trust" on device',
    'ios_guide_backup': 'Backup: iTunes/Finder > "Back Up Now" (unencrypted)',

    # -------------------------------------------------------------------------
    # General
    # -------------------------------------------------------------------------
    'refresh': 'Refresh',
    'license_info': 'License Info',
    'close': 'Close',
    'devices_connected': '{count} device(s) connected',
    'backups_found': '{count} backup(s) found',
}


# =============================================================================
# String Access Function
# =============================================================================

def t(key: str, **kwargs) -> str:
    """
    Get a UI string.

    Args:
        key: String key
        **kwargs: Format arguments

    Returns:
        The string value

    Example:
        >>> t('devices_connected', count=3)
        '3 device(s) connected'
    """
    text = STRINGS.get(key, key)

    if kwargs:
        try:
            text = text.format(**kwargs)
        except KeyError:
            pass

    return text
