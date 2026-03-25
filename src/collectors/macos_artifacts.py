# -*- coding: utf-8 -*-
"""
macOS Artifact Definitions - macOS System Artifact Collection Definitions

Defines macOS system artifact collection filters for digital forensics.
Includes all major artifacts collectable from APFS/HFS+ file systems.

Categories:
1. System Logs
2. User Activity
3. Launch Items
4. Network
5. Applications
6. Security
7. Browser
8. Persistence

Usage:
    from collectors.macos_artifacts import MACOS_ARTIFACT_FILTERS

    for artifact_id, config in MACOS_ARTIFACT_FILTERS.items():
        paths = config['paths']
        description = config['description']
        forensic_value = config['forensic_value']
"""

from typing import Dict, List, Any

# ==============================================================================
# macOS Artifact Filter Definitions
# ==============================================================================

MACOS_ARTIFACT_FILTERS: Dict[str, Dict[str, Any]] = {

    # ==========================================================================
    # System Logs
    # ==========================================================================

    'macos_unified_log': {
        'paths': [
            '/var/db/diagnostics/*.tracev3',
            '/var/db/diagnostics/Persist/*.tracev3',
            '/var/db/uuidtext/*',
        ],
        'description': 'Unified Logging System (macOS 10.12+)',
        'forensic_value': 'critical',
        'category': 'system_logs',
        'os_type': 'macos',
        'note': 'Parsing required via log show command',
    },

    'macos_system_log': {
        'paths': [
            '/var/log/system.log',
            '/var/log/system.log.*.gz',
        ],
        'description': 'System log (legacy)',
        'forensic_value': 'high',
        'category': 'system_logs',
        'os_type': 'macos',
    },

    'macos_install_log': {
        'paths': [
            '/var/log/install.log',
        ],
        'description': 'Installation log',
        'forensic_value': 'high',
        'category': 'system_logs',
        'os_type': 'macos',
    },

    'macos_asl_logs': {
        'paths': [
            '/var/log/asl/*.asl',
        ],
        'description': 'Apple System Log (legacy)',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'macos',
    },

    'macos_crash_reports': {
        'paths': [
            '/Library/Logs/DiagnosticReports/*.crash',
            '/Library/Logs/DiagnosticReports/*.diag',
            '/Users/*/Library/Logs/DiagnosticReports/*.crash',
        ],
        'description': 'Application crash reports',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'macos',
    },

    'macos_audit_logs': {
        'paths': [
            '/var/audit/*',
        ],
        'description': 'BSM Audit log',
        'forensic_value': 'critical',
        'category': 'security',
        'os_type': 'macos',
    },

    # ==========================================================================
    # User Activity
    # ==========================================================================

    'macos_bash_history': {
        'paths': [
            '/Users/*/.bash_history',
            '/var/root/.bash_history',
        ],
        'description': 'Bash command history',
        'forensic_value': 'critical',
        'category': 'user_activity',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_zsh_history': {
        'paths': [
            '/Users/*/.zsh_history',
            '/var/root/.zsh_history',
        ],
        'description': 'Zsh command history (Catalina+)',
        'forensic_value': 'critical',
        'category': 'user_activity',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_recent_items': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.recentitems.plist',
        ],
        'description': 'Recent items',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'macos',
    },

    'macos_finder_plist': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.finder.plist',
        ],
        'description': 'Finder settings and recent folders',
        'forensic_value': 'medium',
        'category': 'user_activity',
        'os_type': 'macos',
    },

    'macos_spotlight_shortcuts': {
        'paths': [
            '/Users/*/Library/Application Support/com.apple.spotlight.Shortcuts',
        ],
        'description': 'Spotlight search history',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'macos',
    },

    'macos_trash': {
        'paths': [
            '/Users/*/.Trash/*',
            '/Users/*/.Trash/.DS_Store',
        ],
        'description': 'Trash contents',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'macos',
    },

    'macos_knowledgec': {
        'paths': [
            '/Users/*/Library/Application Support/Knowledge/knowledgeC.db',
            '/private/var/db/CoreDuet/Knowledge/knowledgeC.db',
        ],
        'description': 'KnowledgeC user activity database',
        'forensic_value': 'critical',
        'category': 'user_activity',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_quicklook': {
        'paths': [
            '/Users/*/Library/Caches/com.apple.QuickLook.thumbnailcache/*',
            '/private/var/folders/*/*/C/com.apple.QuickLook.thumbnailcache/*',
        ],
        'description': 'QuickLook thumbnail cache',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'macos',
    },

    'macos_downloads': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2',
        ],
        'description': 'Download quarantine records',
        'forensic_value': 'critical',
        'category': 'user_activity',
        'os_type': 'macos',
        'path_optional': True,
    },

    # ==========================================================================
    # FSEvents (File System Events)
    # ==========================================================================

    'macos_fseventsd': {
        'paths': [
            '/.fseventsd/*',
        ],
        'description': 'FSEvents file system change log',
        'forensic_value': 'critical',
        'category': 'filesystem',
        'os_type': 'macos',
    },

    'macos_spotlight': {
        'paths': [
            '/.Spotlight-V100/*',
        ],
        'description': 'Spotlight index data',
        'forensic_value': 'high',
        'category': 'filesystem',
        'os_type': 'macos',
    },

    # ==========================================================================
    # Launch Items (Startup Items - Persistence)
    # ==========================================================================

    'macos_launch_agents_system': {
        'paths': [
            '/Library/LaunchAgents/*.plist',
            '/System/Library/LaunchAgents/*.plist',
        ],
        'description': 'System Launch Agents',
        'forensic_value': 'critical',
        'category': 'persistence',
        'os_type': 'macos',
    },

    'macos_launch_agents_user': {
        'paths': [
            '/Users/*/Library/LaunchAgents/*.plist',
        ],
        'description': 'User Launch Agents',
        'forensic_value': 'critical',
        'category': 'persistence',
        'os_type': 'macos',
    },

    'macos_launch_daemons': {
        'paths': [
            '/Library/LaunchDaemons/*.plist',
            '/System/Library/LaunchDaemons/*.plist',
        ],
        'description': 'Launch Daemons',
        'forensic_value': 'critical',
        'category': 'persistence',
        'os_type': 'macos',
    },

    'macos_login_items': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.loginitems.plist',
            '/Users/*/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm',
        ],
        'description': 'Login items',
        'forensic_value': 'critical',
        'category': 'persistence',
        'os_type': 'macos',
    },

    'macos_startup_items': {
        'paths': [
            '/Library/StartupItems/*',
        ],
        'description': 'Startup Items (legacy)',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'macos',
    },

    'macos_cron': {
        'paths': [
            '/var/at/tabs/*',
            '/usr/lib/cron/tabs/*',
        ],
        'description': 'Cron jobs',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'macos',
    },

    'macos_periodic': {
        'paths': [
            '/etc/periodic/daily/*',
            '/etc/periodic/weekly/*',
            '/etc/periodic/monthly/*',
        ],
        'description': 'Periodic scripts',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'macos',
    },

    # ==========================================================================
    # Security & Privacy
    # ==========================================================================

    'macos_tcc': {
        'paths': [
            '/Library/Application Support/com.apple.TCC/TCC.db',
            '/Users/*/Library/Application Support/com.apple.TCC/TCC.db',
        ],
        'description': 'TCC permissions database',
        'forensic_value': 'critical',
        'category': 'security',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_keychain': {
        'paths': [
            '/Users/*/Library/Keychains/login.keychain-db',
            '/Library/Keychains/System.keychain',
        ],
        'description': 'Keychain database',
        'forensic_value': 'critical',
        'category': 'security',
        'os_type': 'macos',
    },

    'macos_gatekeeper': {
        'paths': [
            '/var/db/SystemPolicy',
            '/var/db/SystemPolicyConfiguration/*',
        ],
        'description': 'Gatekeeper policy data',
        'forensic_value': 'high',
        'category': 'security',
        'os_type': 'macos',
    },

    'macos_xprotect': {
        'paths': [
            '/Library/Apple/System/Library/CoreServices/XProtect.bundle/*',
            '/var/db/xprotect/*',
        ],
        'description': 'XProtect malware definitions',
        'forensic_value': 'medium',
        'category': 'security',
        'os_type': 'macos',
    },

    # ==========================================================================
    # Network
    # ==========================================================================

    'macos_wifi': {
        'paths': [
            '/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist',
            '/Library/Preferences/com.apple.wifi.known-networks.plist',
        ],
        'description': 'Wi-Fi connection history',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'macos',
    },

    'macos_network_preferences': {
        'paths': [
            '/Library/Preferences/SystemConfiguration/preferences.plist',
            '/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist',
        ],
        'description': 'Network settings',
        'forensic_value': 'medium',
        'category': 'network',
        'os_type': 'macos',
    },

    'macos_hosts': {
        'paths': [
            '/etc/hosts',
            '/private/etc/hosts',
        ],
        'description': 'Hosts file',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'macos',
    },

    'macos_ssh': {
        'paths': [
            '/Users/*/.ssh/known_hosts',
            '/Users/*/.ssh/authorized_keys',
            '/Users/*/.ssh/config',
            '/var/root/.ssh/*',
        ],
        'description': 'SSH settings and history',
        'forensic_value': 'critical',
        'category': 'network',
        'os_type': 'macos',
        'path_optional': True,
    },
    'macos_ssh_authorized_keys': {
        'paths': ['/Users/*/.ssh/authorized_keys', '/var/root/.ssh/authorized_keys'],
        'description': 'Authorized SSH public keys (persistence)',
        'forensic_value': 'critical',
        'category': 'network',
        'os_type': 'macos',
    },
    'macos_ssh_known_hosts': {
        'paths': ['/Users/*/.ssh/known_hosts', '/var/root/.ssh/known_hosts'],
        'description': 'Previously connected SSH servers',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'macos',
    },
    'macos_at_jobs': {
        'paths': ['/var/at/tabs/*', '/private/var/at/tabs/*'],
        'description': 'Scheduled at(1) jobs (persistence)',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'macos',
    },

    # ==========================================================================
    # Browser Artifacts
    # ==========================================================================

    'macos_safari_history': {
        'paths': [
            '/Users/*/Library/Safari/History.db',
            '/Users/*/Library/Safari/History.db-wal',
        ],
        'description': 'Safari browsing history',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_safari_downloads': {
        'paths': [
            '/Users/*/Library/Safari/Downloads.plist',
        ],
        'description': 'Safari download history',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'macos',
    },

    'macos_safari_cookies': {
        'paths': [
            '/Users/*/Library/Cookies/Cookies.binarycookies',
        ],
        'description': 'Safari cookies',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'macos',
    },

    'macos_safari_cache': {
        'paths': [
            '/Users/*/Library/Caches/com.apple.Safari/Cache.db',
        ],
        'description': 'Safari cache',
        'forensic_value': 'medium',
        'category': 'browser',
        'os_type': 'macos',
    },

    'macos_chrome': {
        'paths': [
            '/Users/*/Library/Application Support/Google/Chrome/Default/History',
            '/Users/*/Library/Application Support/Google/Chrome/Default/Cookies',
            '/Users/*/Library/Application Support/Google/Chrome/Default/Login Data',
            '/Users/*/Library/Application Support/Google/Chrome/Default/Bookmarks',
        ],
        'description': 'Chrome browser data',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_firefox': {
        'paths': [
            '/Users/*/Library/Application Support/Firefox/Profiles/*.default*/places.sqlite',
            '/Users/*/Library/Application Support/Firefox/Profiles/*.default*/cookies.sqlite',
            '/Users/*/Library/Application Support/Firefox/Profiles/*.default*/logins.json',
        ],
        'description': 'Firefox browser data',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'macos',
        'path_optional': True,
    },

    # ==========================================================================
    # Applications
    # ==========================================================================

    'macos_imessage': {
        'paths': [
            '/Users/*/Library/Messages/chat.db',
            '/Users/*/Library/Messages/chat.db-wal',
        ],
        'description': 'iMessage messages',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_mail': {
        'paths': [
            '/Users/*/Library/Mail/V*/MailData/Envelope Index',
            '/Users/*/Library/Mail/V*/MailData/Envelope Index-wal',
        ],
        'description': 'Mail app index',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'macos',
    },

    'macos_notes': {
        'paths': [
            '/Users/*/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite',
        ],
        'description': 'Notes app data',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_calendar': {
        'paths': [
            '/Users/*/Library/Calendars/*.caldav/*.calendar/Events/*.ics',
            '/Users/*/Library/Calendars/Calendar Cache',
        ],
        'description': 'Calendar app data',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'macos',
    },

    'macos_reminders': {
        'paths': [
            '/Users/*/Library/Reminders/Container_v1/Stores/*.sqlite',
        ],
        'description': 'Reminders app data',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'macos',
    },

    'macos_photos': {
        'paths': [
            '/Users/*/Pictures/Photos Library.photoslibrary/database/Photos.sqlite',
        ],
        'description': 'Photos app database',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'macos',
    },

    'macos_terminal': {
        'paths': [
            '/Users/*/Library/Saved Application State/com.apple.Terminal.savedState/*',
        ],
        'description': 'Terminal saved state',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'macos',
    },

    # ==========================================================================
    # System Information
    # ==========================================================================

    'macos_system_version': {
        'paths': [
            '/System/Library/CoreServices/SystemVersion.plist',
        ],
        'description': 'macOS version information',
        'forensic_value': 'low',
        'category': 'system_info',
        'os_type': 'macos',
    },

    'macos_bluetooth': {
        'paths': [
            '/Library/Preferences/com.apple.Bluetooth.plist',
        ],
        'description': 'Bluetooth connection history',
        'forensic_value': 'medium',
        'category': 'system_info',
        'os_type': 'macos',
    },

    'macos_usb': {
        'paths': [
            '/var/db/lockdown/*',
        ],
        'description': 'USB device connection history (iOS pairing)',
        'forensic_value': 'high',
        'category': 'system_info',
        'os_type': 'macos',
    },

    'macos_time_machine': {
        'paths': [
            '/Library/Preferences/com.apple.TimeMachine.plist',
        ],
        'description': 'Time Machine settings',
        'forensic_value': 'medium',
        'category': 'system_info',
        'os_type': 'macos',
    },

    # ==========================================================================
    # [2026-03-25] Additional macOS Artifacts (25 new types)
    # ==========================================================================

    # --- System Info ---

    'macos_user_accounts': {
        'paths': [
            '/private/var/db/dslocal/nodes/Default/users/*.plist',
            '/Library/Preferences/com.apple.loginwindow.plist',
            '/Library/Preferences/com.apple.preferences.accounts.plist',
        ],
        'description': 'User account information (macOS)',
        'forensic_value': 'critical',
        'category': 'system_info',
        'os_type': 'macos',
    },

    'macos_timezone': {
        'paths': [
            '/Library/Preferences/.GlobalPreferences.plist',
            '/Library/Preferences/com.apple.timezone.auto.plist',
        ],
        'description': 'Timezone settings',
        'forensic_value': 'medium',
        'category': 'system_info',
        'os_type': 'macos',
        'note': 'AppleTimezone key in GlobalPreferences',
    },

    'macos_network_interfaces': {
        'paths': [
            '/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist',
            '/Library/Preferences/SystemConfiguration/preferences.plist',
        ],
        'description': 'Network interface configuration',
        'forensic_value': 'medium',
        'category': 'network',
        'os_type': 'macos',
    },

    'macos_installed_apps': {
        'paths': [
            '/Applications/*/Contents/Info.plist',
            '/Users/*/Applications/*/Contents/Info.plist',
        ],
        'description': 'Installed applications',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'macos',
    },

    'macos_app_updates': {
        'paths': [
            '/Library/Receipts/InstallHistory.plist',
            '/var/log/install.log',
        ],
        'description': 'Application update history',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'macos',
    },

    # --- User Activity ---

    'macos_command_history': {
        'paths': [
            '/Users/*/.python_history',
            '/Users/*/.mysql_history',
            '/Users/*/.psql_history',
            '/Users/*/.node_repl_history',
            '/Users/*/.irb_history',
        ],
        'description': 'Command history (Python, MySQL, PostgreSQL, Node, IRB)',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_dsstore': {
        'paths': [
            '/Users/*/.DS_Store',
            '/Users/*/Desktop/.DS_Store',
            '/Users/*/Documents/.DS_Store',
            '/Users/*/Downloads/.DS_Store',
        ],
        'description': '.DS_Store files (Finder folder access evidence)',
        'forensic_value': 'medium',
        'category': 'user_activity',
        'os_type': 'macos',
    },

    'macos_dock': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.dock.plist',
        ],
        'description': 'Dock configuration',
        'forensic_value': 'medium',
        'category': 'user_activity',
        'os_type': 'macos',
    },

    'macos_volume_mounts': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.finder.plist',
            '/Users/*/Library/Preferences/com.apple.sidebarlists.plist',
        ],
        'description': 'Recently mounted volumes (FXRecentFolders)',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'macos',
        'note': 'FXRecentFolders key in Finder plist',
    },

    'macos_recent_apps': {
        'paths': [
            '/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentApplications.sfl2',
        ],
        'description': 'Recently launched applications',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'macos',
    },

    'macos_recent_docs': {
        'paths': [
            '/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentDocuments.sfl2',
            '/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentServers.sfl2',
        ],
        'description': 'Recently accessed documents and servers',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'macos',
    },

    'macos_file_copy_move': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.finder.plist',
            '/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentServers.sfl2',
        ],
        'description': 'File copy/move paths (Finder GoToField)',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'macos',
        'note': 'GoToField key in Finder plist',
    },

    # --- External Devices ---

    'macos_ipod_devices': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.iPod.plist',
            '/Users/*/Library/Preferences/com.apple.AMPDeviceDiscoveryAgent.plist',
        ],
        'description': 'Connected iPod/iOS device history',
        'forensic_value': 'high',
        'category': 'system_info',
        'os_type': 'macos',
    },

    # --- Applications & Messaging ---

    'macos_itunes_cloud': {
        'paths': [
            '/Users/*/Library/Application Support/iTunes/iTunesApplicationSupport/*',
            '/Users/*/Library/Preferences/com.apple.iTunes.plist',
        ],
        'description': 'iTunes/Apple Music cloud data',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'macos',
    },

    'macos_notification': {
        'paths': [
            '/Users/*/Library/Group Containers/group.com.apple.usernoted/db2/db',
            '/private/var/folders/*/*/com.apple.notificationcenterui/db2/db',
        ],
        'description': 'Notification Center database',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_identity_services': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.identityservicesd.plist',
            '/Users/*/Library/IdentityServices/*',
        ],
        'description': 'Identity Services daemon (IDS)',
        'forensic_value': 'high',
        'category': 'security',
        'os_type': 'macos',
    },

    'macos_storage_byhost': {
        'paths': [
            '/Users/*/Library/Preferences/ByHost/*.plist',
        ],
        'description': 'Per-host storage preferences',
        'forensic_value': 'medium',
        'category': 'system_info',
        'os_type': 'macos',
    },

    'macos_weather': {
        'paths': [
            '/Users/*/Library/Containers/com.apple.weather/Data/Library/Caches/*',
            '/Users/*/Library/Preferences/com.apple.weather.plist',
        ],
        'description': 'Weather app location data',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'macos',
    },

    'macos_user_preferences': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.systempreferences.plist',
            '/Users/*/Library/Preferences/.GlobalPreferences.plist',
        ],
        'description': 'User customization settings',
        'forensic_value': 'medium',
        'category': 'user_activity',
        'os_type': 'macos',
    },

    'macos_icloud_accounts': {
        'paths': [
            '/Users/*/Library/Preferences/MobileMeAccounts.plist',
            '/Users/*/Library/Application Support/iCloud/Accounts/*',
        ],
        'description': 'iCloud sync account information',
        'forensic_value': 'critical',
        'category': 'security',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_ichat': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.iChat.plist',
        ],
        'description': 'iChat/Messages legacy user data',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'macos',
        'note': 'chat.db handled by macos_imessage; this covers iChat plist settings',
    },

    # --- Browser ---

    'macos_safari_search': {
        'paths': [
            '/Users/*/Library/Safari/RecentlyClosedTabs.plist',
            '/Users/*/Library/Safari/TopSites.plist',
            '/Users/*/Library/Safari/SearchDescriptions.plist',
            '/Users/*/Library/Suggestions/snippets.db',
        ],
        'description': 'Safari search history and suggestions',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'macos',
        'path_optional': True,
    },

    # --- Contacts ---

    'macos_blocked_contacts': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.cmfsyncagent.plist',
            '/Users/*/Library/Application Support/AddressBook/AddressBook-v22.abcddb',
        ],
        'description': 'Blocked phone numbers/contacts',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'macos',
        'path_optional': True,
    },

    # --- Korean Messenger (KakaoTalk) ---

    'macos_kakaotalk_uid': {
        'paths': [
            '/Users/*/Library/Containers/com.kakao.KakaoTalkMac/Data/Library/Application Support/KakaoTalk/*',
            '/Users/*/Library/Preferences/com.kakao.KakaoTalkMac.plist',
        ],
        'description': 'KakaoTalk user identifier',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_kakaotalk_credentials': {
        'paths': [
            '/Users/*/Library/Containers/com.kakao.KakaoTalkMac/Data/Library/Cookies/Cookies.binarycookies',
            '/Users/*/Library/Containers/com.kakao.KakaoTalkMac/Data/Library/Application Support/KakaoTalk/talk.db',
        ],
        'description': 'KakaoTalk login data and message database',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'macos',
        'path_optional': True,
    },
}


# ==============================================================================
# Helper Functions
# ==============================================================================

def get_macos_artifacts_by_category(category: str) -> Dict[str, Dict[str, Any]]:
    """Return macOS artifacts by category"""
    return {
        k: v for k, v in MACOS_ARTIFACT_FILTERS.items()
        if v.get('category') == category
    }


def get_macos_artifacts_by_forensic_value(value: str) -> Dict[str, Dict[str, Any]]:
    """Return macOS artifacts by forensic value"""
    return {
        k: v for k, v in MACOS_ARTIFACT_FILTERS.items()
        if v.get('forensic_value') == value
    }


def get_all_macos_artifact_paths() -> List[str]:
    """Return all macOS artifact paths (including wildcards)"""
    paths = []
    for config in MACOS_ARTIFACT_FILTERS.values():
        paths.extend(config.get('paths', []))
    return paths


def get_macos_categories() -> List[str]:
    """Return list of macOS artifact categories"""
    categories = set()
    for config in MACOS_ARTIFACT_FILTERS.values():
        if 'category' in config:
            categories.add(config['category'])
    return sorted(list(categories))


# Artifact statistics
MACOS_ARTIFACT_STATS = {
    'total_artifacts': len(MACOS_ARTIFACT_FILTERS),
    'categories': get_macos_categories(),
    'critical_artifacts': len(get_macos_artifacts_by_forensic_value('critical')),
    'high_artifacts': len(get_macos_artifacts_by_forensic_value('high')),
}
