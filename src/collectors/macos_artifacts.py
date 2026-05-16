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
    'macos_shortcuts': {
        'paths': [
            '/Users/*/Library/Shortcuts/*',
            '/Users/*/Library/Containers/com.apple.shortcuts/Data/Library/Shortcuts/*',
            '/Users/*/Library/Group Containers/group.is.workflow.my.workflows/*',
            '/Users/*/Library/Group Containers/group.com.apple.shortcuts/*',
            '/private/var/mobile/Library/Shortcuts/*',
        ],
        'description': 'Shortcuts automation library, workflow metadata, and automation state',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'macos',
        'path_optional': True,
    },
    'macos_screentime': {
        'paths': [
            '/Users/*/Library/Application Support/Knowledge/knowledgeC.db',
            '/Users/*/Library/Application Support/com.apple.ScreenTimeAgent/*',
            '/Users/*/Library/Preferences/com.apple.ScreenTimeAgent.plist',
            '/Users/*/Library/Preferences/com.apple.ScreenTime.plist',
            '/private/var/db/CoreDuet/Knowledge/knowledgeC.db',
        ],
        'description': 'Screen Time app usage, device activity, limits, and local policy state',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'macos',
        'path_optional': True,
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

    'macos_xprotect_remediator_db': {
        'paths': [
            '/var/protected/xprotect/XPdb',
            '/private/var/protected/xprotect/XPdb',
        ],
        'description': 'XProtect Behavior Service database',
        'forensic_value': 'high',
        'category': 'security',
        'os_type': 'macos',
    },

    'macos_biome_stream': {
        'paths': [
            '/Users/*/Library/Biome/streams/*/*/local/*',
            '/Users/*/Library/Biome/streams/*/*/remote/*',
            '/Users/*/Library/Biome/streams/*/*/metadata.plist',
            '/var/db/Biome/streams/*/*/local/*',
            '/var/db/Biome/streams/*/*/remote/*',
            '/private/var/db/Biome/streams/*/*/local/*',
        ],
        'description': 'macOS Biome streams',
        'forensic_value': 'high',
        'category': 'user_activity',
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
    # Additional macOS Artifacts (25 new types)
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
            '/Users/*/Library/Containers/com.kakao.KakaoTalkMac/Data/Library/Preferences/com.kakao.KakaoTalkMac.plist',
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
            '/Users/*/Library/Containers/com.kakao.KakaoTalkMac/Data/Library/Application Support/com.kakao.KakaoTalkMac/*',
            '/Users/*/Library/Containers/com.kakao.KakaoTalkMac/Data/Library/Application Support/KakaoTalk/*',
            '/Users/*/Library/Application Support/com.kakao.KakaoTalkMac/*',
            '/Users/*/Library/Application Support/KakaoTalk/*',
            '/Users/*/Library/Containers/com.kakao.KakaoTalkMac/Data/Library/Cookies/*',
            '/Users/*/Library/Containers/com.kakao.KakaoTalkMac/Data/Library/Preferences/*.plist',
            '/Users/*/Library/Containers/com.kakao.KakaoTalkMac/Data/Library/Caches/Cache.db',
            '/Users/*/Library/Containers/com.kakao.KakaoTalkMac/Data/Library/Caches/Cache.db-wal',
            '/Users/*/Library/Containers/com.kakao.KakaoTalkMac/Data/Library/Caches/Cache.db-shm',
        ],
        'description': 'KakaoTalk message database and application data',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_kakaotalk_cache': {
        'paths': [
            '/Users/*/Library/Containers/com.kakao.KakaoTalkMac/Data/Library/Caches/Cache.db',
            '/Users/*/Library/Containers/com.kakao.KakaoTalkMac/Data/Library/Caches/Cache.db-wal',
            '/Users/*/Library/Containers/com.kakao.KakaoTalkMac/Data/Library/Caches/Cache.db-shm',
            '/Users/*/Library/Caches/com.kakao.KakaoTalkMac/Cache.db',
            '/Users/*/Library/Caches/com.kakao.KakaoTalkMac/Cache.db-wal',
            '/Users/*/Library/Caches/com.kakao.KakaoTalkMac/Cache.db-shm',
        ],
        'description': 'KakaoTalk NSURLCache login and device metadata',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'macos',
        'path_optional': True,
    },

    # --- WhatsApp macOS ---

    'macos_whatsapp': {
        'paths': [
            '/Users/*/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/ChatStorage.sqlite',
            '/Users/*/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/ChatStorage.sqlite-wal',
            '/Users/*/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/ChatStorage.sqlite-shm',
            '/Users/*/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Contacts.sqlite',
            '/Users/*/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Media/*',
        ],
        'description': 'WhatsApp macOS message database and media',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'macos',
        'path_optional': True,
    },

    # --- WeChat macOS ---

    'macos_wechat': {
        'paths': [
            '/Users/*/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/*/*/*.db',
            '/Users/*/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/*/*/*.db-wal',
            '/Users/*/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/*/*/*/*.db',
        ],
        'description': 'WeChat macOS message databases',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'macos',
        'path_optional': True,
    },

    # --- LINE macOS ---

    'macos_line': {
        'paths': [
            '/Users/*/Library/Containers/jp.naver.line.mac/Data/Library/Application Support/LINE/Data/db/*.edb',
            '/Users/*/Library/Containers/Line/Data/Library/Container/jp.naver.line/Data/db/*.edb',
            '/Users/*/Library/Containers/jp.naver.line.mac/Data/Library/Application Support/LINE/Data/db/*.sqlite',
        ],
        'description': 'LINE macOS message databases',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'macos',
        'path_optional': True,
    },

    # --- Signal macOS ---

    'macos_signal': {
        'paths': [
            '/Users/*/Library/Application Support/Signal/sql/db.sqlite',
            '/Users/*/Library/Application Support/Signal/config.json',
            '/Users/*/Library/Application Support/Signal/sql/db.sqlite-wal',
        ],
        'description': 'Signal macOS database and config',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'macos',
        'path_optional': True,
    },

    # --- Discord macOS ---

    'macos_discord': {
        'paths': [
            '/Users/*/Library/Application Support/discord/Local Storage/leveldb/*',
            '/Users/*/Library/Application Support/discord/userDataCache.json',
            '/Users/*/Library/Application Support/discord/Cache/Cache_Data/*',
        ],
        'description': 'Discord Desktop LevelDB data and user cache',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'macos',
        'path_optional': True,
    },

    # --- macOS Keychain ---

    'macos_keychain_data': {
        'paths': [
            '/Users/*/Library/Keychains/login.keychain-db',
            '/Library/Keychains/System.keychain',
        ],
        'description': 'macOS Keychain databases',
        'forensic_value': 'critical',
        'category': 'security',
        'os_type': 'macos',
        'path_optional': True,
    },

    # --- Process Memory Dumps ---

    'macos_process_memory': {
        'paths': [
            '/tmp/forensic_memdump_*.bin',
        ],
        'description': 'Process memory dumps',
        'forensic_value': 'critical',
        'category': 'memory',
        'os_type': 'macos',
        'path_optional': True,
    },

    # --- Device UUID ---

    'macos_device_uuid': {
        'paths': [
            '/private/var/db/SystemIdentity.plist',
            '/Library/Preferences/SystemConfiguration/com.apple.Boot.plist',
            '/private/var/db/dslocal/nodes/Default/config/KernelCoreDumpConfig.plist',
        ],
        'description': 'Device UUID (IOPlatformUUID)',
        'forensic_value': 'critical',
        'category': 'system_info',
        'os_type': 'macos',
    },

    # ==========================================================================
    # AI Agent Activity (P0 - 2026 emerging forensic surface)
    # ==========================================================================
    # AI tools leave rich forensic traces: full conversation logs, tool-call
    # records (which files the agent read/wrote), MCP server grants, model
    # identifiers, token counts. For insider-threat / IP-theft / compliance
    # investigations, AI artifacts are increasingly the primary evidence.

    'ai_claude_code': {
        'paths': [
            '/Users/*/.claude/history.jsonl',
            '/Users/*/.claude/settings.json',
            '/Users/*/.claude/settings.local.json',
            '/Users/*/.claude/CLAUDE.md',
            '/Users/*/.claude/stats-cache.json',
            '/Users/*/.claude/mcp-needs-auth-cache.json',
            '/Users/*/.claude/projects/*/*.jsonl',
            '/Users/*/.claude/projects/*/*/*.jsonl',
            '/Users/*/.claude/projects/*/*/subagents/*.jsonl',
            '/Users/*/.claude/sessions/*.json',
            '/Users/*/.claude/plans/*',
            '/Users/*/.claude/file-history/*',
            '/Users/*/.claude/shell-snapshots/*.sh',
        ],
        'description': 'Claude Code agent session logs, tool-call records, project memory, shell snapshots',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
        'note': 'JSONL format. Each line is a message, tool call, or tool result with timestamps and full content.',
    },

    'ai_claude_desktop': {
        'paths': [
            '/Users/*/Library/Application Support/Claude/config.json',
            '/Users/*/Library/Application Support/Claude/claude_desktop_config.json',
            '/Users/*/Library/Logs/Claude/*.log',
            '/Users/*/Library/Preferences/com.anthropic.claudefordesktop.plist',
        ],
        'description': 'Claude Desktop config, MCP server grants, recent attachments, logs',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },

    'ai_chatgpt_desktop': {
        'paths': [
            '/Users/*/Library/Application Support/com.openai.chat/*',
            '/Users/*/Library/Caches/com.openai.chat/*',
            '/Users/*/Library/Logs/com.openai.chat/*',
            '/Users/*/Library/Preferences/com.openai.chat.plist',
        ],
        'description': 'ChatGPT Desktop config, cache, custom GPTs, recent uploads',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },

    'ai_cursor': {
        'paths': [
            '/Users/*/Library/Application Support/Cursor/User/settings.json',
            '/Users/*/Library/Application Support/Cursor/User/globalStorage/state.vscdb',
            '/Users/*/Library/Application Support/Cursor/User/workspaceStorage/*/state.vscdb',
            '/Users/*/Library/Application Support/Cursor/User/History/*/*',
            '/Users/*/Library/Logs/Cursor/*',
        ],
        'description': 'Cursor IDE chat history, code context, workspace state (SQLite); contains full AI conversation per workspace',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
        'note': 'state.vscdb is SQLite - parse with chat-history schema.',
    },

    'ai_copilot_vscode': {
        'paths': [
            '/Users/*/Library/Application Support/Code/User/globalStorage/github.copilot-chat/*',
            '/Users/*/Library/Application Support/Code/User/globalStorage/github.copilot/*',
            '/Users/*/Library/Application Support/Code/User/workspaceStorage/*/github.copilot-chat/*',
            '/Users/*/Library/Application Support/Code/logs/*/exthost*/output_logging_*/*.log',
        ],
        'description': 'GitHub Copilot Chat extension - conversation logs, prompts, completions, telemetry',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
    },

    'ai_continue_dev': {
        'paths': [
            '/Users/*/.continue/config.json',
            '/Users/*/.continue/config.yaml',
            '/Users/*/.continue/dev_data/*',
            '/Users/*/.continue/index/*',
            '/Users/*/.continue/sessions/*',
        ],
        'description': 'Continue.dev VS Code/JetBrains extension - chat sessions, model configs, indexed code context',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },

    'ai_aider': {
        'paths': [
            '/Users/*/.aider*',
            '/Users/*/.aider.chat.history.md',
            '/Users/*/.aider.input.history',
            '/Users/*/.aider.tags.cache.v3/*',
        ],
        'description': 'Aider AI coding CLI - chat history (markdown), input history, project tags cache',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },

    'ai_ollama': {
        'paths': [
            '/Users/*/.ollama/id_ed25519',
            '/Users/*/.ollama/id_ed25519.pub',
            '/Users/*/.ollama/history',
            '/Users/*/.ollama/models/manifests/*',
            '/Users/*/.ollama/logs/server.log',
            '/Users/*/Library/Application Support/Ollama/*',
            '/Users/*/Library/Logs/Ollama/*',
        ],
        'description': 'Ollama local LLM runtime - identity key, model manifests, server log (often contains user prompts)',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
        'note': 'server.log records all prompt/response by default unless OLLAMA_DEBUG=0. Identity key is unique per install.',
    },

    'ai_lmstudio': {
        'paths': [
            '/Users/*/.cache/lm-studio/*',
            '/Users/*/.lmstudio/*',
            '/Users/*/Library/Application Support/LM Studio/*',
            '/Users/*/Library/Application Support/LM Studio/user-data/conversations/*',
        ],
        'description': 'LM Studio local LLM GUI - conversation history (JSON), model preferences',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },

    'ai_huggingface_cache': {
        'paths': [
            '/Users/*/.cache/huggingface/hub/models--*/blobs/*',
            '/Users/*/.cache/huggingface/hub/models--*/snapshots/*',
            '/Users/*/.cache/huggingface/token',
            '/Users/*/.cache/huggingface/hub/version.txt',
        ],
        'description': 'HuggingFace models cache - downloaded model weights, API token, version metadata',
        'forensic_value': 'medium',
        'category': 'ai_activity',
        'os_type': 'macos',
        'note': 'Used by transformers, vllm, diffusers, and most local LLM Python ecosystems.',
    },

    'ai_mcp_servers': {
        'paths': [
            '/Users/*/.claude/mcp-needs-auth-cache.json',
            '/Users/*/Library/Application Support/Claude/claude_desktop_config.json',
            '/Users/*/.continue/config.json',
            '/Users/*/.continue/config.yaml',
            '/Users/*/.config/claude/mcp.json',
            '/Users/*/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/*',
        ],
        'description': 'Model Context Protocol server configurations - lists external services AI agents were granted access to (filesystem, GitHub, Slack, Gmail, etc.)',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
        'note': 'Single highest-value AI artifact: shows full attack surface granted to agents in one file.',
    },

    # ==========================================================================
    # Round 10 - Desktop AI Expansion (macOS, 2026-05-06)
    # ==========================================================================

    'ai_cline': {
        'paths': [
            '/Users/*/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/state/*',
            '/Users/*/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/tasks/*/api_conversation_history.json',
            '/Users/*/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/tasks/*/ui_messages.json',
            '/Users/*/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/tasks/*/task_metadata.json',
            '/Users/*/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/checkpoints/*',
        ],
        'description': 'Cline (Claude Dev) VS Code extension - full task history, AI conversation, tool calls, checkpoints',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
        'note': '2025 explosive growth (>2M installs). Each task has api_conversation_history.json with raw Claude API exchanges.',
    },
    'ai_roo_code': {
        'paths': [
            '/Users/*/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/state/*',
            '/Users/*/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks/*/api_conversation_history.json',
            '/Users/*/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks/*/ui_messages.json',
            '/Users/*/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/*',
        ],
        'description': 'Roo Code / Kilo Code (Cline forks) - same forensic schema as Cline',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_windsurf': {
        'paths': [
            '/Users/*/.codeium/*',
            '/Users/*/Library/Application Support/Windsurf/User/globalStorage/*',
            '/Users/*/Library/Application Support/Windsurf/User/settings.json',
            '/Users/*/Library/Application Support/Windsurf/logs/*',
        ],
        'description': 'Windsurf (Codeium IDE) - Cascade agent IDE chat history, settings, logs',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_jan': {
        'paths': [
            '/Users/*/Library/Application Support/Jan/data/threads/*',
            '/Users/*/Library/Application Support/Jan/data/models/*',
            '/Users/*/Library/Application Support/Jan/data/settings/*',
            '/Users/*/Library/Application Support/Jan/data/assistants/*',
        ],
        'description': 'Jan local LLM app - threads (chat history JSON), downloaded models, settings, custom assistants',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_gpt4all': {
        'paths': [
            '/Users/*/Library/Application Support/nomic.ai/GPT4All/*',
            '/Users/*/Library/Application Support/nomic.ai/GPT4All/chats/*',
            '/Users/*/Library/Application Support/nomic.ai/GPT4All/localdocs_v3.db',
        ],
        'description': 'GPT4All local LLM - chat history (SQLite), downloaded GGUF models, LocalDocs RAG database',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_anythingllm': {
        'paths': [
            '/Users/*/Library/Application Support/anythingllm-desktop/storage/*',
            '/Users/*/Library/Application Support/anythingllm-desktop/storage/anythingllm.db',
            '/Users/*/Library/Application Support/anythingllm-desktop/storage/lancedb/*',
            '/Users/*/Library/Application Support/anythingllm-desktop/storage/documents/*',
        ],
        'description': 'AnythingLLM desktop - chat DB (SQLite), LanceDB vector store, ingested documents (RAG corpus)',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
        'note': 'documents/ folder often contains exfil-relevant files ingested as RAG context.',
    },
    'ai_sillytavern': {
        'paths': [
            '/Users/*/SillyTavern/data/default-user/chats/*',
            '/Users/*/SillyTavern/data/default-user/characters/*',
            '/Users/*/SillyTavern/data/default-user/worlds/*',
            '/Users/*/SillyTavern/data/default-user/secrets.json',
            '/Users/*/SillyTavern/data/default-user/settings.json',
        ],
        'description': 'SillyTavern frontend - JSONL chat logs per character, character cards, secrets.json (API keys)',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
        'note': 'Common in jailbreak/abuse cases. Character PNG cards have embedded JSON metadata.',
    },
    'ai_open_interpreter': {
        'paths': [
            '/Users/*/Library/Application Support/Open Interpreter/conversations.json',
            '/Users/*/Library/Application Support/Open Interpreter/*',
            '/Users/*/.config/open-interpreter/*',
        ],
        'description': 'Open Interpreter autonomous code-execution agent - conversations.json shows commands the agent ran on the host',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_jetbrains_assistant': {
        'paths': [
            '/Users/*/Library/Caches/JetBrains/*/AIAssistant/*',
            '/Users/*/Library/Application Support/JetBrains/*/options/ai-*.xml',
            '/Users/*/Library/Application Support/JetBrains/*/options/chat-history.xml',
        ],
        'description': 'JetBrains AI Assistant (IntelliJ family) - chat history XML, AI configuration',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_codeium': {
        'paths': [
            '/Users/*/.codeium/*',
            '/Users/*/Library/Application Support/Code/User/globalStorage/codeium.codeium/*',
        ],
        'description': 'Codeium VS Code extension - completion history, telemetry',
        'forensic_value': 'medium',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_tabnine': {
        'paths': [
            '/Users/*/.tabnine/*',
            '/Users/*/Library/Application Support/Tabnine/*',
            '/Users/*/Library/Application Support/Code/User/globalStorage/TabNine.tabnine-vscode/*',
        ],
        'description': 'Tabnine VS Code/JetBrains extension - binary cache, telemetry, local config',
        'forensic_value': 'medium',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_sourcegraph_cody': {
        'paths': [
            '/Users/*/Library/Application Support/Code/User/globalStorage/sourcegraph.cody-ai/*',
            '/Users/*/.config/sourcegraph/*',
        ],
        'description': 'Sourcegraph Cody - chat history, code context cache',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_amazon_q': {
        'paths': [
            '/Users/*/.aws/sso/cache/*',
            '/Users/*/Library/Application Support/Code/User/globalStorage/AmazonWebServices.aws-toolkit-vscode/*',
            '/Users/*/Library/Application Support/Code/User/globalStorage/amazonwebservices.amazon-q-vscode/*',
        ],
        'description': 'Amazon Q Developer (formerly CodeWhisperer) - SSO cache, AI completion history',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_pieces': {
        'paths': [
            '/Users/*/Library/Application Support/Pieces/*',
            '/Users/*/Library/Application Support/com.pieces.os/*',
        ],
        'description': 'Pieces for Developers - PiecesOS SQLite snippet store; captures clipboard-like dev IP across machines',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_msty': {
        'paths': [
            '/Users/*/Library/Application Support/Msty/*',
            '/Users/*/Library/Application Support/Msty/chats/*',
        ],
        'description': 'Msty local LLM GUI - SQLite chat database',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_open_webui': {
        'paths': [
            '/Users/*/.open-webui/*',
            '/Users/*/.open-webui/webui.db',
        ],
        'description': 'Open WebUI (formerly Ollama WebUI) - SQLite chat database with full conversation history',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_text_gen_webui': {
        'paths': [
            '/Users/*/text-generation-webui/logs/chat/*/*.json',
            '/Users/*/text-generation-webui/characters/*',
            '/Users/*/text-generation-webui/loras/*',
            '/Users/*/text-generation-webui/models/*',
        ],
        'description': 'text-generation-webui (Oobabooga) - chat JSON per character, LoRA fine-tunes, model files',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_koboldcpp': {
        'paths': [
            '/Users/*/koboldcpp.cfg',
            '/Users/*/KoboldCPP/*',
        ],
        'description': 'KoboldCPP single-exe local inference - config + user-saved chat JSON',
        'forensic_value': 'medium',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_backyard_ai': {
        'paths': [
            '/Users/*/Library/Application Support/faraday/*',
            '/Users/*/Library/Application Support/Backyard AI/*',
        ],
        'description': 'Backyard AI / Faraday - SQLite chats DB, downloaded GGUFs, character cards',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
        'note': 'Common in uncensored RP/jailbreak abuse cases.',
    },
    'ai_pinokio': {
        'paths': [
            '/Users/*/pinokio/*',
            '/Users/*/pinokio/api/*',
        ],
        'description': 'Pinokio meta-installer - hides 1-click installs of Stable Diffusion / SD video / voice cloning tools',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_raycast_ai': {
        'paths': [
            '/Users/*/Library/Application Support/com.raycast.macos/LocalDatabase.db',
            '/Users/*/Library/Application Support/com.raycast.macos/*',
        ],
        'description': 'Raycast AI - SQLite database with AI chat history and quicklinks',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_granola': {
        'paths': [
            '/Users/*/Library/Application Support/Granola/*',
            '/Users/*/Library/Application Support/Granola/recordings/*',
            '/Users/*/Library/Application Support/Granola/transcripts/*',
        ],
        'description': 'Granola meeting notetaker - audio recordings + AI transcripts + meeting summaries',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_notion_ai_desktop': {
        'paths': [
            '/Users/*/Library/Application Support/Notion/IndexedDB/*',
            '/Users/*/Library/Application Support/Notion/*',
        ],
        'description': 'Notion desktop AI cache - IndexedDB caches recent AI block responses',
        'forensic_value': 'medium',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_glean_desktop': {
        'paths': [
            '/Users/*/Library/Preferences/com.glean.desktop.plist',
            '/Users/*/Library/Application Support/com.glean.desktop/*',
        ],
        'description': 'Glean enterprise AI search - desktop cache + plist preferences',
        'forensic_value': 'medium',
        'category': 'ai_activity',
        'os_type': 'macos',
    },

    # ==========================================================================
    # Round 11 - Browser AI Universal (LevelDB + extensions)
    # ==========================================================================

    'ai_browser_indexeddb': {
        'paths': [
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_claude.ai_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_chatgpt.com_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_chat.openai.com_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_gemini.google.com_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_copilot.microsoft.com_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_www.perplexity.ai_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_perplexity.ai_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_chat.deepseek.com_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_chat.mistral.ai_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_character.ai_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_poe.com_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_kimi.com_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_doubao.com_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_you.com_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_phind.com_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_huggingface.co_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_pi.ai_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/IndexedDB/https_wrtn.ai_0.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/Microsoft Edge/Default/IndexedDB/https_*.indexeddb.leveldb/*',
            '/Users/*/Library/Application Support/BraveSoftware/Brave-Browser/Default/IndexedDB/https_*.indexeddb.leveldb/*',
            '/Users/*/Library/Safari/Databases/__IndexedDB/*',
            '/Users/*/Library/Containers/com.apple.Safari/Data/Library/WebKit/WebsiteData/Default/IndexedDB/v1/https_claude.ai_0/*',
            '/Users/*/Library/Containers/com.apple.Safari/Data/Library/WebKit/WebsiteData/Default/IndexedDB/v1/https_chatgpt.com_0/*',
        ],
        'description': 'Cloud AI conversation cache in browser IndexedDB (LevelDB / WebKit). Recovers conversations + drafts + WAL log entries (deleted recovery)',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
        'note': 'WAL recovery technique (Hassan/Patsakis 2025): deleted conversations recoverable from .log files.',
    },
    'ai_browser_localstorage': {
        'paths': [
            '/Users/*/Library/Application Support/Google/Chrome/Default/Local Storage/leveldb/*',
            '/Users/*/Library/Application Support/Microsoft Edge/Default/Local Storage/leveldb/*',
            '/Users/*/Library/Application Support/BraveSoftware/Brave-Browser/Default/Local Storage/leveldb/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/Session Storage/*',
        ],
        'description': 'Browser LocalStorage / SessionStorage - cloud AI service drafts, UI state',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_browser_ai_extension': {
        'paths': [
            '/Users/*/Library/Application Support/Google/Chrome/Default/Local Extension Settings/*',
            '/Users/*/Library/Application Support/Microsoft Edge/Default/Local Extension Settings/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/Extensions/*',
        ],
        'description': 'Browser AI extensions - Monica, Merlin, AITOPIA, Sider, Compose AI etc. Conversation history + (in malicious cases) exfil queue',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
        'note': 'Dec 2025 incident: 900K users compromised by malicious AI Chrome extensions.',
    },
    'ai_brave_leo': {
        'paths': [
            '/Users/*/Library/Application Support/BraveSoftware/Brave-Browser/Default/AIChat',
            '/Users/*/Library/Application Support/BraveSoftware/Brave-Browser/Default/AIChat-journal',
        ],
        'description': 'Brave Leo built-in AI - **UNENCRYPTED** SQLite database with full chat history',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
        'note': 'Documented in Brave GitHub issue 54544 - stores plaintext.',
    },
    'ai_arc_max': {
        'paths': [
            '/Users/*/Library/Application Support/Arc/User Data/Default/IndexedDB/*',
            '/Users/*/Library/Application Support/Arc/*',
        ],
        'description': 'Arc Max AI features (Browser Company) - IndexedDB conversation cache',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_perplexity_comet': {
        'paths': [
            '/Users/*/Library/Application Support/Perplexity/Comet/User Data/Default/IndexedDB/*',
            '/Users/*/Library/Application Support/Perplexity/Comet/User Data/Default/Local Storage/*',
            '/Users/*/Library/Application Support/Perplexity/Comet/User Data/Default/History',
        ],
        'description': 'Perplexity Comet browser (Chromium fork) - history + AI sidebar conversation cache',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_chrome_gemini_nano': {
        'paths': [
            '/Users/*/Library/Application Support/Google/Chrome/OptimizationGuide/*',
            '/Users/*/Library/Application Support/Google/Chrome/Default/AIDataService/*',
        ],
        'description': 'Chrome built-in Gemini Nano - on-device model files + on-device prompt history',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },

    # ==========================================================================
    # Round 12 - Frontier
    # ==========================================================================

    'ai_apple_intelligence': {
        'paths': [
            '/Users/*/Library/Caches/com.apple.intelligenceplatform/*',
            '/Users/*/Library/Application Support/com.apple.intelligenceplatform/*',
            '/Users/*/Library/Caches/com.apple.WritingTools/*',
            '/Users/*/Library/Caches/Genmoji/*',
        ],
        'description': 'Apple Intelligence on-device traces (macOS 15.1+) - Writing Tools history, Genmoji prompt logs',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_slack_ai_recap': {
        'paths': [
            '/Users/*/Library/Application Support/Slack/IndexedDB/*',
            '/Users/*/Library/Application Support/Slack/Cache/*',
        ],
        'description': 'Slack AI Recap and Summaries - LevelDB caches summary text and conversation context',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_outlook_copilot': {
        'paths': [
            '/Users/*/Library/Group Containers/UBF8T346G9.Office/Outlook/*Copilot*',
            '/Users/*/Library/Containers/com.microsoft.Outlook/Data/Library/Application Support/com.microsoft.Outlook/*Copilot*',
        ],
        'description': 'Microsoft Copilot in Outlook Mac - cache, instant reply suggestions',
        'forensic_value': 'medium',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_agent_framework': {
        'paths': [
            '/Users/*/.langchain/*',
            '/Users/*/.llama_index/*',
            '/Users/*/.crewai/*',
            '/Users/*/.anthropic/*',
            '/Users/*/.openai/*',
            '/Users/*/.n8n/*',
            '/Users/*/auto_gpt_workspace/*',
        ],
        'description': 'AI agent frameworks (LangChain, LlamaIndex, AutoGen, CrewAI, AutoGPT, n8n, etc.) - workspace artifacts, vector stores, credentials',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'macos',
    },
    'ai_api_keys': {
        'paths': [
            '/Users/*/.bashrc',
            '/Users/*/.zshrc',
            '/Users/*/.profile',
            '/Users/*/.env',
            '/Users/*/.config/openai/auth.json',
            '/Users/*/.config/anthropic/*',
            '/Users/*/.cursor/config.json',
        ],
        'description': 'Credential / API key locations - shell rc files, .env files, AI tool auth configs',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'macos',
        'note': 'Sensitive token patterns are treated as protected evidence metadata.',
    },
    'ai_model_files': {
        'paths': [
            '/Users/*/Documents/models/*.gguf',
            '/Users/*/Documents/models/*.safetensors',
            '/Users/*/Models/*.gguf',
            '/Users/*/Models/*.safetensors',
            '/Users/*/.cache/huggingface/hub/models--*/blobs/*',
        ],
        'description': 'AI model weight files (GGUF, safetensors) on disk - identifies which models user has run',
        'forensic_value': 'medium',
        'category': 'ai_activity',
        'os_type': 'macos',
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
