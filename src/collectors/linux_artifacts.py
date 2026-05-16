# -*- coding: utf-8 -*-
"""
Linux Artifact Definitions - Linux System Artifact Collection Definitions

Defines Linux system artifact collection filters for digital forensics.
Includes all major artifacts collectable from ext2/3/4 file systems.

Supported Distributions:
- Debian/Ubuntu
- RHEL/CentOS/Fedora
- Arch Linux
- SUSE
- Other systemd-based distributions

Categories:
1. System Logs
2. Authentication
3. User Activity
4. Network Settings
5. Services and Daemons
6. Persistence Mechanisms
7. Browser Artifacts
8. Application Data

Usage:
    from collectors.linux_artifacts import LINUX_ARTIFACT_FILTERS

    for artifact_id, config in LINUX_ARTIFACT_FILTERS.items():
        paths = config['paths']
        description = config['description']
        forensic_value = config['forensic_value']
"""

from typing import Dict, List, Any

# ==============================================================================
# Linux Artifact Filter Definitions
# ==============================================================================

LINUX_ARTIFACT_FILTERS: Dict[str, Dict[str, Any]] = {

    # ==========================================================================
    # System Logs
    # ==========================================================================

    'linux_syslog': {
        'paths': [
            '/var/log/syslog',           # Debian/Ubuntu
            '/var/log/messages',         # RHEL/CentOS
        ],
        'description': 'System log (kernel, service messages)',
        'forensic_value': 'high',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_auth_log': {
        'paths': [
            '/var/log/auth.log',         # Debian/Ubuntu
            '/var/log/secure',           # RHEL/CentOS
        ],
        'description': 'Authentication log (login, sudo, SSH)',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_kern_log': {
        'paths': [
            '/var/log/kern.log',         # Debian/Ubuntu
            '/var/log/dmesg',            # Kernel messages
        ],
        'description': 'Kernel log (hardware, drivers)',
        'forensic_value': 'high',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_boot_log': {
        'paths': [
            '/var/log/boot.log',
            '/var/log/boot.msg',         # SUSE
        ],
        'description': 'Boot log',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_daemon_log': {
        'paths': [
            '/var/log/daemon.log',
        ],
        'description': 'Daemon service log',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_cron_log': {
        'paths': [
            '/var/log/cron',
            '/var/log/cron.log',
        ],
        'description': 'Cron job log',
        'forensic_value': 'high',
        'category': 'scheduled_tasks',
        'os_type': 'linux',
    },

    'linux_mail_log': {
        'paths': [
            '/var/log/mail.log',
            '/var/log/maillog',
        ],
        'description': 'Mail server log',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_apt_log': {
        'paths': [
            '/var/log/apt/history.log',
            '/var/log/apt/term.log',
        ],
        'description': 'APT package installation log (Debian/Ubuntu)',
        'forensic_value': 'high',
        'category': 'package_manager',
        'os_type': 'linux',
    },

    'linux_yum_log': {
        'paths': [
            '/var/log/yum.log',
            '/var/log/dnf.log',
        ],
        'description': 'YUM/DNF package installation log (RHEL/CentOS/Fedora)',
        'forensic_value': 'high',
        'category': 'package_manager',
        'os_type': 'linux',
    },

    'linux_dpkg_log': {
        'paths': [
            '/var/log/dpkg.log',
        ],
        'description': 'DPKG package log',
        'forensic_value': 'high',
        'category': 'package_manager',
        'os_type': 'linux',
    },

    'linux_audit_log': {
        'paths': [
            '/var/log/audit/audit.log',
        ],
        'description': 'Audit log (SELinux, security events)',
        'forensic_value': 'critical',
        'category': 'security',
        'os_type': 'linux',
    },

    'linux_auditd_log': {
        'paths': [
            '/var/log/audit/audit.log',
            '/var/log/audit/audit.log.*',
        ],
        'description': 'Kernel audit subsystem records',
        'forensic_value': 'critical',
        'category': 'security',
        'os_type': 'linux',
    },

    'linux_faillog': {
        'paths': [
            '/var/log/faillog',
            '/var/log/btmp',             # Failed login attempts
        ],
        'description': 'Login failure records',
        'forensic_value': 'high',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_lastlog': {
        'paths': ['/var/log/lastlog'],
        'description': 'Last login time per user (binary)',
        'forensic_value': 'high',
        'category': 'authentication',
        'os_type': 'linux',
    },
    'linux_wtmp': {
        'paths': ['/var/log/wtmp', '/var/log/wtmp.*'],
        'description': 'Login/logout session history (binary)',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },
    'linux_btmp': {
        'paths': ['/var/log/btmp', '/var/log/btmp.*'],
        'description': 'Failed login attempts (binary)',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },
    'linux_utmp': {
        'paths': ['/var/run/utmp', '/run/utmp'],
        'description': 'Currently logged-in users (binary)',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },
    'linux_rc_local': {
        'paths': ['/etc/rc.local', '/etc/rc.d/rc.local'],
        'description': 'Legacy startup script (persistence)',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Authentication & Users
    # ==========================================================================

    'linux_passwd': {
        'paths': [
            '/etc/passwd',
        ],
        'description': 'User account information',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_shadow': {
        'paths': [
            '/etc/shadow',
        ],
        'description': 'Encrypted password hashes',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_group': {
        'paths': [
            '/etc/group',
            '/etc/gshadow',
        ],
        'description': 'Group information',
        'forensic_value': 'high',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_sudoers': {
        'paths': [
            '/etc/sudoers',
            '/etc/sudoers.d/*',
        ],
        'description': 'sudo privilege configuration',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },

    # ==========================================================================
    # User Activity
    # ==========================================================================

    'linux_bash_history': {
        'paths': [
            '/home/*/.bash_history',
            '/root/.bash_history',
        ],
        'description': 'Bash command history',
        'forensic_value': 'critical',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,  # Allow search by filename
    },

    'linux_zsh_history': {
        'paths': [
            '/home/*/.zsh_history',
            '/home/*/.zhistory',
            '/root/.zsh_history',
        ],
        'description': 'Zsh command history',
        'forensic_value': 'critical',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_fish_history': {
        'paths': [
            '/home/*/.local/share/fish/fish_history',
        ],
        'description': 'Fish command history',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_bashrc': {
        'paths': [
            '/home/*/.bashrc',
            '/home/*/.bash_profile',
            '/home/*/.profile',
            '/root/.bashrc',
            '/etc/bash.bashrc',
        ],
        'description': 'Bash configuration files (aliases, environment variables)',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
    },

    'linux_viminfo': {
        'paths': [
            '/home/*/.viminfo',
            '/root/.viminfo',
        ],
        'description': 'Vim editor history',
        'forensic_value': 'medium',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_recent_files': {
        'paths': [
            '/home/*/.local/share/recently-used.xbel',
        ],
        'description': 'Recently used files (GNOME)',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
    },

    'linux_trash': {
        'paths': [
            '/home/*/.local/share/Trash/files/*',
            '/home/*/.local/share/Trash/info/*',
        ],
        'description': 'Trash contents',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
    },

    # ==========================================================================
    # SSH & Remote Access
    # ==========================================================================

    'linux_ssh_config': {
        'paths': [
            '/etc/ssh/sshd_config',
            '/etc/ssh/ssh_config',
            '/home/*/.ssh/config',
        ],
        'description': 'SSH configuration',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    'linux_ssh_known_hosts': {
        'paths': [
            '/home/*/.ssh/known_hosts',
            '/root/.ssh/known_hosts',
            '/etc/ssh/ssh_known_hosts',
        ],
        'description': 'SSH connection host records',
        'forensic_value': 'critical',
        'category': 'network',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_ssh_authorized_keys': {
        'paths': [
            '/home/*/.ssh/authorized_keys',
            '/root/.ssh/authorized_keys',
        ],
        'description': 'SSH authorized public keys',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_ssh_private_keys': {
        'paths': [
            '/home/*/.ssh/id_rsa',
            '/home/*/.ssh/id_ed25519',
            '/home/*/.ssh/id_ecdsa',
            '/root/.ssh/id_rsa',
        ],
        'description': 'SSH private keys (sensitive)',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
        'path_optional': True,
    },

    # ==========================================================================
    # Network Configuration
    # ==========================================================================

    'linux_hosts': {
        'paths': [
            '/etc/hosts',
            '/etc/hosts.allow',
            '/etc/hosts.deny',
        ],
        'description': 'Hosts file',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    'linux_resolv': {
        'paths': [
            '/etc/resolv.conf',
        ],
        'description': 'DNS settings',
        'forensic_value': 'medium',
        'category': 'network',
        'os_type': 'linux',
    },

    'linux_network_interfaces': {
        'paths': [
            '/etc/network/interfaces',
            '/etc/sysconfig/network-scripts/ifcfg-*',
            '/etc/netplan/*.yaml',
        ],
        'description': 'Network interface settings',
        'forensic_value': 'medium',
        'category': 'network',
        'os_type': 'linux',
    },

    'linux_iptables': {
        'paths': [
            '/etc/iptables/rules.v4',
            '/etc/iptables/rules.v6',
            '/etc/sysconfig/iptables',
        ],
        'description': 'Firewall rules',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Scheduled Tasks
    # ==========================================================================

    'linux_crontab': {
        'paths': [
            '/etc/crontab',
            '/etc/cron.d/*',
            '/etc/cron.daily/*',
            '/etc/cron.hourly/*',
            '/etc/cron.weekly/*',
            '/etc/cron.monthly/*',
            '/var/spool/cron/crontabs/*',
        ],
        'description': 'Cron scheduled tasks',
        'forensic_value': 'critical',
        'category': 'scheduled_tasks',
        'os_type': 'linux',
    },

    'linux_anacron': {
        'paths': [
            '/etc/anacrontab',
        ],
        'description': 'Anacron scheduled tasks',
        'forensic_value': 'high',
        'category': 'scheduled_tasks',
        'os_type': 'linux',
    },

    'linux_at_jobs': {
        'paths': [
            '/var/spool/at/*',
            '/var/spool/atjobs/*',
        ],
        'description': 'at scheduled tasks',
        'forensic_value': 'high',
        'category': 'scheduled_tasks',
        'os_type': 'linux',
    },

    'linux_systemd_timers': {
        'paths': [
            '/etc/systemd/system/*.timer',
            '/usr/lib/systemd/system/*.timer',
            '/home/*/.config/systemd/user/*.timer',
        ],
        'description': 'Systemd timers',
        'forensic_value': 'high',
        'category': 'scheduled_tasks',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Services & Daemons
    # ==========================================================================

    'linux_systemd_service': {
        'paths': [
            '/etc/systemd/system/*.service',
            '/usr/lib/systemd/system/*.service',
            '/home/*/.config/systemd/user/*.service',
        ],
        'description': 'Systemd service definitions',
        'forensic_value': 'critical',
        'category': 'services',
        'os_type': 'linux',
    },

    'linux_init_scripts': {
        'paths': [
            '/etc/init.d/*',
            '/etc/rc.local',
        ],
        'description': 'SysV init scripts',
        'forensic_value': 'high',
        'category': 'services',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Persistence Mechanisms
    # ==========================================================================

    'linux_autostart': {
        'paths': [
            '/etc/xdg/autostart/*.desktop',
            '/home/*/.config/autostart/*.desktop',
        ],
        'description': 'Auto-start items (GUI)',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'linux',
    },

    'linux_profile_scripts': {
        'paths': [
            '/etc/profile',
            '/etc/profile.d/*',
            '/etc/environment',
        ],
        'description': 'Login execution scripts',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'linux',
    },

    'linux_ld_preload': {
        'paths': [
            '/etc/ld.so.preload',
            '/etc/ld.so.conf',
            '/etc/ld.so.conf.d/*',
        ],
        'description': 'Dynamic library preload settings',
        'forensic_value': 'critical',
        'category': 'persistence',
        'os_type': 'linux',
    },

    'linux_modules': {
        'paths': [
            '/etc/modules',
            '/etc/modprobe.d/*',
            '/etc/modules-load.d/*',
        ],
        'description': 'Kernel module settings',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Browser Artifacts
    # ==========================================================================

    'linux_firefox': {
        'paths': [
            '/home/*/.mozilla/firefox/*.default*/places.sqlite',
            '/home/*/.mozilla/firefox/*.default*/cookies.sqlite',
            '/home/*/.mozilla/firefox/*.default*/formhistory.sqlite',
            '/home/*/.mozilla/firefox/*.default*/logins.json',
            '/home/*/.mozilla/firefox/*.default*/key4.db',
        ],
        'description': 'Firefox browser data',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_chrome': {
        'paths': [
            '/home/*/.config/google-chrome/Default/History',
            '/home/*/.config/google-chrome/Default/Cookies',
            '/home/*/.config/google-chrome/Default/Login Data',
            '/home/*/.config/google-chrome/Default/Bookmarks',
            '/home/*/.config/google-chrome/Default/Web Data',
        ],
        'description': 'Chrome browser data',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_chromium': {
        'paths': [
            '/home/*/.config/chromium/Default/History',
            '/home/*/.config/chromium/Default/Cookies',
            '/home/*/.config/chromium/Default/Login Data',
        ],
        'description': 'Chromium browser data',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'linux',
        'path_optional': True,
    },

    # ==========================================================================
    # Application Data
    # ==========================================================================

    'linux_docker': {
        'paths': [
            '/var/lib/docker/containers/*/*.json',
            '/etc/docker/daemon.json',
        ],
        'description': 'Docker container information',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_mysql': {
        'paths': [
            '/var/log/mysql/error.log',
            '/var/lib/mysql/*.err',
            '/home/*/.mysql_history',
        ],
        'description': 'MySQL logs and history',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_postgresql': {
        'paths': [
            '/var/log/postgresql/*.log',
            '/home/*/.psql_history',
        ],
        'description': 'PostgreSQL logs and history',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_apache': {
        'paths': [
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/httpd/access_log',
            '/var/log/httpd/error_log',
        ],
        'description': 'Apache web server logs',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_nginx': {
        'paths': [
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
        ],
        'description': 'Nginx web server logs',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_git': {
        'paths': [
            '/home/*/.gitconfig',
            '/home/*/.git-credentials',
        ],
        'description': 'Git settings and credentials',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    # ==========================================================================
    # System Configuration
    # ==========================================================================

    'linux_os_release': {
        'paths': [
            '/etc/os-release',
            '/etc/lsb-release',
            '/etc/redhat-release',
            '/etc/debian_version',
        ],
        'description': 'OS version information',
        'forensic_value': 'medium',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_hostname': {
        'paths': [
            '/etc/hostname',
            '/etc/machine-id',
        ],
        'description': 'Hostname and machine ID',
        'forensic_value': 'medium',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_fstab': {
        'paths': [
            '/etc/fstab',
        ],
        'description': 'File system mount settings',
        'forensic_value': 'medium',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_timezone': {
        'paths': [
            '/etc/timezone',
            '/etc/localtime',
        ],
        'description': 'Timezone settings',
        'forensic_value': 'low',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_sysctl': {
        'paths': [
            '/etc/sysctl.conf',
            '/etc/sysctl.d/*.conf',
        ],
        'description': 'Kernel parameter configuration (network forwarding, ASLR)',
        'forensic_value': 'high',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_login_defs': {
        'paths': [
            '/etc/login.defs',
        ],
        'description': 'Login policy (password aging, UID ranges)',
        'forensic_value': 'medium',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_selinux': {
        'paths': [
            '/etc/selinux/config',
        ],
        'description': 'SELinux security configuration',
        'forensic_value': 'high',
        'category': 'security',
        'os_type': 'linux',
    },

    'linux_apparmor': {
        'paths': [
            '/etc/apparmor.d/*',
            '/etc/apparmor/parser.conf',
        ],
        'description': 'AppArmor mandatory access control profiles',
        'forensic_value': 'high',
        'category': 'security',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Additional User Activity
    # ==========================================================================

    'linux_python_history': {
        'paths': [
            '/home/*/.python_history',
            '/root/.python_history',
        ],
        'description': 'Python interactive shell history',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_mysql_history': {
        'paths': [
            '/home/*/.mysql_history',
            '/root/.mysql_history',
        ],
        'description': 'MySQL CLI command history',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_psql_history': {
        'paths': [
            '/home/*/.psql_history',
            '/root/.psql_history',
        ],
        'description': 'PostgreSQL CLI command history',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_lesshst': {
        'paths': [
            '/home/*/.lesshst',
            '/root/.lesshst',
        ],
        'description': 'Less pager search and command history',
        'forensic_value': 'medium',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_nano_history': {
        'paths': [
            '/home/*/.nano/search_history',
            '/root/.nano/search_history',
        ],
        'description': 'Nano editor search history',
        'forensic_value': 'medium',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_wget_hsts': {
        'paths': [
            '/home/*/.wget-hsts',
            '/root/.wget-hsts',
        ],
        'description': 'Wget HSTS cache (evidence of file downloads)',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_xsession_errors': {
        'paths': [
            '/home/*/.xsession-errors',
            '/home/*/.xsession-errors.old',
        ],
        'description': 'X11 session errors (GUI application crashes, execution evidence)',
        'forensic_value': 'medium',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    # ==========================================================================
    # Additional Authentication & Security
    # ==========================================================================

    'linux_pam_config': {
        'paths': [
            '/etc/pam.d/common-auth',
            '/etc/pam.d/common-password',
            '/etc/pam.d/sshd',
            '/etc/pam.d/sudo',
            '/etc/pam.d/login',
            '/etc/pam.d/su',
        ],
        'description': 'PAM authentication module configuration',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_security_limits': {
        'paths': [
            '/etc/security/limits.conf',
            '/etc/security/limits.d/*',
            '/etc/security/access.conf',
        ],
        'description': 'Security limits and access control configuration',
        'forensic_value': 'medium',
        'category': 'security',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Additional System Logs
    # ==========================================================================

    'linux_journald': {
        'paths': [
            '/var/log/journal/*/*.journal',
            '/var/log/journal/*/*.journal~',
        ],
        'description': 'Systemd journal binary logs (persistent journald)',
        'forensic_value': 'critical',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_systemd_journal': {
        'paths': [
            '/var/log/journal/*/*.journal',
            '/var/log/journal/*/*.journal~',
            '/run/log/journal/*/*.journal',
        ],
        'description': 'Systemd journal records from persistent or live store',
        'forensic_value': 'critical',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_ufw_log': {
        'paths': [
            '/var/log/ufw.log',
            '/var/log/ufw.log.*',
        ],
        'description': 'UFW firewall log (Debian/Ubuntu)',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Additional Network
    # ==========================================================================

    'linux_networkmanager': {
        'paths': [
            '/etc/NetworkManager/NetworkManager.conf',
            '/etc/NetworkManager/system-connections/*',
        ],
        'description': 'NetworkManager configuration and saved connections (may contain WiFi PSK)',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    'linux_wifi_config': {
        'paths': [
            '/etc/wpa_supplicant/wpa_supplicant.conf',
            '/etc/wpa_supplicant/*.conf',
        ],
        'description': 'WPA supplicant WiFi configuration (SSID, PSK)',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    'linux_nftables': {
        'paths': [
            '/etc/nftables.conf',
            '/etc/nftables.d/*.nft',
        ],
        'description': 'nftables firewall rules',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Additional Persistence Mechanisms
    # ==========================================================================

    'linux_systemd_generators': {
        'paths': [
            '/etc/systemd/system-generators/*',
            '/usr/lib/systemd/system-generators/*',
        ],
        'description': 'Systemd generators (run at boot before services)',
        'forensic_value': 'critical',
        'category': 'persistence',
        'os_type': 'linux',
    },

    'linux_udev_rules': {
        'paths': [
            '/etc/udev/rules.d/*.rules',
            '/usr/lib/udev/rules.d/*.rules',
        ],
        'description': 'Udev device event rules (triggers on device insertion)',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'linux',
    },

    'linux_motd': {
        'paths': [
            '/etc/motd',
            '/etc/update-motd.d/*',
        ],
        'description': 'Message of the day scripts (executed at login)',
        'forensic_value': 'medium',
        'category': 'persistence',
        'os_type': 'linux',
    },

    'linux_xprofile': {
        'paths': [
            '/home/*/.xprofile',
            '/home/*/.xinitrc',
            '/home/*/.xsessionrc',
            '/etc/X11/Xsession.d/*',
        ],
        'description': 'X11 login scripts (persistence via GUI session)',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'linux',
        'path_optional': True,
    },

    # ==========================================================================
    # Additional Web Server / Application Logs
    # ==========================================================================

    'linux_apache_config': {
        'paths': [
            '/etc/apache2/apache2.conf',
            '/etc/apache2/sites-enabled/*',
            '/etc/httpd/conf/httpd.conf',
            '/etc/httpd/conf.d/*',
        ],
        'description': 'Apache web server configuration',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_nginx_config': {
        'paths': [
            '/etc/nginx/nginx.conf',
            '/etc/nginx/sites-enabled/*',
            '/etc/nginx/conf.d/*',
        ],
        'description': 'Nginx web server configuration',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_php_log': {
        'paths': [
            '/var/log/php*.log',
            '/var/log/php-fpm/*.log',
        ],
        'description': 'PHP error and FPM logs',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Additional Container / Virtualization
    # ==========================================================================

    'linux_docker_containers': {
        'paths': [
            '/var/lib/docker/containers/*/*-json.log',
        ],
        'description': 'Docker container stdout/stderr logs',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_container_state': {
        'paths': [
            '/var/lib/docker/containers/*/config.v2.json',
            '/var/lib/docker/containers/*/hostconfig.json',
            '/var/lib/docker/containers/*/*-json.log',
            '/var/lib/docker/image/overlay2/repositories.json',
            '/var/lib/containers/storage/overlay-containers/containers.json',
            '/home/*/.local/share/containers/storage/overlay-containers/containers.json',
        ],
        'description': 'Docker and Podman runtime state',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_podman': {
        'paths': [
            '/home/*/.config/containers/containers.conf',
            '/etc/containers/containers.conf',
            '/etc/containers/registries.conf',
        ],
        'description': 'Podman container engine configuration',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_libvirt': {
        'paths': [
            '/etc/libvirt/qemu/*.xml',
            '/var/log/libvirt/qemu/*.log',
        ],
        'description': 'KVM/QEMU virtual machine definitions and logs',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Additional Database Artifacts
    # ==========================================================================

    'linux_redis': {
        'paths': [
            '/etc/redis/redis.conf',
            '/etc/redis.conf',
            '/var/log/redis/redis-server.log',
        ],
        'description': 'Redis configuration and server log',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_mongodb': {
        'paths': [
            '/etc/mongod.conf',
            '/var/log/mongodb/mongod.log',
        ],
        'description': 'MongoDB configuration and server log',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Additional Application Artifacts
    # ==========================================================================

    'linux_thunderbird': {
        'paths': [
            '/home/*/.thunderbird/*.default*/prefs.js',
            '/home/*/.thunderbird/*.default*/global-messages-db.sqlite',
            '/home/*/.thunderbird/*.default*/places.sqlite',
        ],
        'description': 'Thunderbird email client data',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_aws_credentials': {
        'paths': [
            '/home/*/.aws/credentials',
            '/home/*/.aws/config',
            '/root/.aws/credentials',
        ],
        'description': 'AWS CLI credentials and configuration',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_gcloud_config': {
        'paths': [
            '/home/*/.config/gcloud/properties',
            '/home/*/.config/gcloud/credentials.db',
            '/home/*/.config/gcloud/access_tokens.db',
        ],
        'description': 'Google Cloud SDK configuration and credentials',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_azure_config': {
        'paths': [
            '/home/*/.azure/azureProfile.json',
            '/home/*/.azure/accessTokens.json',
            '/home/*/.azure/msal_token_cache.json',
        ],
        'description': 'Azure CLI configuration and token cache',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_kubectl_config': {
        'paths': [
            '/home/*/.kube/config',
            '/root/.kube/config',
        ],
        'description': 'Kubernetes kubectl configuration (cluster credentials)',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_screen_tmux': {
        'paths': [
            '/home/*/.screenrc',
            '/home/*/.tmux.conf',
            '/tmp/tmux-*/default',
        ],
        'description': 'Screen/tmux configuration and socket files',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_npm_config': {
        'paths': [
            '/home/*/.npmrc',
            '/root/.npmrc',
        ],
        'description': 'NPM configuration (may contain auth tokens)',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_pip_config': {
        'paths': [
            '/home/*/.pip/pip.conf',
            '/home/*/.config/pip/pip.conf',
            '/etc/pip.conf',
        ],
        'description': 'Python pip configuration (may contain index URLs, credentials)',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_env_files': {
        'paths': [
            '/etc/environment',
            '/etc/default/locale',
        ],
        'description': 'System-wide environment variables',
        'forensic_value': 'medium',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_crypttab': {
        'paths': [
            '/etc/crypttab',
        ],
        'description': 'Encrypted device mapping (LUKS volumes)',
        'forensic_value': 'high',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_cups_log': {
        'paths': [
            '/var/log/cups/access_log',
            '/var/log/cups/error_log',
        ],
        'description': 'CUPS printing system log (document exfiltration evidence)',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_snap_log': {
        'paths': [
            '/var/log/syslog',          # snap logs via syslog
            '/var/snap/*/common/*.log',
        ],
        'description': 'Snap package application logs',
        'forensic_value': 'low',
        'category': 'package_manager',
        'os_type': 'linux',
    },
    'linux_flatpak': {
        'paths': [
            '/var/lib/flatpak/app/*/*/*/metadata',
            '/var/lib/flatpak/appstream/*',
            '/var/lib/flatpak/exports/share/applications/*.desktop',
            '/home/*/.local/share/flatpak/app/*/*/*/metadata',
            '/home/*/.local/share/flatpak/exports/share/applications/*.desktop',
            '/home/*/.var/app/*/.flatpak-info',
            '/home/*/.var/app/*/config/*',
            '/home/*/.var/app/*/data/*',
        ],
        'description': 'Flatpak app manifests, sandbox metadata, user app data, and per-app configuration',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_dmesg': {
        'paths': [
            '/var/log/dmesg',
            '/var/log/dmesg.0',
            '/var/log/dmesg.1.gz',
        ],
        'description': 'Kernel ring buffer dump (USB insertions, hardware changes)',
        'forensic_value': 'high',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    # ==========================================================================
    # AI Agent Activity (P0 - 2026 emerging forensic surface)
    # ==========================================================================
    # See macos_artifacts.py 'ai_*' entries for the full rationale. Linux paths
    # follow XDG Base Directory ($HOME, $HOME/.config, $HOME/.cache, $HOME/.local).

    'ai_claude_code': {
        'paths': [
            '/home/*/.claude/history.jsonl',
            '/home/*/.claude/settings.json',
            '/home/*/.claude/settings.local.json',
            '/home/*/.claude/CLAUDE.md',
            '/home/*/.claude/stats-cache.json',
            '/home/*/.claude/mcp-needs-auth-cache.json',
            '/home/*/.claude/projects/*/*.jsonl',
            '/home/*/.claude/projects/*/*/*.jsonl',
            '/home/*/.claude/projects/*/*/subagents/*.jsonl',
            '/home/*/.claude/sessions/*.json',
            '/home/*/.claude/plans/*',
            '/home/*/.claude/file-history/*',
            '/home/*/.claude/shell-snapshots/*.sh',
            '/root/.claude/*',
        ],
        'description': 'Claude Code agent session logs, tool-call records, project memory, shell snapshots',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'linux',
        'note': 'JSONL format. Each line is a message, tool call, or tool result with timestamps and full content.',
    },

    'ai_claude_desktop': {
        'paths': [
            '/home/*/.config/Claude/config.json',
            '/home/*/.config/Claude/claude_desktop_config.json',
            '/home/*/.config/Claude/logs/*.log',
        ],
        'description': 'Claude Desktop config, MCP server grants, logs',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },

    'ai_chatgpt_desktop': {
        'paths': [
            '/home/*/.config/ChatGPT/*',
            '/home/*/.cache/ChatGPT/*',
        ],
        'description': 'ChatGPT Desktop config and cache',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },

    'ai_cursor': {
        'paths': [
            '/home/*/.config/Cursor/User/settings.json',
            '/home/*/.config/Cursor/User/globalStorage/state.vscdb',
            '/home/*/.config/Cursor/User/workspaceStorage/*/state.vscdb',
            '/home/*/.config/Cursor/User/History/*/*',
            '/home/*/.config/Cursor/logs/*',
        ],
        'description': 'Cursor IDE chat history, code context, workspace state (SQLite); contains full AI conversation per workspace',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'linux',
    },

    'ai_copilot_vscode': {
        'paths': [
            '/home/*/.config/Code/User/globalStorage/github.copilot-chat/*',
            '/home/*/.config/Code/User/globalStorage/github.copilot/*',
            '/home/*/.config/Code/User/workspaceStorage/*/github.copilot-chat/*',
            '/home/*/.config/Code/logs/*/exthost*/output_logging_*/*.log',
        ],
        'description': 'GitHub Copilot Chat extension logs, prompts, completions, telemetry',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'linux',
    },

    'ai_continue_dev': {
        'paths': [
            '/home/*/.continue/config.json',
            '/home/*/.continue/config.yaml',
            '/home/*/.continue/dev_data/*',
            '/home/*/.continue/index/*',
            '/home/*/.continue/sessions/*',
        ],
        'description': 'Continue.dev VS Code/JetBrains extension chat sessions, model configs, indexed code context',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },

    'ai_aider': {
        'paths': [
            '/home/*/.aider*',
            '/home/*/.aider.chat.history.md',
            '/home/*/.aider.input.history',
            '/home/*/.aider.tags.cache.v3/*',
        ],
        'description': 'Aider AI coding CLI - chat history (markdown), input history, project tags cache',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },

    'ai_ollama': {
        'paths': [
            '/home/*/.ollama/id_ed25519',
            '/home/*/.ollama/id_ed25519.pub',
            '/home/*/.ollama/history',
            '/home/*/.ollama/models/manifests/*',
            '/home/*/.ollama/logs/server.log',
            '/usr/share/ollama/.ollama/models/manifests/*',
            '/usr/share/ollama/.ollama/id_ed25519',
            '/var/log/ollama.log',
        ],
        'description': 'Ollama local LLM runtime - identity key, model manifests, server log (often contains user prompts)',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'linux',
        'note': 'On Linux, ollama often runs as systemd service under /usr/share/ollama.',
    },

    'ai_lmstudio': {
        'paths': [
            '/home/*/.cache/lm-studio/*',
            '/home/*/.lmstudio/*',
            '/home/*/.config/LMStudio/*',
        ],
        'description': 'LM Studio local LLM GUI - conversation history, model preferences',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },

    'ai_huggingface_cache': {
        'paths': [
            '/home/*/.cache/huggingface/hub/models--*/blobs/*',
            '/home/*/.cache/huggingface/hub/models--*/snapshots/*',
            '/home/*/.cache/huggingface/token',
            '/home/*/.cache/huggingface/hub/version.txt',
            '/root/.cache/huggingface/*',
        ],
        'description': 'HuggingFace models cache - downloaded model weights, API token',
        'forensic_value': 'medium',
        'category': 'ai_activity',
        'os_type': 'linux',
    },

    'ai_mcp_servers': {
        'paths': [
            '/home/*/.claude/mcp-needs-auth-cache.json',
            '/home/*/.config/Claude/claude_desktop_config.json',
            '/home/*/.continue/config.json',
            '/home/*/.continue/config.yaml',
            '/home/*/.config/claude/mcp.json',
            '/home/*/.config/Cursor/User/globalStorage/cursor.mcp/*',
        ],
        'description': 'Model Context Protocol server configurations - lists external services AI agents were granted access to',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'linux',
        'note': 'Single highest-value AI artifact: shows full attack surface granted to agents in one file.',
    },

    # ==========================================================================
    # Round 10 - Desktop AI Expansion (Linux, 2026-05-06)
    # ==========================================================================

    'ai_cline': {
        'paths': [
            '/home/*/.config/Code/User/globalStorage/saoudrizwan.claude-dev/state/*',
            '/home/*/.config/Code/User/globalStorage/saoudrizwan.claude-dev/tasks/*/api_conversation_history.json',
            '/home/*/.config/Code/User/globalStorage/saoudrizwan.claude-dev/tasks/*/ui_messages.json',
            '/home/*/.config/Code/User/globalStorage/saoudrizwan.claude-dev/tasks/*/task_metadata.json',
            '/home/*/.config/Code/User/globalStorage/saoudrizwan.claude-dev/checkpoints/*',
        ],
        'description': 'Cline (Claude Dev) VS Code extension - full task history with raw Claude API exchanges',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_roo_code': {
        'paths': [
            '/home/*/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/*',
            '/home/*/.config/Code/User/globalStorage/kilocode.kilo-code/*',
        ],
        'description': 'Roo Code / Kilo Code (Cline forks)',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_windsurf': {
        'paths': [
            '/home/*/.codeium/*',
            '/home/*/.config/Windsurf/User/globalStorage/*',
            '/home/*/.config/Windsurf/User/settings.json',
            '/home/*/.config/Windsurf/logs/*',
        ],
        'description': 'Windsurf (Codeium IDE) - Cascade agent IDE',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_jan': {
        'paths': [
            '/home/*/jan/threads/*',
            '/home/*/jan/models/*',
            '/home/*/jan/settings/*',
            '/home/*/jan/assistants/*',
            '/home/*/.config/jan/*',
        ],
        'description': 'Jan local LLM app - threads, models, settings, custom assistants',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_gpt4all': {
        'paths': [
            '/home/*/.local/share/nomic.ai/GPT4All/*',
            '/home/*/.local/share/nomic.ai/GPT4All/chats/*',
            '/home/*/.local/share/nomic.ai/GPT4All/localdocs_v3.db',
        ],
        'description': 'GPT4All - chat history (SQLite), GGUFs, LocalDocs RAG database',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_anythingllm': {
        'paths': [
            '/home/*/.config/anythingllm-desktop/storage/*',
            '/home/*/.config/anythingllm-desktop/storage/anythingllm.db',
            '/home/*/.config/anythingllm-desktop/storage/lancedb/*',
            '/home/*/.config/anythingllm-desktop/storage/documents/*',
        ],
        'description': 'AnythingLLM desktop - chat DB, LanceDB vector store, RAG documents',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_sillytavern': {
        'paths': [
            '/home/*/SillyTavern/data/default-user/chats/*',
            '/home/*/SillyTavern/data/default-user/characters/*',
            '/home/*/SillyTavern/data/default-user/secrets.json',
        ],
        'description': 'SillyTavern frontend - JSONL chat logs, character cards, secrets.json',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_open_interpreter': {
        'paths': [
            '/home/*/.config/open-interpreter/conversations.json',
            '/home/*/.config/open-interpreter/*',
        ],
        'description': 'Open Interpreter agent - commands the agent ran on the host',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_jetbrains_assistant': {
        'paths': [
            '/home/*/.cache/JetBrains/*/AIAssistant/*',
            '/home/*/.config/JetBrains/*/options/ai-*.xml',
            '/home/*/.config/JetBrains/*/options/chat-history.xml',
        ],
        'description': 'JetBrains AI Assistant - chat history XML',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_codeium': {
        'paths': [
            '/home/*/.codeium/*',
            '/home/*/.config/Code/User/globalStorage/codeium.codeium/*',
        ],
        'description': 'Codeium VS Code extension',
        'forensic_value': 'medium',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_tabnine': {
        'paths': [
            '/home/*/.tabnine/*',
            '/home/*/.config/Code/User/globalStorage/TabNine.tabnine-vscode/*',
        ],
        'description': 'Tabnine extension',
        'forensic_value': 'medium',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_sourcegraph_cody': {
        'paths': [
            '/home/*/.config/Code/User/globalStorage/sourcegraph.cody-ai/*',
            '/home/*/.config/sourcegraph/*',
        ],
        'description': 'Sourcegraph Cody',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_amazon_q': {
        'paths': [
            '/home/*/.aws/sso/cache/*',
            '/home/*/.config/Code/User/globalStorage/AmazonWebServices.aws-toolkit-vscode/*',
            '/home/*/.config/Code/User/globalStorage/amazonwebservices.amazon-q-vscode/*',
        ],
        'description': 'Amazon Q Developer / CodeWhisperer',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_pieces': {
        'paths': [
            '/home/*/.local/share/Pieces/*',
            '/home/*/.config/Pieces/*',
        ],
        'description': 'Pieces for Developers - PiecesOS SQLite snippet store',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_msty': {
        'paths': [
            '/home/*/.config/Msty/*',
            '/home/*/.config/Msty/chats/*',
        ],
        'description': 'Msty local LLM GUI',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_open_webui': {
        'paths': [
            '/home/*/.open-webui/*',
            '/home/*/.open-webui/webui.db',
            '/var/lib/open-webui/*',
        ],
        'description': 'Open WebUI - SQLite chat database',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_text_gen_webui': {
        'paths': [
            '/home/*/text-generation-webui/logs/chat/*/*.json',
            '/home/*/text-generation-webui/characters/*',
            '/home/*/text-generation-webui/loras/*',
            '/home/*/text-generation-webui/models/*',
        ],
        'description': 'text-generation-webui (Oobabooga)',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_koboldcpp': {
        'paths': [
            '/home/*/koboldcpp.cfg',
            '/home/*/KoboldCPP/*',
        ],
        'description': 'KoboldCPP single-binary local inference',
        'forensic_value': 'medium',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_backyard_ai': {
        'paths': [
            '/home/*/.config/faraday/*',
            '/home/*/.config/Backyard AI/*',
        ],
        'description': 'Backyard AI / Faraday - SQLite chats DB',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_pinokio': {
        'paths': [
            '/home/*/pinokio/*',
        ],
        'description': 'Pinokio meta-installer',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Round 11 - Browser AI Universal (Linux)
    # ==========================================================================

    'ai_browser_indexeddb': {
        'paths': [
            '/home/*/.config/google-chrome/Default/IndexedDB/https_claude.ai_0.indexeddb.leveldb/*',
            '/home/*/.config/google-chrome/Default/IndexedDB/https_chatgpt.com_0.indexeddb.leveldb/*',
            '/home/*/.config/google-chrome/Default/IndexedDB/https_gemini.google.com_0.indexeddb.leveldb/*',
            '/home/*/.config/google-chrome/Default/IndexedDB/https_copilot.microsoft.com_0.indexeddb.leveldb/*',
            '/home/*/.config/google-chrome/Default/IndexedDB/https_www.perplexity.ai_0.indexeddb.leveldb/*',
            '/home/*/.config/google-chrome/Default/IndexedDB/https_chat.deepseek.com_0.indexeddb.leveldb/*',
            '/home/*/.config/google-chrome/Default/IndexedDB/https_chat.mistral.ai_0.indexeddb.leveldb/*',
            '/home/*/.config/google-chrome/Default/IndexedDB/https_character.ai_0.indexeddb.leveldb/*',
            '/home/*/.config/google-chrome/Default/IndexedDB/https_poe.com_0.indexeddb.leveldb/*',
            '/home/*/.config/google-chrome/Default/IndexedDB/https_kimi.com_0.indexeddb.leveldb/*',
            '/home/*/.config/google-chrome/Default/IndexedDB/https_doubao.com_0.indexeddb.leveldb/*',
            '/home/*/.config/google-chrome/Default/IndexedDB/https_you.com_0.indexeddb.leveldb/*',
            '/home/*/.config/google-chrome/Default/IndexedDB/https_huggingface.co_0.indexeddb.leveldb/*',
            '/home/*/.config/google-chrome/Default/IndexedDB/https_wrtn.ai_0.indexeddb.leveldb/*',
            '/home/*/.config/microsoft-edge/Default/IndexedDB/*',
            '/home/*/.config/BraveSoftware/Brave-Browser/Default/IndexedDB/*',
            '/home/*/.mozilla/firefox/*.default*/storage/default/https+++claude.ai/idb/*.sqlite',
            '/home/*/.mozilla/firefox/*.default*/storage/default/https+++chatgpt.com/idb/*.sqlite',
        ],
        'description': 'Cloud AI conversation cache in browser IndexedDB',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_browser_localstorage': {
        'paths': [
            '/home/*/.config/google-chrome/Default/Local Storage/leveldb/*',
            '/home/*/.config/microsoft-edge/Default/Local Storage/leveldb/*',
            '/home/*/.config/BraveSoftware/Brave-Browser/Default/Local Storage/leveldb/*',
        ],
        'description': 'Browser LocalStorage (Linux)',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_browser_ai_extension': {
        'paths': [
            '/home/*/.config/google-chrome/Default/Local Extension Settings/*',
            '/home/*/.config/microsoft-edge/Default/Local Extension Settings/*',
        ],
        'description': 'Browser AI extensions on Linux',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_brave_leo': {
        'paths': [
            '/home/*/.config/BraveSoftware/Brave-Browser/Default/AIChat',
            '/home/*/.config/BraveSoftware/Brave-Browser/Default/AIChat-journal',
        ],
        'description': 'Brave Leo built-in AI - unencrypted SQLite',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    # Chrome/Chromium ships through multiple Linux package systems. Each one
    # isolates user data under a different profile root.
    #   1. Native APT/RPM: ~/.config/google-chrome[-channel]/
    #   2. Native Chromium: ~/.config/chromium/
    #   3. Snap Chromium: ~/snap/chromium/current/.config/chromium/
    #   4. Flatpak Chrome: ~/.var/app/com.google.Chrome/config/google-chrome/
    #   5. Flatpak Chromium: ~/.var/app/org.chromium.Chromium/config/chromium/
    # Each isolates user data per-package; missing any of these means
    # the on-device AI artifact is invisible on that machine.
    'ai_chrome_gemini_nano': {
        'paths': [
            # Native APT/RPM Chrome, including channel variants
            '/home/*/.config/google-chrome/*/OptimizationGuide*',
            '/home/*/.config/google-chrome/*/optimization_guide_*',
            '/home/*/.config/google-chrome-beta/*/OptimizationGuide*',
            '/home/*/.config/google-chrome-beta/*/optimization_guide_*',
            '/home/*/.config/google-chrome-unstable/*/OptimizationGuide*',
            '/home/*/.config/google-chrome-unstable/*/optimization_guide_*',
            '/home/*/.config/google-chrome-canary/*/OptimizationGuide*',
            '/home/*/.config/google-chrome-canary/*/optimization_guide_*',
            # Native Chromium
            '/home/*/.config/chromium/*/OptimizationGuide*',
            '/home/*/.config/chromium/*/optimization_guide_*',
            # Snap Chromium (Ubuntu default since 19.10)
            '/home/*/snap/chromium/current/.config/chromium/*/OptimizationGuide*',
            '/home/*/snap/chromium/current/.config/chromium/*/optimization_guide_*',
            # Flatpak Chrome
            '/home/*/.var/app/com.google.Chrome/config/google-chrome/*/OptimizationGuide*',
            '/home/*/.var/app/com.google.Chrome/config/google-chrome/*/optimization_guide_*',
            # Flatpak Chromium
            '/home/*/.var/app/org.chromium.Chromium/config/chromium/*/OptimizationGuide*',
            '/home/*/.var/app/org.chromium.Chromium/config/chromium/*/optimization_guide_*',
        ],
        'description': 'Chrome 127+ on-device Gemini Nano model store (stable/beta/dev/canary/chromium/snap/flatpak)',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Round 12 - Frontier (Linux)
    # ==========================================================================

    'ai_slack_ai_recap': {
        'paths': [
            '/home/*/.config/Slack/IndexedDB/*',
            '/home/*/.config/Slack/Cache/*',
        ],
        'description': 'Slack AI Recap and Summaries',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_agent_framework': {
        'paths': [
            '/home/*/.langchain/*',
            '/home/*/.llama_index/*',
            '/home/*/.crewai/*',
            '/home/*/.anthropic/*',
            '/home/*/.openai/*',
            '/home/*/.n8n/*',
            '/home/*/auto_gpt_workspace/*',
        ],
        'description': 'AI agent frameworks workspace artifacts',
        'forensic_value': 'high',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_api_keys': {
        'paths': [
            '/home/*/.bashrc',
            '/home/*/.zshrc',
            '/home/*/.profile',
            '/home/*/.env',
            '/home/*/.config/openai/auth.json',
            '/home/*/.config/anthropic/*',
            '/home/*/.cursor/config.json',
        ],
        'description': 'AI tool credential / API key locations',
        'forensic_value': 'critical',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
    'ai_model_files': {
        'paths': [
            '/home/*/Documents/models/*.gguf',
            '/home/*/Documents/models/*.safetensors',
            '/home/*/models/*.gguf',
            '/home/*/.cache/huggingface/hub/models--*/blobs/*',
        ],
        'description': 'AI model weight files on disk',
        'forensic_value': 'medium',
        'category': 'ai_activity',
        'os_type': 'linux',
    },
}


# ==============================================================================
# Helper Functions
# ==============================================================================

def get_linux_artifacts_by_category(category: str) -> Dict[str, Dict[str, Any]]:
    """Return Linux artifacts by category"""
    return {
        k: v for k, v in LINUX_ARTIFACT_FILTERS.items()
        if v.get('category') == category
    }


def get_linux_artifacts_by_forensic_value(value: str) -> Dict[str, Dict[str, Any]]:
    """Return Linux artifacts by forensic value"""
    return {
        k: v for k, v in LINUX_ARTIFACT_FILTERS.items()
        if v.get('forensic_value') == value
    }


def get_all_linux_artifact_paths() -> List[str]:
    """Return all Linux artifact paths (including wildcards)"""
    paths = []
    for config in LINUX_ARTIFACT_FILTERS.values():
        paths.extend(config.get('paths', []))
    return paths


def get_linux_categories() -> List[str]:
    """Return list of Linux artifact categories"""
    categories = set()
    for config in LINUX_ARTIFACT_FILTERS.values():
        if 'category' in config:
            categories.add(config['category'])
    return sorted(list(categories))


# Artifact statistics
LINUX_ARTIFACT_STATS = {
    'total_artifacts': len(LINUX_ARTIFACT_FILTERS),
    'categories': get_linux_categories(),
    'critical_artifacts': len(get_linux_artifacts_by_forensic_value('critical')),
    'high_artifacts': len(get_linux_artifacts_by_forensic_value('high')),
}
