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
