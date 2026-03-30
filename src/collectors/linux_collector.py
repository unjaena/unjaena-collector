"""
Linux Forensic Artifact Collector

Linux system forensic artifact collection module.
Collects artifacts from local system or mounted ext2/3/4 filesystems.

Collection Methods:
1. Local collection: Direct artifact collection from current system (target_root='/')
2. Mount collection: Collection after mounting ext2/3/4 image (target_root='/mnt/linux')
3. Remote collection: Collection via SSH connection (future)

For E01/RAW image analysis, use ForensicDiskAccessor (dissect-based) instead.

Core Artifacts:
- auth.log, syslog, kern.log (authentication/system logs)
- bash_history, zsh_history (command history)
- crontab, systemd services (scheduled tasks/services)
- /etc/passwd, shadow, sudoers (account information)
- ssh authorized_keys, known_hosts (SSH configuration)

MITRE ATT&CK Mapping:
- T1078 (Valid Accounts): auth.log
- T1059.004 (Unix Shell): bash_history
- T1053.003 (Cron): crontab
- T1098.004 (SSH Authorized Keys): ssh_authorized_keys
"""
import os
import glob
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Generator, Dict, Any, Optional, List, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Debug output control
_DEBUG_OUTPUT = False

def _debug_print(message: str):
    """Debug output (disabled in production)"""
    if _DEBUG_OUTPUT:
        print(message)


@dataclass
class LinuxArtifactInfo:
    """Linux artifact metadata"""
    artifact_type: str
    file_path: str
    file_size: int
    modified_time: datetime
    permissions: str
    owner: str
    content: bytes
    hash_md5: str
    hash_sha256: str
    extra_metadata: Dict[str, Any]


# Linux artifact type definitions
LINUX_ARTIFACT_TYPES = {
    # ==========================================================================
    # Authentication & Security Logs (P0 - Critical)
    # ==========================================================================
    'linux_auth_log': {
        'name': 'Linux Authentication Log',
        'description': 'Authentication events (login, sudo, ssh)',
        'paths': [
            '/var/log/auth.log',      # Debian/Ubuntu
            '/var/log/secure',         # RHEL/CentOS/Fedora
            '/var/log/auth.log.*',     # Rotated logs
            '/var/log/secure.*',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1078',
        'kill_chain_phase': 'initial_access',
    },
    'linux_syslog': {
        'name': 'Linux System Log',
        'description': 'General system events and daemon logs',
        'paths': [
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/syslog.*',
            '/var/log/messages.*',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1070.002',
        'kill_chain_phase': 'defense_evasion',
    },
    'linux_kern_log': {
        'name': 'Linux Kernel Log',
        'description': 'Kernel messages and driver events',
        'paths': [
            '/var/log/kern.log',
            '/var/log/dmesg',
            '/var/log/kern.log.*',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1014',
        'kill_chain_phase': 'defense_evasion',
    },

    # ==========================================================================
    # Shell History (P0 - Critical for command execution)
    # ==========================================================================
    'linux_bash_history': {
        'name': 'Bash Command History',
        'description': 'Executed bash commands per user',
        'paths': [
            '/home/*/.bash_history',
            '/root/.bash_history',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1059.004',
        'kill_chain_phase': 'execution',
    },
    'linux_zsh_history': {
        'name': 'Zsh Command History',
        'description': 'Executed zsh commands per user',
        'paths': [
            '/home/*/.zsh_history',
            '/home/*/.zhistory',
            '/root/.zsh_history',
            '/root/.zhistory',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1059.004',
        'kill_chain_phase': 'execution',
    },
    'linux_fish_history': {
        'name': 'Fish Command History',
        'description': 'Executed fish shell commands per user',
        'paths': [
            '/home/*/.local/share/fish/fish_history',
            '/root/.local/share/fish/fish_history',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1059.004',
        'kill_chain_phase': 'execution',
    },

    # ==========================================================================
    # Scheduled Tasks (P0 - Persistence)
    # ==========================================================================
    'linux_crontab': {
        'name': 'Crontab Entries',
        'description': 'Scheduled tasks via cron',
        'paths': [
            '/etc/crontab',
            '/etc/cron.d/*',
            '/var/spool/cron/crontabs/*',  # User crontabs (Debian)
            '/var/spool/cron/*',            # User crontabs (RHEL)
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1053.003',
        'kill_chain_phase': 'persistence',
    },
    'linux_systemd_service': {
        'name': 'Systemd Services',
        'description': 'Systemd service unit files',
        'paths': [
            '/etc/systemd/system/*.service',
            '/etc/systemd/system/**/*.service',
            '/usr/lib/systemd/system/*.service',
            '/lib/systemd/system/*.service',
            '/home/*/.config/systemd/user/*.service',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1543.002',
        'kill_chain_phase': 'persistence',
    },
    'linux_systemd_timers': {
        'name': 'Systemd Timers',
        'description': 'Systemd timer unit files (scheduled execution)',
        'paths': [
            '/etc/systemd/system/*.timer',
            '/usr/lib/systemd/system/*.timer',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1053.006',
        'kill_chain_phase': 'persistence',
    },

    # ==========================================================================
    # Account Information (P0 - Credential Access)
    # ==========================================================================
    'linux_passwd': {
        'name': 'Passwd File',
        'description': 'User account information',
        'paths': ['/etc/passwd'],
        'forensic_value': 'critical',
        'mitre_attack': 'T1087.001',
        'kill_chain_phase': 'discovery',
    },
    'linux_shadow': {
        'name': 'Shadow File',
        'description': 'Password hashes (requires root)',
        'paths': ['/etc/shadow'],
        'forensic_value': 'critical',
        'mitre_attack': 'T1003.008',
        'kill_chain_phase': 'credential_access',
    },
    'linux_group': {
        'name': 'Group File',
        'description': 'Group membership information',
        'paths': ['/etc/group'],
        'forensic_value': 'high',
        'mitre_attack': 'T1087.001',
        'kill_chain_phase': 'discovery',
    },
    'linux_sudoers': {
        'name': 'Sudoers Configuration',
        'description': 'Sudo privilege configuration',
        'paths': [
            '/etc/sudoers',
            '/etc/sudoers.d/*',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1548.003',
        'kill_chain_phase': 'privilege_escalation',
    },

    # ==========================================================================
    # SSH Artifacts (P0 - Remote Access)
    # ==========================================================================
    'linux_ssh_authorized_keys': {
        'name': 'SSH Authorized Keys',
        'description': 'Authorized public keys for SSH access',
        'paths': [
            '/home/*/.ssh/authorized_keys',
            '/root/.ssh/authorized_keys',
            '/home/*/.ssh/authorized_keys2',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1098.004',
        'kill_chain_phase': 'persistence',
    },
    'linux_ssh_known_hosts': {
        'name': 'SSH Known Hosts',
        'description': 'Previously connected SSH servers',
        'paths': [
            '/home/*/.ssh/known_hosts',
            '/root/.ssh/known_hosts',
            '/etc/ssh/ssh_known_hosts',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1021.004',
        'kill_chain_phase': 'lateral_movement',
    },
    'linux_ssh_config': {
        'name': 'SSH Configuration',
        'description': 'SSH client and server configuration',
        'paths': [
            '/home/*/.ssh/config',
            '/etc/ssh/sshd_config',
            '/etc/ssh/ssh_config',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1021.004',
        'kill_chain_phase': 'lateral_movement',
    },
    'linux_ssh_private_keys': {
        'name': 'SSH Private Keys',
        'description': 'Private key files (sensitive)',
        'paths': [
            '/home/*/.ssh/id_*',
            '/root/.ssh/id_*',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1552.004',
        'kill_chain_phase': 'credential_access',
    },

    # ==========================================================================
    # Network Configuration (P1)
    # ==========================================================================
    'linux_hosts': {
        'name': 'Hosts File',
        'description': 'Static hostname mappings',
        'paths': ['/etc/hosts'],
        'forensic_value': 'medium',
        'mitre_attack': 'T1565.001',
        'kill_chain_phase': 'defense_evasion',
    },
    'linux_resolv': {
        'name': 'DNS Configuration',
        'description': 'DNS resolver configuration',
        'paths': ['/etc/resolv.conf'],
        'forensic_value': 'medium',
        'mitre_attack': 'T1071.004',
        'kill_chain_phase': 'command_and_control',
    },
    'linux_network_interfaces': {
        'name': 'Network Interfaces',
        'description': 'Network interface configuration',
        'paths': [
            '/etc/network/interfaces',
            '/etc/netplan/*.yaml',
            '/etc/sysconfig/network-scripts/ifcfg-*',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1016',
        'kill_chain_phase': 'discovery',
    },
    'linux_iptables': {
        'name': 'Firewall Rules',
        'description': 'iptables/nftables firewall configuration',
        'paths': [
            '/etc/iptables/rules.v4',
            '/etc/iptables/rules.v6',
            '/etc/nftables.conf',
            '/etc/sysconfig/iptables',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1562.004',
        'kill_chain_phase': 'defense_evasion',
    },

    # ==========================================================================
    # Web Server Logs (P1)
    # ==========================================================================
    'linux_apache_access': {
        'name': 'Apache Access Log',
        'description': 'Apache HTTP server access logs',
        'paths': [
            '/var/log/apache2/access.log',
            '/var/log/httpd/access_log',
            '/var/log/apache2/access.log.*',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1190',
        'kill_chain_phase': 'initial_access',
    },
    'linux_apache': {
        'name': 'Apache Error Log',
        'description': 'Apache HTTP server error logs',
        'paths': [
            '/var/log/apache2/error.log',
            '/var/log/httpd/error_log',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1190',
        'kill_chain_phase': 'initial_access',
    },
    'linux_nginx_access': {
        'name': 'Nginx Access Log',
        'description': 'Nginx HTTP server access logs',
        'paths': [
            '/var/log/nginx/access.log',
            '/var/log/nginx/access.log.*',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1190',
        'kill_chain_phase': 'initial_access',
    },
    'linux_nginx': {
        'name': 'Nginx Error Log',
        'description': 'Nginx HTTP server error logs',
        'paths': ['/var/log/nginx/error.log'],
        'forensic_value': 'high',
        'mitre_attack': 'T1190',
        'kill_chain_phase': 'initial_access',
    },

    # ==========================================================================
    # Application & Process Artifacts (P1)
    # ==========================================================================
    'linux_lastlog': {
        'name': 'Last Login Record',
        'description': 'Last login time per user (binary)',
        'paths': ['/var/log/lastlog'],
        'forensic_value': 'high',
        'mitre_attack': 'T1078',
        'kill_chain_phase': 'initial_access',
    },
    'linux_wtmp': {
        'name': 'Login Records (wtmp)',
        'description': 'Login/logout history (binary)',
        'paths': [
            '/var/log/wtmp',
            '/var/log/wtmp.*',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1078',
        'kill_chain_phase': 'initial_access',
    },
    'linux_btmp': {
        'name': 'Failed Login Records (btmp)',
        'description': 'Failed login attempts (binary)',
        'paths': [
            '/var/log/btmp',
            '/var/log/btmp.*',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1110',
        'kill_chain_phase': 'credential_access',
    },
    'linux_utmp': {
        'name': 'Current Login Records (utmp)',
        'description': 'Currently logged in users (binary)',
        'paths': ['/var/run/utmp'],
        'forensic_value': 'high',
        'mitre_attack': 'T1078',
        'kill_chain_phase': 'initial_access',
    },

    # ==========================================================================
    # Application Configuration (P2)
    # ==========================================================================
    'linux_profile_scripts': {
        'name': 'Shell Profile Scripts',
        'description': 'Login shell initialization scripts',
        'paths': [
            '/etc/profile',
            '/etc/profile.d/*',
            '/etc/bash.bashrc',
            '/home/*/.bashrc',
            '/home/*/.bash_profile',
            '/home/*/.profile',
            '/root/.bashrc',
            '/root/.profile',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1546.004',
        'kill_chain_phase': 'persistence',
    },
    'linux_rc_local': {
        'name': 'rc.local Script',
        'description': 'Legacy startup script',
        'paths': [
            '/etc/rc.local',
            '/etc/rc.d/rc.local',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1037.004',
        'kill_chain_phase': 'persistence',
    },
    'linux_init_scripts': {
        'name': 'Init Scripts',
        'description': 'SysV init scripts',
        'paths': ['/etc/init.d/*'],
        'forensic_value': 'medium',
        'mitre_attack': 'T1037',
        'kill_chain_phase': 'persistence',
    },

    # ==========================================================================
    # Package & Installation (P2)
    # ==========================================================================
    'linux_apt_log': {
        'name': 'APT Package History',
        'description': 'Package installation history (Debian)',
        'paths': [
            '/var/log/apt/history.log',
            '/var/log/apt/history.log.*',
            '/var/log/dpkg.log',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1072',
        'kill_chain_phase': 'execution',
    },
    'linux_yum_log': {
        'name': 'YUM/DNF Package History',
        'description': 'Package installation history (RHEL)',
        'paths': [
            '/var/log/yum.log',
            '/var/log/dnf.log',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1072',
        'kill_chain_phase': 'execution',
    },

    # ==========================================================================
    # Docker/Container Artifacts (P2)
    # ==========================================================================
    'linux_docker': {
        'name': 'Docker Configuration',
        'description': 'Docker daemon and client configuration',
        'paths': [
            '/etc/docker/daemon.json',
            '/home/*/.docker/config.json',
            '/root/.docker/config.json',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1610',
        'kill_chain_phase': 'execution',
    },

    # ==========================================================================
    # Additional System Configuration (P1)
    # ==========================================================================
    'linux_sysctl': {
        'name': 'Kernel Parameters',
        'description': 'Sysctl kernel parameter configuration',
        'paths': [
            '/etc/sysctl.conf',
            '/etc/sysctl.d/*.conf',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1556',
        'kill_chain_phase': 'defense_evasion',
    },
    'linux_login_defs': {
        'name': 'Login Definitions',
        'description': 'Login policy configuration (password aging, UID ranges)',
        'paths': ['/etc/login.defs'],
        'forensic_value': 'medium',
        'mitre_attack': 'T1087.001',
        'kill_chain_phase': 'discovery',
    },
    'linux_selinux': {
        'name': 'SELinux Configuration',
        'description': 'SELinux mandatory access control settings',
        'paths': ['/etc/selinux/config'],
        'forensic_value': 'high',
        'mitre_attack': 'T1562.001',
        'kill_chain_phase': 'defense_evasion',
    },
    'linux_apparmor': {
        'name': 'AppArmor Profiles',
        'description': 'AppArmor mandatory access control profiles',
        'paths': [
            '/etc/apparmor.d/*',
            '/etc/apparmor/parser.conf',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1562.001',
        'kill_chain_phase': 'defense_evasion',
    },

    # ==========================================================================
    # Additional User Activity (P1)
    # ==========================================================================
    'linux_python_history': {
        'name': 'Python Shell History',
        'description': 'Python interactive shell command history',
        'paths': [
            '/home/*/.python_history',
            '/root/.python_history',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1059.006',
        'kill_chain_phase': 'execution',
    },
    'linux_mysql_history': {
        'name': 'MySQL CLI History',
        'description': 'MySQL command line client history',
        'paths': [
            '/home/*/.mysql_history',
            '/root/.mysql_history',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1059',
        'kill_chain_phase': 'execution',
    },
    'linux_psql_history': {
        'name': 'PostgreSQL CLI History',
        'description': 'PostgreSQL command line client history',
        'paths': [
            '/home/*/.psql_history',
            '/root/.psql_history',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1059',
        'kill_chain_phase': 'execution',
    },
    'linux_lesshst': {
        'name': 'Less Pager History',
        'description': 'Less pager search and command history',
        'paths': [
            '/home/*/.lesshst',
            '/root/.lesshst',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1083',
        'kill_chain_phase': 'discovery',
    },
    'linux_nano_history': {
        'name': 'Nano Editor History',
        'description': 'Nano editor search history',
        'paths': [
            '/home/*/.nano/search_history',
            '/root/.nano/search_history',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1083',
        'kill_chain_phase': 'discovery',
    },
    'linux_wget_hsts': {
        'name': 'Wget HSTS Cache',
        'description': 'Wget HTTP Strict Transport Security cache (download evidence)',
        'paths': [
            '/home/*/.wget-hsts',
            '/root/.wget-hsts',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1105',
        'kill_chain_phase': 'command_and_control',
    },
    'linux_xsession_errors': {
        'name': 'X Session Errors',
        'description': 'X11 session error log (GUI application execution evidence)',
        'paths': [
            '/home/*/.xsession-errors',
            '/home/*/.xsession-errors.old',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1204',
        'kill_chain_phase': 'execution',
    },

    # ==========================================================================
    # Additional Authentication & Security (P0)
    # ==========================================================================
    'linux_pam_config': {
        'name': 'PAM Configuration',
        'description': 'Pluggable Authentication Module configuration',
        'paths': [
            '/etc/pam.d/common-auth',
            '/etc/pam.d/common-password',
            '/etc/pam.d/sshd',
            '/etc/pam.d/sudo',
            '/etc/pam.d/login',
            '/etc/pam.d/su',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1556.003',
        'kill_chain_phase': 'persistence',
    },
    'linux_security_limits': {
        'name': 'Security Limits',
        'description': 'Security limits and access control configuration',
        'paths': [
            '/etc/security/limits.conf',
            '/etc/security/limits.d/*',
            '/etc/security/access.conf',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1078',
        'kill_chain_phase': 'initial_access',
    },

    # ==========================================================================
    # Additional System Logs (P0)
    # ==========================================================================
    'linux_journald': {
        'name': 'Systemd Journal',
        'description': 'Systemd journal binary logs (persistent)',
        'paths': [
            '/var/log/journal/*/*.journal',
            '/var/log/journal/*/*.journal~',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1070.002',
        'kill_chain_phase': 'defense_evasion',
    },
    'linux_ufw_log': {
        'name': 'UFW Firewall Log',
        'description': 'Uncomplicated Firewall log (Ubuntu)',
        'paths': [
            '/var/log/ufw.log',
            '/var/log/ufw.log.*',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1562.004',
        'kill_chain_phase': 'defense_evasion',
    },
    'linux_dmesg': {
        'name': 'Kernel Ring Buffer',
        'description': 'Kernel ring buffer dump (USB, hardware, driver events)',
        'paths': [
            '/var/log/dmesg',
            '/var/log/dmesg.0',
            '/var/log/dmesg.1.gz',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1014',
        'kill_chain_phase': 'defense_evasion',
    },
    'linux_cups_log': {
        'name': 'CUPS Printing Log',
        'description': 'Print job log (document exfiltration evidence)',
        'paths': [
            '/var/log/cups/access_log',
            '/var/log/cups/error_log',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1048',
        'kill_chain_phase': 'exfiltration',
    },

    # ==========================================================================
    # Additional Network (P1)
    # ==========================================================================
    'linux_networkmanager': {
        'name': 'NetworkManager Configuration',
        'description': 'NetworkManager config and saved connections (WiFi PSK)',
        'paths': [
            '/etc/NetworkManager/NetworkManager.conf',
            '/etc/NetworkManager/system-connections/*',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1016',
        'kill_chain_phase': 'discovery',
    },
    'linux_wifi_config': {
        'name': 'WiFi Configuration',
        'description': 'WPA supplicant WiFi config (SSID, PSK)',
        'paths': [
            '/etc/wpa_supplicant/wpa_supplicant.conf',
            '/etc/wpa_supplicant/*.conf',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1552.001',
        'kill_chain_phase': 'credential_access',
    },
    'linux_nftables': {
        'name': 'nftables Rules',
        'description': 'nftables firewall rules configuration',
        'paths': [
            '/etc/nftables.conf',
            '/etc/nftables.d/*.nft',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1562.004',
        'kill_chain_phase': 'defense_evasion',
    },

    # ==========================================================================
    # Additional Persistence (P0)
    # ==========================================================================
    'linux_systemd_generators': {
        'name': 'Systemd Generators',
        'description': 'Systemd generators (run at boot before services)',
        'paths': [
            '/etc/systemd/system-generators/*',
            '/usr/lib/systemd/system-generators/*',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1543.002',
        'kill_chain_phase': 'persistence',
    },
    'linux_udev_rules': {
        'name': 'Udev Rules',
        'description': 'Udev device event rules (triggers on device events)',
        'paths': [
            '/etc/udev/rules.d/*.rules',
            '/usr/lib/udev/rules.d/*.rules',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1546',
        'kill_chain_phase': 'persistence',
    },
    'linux_motd': {
        'name': 'MOTD Scripts',
        'description': 'Message of the day scripts (executed at login)',
        'paths': [
            '/etc/motd',
            '/etc/update-motd.d/*',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1546.004',
        'kill_chain_phase': 'persistence',
    },
    'linux_xprofile': {
        'name': 'X11 Login Scripts',
        'description': 'X11 session initialization scripts (GUI persistence)',
        'paths': [
            '/home/*/.xprofile',
            '/home/*/.xinitrc',
            '/home/*/.xsessionrc',
            '/etc/X11/Xsession.d/*',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1546.004',
        'kill_chain_phase': 'persistence',
    },

    # ==========================================================================
    # Additional Web Server Configuration (P2)
    # ==========================================================================
    'linux_apache_config': {
        'name': 'Apache Configuration',
        'description': 'Apache HTTP server configuration files',
        'paths': [
            '/etc/apache2/apache2.conf',
            '/etc/apache2/sites-enabled/*',
            '/etc/httpd/conf/httpd.conf',
            '/etc/httpd/conf.d/*',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1190',
        'kill_chain_phase': 'initial_access',
    },
    'linux_nginx_config': {
        'name': 'Nginx Configuration',
        'description': 'Nginx HTTP server configuration files',
        'paths': [
            '/etc/nginx/nginx.conf',
            '/etc/nginx/sites-enabled/*',
            '/etc/nginx/conf.d/*',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1190',
        'kill_chain_phase': 'initial_access',
    },
    'linux_php_log': {
        'name': 'PHP Error Log',
        'description': 'PHP error and FPM logs',
        'paths': [
            '/var/log/php*.log',
            '/var/log/php-fpm/*.log',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1190',
        'kill_chain_phase': 'initial_access',
    },

    # ==========================================================================
    # Additional Container / Virtualization (P2)
    # ==========================================================================
    'linux_docker_containers': {
        'name': 'Docker Container Logs',
        'description': 'Docker container stdout/stderr log files',
        'paths': [
            '/var/lib/docker/containers/*/*-json.log',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1610',
        'kill_chain_phase': 'execution',
    },
    'linux_podman': {
        'name': 'Podman Configuration',
        'description': 'Podman container engine configuration',
        'paths': [
            '/home/*/.config/containers/containers.conf',
            '/etc/containers/containers.conf',
            '/etc/containers/registries.conf',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1610',
        'kill_chain_phase': 'execution',
    },
    'linux_libvirt': {
        'name': 'KVM/QEMU Configuration',
        'description': 'KVM/QEMU virtual machine definitions and logs',
        'paths': [
            '/etc/libvirt/qemu/*.xml',
            '/var/log/libvirt/qemu/*.log',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1564.006',
        'kill_chain_phase': 'defense_evasion',
    },

    # ==========================================================================
    # Additional Database (P2)
    # ==========================================================================
    'linux_redis': {
        'name': 'Redis Configuration & Log',
        'description': 'Redis configuration and server log',
        'paths': [
            '/etc/redis/redis.conf',
            '/etc/redis.conf',
            '/var/log/redis/redis-server.log',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1505',
        'kill_chain_phase': 'persistence',
    },
    'linux_mongodb': {
        'name': 'MongoDB Configuration & Log',
        'description': 'MongoDB configuration and server log',
        'paths': [
            '/etc/mongod.conf',
            '/var/log/mongodb/mongod.log',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1505',
        'kill_chain_phase': 'persistence',
    },

    # ==========================================================================
    # Additional Application Artifacts (P1-P2)
    # ==========================================================================
    'linux_thunderbird': {
        'name': 'Thunderbird Email Client',
        'description': 'Thunderbird email client data and settings',
        'paths': [
            '/home/*/.thunderbird/*.default*/prefs.js',
            '/home/*/.thunderbird/*.default*/global-messages-db.sqlite',
            '/home/*/.thunderbird/*.default*/places.sqlite',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1114.001',
        'kill_chain_phase': 'collection',
    },
    'linux_aws_credentials': {
        'name': 'AWS Credentials',
        'description': 'AWS CLI credentials and configuration',
        'paths': [
            '/home/*/.aws/credentials',
            '/home/*/.aws/config',
            '/root/.aws/credentials',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1552.001',
        'kill_chain_phase': 'credential_access',
    },
    'linux_gcloud_config': {
        'name': 'Google Cloud Credentials',
        'description': 'Google Cloud SDK configuration and credentials',
        'paths': [
            '/home/*/.config/gcloud/properties',
            '/home/*/.config/gcloud/credentials.db',
            '/home/*/.config/gcloud/access_tokens.db',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1552.001',
        'kill_chain_phase': 'credential_access',
    },
    'linux_azure_config': {
        'name': 'Azure CLI Credentials',
        'description': 'Azure CLI configuration and token cache',
        'paths': [
            '/home/*/.azure/azureProfile.json',
            '/home/*/.azure/accessTokens.json',
            '/home/*/.azure/msal_token_cache.json',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1552.001',
        'kill_chain_phase': 'credential_access',
    },
    'linux_kubectl_config': {
        'name': 'Kubernetes Config',
        'description': 'Kubernetes kubectl configuration (cluster credentials)',
        'paths': [
            '/home/*/.kube/config',
            '/root/.kube/config',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1552.001',
        'kill_chain_phase': 'credential_access',
    },
    'linux_screen_tmux': {
        'name': 'Screen/Tmux Config',
        'description': 'Screen/tmux configuration and socket files',
        'paths': [
            '/home/*/.screenrc',
            '/home/*/.tmux.conf',
            '/tmp/tmux-*/default',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1059.004',
        'kill_chain_phase': 'execution',
    },
    'linux_npm_config': {
        'name': 'NPM Configuration',
        'description': 'NPM configuration (may contain auth tokens)',
        'paths': [
            '/home/*/.npmrc',
            '/root/.npmrc',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1552.001',
        'kill_chain_phase': 'credential_access',
    },
    'linux_pip_config': {
        'name': 'Python Pip Configuration',
        'description': 'Pip configuration (may contain index URLs, credentials)',
        'paths': [
            '/home/*/.pip/pip.conf',
            '/home/*/.config/pip/pip.conf',
            '/etc/pip.conf',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1552.001',
        'kill_chain_phase': 'credential_access',
    },
    'linux_env_files': {
        'name': 'Environment Variables',
        'description': 'System-wide environment variable configuration',
        'paths': [
            '/etc/environment',
            '/etc/default/locale',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1574.007',
        'kill_chain_phase': 'persistence',
    },
    'linux_crypttab': {
        'name': 'Encrypted Volumes',
        'description': 'Encrypted device mapping configuration (LUKS)',
        'paths': ['/etc/crypttab'],
        'forensic_value': 'high',
        'mitre_attack': 'T1486',
        'kill_chain_phase': 'impact',
    },
    'linux_snap_log': {
        'name': 'Snap Package Logs',
        'description': 'Snap package application logs',
        'paths': [
            '/var/snap/*/common/*.log',
        ],
        'forensic_value': 'low',
        'mitre_attack': 'T1072',
        'kill_chain_phase': 'execution',
    },

    # ==========================================================================
    # System Logs - Additional (P1)
    # ==========================================================================
    'linux_boot_log': {
        'name': 'Boot Log',
        'description': 'System boot messages',
        'paths': [
            '/var/log/boot.log',
            '/var/log/boot.msg',              # SUSE
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1014',
        'kill_chain_phase': 'defense_evasion',
    },
    'linux_daemon_log': {
        'name': 'Daemon Log',
        'description': 'Daemon service log',
        'paths': [
            '/var/log/daemon.log',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1543',
        'kill_chain_phase': 'persistence',
    },
    'linux_cron_log': {
        'name': 'Cron Log',
        'description': 'Cron job execution log',
        'paths': [
            '/var/log/cron',
            '/var/log/cron.log',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1053.003',
        'kill_chain_phase': 'persistence',
    },
    'linux_mail_log': {
        'name': 'Mail Log',
        'description': 'Mail server log',
        'paths': [
            '/var/log/mail.log',
            '/var/log/maillog',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1114',
        'kill_chain_phase': 'collection',
    },
    'linux_dpkg_log': {
        'name': 'DPKG Package Log',
        'description': 'DPKG package installation log',
        'paths': [
            '/var/log/dpkg.log',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1072',
        'kill_chain_phase': 'execution',
    },

    # ==========================================================================
    # Security Logs - Additional (P0)
    # ==========================================================================
    'linux_audit_log': {
        'name': 'Audit Log',
        'description': 'Audit log (SELinux, security events)',
        'paths': [
            '/var/log/audit/audit.log',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1070.002',
        'kill_chain_phase': 'defense_evasion',
    },
    'linux_faillog': {
        'name': 'Login Failure Records',
        'description': 'Login failure records',
        'paths': [
            '/var/log/faillog',
            '/var/log/btmp',                  # Failed login attempts
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1110',
        'kill_chain_phase': 'credential_access',
    },

    # ==========================================================================
    # User Activity - Additional (P1)
    # ==========================================================================
    'linux_bashrc': {
        'name': 'Bash Configuration',
        'description': 'Bash configuration files (aliases, environment variables)',
        'paths': [
            '/home/*/.bashrc',
            '/home/*/.bash_profile',
            '/home/*/.profile',
            '/root/.bashrc',
            '/etc/bash.bashrc',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1546.004',
        'kill_chain_phase': 'persistence',
    },
    'linux_viminfo': {
        'name': 'Vim Editor History',
        'description': 'Vim editor history',
        'paths': [
            '/home/*/.viminfo',
            '/root/.viminfo',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1083',
        'kill_chain_phase': 'discovery',
    },
    'linux_recent_files': {
        'name': 'Recently Used Files',
        'description': 'Recently used files (GNOME)',
        'paths': [
            '/home/*/.local/share/recently-used.xbel',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1083',
        'kill_chain_phase': 'discovery',
    },
    'linux_trash': {
        'name': 'Trash Contents',
        'description': 'Trash contents and metadata',
        'paths': [
            '/home/*/.local/share/Trash/files/*',
            '/home/*/.local/share/Trash/info/*',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1070.004',
        'kill_chain_phase': 'defense_evasion',
    },

    # ==========================================================================
    # Scheduled Tasks - Additional (P1)
    # ==========================================================================
    'linux_anacron': {
        'name': 'Anacron Scheduled Tasks',
        'description': 'Anacron scheduled tasks',
        'paths': [
            '/etc/anacrontab',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1053.003',
        'kill_chain_phase': 'persistence',
    },
    'linux_at_jobs': {
        'name': 'At Scheduled Jobs',
        'description': 'at scheduled tasks',
        'paths': [
            '/var/spool/at/*',
            '/var/spool/atjobs/*',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1053.002',
        'kill_chain_phase': 'persistence',
    },

    # ==========================================================================
    # Persistence Mechanisms - Additional (P0)
    # ==========================================================================
    'linux_autostart': {
        'name': 'Auto-Start Items',
        'description': 'Auto-start items (GUI desktop entries)',
        'paths': [
            '/etc/xdg/autostart/*.desktop',
            '/home/*/.config/autostart/*.desktop',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1547.001',
        'kill_chain_phase': 'persistence',
    },
    'linux_ld_preload': {
        'name': 'LD Preload Configuration',
        'description': 'Dynamic library preload settings',
        'paths': [
            '/etc/ld.so.preload',
            '/etc/ld.so.conf',
            '/etc/ld.so.conf.d/*',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1574.006',
        'kill_chain_phase': 'persistence',
    },
    'linux_modules': {
        'name': 'Kernel Module Settings',
        'description': 'Kernel module configuration',
        'paths': [
            '/etc/modules',
            '/etc/modprobe.d/*',
            '/etc/modules-load.d/*',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1547.006',
        'kill_chain_phase': 'persistence',
    },

    # ==========================================================================
    # Browser Artifacts (P1)
    # ==========================================================================
    'linux_firefox': {
        'name': 'Firefox Browser Data',
        'description': 'Firefox browser data',
        'paths': [
            '/home/*/.mozilla/firefox/*.default*/places.sqlite',
            '/home/*/.mozilla/firefox/*.default*/cookies.sqlite',
            '/home/*/.mozilla/firefox/*.default*/formhistory.sqlite',
            '/home/*/.mozilla/firefox/*.default*/logins.json',
            '/home/*/.mozilla/firefox/*.default*/key4.db',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1539',
        'kill_chain_phase': 'credential_access',
    },
    'linux_chrome': {
        'name': 'Chrome Browser Data',
        'description': 'Chrome browser data',
        'paths': [
            '/home/*/.config/google-chrome/Default/History',
            '/home/*/.config/google-chrome/Default/Cookies',
            '/home/*/.config/google-chrome/Default/Login Data',
            '/home/*/.config/google-chrome/Default/Bookmarks',
            '/home/*/.config/google-chrome/Default/Web Data',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1539',
        'kill_chain_phase': 'credential_access',
    },
    'linux_chromium': {
        'name': 'Chromium Browser Data',
        'description': 'Chromium browser data',
        'paths': [
            '/home/*/.config/chromium/Default/History',
            '/home/*/.config/chromium/Default/Cookies',
            '/home/*/.config/chromium/Default/Login Data',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1539',
        'kill_chain_phase': 'credential_access',
    },

    # ==========================================================================
    # Application Data - Additional (P1-P2)
    # ==========================================================================
    'linux_mysql': {
        'name': 'MySQL Logs and History',
        'description': 'MySQL logs and history',
        'paths': [
            '/var/log/mysql/error.log',
            '/var/lib/mysql/*.err',
            '/home/*/.mysql_history',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1505',
        'kill_chain_phase': 'persistence',
    },
    'linux_postgresql': {
        'name': 'PostgreSQL Logs and History',
        'description': 'PostgreSQL logs and history',
        'paths': [
            '/var/log/postgresql/*.log',
            '/home/*/.psql_history',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1505',
        'kill_chain_phase': 'persistence',
    },
    'linux_git': {
        'name': 'Git Configuration',
        'description': 'Git settings and stored credentials',
        'paths': [
            '/home/*/.gitconfig',
            '/home/*/.git-credentials',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1552.001',
        'kill_chain_phase': 'credential_access',
    },

    # ==========================================================================
    # System Configuration - Additional (P2)
    # ==========================================================================
    'linux_os_release': {
        'name': 'OS Version Information',
        'description': 'OS version information',
        'paths': [
            '/etc/os-release',
            '/etc/lsb-release',
            '/etc/redhat-release',
            '/etc/debian_version',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1082',
        'kill_chain_phase': 'discovery',
    },
    'linux_hostname': {
        'name': 'Hostname and Machine ID',
        'description': 'Hostname and machine ID',
        'paths': [
            '/etc/hostname',
            '/etc/machine-id',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1082',
        'kill_chain_phase': 'discovery',
    },
    'linux_fstab': {
        'name': 'File System Mount Settings',
        'description': 'File system mount configuration',
        'paths': [
            '/etc/fstab',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1082',
        'kill_chain_phase': 'discovery',
    },
    'linux_timezone': {
        'name': 'Timezone Settings',
        'description': 'Timezone settings',
        'paths': [
            '/etc/timezone',
            '/etc/localtime',
        ],
        'forensic_value': 'low',
        'mitre_attack': 'T1070.006',
        'kill_chain_phase': 'defense_evasion',
    },
}


class LinuxCollector:
    """
    Linux Forensic Artifact Collector

    Collects forensic artifacts from local or mounted filesystems.

    Collection Modes:
    1. Local/Mount mode: Direct collection from target_root path (default)

    For E01/RAW image analysis, use ForensicDiskAccessor (dissect-based) instead.
    """

    def __init__(
        self,
        output_dir: str,
        target_root: str = '/',
        e01_path: Optional[str] = None,
        partition_offset: Optional[int] = None
    ):
        """
        Initialize Linux collector.

        Args:
            output_dir: Directory to store collected artifacts
            target_root: Root path for collection (default: '/' for local)
                        Use mount point for mounted image analysis
            e01_path: DEPRECATED - use ForensicDiskAccessor.from_e01() instead
            partition_offset: DEPRECATED - use ForensicDiskAccessor instead
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        if e01_path:
            raise NotImplementedError(
                "E01 direct collection via pytsk3 has been removed. "
                "Use ForensicDiskAccessor.from_e01() with dissect instead."
            )

        # Local/mount collection mode
        self.target_root = Path(target_root)
        if not self.target_root.exists():
            raise FileNotFoundError(f"Target root not found: {target_root}")

        _debug_print(f"[LinuxCollector] Initialized: target_root={target_root}")

    def close(self):
        """Release resources (no-op for local/mount mode)"""
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def get_artifact_types(self) -> Dict[str, Dict[str, Any]]:
        """Return supported artifact types"""
        return LINUX_ARTIFACT_TYPES

    def collect(
        self,
        artifact_type: str,
        **kwargs
    ) -> Generator[Tuple[str, bytes, Dict[str, Any]], None, None]:
        """
        Collect specified artifact type.

        Args:
            artifact_type: Type of artifact to collect (e.g., 'linux_auth_log')

        Yields:
            Tuple of (relative_path, content_bytes, metadata)
        """
        if artifact_type not in LINUX_ARTIFACT_TYPES:
            raise ValueError(f"Unknown artifact type: {artifact_type}")

        config = LINUX_ARTIFACT_TYPES[artifact_type]
        paths = config.get('paths', [])

        _debug_print(f"[LinuxCollector] Collecting {artifact_type} from {len(paths)} path patterns")

        # Local/mount collection mode
        for pattern in paths:
            # Combine with target root
            full_pattern = str(self.target_root) + pattern

            # Expand glob pattern
            for file_path in glob.glob(full_pattern, recursive=True):
                try:
                    yield from self._collect_file(file_path, artifact_type, config)
                except Exception as e:
                    logger.warning(f"[LinuxCollector] Failed to collect {file_path}: {e}")

    def _collect_file(
        self,
        file_path: str,
        artifact_type: str,
        config: Dict[str, Any]
    ) -> Generator[Tuple[str, bytes, Dict[str, Any]], None, None]:
        """
        Collect a single file.

        Args:
            file_path: Full path to file
            artifact_type: Artifact type identifier
            config: Artifact type configuration

        Yields:
            Tuple of (relative_path, content_bytes, metadata)
        """
        path = Path(file_path)

        if not path.exists():
            return

        if not path.is_file():
            return

        try:
            stat_info = path.stat()

            # Read file content (cap at 100MB to prevent OOM)
            MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
            if stat_info.st_size > MAX_FILE_SIZE:
                logger.warning(
                    f"[LinuxCollector] File too large ({stat_info.st_size / (1024**2):.0f}MB > 100MB), "
                    f"truncating: {path}"
                )
            with open(path, 'rb') as f:
                content = f.read(MAX_FILE_SIZE)

            # Calculate hashes
            hash_sha256 = hashlib.sha256(content).hexdigest()

            # Extract username from path if applicable
            username = self._extract_username(str(path))

            # Get file permissions (Unix style)
            permissions = oct(stat_info.st_mode)[-3:]

            # Get owner (if possible)
            try:
                import pwd
                owner = pwd.getpwuid(stat_info.st_uid).pw_name
            except (ImportError, KeyError):
                owner = str(stat_info.st_uid)

            # Build metadata
            metadata = {
                'artifact_type': artifact_type,
                'original_path': str(path),
                'file_size': stat_info.st_size,
                'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed_time': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                'created_time': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'permissions': permissions,
                'owner': owner,
                'hash_sha256': hash_sha256,
                'forensic_value': config.get('forensic_value', 'medium'),
                'mitre_attack': config.get('mitre_attack', ''),
                'kill_chain_phase': config.get('kill_chain_phase', ''),
            }

            if username:
                metadata['username'] = username

            # Relative path from target root
            try:
                relative_path = str(path.relative_to(self.target_root))
            except ValueError:
                relative_path = str(path)

            yield (relative_path, content, metadata)

            _debug_print(f"[LinuxCollector] Collected: {relative_path} ({stat_info.st_size} bytes)")

        except PermissionError:
            logger.warning(f"[LinuxCollector] Permission denied: {file_path}")
        except Exception as e:
            logger.error(f"[LinuxCollector] Error collecting {file_path}: {e}")

    def _extract_username(self, path: str) -> Optional[str]:
        """
        Extract username from file path.

        Args:
            path: File path string

        Returns:
            Username if found in path, None otherwise
        """
        # Match /home/username/ pattern
        if '/home/' in path:
            parts = path.split('/home/')[1].split('/')
            if parts:
                return parts[0]

        # Root user
        if path.startswith('/root/') or path.startswith(str(self.target_root) + '/root/'):
            return 'root'

        return None

    def collect_all(
        self,
        artifact_types: Optional[List[str]] = None,
        priority_filter: Optional[str] = None
    ) -> Generator[Tuple[str, bytes, Dict[str, Any]], None, None]:
        """
        Collect all specified artifact types.

        Args:
            artifact_types: List of artifact types to collect (None = all)
            priority_filter: Only collect artifacts with this priority
                           ('critical', 'high', 'medium')

        Yields:
            Tuple of (relative_path, content_bytes, metadata)
        """
        types_to_collect = artifact_types or list(LINUX_ARTIFACT_TYPES.keys())

        for artifact_type in types_to_collect:
            if artifact_type not in LINUX_ARTIFACT_TYPES:
                logger.warning(f"[LinuxCollector] Unknown type: {artifact_type}")
                continue

            config = LINUX_ARTIFACT_TYPES[artifact_type]

            # Filter by priority if specified
            if priority_filter:
                if config.get('forensic_value') != priority_filter:
                    continue

            try:
                yield from self.collect(artifact_type)
            except Exception as e:
                logger.error(f"[LinuxCollector] Failed to collect {artifact_type}: {e}")

        # Release scan cache after all artifact types collected
        if hasattr(self, 'release_scan_cache'):
            self.release_scan_cache()

    def get_system_info(self) -> Dict[str, Any]:
        """
        Get Linux system information.

        Returns:
            Dictionary with system info
        """
        info = {
            'target_root': str(self.target_root),
            'is_local': str(self.target_root) == '/',
            'hostname': None,
            'distribution': None,
            'kernel_version': None,
        }

        # Local/mount mode
        # Read /etc/hostname
        hostname_file = self.target_root / 'etc' / 'hostname'
        if hostname_file.exists():
            try:
                info['hostname'] = hostname_file.read_text().strip()
            except OSError:
                pass

        # Read /etc/os-release for distribution info
        os_release = self.target_root / 'etc' / 'os-release'
        if os_release.exists():
            try:
                content = os_release.read_text()
                for line in content.splitlines():
                    if line.startswith('PRETTY_NAME='):
                        info['distribution'] = line.split('=', 1)[1].strip('"')
                        break
            except OSError:
                pass

        # Read /proc/version for kernel (local only)
        if str(self.target_root) == '/':
            version_file = Path('/proc/version')
            if version_file.exists():
                try:
                    info['kernel_version'] = version_file.read_text().strip()
                except OSError:
                    pass

        return info


# Convenience function
def check_linux_target(target_path: str) -> Dict[str, Any]:
    """
    Check if target path is a valid Linux root filesystem.

    Args:
        target_path: Path to check

    Returns:
        Dictionary with validity and details
    """
    path = Path(target_path)

    result = {
        'valid': False,
        'reason': '',
        'is_local': target_path == '/',
        'has_etc': False,
        'has_var': False,
        'has_home': False,
    }

    if not path.exists():
        result['reason'] = 'Path does not exist'
        return result

    # Check for key Linux directories
    result['has_etc'] = (path / 'etc').is_dir()
    result['has_var'] = (path / 'var').is_dir()
    result['has_home'] = (path / 'home').is_dir()

    if result['has_etc'] and result['has_var']:
        result['valid'] = True
    else:
        result['reason'] = 'Missing essential Linux directories (etc, var)'

    return result
