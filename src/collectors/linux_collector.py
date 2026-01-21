"""
Linux Forensic Artifact Collector

Linux 시스템 포렌식 아티팩트 수집 모듈.
로컬 시스템 또는 마운트된 ext2/3/4 파일시스템에서 아티팩트를 수집합니다.

수집 방식:
1. 로컬 수집: 현재 시스템의 아티팩트 직접 수집
2. 마운트 수집: ext2/3/4 이미지 마운트 후 수집
3. 원격 수집: SSH 연결 통한 원격 시스템 수집 (향후)

핵심 아티팩트:
- auth.log, syslog, kern.log (인증/시스템 로그)
- bash_history, zsh_history (명령어 기록)
- crontab, systemd services (예약작업/서비스)
- /etc/passwd, shadow, sudoers (계정 정보)
- ssh authorized_keys, known_hosts (SSH 설정)

MITRE ATT&CK 매핑:
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
    'linux_systemd_timer': {
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
    'linux_resolv_conf': {
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
    'linux_apache_error': {
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
    'linux_nginx_error': {
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
    'linux_profile': {
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
    'linux_init_d': {
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
    'linux_apt_history': {
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
    'linux_yum_history': {
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
    'linux_docker_config': {
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
}


class LinuxCollector:
    """
    Linux Forensic Artifact Collector

    로컬 또는 마운트된 Linux 파일시스템에서 포렌식 아티팩트를 수집합니다.
    """

    def __init__(self, output_dir: str, target_root: str = '/'):
        """
        Initialize Linux collector.

        Args:
            output_dir: Directory to store collected artifacts
            target_root: Root path for collection (default: '/' for local)
                        Use mount point for image analysis
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.target_root = Path(target_root)
        if not self.target_root.exists():
            raise FileNotFoundError(f"Target root not found: {target_root}")

        _debug_print(f"[LinuxCollector] Initialized with target_root: {target_root}")

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

            # Read file content
            with open(path, 'rb') as f:
                content = f.read()

            # Calculate hashes
            hash_md5 = hashlib.md5(content).hexdigest()
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
                'hash_md5': hash_md5,
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

        # Read /etc/hostname
        hostname_file = self.target_root / 'etc' / 'hostname'
        if hostname_file.exists():
            try:
                info['hostname'] = hostname_file.read_text().strip()
            except:
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
            except:
                pass

        # Read /proc/version for kernel (local only)
        if str(self.target_root) == '/':
            version_file = Path('/proc/version')
            if version_file.exists():
                try:
                    info['kernel_version'] = version_file.read_text().strip()
                except:
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
