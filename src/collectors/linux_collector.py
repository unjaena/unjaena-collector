"""
Linux Forensic Artifact Collector

Linux system forensic artifact collection module.
Collects artifacts from local system, mounted ext2/3/4 filesystems, or E01 images.

Collection Methods:
1. Local collection: Direct artifact collection from current system (target_root='/')
2. Mount collection: Collection after mounting ext2/3/4 image (target_root='/mnt/linux')
3. E01 direct collection: Direct filesystem collection within E01 using pyewf + pytsk3 (e01_path specified)
4. Remote collection: Collection via SSH connection (future)

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
import fnmatch
from pathlib import Path
from datetime import datetime
from typing import Generator, Dict, Any, Optional, List, Tuple, Union
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Check pytsk3 availability (for E01 direct collection)
try:
    import pytsk3
    PYTSK3_AVAILABLE = True
except ImportError:
    PYTSK3_AVAILABLE = False
    logger.debug("pytsk3 not available - E01 direct collection disabled")

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
    'linux_init_scripts': {
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
}


class LinuxCollector:
    """
    Linux Forensic Artifact Collector

    Collects forensic artifacts from local, mounted filesystems, or E01 images.

    Collection Modes:
    1. Local/Mount mode: Direct collection from target_root path (default)
    2. E01 direct collection mode: Direct filesystem collection within image using pyewf + pytsk3
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
            e01_path: E01 image path (enables E01 direct collection mode when specified)
            partition_offset: Partition offset within E01 (auto-detected if None)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # E01 direct collection mode
        self._e01_mode = False
        self._img_info = None
        self._fs_info = None
        self._partition_offset = partition_offset

        if e01_path:
            self._init_e01_mode(e01_path)
            self.target_root = None  # Not used in E01 mode
        else:
            # Local/mount collection mode
            self.target_root = Path(target_root)
            if not self.target_root.exists():
                raise FileNotFoundError(f"Target root not found: {target_root}")

        _debug_print(f"[LinuxCollector] Initialized: e01_mode={self._e01_mode}, target_root={target_root}")

    def _init_e01_mode(self, e01_path: str):
        """
        Initialize direct collection mode from E01 image

        Args:
            e01_path: E01 image file path
        """
        if not PYTSK3_AVAILABLE:
            raise ImportError(
                "pytsk3 is required for E01 direct collection. "
                "Install with: pip install pytsk3"
            )

        try:
            from .forensic_disk.ewf_img_info import (
                open_e01_as_pytsk3,
                detect_partitions_pytsk3,
                detect_os_from_filesystem
            )

            # Open E01 image
            self._img_info = open_e01_as_pytsk3(e01_path)

            # Auto-detect partition
            if self._partition_offset is None:
                partitions = detect_partitions_pytsk3(self._img_info)

                # Find Linux partition (ext2/3/4)
                linux_partition = None
                for part in partitions:
                    fs_type = part.get('filesystem', '')
                    if detect_os_from_filesystem(fs_type) == 'linux':
                        linux_partition = part
                        break

                if linux_partition:
                    self._partition_offset = linux_partition['offset']
                    logger.info(
                        f"[LinuxCollector] Auto-detected Linux partition: "
                        f"{linux_partition['filesystem']} at offset {self._partition_offset}"
                    )
                else:
                    # If no Linux partition found, try offset 0
                    self._partition_offset = 0
                    logger.warning(
                        "[LinuxCollector] No Linux partition found, trying offset 0"
                    )

            # Open pytsk3 filesystem
            self._fs_info = pytsk3.FS_Info(self._img_info, offset=self._partition_offset)
            self._e01_mode = True

            logger.info(f"[LinuxCollector] E01 mode initialized: {e01_path}")

        except Exception as e:
            if self._img_info:
                self._img_info.close()
            raise RuntimeError(f"Failed to initialize E01 mode: {e}")

    def close(self):
        """Release resources"""
        if self._img_info:
            try:
                self._img_info.close()
            except Exception:
                pass
            self._img_info = None
            self._fs_info = None

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

        if self._e01_mode:
            # E01 direct collection mode
            yield from self._collect_from_e01(artifact_type, config, paths)
        else:
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

    def _collect_from_e01(
        self,
        artifact_type: str,
        config: Dict[str, Any],
        patterns: List[str]
    ) -> Generator[Tuple[str, bytes, Dict[str, Any]], None, None]:
        """
        Collect artifacts from E01 image (using pytsk3)

        Args:
            artifact_type: Artifact type
            config: Artifact configuration
            patterns: List of path patterns to collect

        Yields:
            Tuple of (relative_path, content_bytes, metadata)
        """
        for pattern in patterns:
            # Analyze pattern
            pattern = pattern.lstrip('/')

            # If wildcard is included
            if '*' in pattern:
                # Separate fixed path part and wildcard part
                parts = pattern.split('/')
                fixed_parts = []
                for part in parts:
                    if '*' in part:
                        break
                    fixed_parts.append(part)

                fixed_path = '/'.join(fixed_parts) if fixed_parts else ''
                wildcard_pattern = '/'.join(parts[len(fixed_parts):])

                # Recursively search for files from fixed path
                try:
                    yield from self._collect_e01_glob(
                        fixed_path, wildcard_pattern, artifact_type, config
                    )
                except Exception as e:
                    logger.debug(f"[LinuxCollector] E01 glob failed for {pattern}: {e}")
            else:
                # Fixed path
                try:
                    yield from self._collect_e01_file(pattern, artifact_type, config)
                except Exception as e:
                    logger.debug(f"[LinuxCollector] E01 file not found: {pattern}")

    def _collect_e01_glob(
        self,
        base_path: str,
        pattern: str,
        artifact_type: str,
        config: Dict[str, Any]
    ) -> Generator[Tuple[str, bytes, Dict[str, Any]], None, None]:
        """
        Collect files by glob pattern within E01

        Args:
            base_path: Starting path for search
            pattern: Wildcard pattern (e.g., '*/.bash_history')
            artifact_type: Artifact type
            config: Configuration

        Yields:
            Collected file tuples
        """
        # Open base_path directory
        try:
            if base_path:
                directory = self._fs_info.open_dir(path='/' + base_path)
            else:
                directory = self._fs_info.open_dir(path='/')
        except Exception as e:
            logger.debug(f"[LinuxCollector] Cannot open directory /{base_path}: {e}")
            return

        # Recursive directory traversal
        yield from self._walk_e01_directory(directory, base_path, pattern, artifact_type, config)

    def _walk_e01_directory(
        self,
        directory,
        current_path: str,
        pattern: str,
        artifact_type: str,
        config: Dict[str, Any],
        depth: int = 0,
        max_depth: int = 10
    ) -> Generator[Tuple[str, bytes, Dict[str, Any]], None, None]:
        """
        Recursive E01 directory traversal

        Args:
            directory: pytsk3 directory object
            current_path: Current path
            pattern: Pattern to match
            artifact_type: Artifact type
            config: Configuration
            depth: Current depth
            max_depth: Maximum traversal depth

        Yields:
            Collected file tuples
        """
        if depth > max_depth:
            return

        for entry in directory:
            try:
                name = entry.info.name.name.decode('utf-8', errors='replace')

                # Skip . and ..
                if name in ('.', '..'):
                    continue

                # Full path of current entry
                if current_path:
                    full_path = f"{current_path}/{name}"
                else:
                    full_path = name

                # If directory, traverse recursively
                if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    try:
                        sub_dir = self._fs_info.open_dir(path='/' + full_path)
                        yield from self._walk_e01_directory(
                            sub_dir, full_path, pattern, artifact_type, config, depth + 1, max_depth
                        )
                    except Exception:
                        pass
                # If file, perform pattern matching
                elif entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                    # Pattern matching with fnmatch
                    if fnmatch.fnmatch(full_path, pattern) or fnmatch.fnmatch(name, pattern.split('/')[-1]):
                        try:
                            yield from self._collect_e01_file(full_path, artifact_type, config)
                        except Exception as e:
                            logger.debug(f"[LinuxCollector] Failed to collect {full_path}: {e}")

            except Exception as e:
                continue

    def _collect_e01_file(
        self,
        file_path: str,
        artifact_type: str,
        config: Dict[str, Any]
    ) -> Generator[Tuple[str, bytes, Dict[str, Any]], None, None]:
        """
        Collect single file from E01

        Args:
            file_path: File path (relative to root)
            artifact_type: Artifact type
            config: Configuration

        Yields:
            (relative_path, content, metadata) tuple
        """
        try:
            # Open file
            file_path_normalized = '/' + file_path.lstrip('/')
            file_entry = self._fs_info.open(file_path_normalized)

            # Check metadata
            meta = file_entry.info.meta
            if not meta:
                return

            # Check file size (skip files too large - 100MB)
            file_size = meta.size
            if file_size > 100 * 1024 * 1024:
                logger.warning(f"[LinuxCollector] File too large, skipping: {file_path} ({file_size} bytes)")
                return

            # Read file content
            content = file_entry.read_random(0, file_size)

            # Calculate hashes
            hash_md5 = hashlib.md5(content).hexdigest()
            hash_sha256 = hashlib.sha256(content).hexdigest()

            # Convert timestamps
            modified_time = datetime.fromtimestamp(meta.mtime).isoformat() if meta.mtime else None
            accessed_time = datetime.fromtimestamp(meta.atime).isoformat() if meta.atime else None
            created_time = datetime.fromtimestamp(meta.crtime).isoformat() if meta.crtime else None

            # Build metadata
            metadata = {
                'artifact_type': artifact_type,
                'original_path': file_path_normalized,
                'file_size': file_size,
                'modified_time': modified_time,
                'accessed_time': accessed_time,
                'created_time': created_time,
                'permissions': oct(meta.mode)[-3:] if meta.mode else '000',
                'owner': str(meta.uid) if meta.uid is not None else 'unknown',
                'hash_md5': hash_md5,
                'hash_sha256': hash_sha256,
                'forensic_value': config.get('forensic_value', 'medium'),
                'mitre_attack': config.get('mitre_attack', ''),
                'kill_chain_phase': config.get('kill_chain_phase', ''),
                'collection_mode': 'e01_direct',
            }

            # Extract username
            username = self._extract_username(file_path_normalized)
            if username:
                metadata['username'] = username

            yield (file_path.lstrip('/'), content, metadata)

            _debug_print(f"[LinuxCollector] E01 collected: {file_path} ({file_size} bytes)")

        except Exception as e:
            logger.debug(f"[LinuxCollector] E01 file read error {file_path}: {e}")

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

    def get_system_info(self) -> Dict[str, Any]:
        """
        Get Linux system information.

        Returns:
            Dictionary with system info
        """
        info = {
            'target_root': str(self.target_root) if self.target_root else 'E01 Image',
            'is_local': str(self.target_root) == '/' if self.target_root else False,
            'is_e01_mode': self._e01_mode,
            'hostname': None,
            'distribution': None,
            'kernel_version': None,
        }

        if self._e01_mode:
            # Read system info in E01 mode
            info.update(self._get_system_info_e01())
        else:
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

    def _get_system_info_e01(self) -> Dict[str, Any]:
        """Read system information from E01 image"""
        info = {}

        try:
            # Read /etc/hostname
            try:
                hostname_file = self._fs_info.open('/etc/hostname')
                content = hostname_file.read_random(0, hostname_file.info.meta.size)
                info['hostname'] = content.decode('utf-8', errors='replace').strip()
            except Exception:
                pass

            # Read /etc/os-release
            try:
                os_release = self._fs_info.open('/etc/os-release')
                content = os_release.read_random(0, os_release.info.meta.size)
                for line in content.decode('utf-8', errors='replace').splitlines():
                    if line.startswith('PRETTY_NAME='):
                        info['distribution'] = line.split('=', 1)[1].strip('"')
                        break
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"[LinuxCollector] Failed to get E01 system info: {e}")

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
