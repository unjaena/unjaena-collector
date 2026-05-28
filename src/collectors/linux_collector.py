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
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Generator, Dict, Any, Optional, List, Tuple
from dataclasses import dataclass

from collectors.live_command import iter_live_command_outputs

logger = logging.getLogger(__name__)


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
LINUX_ARTIFACT_TYPES: Dict[str, Dict[str, Any]] = {}

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

        logger.debug(f"[LinuxCollector] Initialized: target_root={target_root}")

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

    def _is_live_local_target(self) -> bool:
        return sys.platform.startswith('linux') and str(self.target_root) == '/'

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

        logger.debug(f"[LinuxCollector] Collecting {artifact_type} from {len(paths)} path patterns")

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

        if self._is_live_local_target():
            yield from iter_live_command_outputs(
                config.get('live_commands', []),
                artifact_type=artifact_type,
                platform_tag='linux',
            )

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
                'modified_time': datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc).isoformat(),
                'accessed_time': datetime.fromtimestamp(stat_info.st_atime, tz=timezone.utc).isoformat(),
                'created_time': datetime.fromtimestamp(stat_info.st_ctime, tz=timezone.utc).isoformat(),
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

            logger.debug(f"[LinuxCollector] Collected: {relative_path} ({stat_info.st_size} bytes)")

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
