"""
macOS Forensic Artifact Collector

macOS system forensic artifact collection module.
Collects artifacts from local systems, mounted APFS/HFS+ images, or E01 images.

Collection Methods:
1. Local collection: Current system artifacts (target_root='/')
2. Mount collection: Collect after mounting APFS/HFS+ image (target_root='/Volumes/macOS')
3. E01 direct collection: Direct filesystem collection from E01 using pyewf + pytsk3 (e01_path specified)
4. Time Machine backup collection

Core Artifacts:
- Unified Log (log show --predicate)
- Launch Agents/Daemons (persistence)
- TCC.db (permissions database)
- KnowledgeC.db (user activity)
- FSEvents (filesystem changes)

MITRE ATT&CK Mapping:
- T1070.002 (Clear Linux/Mac Logs): unified_log
- T1543.001 (Launch Agent): launch_agents
- T1059.004 (Unix Shell): zsh_history
- T1548.004 (Elevated Execution with Prompt): tcc.db
"""
import os
import glob
import hashlib
import plistlib
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


# Check for biplist (binary plist support)
try:
    import biplist
    BIPLIST_AVAILABLE = True
except ImportError:
    BIPLIST_AVAILABLE = False


@dataclass
class MacOSArtifactInfo:
    """macOS artifact metadata"""
    artifact_type: str
    file_path: str
    file_size: int
    modified_time: datetime
    content: bytes
    hash_md5: str
    hash_sha256: str
    extra_metadata: Dict[str, Any]


# macOS artifact type definitions
MACOS_ARTIFACT_TYPES = {
    # ==========================================================================
    # Unified Log (P0 - Critical for forensic timeline)
    # ==========================================================================
    'macos_unified_log': {
        'name': 'macOS Unified Log',
        'description': 'Unified logging system (log show command)',
        'paths': [
            '/var/db/diagnostics/Persist/*.tracev3',
            '/var/db/diagnostics/Special/*.tracev3',
            '/var/db/uuidtext/*',
            '/private/var/db/diagnostics/Persist/*.tracev3',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1070.002',
        'kill_chain_phase': 'defense_evasion',
        'requires_admin': True,
    },
    'macos_system_log': {
        'name': 'macOS System Log',
        'description': 'Traditional system logs',
        'paths': [
            '/var/log/system.log',
            '/var/log/system.log.*',
            '/private/var/log/system.log',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1070.002',
        'kill_chain_phase': 'defense_evasion',
    },
    'macos_install_log': {
        'name': 'macOS Install Log',
        'description': 'Software installation history',
        'paths': [
            '/var/log/install.log',
            '/var/log/install.log.*',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1072',
        'kill_chain_phase': 'execution',
    },

    # ==========================================================================
    # Launch Agents/Daemons (P0 - Persistence)
    # ==========================================================================
    'macos_launch_agent': {
        'name': 'Launch Agents (User)',
        'description': 'User-level LaunchAgent plist files',
        'paths': [
            '/Library/LaunchAgents/*.plist',
            '/Users/*/Library/LaunchAgents/*.plist',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1543.001',
        'kill_chain_phase': 'persistence',
        'plist_parsing': True,
    },
    'macos_launch_daemon': {
        'name': 'Launch Daemons (System)',
        'description': 'System-level LaunchDaemon plist files',
        'paths': [
            '/Library/LaunchDaemons/*.plist',
            '/System/Library/LaunchDaemons/*.plist',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1543.004',
        'kill_chain_phase': 'persistence',
        'plist_parsing': True,
        'requires_admin': True,
    },
    'macos_launch_agents_system': {
        'name': 'System Launch Agents',
        'description': 'System-level LaunchAgent plist files',
        'paths': [
            '/System/Library/LaunchAgents/*.plist',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1543.001',
        'kill_chain_phase': 'persistence',
        'plist_parsing': True,
    },

    # ==========================================================================
    # Shell History (P0 - Command Execution)
    # ==========================================================================
    'macos_zsh_history': {
        'name': 'Zsh Command History',
        'description': 'Zsh shell command history (default since Catalina)',
        'paths': [
            '/Users/*/.zsh_history',
            '/var/root/.zsh_history',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1059.004',
        'kill_chain_phase': 'execution',
    },
    'macos_bash_history': {
        'name': 'Bash Command History',
        'description': 'Bash shell command history',
        'paths': [
            '/Users/*/.bash_history',
            '/var/root/.bash_history',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1059.004',
        'kill_chain_phase': 'execution',
    },

    # ==========================================================================
    # Privacy & Permissions (P0 - TCC Database)
    # ==========================================================================
    'macos_tcc_db': {
        'name': 'TCC Database',
        'description': 'Transparency, Consent, and Control permissions database',
        'paths': [
            '/Library/Application Support/com.apple.TCC/TCC.db',
            '/Users/*/Library/Application Support/com.apple.TCC/TCC.db',
            '/private/var/db/tcc/TCC.db',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1548.004',
        'kill_chain_phase': 'privilege_escalation',
        'requires_admin': True,
    },

    # ==========================================================================
    # User Activity (P0 - KnowledgeC)
    # ==========================================================================
    'macos_knowledgec': {
        'name': 'KnowledgeC Database',
        'description': 'User activity, app usage, and screen time tracking',
        'paths': [
            '/Users/*/Library/Application Support/Knowledge/knowledgeC.db',
            '/private/var/db/CoreDuet/Knowledge/knowledgeC.db',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1087.001',
        'kill_chain_phase': 'discovery',
    },

    # ==========================================================================
    # Filesystem Events (P0 - File Monitoring)
    # ==========================================================================
    'macos_fseventsd': {
        'name': 'FSEvents Log',
        'description': 'File system events (file creation/deletion/modification)',
        'paths': [
            '/.fseventsd/*',
            '/System/Volumes/Data/.fseventsd/*',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1070.004',
        'kill_chain_phase': 'defense_evasion',
        'requires_admin': True,
    },

    # ==========================================================================
    # Spotlight (P1 - Search History)
    # ==========================================================================
    'macos_spotlight': {
        'name': 'Spotlight Index',
        'description': 'Spotlight search index and metadata',
        'paths': [
            '/.Spotlight-V100/*',
            '/Users/*/.Spotlight-V100/*',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1083',
        'kill_chain_phase': 'discovery',
    },

    # ==========================================================================
    # Browser Artifacts (P1)
    # ==========================================================================
    'macos_safari_history': {
        'name': 'Safari History',
        'description': 'Safari browser history database',
        'paths': [
            '/Users/*/Library/Safari/History.db',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1185',
        'kill_chain_phase': 'collection',
    },
    'macos_safari_downloads': {
        'name': 'Safari Downloads',
        'description': 'Safari download records',
        'paths': [
            '/Users/*/Library/Safari/Downloads.plist',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1185',
        'kill_chain_phase': 'collection',
        'plist_parsing': True,
    },
    'macos_chrome': {
        'name': 'Chrome History',
        'description': 'Google Chrome browser history',
        'paths': [
            '/Users/*/Library/Application Support/Google/Chrome/Default/History',
            '/Users/*/Library/Application Support/Google/Chrome/Profile */History',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1185',
        'kill_chain_phase': 'collection',
    },

    # ==========================================================================
    # Network (P1)
    # ==========================================================================
    'macos_wifi_known_networks': {
        'name': 'Known WiFi Networks',
        'description': 'Previously connected WiFi networks',
        'paths': [
            '/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist',
            '/Library/Preferences/com.apple.wifi.known-networks.plist',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1016',
        'kill_chain_phase': 'discovery',
        'plist_parsing': True,
    },
    'macos_hosts': {
        'name': 'Hosts File',
        'description': 'Static hostname mappings',
        'paths': [
            '/etc/hosts',
            '/private/etc/hosts',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1565.001',
        'kill_chain_phase': 'defense_evasion',
    },

    # ==========================================================================
    # Keychain (P1 - Credentials)
    # ==========================================================================
    'macos_keychain': {
        'name': 'Keychain Database',
        'description': 'User and system keychain files',
        'paths': [
            '/Users/*/Library/Keychains/login.keychain-db',
            '/Library/Keychains/System.keychain',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1555.001',
        'kill_chain_phase': 'credential_access',
        'requires_admin': True,
    },

    # ==========================================================================
    # SSH (P1)
    # ==========================================================================
    'macos_ssh': {
        'name': 'SSH Authorized Keys',
        'description': 'Authorized public keys for SSH access',
        'paths': [
            '/Users/*/.ssh/authorized_keys',
            '/var/root/.ssh/authorized_keys',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1098.004',
        'kill_chain_phase': 'persistence',
    },
    'macos_ssh': {
        'name': 'SSH Known Hosts',
        'description': 'Previously connected SSH servers',
        'paths': [
            '/Users/*/.ssh/known_hosts',
            '/var/root/.ssh/known_hosts',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1021.004',
        'kill_chain_phase': 'lateral_movement',
    },

    # ==========================================================================
    # Application Artifacts (P2)
    # ==========================================================================
    'macos_recent_items': {
        'name': 'Recent Items',
        'description': 'Recently accessed files and applications',
        'paths': [
            '/Users/*/Library/Application Support/com.apple.sharedfilelist/*.sfl2',
            '/Users/*/Library/Application Support/com.apple.sharedfilelist/*.sfl',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1083',
        'kill_chain_phase': 'discovery',
    },
    'macos_quarantine_events': {
        'name': 'Quarantine Events',
        'description': 'Downloaded files quarantine database',
        'paths': [
            '/Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1204.002',
        'kill_chain_phase': 'execution',
    },
    'macos_login_items': {
        'name': 'Login Items',
        'description': 'Applications launched at login',
        'paths': [
            '/Users/*/Library/Preferences/com.apple.loginitems.plist',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1547.015',
        'kill_chain_phase': 'persistence',
        'plist_parsing': True,
    },

    # ==========================================================================
    # System Configuration (P2)
    # ==========================================================================
    'macos_system_version': {
        'name': 'System Version',
        'description': 'macOS version information',
        'paths': [
            '/System/Library/CoreServices/SystemVersion.plist',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1082',
        'kill_chain_phase': 'discovery',
        'plist_parsing': True,
    },
    'macos_audit_logs': {
        'name': 'Security Audit Logs',
        'description': 'OpenBSM audit logs',
        'paths': [
            '/var/audit/*',
            '/private/var/audit/*',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1070.002',
        'kill_chain_phase': 'defense_evasion',
        'requires_admin': True,
    },

    # ==========================================================================
    # Cron & Scheduled Tasks (P2)
    # ==========================================================================
    'macos_cron': {
        'name': 'Crontab Entries',
        'description': 'Scheduled tasks via cron',
        'paths': [
            '/usr/lib/cron/tabs/*',
            '/var/at/tabs/*',
            '/private/var/at/tabs/*',
        ],
        'forensic_value': 'critical',
        'mitre_attack': 'T1053.003',
        'kill_chain_phase': 'persistence',
    },
    'macos_at_jobs': {
        'name': 'At Jobs',
        'description': 'Scheduled tasks via at command',
        'paths': [
            '/var/at/jobs/*',
            '/private/var/at/jobs/*',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1053.002',
        'kill_chain_phase': 'persistence',
    },

    # ==========================================================================
    # Application Support Databases (P2)
    # ==========================================================================
    'macos_finder_plist': {
        'name': 'Dock Configuration',
        'description': 'Dock items and recent applications',
        'paths': [
            '/Users/*/Library/Preferences/com.apple.dock.plist',
        ],
        'forensic_value': 'medium',
        'mitre_attack': 'T1087.001',
        'kill_chain_phase': 'discovery',
        'plist_parsing': True,
    },
    'macos_terminal': {
        'name': 'Terminal Saved State',
        'description': 'Terminal.app saved window state and history',
        'paths': [
            '/Users/*/Library/Saved Application State/com.apple.Terminal.savedState/*',
        ],
        'forensic_value': 'high',
        'mitre_attack': 'T1059.004',
        'kill_chain_phase': 'execution',
    },
}


class macOSCollector:
    """
    macOS Forensic Artifact Collector

    Collects forensic artifacts from local, mounted filesystems, or E01 images.

    Collection Modes:
    1. Local/Mount mode: Direct collection from target_root path (default)
    2. E01 direct collection mode: Direct filesystem collection from image using pyewf + pytsk3
    """

    def __init__(
        self,
        output_dir: str,
        target_root: str = '/',
        e01_path: Optional[str] = None,
        partition_offset: Optional[int] = None
    ):
        """
        Initialize macOS collector.

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

        _debug_print(f"[macOSCollector] Initialized: e01_mode={self._e01_mode}, target_root={target_root}")

    def _init_e01_mode(self, e01_path: str):
        """
        Initialize E01 image direct collection mode

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

                # Find macOS partition (HFS+/APFS)
                macos_partition = None
                for part in partitions:
                    fs_type = part.get('filesystem', '')
                    if detect_os_from_filesystem(fs_type) == 'macos':
                        macos_partition = part
                        break

                if macos_partition:
                    self._partition_offset = macos_partition['offset']
                    logger.info(
                        f"[macOSCollector] Auto-detected macOS partition: "
                        f"{macos_partition['filesystem']} at offset {self._partition_offset}"
                    )
                else:
                    # Try offset 0 if macOS partition not found
                    self._partition_offset = 0
                    logger.warning(
                        "[macOSCollector] No macOS partition found, trying offset 0"
                    )

            # Open pytsk3 filesystem
            self._fs_info = pytsk3.FS_Info(self._img_info, offset=self._partition_offset)
            self._e01_mode = True

            logger.info(f"[macOSCollector] E01 mode initialized: {e01_path}")

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
        return MACOS_ARTIFACT_TYPES

    def collect(
        self,
        artifact_type: str,
        **kwargs
    ) -> Generator[Tuple[str, bytes, Dict[str, Any]], None, None]:
        """
        Collect specified artifact type.

        Args:
            artifact_type: Type of artifact to collect (e.g., 'macos_launch_agent')

        Yields:
            Tuple of (relative_path, content_bytes, metadata)
        """
        if artifact_type not in MACOS_ARTIFACT_TYPES:
            raise ValueError(f"Unknown artifact type: {artifact_type}")

        config = MACOS_ARTIFACT_TYPES[artifact_type]
        paths = config.get('paths', [])

        _debug_print(f"[macOSCollector] Collecting {artifact_type} from {len(paths)} path patterns")

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
                        logger.warning(f"[macOSCollector] Failed to collect {file_path}: {e}")

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

            # If pattern contains wildcards
            if '*' in pattern:
                # Separate fixed path and wildcard parts
                parts = pattern.split('/')
                fixed_parts = []
                for part in parts:
                    if '*' in part:
                        break
                    fixed_parts.append(part)

                fixed_path = '/'.join(fixed_parts) if fixed_parts else ''
                wildcard_pattern = '/'.join(parts[len(fixed_parts):])

                # Recursively search files from fixed path
                try:
                    yield from self._collect_e01_glob(
                        fixed_path, wildcard_pattern, artifact_type, config
                    )
                except Exception as e:
                    logger.debug(f"[macOSCollector] E01 glob failed for {pattern}: {e}")
            else:
                # Fixed path
                try:
                    yield from self._collect_e01_file(pattern, artifact_type, config)
                except Exception as e:
                    logger.debug(f"[macOSCollector] E01 file not found: {pattern}")

    def _collect_e01_glob(
        self,
        base_path: str,
        pattern: str,
        artifact_type: str,
        config: Dict[str, Any]
    ) -> Generator[Tuple[str, bytes, Dict[str, Any]], None, None]:
        """
        Collect files using glob pattern within E01

        Args:
            base_path: Starting path for search
            pattern: Wildcard pattern
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
            logger.debug(f"[macOSCollector] Cannot open directory /{base_path}: {e}")
            return

        # Recursively traverse directory
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
        Recursively traverse E01 directory

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

                # Recursively traverse if directory
                if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    try:
                        sub_dir = self._fs_info.open_dir(path='/' + full_path)
                        yield from self._walk_e01_directory(
                            sub_dir, full_path, pattern, artifact_type, config, depth + 1, max_depth
                        )
                    except Exception:
                        pass
                # Match pattern if file
                elif entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                    # Pattern matching with fnmatch
                    if fnmatch.fnmatch(full_path, pattern) or fnmatch.fnmatch(name, pattern.split('/')[-1]):
                        try:
                            yield from self._collect_e01_file(full_path, artifact_type, config)
                        except Exception as e:
                            logger.debug(f"[macOSCollector] Failed to collect {full_path}: {e}")

            except Exception as e:
                continue

    def _collect_e01_file(
        self,
        file_path: str,
        artifact_type: str,
        config: Dict[str, Any]
    ) -> Generator[Tuple[str, bytes, Dict[str, Any]], None, None]:
        """
        Collect a single file from E01

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
                logger.warning(f"[macOSCollector] File too large, skipping: {file_path} ({file_size} bytes)")
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

            _debug_print(f"[macOSCollector] E01 collected: {file_path} ({file_size} bytes)")

        except Exception as e:
            logger.debug(f"[macOSCollector] E01 file read error {file_path}: {e}")

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
                    f"[macOSCollector] File too large ({stat_info.st_size / (1024**2):.0f}MB > 100MB), "
                    f"truncating: {path}"
                )
            with open(path, 'rb') as f:
                content = f.read(MAX_FILE_SIZE)

            # Calculate hashes
            hash_sha256 = hashlib.sha256(content).hexdigest()

            # Extract username from path if applicable
            username = self._extract_username(str(path))

            # Build metadata
            metadata = {
                'artifact_type': artifact_type,
                'original_path': str(path),
                'file_size': stat_info.st_size,
                'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed_time': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                'created_time': datetime.fromtimestamp(
                    getattr(stat_info, 'st_birthtime', stat_info.st_ctime)
                ).isoformat(),
                'hash_sha256': hash_sha256,
                'forensic_value': config.get('forensic_value', 'medium'),
                'mitre_attack': config.get('mitre_attack', ''),
                'kill_chain_phase': config.get('kill_chain_phase', ''),
            }

            if username:
                metadata['username'] = username

            # [2026-01-31] plist parsing is performed on server (removed from collector for security)
            # Collector only collects raw files, parsing is done on server

            # Relative path from target root
            try:
                relative_path = str(path.relative_to(self.target_root))
            except ValueError:
                relative_path = str(path)

            yield (relative_path, content, metadata)

            _debug_print(f"[macOSCollector] Collected: {relative_path} ({stat_info.st_size} bytes)")

        except PermissionError:
            logger.warning(f"[macOSCollector] Permission denied: {file_path}")
        except Exception as e:
            logger.error(f"[macOSCollector] Error collecting {file_path}: {e}")

    def _parse_plist(self, path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse a plist file (binary or XML).

        Args:
            path: Path to plist file

        Returns:
            Parsed plist as dictionary, or None on failure
        """
        try:
            with open(path, 'rb') as f:
                return plistlib.load(f)
        except Exception:
            # Try biplist for binary plists
            if BIPLIST_AVAILABLE:
                try:
                    return biplist.readPlist(str(path))
                except Exception:
                    pass
        return None

    # [2026-01-31] _extract_launch_metadata removed
    # Forensic analysis logic is performed on server (macos_basic_parser.py)

    def _extract_username(self, path: str) -> Optional[str]:
        """
        Extract username from file path.

        Args:
            path: File path string

        Returns:
            Username if found in path, None otherwise
        """
        # Match /Users/username/ pattern
        if '/Users/' in path:
            parts = path.split('/Users/')[1].split('/')
            if parts and parts[0] != 'Shared':
                return parts[0]

        # Root user
        if '/var/root/' in path or '/private/var/root/' in path:
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
        types_to_collect = artifact_types or list(MACOS_ARTIFACT_TYPES.keys())

        for artifact_type in types_to_collect:
            if artifact_type not in MACOS_ARTIFACT_TYPES:
                logger.warning(f"[macOSCollector] Unknown type: {artifact_type}")
                continue

            config = MACOS_ARTIFACT_TYPES[artifact_type]

            # Filter by priority if specified
            if priority_filter:
                if config.get('forensic_value') != priority_filter:
                    continue

            try:
                yield from self.collect(artifact_type)
            except Exception as e:
                logger.error(f"[macOSCollector] Failed to collect {artifact_type}: {e}")

    def get_system_info(self) -> Dict[str, Any]:
        """
        Get macOS system information.

        Returns:
            Dictionary with system info
        """
        info = {
            'target_root': str(self.target_root) if self.target_root else 'E01 Image',
            'is_local': str(self.target_root) == '/' if self.target_root else False,
            'is_e01_mode': self._e01_mode,
            'hostname': None,
            'macos_version': None,
            'build_version': None,
        }

        if self._e01_mode:
            # Read system info in E01 mode
            info.update(self._get_system_info_e01())
        else:
            # Local/mount mode
            # Read SystemVersion.plist
            version_plist = self.target_root / 'System' / 'Library' / 'CoreServices' / 'SystemVersion.plist'
            if version_plist.exists():
                plist_data = self._parse_plist(version_plist)
                if plist_data:
                    info['macos_version'] = plist_data.get('ProductVersion')
                    info['build_version'] = plist_data.get('ProductBuildVersion')

            # Read hostname
            hostname_files = [
                self.target_root / 'etc' / 'hostname',
                self.target_root / 'private' / 'etc' / 'hostname',
            ]
            for hf in hostname_files:
                if hf.exists():
                    try:
                        info['hostname'] = hf.read_text().strip()
                        break
                    except OSError:
                        pass

        return info

    def _get_system_info_e01(self) -> Dict[str, Any]:
        """Read system information from E01 image"""
        info = {}

        try:
            # Read SystemVersion.plist
            try:
                version_file = self._fs_info.open('/System/Library/CoreServices/SystemVersion.plist')
                content = version_file.read_random(0, version_file.info.meta.size)
                plist_data = plistlib.loads(content)
                info['macos_version'] = plist_data.get('ProductVersion')
                info['build_version'] = plist_data.get('ProductBuildVersion')
            except Exception:
                pass

            # Read hostname
            for hostname_path in ['/etc/hostname', '/private/etc/hostname']:
                try:
                    hostname_file = self._fs_info.open(hostname_path)
                    content = hostname_file.read_random(0, hostname_file.info.meta.size)
                    info['hostname'] = content.decode('utf-8', errors='replace').strip()
                    break
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"[macOSCollector] Failed to get E01 system info: {e}")

        return info


# Convenience function
def check_macos_target(target_path: str) -> Dict[str, Any]:
    """
    Check if target path is a valid macOS root filesystem.

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
        'has_system': False,
        'has_library': False,
        'has_users': False,
        'macos_version': None,
    }

    if not path.exists():
        result['reason'] = 'Path does not exist'
        return result

    # Check for key macOS directories
    result['has_system'] = (path / 'System').is_dir()
    result['has_library'] = (path / 'Library').is_dir()
    result['has_users'] = (path / 'Users').is_dir()

    # Check for SystemVersion.plist
    version_plist = path / 'System' / 'Library' / 'CoreServices' / 'SystemVersion.plist'
    if version_plist.exists():
        try:
            with open(version_plist, 'rb') as f:
                data = plistlib.load(f)
                result['macos_version'] = data.get('ProductVersion')
        except Exception:
            pass

    if result['has_system'] and result['has_library']:
        result['valid'] = True
    else:
        result['reason'] = 'Missing essential macOS directories (System, Library)'

    return result
