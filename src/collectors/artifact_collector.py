"""
Artifact Collector Module

Digital forensics artifact collection module.
MFT (Master File Table) based collection is used by default,
falling back to legacy methods when MFT is unavailable.

Collection methods:
- BaseMFTCollector: Unified MFT-based collection (shared for E01/Local)
- ForensicDiskAccessor: Pure Python raw disk access (recommended)
- Legacy: glob.glob + shutil.copy2 (fallback)

Note: MFT-based collection requires administrator privileges
"""
import os
import ntpath
import re
import sys
import glob
import shutil
import hashlib
import logging
import fnmatch
from pathlib import Path
from datetime import datetime, timezone
from typing import Generator, Tuple, Dict, Any, Optional, List

# macOS artifact filters for auto-registration in ARTIFACT_TYPES
try:
    from collectors.macos_artifacts import MACOS_ARTIFACT_FILTERS as _MACOS_FILTERS
except ImportError:
    _MACOS_FILTERS = {}

try:
    from collectors.mobile_ffs.path_specs import (
        ANDROID_PATH_SPECS as _ANDROID_FFS_SPECS,
        IOS_PATH_SPECS as _IOS_FFS_SPECS,
    )
except ImportError:
    _ANDROID_FFS_SPECS = ()
    _IOS_FFS_SPECS = ()

logger = logging.getLogger(__name__)

# Try to import BaseMFTCollector (unified base class)
try:
    from collectors.base_mft_collector import (
        BaseMFTCollector,
        ARTIFACT_MFT_FILTERS,
        DOCUMENT_EXTENSIONS,
        EMAIL_EXTENSIONS,
        IMAGE_EXTENSIONS,
        VIDEO_EXTENSIONS,
        SOURCE_CODE_EXTENSIONS,
        USER_FILE_EXTENSION_POLICY,
    )
    BASE_MFT_AVAILABLE = True
except ImportError:
    BASE_MFT_AVAILABLE = False
    BaseMFTCollector = None
    ARTIFACT_MFT_FILTERS = {}
    DOCUMENT_EXTENSIONS = frozenset({
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.pdf', '.hwp', '.hwpx', '.txt', '.csv', '.rtf',
    })
    EMAIL_EXTENSIONS = frozenset({'.eml', '.msg', '.pst', '.ost'})
    IMAGE_EXTENSIONS = frozenset({
        '.jpg', '.jpeg', '.png', '.gif', '.bmp',
        '.tiff', '.tif', '.heic', '.heif', '.webp',
        '.raw',
    })
    VIDEO_EXTENSIONS = frozenset({
        '.mp4', '.avi', '.mov', '.mkv', '.wmv', '.flv',
        '.webm', '.m4v', '.mpg', '.mpeg', '.3gp',
    })
    SOURCE_CODE_EXTENSIONS = frozenset({
        '.py', '.pyw', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
        '.java', '.kt', '.kts', '.go', '.rs', '.cs', '.cpp', '.cc',
        '.c', '.h', '.hpp', '.php', '.rb', '.swift', '.scala',
        '.ps1', '.psm1', '.bat', '.cmd', '.sh', '.bash', '.zsh',
        '.sql', '.r', '.lua', '.pl', '.json', '.toml', '.yaml', '.yml',
            '.xml', '.gradle', '.lock', '.ini', '.cfg', '.conf', '.properties',
    })
    USER_FILE_EXTENSION_POLICY = {
        'document': DOCUMENT_EXTENSIONS,
        'email': EMAIL_EXTENSIONS,
        'image': IMAGE_EXTENSIONS,
        'video': VIDEO_EXTENSIONS,
        'source_code': SOURCE_CODE_EXTENSIONS,
    }


def _glob_paths_for_extensions(base_dirs: List[str], extensions) -> List[str]:
    return [
        f"{base_dir}\\**\\*{ext}"
        for base_dir in base_dirs
        for ext in sorted(extensions)
    ]


AI_BROWSER_EXTENSION_IDS = ()
AI_BROWSER_STORAGE_ORIGINS = ()

def _chromium_ai_extension_manifest_paths(profile_roots: List[str]) -> List[str]:
    return []

def _chromium_ai_storage_paths(profile_roots: List[str]) -> List[str]:
    return []

LEVELDB_STORE_FILE_PATTERNS = ('*.ldb', '*.log', '*.sst', 'CURRENT', 'LOG', 'LOG.old', 'MANIFEST-*')

def _leveldb_file_paths(leveldb_roots: List[str]) -> List[str]:
    return []

def _messenger_process_names(config: Dict[str, Any]) -> List[str]:
    names: List[str] = []
    primary = config.get('process_name')
    if primary:
        if isinstance(primary, (list, tuple, set)):
            names.extend(str(item) for item in primary if item)
        else:
            names.append(str(primary))
    aliases = config.get('process_names') or []
    if isinstance(aliases, str):
        aliases = [aliases]
    names.extend(str(item) for item in aliases if item)

    deduped: List[str] = []
    seen = set()
    for name in names:
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(name)
    return deduped

def _build_collected_file_metadata(
    src_path: str,
    dst_path: Path,
    artifact_type: str,
) -> Dict[str, Any]:
    src = Path(src_path)
    dst = Path(dst_path)
    max_hash_size = 100 * 1024 * 1024
    file_size = dst.stat().st_size
    hash_skipped = False

    if file_size <= max_hash_size:
        sha256 = hashlib.sha256()
        md5 = hashlib.md5(usedforsecurity=False)
        with open(dst, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
                md5.update(chunk)
        sha256_hex = sha256.hexdigest()
        md5_hex = md5.hexdigest()
    else:
        sha256_hex = ''
        md5_hex = ''
        hash_skipped = True

    try:
        stat = src.stat()
        timestamps = {
            'created': datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            'accessed': datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat(),
        }
    except (OSError, ValueError):
        timestamps = {}

    metadata = {
        'artifact_type': artifact_type,
        'original_path': str(src_path),
        'filename': src.name,
        'size': file_size,
        'sha256': sha256_hex,
        'md5': md5_hex,
        'timestamps': timestamps,
        'collected_at': datetime.utcnow().isoformat(),
        'collection_method': 'legacy_file_api',
    }
    if hash_skipped:
        metadata['hash_skipped'] = True
    return metadata

# Try to import ForensicDiskAccessor (pure Python - preferred)
try:
    from collectors.forensic_disk import (
        ForensicDiskAccessor,
        FORENSIC_DISK_AVAILABLE
    )
except ImportError:
    FORENSIC_DISK_AVAILABLE = False
    ForensicDiskAccessor = None

# Try to import MFT collector (ForensicDiskAccessor-based fallback)
try:
    from collectors.mft_collector import (
        MFTCollector, MFT_ARTIFACT_TYPES,
        is_mft_available, check_admin_privileges
    )
    MFT_AVAILABLE = is_mft_available()
except ImportError:
    MFT_AVAILABLE = False
    MFTCollector = None

# Try to import Android collector
try:
    from collectors.android_collector import (
        AndroidCollector, ANDROID_ARTIFACT_TYPES,
        ADBDeviceMonitor, DeviceInfo,
        ADB_AVAILABLE,
    )
except ImportError:
    ADB_AVAILABLE = False
    ANDROID_ARTIFACT_TYPES = {}
    AndroidCollector = None
    ADBDeviceMonitor = None
    DeviceInfo = None

# Try to import iOS collector
try:
    from collectors.ios_collector import (
        iOSCollector, IOS_ARTIFACT_TYPES,
        find_ios_backups,
    )
    IOS_AVAILABLE = True
except ImportError:
    IOS_AVAILABLE = False
    IOS_ARTIFACT_TYPES = {}
    iOSCollector = None
    find_ios_backups = None

# Try to import Linux collector
try:
    from collectors.linux_collector import (
        LinuxCollector, LINUX_ARTIFACT_TYPES,
        check_linux_target
    )
    LINUX_AVAILABLE = True
except ImportError:
    LINUX_AVAILABLE = False
    LINUX_ARTIFACT_TYPES = {}
    LinuxCollector = None
    check_linux_target = None

# Try to import macOS collector
try:
    from collectors.macos_collector import (
        macOSCollector, MACOS_ARTIFACT_TYPES,
        check_macos_target
    )
    MACOS_AVAILABLE = True
except ImportError:
    MACOS_AVAILABLE = False
    MACOS_ARTIFACT_TYPES = {}
    macOSCollector = None
    check_macos_target = None

# =============================================================================
# C4 Security: Path Traversal Attack Defense Utilities
# =============================================================================

def validate_safe_path(base_dir: Path, target_path: Path) -> Path:
    """
    Verify that a path is inside base_dir

    Args:
        base_dir: Allowed base directory
        target_path: Target path to verify

    Returns:
        Verified path (in resolved state)

    Raises:
        ValueError: If path is outside base_dir
    """
    resolved_base = base_dir.resolve()
    resolved_target = target_path.resolve()

    try:
        resolved_target.relative_to(resolved_base)
    except ValueError:
        raise ValueError(
            f"[SECURITY] Path traversal detected: '{target_path}' "
            f"is outside allowed directory '{base_dir}'"
        )

    return resolved_target

def sanitize_path_component(name: str) -> str:
    """
    Remove dangerous characters from path component

    Args:
        name: Path component (filename or directory name)

    Returns:
        Safe name
    """
    # Remove path separators and parent directory references
    dangerous_chars = ['/', '\\', '..', '\x00']
    safe_name = name
    for char in dangerous_chars:
        safe_name = safe_name.replace(char, '_')

    # Use default if empty string
    if not safe_name.strip():
        safe_name = 'unnamed'

    return safe_name

# Artifact type definitions
ARTIFACT_TYPES: Dict[str, Dict[str, Any]] = {}

# =============================================================================
# Local MFT Collector (inherits from BaseMFTCollector)
# =============================================================================

# BitLocker module import
try:
    from utils.bitlocker import (
        detect_bitlocker_on_system_drive,
        BitLockerDecryptor,
        is_pybde_installed,
        BitLockerVolumeDetectionResult
    )
    BITLOCKER_MODULE_AVAILABLE = True
except ImportError:
    BITLOCKER_MODULE_AVAILABLE = False
    BitLockerDecryptor = None

# Dynamic base class determination
_LocalMFTBase = BaseMFTCollector if (BASE_MFT_AVAILABLE and BaseMFTCollector) else object

class LocalSystemCollector:
    """
    Local macOS/Linux live system collector.

    Adapter that wraps macOSCollector or LinuxCollector to produce
    the (file_path, metadata) 2-tuples expected by the GUI collection
    worker, matching the LocalMFTCollector interface used for Windows.

    Tracks PermissionError counts for UI feedback.
    """

    def __init__(self, output_dir: str, os_type: str, target_root: str = '/'):
        """
        Args:
            output_dir: Output directory for collected files
            os_type: 'macos' or 'linux'
            target_root: Filesystem root (default: '/' for live collection)
        """
        self._output_dir = Path(output_dir)
        self._os_type = os_type
        self._target_root = target_root
        self.permission_error_count = 0
        self.permission_error_paths = []

        self._output_dir.mkdir(parents=True, exist_ok=True)

    def get_collection_mode(self) -> str:
        """Return collection mode description"""
        root_tag = "root" if self._is_root() else "non-root"
        return f"{self._os_type} local ({root_tag})"

    def _is_root(self) -> bool:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False

    def collect(self, artifact_type: str, **kwargs):
        """
        Collect artifacts and yield (file_path, metadata) 2-tuples.

        Wraps the underlying platform collector's 3-tuple output,
        writes content to disk, and yields the output path with metadata.
        """
        if self._os_type == 'macos':
            if not MACOS_AVAILABLE or macOSCollector is None:
                yield '', {
                    'status': 'error',
                    'error': 'macOS collector not available on this platform',
                    'artifact_type': artifact_type,
                }
                return
            CollectorClass = macOSCollector
            method_label = 'macos_local_collector'
        elif self._os_type == 'linux':
            if not LINUX_AVAILABLE or LinuxCollector is None:
                yield '', {
                    'status': 'error',
                    'error': 'Linux collector not available on this platform',
                    'artifact_type': artifact_type,
                }
                return
            CollectorClass = LinuxCollector
            method_label = 'linux_local_collector'
        else:
            yield '', {
                'status': 'error',
                'error': f'Unknown OS type: {self._os_type}',
                'artifact_type': artifact_type,
            }
            return

        artifact_dir = self._output_dir / artifact_type
        artifact_dir.mkdir(parents=True, exist_ok=True)

        try:
            collector = CollectorClass(str(artifact_dir), target_root=self._target_root)

            for relative_path, content, metadata in collector.collect(artifact_type):
                try:
                    output_path = artifact_dir / relative_path.replace('/', os.sep)
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    output_path.write_bytes(content)

                    file_metadata = {
                        'artifact_type': artifact_type,
                        'collection_method': method_label,
                        'target_root': self._target_root,
                        'collected_at': datetime.utcnow().isoformat(),
                        'file_size': len(content),
                        **metadata
                    }

                    yield str(output_path), file_metadata

                except PermissionError as e:
                    self.permission_error_count += 1
                    self.permission_error_paths.append(str(e))

        except PermissionError as e:
            self.permission_error_count += 1
            self.permission_error_paths.append(str(e))
        except Exception as e:
            logger.debug(f"[{self._os_type.upper()}] Collection failed for {artifact_type}: {e}")

    def close(self):
        """Cleanup (no-op for local collection)"""
        pass


def _collect_hardware_metadata_standalone() -> Optional[Dict[str, str]]:
    """Collect system hardware identifiers (standalone, no class dependency)."""
    meta = {}
    try:
        import wmi
        c = wmi.WMI()
        for cs in c.Win32_ComputerSystemProduct():
            if cs.UUID:
                meta['sys_uuid'] = cs.UUID
                break
        for disk in c.Win32_DiskDrive():
            if disk.Index == 0:
                meta['hdd_model'] = disk.Model or ''
                meta['hdd_serial'] = (disk.SerialNumber or '').strip()
                break
    except Exception:
        pass
    if 'sys_uuid' not in meta:
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Cryptography')
            val, _ = winreg.QueryValueEx(key, 'MachineGuid')
            meta['sys_uuid'] = val
            winreg.CloseKey(key)
        except Exception:
            pass
    if 'hdd_model' not in meta or 'hdd_serial' not in meta:
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\disk\Enum')
            count, _ = winreg.QueryValueEx(key, 'Count')
            if count > 0:
                disk_id, _ = winreg.QueryValueEx(key, '0')
                if 'hdd_model' not in meta:
                    meta['hdd_model'] = disk_id.split('\\')[1] if '\\' in disk_id else ''
                if 'hdd_serial' not in meta:
                    parts = disk_id.split('\\')
                    meta['hdd_serial'] = parts[2] if len(parts) > 2 else ''
            winreg.CloseKey(key)
        except Exception:
            pass
    return meta if meta.get('sys_uuid') else None


def _save_hardware_metadata_standalone(
    output_dir, artifact_type: str
) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Collect and save hardware metadata as JSON."""
    import json as _json
    hw_meta = _collect_hardware_metadata_standalone()
    if not hw_meta:
        return None
    hw_path = Path(output_dir) / '_hardware_info.json'
    try:
        with open(hw_path, 'w') as f:
            _json.dump(hw_meta, f, indent=2)
        return str(hw_path), {
            'artifact_type': artifact_type,
            'original_path': str(hw_path),
            'filename': '_hardware_info.json',
            'type': artifact_type,
            'name': '_hardware_info.json',
            'path': str(hw_path),
            'size': hw_path.stat().st_size,
            'is_metadata': True,
            'collection_method': 'hardware_metadata',
        }
    except Exception:
        return None


def _save_collection_diagnostic_standalone(
    output_dir,
    artifact_type: str,
    filename: str,
    diagnostic: Dict[str, Any],
) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Save a small collection diagnostic file for parser/user visibility."""
    import json as _json

    diag_path = Path(output_dir) / filename
    payload = {
        'artifact_type': artifact_type,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        **diagnostic,
    }
    try:
        diag_path.parent.mkdir(parents=True, exist_ok=True)
        with open(diag_path, 'w', encoding='utf-8') as f:
            _json.dump(payload, f, indent=2)
        return str(diag_path), {
            'artifact_type': artifact_type,
            'original_path': str(diag_path),
            'filename': filename,
            'type': artifact_type,
            'name': filename,
            'path': str(diag_path),
            'size': diag_path.stat().st_size,
            'is_metadata': True,
            'collection_method': 'collection_diagnostic',
        }
    except Exception:
        return None


def _dump_process_memory_for_artifact(
    owner: Any,
    artifact_type: str,
    process_name: Any,
    artifact_dir: Path,
) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
    """Dump messenger process memory once per artifact type."""
    if getattr(owner, f'_memory_dumped_{artifact_type}', False):
        return
    setattr(owner, f'_memory_dumped_{artifact_type}', True)

    try:
        from collectors.process_memory_dumper import ProcessMemoryDumper
        dumper = ProcessMemoryDumper()
        process_names = process_name
        if isinstance(process_names, str):
            process_names = [process_names]
        process_names = [str(name) for name in (process_names or []) if name]
        last_result: Dict[str, Any] = {}

        for candidate_name in process_names:
            dump_filename = f"{candidate_name.replace('.exe', '').lower()}_memory.dmp"
            dump_path = str(artifact_dir / dump_filename)

            logger.debug(f"[MEMORY] Dumping {candidate_name}...")
            dump_result = dumper.dump_process_lightweight(candidate_name, dump_path)
            last_result = dump_result

            if dump_result.get('success'):
                size_mb = dump_result.get('size', 0) / 1024 / 1024
                logger.info(
                    f"[MEMORY] Dump success: {dump_filename} "
                    f"({size_mb:.1f} MB, PID={dump_result.get('pid')})"
                )
                yield dump_path, {
                    'artifact_type': artifact_type,
                    'original_path': dump_path,
                    'type': artifact_type,
                    'name': dump_filename,
                    'path': dump_path,
                    'size': dump_result.get('size', 0),
                    'process_pid': dump_result.get('pid'),
                    'process_name': candidate_name,
                    'is_memory_dump': True,
                    'collection_method': 'process_memory_dump',
                }
                return

            try:
                failed_dump = Path(dump_path)
                if failed_dump.exists():
                    failed_dump.unlink()
            except Exception:
                pass

        logger.debug(
            f"[MEMORY] Dump skipped: "
            f"{last_result.get('error', 'process not found') if last_result else 'no process names'}"
        )
        if artifact_type == 'server_managed_windows_app':
            diag_result = _save_collection_diagnostic_standalone(
                artifact_dir,
                artifact_type,
                '_collection_status.json',
                {
                    'collection_status': 'partial',
                    'detail_code': 'protected_live_context_unavailable',
                    'impact': 'Some protected application records may be unavailable in this collection.',
                    'operator_action': 'Review collection prerequisites and retry with elevated collection mode when appropriate.',
                },
            )
            if diag_result:
                yield diag_result
        if last_result.get('requires_admin'):
            if artifact_type == 'server_managed_windows_app':
                logger.warning(
                    "[MEMORY] Some protected application data may require elevated collection mode."
                )
            else:
                logger.warning(
                    "[MEMORY] Re-run the collector as Administrator to collect "
                    "messenger process memory."
                )
    except ImportError:
        logger.debug("[MEMORY] ProcessMemoryDumper not available")
    except Exception as e:
        logger.debug(f"[MEMORY] Error: {e}")


class LocalMFTCollector(_LocalMFTBase):
    """
    Local disk MFT-based collector

    Inherits from BaseMFTCollector to use the same MFT-based collection as E01.

    Collection priority:
    1. MFT parsing-based collection (ForensicDiskAccessor)
    2. BitLocker encrypted -> attempt decryption -> MFT collection
    3. Decryption failed -> directory traversal fallback (Windows API)

    Digital forensics principles:
    - No file count limit
    - Include deleted files (MFT mode only)
    - Include system folders
    """

    def __init__(self, output_dir: str, volume: str = 'C', decrypted_reader=None):
        """
        Args:
            output_dir: Directory to store extracted artifacts
            volume: Volume to collect from (default: 'C')
            decrypted_reader: Pre-decrypted BitLocker/LUKS volume reader (optional)
        """
        if not BASE_MFT_AVAILABLE:
            raise ImportError("BaseMFTCollector not available")

        super().__init__(output_dir)

        self.volume = volume
        self._partition_index: Optional[int] = None
        self._drive_number: Optional[int] = None

        # BitLocker and fallback related
        self._bitlocker_detected: bool = False
        self._bitlocker_decrypted: bool = False
        self._use_directory_fallback: bool = False
        self._decrypted_reader = decrypted_reader

        self._initialize_accessor()

    def _initialize_accessor(self) -> bool:
        """
        Initialize ForensicDiskAccessor

        Collection priority:
        1. Normal NTFS partition -> MFT collection
        2. BitLocker partition -> attempt decryption -> MFT collection
        3. Decryption failed -> directory traversal fallback
        """
        if not FORENSIC_DISK_AVAILABLE or ForensicDiskAccessor is None:
            logger.warning("ForensicDiskAccessor not available, using directory fallback")
            self._use_directory_fallback = True
            return False

        try:
            # Get physical drive number
            self._drive_number = self._get_physical_drive_number()
            if self._drive_number is None:
                logger.warning("Cannot determine physical drive number, using directory fallback")
                self._use_directory_fallback = True
                return False

            self._accessor = ForensicDiskAccessor.from_physical_disk(self._drive_number)

            # Find partition for volume
            partition_result = self._find_partition_for_volume()

            if partition_result['found']:
                if partition_result['is_bitlocker']:
                    # BitLocker encrypted partition found
                    self._bitlocker_detected = True
                    logger.info(f"BitLocker encrypted partition detected at index {partition_result['index']}")

                    # Use pre-decrypted reader if available (from GUI dialog)
                    if self._decrypted_reader:
                        try:
                            self._accessor = ForensicDiskAccessor(self._decrypted_reader)
                            self._accessor.select_partition(0)
                            self._partition_index = 0
                            self._bitlocker_decrypted = True
                            logger.info("Using pre-decrypted BitLocker volume for MFT collection")
                            return True
                        except Exception as e:
                            logger.warning(f"Decrypted reader initialization failed: {e}")

                    # Attempt auto-decryption
                    if self._try_bitlocker_decryption(partition_result['index']):
                        self._bitlocker_decrypted = True
                        logger.info("BitLocker decryption successful, using MFT collection")
                        return True
                    else:
                        # Decryption failed -> directory traversal fallback
                        logger.warning("BitLocker decryption failed, falling back to directory traversal")
                        self._use_directory_fallback = True
                        self._accessor = None
                        return False
                else:
                    # Normal NTFS partition
                    self._accessor.select_partition(partition_result['index'])
                    self._partition_index = partition_result['index']
                    logger.info(f"LocalMFTCollector initialized: {self.volume}: (Drive {self._drive_number}, Partition {partition_result['index']})")
                    return True
            else:
                # Cannot find partition -> directory traversal fallback
                logger.warning("Cannot find partition for volume, using directory fallback")
                self._use_directory_fallback = True
                return False

        except Exception as e:
            logger.warning(f"LocalMFTCollector initialization failed: {e}, using directory fallback")
            self._accessor = None
            self._use_directory_fallback = True
            return False

    def _try_bitlocker_decryption(self, partition_index: int) -> bool:
        """
        Attempt BitLocker decryption

        If Windows has already mounted the volume (logged in state),
        it can be accessed via OS, so collection is possible via directory fallback.

        Args:
            partition_index: BitLocker partition index

        Returns:
            Whether decryption was successful
        """
        if not BITLOCKER_MODULE_AVAILABLE:
            logger.debug("BitLocker module not available")
            return False

        if not is_pybde_installed():
            logger.debug("pybde not installed, cannot decrypt BitLocker")
            return False

        decryptor = None
        try:
            # Initialize BitLocker decryptor
            decryptor = BitLockerDecryptor.from_physical_disk(
                self._drive_number,
                partition_index
            )

            # Attempt auto-unlock (TPM, auto-unlock key, etc.)
            # User input may actually be required
            # Here we check if Windows has already mounted the volume

            # Windows-mounted volumes can be accessed via directory traversal
            volume_path = f"{self.volume}:\\"
            if os.path.exists(volume_path) and os.path.isdir(volume_path):
                logger.info(f"Volume {self.volume}: is mounted and accessible via Windows API")
                # Use directory fallback (already mounted)
                return False  # MFT still inaccessible, fallback needed

            return False

        except Exception as e:
            logger.debug(f"BitLocker decryption attempt failed: {e}")
            return False
        finally:
            if decryptor is not None:
                try:
                    decryptor.close()
                except Exception:
                    pass

    def _get_source_description(self) -> str:
        """Return source description"""
        if self._use_directory_fallback:
            return f"Local: {self.volume}: (Directory Fallback)"
        return f"Local: {self.volume}:"

    def _get_physical_drive_number(self) -> Optional[int]:
        """Get physical drive number from volume letter"""
        try:
            import ctypes
            from ctypes import wintypes

            volume_path = f"\\\\.\\{self.volume}:"

            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.CreateFileW(
                volume_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )

            if handle == -1:
                return None

            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000

            class DISK_EXTENT(ctypes.Structure):
                _fields_ = [
                    ("DiskNumber", wintypes.DWORD),
                    ("StartingOffset", ctypes.c_int64),
                    ("ExtentLength", ctypes.c_int64),
                ]

            class VOLUME_DISK_EXTENTS(ctypes.Structure):
                _fields_ = [
                    ("NumberOfDiskExtents", wintypes.DWORD),
                    ("Extents", DISK_EXTENT * 1),
                ]

            extents = VOLUME_DISK_EXTENTS()
            bytes_returned = wintypes.DWORD()

            result = kernel32.DeviceIoControl(
                handle,
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                None, 0,
                ctypes.byref(extents),
                ctypes.sizeof(extents),
                ctypes.byref(bytes_returned),
                None
            )

            kernel32.CloseHandle(handle)

            if result and extents.NumberOfDiskExtents > 0:
                return extents.Extents[0].DiskNumber

            return None

        except Exception as e:
            logger.debug(f"Cannot get physical drive number: {e}")
            return None

    def _find_partition_for_volume(self) -> Dict[str, Any]:
        """
        Find partition index for current volume

        Returns:
            {
                'found': bool,
                'index': Optional[int],
                'is_bitlocker': bool,
                'filesystem': str
            }
        """
        result = {'found': False, 'index': None, 'is_bitlocker': False, 'filesystem': ''}

        if not self._accessor:
            return result

        try:
            partitions = self._accessor.list_partitions()

            best_partition = None
            best_size = 0
            bitlocker_partition = None

            for i, part in enumerate(partitions):
                # Skip Recovery partition
                if 'recovery' in part.type_name.lower():
                    continue

                # Record BitLocker encrypted partition
                if part.filesystem in ('BitLocker', 'bitlocker'):
                    # Select largest BitLocker partition (usually main Windows partition)
                    if bitlocker_partition is None or part.size > best_size:
                        bitlocker_partition = i
                        best_size = part.size
                    continue

                # Select largest NTFS partition
                if part.filesystem in ('NTFS', 'ntfs'):
                    if part.size > best_size:
                        best_size = part.size
                        best_partition = i

            # NTFS partition takes priority
            if best_partition is not None:
                result['found'] = True
                result['index'] = best_partition
                result['is_bitlocker'] = False
                result['filesystem'] = 'NTFS'
            # If no NTFS, use BitLocker partition
            elif bitlocker_partition is not None:
                result['found'] = True
                result['index'] = bitlocker_partition
                result['is_bitlocker'] = True
                result['filesystem'] = 'BitLocker'

            return result

        except Exception as e:
            logger.debug(f"Cannot find partition: {e}")
            return result

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None,
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts

        Uses MFT mode or directory traversal fallback.

        Args:
            artifact_type: Type of artifact to collect
            progress_callback: Progress callback

        Yields:
            (local path, metadata) tuple
        """
        if self._use_directory_fallback:
            # BitLocker or MFT inaccessible -> directory traversal
            logger.info(f"[{self._get_source_description()}] Collecting {artifact_type} via directory traversal...")
            yield from self._collect_directory_fallback(artifact_type, progress_callback)
        else:
            # MFT mode: if artifact is NOT in MFT filters but IS in ARTIFACT_TYPES
            # (e.g., PC messengers with glob-based collection), use directory fallback for those
            # zone_identifier: MFT ADS scan doesn't work on live disk (ads_streams not populated),
            # use Windows API to read ADS directly instead
            if artifact_type not in ARTIFACT_MFT_FILTERS and artifact_type in ARTIFACT_TYPES:
                logger.info(f"[{self._get_source_description()}] {artifact_type} not in MFT filters, using directory fallback...")
                yield from self._collect_directory_fallback(artifact_type, progress_callback)
            elif artifact_type == 'zone_identifier':
                logger.info(f"[{self._get_source_description()}] zone_identifier: using Windows API for ADS collection...")
                yield from self._collect_directory_fallback(artifact_type, progress_callback)
            else:
                # MFT-based collection (parent class)
                yield from super().collect(artifact_type, progress_callback, **kwargs)

                # Memory dump for PC messengers collected via MFT mode.
                if artifact_type in ARTIFACT_TYPES:
                    at_config = ARTIFACT_TYPES[artifact_type]
                    if at_config.get('collector') == 'collect_messenger_with_memory':
                        process_names = _messenger_process_names(at_config)
                        already_dumped = getattr(self, f'_memory_dumped_{artifact_type}', False)
                        logger.info(
                            f"[MFT+Memory] {artifact_type}: process_names={process_names}, "
                            f"already_dumped={already_dumped}"
                        )
                        artifact_dir = self.output_dir / artifact_type
                        artifact_dir.mkdir(exist_ok=True)
                        yield from _dump_process_memory_for_artifact(
                            self,
                            artifact_type, process_names, artifact_dir
                        )
                        # Collect hardware metadata (for server-side processing)
                        if artifact_type == 'server_managed_windows_app':
                            hw_dir = self.output_dir / artifact_type
                            hw_dir.mkdir(exist_ok=True)
                            hw_result = _save_hardware_metadata_standalone(hw_dir, artifact_type)
                            if hw_result:
                                yield hw_result
                    else:
                        logger.debug(f"[MFT+Memory] {artifact_type}: collector={at_config.get('collector')}, skipping dump")

        live_config = ARTIFACT_TYPES.get(artifact_type, {})
        if live_config.get('registry_context'):
            for result in self._collect_live_registry_context(
                artifact_type, live_config
            ):
                yield result
                if progress_callback:
                    progress_callback(result[0])

    def _collect_live_registry_context(
        self,
        artifact_type: str,
        config: Dict[str, Any],
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect explicit registry values authorized by the runtime profile."""
        if os.name != 'nt':
            return
        system_drive = os.environ.get('SystemDrive', 'C:').rstrip(':').lower()
        if str(self.volume).rstrip(':').lower() != system_drive:
            return
        try:
            import base64
            import json
            import winreg
        except ImportError:
            return

        roots = {
            'HKCU': winreg.HKEY_CURRENT_USER,
            'HKLM': winreg.HKEY_LOCAL_MACHINE,
        }
        values = []
        for descriptor in config.get('registry_context', [])[:16]:
            root_name = str(descriptor.get('root', '')).upper()
            key_path = str(descriptor.get('path', ''))
            root = roots.get(root_name)
            if root is None or not key_path:
                continue
            try:
                with winreg.OpenKey(root, key_path) as key:
                    for value_name in descriptor.get('values', [])[:32]:
                        try:
                            value, value_type = winreg.QueryValueEx(key, value_name)
                        except OSError:
                            continue
                        if isinstance(value, bytes):
                            encoded: Any = {
                                'encoding': 'base64',
                                'data': base64.b64encode(value).decode('ascii'),
                            }
                        elif isinstance(value, (str, int)):
                            encoded = value
                        elif isinstance(value, (list, tuple)):
                            encoded = [str(item) for item in value[:256]]
                        else:
                            encoded = str(value)
                        values.append({
                            'root': root_name,
                            'path': key_path,
                            'name': str(value_name),
                            'type': int(value_type),
                            'value': encoded,
                        })
            except OSError:
                continue
        if not values:
            return

        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)
        output_path = artifact_dir / '_registry_context.json'
        output_path.write_text(
            json.dumps(
                {
                    'schema': 'unjaena.registry-context.v1',
                    'artifact_type': artifact_type,
                    'values': values,
                },
                ensure_ascii=True,
                separators=(',', ':'),
            ),
            encoding='utf-8',
        )
        metadata = self._get_metadata(
            str(output_path), output_path, artifact_type
        )
        metadata['collection_method'] = 'authorized_registry_context'
        metadata['original_path'] = 'registry://authorized-context'
        yield str(output_path), metadata

    def _get_metadata(
        self,
        src_path: str,
        dst_path: Path,
        artifact_type: str
    ) -> Dict[str, Any]:
        return _build_collected_file_metadata(src_path, Path(dst_path), artifact_type)

    def _collect_directory_fallback(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Directory traversal-based collection (BitLocker/MFT fallback)

        Collects files using paths from ARTIFACT_TYPES.
        Cannot collect deleted files.
        """
        if artifact_type not in ARTIFACT_TYPES:
            # Handle MFT-only artifacts (document, image, video, etc.)
            if artifact_type in ARTIFACT_MFT_FILTERS:
                yield from self._collect_full_disk_scan(artifact_type, progress_callback)
            else:
                logger.debug(f"Skipping unsupported artifact type: {artifact_type}")
            return

        config = ARTIFACT_TYPES[artifact_type]
        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)

        source = self._get_source_description()
        collected_count = 0

        # Special artifacts ($MFT, $UsnJrnl, $LogFile) require MFT-based collection
        # Delegate to mft_collector if available, otherwise skip
        if artifact_type in ARTIFACT_MFT_FILTERS:
            mft_filter = ARTIFACT_MFT_FILTERS[artifact_type]
            if mft_filter.get('special'):
                if hasattr(self, 'mft_collector') and self.mft_collector:
                    yield from self._collect_mft(
                        artifact_type, config, artifact_dir,
                        progress_callback, include_deleted=True
                    )
                else:
                    logger.warning(f"Cannot collect {artifact_type} - requires MFT-based collection")
                return

        # Special artifacts cannot be collected via directory fallback
        if config.get('requires_mft'):
            logger.warning(f"Cannot collect {artifact_type} via directory fallback (requires raw disk access)")
            return

        # Skip non-Windows artifacts (mobile, macOS, Linux require their own collectors)
        if config.get('category') in ('android', 'ios', 'macos', 'linux'):
            logger.debug(f"Skipping non-Windows artifact: {artifact_type}")
            return

        # Handle aliases
        if 'alias_of' in config:
            artifact_type = config['alias_of']
            config = ARTIFACT_TYPES[artifact_type]

        # User file artifacts share one extension/path policy across local,
        # fallback, and disk-image collection paths.
        if artifact_type in USER_FILE_EXTENSION_POLICY:
            mft_filter = ARTIFACT_MFT_FILTERS.get(artifact_type, {})
            yield from self._collect_user_file_filter_scan(
                artifact_type, mft_filter, progress_callback
            )
            return

        collector_type = config.get('collector')
        paths = config.get('paths', [])

        # User folder list
        users_dir = Path(f"{self.volume}:/Users")
        user_folders = []
        if users_dir.exists():
            for entry in users_dir.iterdir():
                if entry.is_dir() and entry.name.lower() not in {'public', 'default', 'default user', 'all users'}:
                    user_folders.append(entry)

        if collector_type == 'collect_glob':
            # Glob pattern collection
            for path_pattern in paths:
                expanded = self._expand_path(path_pattern)
                for match in glob.glob(expanded, recursive=True):
                    result = self._copy_file_with_metadata(match, artifact_dir, artifact_type)
                    if result:
                        collected_count += 1
                        yield result
                        if progress_callback:
                            progress_callback(result[0])

        elif collector_type == 'collect_files':
            # Specific file collection
            for file_path in paths:
                expanded = self._expand_path(file_path)
                if os.path.exists(expanded):
                    result = self._copy_file_with_metadata(expanded, artifact_dir, artifact_type)
                    if result:
                        collected_count += 1
                        yield result
                        if progress_callback:
                            progress_callback(result[0])

        elif collector_type == 'collect_locked_files':
            # Locked file collection (attempt normal copy)
            for file_path in paths:
                expanded = self._expand_path(file_path)
                if os.path.exists(expanded):
                    result = self._copy_file_with_metadata(expanded, artifact_dir, artifact_type)
                    if result:
                        collected_count += 1
                        yield result
                        if progress_callback:
                            progress_callback(result[0])

        elif collector_type in ('collect_ntuser', 'collect_usrclass'):
            # Per-user registry collection
            mft_config = config.get('mft_config', {})
            user_file = mft_config.get('user_path', '')
            for user_folder in user_folders:
                file_path = user_folder / user_file
                if file_path.exists():
                    result = self._copy_file_with_metadata(str(file_path), artifact_dir, artifact_type)
                    if result:
                        collected_count += 1
                        yield result
                        if progress_callback:
                            progress_callback(result[0])

        elif collector_type in ('collect_user_glob', 'collect_user_files'):
            # Per-user glob collection (+ system-wide %PROGRAMDATA% support)
            for path_pattern in paths:
                # System-wide paths (not per-user)
                if '%PROGRAMDATA%' in path_pattern or '%SYSTEMROOT%' in path_pattern:
                    expanded = self._expand_path(path_pattern)
                    for match in glob.glob(expanded, recursive=True):
                        if os.path.isdir(match):
                            continue
                        result = self._copy_file_with_metadata(match, artifact_dir, artifact_type)
                        if result:
                            collected_count += 1
                            yield result
                            if progress_callback:
                                progress_callback(result[0])
                    continue

                # Per-user paths
                for user_folder in user_folders:
                    # %APPDATA% -> Users/xxx/AppData/Roaming
                    expanded = path_pattern.replace('%APPDATA%', str(user_folder / 'AppData' / 'Roaming'))
                    expanded = expanded.replace('%LOCALAPPDATA%', str(user_folder / 'AppData' / 'Local'))
                    expanded = expanded.replace('%USERPROFILE%', str(user_folder))
                    for match in glob.glob(expanded, recursive=True):
                        if os.path.isdir(match):
                            continue
                        result = self._copy_file_with_metadata(match, artifact_dir, artifact_type)
                        if result:
                            collected_count += 1
                            yield result
                            if progress_callback:
                                progress_callback(result[0])

        elif collector_type == 'collect_app_bundle':
            seen_paths = set()
            for path_pattern in paths:
                expanded = self._expand_path(path_pattern)
                for match in glob.glob(expanded, recursive=True):
                    if os.path.isdir(match):
                        continue
                    normalized = os.path.normcase(os.path.abspath(match))
                    if normalized in seen_paths:
                        continue
                    seen_paths.add(normalized)
                    result = self._copy_file_with_metadata(
                        match, artifact_dir, artifact_type
                    )
                    if result:
                        result[1]['collection_method'] = 'application_bundle_directory_fallback'
                        result[1]['source_pattern'] = path_pattern
                        collected_count += 1
                        yield result
                        if progress_callback:
                            progress_callback(result[0])

        elif collector_type == 'collect_ai_activity':
            seen_paths = set()
            for path_pattern in paths:
                expanded = self._expand_path(path_pattern)
                for match in glob.glob(expanded, recursive=True):
                    candidates = []
                    if os.path.isdir(match):
                        for root, _dirs, files in os.walk(match):
                            for filename in files:
                                candidates.append(os.path.join(root, filename))
                    else:
                        candidates.append(match)

                    for candidate in candidates:
                        normalized = os.path.normcase(os.path.abspath(candidate))
                        if normalized in seen_paths:
                            continue
                        seen_paths.add(normalized)

                        result = self._copy_file_with_metadata(candidate, artifact_dir, artifact_type)
                        if result:
                            result[1]['collection_method'] = 'ai_activity_directory_fallback'
                            result[1]['source_pattern'] = path_pattern
                            collected_count += 1
                            yield result
                            if progress_callback:
                                progress_callback(result[0])

        elif collector_type == 'collect_messenger_with_memory':
            # Messenger app collection with process memory dump
            # 1. Collect user data folders (same as collect_user_glob)
            exclude_exts = config.get('exclude_extensions', [])
            for path_pattern in paths:
                for user_folder in user_folders:
                    expanded = path_pattern.replace('%APPDATA%', str(user_folder / 'AppData' / 'Roaming'))
                    expanded = expanded.replace('%LOCALAPPDATA%', str(user_folder / 'AppData' / 'Local'))
                    expanded = expanded.replace('%USERPROFILE%', str(user_folder))
                    for match in glob.glob(expanded, recursive=True):
                        if os.path.isdir(match):
                            continue
                        # Skip excluded extensions
                        if exclude_exts and any(match.lower().endswith(ext.lower()) for ext in exclude_exts):
                            continue
                        result = self._copy_file_with_metadata(match, artifact_dir, artifact_type)
                        if result:
                            collected_count += 1
                            yield result
                            if progress_callback:
                                progress_callback(result[0])

            # 2. Collect process memory dump (if process is running)
            process_names = _messenger_process_names(config)
            logger.info(
                f"[DirFallback+Memory] {artifact_type}: process_names={process_names}, "
                f"collected={collected_count} files"
            )
            for result in _dump_process_memory_for_artifact(
                self,
                artifact_type, process_names, artifact_dir
            ):
                collected_count += 1
                yield result

            # 3. Collect hardware metadata (for server-side processing)
            if artifact_type == 'server_managed_windows_app':
                hw_result = _save_hardware_metadata_standalone(artifact_dir, artifact_type)
                if hw_result:
                    collected_count += 1
                    yield hw_result

        elif collector_type == 'collect_all_browsers':
            # Browser data collection
            browsers = config.get('browsers', {})
            for browser_name, browser_config in browsers.items():
                browser_paths = browser_config.get('paths', [])
                for path_pattern in browser_paths:
                    for user_folder in user_folders:
                        expanded = path_pattern.replace('%LOCALAPPDATA%', str(user_folder / 'AppData' / 'Local'))
                        expanded = expanded.replace('%APPDATA%', str(user_folder / 'AppData' / 'Roaming'))
                        for match in glob.glob(expanded, recursive=True):
                            result = self._copy_file_with_metadata(match, artifact_dir, artifact_type)
                            if result:
                                collected_count += 1
                                yield result
                                if progress_callback:
                                    progress_callback(result[0])

        elif collector_type == 'collect_scheduled_tasks':
            # Scheduled task collection
            tasks_dir = Path(f"{self.volume}:/Windows/System32/Tasks")
            if tasks_dir.exists():
                for root, dirs, files in os.walk(tasks_dir):
                    for filename in files:
                        file_path = os.path.join(root, filename)
                        result = self._copy_file_with_metadata(file_path, artifact_dir, artifact_type)
                        if result:
                            collected_count += 1
                            yield result
                            if progress_callback:
                                progress_callback(result[0])

        elif collector_type == 'collect_recycle_bin':
            # Recycle Bin dedicated collection - improved system folder permission handling
            # Use Windows path format (backslash)
            recycle_bin_path = None

            # Try case variations (Windows is case-insensitive, but try explicitly)
            variants = ['$Recycle.Bin', '$RECYCLE.BIN', '$recycle.bin', 'RECYCLER']
            for variant in variants:
                # Use backslash
                test_path = Path(f"{self.volume}:\\{variant}")
                logger.debug(f"[RecycleBin] Checking path: {test_path}")
                try:
                    if test_path.exists():
                        recycle_bin_path = test_path
                        logger.info(f"[RecycleBin] Found at: {recycle_bin_path}")
                        break
                except (PermissionError, OSError) as e:
                    logger.debug(f"[RecycleBin] Cannot check {test_path}: {e}")
                    continue

            if recycle_bin_path is None:
                logger.warning(f"[RecycleBin] $Recycle.Bin not found on {self.volume}:")
                logger.debug(f"[RecycleBin] $Recycle.Bin not found on {self.volume}:")
            else:
                try:
                    # Traverse each user SID folder
                    sid_folders = list(recycle_bin_path.iterdir())
                    logger.info(f"[RecycleBin] Found {len(sid_folders)} folders in Recycle Bin")

                    for sid_folder in sid_folders:
                        if sid_folder.is_dir() and sid_folder.name.startswith('S-1-'):
                            logger.debug(f"[RecycleBin] Processing SID folder: {sid_folder.name}")
                            logger.debug(f"[RecycleBin] Processing SID folder: {sid_folder.name}")
                            try:
                                # Collect $I files (metadata) and $R files
                                entries = list(sid_folder.iterdir())
                                logger.debug(f"[RecycleBin] Found {len(entries)} entries in {sid_folder.name}")

                                for entry in entries:
                                    # Collect $I file (metadata)
                                    if entry.name.startswith('$I') and entry.is_file():
                                        try:
                                            result = self._copy_file_with_metadata(
                                                str(entry), artifact_dir, artifact_type
                                            )
                                            if result:
                                                collected_count += 1
                                                logger.info(f"[RecycleBin] Collected: {entry.name}")
                                                yield result
                                                if progress_callback:
                                                    progress_callback(result[0])

                                                # Also try to collect corresponding $R file
                                                r_file = sid_folder / entry.name.replace('$I', '$R')
                                                if r_file.exists():
                                                    r_result = self._copy_file_with_metadata(
                                                        str(r_file), artifact_dir, artifact_type
                                                    )
                                                    if r_result:
                                                        collected_count += 1
                                                        logger.info(f"[RecycleBin] Collected: {r_file.name}")
                                                        yield r_result
                                        except PermissionError as pe:
                                            logger.warning(f"[RecycleBin] Permission denied: {entry} - {pe}")
                                            logger.debug(f"[RecycleBin] Permission denied: {entry} - {pe}")
                                            continue
                                        except OSError as oe:
                                            logger.warning(f"[RecycleBin] OS error: {entry} - {oe}")
                                            logger.debug(f"[RecycleBin] OS error: {entry} - {oe}")
                                            continue
                            except PermissionError as pe:
                                logger.warning(f"[RecycleBin] Cannot access SID folder: {sid_folder} - {pe}")
                                logger.debug(f"[RecycleBin] Cannot access SID folder: {sid_folder}")
                                continue
                            except OSError as oe:
                                logger.warning(f"[RecycleBin] OS error on SID folder: {sid_folder} - {oe}")
                                continue

                    logger.info(f"[RecycleBin] Collection complete: {collected_count} files")

                except PermissionError as e:
                    logger.error(f"[RecycleBin] Cannot access Recycle Bin: {e} - requires admin privileges")
                    logger.debug(f"[RecycleBin] Cannot access Recycle Bin: {e}")
                except OSError as e:
                    logger.error(f"[RecycleBin] OS error accessing Recycle Bin: {e}")

        elif collector_type == 'collect_zone_identifier':
            # Zone.Identifier ADS collection via Windows API
            # MFT-based ADS scan doesn't work on live disk, read ADS directly
            user_dirs_to_scan = ['Downloads', 'Desktop', 'Documents']
            for user_folder in user_folders:
                for subdir in user_dirs_to_scan:
                    scan_dir = user_folder / subdir
                    if not scan_dir.exists():
                        continue
                    try:
                        for entry in scan_dir.iterdir():
                            if not entry.is_file():
                                continue
                            ads_path = str(entry) + ':Zone.Identifier'
                            try:
                                with open(ads_path, 'r', encoding='utf-8', errors='replace') as f:
                                    ads_data = f.read()
                                if ads_data.strip():
                                    safe_name = entry.name.replace(':', '_').replace('/', '_').replace('\\', '_')
                                    output_file = artifact_dir / f"{safe_name}_Zone.Identifier.txt"
                                    output_file.write_text(ads_data, encoding='utf-8')
                                    collected_count += 1
                                    metadata = self._get_metadata(str(entry), str(output_file), artifact_type)
                                    metadata['original_path'] = f"{entry}:Zone.Identifier"
                                    metadata['ads_content'] = ads_data[:500]
                                    yield str(output_file), metadata
                                    if progress_callback:
                                        progress_callback(str(output_file))
                            except (OSError, PermissionError):
                                # No Zone.Identifier ADS on this file
                                continue
                    except (PermissionError, OSError) as e:
                        logger.debug(f"[ZoneId] Cannot access {scan_dir}: {e}")
                        continue
            logger.info(f"[ZoneId] Collected {collected_count} Zone.Identifier ADS streams")

        else:
            # Default: try to collect if paths exist
            for path_pattern in paths:
                expanded = self._expand_path(path_pattern)
                if '*' in expanded or '?' in expanded:
                    for match in glob.glob(expanded, recursive=True):
                        result = self._copy_file_with_metadata(match, artifact_dir, artifact_type)
                        if result:
                            collected_count += 1
                            yield result
                            if progress_callback:
                                progress_callback(result[0])
                elif os.path.exists(expanded):
                    result = self._copy_file_with_metadata(expanded, artifact_dir, artifact_type)
                    if result:
                        collected_count += 1
                        yield result
                        if progress_callback:
                            progress_callback(result[0])

        logger.info(f"[{source}] Collected {collected_count} {artifact_type} artifacts (directory fallback)")

    def _expand_path(self, path: str) -> str:
        """Expand environment variables"""
        volume_root = f"{self.volume}:"
        # Expand environment variables
        path = path.replace('%SYSTEMROOT%', f'{volume_root}\\Windows')
        path = path.replace('%WINDIR%', f'{volume_root}\\Windows')
        path = path.replace('%PROGRAMDATA%', f'{volume_root}\\ProgramData')
        # User-specific paths are based on current user
        path = os.path.expandvars(path)
        # Change C: drive to current volume
        if path.startswith('C:'):
            path = volume_root + path[2:]
        return path

    def _collect_user_file_filter_scan(
        self,
        artifact_type: str,
        mft_filter: Dict[str, Any],
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect user-file artifacts using the shared MFT filter policy."""
        extensions = set(mft_filter.get('extensions') or USER_FILE_EXTENSION_POLICY.get(artifact_type, set()))
        target_files = {str(name).lower() for name in (mft_filter.get('files') or set())}
        if not extensions and not target_files:
            return

        path_patterns = []
        if mft_filter.get('path_pattern'):
            path_patterns.append(mft_filter['path_pattern'])
        path_patterns.extend(mft_filter.get('path_patterns') or [])
        compiled_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in path_patterns
        ]
        exclude_path_patterns = mft_filter.get('exclude_path_patterns') or []
        compiled_exclude_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in exclude_path_patterns
        ]

        def _normalized_filter_path(value: str) -> str:
            normalized = value.replace('\\', '/').lower()
            return re.sub(r'^[a-z]:/*', '', normalized).lstrip('/')

        def _excluded_path(value: str) -> bool:
            normalized = _normalized_filter_path(value)
            return any(pattern.search(normalized) for pattern in compiled_exclude_patterns)

        full_disk_scan = bool(mft_filter.get('full_disk_scan'))
        max_file_size = int(mft_filter.get('max_file_size') or 0)

        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)

        volume_root = f"{self.volume}:\\"
        source = self._get_source_description()
        collected_count = 0

        def _join_scan_path(parent: str, child: str) -> str:
            if '\\' in parent or re.match(r'^[a-zA-Z]:', parent):
                return ntpath.join(parent, child)
            return os.path.join(parent, child)

        skip_dirs = {
            'windows', '$recycle.bin', 'system volume information',
            'programdata', '$windows.~bt', '$windows.~ws',
            'recovery', 'boot', 'perflogs',
        }
        skip_subdirs = {
            'winsxs', 'installer', 'assembly', 'servicing',
            'softwaredistribution', 'catroot', 'catroot2',
            'e01_extract', 'e01_preview_',
        }
        skip_prefixes = ('forensic_', 'e01_preview_')

        users_dir = _join_scan_path(volume_root, 'Users')
        scan_dirs = []
        if os.path.exists(users_dir):
            scan_dirs.append(users_dir)

        try:
            for entry in os.scandir(volume_root):
                if not entry.is_dir():
                    continue
                name_lower = entry.name.lower()
                if name_lower in skip_dirs:
                    continue
                if entry.path != users_dir:
                    scan_dirs.append(entry.path)
        except PermissionError:
            pass
        except OSError as e:
            logger.debug(f"Cannot scan {volume_root}: {e}")

        total_dirs = len(scan_dirs)
        logger.info(
            f"[{source}] Filter scan for {artifact_type} "
            f"({len(extensions)} extensions, {total_dirs} roots)"
        )

        for dir_idx, scan_dir in enumerate(scan_dirs, 1):
            logger.info(f"[{source}] Scanning [{dir_idx}/{total_dirs}] {scan_dir}")

            for root, dirs, files in os.walk(scan_dir):
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in skip_subdirs
                    and not any(d.lower().startswith(prefix) for prefix in skip_prefixes)
                    and not _excluded_path(_join_scan_path(root, d))
                ]

                try:
                    for filename in files:
                        filename_lower = filename.lower()
                        if filename_lower.startswith('._'):
                            continue
                        ext = os.path.splitext(filename)[1].lower()
                        if ext not in extensions and filename_lower not in target_files:
                            continue

                        src_path = _join_scan_path(root, filename)
                        if _excluded_path(src_path):
                            continue
                        if max_file_size > 0:
                            try:
                                if os.path.getsize(src_path) > max_file_size:
                                    continue
                            except OSError:
                                continue

                        if compiled_patterns and not full_disk_scan:
                            normalized_path = _normalized_filter_path(src_path)
                            if not any(pattern.search(normalized_path) for pattern in compiled_patterns):
                                continue

                        result = self._copy_file_with_metadata(src_path, artifact_dir, artifact_type)
                        if result:
                            collected_count += 1
                            yield result
                            if progress_callback:
                                progress_callback(result[0])
                except PermissionError:
                    continue
                except Exception as e:
                    logger.debug(f"Error scanning {root}: {e}")
                    continue

        logger.info(f"[{source}] Collected {collected_count} {artifact_type} artifacts (filter scan)")

    def _collect_full_disk_scan(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Full disk scan (document, image, video, etc.)"""
        if artifact_type not in ARTIFACT_MFT_FILTERS:
            return
        yield from self._collect_user_file_filter_scan(
            artifact_type,
            ARTIFACT_MFT_FILTERS[artifact_type],
            progress_callback,
        )

    def _copy_file_with_metadata(
        self,
        src_path: str,
        artifact_dir: Path,
        artifact_type: str
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Copy file and generate metadata

        Args:
            src_path: Source file path
            artifact_dir: Output directory
            artifact_type: Artifact type

        Returns:
            (local path, metadata) or None
        """
        try:
            src = Path(src_path)
            if not src.exists() or not src.is_file():
                return None

            # Generate output filename
            safe_filename = src.name
            output_file = artifact_dir / safe_filename

            # Prevent duplicates
            if output_file.exists():
                base = output_file.stem
                suffix = output_file.suffix
                counter = 1
                while output_file.exists():
                    output_file = artifact_dir / f"{base}_{counter}{suffix}"
                    counter += 1

            # Single-pass copy + hash (avoid reading file twice)
            MAX_HASH_SIZE = 100 * 1024 * 1024  # 100MB
            stat = src.stat()
            hash_skipped = False

            if stat.st_size <= MAX_HASH_SIZE:
                md5_hash = hashlib.md5(usedforsecurity=False)
                sha256_hash = hashlib.sha256()
                # Use exclusive create to prevent race conditions
                try:
                    fd = os.open(str(output_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                except FileExistsError:
                    # Another thread created it first; use fallback name
                    output_file = artifact_dir / f"{output_file.stem}_{os.getpid()}{output_file.suffix}"
                    fd = os.open(str(output_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                with open(src_path, 'rb') as f_in, os.fdopen(fd, 'wb') as f_out:
                    while True:
                        chunk = f_in.read(65536)
                        if not chunk:
                            break
                        f_out.write(chunk)
                        md5_hash.update(chunk)
                        sha256_hash.update(chunk)
                # Preserve timestamps after writing
                shutil.copystat(src_path, str(output_file))
                md5_hex = md5_hash.hexdigest()
                sha256_hex = sha256_hash.hexdigest()
            else:
                # Large files: copy without hashing
                shutil.copy2(src_path, output_file)
                md5_hex = ''
                sha256_hex = ''
                hash_skipped = True

            # Generate metadata
            metadata = {
                'artifact_type': artifact_type,
                'name': src.name,
                'original_path': str(src),
                'size': stat.st_size,
                'hash_md5': md5_hex,
                'hash_sha256': sha256_hex,
                'collection_method': 'directory_fallback',
                'source': self._get_source_description(),
                'is_deleted': False,  # Directory fallback cannot collect deleted files
                'created_time': datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
                'modified_time': datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                'collected_at': datetime.now().isoformat(),
                'warning': 'Collected via directory fallback - deleted files not recoverable',
            }
            if hash_skipped:
                metadata['hash_skipped'] = True

            if self._bitlocker_detected:
                metadata['bitlocker_status'] = 'encrypted_but_mounted'

            return str(output_file), metadata

        except PermissionError:
            logger.debug(f"Permission denied: {src_path}")
            return None
        except Exception as e:
            logger.debug(f"Cannot copy {src_path}: {e}")
            return None

    def get_collection_mode(self) -> str:
        """Return current collection mode"""
        if self._use_directory_fallback:
            if self._bitlocker_detected:
                return "directory_fallback (BitLocker)"
            return "directory_fallback"
        return "mft_based"

class ArtifactCollector:
    """
    Forensic artifact collector with ForensicDiskAccessor and MFT support.

    Collection priority:
    1. ForensicDiskAccessor (pure Python, raw sector access) - direct read of locked files
    2. MFTCollector (ForensicDiskAccessor-based) - MFT-based collection
    3. Legacy (shutil) - normal file copy

    ForensicDiskAccessor advantages:
    - Pure Python implementation (no external dependencies)
    - Direct parsing of MBR/GPT -> VBR -> MFT -> Cluster Run
    - Can collect OS-locked files
    - ADS (Alternate Data Streams) support
    - Deleted file recovery possible

    BitLocker support:
    - Pass decrypted volume via decrypted_reader parameter
    """

    def __init__(
        self,
        output_dir: str,
        use_mft: bool = True,
        volume: str = 'C',
        decrypted_reader=None  # BitLocker decrypted UnifiedDiskReader
    ):
        """
        Initialize the collector.

        Args:
            output_dir: Directory to store collected artifacts
            use_mft: Whether to use MFT-based collection (default: True)
            volume: Volume to collect from (default: 'C')
            decrypted_reader: BitLocker decrypted disk reader (optional)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.volume = volume
        self.decrypted_reader = decrypted_reader

        # Collectors
        self.forensic_disk_accessor: Optional[ForensicDiskAccessor] = None
        self.mft_collector: Optional[MFTCollector] = None
        self.collection_mode = 'legacy'

        # ==========================================================
        # Priority 1: ForensicDiskAccessor (pure Python)
        # ==========================================================
        if use_mft and FORENSIC_DISK_AVAILABLE and ForensicDiskAccessor is not None:
            # Use decrypted reader directly (BitLocker/LUKS already unlocked)
            if self.decrypted_reader:
                try:
                    self.forensic_disk_accessor = ForensicDiskAccessor(self.decrypted_reader)
                    self.forensic_disk_accessor.select_partition(0)
                    self.collection_mode = 'forensic_disk_accessor'
                    logger.debug("[INFO] ForensicDiskAccessor initialized from decrypted volume")
                except Exception as e:
                    logger.debug(f"[WARNING] Decrypted volume ForensicDiskAccessor failed: {e}")
                    self.forensic_disk_accessor = None
            else:
                try:
                    drive_number = self._get_physical_drive_number()
                    if drive_number is not None:
                        self.forensic_disk_accessor = ForensicDiskAccessor.from_physical_disk(drive_number)
                        partition_idx = self._find_partition_for_volume()
                        if partition_idx is not None:
                            self.forensic_disk_accessor.select_partition(partition_idx)
                            self.collection_mode = 'forensic_disk_accessor'
                            logger.debug(f"[INFO] ForensicDiskAccessor initialized for {self.volume}: (Drive {drive_number}, Partition {partition_idx})")
                except Exception as e:
                    logger.debug(f"[WARNING] ForensicDiskAccessor unavailable: {e}")
                    self.forensic_disk_accessor = None

        # ==========================================================
        # Priority 2: MFTCollector (ForensicDiskAccessor) - fallback
        # ==========================================================
        if self.collection_mode != 'forensic_disk_accessor' and use_mft and MFT_AVAILABLE:
            try:
                if self.decrypted_reader:
                    logger.debug("[INFO] Using BitLocker decrypted volume for MFT collection")
                    self.mft_collector = MFTCollector(
                        volume,
                        str(output_dir),
                        disk_reader=self.decrypted_reader
                    )
                else:
                    self.mft_collector = MFTCollector(volume, str(output_dir))
                self.collection_mode = 'mft'
                logger.debug("[INFO] MFTCollector initialized")
            except Exception as e:
                logger.debug(f"[WARNING] MFT collection unavailable: {e}")
                self.mft_collector = None

        # ==========================================================
        # Priority 3: Legacy (shutil)
        # ==========================================================
        if self.collection_mode == 'legacy':
            logger.debug("[INFO] Using legacy collection method (shutil)")

        # Flag for compatibility
        self.use_mft = self.collection_mode in ('forensic_disk_accessor', 'mft')

        # Cache for scan_all_files() results — avoids repeated full MFT scans
        self._scan_cache = None
        # Pre-built index from scan cache for O(1) extension/filename lookups
        self._scan_index = None
        self._app_bundle_seen: Dict[str, set[str]] = {}

    def _get_physical_drive_number(self) -> Optional[int]:
        """Get physical drive number from volume letter"""
        try:
            import ctypes
            from ctypes import wintypes

            # Volume path
            volume_path = f"\\\\.\\{self.volume}:"

            # Open volume
            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.CreateFileW(
                volume_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )

            if handle == -1:
                return None

            # Get disk extent info via IOCTL
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000

            class DISK_EXTENT(ctypes.Structure):
                _fields_ = [
                    ("DiskNumber", wintypes.DWORD),
                    ("StartingOffset", ctypes.c_int64),
                    ("ExtentLength", ctypes.c_int64),
                ]

            class VOLUME_DISK_EXTENTS(ctypes.Structure):
                _fields_ = [
                    ("NumberOfDiskExtents", wintypes.DWORD),
                    ("Extents", DISK_EXTENT * 1),
                ]

            extents = VOLUME_DISK_EXTENTS()
            bytes_returned = wintypes.DWORD()

            result = kernel32.DeviceIoControl(
                handle,
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                None, 0,
                ctypes.byref(extents),
                ctypes.sizeof(extents),
                ctypes.byref(bytes_returned),
                None
            )

            kernel32.CloseHandle(handle)

            if result and extents.NumberOfDiskExtents > 0:
                return extents.Extents[0].DiskNumber

            return None

        except Exception as e:
            logger.debug(f"[WARNING] Cannot get physical drive number: {e}")
            return None

    def _find_partition_for_volume(self) -> Optional[int]:
        """
        Find partition index for current volume

        BitLocker encrypted partitions are skipped.
        Non-decrypted BitLocker volumes cannot be accessed via raw sector access.
        """
        if not self.forensic_disk_accessor:
            return None

        try:
            partitions = self.forensic_disk_accessor.list_partitions()

            # 1. Find largest NTFS partition by volume size (usually main Windows partition)
            # 2. Skip BitLocker encrypted partitions
            best_partition = None
            best_size = 0

            for i, part in enumerate(partitions):
                # Skip BitLocker encrypted partition
                if part.filesystem in ('BitLocker', 'bitlocker'):
                    logger.debug(f"[INFO] Partition {i} is BitLocker encrypted - skipping for ForensicDiskAccessor")
                    continue

                # Skip Recovery partition (no Windows folder)
                if 'recovery' in part.type_name.lower():
                    continue

                # Select largest NTFS partition
                if part.filesystem in ('NTFS', 'ntfs'):
                    if part.size > best_size:
                        best_size = part.size
                        best_partition = i

            if best_partition is not None:
                # Check if selected partition has Windows folder
                try:
                    self.forensic_disk_accessor.select_partition(best_partition)
                    # Check for Windows folder existence (find Windows among root's children)
                    has_windows = False
                    for entry_num in range(0, 200):
                        try:
                            metadata = self.forensic_disk_accessor._extractor.get_file_metadata(entry_num)
                            if (metadata.parent_ref == 5 and
                                metadata.is_directory and
                                metadata.filename.lower() == 'windows'):
                                has_windows = True
                                break
                        except Exception:
                            continue

                    if has_windows:
                        return best_partition
                    else:
                        logger.debug(f"[INFO] Partition {best_partition} has no Windows folder - trying MFTCollector")
                        return None
                except Exception as e:
                    logger.debug(f"[WARNING] Cannot verify partition {best_partition}: {e}")
                    return None

            # If no NTFS, return None (fallback to MFTCollector)
            logger.debug("[INFO] No suitable NTFS partition found for ForensicDiskAccessor")
            return None

        except Exception as e:
            logger.debug(f"[WARNING] Cannot find partition: {e}")
            return None

    def close(self):
        """Clean up resources"""
        # Release scan cache and index to free memory
        self._scan_cache = None
        self._scan_index = None

        if self.forensic_disk_accessor:
            try:
                self.forensic_disk_accessor.close()
            except Exception:
                pass
            self.forensic_disk_accessor = None

        if self.mft_collector:
            self.mft_collector.close()
            self.mft_collector = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _build_scan_index(self, scan_result):
        """Build extension and path-based indices from MFT scan results.

        Converts O(n) linear scan per artifact type to O(1) dict lookup
        by pre-grouping entries by file extension and filename.
        Called once after the first MFT scan, then reused for all artifact types.
        """
        index = {
            'by_extension': {},   # {'.evtx': [entry, ...], '.pf': [entry, ...]}
            'by_filename': {},    # {'ntuser.dat': [entry, ...]}
            'no_extension': [],   # entries without file extension
            'has_ads': [],        # entries with Alternate Data Streams
        }

        all_files = list(scan_result.get('active_files', []))
        all_files.extend(scan_result.get('deleted_files', []))

        for entry in all_files:
            if entry.is_directory:
                continue

            filename_lower = entry.filename.lower()

            # Index by extension
            if '.' in filename_lower:
                ext = '.' + filename_lower.rsplit('.', 1)[-1]
                if ext not in index['by_extension']:
                    index['by_extension'][ext] = []
                index['by_extension'][ext].append(entry)
            else:
                index['no_extension'].append(entry)

            # Index by lowercase filename (for exact name matches)
            if filename_lower not in index['by_filename']:
                index['by_filename'][filename_lower] = []
            index['by_filename'][filename_lower].append(entry)

            # Index entries with Alternate Data Streams (Zone.Identifier, etc.)
            if hasattr(entry, 'ads_streams') and entry.ads_streams:
                index['has_ads'].append(entry)

        ext_count = sum(len(v) for v in index['by_extension'].values())
        logger.debug(
            f"[ForensicDisk] Scan index built: "
            f"{len(index['by_extension'])} extensions, "
            f"{len(index['by_filename'])} unique filenames, "
            f"{len(index['has_ads'])} ADS entries, "
            f"{ext_count + len(index['no_extension'])} total entries"
        )

        return index

    def get_available_artifacts(self) -> List[Dict[str, Any]]:
        """
        Get list of available artifact types.

        Returns:
            List of artifact info dictionaries
        """
        artifacts = []
        for type_id, info in ARTIFACT_TYPES.items():
            available = True
            unavailable_reason = None

            # Check if requires MFT
            if info.get('requires_mft', False) and not self.use_mft:
                available = False
                unavailable_reason = 'MFT collection required'

            # Check if requires ADB
            if info.get('requires_adb', False) and not ADB_AVAILABLE:
                available = False
                unavailable_reason = 'ADB not installed or not in PATH'

            # Check if requires iOS backup
            if info.get('requires_backup', False) and not IOS_AVAILABLE:
                available = False
                unavailable_reason = 'iOS backup support not available'

            artifacts.append({
                'type': type_id,
                'name': info['name'],
                'description': info['description'],
                'category': info.get('category', 'windows'),
                'requires_admin': info.get('requires_admin', False),
                'requires_mft': info.get('requires_mft', False),
                'requires_adb': info.get('requires_adb', False),
                'requires_root': info.get('requires_root', False),
                'requires_backup': info.get('requires_backup', False),
                'available': available,
                'unavailable_reason': unavailable_reason,
            })

        return artifacts

    def get_artifacts_by_category(self, category: str) -> List[Dict[str, Any]]:
        """
        Get available artifacts filtered by category.

        Args:
            category: 'windows', 'android', or 'ios'

        Returns:
            List of artifact info dictionaries for the category
        """
        all_artifacts = self.get_available_artifacts()
        return [a for a in all_artifacts if a.get('category', 'windows') == category]

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None,
        include_deleted: bool = True,
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts of a specific type.

        Args:
            artifact_type: Type of artifact to collect (e.g., 'prefetch')
            progress_callback: Optional callback for progress updates
            include_deleted: Include deleted files (MFT mode only)
            **kwargs: Additional arguments for specific collectors
                - device_serial: Android device serial (for android category)
                - backup_path: iOS backup path (for ios category)

        Yields:
            Tuple of (file_path, metadata) for each collected file
        """
        if artifact_type not in ARTIFACT_TYPES:
            raise ValueError(f"Unknown artifact type: {artifact_type}")

        artifact_info = ARTIFACT_TYPES[artifact_type]

        # Handle alias types (e.g., browser_chrome -> browser)
        if 'alias_of' in artifact_info:
            actual_type = artifact_info['alias_of']
            browser_filter = artifact_info.get('filter_browser')
            artifact_info = ARTIFACT_TYPES[actual_type]
            artifact_type = actual_type
        else:
            browser_filter = None

        # Get category for routing
        category = artifact_info.get('category', 'windows')

        # Check availability based on category
        if artifact_info.get('requires_mft', False) and not self.use_mft:
            logger.debug(f"[WARNING] {artifact_type} requires MFT collection")
            return

        if artifact_info.get('requires_adb', False) and not ADB_AVAILABLE:
            logger.debug(f"[WARNING] {artifact_type} requires ADB (not in PATH)")
            return

        if artifact_info.get('requires_backup', False) and not IOS_AVAILABLE:
            logger.debug(f"[WARNING] {artifact_type} requires iOS backup support")
            return

        # Create artifact-specific output directory
        # C4 Security: Path traversal attack defense - verify with utility functions
        artifact_dir = self.output_dir / sanitize_path_component(artifact_type)
        validate_safe_path(self.output_dir, artifact_dir)
        artifact_dir.mkdir(exist_ok=True)

        # Route to appropriate collector based on category
        if category == 'android':
            yield from self._collect_android(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, **kwargs
            )
        elif category == 'ios':
            yield from self._collect_ios(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, **kwargs
            )
        elif category == 'linux':
            yield from self._collect_linux(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, **kwargs
            )
        elif category == 'macos':
            yield from self._collect_macos(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, **kwargs
            )
        elif artifact_type == 'browser':
            # Special handling for browser type
            yield from self._collect_browsers(
                artifact_info, artifact_dir, progress_callback,
                browser_filter, include_deleted
            )
        elif self.collection_mode == 'forensic_disk_accessor' and self.forensic_disk_accessor:
            # Priority 1: ForensicDiskAccessor (pure Python)
            yield from self._collect_forensic_disk(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, include_deleted
            )
        elif self.collection_mode == 'mft' and self.mft_collector:
            # Priority 2: MFTCollector (ForensicDiskAccessor)
            yield from self._collect_mft(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, include_deleted
            )
        else:
            # Priority 3: Legacy (shutil)
            yield from self._collect_legacy(
                artifact_type, artifact_info, artifact_dir,
                progress_callback
            )

        if artifact_info.get('registry_context'):
            for result in self._collect_registry_context(
                artifact_type, artifact_info, artifact_dir
            ):
                yield result
                if progress_callback:
                    progress_callback(result[0])

    def _collect_browsers(
        self,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        browser_filter: Optional[str],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect browser data from Chrome, Edge, and Firefox.

        Args:
            artifact_info: Browser artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            browser_filter: Optional filter for specific browser (e.g., 'chrome')
            include_deleted: Include deleted files (MFT mode only)
        """
        browsers = artifact_info.get('browsers', {})

        for browser_id, browser_config in browsers.items():
            # Skip if filter is set and doesn't match
            if browser_filter and browser_id != browser_filter:
                continue

            browser_name = browser_config.get('name', browser_id)
            # C4 Security: Path traversal defense
            browser_dir = artifact_dir / sanitize_path_component(browser_id)
            validate_safe_path(self.output_dir, browser_dir)
            browser_dir.mkdir(exist_ok=True)

            # Use MFT collection if available
            if self.use_mft and self.mft_collector:
                yield from self._collect_browser_mft(
                    browser_id, browser_config, browser_dir,
                    progress_callback, include_deleted
                )
            else:
                yield from self._collect_browser_legacy(
                    browser_id, browser_config, browser_dir,
                    progress_callback
                )

    def _collect_browser_mft(
        self,
        browser_id: str,
        browser_config: Dict[str, Any],
        browser_dir: Path,
        progress_callback: Optional[callable],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect browser data using MFT"""
        browser_name = browser_config.get('name', browser_id)
        mft_path = browser_config.get('mft_path', '')
        files = browser_config.get('files', [])
        profile_based = browser_config.get('profile_based', False)

        users_dir = Path(r'C:\Users')

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue
            if user_dir.name.lower() in ['public', 'default', 'default user', 'all users']:
                continue

            if profile_based:
                # Firefox: search for profiles
                profiles_path = f"Users/{user_dir.name}/{mft_path}"
                try:
                    for result in self.mft_collector.collect_by_pattern(
                        profiles_path, "*.sqlite", "browser", include_deleted
                    ):
                        result[1]['browser'] = browser_name
                        result[1]['browser_id'] = browser_id
                        result[1]['username'] = user_dir.name
                        yield result
                        if progress_callback:
                            progress_callback(result[0])
                except Exception as e:
                    logger.debug(f"[MFT BROWSER] Firefox profiles error for {user_dir.name}: {e}")
            else:
                # Chrome/Edge: specific files
                full_base_path = f"Users/{user_dir.name}/{mft_path}"
                for filename in files:
                    file_path = f"{full_base_path}/{filename}"
                    try:
                        for result in self.mft_collector.collect_by_path(
                            file_path, "browser", include_deleted
                        ):
                            result[1]['browser'] = browser_name
                            result[1]['browser_id'] = browser_id
                            result[1]['username'] = user_dir.name
                            yield result
                            if progress_callback:
                                progress_callback(result[0])
                    except Exception as e:
                        logger.debug(f"[MFT BROWSER] Error collecting {filename} for {user_dir.name}: {e}")

    def _collect_browser_legacy(
        self,
        browser_id: str,
        browser_config: Dict[str, Any],
        browser_dir: Path,
        progress_callback: Optional[callable]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect browser data using legacy method"""
        browser_name = browser_config.get('name', browser_id)
        profile_based = browser_config.get('profile_based', False)

        if profile_based:
            # Firefox
            yield from self._collect_firefox_profiles(
                browser_config, browser_dir, 'browser', browser_name
            )
        else:
            # Chrome/Edge
            for path_pattern in browser_config.get('paths', []):
                expanded_path = os.path.expandvars(path_pattern)
                src_path = Path(expanded_path)

                if src_path.exists():
                    try:
                        dst_path = browser_dir / src_path.name
                        shutil.copy2(src_path, dst_path)
                        metadata = self._get_metadata(
                            str(src_path), dst_path, 'browser'
                        )
                        metadata['browser'] = browser_name
                        metadata['browser_id'] = browser_id
                        yield str(dst_path), metadata
                        if progress_callback:
                            progress_callback(str(dst_path))
                    except (PermissionError, OSError) as e:
                        logger.debug(f"[BROWSER] Cannot access {expanded_path}: {e}")

    def _collect_forensic_disk(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts using ForensicDiskAccessor.

        Follows MBR/GPT -> VBR -> MFT -> Data Runs -> Cluster chain
        to read files directly from disk, bypassing the file system.

        Digital forensics principles:
        - document, image, video, email: full disk scan (MFT-based)
        - No file count limit
        - Include deleted files
        - Include system folders

        Advantages:
        - Direct collection of OS-locked files (SYSTEM, SAM, NTUSER.DAT, etc.)
        - Deleted file recovery possible
        - ADS (Alternate Data Streams) support
        - System file collection ($MFT, $UsnJrnl:$J, $LogFile, etc.)
        """
        mft_config = artifact_info.get('mft_config', {})

        # ==========================================================
        # No mft_config → use legacy fallback
        # ==========================================================
        if not mft_config:
            logger.info(f"[ForensicDisk] {artifact_type}: no mft_config, using legacy fallback")
            yield from self._collect_legacy(
                artifact_type, artifact_info, artifact_dir, progress_callback
            )
            return

        # ==========================================================
        # Special MFT artifacts ($MFT, $UsnJrnl, $LogFile)
        # ==========================================================
        if 'special' in mft_config:
            method_name = mft_config['special']
            yield from self._collect_forensic_disk_special(
                method_name, artifact_type, artifact_dir, progress_callback
            )
            return

        # ==========================================================
        # Digital forensics: full disk scan for document, image, video, email
        # ==========================================================
        if artifact_type in {'document', 'image', 'video', 'email'}:
            extensions = mft_config.get('extensions', None)
            if extensions:
                logger.debug(f"[ForensicDisk] Full disk scan for {artifact_type} (Digital Forensics mode)")
                yield from self._collect_forensic_disk_pattern(
                    '',  # Ignore base_path
                    '*.*',  # pattern
                    artifact_type,
                    artifact_dir,
                    progress_callback,
                    include_deleted=include_deleted,
                    extensions=extensions,
                    full_disk_scan=True  # Full disk scan
                )
                return

        # ==========================================================
        # User-specific paths (NTUSER.DAT, browser profiles, messengers, etc.)
        # ==========================================================
        if 'user_path' in mft_config or 'user_paths' in mft_config:
            yield from self._collect_forensic_disk_user_paths(
                artifact_type, mft_config, artifact_dir,
                progress_callback, include_deleted
            )
            # Don't return - may also have system_base_paths or process_name
        else:
            # ==========================================================
            # Pattern-based or file list collection (system paths)
            # ==========================================================
            base_path = mft_config.get('base_path', '')
            pattern = mft_config.get('pattern', None)
            files = mft_config.get('files', None)
            extensions = mft_config.get('extensions', None)

            if pattern:
                # Pattern-based collection (with extension filter)
                yield from self._collect_forensic_disk_pattern(
                    base_path, pattern, artifact_type, artifact_dir,
                    progress_callback, include_deleted,
                    extensions=extensions
                )
            elif files:
                # Specific file list collection
                for filename in files:
                    file_path = f"{base_path}/{filename}" if base_path else filename
                    yield from self._collect_forensic_disk_file(
                        file_path, artifact_type, artifact_dir, progress_callback
                    )

        for extra in mft_config.get('additional_patterns', []):
            if not isinstance(extra, dict) or not extra.get('pattern'):
                continue
            yield from self._collect_forensic_disk_pattern(
                str(extra.get('base_path', '')),
                str(extra['pattern']),
                artifact_type,
                artifact_dir,
                progress_callback,
                include_deleted,
                extensions=extra.get('extensions'),
                exclude_extensions=extra.get('exclude_extensions'),
            )

        # ==========================================================
        # System-wide paths (TeamViewer/AnyDesk ProgramData, etc.)
        # ==========================================================
        for sys_path in mft_config.get('system_base_paths', []):
            extensions = mft_config.get('extensions', None)
            exclude_extensions = mft_config.get('exclude_extensions', None)
            logger.debug(f"[ForensicDisk] System path scan: {sys_path}")
            yield from self._collect_forensic_disk_pattern(
                sys_path, '*', artifact_type, artifact_dir,
                progress_callback, include_deleted,
                extensions=extensions,
                exclude_extensions=exclude_extensions,
            )

        # ==========================================================
        # Process memory dump (live system only, for PC messengers)
        # ==========================================================
        process_names = _messenger_process_names(artifact_info)
        if process_names:
            yield from self._dump_process_memory(
                artifact_type, process_names, artifact_dir
            )

        # ==========================================================
        # Hardware metadata (for server-side application data processing)
        # ==========================================================
        if artifact_type == 'server_managed_windows_app':
            hw_result = self._save_hardware_metadata(artifact_dir, artifact_type)
            if hw_result:
                yield hw_result

    def _collect_forensic_disk_special(
        self,
        method_name: str,
        artifact_type: str,
        artifact_dir: Path,
        progress_callback: Optional[callable]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect system MFT artifacts ($MFT, $UsnJrnl:$J, $LogFile)

        NTFS system file inodes:
        - $MFT: inode 0
        - $MFTMirr: inode 1
        - $LogFile: inode 2
        - $Volume: inode 3
        - $AttrDef: inode 4
        - . (Root): inode 5
        - $Bitmap: inode 6
        - $Boot: inode 7
        - $UsnJrnl: $Extend/$UsnJrnl (inode varies, ADS stream "$J")
        """
        try:
            if method_name == 'collect_mft_raw':
                # $MFT (inode 0) — streaming to avoid loading entire MFT into memory
                logger.debug("[ForensicDisk] Collecting $MFT (inode 0)...")
                output_file = artifact_dir / '$MFT'
                md5_hash = hashlib.md5(usedforsecurity=False)
                sha256_hash = hashlib.sha256()
                total_size = 0

                if hasattr(self.forensic_disk_accessor, 'stream_file_by_inode'):
                    with open(output_file, 'wb') as f:
                        for chunk in self.forensic_disk_accessor.stream_file_by_inode(0):
                            if chunk:
                                f.write(chunk)
                                md5_hash.update(chunk)
                                sha256_hash.update(chunk)
                                total_size += len(chunk)
                else:
                    data = self.forensic_disk_accessor.read_file_by_inode(0)
                    if data:
                        output_file.write_bytes(data)
                        md5_hash.update(data)
                        sha256_hash.update(data)
                        total_size = len(data)

                if total_size > 0:
                    metadata = {
                        'artifact_type': artifact_type,
                        'name': '$MFT',
                        'original_path': '$MFT',
                        'size': total_size,
                        'hash_md5': md5_hash.hexdigest(),
                        'hash_sha256': sha256_hash.hexdigest(),
                        'collection_method': 'forensic_disk_accessor',
                        'mft_inode': 0,
                        'collected_at': datetime.now().isoformat(),
                    }

                    yield str(output_file), metadata
                    if progress_callback:
                        progress_callback(str(output_file))
                else:
                    # Clean up empty file if created
                    if output_file.exists():
                        output_file.unlink()

            elif method_name == 'collect_usn_journal':
                # $UsnJrnl:$J - $J ADS of $UsnJrnl file in $Extend folder
                logger.debug("[ForensicDisk] Collecting $UsnJrnl:$J...")

                # Collect $UsnJrnl - use dedicated method
                data = None
                try:
                    # Skip sparse regions (fix memory/size issues)
                    data = self.forensic_disk_accessor.read_usnjrnl_raw(skip_sparse=True)
                except Exception as e1:
                    logger.debug("read_usnjrnl_raw failed: %s", e1)
                    # Alternative: find directly in $Extend directory
                    try:
                        # Find $UsnJrnl in $Extend directory (inode 11)
                        usnjrnl_inode = self.forensic_disk_accessor._find_in_directory(11, '$UsnJrnl')
                        if usnjrnl_inode:
                            # Alternative method also skips sparse
                            data = self.forensic_disk_accessor._read_file_skip_sparse(
                                usnjrnl_inode, stream_name='$J'
                            )
                    except Exception as e2:
                        logger.debug("Alternative USN Journal collection failed: %s", e2)

                if data and len(data) > 0:
                    # USN Journal is sparse file, mostly filled with zeros
                    # Check if there's actual data
                    non_zero_bytes = sum(1 for b in data[:min(len(data), 1024*1024)] if b != 0)
                    logger.debug(f"[ForensicDisk] $UsnJrnl:$J size={len(data)} bytes, non-zero (first 1MB)={non_zero_bytes}")

                    output_file = artifact_dir / '$UsnJrnl_J'
                    output_file.write_bytes(data)

                    metadata = {
                        'artifact_type': artifact_type,
                        'name': '$UsnJrnl:$J',
                        'original_path': '$Extend/$UsnJrnl:$J',
                        'size': len(data),
                        'hash_md5': hashlib.md5(data, usedforsecurity=False).hexdigest(),
                        'hash_sha256': hashlib.sha256(data).hexdigest(),
                        'collection_method': 'forensic_disk_accessor',
                        'ads_stream': '$J',
                        'collected_at': datetime.now().isoformat(),
                    }

                    yield str(output_file), metadata
                    if progress_callback:
                        progress_callback(str(output_file))
                else:
                    logger.debug("[WARNING] $UsnJrnl:$J not found or empty (data is None or 0 bytes)")

            elif method_name == 'collect_logfile':
                # $LogFile (inode 2) — streaming to avoid loading entire LogFile into memory
                logger.debug("[ForensicDisk] Collecting $LogFile (inode 2)...")
                output_file = artifact_dir / '$LogFile'
                md5_hash = hashlib.md5(usedforsecurity=False)
                sha256_hash = hashlib.sha256()
                total_size = 0

                if hasattr(self.forensic_disk_accessor, 'stream_file_by_inode'):
                    with open(output_file, 'wb') as f:
                        for chunk in self.forensic_disk_accessor.stream_file_by_inode(2):
                            if chunk:
                                f.write(chunk)
                                md5_hash.update(chunk)
                                sha256_hash.update(chunk)
                                total_size += len(chunk)
                else:
                    data = self.forensic_disk_accessor.read_file_by_inode(2)
                    if data:
                        output_file.write_bytes(data)
                        md5_hash.update(data)
                        sha256_hash.update(data)
                        total_size = len(data)

                if total_size > 0:
                    metadata = {
                        'artifact_type': artifact_type,
                        'name': '$LogFile',
                        'original_path': '$LogFile',
                        'size': total_size,
                        'hash_md5': md5_hash.hexdigest(),
                        'hash_sha256': sha256_hash.hexdigest(),
                        'collection_method': 'forensic_disk_accessor',
                        'mft_inode': 2,
                        'collected_at': datetime.now().isoformat(),
                    }

                    yield str(output_file), metadata
                    if progress_callback:
                        progress_callback(str(output_file))
                else:
                    # Clean up empty file if created
                    if output_file.exists():
                        output_file.unlink()

            elif method_name == 'collect_zone_identifier':
                # Zone.Identifier ADS - download file source info
                logger.debug("[ForensicDisk] Collecting Zone.Identifier ADS streams...")

                # Target user directories (case-insensitive)
                user_paths = ['downloads', 'desktop', 'documents']
                ads_stream_name = 'Zone.Identifier'
                collected_count = 0
                checked_count = 0

                # Use cached scan result (active_files only for Zone.Identifier)
                if self._scan_cache is None:
                    self._scan_cache = self.forensic_disk_accessor.scan_all_files(include_deleted=True)

                # Build index if not already built
                if self._scan_index is None:
                    self._scan_index = self._build_scan_index(self._scan_cache)

                # Use pre-built ADS index for O(1) lookup instead of scanning all files
                if self._scan_index and 'has_ads' in self._scan_index:
                    ads_entries = self._scan_index['has_ads']
                else:
                    ads_entries = [e for e in self._scan_cache.get('active_files', [])
                                   if hasattr(e, 'ads_streams') and e.ads_streams]

                logger.debug(f"[ForensicDisk] Checking {len(ads_entries)} ADS entries for Zone.Identifier...")

                for entry in ads_entries:
                    try:
                        full_path = getattr(entry, 'full_path', '') or ''
                        filename = getattr(entry, 'filename', '') or ''
                        inode = getattr(entry, 'inode', None)
                        # ads_streams already included in FileCatalogEntry
                        entry_ads = getattr(entry, 'ads_streams', []) or []

                        if not inode or not full_path:
                            continue

                        full_path_lower = full_path.lower()

                        # Filter user directories (under Users folder)
                        is_user_path = False
                        for user_path in user_paths:
                            # '/users/' or 'users/' (handle both with and without root prefix)
                            if ('users/' in full_path_lower or '/users/' in full_path_lower) and \
                               f'/{user_path}/' in full_path_lower:
                                is_user_path = True
                                break

                        if not is_user_path:
                            continue

                        checked_count += 1

                        # Check Zone.Identifier ADS existence (use cached ads_streams)
                        if ads_stream_name not in entry_ads:
                            continue

                        # Read Zone.Identifier ADS
                        ads_data = self.forensic_disk_accessor.read_file_by_inode(
                            inode, stream_name=ads_stream_name
                        )

                        if ads_data:
                            # Output filename: originalfilename_Zone.Identifier.txt
                            safe_filename = self._sanitize_filename(filename)
                            output_filename = f"{safe_filename}_Zone.Identifier.txt"
                            output_file = artifact_dir / output_filename

                            # Prevent duplicates
                            if output_file.exists():
                                counter = 1
                                while output_file.exists():
                                    output_file = artifact_dir / f"{safe_filename}_{counter}_Zone.Identifier.txt"
                                    counter += 1

                            output_file.write_bytes(ads_data)
                            collected_count += 1

                            metadata = {
                                'artifact_type': artifact_type,
                                'name': f"{filename}:Zone.Identifier",
                                'original_path': f"{full_path}:Zone.Identifier",
                                'parent_file': filename,
                                'parent_path': full_path,
                                'size': len(ads_data),
                                'hash_md5': hashlib.md5(ads_data, usedforsecurity=False).hexdigest(),
                                'hash_sha256': hashlib.sha256(ads_data).hexdigest(),
                                'collection_method': 'forensic_disk_accessor',
                                'ads_stream': ads_stream_name,
                                'mft_inode': inode,
                                'collected_at': datetime.now().isoformat(),
                            }

                            # Parse Zone.Identifier content (ZoneId, ReferrerUrl, HostUrl)
                            try:
                                ads_text = ads_data.decode('utf-8', errors='ignore')
                                for line in ads_text.split('\n'):
                                    line = line.strip()
                                    if '=' in line:
                                        key, value = line.split('=', 1)
                                        key = key.strip()
                                        value = value.strip()
                                        if key == 'ZoneId':
                                            metadata['zone_id'] = int(value)
                                            # Zone ID meaning:
                                            # 0 = Local Machine, 1 = Local Intranet
                                            # 2 = Trusted Sites, 3 = Internet, 4 = Restricted Sites
                                            zone_names = {
                                                0: 'Local Machine',
                                                1: 'Local Intranet',
                                                2: 'Trusted Sites',
                                                3: 'Internet',
                                                4: 'Restricted Sites'
                                            }
                                            metadata['zone_name'] = zone_names.get(int(value), 'Unknown')
                                        elif key == 'ReferrerUrl':
                                            metadata['referrer_url'] = value
                                        elif key == 'HostUrl':
                                            metadata['host_url'] = value
                            except Exception:
                                pass

                            yield str(output_file), metadata
                            if progress_callback:
                                progress_callback(str(output_file))

                    except Exception as entry_err:
                        logger.debug("Zone.Identifier entry error: %s", entry_err)
                        continue

                logger.debug(f"[ForensicDisk] Zone.Identifier: checked {checked_count} user files, collected {collected_count} ADS streams")

        except Exception as e:
            logger.debug(f"[ERROR] ForensicDisk special collection failed ({method_name}): {e}")

    def _collect_forensic_disk_file(
        self,
        file_path: str,
        artifact_type: str,
        artifact_dir: Path,
        progress_callback: Optional[callable]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Single file collection (ForensicDiskAccessor)
        """
        try:
            # Normalize path (Windows -> Unix style)
            normalized_path = file_path.replace('\\', '/')
            if not normalized_path.startswith('/'):
                normalized_path = '/' + normalized_path

            logger.debug(f"[ForensicDisk] Reading: {normalized_path}")
            data = self.forensic_disk_accessor.read_file(normalized_path)

            if data:
                # Generate output filename
                filename = Path(file_path).name
                output_file = artifact_dir / filename

                # Prevent duplicates
                if output_file.exists():
                    base = output_file.stem
                    suffix = output_file.suffix
                    counter = 1
                    while output_file.exists():
                        output_file = artifact_dir / f"{base}_{counter}{suffix}"
                        counter += 1

                output_file.write_bytes(data)

                metadata = {
                    'artifact_type': artifact_type,
                    'name': filename,
                    'original_path': file_path,
                    'size': len(data),
                    'hash_md5': hashlib.md5(data, usedforsecurity=False).hexdigest(),
                    'hash_sha256': hashlib.sha256(data).hexdigest(),
                    'collection_method': 'forensic_disk_accessor',
                    'collected_at': datetime.now().isoformat(),
                }

                yield str(output_file), metadata
                if progress_callback:
                    progress_callback(str(output_file))

        except Exception as e:
            logger.debug(f"[WARNING] ForensicDisk cannot read {file_path}: {e}")

    def _collect_forensic_disk_pattern(
        self,
        base_path: str,
        pattern: str,
        artifact_type: str,
        artifact_dir: Path,
        progress_callback: Optional[callable],
        include_deleted: bool,
        extensions: Optional[List[str]] = None,
        exclude_extensions: Optional[List[str]] = None,
        full_disk_scan: bool = False
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Pattern-based collection (ForensicDiskAccessor)

        Scans MFT to collect files matching the pattern.

        Digital forensics principles:
        - No file count limit
        - Include deleted files
        - Include system folders (when full_disk_scan=True)

        Args:
            base_path: Base path (e.g., 'Users/username/Documents')
            pattern: Filename pattern (e.g., '*.pf', '*.*')
            artifact_type: Artifact type
            artifact_dir: Output directory
            progress_callback: Progress callback
            include_deleted: Whether to include deleted files
            extensions: Extension include filter (e.g., ['.doc', '.docx', '.pdf'])
            exclude_extensions: Extension exclude filter (e.g., ['.png', '.jpg'])
            full_disk_scan: If True, scan entire disk (ignore base_path)
        """
        try:
            # MFT scan
            if full_disk_scan:
                logger.debug(f"[ForensicDisk] Full disk scan for {artifact_type} (extensions: {extensions})")
            else:
                logger.debug(f"[ForensicDisk] Scanning for pattern: {base_path}/{pattern}")

            # Use cached scan result to avoid repeated full MFT scans (OOM prevention)
            if self._scan_cache is None:
                self._scan_cache = self.forensic_disk_accessor.scan_all_files(
                    include_deleted=True
                )
            scan_result = self._scan_cache

            # Build index once from scan cache for O(1) lookups across artifact types
            if self._scan_index is None:
                self._scan_index = self._build_scan_index(scan_result)

            # Normalize path
            base_normalized = base_path.replace('\\', '/').strip('/') if not full_disk_scan else ''

            collected_count = 0

            # Normalize extensions (lowercase, include '.')
            if extensions:
                normalized_extensions = set()
                for ext in extensions:
                    ext_lower = ext.lower()
                    if not ext_lower.startswith('.'):
                        ext_lower = '.' + ext_lower
                    normalized_extensions.add(ext_lower)
                extensions = normalized_extensions

            # Normalize exclude_extensions
            normalized_exclude_ext = None
            if exclude_extensions:
                normalized_exclude_ext = set()
                for ext in exclude_extensions:
                    ext_lower = ext.lower()
                    if not ext_lower.startswith('.'):
                        ext_lower = '.' + ext_lower
                    normalized_exclude_ext.add(ext_lower)

            # Select candidate entries using index for fast filtering.
            # With 1M+ MFT entries and 20+ artifact types, index lookup
            # reduces per-type cost from O(n) to O(matches).
            if extensions and self._scan_index:
                # Collect entries matching any requested extension via index
                candidate_entries = []
                for ext in extensions:
                    candidate_entries.extend(
                        self._scan_index['by_extension'].get(ext, [])
                    )
                # Filter by include_deleted preference
                if not include_deleted:
                    candidate_entries = [e for e in candidate_entries if not e.is_deleted]
            elif self._scan_index and not normalized_exclude_ext and pattern:
                # Check for exact filename match (no wildcards)
                if '*' not in pattern and '?' not in pattern:
                    candidate_entries = list(
                        self._scan_index['by_filename'].get(pattern.lower(), [])
                    )
                    if not include_deleted:
                        candidate_entries = [e for e in candidate_entries if not e.is_deleted]
                else:
                    # Wildcard pattern — fall back to full list
                    candidate_entries = list(scan_result.get('active_files', []))
                    if include_deleted:
                        candidate_entries.extend(scan_result.get('deleted_files', []))
            else:
                # No extension filter and no simple pattern — use full list
                candidate_entries = list(scan_result.get('active_files', []))
                if include_deleted:
                    candidate_entries.extend(scan_result.get('deleted_files', []))

            for entry in candidate_entries:
                if entry.is_directory:
                    continue

                filename = entry.filename
                filename_lower = filename.lower()

                # Extension exclude filter (e.g., Telegram: skip media files)
                if normalized_exclude_ext and '.' in filename_lower:
                    file_ext = '.' + filename_lower.rsplit('.', 1)[-1]
                    if file_ext in normalized_exclude_ext:
                        continue

                # Path matching (only when not full_disk_scan)
                if not full_disk_scan and base_normalized:
                    entry_path = entry.full_path.replace('\\', '/').strip('/')
                    if not entry_path.lower().startswith(base_normalized.lower()):
                        continue

                # Pattern matching (only when no extension filter and wildcard pattern)
                if not extensions and not normalized_exclude_ext and pattern:
                    if '*' in pattern or '?' in pattern:
                        if not fnmatch.fnmatch(filename_lower, pattern.lower()):
                            continue

                # Collect file
                try:
                    data = self.forensic_disk_accessor.read_file_by_inode(entry.inode)

                    if data:
                        # Output filename (add prefix for deleted files)
                        if entry.is_deleted:
                            output_filename = f"[DELETED]_{filename}"
                        else:
                            output_filename = filename

                        output_file = artifact_dir / output_filename

                        # Prevent duplicates
                        if output_file.exists():
                            base = output_file.stem
                            suffix = output_file.suffix
                            counter = 1
                            while output_file.exists():
                                output_file = artifact_dir / f"{base}_{counter}{suffix}"
                                counter += 1

                        output_file.write_bytes(data)

                        metadata = {
                            'artifact_type': artifact_type,
                            'name': filename,
                            'original_path': entry.full_path,
                            'size': len(data),
                            'hash_md5': hashlib.md5(data, usedforsecurity=False).hexdigest(),
                            'hash_sha256': hashlib.sha256(data).hexdigest(),
                            'collection_method': 'forensic_disk_accessor',
                            'mft_inode': entry.inode,
                            'is_deleted': entry.is_deleted,
                            'created_time': entry.created_time,
                            'modified_time': entry.modified_time,
                            'collected_at': datetime.now().isoformat(),
                        }

                        yield str(output_file), metadata
                        collected_count += 1

                        if progress_callback:
                            progress_callback(str(output_file))

                except Exception as e:
                    logger.debug(f"[WARNING] Cannot read {entry.full_path}: {e}")

            logger.debug(f"[ForensicDisk] Pattern collection completed: {collected_count} files (no limits)")

        except Exception as e:
            logger.debug(f"[ERROR] ForensicDisk pattern collection failed: {e}")

    def _collect_forensic_disk_user_paths(
        self,
        artifact_type: str,
        mft_config: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Per-user path collection (NTUSER.DAT, browser profiles, messengers, etc.)

        Digital forensics principles:
        - Apply extension filter (include or exclude)
        - Include deleted files
        - Support user_path as string or list (e.g., profile-managed dual layout)
        """
        users_dir = Path(r'C:\Users')

        # Support user_path as string or list
        raw_user_path = mft_config.get(
            'user_path', mft_config.get('user_paths', '')
        )
        if isinstance(raw_user_path, str):
            user_path_list = [raw_user_path]
        else:
            user_path_list = raw_user_path

        pattern = mft_config.get('pattern', None)
        files = mft_config.get('files', None)
        extensions = mft_config.get('extensions', None)
        exclude_extensions = mft_config.get('exclude_extensions', None)

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue

            # Exclude system directories
            if user_dir.name.lower() in ['public', 'default', 'default user', 'all users']:
                continue

            # Per-user output directory
            user_output_dir = artifact_dir / user_dir.name
            user_output_dir.mkdir(exist_ok=True)

            for user_path in user_path_list:
                try:
                    if pattern:
                        # Pattern-based collection (with extension filter)
                        full_base_path = f"Users/{user_dir.name}/{user_path}"
                        for result in self._collect_forensic_disk_pattern(
                            full_base_path, pattern, artifact_type,
                            user_output_dir, progress_callback, include_deleted,
                            extensions=extensions,
                            exclude_extensions=exclude_extensions,
                        ):
                            result[1]['username'] = user_dir.name
                            yield result

                    elif files:
                        # File list collection
                        for filename in files:
                            file_path = f"Users/{user_dir.name}/{user_path}/{filename}"
                            for result in self._collect_forensic_disk_file(
                                file_path, artifact_type, user_output_dir, progress_callback
                            ):
                                result[1]['username'] = user_dir.name
                                yield result

                    elif user_path:
                        # Single file (e.g., NTUSER.DAT)
                        full_path = f"Users/{user_dir.name}/{user_path}"
                        for result in self._collect_forensic_disk_file(
                            full_path, artifact_type, user_output_dir, progress_callback
                        ):
                            result[1]['username'] = user_dir.name
                            yield result

                except Exception as e:
                    logger.debug(f"[WARNING] ForensicDisk error for user {user_dir.name}/{user_path}: {e}")

    def _collect_mft(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts using MFT-based method.
        """
        mft_config = artifact_info.get('mft_config', {})

        # No mft_config → use legacy fallback
        if not mft_config:
            logger.info(f"[MFT] {artifact_type}: no mft_config, using legacy fallback")
            yield from self._collect_legacy(
                artifact_type, artifact_info, artifact_dir, progress_callback
            )
            return

        # Handle special collection methods
        if 'special' in mft_config:
            method_name = mft_config['special']
            method = getattr(self.mft_collector, method_name)
            result = method()
            if result:
                yield result
                if progress_callback:
                    progress_callback(result[0])
            return

        # Handle user-specific paths
        if 'user_path' in mft_config or 'user_paths' in mft_config:
            yield from self._collect_mft_user_paths(
                artifact_type, mft_config, artifact_dir,
                progress_callback, include_deleted
            )
            # Don't return - may also have system_base_paths or process_name
        else:
            # Handle pattern-based collection (system paths)
            base_path = mft_config.get('base_path', '')
            pattern = mft_config.get('pattern', None)
            files = mft_config.get('files', None)
            extensions = mft_config.get('extensions', None)
            exclude_extensions = mft_config.get('exclude_extensions', None)

            if pattern:
                for result in self.mft_collector.collect_by_pattern(
                    base_path, pattern, artifact_type, include_deleted,
                    extensions=extensions,
                    exclude_extensions=exclude_extensions,
                ):
                    yield result
                    if progress_callback:
                        progress_callback(result[0])

            elif files:
                for filename in files:
                    file_path = f"{base_path}/{filename}" if base_path else filename
                    for result in self.mft_collector.collect_by_path(
                        file_path, artifact_type, include_deleted
                    ):
                        yield result
                        if progress_callback:
                            progress_callback(result[0])

        for extra in mft_config.get('additional_patterns', []):
            if not isinstance(extra, dict) or not extra.get('pattern'):
                continue
            for result in self.mft_collector.collect_by_pattern(
                str(extra.get('base_path', '')),
                str(extra['pattern']),
                artifact_type,
                include_deleted,
                extensions=extra.get('extensions'),
                exclude_extensions=extra.get('exclude_extensions'),
            ):
                yield result
                if progress_callback:
                    progress_callback(result[0])

        # System-wide paths (TeamViewer/AnyDesk ProgramData, etc.)
        for sys_path in mft_config.get('system_base_paths', []):
            extensions = mft_config.get('extensions', None)
            exclude_extensions = mft_config.get('exclude_extensions', None)
            logger.debug(f"[MFT] System path scan: {sys_path}")
            try:
                for result in self.mft_collector.collect_by_pattern(
                    sys_path, '*', artifact_type, include_deleted,
                    extensions=extensions,
                    exclude_extensions=exclude_extensions,
                ):
                    # Keep a post-filter for compatibility; modern MFT
                    # collectors apply this before reading/saving content.
                    if extensions:
                        filename = result[0].lower() if isinstance(result[0], str) else str(result[0]).lower()
                        if not any(filename.endswith(ext.lower()) for ext in extensions):
                            continue
                    yield result
                    if progress_callback:
                        progress_callback(result[0])
            except Exception as e:
                logger.debug(f"[MFT] System path {sys_path} not found or inaccessible: {e}")

        # Process memory dump (live system only, for PC messengers)
        process_names = _messenger_process_names(artifact_info)
        if process_names:
            yield from self._dump_process_memory(
                artifact_type, process_names, artifact_dir
            )

        # Hardware metadata (for server-side application data processing)
        if artifact_type == 'server_managed_windows_app':
            hw_result = self._save_hardware_metadata(artifact_dir, artifact_type)
            if hw_result:
                yield hw_result

    def _collect_mft_user_paths(
        self,
        artifact_type: str,
        mft_config: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts from user profile directories using MFT.
        Supports user_path as string or list (e.g., profile-managed dual layout).
        """
        users_dir = Path(r'C:\Users')

        # Support user_path as string or list
        raw_user_path = mft_config.get(
            'user_path', mft_config.get('user_paths', '')
        )
        if isinstance(raw_user_path, str):
            user_path_list = [raw_user_path]
        else:
            user_path_list = raw_user_path

        pattern = mft_config.get('pattern', None)
        files = mft_config.get('files', None)
        extensions = mft_config.get('extensions', None)
        exclude_extensions = mft_config.get('exclude_extensions', None)

        # Normalize exclude_extensions for fast lookup
        exclude_ext_set = None
        if exclude_extensions:
            exclude_ext_set = {
                ext.lower() if ext.startswith('.') else f'.{ext.lower()}'
                for ext in exclude_extensions
            }

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue

            # Skip system directories
            if user_dir.name.lower() in ['public', 'default', 'default user', 'all users']:
                continue

            for user_path in user_path_list:
                full_base_path = f"Users/{user_dir.name}/{user_path}"

                try:
                    if pattern:
                        for result in self.mft_collector.collect_by_pattern(
                            full_base_path, pattern, artifact_type, include_deleted,
                            extensions=extensions,
                            exclude_extensions=exclude_extensions,
                        ):
                            file_name = result[0].lower() if isinstance(result[0], str) else str(result[0]).lower()

                            # Extension include filter
                            if extensions:
                                if not any(file_name.endswith(ext.lower()) for ext in extensions):
                                    continue

                            # Extension exclude filter (e.g., Telegram media)
                            if exclude_ext_set and '.' in file_name:
                                file_ext = '.' + file_name.rsplit('.', 1)[-1]
                                if file_ext in exclude_ext_set:
                                    continue

                            result[1]['username'] = user_dir.name
                            yield result
                            if progress_callback:
                                progress_callback(result[0])

                    elif files:
                        for filename in files:
                            file_path = f"{full_base_path}/{filename}"
                            for result in self.mft_collector.collect_by_path(
                                file_path, artifact_type, include_deleted
                            ):
                                result[1]['username'] = user_dir.name
                                yield result
                                if progress_callback:
                                    progress_callback(result[0])

                    elif user_path:
                        # Single file (like NTUSER.DAT)
                        for result in self.mft_collector.collect_by_path(
                            f"Users/{user_dir.name}/{user_path}",
                            artifact_type, include_deleted
                        ):
                            result[1]['username'] = user_dir.name
                            yield result
                            if progress_callback:
                                progress_callback(result[0])

                except Exception as e:
                    logger.debug(f"[MFT] Error collecting from {user_dir.name}/{user_path}: {e}")

    def _dump_process_memory(
        self,
        artifact_type: str,
        process_name: Any,
        artifact_dir: Path,
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Dump process memory for forensic analysis (live system only).
        Gracefully fails on dead disk (E01) or when process is not running.
        """
        yield from _dump_process_memory_for_artifact(
            self, artifact_type, process_name, artifact_dir
        )

    def _collect_legacy(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts using legacy file API (fallback).

        Note: This method cannot:
        - Recover deleted files
        - Access locked files
        - Preserve MFT metadata
        """
        collector_method_name = artifact_info.get('collector')
        if not collector_method_name:
            return

        collector_method = getattr(self, collector_method_name)

        # Get exclude extensions if specified
        exclude_extensions = artifact_info.get('exclude_extensions')

        for path_pattern in artifact_info['paths']:
            # Pass exclude_extensions for methods that support it
            if collector_method_name in ('collect_user_glob', 'collect_messenger_with_memory') and exclude_extensions:
                results = collector_method(path_pattern, artifact_dir, artifact_type, exclude_extensions)
            else:
                results = collector_method(path_pattern, artifact_dir, artifact_type)

            for result in results:
                # Mark as legacy collection
                result[1].setdefault('collection_method', 'legacy_file_api')
                result[1].setdefault('warning', 'Collected via legacy method - limited forensic value')
                yield result
                if progress_callback:
                    progress_callback(result[0])

    def collect_deleted_files(
        self,
        extensions: Optional[List[str]] = None,
        min_size: int = 0,
        max_size: int = 100 * 1024 * 1024
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Scan and collect deleted files (MFT mode only).

        Args:
            extensions: List of file extensions to look for
            min_size: Minimum file size
            max_size: Maximum file size

        Yields:
            Tuple of (file_path, metadata) for each recovered file
        """
        if not self.use_mft or not self.mft_collector:
            logger.debug("[WARNING] Deleted file recovery requires MFT collection")
            return

        deleted_dir = self.output_dir / 'deleted_files'
        deleted_dir.mkdir(exist_ok=True)

        for entry_info in self.mft_collector.scan_deleted_files(extensions, min_size, max_size):
            # Try to extract the file
            try:
                file_obj = self.mft_collector.fs.open_meta(inode=entry_info.entry_number)
                for result in self.mft_collector._extract_file(
                    file_obj, "", "deleted_recovery"
                ):
                    yield result
            except Exception as e:
                logger.debug(f"[MFT] Cannot recover deleted file {entry_info.filename}: {e}")

    # =========================================================================
    # Legacy Collection Methods (Fallback)
    # =========================================================================

    def collect_app_bundle(
        self,
        pattern: str,
        output_dir: Path,
        artifact_type: str,
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect a bounded application bundle while preserving its path."""
        expanded_pattern = os.path.expandvars(pattern)
        if re.match(r'^[A-Za-z]:[\\/]', expanded_pattern):
            volume = getattr(self, 'volume', expanded_pattern[0])
            expanded_pattern = f"{volume}:{expanded_pattern[2:]}"

        seen_paths = self._app_bundle_seen.setdefault(artifact_type, set())
        for src_path in glob.glob(expanded_pattern, recursive=True):
            if not os.path.isfile(src_path):
                continue

            normalized = os.path.normcase(os.path.abspath(src_path))
            if normalized in seen_paths:
                continue
            seen_paths.add(normalized)

            rel_output = self._safe_ai_output_path(src_path)
            dst_path = output_dir / rel_output
            try:
                validate_safe_path(output_dir, dst_path)
                dst_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_path, dst_path)
                collection_method = 'application_bundle_file_api'
            except (PermissionError, OSError, ValueError):
                try:
                    vss_path = self._get_vss_path(str(src_path))
                    if not vss_path or not Path(vss_path).is_file():
                        continue
                    validate_safe_path(output_dir, dst_path)
                    dst_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(vss_path, dst_path)
                    collection_method = 'application_bundle_vss'
                except (PermissionError, OSError, ValueError):
                    continue

            metadata = self._get_metadata(src_path, dst_path, artifact_type)
            metadata['collection_method'] = collection_method
            metadata['source_pattern'] = pattern
            yield str(dst_path), metadata

    def _collect_registry_context(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        output_dir: Path,
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect explicitly authorized registry values for a live bundle."""
        if os.name != 'nt' or self.decrypted_reader is not None:
            return

        system_drive = os.environ.get('SystemDrive', 'C:').rstrip(':').lower()
        if str(self.volume).rstrip(':').lower() != system_drive:
            return

        try:
            import base64
            import json
            import winreg
        except ImportError:
            return

        roots = {
            'HKCU': winreg.HKEY_CURRENT_USER,
            'HKLM': winreg.HKEY_LOCAL_MACHINE,
        }
        records: List[Dict[str, Any]] = []
        for descriptor in artifact_info.get('registry_context', [])[:16]:
            root_name = str(descriptor.get('root', '')).upper()
            key_path = str(descriptor.get('path', ''))
            root = roots.get(root_name)
            if root is None or not key_path:
                continue
            try:
                with winreg.OpenKey(root, key_path) as key:
                    for value_name in descriptor.get('values', [])[:32]:
                        try:
                            value, value_type = winreg.QueryValueEx(key, value_name)
                        except OSError:
                            continue
                        if isinstance(value, bytes):
                            encoded_value: Any = {
                                'encoding': 'base64',
                                'data': base64.b64encode(value).decode('ascii'),
                            }
                        elif isinstance(value, (str, int)):
                            encoded_value = value
                        elif isinstance(value, (list, tuple)):
                            encoded_value = [str(item) for item in value[:256]]
                        else:
                            encoded_value = str(value)
                        records.append({
                            'root': root_name,
                            'path': key_path,
                            'name': str(value_name),
                            'type': int(value_type),
                            'value': encoded_value,
                        })
            except OSError:
                continue

        if not records:
            return

        output_path = output_dir / '_registry_context.json'
        payload = {
            'schema': 'unjaena.registry-context.v1',
            'artifact_type': artifact_type,
            'values': records,
        }
        output_path.write_text(
            json.dumps(payload, ensure_ascii=True, separators=(',', ':')),
            encoding='utf-8',
        )
        metadata = self._get_metadata(
            str(output_path), output_path, artifact_type
        )
        metadata['collection_method'] = 'authorized_registry_context'
        metadata['original_path'] = 'registry://authorized-context'
        yield str(output_path), metadata

    def collect_ai_activity(
        self,
        pattern: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        expanded_pattern = os.path.expandvars(pattern)
        if re.match(r'^[A-Za-z]:[\\/]', expanded_pattern):
            volume = getattr(self, 'volume', expanded_pattern[0])
            expanded_pattern = f"{volume}:{expanded_pattern[2:]}"

        seen_paths = set()
        for match in glob.glob(expanded_pattern, recursive=True):
            candidates = []
            if os.path.isdir(match):
                for root, _dirs, files in os.walk(match):
                    for filename in files:
                        candidates.append(os.path.join(root, filename))
            else:
                candidates.append(match)

            for src_path in candidates:
                if not os.path.isfile(src_path):
                    continue
                normalized = os.path.normcase(os.path.abspath(src_path))
                if normalized in seen_paths:
                    continue
                seen_paths.add(normalized)

                try:
                    rel_output = self._safe_ai_output_path(src_path)
                    dst_path = output_dir / rel_output
                    validate_safe_path(output_dir, dst_path)
                    dst_path.parent.mkdir(parents=True, exist_ok=True)

                    if dst_path.exists():
                        base = dst_path.stem
                        suffix = dst_path.suffix
                        counter = 1
                        while dst_path.exists():
                            dst_path = dst_path.parent / f"{base}_{counter}{suffix}"
                            counter += 1

                    shutil.copy2(src_path, dst_path)
                    metadata = self._get_metadata(src_path, dst_path, artifact_type)
                    metadata['collection_method'] = 'ai_activity_file_api'
                    metadata['source_pattern'] = pattern
                    yield str(dst_path), metadata
                except (PermissionError, OSError, ValueError) as e:
                    logger.debug(f"[AI Activity] Cannot access {src_path}: {e}")

    def _safe_ai_output_path(self, src_path: str) -> Path:
        normalized = str(src_path).replace('\\', '/')
        normalized = re.sub(r'^[A-Za-z]:', lambda m: m.group(0)[0], normalized)
        parts = [
            sanitize_path_component(part)
            for part in normalized.strip('/').split('/')
            if part and part not in ('.', '..')
        ]
        if not parts:
            parts = ['unnamed_ai_artifact']
        return Path(*parts)

    def collect_glob(
        self,
        pattern: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files matching a glob pattern (legacy)"""
        for src_path in glob.glob(pattern, recursive=True):
            try:
                dst_path = output_dir / Path(src_path).name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(src_path, dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                logger.debug(f"[LEGACY] Cannot access {src_path}: {e}")
                continue

    def collect_files(
        self,
        file_path: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect a specific file (legacy)"""
        src_path = Path(file_path)
        if src_path.exists():
            try:
                dst_path = output_dir / src_path.name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(str(src_path), dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                logger.debug(f"[LEGACY] Cannot access {file_path}: {e}")

    def collect_locked_files(
        self,
        file_path: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect files that may be locked by the OS (legacy).

        Uses Volume Shadow Copy or raw file read.
        """
        src_path = Path(file_path)
        if not src_path.exists():
            return

        dst_path = output_dir / src_path.name

        # Try direct copy first
        try:
            shutil.copy2(src_path, dst_path)
            yield str(dst_path), self._get_metadata(str(src_path), dst_path, artifact_type)
            return
        except (PermissionError, OSError):
            pass

        # Try using Volume Shadow Copy
        try:
            vss_path = self._get_vss_path(str(src_path))
            if vss_path and Path(vss_path).exists():
                shutil.copy2(vss_path, dst_path)
                metadata = self._get_metadata(str(src_path), dst_path, artifact_type)
                metadata['collection_method'] = 'vss'
                yield str(dst_path), metadata
                return
        except Exception:
            pass

        logger.debug(f"[LEGACY] Cannot collect locked file {file_path}")
        logger.debug("[INFO] Consider using MFT collection for locked files")

    def collect_user_files(
        self,
        path_pattern: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files from user profile with environment variable expansion (legacy)"""
        expanded_path = os.path.expandvars(path_pattern)
        if glob.has_magic(expanded_path):
            yield from self.collect_user_glob(
                path_pattern, output_dir, artifact_type
            )
            return
        src_path = Path(expanded_path)

        if src_path.exists():
            try:
                dst_path = output_dir / src_path.name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(expanded_path, dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                logger.debug(f"[LEGACY] Cannot access {expanded_path}: {e}")

    def collect_user_glob(
        self,
        pattern: str,
        output_dir: Path,
        artifact_type: str,
        exclude_extensions: Optional[List[str]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files matching a glob pattern with environment variable expansion (legacy)

        Args:
            pattern: Glob pattern with environment variables
            output_dir: Output directory path
            artifact_type: Artifact type identifier
            exclude_extensions: List of file extensions to exclude (e.g., ['.png', '.jpg'])
        """
        expanded_pattern = os.path.expandvars(pattern)

        # Normalize exclude extensions to lowercase with leading dot
        if exclude_extensions:
            exclude_set = {ext.lower() if ext.startswith('.') else f'.{ext.lower()}'
                          for ext in exclude_extensions}
        else:
            exclude_set = set()

        for src_path in glob.glob(expanded_pattern, recursive=True):
            # Skip directories
            if os.path.isdir(src_path):
                continue

            # Check extension exclusion
            if exclude_set:
                _, ext = os.path.splitext(src_path)
                if ext.lower() in exclude_set:
                    continue

            try:
                dst_path = output_dir / Path(src_path).name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(src_path, dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                logger.debug(f"[LEGACY] Cannot access {src_path}: {e}")
                continue

    def collect_messenger_with_memory(
        self,
        pattern: str,
        output_dir: Path,
        artifact_type: str,
        exclude_extensions: Optional[List[str]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect messenger app data with process memory dump.
        Preserves directory structure for parser compatibility.

        This collector:
        1. Collects user data files (preserving directory structure)
        2. Creates a process memory dump (if process is running)

        Args:
            pattern: Glob pattern with environment variables
            output_dir: Output directory path
            artifact_type: Artifact type identifier
            exclude_extensions: List of file extensions to exclude
        """
        # 1. Collect user data files (preserving directory structure)
        expanded_pattern = os.path.expandvars(pattern)

        # Normalize exclude extensions
        if exclude_extensions:
            exclude_set = {ext.lower() if ext.startswith('.') else f'.{ext.lower()}'
                          for ext in exclude_extensions}
        else:
            exclude_set = set()

        # Find base directory from the configured pattern.
        # We want to preserve structure from 'users' directory onwards
        base_marker = None
        for marker in ['users', 'Users', 'AppData']:
            if marker in expanded_pattern:
                base_idx = expanded_pattern.find(marker)
                base_marker = expanded_pattern[:base_idx + len(marker)]
                break

        for src_path in glob.glob(expanded_pattern, recursive=True):
            # Skip directories
            if os.path.isdir(src_path):
                continue

            # Check extension exclusion
            if exclude_set:
                _, ext = os.path.splitext(src_path)
                if ext.lower() in exclude_set:
                    continue

            try:
                # Preserve directory structure from base_marker
                if base_marker and base_marker in src_path:
                    rel_path = src_path[len(base_marker):].lstrip(os.sep).lstrip('/')
                    dst_path = output_dir / rel_path
                else:
                    dst_path = output_dir / Path(src_path).name

                # Create parent directories
                dst_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(src_path, dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                logger.debug(f"[LEGACY] Cannot access {src_path}: {e}")
                continue

        # 2. Collect process memory dump (only once per artifact type)
        artifact_info = ARTIFACT_TYPES.get(artifact_type, {})
        process_names = _messenger_process_names(artifact_info)
        if process_names:
            yield from self._dump_process_memory(
                artifact_type, process_names, output_dir
            )

        # 3. Collect hardware metadata for downstream processing.
        if artifact_type == 'server_managed_windows_app':
            hw_result = self._save_hardware_metadata(output_dir, artifact_type)
            if hw_result:
                yield hw_result

    def _collect_hardware_metadata(self) -> Optional[Dict[str, str]]:
        """Collect system hardware identifiers for forensic analysis.

        Gathers hardware fingerprints used for application data processing.
        No transformations are performed
        on the collected values - raw identifiers only.

        Returns:
            Dict with sys_uuid, hdd_model, hdd_serial or None if unavailable
        """
        meta = {}

        # Method 1: WMI (preferred - accurate hardware identifiers)
        try:
            import wmi
            c = wmi.WMI()
            # System UUID from SMBIOS
            for cs in c.Win32_ComputerSystemProduct():
                if cs.UUID:
                    meta['sys_uuid'] = cs.UUID
                    break
            # Primary disk info
            for disk in c.Win32_DiskDrive():
                if disk.Index == 0:
                    meta['hdd_model'] = disk.Model or ''
                    meta['hdd_serial'] = (disk.SerialNumber or '').strip()
                    break
        except Exception:
            pass

        # Method 2: Registry fallback for MachineGuid
        if 'sys_uuid' not in meta:
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r'SOFTWARE\Microsoft\Cryptography'
                )
                val, _ = winreg.QueryValueEx(key, 'MachineGuid')
                meta['sys_uuid'] = val
                winreg.CloseKey(key)
            except Exception:
                pass

        # Method 3: Registry fallback for HDD info
        if 'hdd_model' not in meta or 'hdd_serial' not in meta:
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Services\disk\Enum'
                )
                count, _ = winreg.QueryValueEx(key, 'Count')
                if count > 0:
                    disk_id, _ = winreg.QueryValueEx(key, '0')
                    # disk_id format: IDE\DiskVENDOR_MODEL____SERIAL\...
                    if 'hdd_model' not in meta:
                        meta['hdd_model'] = disk_id.split('\\')[1] if '\\' in disk_id else ''
                    if 'hdd_serial' not in meta:
                        parts = disk_id.split('\\')
                        meta['hdd_serial'] = parts[2] if len(parts) > 2 else ''
                winreg.CloseKey(key)
            except Exception:
                pass

        if meta.get('sys_uuid'):
            return meta
        return None

    def _save_hardware_metadata(
        self,
        output_dir: Path,
        artifact_type: str
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Collect and save hardware metadata as JSON alongside artifact files.

        Args:
            output_dir: Directory to save _hardware_info.json
            artifact_type: Artifact type identifier

        Returns:
            (file_path, metadata) tuple or None if collection failed
        """
        import json as _json

        hw_meta = self._collect_hardware_metadata()
        if not hw_meta:
            logger.debug("[HW_META] Hardware metadata collection failed")
            return None

        hw_path = output_dir / '_hardware_info.json'
        try:
            with open(hw_path, 'w') as f:
                _json.dump(hw_meta, f, indent=2)
            logger.debug(f"[HW_META] Saved hardware metadata: {list(hw_meta.keys())}")
            return str(hw_path), {
                'artifact_type': artifact_type,
                'original_path': str(hw_path),
                'filename': '_hardware_info.json',
                'type': artifact_type,
                'name': '_hardware_info.json',
                'path': str(hw_path),
                'size': hw_path.stat().st_size,
                'is_metadata': True,
                'collection_method': 'hardware_metadata',
            }
        except Exception as e:
            logger.debug(f"[HW_META] Failed to save hardware metadata: {e}")
            return None

    def collect_recycle_bin(
        self,
        _: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect Recycle Bin metadata files ($I files).

        Collects metadata ($I) and original file contents ($R) of deleted files from Recycle Bin.
        $I file: Metadata including original path, deletion time, etc.
        $R file: Actual deleted file contents

        Note: Requires admin privileges for full access.
        """
        collected_count = 0

        # Try case variations (Windows is case-insensitive)
        variants = ['$Recycle.Bin', '$RECYCLE.BIN', '$recycle.bin', 'RECYCLER']
        recycle_bin_path = None

        for variant in variants:
            test_path = Path(f"{self.volume}:\\{variant}")
            logger.debug(f"[RecycleBin] Checking path: {test_path}")
            try:
                if test_path.exists():
                    recycle_bin_path = test_path
                    logger.debug(f"[RecycleBin] Found at: {recycle_bin_path}")
                    break
            except (PermissionError, OSError) as e:
                logger.debug(f"[RecycleBin] Cannot check {test_path}: {e}")
                continue

        if recycle_bin_path is None:
            logger.debug(f"[RecycleBin] $Recycle.Bin not found on {self.volume}:")
            return

        try:
            # Traverse each user SID folder
            sid_folders = list(recycle_bin_path.iterdir())
            logger.debug(f"[RecycleBin] Found {len(sid_folders)} folders in Recycle Bin")

            for sid_folder in sid_folders:
                if sid_folder.is_dir() and sid_folder.name.startswith('S-1-'):
                    logger.debug(f"[RecycleBin] Processing SID folder: {sid_folder.name}")

                    # Create per-SID output directory
                    sid_output_dir = output_dir / sid_folder.name
                    sid_output_dir.mkdir(exist_ok=True)

                    try:
                        entries = list(sid_folder.iterdir())
                        logger.debug(f"[RecycleBin] Found {len(entries)} entries in {sid_folder.name}")

                        for entry in entries:
                            # Collect $I file (metadata)
                            if entry.name.startswith('$I') and entry.is_file():
                                try:
                                    dst_path = sid_output_dir / entry.name
                                    shutil.copy2(entry, dst_path)
                                    metadata = self._get_metadata(str(entry), dst_path, artifact_type)
                                    metadata['user_sid'] = sid_folder.name
                                    metadata['file_type'] = 'metadata'
                                    collected_count += 1
                                    logger.debug(f"[RecycleBin] Collected: {entry.name}")
                                    yield str(dst_path), metadata

                                    # Also try to collect corresponding $R file
                                    # Skip $R content files larger than 50MB (collect metadata-only for large deleted files)
                                    MAX_RECYCLE_CONTENT_SIZE = 50 * 1024 * 1024  # 50MB
                                    r_file = sid_folder / entry.name.replace('$I', '$R')
                                    if r_file.exists():
                                        try:
                                            r_size = r_file.stat().st_size
                                            if r_size > MAX_RECYCLE_CONTENT_SIZE:
                                                # Record metadata without copying the actual file
                                                r_metadata = {
                                                    'artifact_type': artifact_type,
                                                    'original_path': str(r_file),
                                                    'filename': r_file.name,
                                                    'size': r_size,
                                                    'skipped': True,
                                                    'skip_reason': f'File too large ({r_size} bytes, limit {MAX_RECYCLE_CONTENT_SIZE})',
                                                    'collection_method': 'direct',
                                                    'user_sid': sid_folder.name,
                                                    'file_type': 'content_metadata_only',
                                                    'collected_at': datetime.utcnow().isoformat(),
                                                }
                                                collected_count += 1
                                                logger.debug(f"[RecycleBin] Skipped large $R file: {r_file.name} ({r_size} bytes)")
                                                yield str(r_file), r_metadata
                                                continue
                                            r_dst_path = sid_output_dir / r_file.name
                                            shutil.copy2(r_file, r_dst_path)
                                            r_metadata = self._get_metadata(str(r_file), r_dst_path, artifact_type)
                                            r_metadata['user_sid'] = sid_folder.name
                                            r_metadata['file_type'] = 'content'
                                            collected_count += 1
                                            logger.debug(f"[RecycleBin] Collected: {r_file.name}")
                                            yield str(r_dst_path), r_metadata
                                        except (PermissionError, OSError) as e:
                                            logger.debug(f"[RecycleBin] Cannot access $R file {r_file}: {e}")

                                except (PermissionError, OSError) as e:
                                    logger.debug(f"[RecycleBin] Permission denied: {entry} - {e}")
                                    continue

                    except PermissionError as e:
                        logger.debug(f"[RecycleBin] Cannot access SID folder: {sid_folder} - {e}")
                        continue
                    except OSError as e:
                        logger.debug(f"[RecycleBin] OS error on SID folder: {sid_folder} - {e}")
                        continue

            logger.debug(f"[RecycleBin] Collection complete: {collected_count} files")

        except PermissionError as e:
            logger.debug(f"[RecycleBin] Cannot access Recycle Bin: {e} - requires admin privileges")
        except OSError as e:
            logger.debug(f"[RecycleBin] OS error accessing Recycle Bin: {e}")

    def collect_ntuser(
        self,
        _: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect NTUSER.DAT files for all users (legacy)"""
        users_dir = Path(r'C:\Users')

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue

            ntuser_path = user_dir / 'NTUSER.DAT'
            if ntuser_path.exists():
                dst_path = output_dir / f"NTUSER.DAT_{user_dir.name}"

                # NTUSER.DAT is usually locked
                for result in self.collect_locked_files(
                    str(ntuser_path), output_dir, artifact_type
                ):
                    # Rename to include username
                    if Path(result[0]).exists():
                        final_path = output_dir / f"NTUSER.DAT_{user_dir.name}"
                        Path(result[0]).rename(final_path)
                        result[1]['username'] = user_dir.name
                        yield str(final_path), result[1]

    def collect_usrclass(
        self,
        _: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect UsrClass.dat files for all users.

        UsrClass.dat contains ShellBags information for folder browsing history.
        Located at: %LOCALAPPDATA%\\Microsoft\\Windows\\UsrClass.dat
        """
        users_dir = Path(r'C:\Users')

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue

            # Skip system directories
            if user_dir.name.lower() in ('public', 'default', 'default user', 'all users'):
                continue

            usrclass_path = user_dir / 'AppData' / 'Local' / 'Microsoft' / 'Windows' / 'UsrClass.dat'
            if usrclass_path.exists():
                # UsrClass.dat is usually locked, use locked file collection
                for result in self.collect_locked_files(
                    str(usrclass_path), output_dir, artifact_type
                ):
                    # Rename to include username
                    if Path(result[0]).exists():
                        final_path = output_dir / f"UsrClass.dat_{user_dir.name}"
                        try:
                            Path(result[0]).rename(final_path)
                            result[1]['username'] = user_dir.name
                            result[1]['artifact_type'] = 'shellbags'
                            yield str(final_path), result[1]
                        except Exception as e:
                            logger.debug(f"[WARNING] Failed to rename UsrClass.dat for {user_dir.name}: {e}")
                            yield result[0], result[1]

    def collect_all_browsers(
        self,
        _: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect browser data from Chrome, Edge, and Firefox (legacy).

        Collects browser profile databases and related metadata
        """
        browser_info = ARTIFACT_TYPES.get('browser', {})
        browsers = browser_info.get('browsers', {})

        for browser_id, browser_config in browsers.items():
            browser_name = browser_config.get('name', browser_id)
            browser_dir = output_dir / browser_id
            browser_dir.mkdir(exist_ok=True)

            # Handle Firefox profile-based structure
            if browser_config.get('profile_based', False):
                yield from self._collect_firefox_profiles(
                    browser_config, browser_dir, artifact_type, browser_name
                )
            else:
                # Chrome/Edge - standard paths
                for path_pattern in browser_config.get('paths', []):
                    expanded_path = os.path.expandvars(path_pattern)
                    src_path = Path(expanded_path)

                    if src_path.exists():
                        try:
                            dst_path = browser_dir / src_path.name
                            shutil.copy2(src_path, dst_path)
                            metadata = self._get_metadata(
                                str(src_path), dst_path, artifact_type
                            )
                            metadata['browser'] = browser_name
                            metadata['browser_id'] = browser_id
                            yield str(dst_path), metadata
                        except (PermissionError, OSError) as e:
                            logger.debug(f"[BROWSER] Cannot access {expanded_path}: {e}")

    def _collect_firefox_profiles(
        self,
        browser_config: Dict[str, Any],
        output_dir: Path,
        artifact_type: str,
        browser_name: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect Firefox data from all profiles"""
        firefox_profiles_dir = Path(os.path.expandvars(
            r'%APPDATA%\Mozilla\Firefox\Profiles'
        ))

        if not firefox_profiles_dir.exists():
            return

        for profile_dir in firefox_profiles_dir.iterdir():
            if not profile_dir.is_dir():
                continue

            profile_name = profile_dir.name
            profile_output = output_dir / profile_name
            profile_output.mkdir(exist_ok=True)

            for filename in browser_config.get('files', []):
                src_path = profile_dir / filename
                if src_path.exists():
                    try:
                        dst_path = profile_output / filename
                        shutil.copy2(src_path, dst_path)
                        metadata = self._get_metadata(
                            str(src_path), dst_path, artifact_type
                        )
                        metadata['browser'] = browser_name
                        metadata['browser_id'] = 'firefox'
                        metadata['profile'] = profile_name
                        yield str(dst_path), metadata
                    except (PermissionError, OSError) as e:
                        logger.debug(f"[FIREFOX] Cannot access {src_path}: {e}")

    def _sanitize_filename(self, filename: str) -> str:
        """Remove invalid characters from filename"""
        sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
        sanitized = re.sub(r'_+', '_', sanitized)
        sanitized = sanitized.strip(' _.')
        if not sanitized:
            sanitized = 'unnamed_file'
        return sanitized

    def _get_metadata(
        self,
        src_path: str,
        dst_path: Path,
        artifact_type: str
    ) -> Dict[str, Any]:
        """Generate metadata for a collected file (legacy)"""
        return _build_collected_file_metadata(src_path, Path(dst_path), artifact_type)

    # =========================================================================
    # Android Forensics Collection Methods
    # =========================================================================

    def _collect_android(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect Android forensics artifacts via USB (adb-shell).

        Args:
            artifact_type: Type of Android artifact (e.g., 'mobile_android_profile_target')
            artifact_info: Artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            **kwargs: device_serial for specific device
        """
        from collectors.android_collector import AndroidCollector, ANDROID_ARTIFACT_TYPES

        device_serial = kwargs.get('device_serial')

        # Check if artifact_type is supported by AndroidCollector
        if artifact_type not in ANDROID_ARTIFACT_TYPES:
            logger.debug(f"[ANDROID] Artifact type not in ANDROID_ARTIFACT_TYPES: {artifact_type}")
            return

        try:
            # Use context manager for automatic cleanup
            # AndroidCollector(output_dir, device_serial) - correct order
            with AndroidCollector(str(artifact_dir), device_serial) as collector:
                # Connect to device
                collector.connect(device_serial)
                logger.debug(f"[ANDROID] Connected to device: {collector.device_serial}")

                # Use generic collect() method - handles all artifact types
                for result in collector.collect(artifact_type, progress_callback):
                    file_path, file_metadata = result

                    # Skip error results (empty path)
                    if not file_path:
                        if file_metadata.get('status') == 'error':
                            logger.debug(f"[ANDROID] Collection error: {file_metadata.get('error', 'Unknown')}")
                        continue

                    # Add standard fields if not already present
                    if 'artifact_type' not in file_metadata:
                        file_metadata['artifact_type'] = artifact_type
                    if 'device_serial' not in file_metadata:
                        file_metadata['device_serial'] = device_serial or collector.device_serial
                    if 'collected_at' not in file_metadata:
                        file_metadata['collected_at'] = datetime.utcnow().isoformat()

                    yield file_path, file_metadata

        except RuntimeError as e:
            # USB/device connection errors
            logger.debug(f"[ANDROID] Connection failed: {e}")
        except ValueError as e:
            # Invalid artifact type or device not found
            logger.debug(f"[ANDROID] Invalid configuration: {e}")
        except Exception as e:
            logger.debug(f"[ANDROID] Collection failed for {artifact_type}: {e}")

    # =========================================================================
    # iOS Forensics Collection Methods
    # =========================================================================

    def _collect_ios(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect iOS forensics artifacts from iTunes/Finder backup.

        Args:
            artifact_type: Type of iOS artifact (e.g., 'mobile_ios_profile_target')
            artifact_info: Artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            **kwargs: backup_path for specific backup
        """
        from collectors.ios_collector import iOSCollector, find_ios_backups, IOS_ARTIFACT_TYPES

        backup_path = kwargs.get('backup_path')

        # Check if artifact_type is supported by iOSCollector
        if artifact_type not in IOS_ARTIFACT_TYPES:
            logger.debug(f"[iOS] Artifact type not in IOS_ARTIFACT_TYPES: {artifact_type}")
            return

        # If no backup path specified, try to find one
        if not backup_path:
            backups = find_ios_backups()
            if not backups:
                logger.debug("[iOS] No iOS backups found on this system")
                return
            # Use the most recent backup
            backup_path = str(backups[0].path)
            logger.debug(f"[iOS] Using backup: {backups[0].device_name} ({backups[0].ios_version})")

        try:
            # iOSCollector(output_dir, backup_path) - correct order
            collector = iOSCollector(str(artifact_dir), backup_path)

            # Select backup first
            if not collector.select_backup(backup_path):
                logger.debug(f"[iOS] Failed to select backup: {backup_path}")
                return

            # Check if backup is encrypted without decryptor
            if collector.is_encrypted and not getattr(collector, '_encrypted_backup', None):
                logger.debug("[iOS] Backup is encrypted - decryptor not provided, skipping")
                return

            # Use generic collect() method - handles all artifact types
            for result in collector.collect(artifact_type, progress_callback):
                file_path, file_metadata = result

                # Skip error results (empty path)
                if not file_path:
                    if file_metadata.get('status') == 'error':
                        logger.debug(f"[iOS] Collection error: {file_metadata.get('error', 'Unknown')}")
                    continue

                # Add standard fields if not already present
                if 'artifact_type' not in file_metadata:
                    file_metadata['artifact_type'] = artifact_type
                if 'collection_method' not in file_metadata:
                    file_metadata['collection_method'] = 'ios_backup'
                if 'backup_path' not in file_metadata:
                    file_metadata['backup_path'] = backup_path
                if 'collected_at' not in file_metadata:
                    file_metadata['collected_at'] = datetime.utcnow().isoformat()

                yield file_path, file_metadata

        except RuntimeError as e:
            # Backup selection errors
            logger.debug(f"[iOS] Backup error: {e}")
        except ValueError as e:
            # Invalid artifact type
            logger.debug(f"[iOS] Invalid configuration: {e}")
        except Exception as e:
            logger.debug(f"[iOS] Collection failed for {artifact_type}: {e}")

    # =========================================================================
    # Linux Forensics Collection Methods
    # =========================================================================

    def _collect_linux(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect Linux forensics artifacts.

        Args:
            artifact_type: Type of Linux artifact (e.g., 'linux_auth_log')
            artifact_info: Artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            **kwargs: target_root for mounted filesystem (default: '/')
        """
        if not LINUX_AVAILABLE or LinuxCollector is None:
            logger.debug(f"[LINUX] LinuxCollector not available")
            return

        target_root = kwargs.get('target_root', '/')

        try:
            collector = LinuxCollector(str(artifact_dir), target_root=target_root)

            for relative_path, content, metadata in collector.collect(artifact_type):
                # Write content to output directory
                output_path = artifact_dir / relative_path.replace('/', os.sep)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(content)

                # Build result metadata
                file_metadata = {
                    'artifact_type': artifact_type,
                    'collection_method': 'linux_collector',
                    'target_root': target_root,
                    'collected_at': datetime.utcnow().isoformat(),
                    'file_size': len(content),
                    **metadata
                }

                yield str(output_path), file_metadata

                if progress_callback:
                    progress_callback(f"Collected: {relative_path}")

        except Exception as e:
            logger.debug(f"[LINUX] Collection failed for {artifact_type}: {e}")

    # =========================================================================
    # macOS Forensics Collection Methods
    # =========================================================================

    def _collect_macos(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect macOS forensics artifacts.

        Args:
            artifact_type: Type of macOS artifact (e.g., 'macos_launch_agent')
            artifact_info: Artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            **kwargs: target_root for mounted filesystem (default: '/')
        """
        if not MACOS_AVAILABLE or macOSCollector is None:
            logger.debug(f"[MACOS] macOSCollector not available")
            return

        target_root = kwargs.get('target_root', '/')

        try:
            collector = macOSCollector(str(artifact_dir), target_root=target_root)

            for relative_path, content, metadata in collector.collect(artifact_type):
                # Write content to output directory
                output_path = artifact_dir / relative_path.replace('/', os.sep)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(content)

                # Build result metadata
                file_metadata = {
                    'artifact_type': artifact_type,
                    'collection_method': 'macos_collector',
                    'target_root': target_root,
                    'collected_at': datetime.utcnow().isoformat(),
                    'file_size': len(content),
                    **metadata
                }

                yield str(output_path), file_metadata

                if progress_callback:
                    progress_callback(f"Collected: {relative_path}")

        except Exception as e:
            logger.debug(f"[MACOS] Collection failed for {artifact_type}: {e}")

    def _get_vss_path(self, file_path: str) -> Optional[str]:
        """Get path to file in latest Volume Shadow Copy

        [SECURITY] Validates VSS path to prevent path traversal attacks.
        """
        try:
            import subprocess

            result = subprocess.run(
                ['vssadmin', 'list', 'shadows'],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )

            # Parse VSS output to find latest shadow copy
            for line in result.stdout.split('\n'):
                if 'Shadow Copy Volume' in line:
                    vss_volume = line.split(':')[-1].strip()

                    # [SECURITY] Validate VSS volume format
                    # Expected: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{N}\
                    if not re.match(r'^\\\\[\?\.]\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+\\?$', vss_volume):
                        logger.warning(f"[SECURITY] Invalid VSS volume format: {vss_volume}")
                        continue

                    # [SECURITY] Validate file_path format (must be absolute Windows path)
                    if len(file_path) < 3 or file_path[1] != ':':
                        logger.warning(f"[SECURITY] Invalid file path format: {file_path}")
                        return None

                    drive = file_path[0].upper()
                    relative_path = file_path[2:]  # Remove 'C:'

                    # [SECURITY] Check for path traversal attempts
                    if '..' in relative_path or relative_path.startswith('/'):
                        logger.warning(f"[SECURITY] Path traversal detected: {relative_path}")
                        return None

                    # Construct and validate final path
                    vss_path = f"{vss_volume}{relative_path}"

                    # [SECURITY] Verify path stays within VSS volume
                    try:
                        resolved = Path(vss_path).resolve()
                        if not str(resolved).startswith(vss_volume.rstrip('\\')):
                            logger.warning(f"[SECURITY] Path escape detected: {resolved}")
                            return None
                    except (OSError, ValueError):
                        # Path resolution failed - reject for safety
                        return None

                    return vss_path

        except Exception as e:
            logger.debug(f"VSS path resolution failed: {e}")

        return None

def get_collection_mode() -> str:
    """
    Get current collection mode.

    Returns:
        'mft' if MFT collection available, 'legacy' otherwise
    """
    if MFT_AVAILABLE:
        try:
            if check_admin_privileges():
                return 'mft'
            else:
                return 'legacy (no admin)'
        except Exception:
            return 'legacy'
    return 'legacy (no MFT backend)'

if __name__ == "__main__":
    import sys

    logger.debug(f"Collection mode: {get_collection_mode()}")
    logger.debug(f"MFT available: {MFT_AVAILABLE}")

    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            collector = ArtifactCollector(temp_dir)
            logger.debug(f"\nUsing {collector.collection_mode} collection method")

            logger.debug("\nAvailable artifacts:")
            for artifact in collector.get_available_artifacts():
                status = "OK" if artifact['available'] else "N/A"
                admin = " [ADMIN]" if artifact['requires_admin'] else ""
                logger.debug(f"  [{status}] {artifact['type']}: {artifact['name']}{admin}")

            collector.close()
