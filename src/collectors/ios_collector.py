"""
iOS Forensics Collector Module

iOS device forensic collection module.
- iTunes/Finder backup parsing
- pymobiledevice3 direct device connection (Pure Python)

Collectible Artifacts:
[Backup-based]
- mobile_ios_sms: iMessage/SMS messages
- mobile_ios_call: Call history
- mobile_ios_contacts: Contacts
- mobile_ios_safari: Safari browser data
- mobile_ios_location: Location history
- mobile_ios_backup: Backup metadata

Mobile Application Artifacts:
- mobile_ios_*: server-authorized mobile artifacts supplied by the collection profile

[Direct Device Connection - pymobiledevice3]
- mobile_ios_device_info: Device information
- mobile_ios_syslog: System log
- mobile_ios_crash_logs: Crash reports
- mobile_ios_installed_apps: Installed app list
- mobile_ios_device_backup: Create new backup
- mobile_ios_unified_logs: Apple Unified Logs (sysdiagnose)

Requirements:
    - biplist>=1.0.3 (for binary plist parsing)
    - plistlib (stdlib)
    - pymobiledevice3 (optional, for device connection)

License:
    - This module is open source
    - pymobiledevice3 is GPL-3.0 licensed
    - This module collects source files only
"""
import os
import re
import sqlite3
import hashlib
import shutil
import plistlib
import json
import threading
import logging
from pathlib import Path
from datetime import datetime
from typing import Generator, Tuple, Dict, Any, Optional, List, Callable
from dataclasses import dataclass

# Check for biplist (for binary plist support)
try:
    import biplist
    BIPLIST_AVAILABLE = True
except ImportError:
    BIPLIST_AVAILABLE = False


# =============================================================================
# pymobiledevice3 Availability Check
# =============================================================================

def _debug_print(msg: str) -> None:
    """Debug print (only in verbose mode)"""
    if os.environ.get('IOS_COLLECTOR_DEBUG'):
        print(msg)


logger = logging.getLogger(__name__)
IOS_ENCRYPTION_SKIP_SENTINEL = "__UNJAENA_IOS_SKIP_ENCRYPTION__"


def _validate_ios_file_hash(file_hash: str) -> bool:
    """
    [SECURITY] Validate iOS backup file hash format.

    iOS backup files are stored using SHA1 hash of domain-path.
    Valid format: 40 hexadecimal characters.
    """
    if not file_hash:
        return False
    # Must be exactly 40 hex characters (SHA1)
    if not re.match(r'^[a-fA-F0-9]{40}$', file_hash):
        logger.warning(f"[SECURITY] Invalid iOS file hash format: {file_hash[:50]}")
        return False
    return True


def _validate_path_within_backup(path: Path, backup_base: Path) -> bool:
    """
    [SECURITY] Validate that resolved path stays within backup directory.

    Prevents symlink attacks and path traversal.
    """
    try:
        resolved_path = path.resolve()
        resolved_base = backup_base.resolve()
        resolved_path.relative_to(resolved_base)
        return True
    except (ValueError, OSError):
        logger.warning(f"[SECURITY] Path escape detected: {path}")
        return False


# Windows-invalid filename characters (control chars 0x00-0x1F + reserved chars)
_INVALID_FILENAME_RE = re.compile(r'[\x00-\x1f<>:"/\\|?*]')


def _sanitize_filename(filename: str) -> str:
    """
    Replace characters invalid on Windows filesystems with underscores.
    Handles control characters (tab, null, etc.) and reserved chars (<>:"/\\|?*).
    """
    sanitized = _INVALID_FILENAME_RE.sub('_', filename)
    if sanitized != filename:
        logger.debug(f"Sanitized filename: '{filename}' -> '{sanitized}'")
    return sanitized




# Check for pymobiledevice3
PYMOBILEDEVICE3_AVAILABLE = False
try:
    from pymobiledevice3.usbmux import list_devices
    from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
    from pymobiledevice3.services.diagnostics import DiagnosticsService
    from pymobiledevice3.services.syslog import SyslogService
    from pymobiledevice3.services.crash_reports import CrashReportsManager
    from pymobiledevice3.services.installation_proxy import InstallationProxyService
    from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
    PYMOBILEDEVICE3_AVAILABLE = True
    _debug_print("[iOS] pymobiledevice3 available")
except ImportError as e:
    _debug_print(f"[iOS] pymobiledevice3 not available: {e}")
except Exception as e:
    _debug_print(f"[iOS] pymobiledevice3 import error: {e}")


@dataclass
class BackupInfo:
    """iOS backup information"""
    path: Path
    device_name: str
    device_id: str
    product_type: str
    ios_version: str
    backup_date: datetime
    encrypted: bool
    size_mb: float


# =========================================================================
# Pattern-based collection filtering
# Only upload files with forensically relevant extensions
# =========================================================================

# Database/data file extensions (parsers can process these)
_FORENSIC_EXTENSIONS = {
    '.db', '.sqlite', '.sqlite3', '.sqlitedb', '.storedata',
    '.mdb', '.edb', '.ldb',
    '.dat', '.data',
    '.plist', '.json', '.xml',
    '.binarycookies',
    '.log', '.txt', '.csv',
}

# Media extensions (for attachment-type artifacts only)
_MEDIA_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.heic', '.heif', '.webp', '.bmp', '.tiff',
    '.mp4', '.mov', '.m4v', '.avi', '.3gp',
    '.mp3', '.m4a', '.aac', '.wav', '.caf', '.amr', '.opus',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.7z',
    '.vcf',
}

# Attachment artifacts - allow media files in addition to DB files
_ATTACHMENT_ARTIFACTS = set()

# Artifact types to skip entirely (reserved for future use)
_SKIP_ARTIFACTS = set()


# iOS artifact type definitions
IOS_ARTIFACT_TYPES: Dict[str, Dict[str, Any]] = {}

def get_backup_locations() -> List[Path]:
    """Get default iOS backup locations based on OS"""
    locations = []

    if os.name == 'nt':  # Windows
        # iTunes backup location
        appdata = os.environ.get('APPDATA', '')
        if appdata:
            locations.append(
                Path(appdata) / 'Apple Computer' / 'MobileSync' / 'Backup'
            )

        # Apple Devices app (Windows 11)
        localappdata = os.environ.get('LOCALAPPDATA', '')
        if localappdata:
            locations.append(
                Path(localappdata) / 'Packages' /
                'AppleInc.AppleDevices_nzyj5cx40ttqa' /
                'LocalCache' / 'Roaming' / 'Apple Computer' /
                'MobileSync' / 'Backup'
            )

    else:  # macOS / Linux
        home = Path.home()
        locations.append(
            home / 'Library' / 'Application Support' /
            'MobileSync' / 'Backup'
        )

    return [loc for loc in locations if loc.exists()]


def find_ios_backups() -> List[BackupInfo]:
    """
    Find all iOS backups on the system.

    Returns:
        List of BackupInfo objects for each backup found
    """
    backups = []

    for backup_dir in get_backup_locations():
        if not backup_dir.exists():
            continue

        for item in backup_dir.iterdir():
            if not item.is_dir():
                continue

            # Check for Info.plist (indicates valid backup)
            info_plist = item / 'Info.plist'
            if not info_plist.exists():
                continue

            try:
                backup_info = parse_backup_info(item)
                if backup_info:
                    backups.append(backup_info)
            except Exception as e:
                _debug_print(f"[iOS] Error parsing backup {item.name}: {e}")

    return sorted(backups, key=lambda b: b.backup_date, reverse=True)


def parse_backup_info(backup_path: Path) -> Optional[BackupInfo]:
    """Parse backup Info.plist and Manifest.plist to extract device information"""
    info_plist = backup_path / 'Info.plist'

    if not info_plist.exists():
        return None

    try:
        with open(info_plist, 'rb') as f:
            info = plistlib.load(f)
    except Exception:
        # Try biplist for binary plists
        if BIPLIST_AVAILABLE:
            try:
                info = biplist.readPlist(str(info_plist))
            except Exception:
                return None
        else:
            return None

    # FIX: IsEncrypted is in Manifest.plist, NOT Info.plist.
    # Info.plist only has device metadata; Manifest.plist has encryption state.
    encrypted = False
    manifest_plist = backup_path / 'Manifest.plist'
    if manifest_plist.exists():
        try:
            with open(manifest_plist, 'rb') as f:
                manifest = plistlib.load(f)
            encrypted = manifest.get('IsEncrypted', False)
        except Exception:
            if BIPLIST_AVAILABLE:
                try:
                    manifest = biplist.readPlist(str(manifest_plist))
                    encrypted = manifest.get('IsEncrypted', False)
                except Exception:
                    pass

    # Calculate backup size
    total_size = sum(
        f.stat().st_size for f in backup_path.rglob('*') if f.is_file()
    )

    return BackupInfo(
        path=backup_path,
        device_name=info.get('Device Name', 'Unknown'),
        device_id=info.get('Target Identifier', backup_path.name),
        product_type=info.get('Product Type', 'Unknown'),
        ios_version=info.get('Product Version', 'Unknown'),
        backup_date=info.get('Last Backup Date', datetime.min),
        encrypted=encrypted,
        size_mb=round(total_size / (1024 * 1024), 2),
    )


class iOSBackupParser:
    """
    iOS backup file extractor

    Queries the Manifest.db of iTunes/Finder backups
    to find and extract specific files.

    NOTE: This class only performs file location lookup and extraction.
          Content interpretation is handled by the configured analysis service.
    """

    def __init__(self, backup_path: Path):
        """
        Initialize backup parser.

        Args:
            backup_path: Path to iOS backup directory
        """
        self.backup_path = backup_path
        self.manifest_db = backup_path / 'Manifest.db'
        self.manifest_plist = backup_path / 'Manifest.plist'

        # Check backup structure
        if not self.backup_path.exists():
            raise FileNotFoundError(f"Backup not found: {backup_path}")

        self.is_modern = self.manifest_db.exists()
        self.is_legacy = self.manifest_plist.exists() and not self.is_modern

        if not self.is_modern and not self.is_legacy:
            raise ValueError("Invalid backup: No Manifest.db or Manifest.plist found")

    def get_file_hash(self, domain: str, relative_path: str) -> Optional[str]:
        """
        Get file hash (filename) for a domain/path combination.

        Args:
            domain: File domain (e.g., 'HomeDomain')
            relative_path: Relative path within domain

        Returns:
            SHA1 hash used as filename in backup, or None if not found
        """
        if self.is_modern:
            return self._get_file_hash_modern(domain, relative_path)
        else:
            return self._get_file_hash_legacy(domain, relative_path)

    def _get_file_hash_modern(self, domain: str, relative_path: str) -> Optional[str]:
        """Get file hash from Manifest.db (iOS 10+)"""
        try:
            conn = sqlite3.connect(str(self.manifest_db))
            cursor = conn.cursor()

            cursor.execute('''
                SELECT fileID FROM Files
                WHERE domain = ? AND relativePath = ?
            ''', (domain, relative_path))

            row = cursor.fetchone()
            conn.close()

            return row[0] if row else None

        except Exception as e:
            _debug_print(f"[iOS] Manifest.db query error: {e}")
            return None

    def _get_file_hash_legacy(self, domain: str, relative_path: str) -> Optional[str]:
        """Get file hash from Manifest.plist (iOS 9 and earlier)"""
        # Calculate the hash directly: SHA1(domain-relativePath)
        full_path = f"{domain}-{relative_path}"
        return hashlib.sha1(full_path.encode(), usedforsecurity=False).hexdigest()

    def list_files(
        self,
        domain_filter: Optional[str] = None,
        path_pattern: Optional[str] = None
    ) -> Generator[Dict[str, Any], None, None]:
        """
        List files in backup matching filters.

        Args:
            domain_filter: Filter by domain (supports * wildcard)
            path_pattern: Filter by path (supports * wildcard)

        Yields:
            File information dictionaries
        """
        if self.is_modern:
            yield from self._list_files_modern(domain_filter, path_pattern)
        else:
            yield from self._list_files_legacy(domain_filter, path_pattern)

    def _list_files_modern(
        self,
        domain_filter: Optional[str],
        path_pattern: Optional[str]
    ) -> Generator[Dict[str, Any], None, None]:
        """List files from Manifest.db"""
        try:
            conn = sqlite3.connect(str(self.manifest_db))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = 'SELECT fileID, domain, relativePath, flags, file FROM Files WHERE 1=1'
            params = []

            if domain_filter:
                if '*' in domain_filter:
                    query += " AND domain LIKE ? ESCAPE '\\'"
                    escaped = domain_filter.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
                    params.append(escaped.replace('*', '%'))
                else:
                    query += ' AND domain = ?'
                    params.append(domain_filter)

            if path_pattern:
                if '*' in path_pattern:
                    query += " AND relativePath LIKE ? ESCAPE '\\'"
                    escaped = path_pattern.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
                    params.append(escaped.replace('*', '%'))
                else:
                    query += ' AND relativePath = ?'
                    params.append(path_pattern)

            # [SECURITY] Pre-resolve backup base once (not per-file)
            resolved_base = str(self.backup_path.resolve()) + os.sep

            cursor.execute(query, params)

            for row in cursor:
                file_hash = row['fileID']

                # [SECURITY] Validate file hash format (SHA1 = 40 hex chars)
                if not _validate_ios_file_hash(file_hash):
                    continue

                # Try path variants: pre-iOS 17, iOS 17+ (Snapshot/), flat
                actual_path = self.backup_path / file_hash[:2] / file_hash
                if not actual_path.exists():
                    actual_path = self.backup_path / 'Snapshot' / file_hash[:2] / file_hash
                if not actual_path.exists():
                    actual_path = self.backup_path / file_hash
                if not actual_path.exists():
                    continue

                # [SECURITY] Path traversal check via string prefix (resolve once)
                try:
                    resolved = str(actual_path.resolve())
                except OSError:
                    continue
                if not resolved.startswith(resolved_base):
                    logger.warning(f"[SECURITY] Path escape detected: {actual_path}")
                    continue

                # Single os.stat() replaces exists() + stat().st_size
                try:
                    st = actual_path.stat()
                except OSError:
                    continue  # File doesn't exist in backup

                yield {
                    'file_id': file_hash,
                    'domain': row['domain'],
                    'relative_path': row['relativePath'],
                    'flags': row['flags'],
                    'backup_path': str(actual_path),
                    'size': st.st_size,
                }

            conn.close()

        except Exception as e:
            _debug_print(f"[iOS] Error listing files: {e}")

    def _list_files_legacy(
        self,
        domain_filter: Optional[str],
        path_pattern: Optional[str]
    ) -> Generator[Dict[str, Any], None, None]:
        """List files from Manifest.mbdb (legacy)"""
        # Legacy format is more complex, placeholder implementation
        yield {
            'status': 'legacy_backup',
            'message': 'Legacy backup format (iOS 9 and earlier) - limited support',
        }

    def extract_file(
        self,
        domain: str,
        relative_path: str,
        output_path: Path
    ) -> bool:
        """
        Extract a specific file from backup.

        Args:
            domain: File domain
            relative_path: Relative path within domain
            output_path: Where to save the extracted file

        Returns:
            True if extraction successful
        """
        file_hash = self.get_file_hash(domain, relative_path)
        if not file_hash:
            return False

        # [SECURITY] Validate file hash format
        if not _validate_ios_file_hash(file_hash):
            return False

        # Find actual file in backup (try pre-iOS 17, iOS 17+ Snapshot/, flat)
        source_path = self.backup_path / file_hash[:2] / file_hash

        if not source_path.exists():
            source_path = self.backup_path / 'Snapshot' / file_hash[:2] / file_hash

        if not source_path.exists():
            source_path = self.backup_path / file_hash

        if not source_path.exists():
            return False

        # [SECURITY] Validate path stays within backup directory
        if not _validate_path_within_backup(source_path, self.backup_path):
            return False

        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(source_path, output_path)
        except (FileNotFoundError, OSError) as e:
            # File may have been removed between exists() check and copy
            # (e.g., incomplete backup, antivirus quarantine)
            _debug_print(f"[iOS] extract_file copy failed: {e}")
            return False
        return True


# =============================================================================
# iOS Device Connector (pymobiledevice3)
# =============================================================================

@dataclass
class iOSDeviceInfo:
    """Connected iOS device information"""
    udid: str
    device_name: str
    product_type: str
    ios_version: str
    serial_number: str
    is_paired: bool


class iOSDeviceConnector:
    """
    iOS device connection class via pymobiledevice3

    Collects forensic artifacts directly from connected iOS devices.
    Pure Python implementation, no external binaries required.

    USB direct connection also supports backup-based artifacts:
    - requires_device=True artifacts: Direct collection (syslog, crash, etc.)
    - Backup-based artifacts: Auto backup creation followed by iOSCollector parsing
    """

    def __init__(self, output_dir: str, udid: Optional[str] = None):
        """
        Initialize device connector.

        Args:
            output_dir: Directory to store collected artifacts
            udid: Optional specific device UDID (auto-detect if None)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.udid = udid
        self.device_info: Optional[iOSDeviceInfo] = None
        self._lockdown: Optional[Any] = None

        # Backup path caching (created once, reused)
        self._backup_path: Optional[Path] = None
        self._backup_collector: Optional['iOSCollector'] = None

        # Encryption state — simplified to 4 variables
        # _encryption_action: None=not yet decided, 'we_enabled'=we turned it ON, 'was_already_on'
        self._encryption_action = None
        self._forensic_backup_password = None  # Password for decryption (forensic or user-provided)
        self._encrypted_backup_obj = None      # iphone_backup_decrypt EncryptedBackup instance
        self._backup_failed_reason = None      # Cached backup failure (skip retries)
        self._password_callback = None         # GUI callback: callback(error_msg) -> password|None
        self._encryption_skip_requested = False

        # Timeout for all change_password() calls (seconds). iOS can take
        # longer than a normal service call while restarting backup services.
        self._CHANGE_PASSWORD_TIMEOUT = 180

    def _clear_password(self):
        """Zero-out and release the forensic backup password from memory.

        Note: Python str objects are immutable and cannot be reliably wiped.
        We convert to bytearray, overwrite in-place, then delete all references.
        The original str may persist in memory until GC reclaims it, but this
        minimizes the exposure window.
        """
        pw = self._forensic_backup_password
        if pw:
            if isinstance(pw, bytearray):
                # bytearray is mutable — can be zeroed in-place
                for i in range(len(pw)):
                    pw[i] = 0
            elif isinstance(pw, str):
                # str is immutable — best effort: create bytearray copy, zero it,
                # and ensure the str reference is dropped for GC
                try:
                    pw_bytes = bytearray(pw.encode('utf-8'))
                    for i in range(len(pw_bytes)):
                        pw_bytes[i] = 0
                    del pw_bytes
                except Exception:
                    pass
            del pw
        self._forensic_backup_password = None

    @staticmethod
    def is_available() -> Dict[str, Any]:
        """Check pymobiledevice3 availability"""
        return {
            'available': PYMOBILEDEVICE3_AVAILABLE,
            'library': 'pymobiledevice3',
        }

    def get_connected_devices(self) -> List[str]:
        """Get list of connected device UDIDs"""
        if not PYMOBILEDEVICE3_AVAILABLE:
            return []

        try:
            devices = list_devices()
            return [d.serial for d in devices]
        except Exception as e:
            _debug_print(f"[iOS] Error listing devices: {e}")
            return []

    def connect(self, udid: Optional[str] = None) -> bool:
        """
        Connect to an iOS device.

        Args:
            udid: Device UDID (uses first available if None)

        Returns:
            True if connected successfully
        """
        if not PYMOBILEDEVICE3_AVAILABLE:
            raise RuntimeError("pymobiledevice3 is not installed. Install with: pip install pymobiledevice3")

        devices = self.get_connected_devices()
        if not devices:
            raise RuntimeError("No iOS device connected")

        if udid:
            if udid not in devices:
                raise ValueError(f"Device {udid} not found")
            self.udid = udid
        else:
            self.udid = devices[0]

        # Create lockdown client
        try:
            self._lockdown = create_using_usbmux(serial=self.udid)
            self.device_info = self._get_device_info()
            return self.device_info is not None
        except Exception as e:
            _debug_print(f"[iOS] Connection error: {e}")
            raise RuntimeError(f"Failed to connect to device: {e}")

    def _get_device_info(self) -> Optional[iOSDeviceInfo]:
        """Get detailed device information"""
        if not self._lockdown:
            return None

        try:
            all_values = self._lockdown.all_values

            return iOSDeviceInfo(
                udid=self.udid,
                device_name=all_values.get('DeviceName', 'Unknown'),
                product_type=all_values.get('ProductType', 'Unknown'),
                ios_version=all_values.get('ProductVersion', 'Unknown'),
                serial_number=all_values.get('SerialNumber', 'Unknown'),
                is_paired=True,
            )
        except Exception as e:
            _debug_print(f"[iOS] Error getting device info: {e}")
            return None

    def set_password_callback(self, callback):
        """
        Set password request callback for USB backup password dialog.

        callback(error_msg: str|None) -> str|None
            Called from collector thread when user password is needed.
            Returns password string, or None if cancelled.
        """
        self._password_callback = callback

    def _change_password_with_timeout(self, backup_dir: str, old_pw: str, new_pw: str) -> bool:
        """
        Run change_password() in a thread with timeout.

        Returns True on success. On timeout, reconnects lockdown and returns False.
        """
        result_box = {'success': False, 'error': None}

        def _do_change():
            try:
                svc = Mobilebackup2Service(lockdown=self._lockdown)
                svc.change_password(
                    backup_directory=backup_dir,
                    old=old_pw,
                    new=new_pw,
                )
                result_box['success'] = True
            except Exception as e:
                result_box['error'] = e

        t = threading.Thread(target=_do_change, daemon=True)
        t.start()
        t.join(timeout=self._CHANGE_PASSWORD_TIMEOUT)

        if t.is_alive():
            logger.warning("[iOS] change_password() timed out — reconnecting lockdown")
            try:
                self._lockdown = create_using_usbmux(serial=self.udid)
            except Exception:
                pass
            return False

        if result_box['success']:
            # Reconnect lockdown — change_password() invalidates the session.
            # iOS backup daemon needs time to restart after encryption state change.
            try:
                import time
                time.sleep(5)
                self._lockdown = create_using_usbmux(serial=self.udid)
                logger.info("[iOS] Lockdown reconnected after change_password()")
            except Exception as e:
                logger.warning(f"[iOS] Lockdown reconnect failed after change_password(): {e}")
            return True

        logger.info(f"[iOS] change_password() failed: {result_box['error']}")
        # Reconnect lockdown after failed change_password (session may be stale)
        try:
            self._lockdown = create_using_usbmux(serial=self.udid)
        except Exception:
            pass
        return False

    def _get_device_backup_encryption_state(self) -> Optional[bool]:
        """Return current device backup encryption state, if readable."""
        if not self._lockdown:
            return None
        try:
            return bool(self._lockdown.get_value("com.apple.mobile.backup", "WillEncrypt"))
        except Exception as e:
            logger.warning(f"[iOS] Failed to read device backup encryption state: {e}")
            try:
                self._lockdown = create_using_usbmux(serial=self.udid)
                return bool(self._lockdown.get_value("com.apple.mobile.backup", "WillEncrypt"))
            except Exception as reconnect_error:
                logger.warning(f"[iOS] Failed to read encryption state after reconnect: {reconnect_error}")
                return None

    def _verify_device_backup_encryption_state(
        self,
        expected: bool,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> bool:
        """Verify that the device backup encryption state matches expectation."""
        actual = self._get_device_backup_encryption_state()
        if actual is expected:
            return True

        msg = (
            f"iOS backup encryption state mismatch: expected {expected}, "
            f"device reports {actual}"
        )
        logger.warning(f"[iOS] {msg}")
        if progress_callback:
            progress_callback(f"[ERROR] {msg}")
        return False

    def _read_backup_manifest_encrypted(self, backup_path: Path) -> Optional[bool]:
        """Read IsEncrypted from a backup Manifest.plist."""
        manifest_plist = Path(backup_path) / 'Manifest.plist'
        if not manifest_plist.exists():
            return None

        try:
            with open(manifest_plist, 'rb') as f:
                manifest = plistlib.load(f)
            return bool(manifest.get('IsEncrypted', False))
        except Exception:
            if BIPLIST_AVAILABLE:
                try:
                    manifest = biplist.readPlist(str(manifest_plist))
                    return bool(manifest.get('IsEncrypted', False))
                except Exception:
                    pass
        return None

    def collect_device_info(
        self,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect device information"""
        if progress_callback:
            progress_callback("Collecting device information")

        if not self._lockdown:
            yield '', {
                'artifact_type': 'mobile_ios_device_info',
                'status': 'error',
                'error': 'Not connected to device',
            }
            return

        try:
            import json
            all_values = self._lockdown.all_values
            output = json.dumps(all_values, indent=2, default=str)

            filename = f"device_info_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            local_path = output_dir / filename
            local_path.write_text(output, encoding='utf-8')

            sha256 = hashlib.sha256(output.encode('utf-8')).hexdigest()

            yield str(local_path), {
                'artifact_type': 'mobile_ios_device_info',
                'filename': filename,
                'size': local_path.stat().st_size,
                'sha256': sha256,
                'device_udid': self.udid,
                'device_name': self.device_info.device_name if self.device_info else 'Unknown',
                'ios_version': self.device_info.ios_version if self.device_info else 'Unknown',
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'pymobiledevice3',
            }

        except Exception as e:
            yield '', {
                'artifact_type': 'mobile_ios_device_info',
                'status': 'error',
                'error': str(e),
            }

    def collect_syslog(
        self,
        output_dir: Path,
        duration_seconds: int = 10,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect system log for specified duration"""
        if not PYMOBILEDEVICE3_AVAILABLE:
            yield '', {
                'artifact_type': 'mobile_ios_syslog',
                'status': 'error',
                'error': 'pymobiledevice3 not installed',
            }
            return

        if progress_callback:
            progress_callback(f"Collecting system log ({duration_seconds}s)")

        try:
            import time
            logs = []
            stop_event = threading.Event()

            def collect_logs():
                try:
                    with SyslogService(lockdown=self._lockdown) as syslog:
                        for line in syslog.watch():
                            if stop_event.is_set():
                                break
                            logs.append(str(line))
                except Exception as e:
                    logs.append(f"Error: {e}")

            # Start collection thread
            thread = threading.Thread(target=collect_logs)
            thread.daemon = True
            thread.start()

            # Wait for specified duration
            time.sleep(duration_seconds)
            stop_event.set()
            thread.join(timeout=2)

            output_text = '\n'.join(logs)

            filename = f"syslog_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
            local_path = output_dir / filename
            local_path.write_text(output_text, encoding='utf-8')

            sha256 = hashlib.sha256(output_text.encode('utf-8')).hexdigest()

            yield str(local_path), {
                'artifact_type': 'mobile_ios_syslog',
                'filename': filename,
                'size': local_path.stat().st_size,
                'sha256': sha256,
                'duration_seconds': duration_seconds,
                'device_udid': self.udid,
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'pymobiledevice3',
            }

        except Exception as e:
            yield '', {
                'artifact_type': 'mobile_ios_syslog',
                'status': 'error',
                'error': str(e),
            }

    def collect_crash_logs(
        self,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect crash reports from device"""
        if not PYMOBILEDEVICE3_AVAILABLE:
            yield '', {
                'artifact_type': 'mobile_ios_crash_logs',
                'status': 'error',
                'error': 'pymobiledevice3 not installed',
            }
            return

        if progress_callback:
            progress_callback("Collecting crash reports")

        crash_dir = output_dir / 'crash_reports'
        crash_dir.mkdir(exist_ok=True)

        try:
            crash_manager = CrashReportsManager(self._lockdown)
            crash_files_collected = []

            for crash in crash_manager.ls('/'):
                try:
                    content = crash_manager.get_file(crash)
                    if content:
                        crash_file = crash_dir / crash.replace('/', '_')
                        crash_file.write_bytes(content)
                        crash_files_collected.append(crash_file)
                except Exception as e:
                    _debug_print(f"[iOS] Error getting crash file {crash}: {e}")

            if crash_files_collected:
                for crash_file in crash_files_collected:
                    sha256 = hashlib.sha256()
                    with open(crash_file, 'rb') as f:
                        for chunk in iter(lambda: f.read(65536), b''):
                            sha256.update(chunk)

                    yield str(crash_file), {
                        'artifact_type': 'mobile_ios_crash_logs',
                        'filename': crash_file.name,
                        'size': crash_file.stat().st_size,
                        'sha256': sha256.hexdigest(),
                        'device_udid': self.udid,
                        'collected_at': datetime.utcnow().isoformat(),
                        'collection_method': 'pymobiledevice3',
                    }
            else:
                yield '', {
                    'artifact_type': 'mobile_ios_crash_logs',
                    'status': 'not_found',
                    'message': 'No crash reports found',
                }

        except Exception as e:
            yield '', {
                'artifact_type': 'mobile_ios_crash_logs',
                'status': 'error',
                'error': str(e),
            }

    def collect_installed_apps(
        self,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect list of installed apps"""
        if not PYMOBILEDEVICE3_AVAILABLE:
            yield '', {
                'artifact_type': 'mobile_ios_installed_apps',
                'status': 'error',
                'error': 'pymobiledevice3 not installed',
            }
            return

        if progress_callback:
            progress_callback("Collecting installed apps list")

        try:
            import json
            installation_proxy = InstallationProxyService(lockdown=self._lockdown)
            apps = installation_proxy.get_apps()

            output = json.dumps(apps, indent=2, default=str)

            filename = f"installed_apps_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            local_path = output_dir / filename
            local_path.write_text(output, encoding='utf-8')

            sha256 = hashlib.sha256(output.encode('utf-8')).hexdigest()

            yield str(local_path), {
                'artifact_type': 'mobile_ios_installed_apps',
                'filename': filename,
                'size': local_path.stat().st_size,
                'sha256': sha256,
                'app_count': len(apps) if isinstance(apps, dict) else 0,
                'device_udid': self.udid,
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'pymobiledevice3',
            }

        except Exception as e:
            yield '', {
                'artifact_type': 'mobile_ios_installed_apps',
                'status': 'error',
                'error': str(e),
            }

    def create_backup(
        self,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Create new iOS backup from device.

        Three scenarios:
          A. will_encrypt=False → auto-enable forensic encryption → backup → close() restores
          B. will_encrypt=True + forensic_pw matches → our previous encryption → backup
          C. will_encrypt=True + forensic_pw fails → user password via callback → backup
        """
        if not PYMOBILEDEVICE3_AVAILABLE:
            yield '', {
                'artifact_type': 'mobile_ios_device_backup',
                'status': 'error',
                'error': 'pymobiledevice3 not installed',
            }
            return

        # Skip if backup already failed (prevents repeated password dialogs)
        if self._backup_failed_reason:
            yield '', {
                'artifact_type': 'mobile_ios_device_backup',
                'status': 'error',
                'error': self._backup_failed_reason,
            }
            return

        # Reuse existing backup from this session (prevents second password prompt
        # and avoids creating a duplicate ~26-min backup)
        if self._backup_path and self._backup_path.exists():
            manifest = self._backup_path / 'Manifest.plist'
            if manifest.exists():
                logger.info(f"[iOS] Reusing existing backup at {self._backup_path}")
                if progress_callback:
                    progress_callback("Using existing backup (already created)")
                total_size = sum(
                    f.stat().st_size for f in self._backup_path.rglob('*') if f.is_file()
                )
                yield str(self._backup_path), {
                    'artifact_type': 'mobile_ios_device_backup',
                    'backup_path': str(self._backup_path),
                    'status': 'success',
                    'message': 'Reused existing backup',
                    'encrypted': bool(self._forensic_backup_password),
                    'total_size': total_size,
                }
                return

        if progress_callback:
            progress_callback("Creating iOS backup (this may take a while)")

        backup_dir = output_dir / 'backup'
        backup_dir.mkdir(exist_ok=True)

        try:
            logger.info(f"[iOS] Reading backup encryption state (lockdown={type(self._lockdown).__name__})")
            will_encrypt = self._get_device_backup_encryption_state()
            if will_encrypt is None:
                raise RuntimeError("Failed to read iOS backup encryption state")
            logger.info(f"[iOS] Backup encryption state: will_encrypt={will_encrypt}")

            # =============================================================
            # Encryption handling — user provides password for all scenarios.
            # No auto-generated keys: user always knows the password,
            # so they can recover if the collector crashes mid-collection.
            # =============================================================
            # Reuse cached password if already verified (prevents re-prompting)
            if self._forensic_backup_password:
                logger.info("[iOS] Reusing cached backup password (already verified)")
            elif not will_encrypt:
                # Encryption OFF -> ask user for a temporary password to enable it.
                # Encrypted backups contain more forensic data.
                if not self._password_callback:
                    self._backup_failed_reason = (
                        "iOS encrypted backup setup requires user confirmation. "
                        "Run the collector UI and enter a temporary backup password."
                    )
                    yield '', {
                        'artifact_type': 'mobile_ios_device_backup',
                        'status': 'error',
                        'error': self._backup_failed_reason,
                    }
                    return

                if progress_callback:
                    progress_callback("Backup encryption required for complete forensic data...")

                user_pw = self._request_encryption_password(str(backup_dir), progress_callback)
                if user_pw:
                    if progress_callback:
                        progress_callback(
                            "Look at the iPhone now: enter the device passcode on the iPhone screen "
                            "to allow encrypted backup."
                        )
                    if self._change_password_with_timeout(str(backup_dir), "", user_pw):
                        self._encryption_action = 'we_enabled'
                        self._forensic_backup_password = user_pw
                        if not self._verify_device_backup_encryption_state(True, progress_callback):
                            self._backup_failed_reason = (
                                "Failed to verify that iOS encrypted backup was enabled. "
                                "Reconnect the device, keep it unlocked, confirm Trust, "
                                "enter the iPhone device passcode when prompted, and run collection again."
                            )
                            logger.warning(f"[iOS] {self._backup_failed_reason}")
                            if self._change_password_with_timeout(str(backup_dir), user_pw, ""):
                                logger.info("[iOS] Encryption restored after verification failure")
                            else:
                                logger.warning("[iOS] Encryption restore failed after verification failure")
                            self._encryption_action = None
                            self._clear_password()
                            yield '', {
                                'artifact_type': 'mobile_ios_device_backup',
                                'status': 'error',
                                'error': self._backup_failed_reason,
                            }
                            return
                        logger.info("[iOS] Backup encryption enabled with user password")
                    else:
                        self._backup_failed_reason = (
                            "Failed to enable iOS encrypted backup. "
                            "Reconnect the device, keep it unlocked, confirm Trust, "
                            "enter the iPhone device passcode when prompted, and run collection again."
                        )
                        logger.warning(f"[iOS] {self._backup_failed_reason}")
                        self._encryption_action = None
                        self._clear_password()
                        yield '', {
                            'artifact_type': 'mobile_ios_device_backup',
                            'status': 'error',
                            'error': self._backup_failed_reason,
                        }
                        return
                else:
                    if self._encryption_skip_requested:
                        logger.info("[iOS] User skipped encryption, proceeding unencrypted")
                        self._encryption_action = None
                        self._clear_password()
                    else:
                        self._backup_failed_reason = "iOS encrypted backup setup was cancelled."
                        yield '', {
                            'artifact_type': 'mobile_ios_device_backup',
                            'status': 'error',
                            'error': self._backup_failed_reason,
                        }
                        return
            else:
                # Encryption already ON → ask user for existing password
                logger.info("[iOS] Encryption already ON — requesting existing password")
                user_pw = self._request_user_password(str(backup_dir), progress_callback)
                if user_pw:
                    self._encryption_action = 'was_already_on'
                    self._forensic_backup_password = user_pw
                else:
                    self._backup_failed_reason = (
                        "Backup password unknown — cannot proceed.\n"
                        "Reset via: Settings > General > Transfer or Reset iPhone "
                        "> Reset > Reset All Settings (data preserved)"
                    )
                    yield '', {
                        'artifact_type': 'mobile_ios_device_backup',
                        'status': 'error',
                        'error': self._backup_failed_reason,
                    }
                    return

            # Create fresh service and start backup with retry logic.
            # After encryption state change, iOS backup daemon may need time to restart.
            import time
            max_attempts = 2
            last_err = None

            for attempt in range(1, max_attempts + 1):
                try:
                    if attempt > 1:
                        logger.info(f"[iOS] Backup retry {attempt}/{max_attempts} — reconnecting lockdown...")
                        if progress_callback:
                            progress_callback(f"Retrying backup (attempt {attempt})...")
                        time.sleep(3)
                        self._lockdown = create_using_usbmux(serial=self.udid)

                    logger.info(f"[iOS] Creating Mobilebackup2Service (attempt {attempt})...")
                    backup_service = Mobilebackup2Service(lockdown=self._lockdown)
                    logger.info(f"[iOS] Starting backup: full=True, dir={backup_dir}, encrypted={bool(self._forensic_backup_password)}")

                    def backup_progress(percentage: float):
                        if progress_callback:
                            progress_callback(f"iOS backup progress: {percentage:.1f}%")

                    backup_service.backup(
                        full=True,
                        backup_directory=str(backup_dir),
                        progress_callback=backup_progress
                    )
                    logger.info("[iOS] Backup completed successfully")
                    last_err = None
                    break

                except ConnectionAbortedError as e:
                    last_err = e
                    logger.warning(f"[iOS] Backup attempt {attempt} failed: ConnectionAbortedError")
                    if attempt < max_attempts:
                        continue
                except ConnectionError as e:
                    last_err = e
                    logger.warning(f"[iOS] Backup attempt {attempt} failed: {type(e).__name__}: {e}")
                    if attempt < max_attempts:
                        continue

            if last_err is not None:
                raise last_err

            # pymobiledevice3 creates backup at <backup_dir>/<UDID>/
            actual_backup_path = backup_dir
            for subdir in backup_dir.iterdir():
                if subdir.is_dir() and (subdir / 'Manifest.plist').exists():
                    actual_backup_path = subdir
                    break

            manifest_encrypted = self._read_backup_manifest_encrypted(actual_backup_path)
            if self._forensic_backup_password and manifest_encrypted is not True:
                raise RuntimeError(
                    "iOS backup was expected to be encrypted, but Manifest.plist "
                    "does not report an encrypted backup."
                )
            if not self._forensic_backup_password and manifest_encrypted is True:
                raise RuntimeError(
                    "iOS backup is encrypted, but no backup password is available for extraction."
                )

            total_size = sum(
                f.stat().st_size for f in actual_backup_path.rglob('*') if f.is_file()
            )

            yield str(actual_backup_path), {
                'artifact_type': 'mobile_ios_device_backup',
                'backup_path': str(actual_backup_path),
                'size_bytes': total_size,
                'size_mb': round(total_size / (1024 * 1024), 2),
                'device_udid': self.udid,
                'encrypted': bool(manifest_encrypted),
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'pymobiledevice3',
            }

        except Exception as e:
            import traceback
            err_type = type(e).__name__
            err_msg = str(e) or f"(empty message, exception type: {err_type})"
            logger.error(f"[iOS] Backup failed: [{err_type}] {err_msg}")
            logger.error(f"[iOS] Backup traceback:\n{traceback.format_exc()}")

            # Restore encryption if we enabled it
            if self._encryption_action == 'we_enabled' and self._forensic_backup_password and self._lockdown:
                if self._change_password_with_timeout(str(backup_dir), self._forensic_backup_password, ""):
                    logger.info("[iOS] Backup failed — encryption restored to OFF")
                else:
                    logger.warning("[iOS] Backup failed AND encryption restore failed")
                self._encryption_action = None
                self._clear_password()

            yield '', {
                'artifact_type': 'mobile_ios_device_backup',
                'status': 'error',
                'error': err_msg,
            }

    def _request_user_password(
        self,
        backup_dir: str,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Optional[str]:
        """
        Request user password via callback loop.

        Returns verified password or None if cancelled.
        """
        if not self._password_callback:
            logger.warning("[iOS] No password callback set — cannot request user password")
            return None

        max_retries = 3
        error_msg = None
        for attempt in range(max_retries):
            password = self._password_callback(error_msg)
            if not password:
                # User cancelled or clicked "I don't know"
                return None

            if progress_callback:
                progress_callback("Verifying entered password...")

            if self._change_password_with_timeout(backup_dir, password, password):
                logger.info("[iOS] User password verified successfully")
                return password

            remaining = max_retries - attempt - 1
            if remaining > 0:
                error_msg = f"Incorrect password. {remaining} attempt(s) remaining."
                logger.info(f"[iOS] User password rejected, {remaining} retries left")
            else:
                logger.warning("[iOS] User password rejected after all attempts")
                return None

    def _request_encryption_password(
        self,
        backup_dir: str,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Optional[str]:
        """
        Request user to set a temporary encryption password (encryption OFF case).

        The user enters a password to enable backup encryption for this session.
        After collection, the collector restores encryption to OFF using this password.
        If crash occurs, the user knows the password and can manage it themselves.

        Returns password or None. Skip and cancel are tracked separately.
        """
        if not self._password_callback:
            logger.warning("[iOS] No password callback set — cannot request encryption password")
            return None

        # Use password callback with a message indicating this is for new encryption
        password = self._password_callback(
            "ENCRYPTION_SETUP"  # Special marker for GUI to show appropriate dialog
        )
        if password == IOS_ENCRYPTION_SKIP_SENTINEL:
            self._encryption_skip_requested = True
            return None
        self._encryption_skip_requested = False
        return password if password else None

    # =========================================================================
    # Unified collect() method - supports all artifact types
    # =========================================================================

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[Callable[[str], None]] = None,
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Unified artifact collection method.

        Collects all iOS artifacts from USB direct connection:
        - Device-only artifacts: Direct collection
        - Backup-based artifacts: Backup creation followed by file extraction

        NOTE: Collector only performs raw file extraction.
              Content interpretation is handled by the configured analysis service.

        Args:
            artifact_type: Artifact type to collect
            progress_callback: Progress callback

        Yields:
            Tuple of (local_path, metadata)
        """
        if artifact_type not in IOS_ARTIFACT_TYPES:
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': f'Unknown artifact type: {artifact_type}',
            }
            return

        artifact_info = IOS_ARTIFACT_TYPES[artifact_type]
        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)

        # =====================================================================
        # Case 1: Device direct collection artifacts (requires_device=True)
        # =====================================================================
        if artifact_info.get('requires_device'):
            yield from self._collect_device_artifact(
                artifact_type, artifact_info, artifact_dir, progress_callback
            )
            return

        # =====================================================================
        # Case 2: Backup-based artifacts -> Backup creation then file extraction via iOSCollector
        # =====================================================================

        # Skip immediately if backup already failed (e.g., iOS 26 beta bug)
        # Prevents wasting 10+ seconds per artifact on repeated failures
        if self._backup_failed_reason:
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': self._backup_failed_reason,
            }
            return

        if progress_callback:
            progress_callback(f"Preparing backup for {artifact_type}...")

        # Create backup if none exists
        if not self._backup_path or not self._backup_path.exists():
            backup_created = False
            for path, meta in self._create_backup_for_extraction(progress_callback):
                if meta.get('status') == 'error':
                    # Cache failure reason to skip subsequent backup-based artifacts
                    err = meta.get('error', 'Unknown backup error')
                    self._backup_failed_reason = f"Backup creation failed: {err}"
                    yield path, meta
                    return
                if path:
                    self._backup_path = Path(meta.get('backup_path', path))
                    backup_created = True

            if not backup_created:
                self._backup_failed_reason = "Failed to create device backup"
                yield '', {
                    'artifact_type': artifact_type,
                    'status': 'error',
                    'error': self._backup_failed_reason,
                }
                return

        # Early fail: encrypted backup but decryptor not available
        if self._forensic_backup_password and not self._encrypted_backup_obj:
            msg = self._backup_failed_reason or "Encrypted backup created but cannot decrypt. Check iphone_backup_decrypt installation."
            logger.error(f"[iOS] {msg}")
            if progress_callback:
                progress_callback(f"[ERROR] {msg}")
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': msg,
            }
            return

        # Extract files from backup via iOSCollector (raw files only, no parsing)
        if not self._backup_collector:
            try:
                # Pass encrypted_backup for NSFileProtectionComplete app access
                collector = iOSCollector(
                    str(self.output_dir),
                    encrypted_backup=self._encrypted_backup_obj
                )
                collector.select_backup(str(self._backup_path))
                self._backup_collector = collector  # Only set on success
            except Exception as e:
                # On failure, do not set _backup_collector so next artifact can retry
                yield '', {
                    'artifact_type': artifact_type,
                    'status': 'error',
                    'error': f'Failed to open backup: {e}',
                }
                return

        # Delegate artifact file extraction from backup
        if progress_callback:
            progress_callback(f"Extracting {artifact_type} from backup...")

        yield from self._backup_collector.collect(artifact_type, progress_callback)

    def _collect_device_artifact(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Handle artifacts collected directly from device.

        Routes to the appropriate collection method for each artifact type.
        """
        if artifact_type == 'mobile_ios_device_info':
            yield from self.collect_device_info(artifact_dir, progress_callback)

        elif artifact_type == 'mobile_ios_syslog':
            yield from self.collect_syslog(artifact_dir, duration_seconds=30, progress_callback=progress_callback)

        elif artifact_type == 'mobile_ios_crash_logs':
            yield from self.collect_crash_logs(artifact_dir, progress_callback)

        elif artifact_type == 'mobile_ios_installed_apps':
            yield from self.collect_installed_apps(artifact_dir, progress_callback)

        elif artifact_type == 'mobile_ios_device_backup':
            # FIX: Store backup path + init decryptor so subsequent
            # backup-based artifacts can reuse this backup instead of creating a second one.
            for path, meta in self.create_backup(artifact_dir, progress_callback):
                if path and meta.get('backup_path'):
                    self._backup_path = Path(meta['backup_path'])
                    # Initialize decryptor for encrypted backups
                    if self._forensic_backup_password:
                        if not self._init_encrypted_decryptor(meta['backup_path'], progress_callback):
                            yield '', {
                                'artifact_type': artifact_type,
                                'status': 'error',
                                'error': self._backup_failed_reason or 'Failed to prepare encrypted backup access',
                            }
                            return
                if meta.get('status') == 'error':
                    yield path, meta
                    return

                backup_path = Path(meta.get('backup_path', path)) if (path or meta.get('backup_path')) else None
                if backup_path is not None and backup_path.is_dir():
                    artifact_dir.mkdir(parents=True, exist_ok=True)
                    summary_path = artifact_dir / 'ios_device_backup_summary.json'
                    summary = dict(meta)
                    summary['backup_path'] = str(backup_path)
                    summary['backup_directory_uploaded'] = False
                    summary['note'] = (
                        'The backup directory is used locally for artifact extraction '
                        'and is not uploaded as a single file.'
                    )
                    with open(summary_path, 'w', encoding='utf-8') as f:
                        json.dump(summary, f, ensure_ascii=False, indent=2, default=str)

                    sha256 = hashlib.sha256()
                    with open(summary_path, 'rb') as f:
                        for chunk in iter(lambda: f.read(65536), b''):
                            sha256.update(chunk)

                    yield str(summary_path), {
                        'artifact_type': artifact_type,
                        'filename': summary_path.name,
                        'size': summary_path.stat().st_size,
                        'sha256': sha256.hexdigest(),
                        'backup_path': str(backup_path),
                        'backup_directory_uploaded': False,
                        'collected_at': datetime.utcnow().isoformat(),
                    }
                    return

                if path and Path(path).is_file():
                    yield path, meta
                    return

        elif artifact_type == 'mobile_ios_unified_logs':
            # sysdiagnose requires separate handling (not yet implemented)
            yield '', {
                'artifact_type': artifact_type,
                'status': 'not_implemented',
                'error': 'Unified logs collection requires sysdiagnose (not yet implemented)',
            }

        else:
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': f'Unknown device artifact: {artifact_type}',
            }

    def _init_encrypted_decryptor(
        self,
        backup_path: str,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> bool:
        """
        Initialize EncryptedBackup decryptor for encrypted iOS backups.

        Password must already be confirmed in create_backup() — this method
        simply runs key derivation key derivation with the known password.

        Returns True if decryptor was initialized successfully.
        """
        if not self._forensic_backup_password:
            return False

        if progress_callback:
            progress_callback("Preparing backup access (this may take 1-2 minutes)...")
        try:
            from collectors.ios_backup_decryptor import create_encrypted_backup

            enc_obj, err = create_encrypted_backup(
                backup_path, self._forensic_backup_password
            )
            if enc_obj:
                self._encrypted_backup_obj = enc_obj
                logger.info("[iOS] Encrypted backup decryptor initialized successfully")
                if progress_callback:
                    progress_callback("Encrypted backup decryptor ready")
                return True

            # Password was verified in create_backup() but key derivation failed = internal error
            logger.error(f"[iOS] Decryptor init failed (internal error): {err}")
            self._backup_failed_reason = f"Decryptor initialization failed: {err}"
            if progress_callback:
                progress_callback(f"[ERROR] Decryptor init failed: {err}")

        except ImportError as ie:
            self._backup_failed_reason = f"iphone_backup_decrypt library not installed: {ie}"
            logger.warning(f"[iOS] ios_backup_decryptor import failed: {ie}")
            if progress_callback:
                progress_callback("[WARNING] Encrypted backup support unavailable (missing: iphone_backup_decrypt)")
        except Exception as e:
            self._backup_failed_reason = f"Decryptor error: {e}"
            logger.warning(f"[iOS] Decryptor init error: {e}")
            if progress_callback:
                progress_callback(f"[WARNING] Decryptor error: {e}")
        return False

    def _create_backup_for_extraction(
        self,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Create backup for artifact extraction.

        Reuses existing backup if available, creates new one otherwise.

        Path structure created by create_backup():
            ios_backup/backup/UDID/   <- actual backup (contains Manifest.plist, Manifest.db)
        We check both the legacy expected path (ios_backup/UDID/) and the
        actual create_backup() output path (ios_backup/backup/UDID/) for reuse.
        """
        if progress_callback:
            progress_callback("Creating device backup for artifact extraction...")

        udid_or_device = self.udid or 'device'
        ios_backup_root = self.output_dir / 'ios_backup'
        ios_backup_root.mkdir(parents=True, exist_ok=True)

        # Check if valid backup already exists.
        # create_backup() places backups at ios_backup/backup/UDID/,
        # so check there first, then fall back to ios_backup/UDID/ (legacy).
        backup_dir = None
        candidate_paths = [
            ios_backup_root / 'backup' / udid_or_device,  # create_backup() output path
            ios_backup_root / udid_or_device,              # legacy/direct path
        ]
        for candidate in candidate_paths:
            if candidate.is_dir() and (candidate / 'Manifest.plist').exists():
                backup_dir = candidate
                break

        if backup_dir is not None:
            if progress_callback:
                progress_callback("Using existing backup...")

            # Reused backup may be encrypted; set up decryptor.
            is_encrypted = self._read_backup_manifest_encrypted(backup_dir)

            if is_encrypted and not self._encrypted_backup_obj:
                # Encrypted backup reuse requires password from current session
                if self._forensic_backup_password:
                    if not self._init_encrypted_decryptor(str(backup_dir), progress_callback):
                        yield '', {
                            'artifact_type': 'mobile_ios_device_backup',
                            'status': 'error',
                            'error': self._backup_failed_reason or 'Failed to prepare encrypted backup access',
                        }
                        return

            yield str(backup_dir), {
                'artifact_type': 'mobile_ios_device_backup',
                'backup_path': str(backup_dir),
                'status': 'reused',
                'message': 'Using existing backup',
            }
            return

        # Create new backup
        for path, meta in self.create_backup(ios_backup_root, progress_callback):
            if meta.get('status') == 'error':
                yield path, meta
                return

            # Initialize decryptor for encrypted backups
            if self._forensic_backup_password and path:
                backup_path = meta.get('backup_path', path)
                if not self._init_encrypted_decryptor(backup_path, progress_callback):
                    yield '', {
                        'artifact_type': 'mobile_ios_device_backup',
                        'status': 'error',
                        'error': self._backup_failed_reason or 'Failed to prepare encrypted backup access',
                    }
                    return

            yield path, meta

    def close(self):
        """Clean up resources and restore device encryption state"""
        # Restore encryption to OFF if we enabled it
        if self._encryption_action == 'we_enabled' and self._forensic_backup_password and self._lockdown:
            restore_dir = self.output_dir
            if self._backup_path and self._backup_path.exists():
                restore_dir = self._backup_path.parent

            if self._change_password_with_timeout(str(restore_dir), self._forensic_backup_password, ""):
                logger.info("[iOS] Backup encryption restored to OFF")
                if not self._verify_device_backup_encryption_state(False):
                    logger.warning("[iOS] Backup encryption restore could not be verified")
            else:
                logger.warning("[iOS] Encryption restore failed — device may still have forensic encryption")
                logger.warning("[iOS] To manually restore: use iTunes/Finder to change backup password")

        # Clean up EncryptedBackup resources
        if self._encrypted_backup_obj:
            if hasattr(self._encrypted_backup_obj, 'close'):
                try:
                    self._encrypted_backup_obj.close()
                except Exception:
                    pass
            self._encrypted_backup_obj = None

        self._lockdown = None
        self._backup_collector = None
        self._clear_password()


class iOSCollector:
    """
    iOS forensic collection unified class

    Extracts forensic artifacts from iTunes/Finder backups.
    """

    def __init__(self, output_dir: str, backup_path: Optional[str] = None, encrypted_backup=None):
        """
        Initialize iOS collector.

        Args:
            output_dir: Directory to store collected artifacts
            backup_path: Path to specific backup (auto-detect if None)
            encrypted_backup: Pre-created EncryptedBackup instance for encrypted backups
                (created via ios_backup_decryptor.create_encrypted_backup())
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.backup_path = Path(backup_path) if backup_path else None
        self.backup_info: Optional[BackupInfo] = None
        self.parser: Optional[iOSBackupParser] = None
        self._encrypted_backup = encrypted_backup

    def get_available_backups(self) -> List[BackupInfo]:
        """Get list of available iOS backups"""
        return find_ios_backups()

    def select_backup(self, backup_path: str) -> bool:
        """
        Select a backup to work with.

        Args:
            backup_path: Path to backup directory

        Returns:
            True if backup is valid and selected
        """
        path = Path(backup_path)
        if not path.exists():
            raise FileNotFoundError(f"Backup not found: {backup_path}")

        self.backup_info = parse_backup_info(path)
        if self.backup_info is None:
            raise ValueError(f"Invalid backup: {backup_path}")

        self.backup_path = path

        # Use encrypted parser if EncryptedBackup provided.
        # Also use it if backup is encrypted (Manifest.plist IsEncrypted=True).
        # The _encrypted_backup check is the primary signal — the EncryptedBackup
        # object already holds the derived key and can decrypt Manifest.db.
        if self._encrypted_backup:
            from collectors.ios_backup_decryptor import iOSEncryptedBackupParser
            self.parser = iOSEncryptedBackupParser(path, self._encrypted_backup)
        else:
            self.parser = iOSBackupParser(path)
        return True

    def close(self):
        """Clean up parser resources (temp decrypted Manifest.db)."""
        if self.parser and hasattr(self.parser, 'close'):
            try:
                self.parser.close()
            except Exception:
                pass
        self.parser = None

    @property
    def is_encrypted(self) -> bool:
        """Check if selected backup is encrypted"""
        return self.backup_info.encrypted if self.backup_info else False

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[Callable[[str], None]] = None,
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect specific artifact type from backup.

        Args:
            artifact_type: Type of artifact to collect
            progress_callback: Callback for progress updates

        Yields:
            Tuple of (local_path, metadata)
        """
        if not self.parser:
            raise RuntimeError("No backup selected. Call select_backup() first.")

        if self.backup_info.encrypted and not self._encrypted_backup:
            yield '', {
                'artifact_type': artifact_type,
                'status': 'error',
                'error': 'Encrypted backup. Password required.',
                'backup_path': str(self.backup_path),
            }
            return

        if artifact_type not in IOS_ARTIFACT_TYPES:
            raise ValueError(f"Unknown artifact type: {artifact_type}")

        # Skip redundant artifact types (covered by specific per-app types)
        if artifact_type in _SKIP_ARTIFACTS:
            _debug_print(f"[iOS] Skipping {artifact_type} (redundant with specific app types)")
            return

        artifact_info = IOS_ARTIFACT_TYPES[artifact_type]

        # Check if artifact requires encrypted backup
        if artifact_info.get('requires_encrypted') and not self.backup_info.encrypted:
            yield '', {
                'artifact_type': artifact_type,
                'status': 'not_found',
                'error': f'{artifact_info["name"]} requires encrypted backup (current backup is unencrypted)',
            }
            return

        # Create artifact output directory
        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)

        # Handle backup metadata separately
        if artifact_type == 'mobile_ios_backup':
            yield from self._collect_backup_metadata(artifact_dir, progress_callback)
            return

        # Handle pattern-based collection
        if artifact_info.get('pattern'):
            yield from self._collect_pattern(
                artifact_type,
                artifact_info,
                artifact_dir,
                progress_callback
            )
            return

        # Handle multiple paths
        if 'manifest_paths' in artifact_info:
            for path in artifact_info['manifest_paths']:
                yield from self._collect_file(
                    artifact_type,
                    artifact_info['manifest_domain'],
                    path,
                    artifact_dir,
                    progress_callback
                )
            return

        # Handle single path
        if 'manifest_path' in artifact_info:
            yield from self._collect_file(
                artifact_type,
                artifact_info['manifest_domain'],
                artifact_info['manifest_path'],
                artifact_dir,
                progress_callback
            )

    def _collect_file(
        self,
        artifact_type: str,
        domain: str,
        relative_path: str,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect a specific file from backup"""
        filename = _sanitize_filename(Path(relative_path).name)
        local_path = output_dir / filename

        if progress_callback:
            progress_callback(f"Extracting {filename}")

        success = self.parser.extract_file(domain, relative_path, local_path)

        if success and local_path.exists():
            sha256 = hashlib.sha256()
            with open(local_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)

            yield str(local_path), {
                'artifact_type': artifact_type,
                'domain': domain,
                'original_path': relative_path,
                'filename': filename,
                'size': local_path.stat().st_size,
                'sha256': sha256.hexdigest(),
                'device_name': self.backup_info.device_name,
                'device_id': self.backup_info.device_id,
                'ios_version': self.backup_info.ios_version,
                'backup_date': self.backup_info.backup_date.isoformat(),
                'collected_at': datetime.utcnow().isoformat(),
                'collection_method': 'ios_backup_extraction',
            }
        else:
            # Diagnostic: show what files ARE in this domain (first 5)
            diag_files = []
            try:
                for i, fi in enumerate(self.parser.list_files(domain_filter=domain)):
                    diag_files.append(fi.get('relative_path', '?'))
                    if i >= 4:
                        break
            except Exception:
                pass

            diag_msg = f"File not found: {domain}/{relative_path}"
            if diag_files:
                diag_msg += f" (domain has: {', '.join(diag_files[:5])})"
            else:
                diag_msg += " (domain empty or not present in backup)"
            _debug_print(f"[iOS] {diag_msg}")

            yield '', {
                'artifact_type': artifact_type,
                'status': 'not_found',
                'domain': domain,
                'path': relative_path,
                'error': diag_msg,
            }

    def _collect_pattern(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files matching domain + path patterns (with extension filtering)"""
        domain_pattern = artifact_info.get('manifest_domain', '*')
        is_encrypted = self.backup_info.encrypted and self._encrypted_backup

        # Determine allowed file extensions
        if artifact_type in _ATTACHMENT_ARTIFACTS:
            allowed_ext = _FORENSIC_EXTENSIONS | _MEDIA_EXTENSIONS
        else:
            allowed_ext = _FORENSIC_EXTENSIONS

        # Build path patterns from manifest_path / manifest_paths
        # These are used as SQL LIKE filters to avoid over-collecting entire domains
        path_patterns = []
        if 'manifest_paths' in artifact_info:
            path_patterns = list(artifact_info['manifest_paths'])
        elif 'manifest_path' in artifact_info:
            path_patterns = [artifact_info['manifest_path']]

        skipped_count = 0
        collected_count = 0
        seen_files = set()  # Track (domain, relative_path) to prevent duplicates
        created_dirs = set()  # Cache mkdir calls (once per domain)

        # If we have specific path patterns, query each pattern separately
        # Otherwise fall back to domain-only scan
        if path_patterns:
            queries = [(domain_pattern, p) for p in path_patterns]
        else:
            queries = [(domain_pattern, None)]

        for domain_q, path_q in queries:
            for file_info in self.parser.list_files(
                domain_filter=domain_q, path_pattern=path_q
            ):
                # Deduplicate across multiple pattern queries
                dedup_key = (
                    file_info.get('domain', ''),
                    file_info.get('relative_path', ''),
                )
                if dedup_key in seen_files:
                    continue
                seen_files.add(dedup_key)

                # Create subdirectory for domain (cached - only once per domain)
                domain = file_info.get('domain', 'unknown')
                domain_key = domain.replace('-', '_').replace('.', '_')
                domain_dir = output_dir / domain_key
                if domain_key not in created_dirs:
                    domain_dir.mkdir(exist_ok=True)
                    created_dirs.add(domain_key)

                rel_path = file_info.get('relative_path', 'unknown')
                filename = _sanitize_filename(Path(rel_path).name)

                # Filter by file extension
                ext = Path(filename).suffix.lower()
                if ext and ext not in allowed_ext:
                    skipped_count += 1
                    continue
                # Block extensionless files (binary caches, LMDB, etc.)
                if not ext:
                    skipped_count += 1
                    continue

                # Prevent filename collisions from different subdirectories
                # e.g. Documents/abc/DB/MM.sqlite vs Documents/def/DB/MM.sqlite
                path_hash = hashlib.sha256(rel_path.encode()).hexdigest()[:12]
                unique_filename = f"{path_hash}_{filename}"
                local_path = domain_dir / unique_filename

                # Rate-limit progress callbacks (every 50 files to avoid UI flood)
                collected_count += 1
                if progress_callback and collected_count % 50 == 1:
                    progress_callback(f"Extracting {artifact_type}: {collected_count} files ({domain}/{filename})")

                # Encrypted backups: use parser.extract_file() (no backup_path key)
                # Unencrypted backups: single-pass copy + SHA256 (avoids double I/O)
                sha256 = hashlib.sha256()
                file_size = 0
                if is_encrypted:
                    if not rel_path or rel_path == 'unknown':
                        continue
                    success = self.parser.extract_file(domain, rel_path, local_path)
                    if not success:
                        continue
                    # Encrypted: extract_file writes the file, compute hash after
                    try:
                        file_size = local_path.stat().st_size
                    except OSError:
                        continue
                    if file_size == 0:
                        continue
                    with open(local_path, 'rb') as f:
                        for chunk in iter(lambda: f.read(65536), b''):
                            sha256.update(chunk)
                else:
                    if 'backup_path' not in file_info:
                        continue
                    source_path = Path(file_info['backup_path'])
                    # Single-pass: copy + hash simultaneously
                    try:
                        with open(source_path, 'rb') as src, open(local_path, 'wb') as dst:
                            for chunk in iter(lambda: src.read(65536), b''):
                                dst.write(chunk)
                                sha256.update(chunk)
                        file_size = local_path.stat().st_size
                    except OSError:
                        continue
                    if file_size == 0:
                        local_path.unlink(missing_ok=True)
                        continue

                yield str(local_path), {
                    'artifact_type': artifact_type,
                    'domain': domain,
                    'original_path': rel_path,
                    'filename': unique_filename,
                    'size': file_size,
                    'sha256': sha256.hexdigest(),
                    'device_name': self.backup_info.device_name,
                    'collected_at': datetime.utcnow().isoformat(),
                }

        if skipped_count > 0:
            _debug_print(f"[iOS] {artifact_type}: skipped {skipped_count} non-forensic/extensionless files")

    def _collect_backup_metadata(
        self,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect backup metadata files"""
        metadata_files = ['Info.plist', 'Manifest.plist', 'Status.plist']

        for filename in metadata_files:
            source_path = self.backup_path / filename
            if not source_path.exists():
                continue

            local_path = output_dir / filename

            if progress_callback:
                progress_callback(f"Copying {filename}")

            try:
                shutil.copy2(source_path, local_path)
            except (FileNotFoundError, OSError) as e:
                _debug_print(f"[iOS] Failed to copy {filename}: {e}")
                continue

            sha256 = hashlib.sha256()
            with open(local_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)

            # Parse plist content
            try:
                with open(local_path, 'rb') as f:
                    content = plistlib.load(f)
            except Exception:
                content = {}

            yield str(local_path), {
                'artifact_type': 'mobile_ios_backup',
                'filename': filename,
                'size': local_path.stat().st_size,
                'sha256': sha256.hexdigest(),
                'content_preview': {
                    k: str(v)[:100] for k, v in list(content.items())[:10]
                },
                'collected_at': datetime.utcnow().isoformat(),
            }

        # Generate Manifest.db diagnostic dump
        yield from self._generate_manifest_diagnostic(output_dir, progress_callback)

    def _generate_manifest_diagnostic(
        self,
        output_dir: Path,
        progress_callback: Optional[Callable[[str], None]]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Generate Manifest.db diagnostic dump.

        Queries all domains/paths from the decrypted Manifest.db and compares
        against configured IOS_ARTIFACT_TYPES to identify path mismatches.
        Outputs a text file uploaded with the collection for debugging.
        """
        if not self.parser:
            return

        if progress_callback:
            progress_callback("Generating Manifest.db diagnostic...")

        lines = []
        lines.append("=" * 80)
        lines.append("iOS Backup Manifest Diagnostic Report")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}Z")
        if self.backup_info:
            lines.append(f"Device: {self.backup_info.device_name}")
            lines.append(f"iOS: {self.backup_info.ios_version}")
            lines.append(f"Encrypted: {self.backup_info.encrypted}")
        lines.append("=" * 80)

        # ── Section 1: Domain summary ──
        domain_stats: Dict[str, int] = {}
        total_files = 0
        try:
            for fi in self.parser.list_files():
                domain = fi.get('domain', 'unknown')
                domain_stats[domain] = domain_stats.get(domain, 0) + 1
                total_files += 1
        except Exception as e:
            lines.append(f"\n[ERROR] Failed to list manifest files: {e}")
            # Still try to write what we have

        lines.append(f"\n{'─' * 80}")
        lines.append(f"SECTION 1: Backup Domain Summary ({total_files} total files)")
        lines.append(f"{'─' * 80}")
        for domain in sorted(domain_stats.keys()):
            lines.append(f"  {domain:<60} {domain_stats[domain]:>6} files")

        # ── Section 2: Per-artifact path verification ──
        lines.append(f"\n{'─' * 80}")
        lines.append("SECTION 2: Artifact Path Verification")
        lines.append(f"{'─' * 80}")
        lines.append(f"  {'Artifact Type':<45} {'Status':<12} {'Details'}")
        lines.append(f"  {'─' * 75}")

        found_count = 0
        missing_count = 0
        app_missing_count = 0

        for atype, ainfo in sorted(IOS_ARTIFACT_TYPES.items()):
            # Skip device-only and special artifacts
            if ainfo.get('requires_device') or ainfo.get('collection_method') == 'device':
                continue
            if atype == 'mobile_ios_backup':
                continue

            domain = ainfo.get('manifest_domain', '')
            if not domain:
                continue

            # Gather configured paths
            paths = []
            if 'manifest_paths' in ainfo:
                paths = list(ainfo['manifest_paths'])
            elif 'manifest_path' in ainfo:
                paths = [ainfo['manifest_path']]

            if not paths:
                # Pattern-only artifact
                file_count = domain_stats.get(domain, 0)
                if file_count > 0:
                    lines.append(f"  {atype:<45} {'FOUND':<12} domain={domain} ({file_count} files)")
                    found_count += 1
                else:
                    lines.append(f"  {atype:<45} {'MISSING':<12} domain={domain} not in backup")
                    missing_count += 1
                continue

            # Check each configured path
            any_found = False
            for path in paths:
                # Check if path exists in manifest
                matches = 0
                try:
                    for _ in self.parser.list_files(domain_filter=domain, path_pattern=path):
                        matches += 1
                        if matches >= 1:
                            break
                except Exception:
                    pass

                if matches > 0:
                    any_found = True

            if any_found:
                lines.append(f"  {atype:<45} {'OK':<12} {domain} / {paths[0][:40]}")
                found_count += 1
            else:
                # Check if domain exists at all
                domain_file_count = domain_stats.get(domain, 0)
                if domain_file_count == 0:
                    # Domain not present — likely app not installed
                    is_app = domain.startswith('AppDomain')
                    label = 'APP_MISSING' if is_app else 'MISSING'
                    lines.append(f"  {atype:<45} {label:<12} domain={domain} not in backup")
                    if is_app:
                        app_missing_count += 1
                    else:
                        missing_count += 1
                else:
                    # Domain exists but configured path not found — PATH MISMATCH
                    lines.append(f"  {atype:<45} {'PATH_ERR':<12} domain has {domain_file_count} files but path not found")
                    missing_count += 1

                    # List actual files in domain for diagnostic (up to 20)
                    try:
                        actual_files = []
                        for fi in self.parser.list_files(domain_filter=domain):
                            actual_files.append(fi.get('relative_path', '?'))
                            if len(actual_files) >= 20:
                                break
                        if actual_files:
                            lines.append(f"    Configured: {', '.join(paths[:3])}")
                            lines.append(f"    Actual files in domain ({min(domain_file_count, 20)} shown):")
                            for af in actual_files:
                                lines.append(f"      - {af}")
                    except Exception:
                        pass

        lines.append(f"\n{'─' * 80}")
        lines.append(f"SUMMARY: {found_count} OK, {missing_count} path errors/missing, {app_missing_count} apps not installed")
        lines.append(f"{'─' * 80}")

        # ── Section 3: System domain file listing (for troubleshooting) ──
        system_domains = ['HomeDomain', 'RootDomain', 'SystemPreferencesDomain',
                          'HealthDomain', 'MediaDomain', 'WirelessDomain',
                          'KeychainDomain', 'CameraRollDomain',
                          'AppDomainGroup-group.com.apple.notes']
        lines.append(f"\n{'─' * 80}")
        lines.append("SECTION 3: System Domain File Listings (for path troubleshooting)")
        lines.append(f"{'─' * 80}")

        for sd in system_domains:
            if sd not in domain_stats:
                lines.append(f"\n  [{sd}] — NOT PRESENT")
                continue

            lines.append(f"\n  [{sd}] — {domain_stats[sd]} files:")
            try:
                file_list = []
                for fi in self.parser.list_files(domain_filter=sd):
                    file_list.append(fi.get('relative_path', '?'))
                # Sort and show up to 100 files
                for fp in sorted(file_list)[:100]:
                    lines.append(f"    {fp}")
                if len(file_list) > 100:
                    lines.append(f"    ... and {len(file_list) - 100} more files")
            except Exception as e:
                lines.append(f"    [ERROR listing files: {e}]")

        # Write diagnostic file
        report_content = '\n'.join(lines)
        diag_path = output_dir / 'manifest_diagnostic.txt'
        try:
            with open(diag_path, 'w', encoding='utf-8') as f:
                f.write(report_content)

            sha256 = hashlib.sha256(report_content.encode('utf-8')).hexdigest()

            logger.info(f"[iOS] Manifest diagnostic: {found_count} OK, {missing_count} errors, {app_missing_count} apps N/A")

            yield str(diag_path), {
                'artifact_type': 'mobile_ios_backup',
                'filename': 'manifest_diagnostic.txt',
                'size': diag_path.stat().st_size,
                'sha256': sha256,
                'diagnostic_summary': {
                    'total_manifest_files': total_files,
                    'total_domains': len(domain_stats),
                    'artifacts_ok': found_count,
                    'artifacts_path_error': missing_count,
                    'artifacts_app_missing': app_missing_count,
                },
                'collected_at': datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.warning(f"[iOS] Failed to write manifest diagnostic: {e}")

    def get_available_artifacts(self) -> List[Dict[str, Any]]:
        """Get list of available iOS artifact types"""
        artifacts = []
        backup_available = self.backup_info is not None
        encrypted = self.backup_info.encrypted if self.backup_info else False
        has_decryptor = bool(self._encrypted_backup)

        for type_id, info in IOS_ARTIFACT_TYPES.items():
            available = backup_available and (not encrypted or has_decryptor)
            reasons = []

            if not backup_available:
                available = False
                reasons.append('Backup selection required')

            if encrypted and not has_decryptor:
                available = False
                reasons.append('Encrypted backup - password required')

            artifacts.append({
                'type': type_id,
                'name': info['name'],
                'description': info['description'],
                'available': available,
                'reasons': reasons,
            })

        return artifacts


def get_backup_guide() -> str:
    """Return iOS backup creation guide"""
    return """
iOS Backup Creation Guide (iTunes/Finder):

=== Windows (iTunes) ===
1. Update iTunes to the latest version
2. Connect iPhone via Lightning/USB-C cable
3. Select "Trust" on the "Trust This Computer" popup
4. Click the device icon in iTunes
5. In the "Summary" tab:
   - Select "This computer" (not iCloud backup)
   - Enable "Encrypt local backup" when authorized and record the password
   - Click "Back Up Now"
6. Wait for backup to complete (minutes to tens of minutes depending on data)

=== macOS (Finder) - macOS Catalina or later ===
1. Connect iPhone via Lightning/USB-C cable
2. Select iPhone in Finder (sidebar)
3. In the "General" tab:
   - "Back up all of the data on your iPhone to this Mac"
   - Enable "Encrypt local backup" when authorized and record the password
   - Click "Back Up Now"

=== Backup File Locations ===
Windows:
  %APPDATA%\\Apple Computer\\MobileSync\\Backup\\

macOS:
  ~/Library/Application Support/MobileSync/Backup/

=== Important Notes ===
- Encrypted backups preserve more forensic data classes, including protected data
- Encrypted backups cannot be analyzed without the password
- Unencrypted backups are still supported, but may contain less data
- Backup size: Similar storage space as device data required
- Do not disconnect cable during backup
- iCloud backups cannot be analyzed with this tool (local backups only)

=== Troubleshooting ===
- "Trust This Computer" popup not appearing:
  -> Unlock device and reconnect
  -> Settings > General > Reset > Reset Location & Privacy

- Backup failure:
  -> Check disk space (need more than backup size)
  -> Try different USB cable and port
  -> Restart iTunes/Finder
"""


if __name__ == "__main__":
    print("iOS Forensics Collector")
    print("=" * 50)

    print("\n[Available Backups]")
    backups = find_ios_backups()

    if backups:
        for backup in backups:
            encrypted_str = " [ENCRYPTED]" if backup.encrypted else ""
            print(f"\n  {backup.device_name}{encrypted_str}")
            print(f"    ID: {backup.device_id}")
            print(f"    Model: {backup.product_type}")
            print(f"    iOS: {backup.ios_version}")
            print(f"    Date: {backup.backup_date}")
            print(f"    Size: {backup.size_mb} MB")
            print(f"    Path: {backup.path}")
    else:
        print("  No iOS backups found.")
        print("\n[Backup Locations Searched]")
        for loc in get_backup_locations():
            print(f"  - {loc}")

        print("\n[How to Create Backup]")
        print(get_backup_guide())
