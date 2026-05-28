# -*- coding: utf-8 -*-
"""
iOS Encrypted Backup Decryptor

Adapter that wraps iphone_backup_decrypt to provide the same interface
as iOSBackupParser for encrypted iOS backups.

Security model:
    - Password is used client-side only (zero-knowledge)
    - EncryptedBackup created once per collection (single key derivation)
    - Password never stored beyond EncryptedBackup creation scope
    - Temp files cleaned up via close() + atexit fallback

Key derivation may take ~50-150s depending on iOS version and hardware

Requirements:
    - iphone_backup_decrypt>=0.6.0 (MIT license)
"""

import atexit
import sqlite3
import logging
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Dict, Any, Generator

logger = logging.getLogger(__name__)

# Check availability
IPHONE_BACKUP_DECRYPT_AVAILABLE = False
try:
    from iphone_backup_decrypt import EncryptedBackup
    IPHONE_BACKUP_DECRYPT_AVAILABLE = True
except ImportError:
    pass


# ============================================================================
# Global temp directory cleanup (atexit fallback)
# ============================================================================

_temp_dirs_to_cleanup: list = []


def _cleanup_temp_dirs():
    """atexit handler: remove any leftover temp directories."""
    for d in _temp_dirs_to_cleanup:
        try:
            if isinstance(d, Path) and d.exists():
                shutil.rmtree(d)
        except Exception:
            pass
    _temp_dirs_to_cleanup.clear()


atexit.register(_cleanup_temp_dirs)


# ============================================================================
# Encrypted Backup Parser
# ============================================================================

class iOSEncryptedBackupParser:
    """
    Encrypted iOS backup parser.

    Wraps a pre-created EncryptedBackup instance to provide the same
    interface as iOSBackupParser (extract_file, list_files, get_file_hash).

    IMPORTANT: The EncryptedBackup must be created in the SAME thread
    that calls extract_file/list_files (sqlite3 thread-safety).
    """

    def __init__(self, backup_path: Path, encrypted_backup):
        """
        Initialize with a pre-verified EncryptedBackup instance.

        Args:
            backup_path: Path to iOS backup directory
            encrypted_backup: Pre-created EncryptedBackup instance
                (created via create_encrypted_backup())
        """
        self.backup_path = Path(backup_path)
        self.backup = encrypted_backup
        self._temp_dir = None
        self._manifest_db_path = None
        self._prepare_manifest()

    def _prepare_manifest(self):
        """Extract decrypted Manifest.db using public API (save_manifest_file)."""
        try:
            self._temp_dir = Path(tempfile.mkdtemp(prefix='ios_edecrypt_'))
            _temp_dirs_to_cleanup.append(self._temp_dir)

            manifest_dest = self._temp_dir / 'Manifest.db'

            # Use public API: save_manifest_file() (iphone_backup_decrypt >=0.5)
            if hasattr(self.backup, 'save_manifest_file'):
                self.backup.save_manifest_file(str(manifest_dest))

            if manifest_dest.exists() and manifest_dest.stat().st_size > 0:
                self._manifest_db_path = manifest_dest
                logger.debug(f"[iOS Decrypt] Manifest.db extracted ({manifest_dest.stat().st_size} bytes)")
            else:
                logger.warning("[iOS Decrypt] save_manifest_file() produced no output")

        except Exception as e:
            logger.warning(f"[iOS Decrypt] Manifest extraction failed: {e}")

    def extract_file(self, domain: str, relative_path: str, output_path: Path) -> bool:
        """
        Extract a specific file from encrypted backup.

        Args:
            domain: File domain (e.g., 'HomeDomain')
            relative_path: Relative path within domain
            output_path: Where to save the extracted file

        Returns:
            True if extraction successful
        """
        try:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # iphone_backup_decrypt API uses 'domain_like' (not 'domain')
            self.backup.extract_file(
                relative_path=relative_path,
                domain_like=domain,
                output_filename=str(output_path)
            )

            return output_path.exists() and output_path.stat().st_size > 0

        except Exception as e:
            logger.debug(f"[iOS Decrypt] Extract failed {domain}/{relative_path}: {e}")
            return False

    def list_files(
        self,
        domain_filter: Optional[str] = None,
        path_pattern: Optional[str] = None
    ) -> Generator[Dict[str, Any], None, None]:
        """
        List files in encrypted backup matching filters.

        Creates a fresh sqlite3 connection each call for thread-safety.

        Args:
            domain_filter: Filter by domain (supports * wildcard)
            path_pattern: Filter by path (supports * wildcard)

        Yields:
            File information dictionaries (no 'backup_path' key -
            callers must use extract_file() for encrypted backups)
        """
        if not self._manifest_db_path:
            logger.warning("[iOS Decrypt] No manifest available, cannot list files")
            return

        conn = None
        try:
            # Fresh connection each call (thread-safe)
            conn = sqlite3.connect(str(self._manifest_db_path), check_same_thread=False)
            cursor = conn.cursor()

            query = 'SELECT fileID, domain, relativePath, flags FROM Files WHERE 1=1'
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

            cursor.execute(query, params)

            for row in cursor:
                file_id, domain, rel_path, flags = row
                yield {
                    'file_id': file_id,
                    'domain': domain,
                    'relative_path': rel_path,
                    'flags': flags,
                    # NOTE: No 'backup_path' key for encrypted backups.
                    # Callers must use extract_file(domain, rel_path, output).
                }

        except Exception as e:
            logger.debug(f"[iOS Decrypt] Error listing files: {e}")
        finally:
            if conn:
                conn.close()

    def get_file_hash(self, domain: str, relative_path: str) -> Optional[str]:
        """
        Get file hash (fileID) for a domain/path combination.

        Args:
            domain: File domain (e.g., 'HomeDomain')
            relative_path: Relative path within domain

        Returns:
            SHA1 hash (fileID) or None if not found
        """
        if not self._manifest_db_path:
            return None

        conn = None
        try:
            conn = sqlite3.connect(str(self._manifest_db_path), check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute(
                'SELECT fileID FROM Files WHERE domain = ? AND relativePath = ?',
                (domain, relative_path)
            )
            row = cursor.fetchone()
            return row[0] if row else None
        except Exception:
            return None
        finally:
            if conn:
                conn.close()

    def close(self):
        """Clean up temporary files and release EncryptedBackup."""
        if self._temp_dir and self._temp_dir.exists():
            try:
                shutil.rmtree(self._temp_dir)
            except Exception:
                pass
            # Remove from global cleanup list
            if self._temp_dir in _temp_dirs_to_cleanup:
                _temp_dirs_to_cleanup.remove(self._temp_dir)
            self._temp_dir = None
            self._manifest_db_path = None

        self.backup = None


# ============================================================================
# Factory function - creates EncryptedBackup (key derivation)
# ============================================================================

def create_encrypted_backup(backup_path: str, password: str) -> tuple:
    """
    Create an EncryptedBackup instance (performs key derivation).

    This is the ONLY place where the password is consumed.
    Caller should discard the password after this call returns.

    iOS 10.2+ key derivation takes 50-150 seconds.

    Args:
        backup_path: Path to iOS backup directory
        password: Backup encryption password

    Returns:
        (EncryptedBackup_or_None, error_message: str)
    """
    if not IPHONE_BACKUP_DECRYPT_AVAILABLE:
        return None, (
            "iphone_backup_decrypt is not installed.\n"
            "Install with: pip install iphone_backup_decrypt"
        )

    try:
        backup = EncryptedBackup(
            backup_directory=str(backup_path),
            passphrase=password
        )
        return backup, ""

    except Exception as e:
        # Sanitize error message - don't expose internal paths or stack traces
        error_str = str(e).lower()
        if 'password' in error_str or 'wrong' in error_str or 'incorrect' in error_str:
            return None, "Incorrect password"
        elif 'not encrypted' in error_str:
            return None, "Backup is not encrypted"
        elif 'manifest' in error_str:
            return None, "Invalid backup format"
        else:
            return None, "Password verification failed"
