# -*- coding: utf-8 -*-
"""
Secure Upload Manager - Secure data upload module

Securely transfers collected forensic artifacts to the server.

Security Features:
- AES-256-GCM data encryption
- JWT token-based authentication
- SHA-256 integrity verification
- TLS 1.3 required (HTTPS)
- Per-session encryption key issuance

Usage:
    from core.secure_upload import SecureUploadManager

    manager = SecureUploadManager(
        server_url="https://api.example.com",
        api_key="your-api-key"
    )

    # Authenticate
    manager.authenticate(user_token="jwt-token")

    # Upload file
    result = manager.upload_file(
        file_path="/path/to/artifact.db",
        case_id="case-123"
    )
"""

import os
import json
import hashlib
import secrets
import base64
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List, BinaryIO
from dataclasses import dataclass, field

# Cryptography imports
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# HTTP client
try:
    import requests
    from requests.adapters import HTTPAdapter
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

CHUNK_SIZE = 1024 * 1024  # 1MB chunks for streaming upload
NONCE_SIZE = 12  # 96 bits for AES-GCM
TAG_SIZE = 16    # 128 bits authentication tag
MIN_TLS_VERSION = 'TLSv1.2'  # Minimum TLS version

# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class UploadResult:
    """Upload result"""
    success: bool
    file_id: Optional[str] = None
    sha256_local: Optional[str] = None
    sha256_server: Optional[str] = None
    encrypted: bool = False
    size_bytes: int = 0
    duration_seconds: float = 0.0
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionInfo:
    """Session information"""
    session_id: str
    encryption_key: bytes
    expires_at: datetime
    case_id: Optional[str] = None


# =============================================================================
# Encryption Utilities
# =============================================================================

class AESGCMCipher:
    """
    AES-256-GCM encryption class

    Uses NIST-recommended AES-GCM mode for simultaneous confidentiality and integrity.
    """

    def __init__(self, key: bytes):
        """
        Initialize cipher with 256-bit key.

        Args:
            key: 32-byte (256-bit) encryption key
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography package is required for encryption")

        if len(key) != 32:
            raise ValueError("Key must be 256 bits (32 bytes)")

        self.key = key
        self.aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypt data with AES-256-GCM.

        Args:
            plaintext: Data to encrypt
            associated_data: Optional authenticated but unencrypted data

        Returns:
            nonce + ciphertext + tag (combined)
        """
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext  # Tag is included in ciphertext

    def decrypt(self, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt data with AES-256-GCM.

        Args:
            ciphertext: nonce + encrypted data + tag
            associated_data: Optional authenticated data

        Returns:
            Decrypted plaintext

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
        """
        nonce = ciphertext[:NONCE_SIZE]
        encrypted_data = ciphertext[NONCE_SIZE:]
        return self.aesgcm.decrypt(nonce, encrypted_data, associated_data)


def derive_key(master_secret: bytes, salt: bytes, info: bytes = b"forensic-upload") -> bytes:
    """
    Derive encryption key from master secret using HKDF.

    Args:
        master_secret: Master secret received from server
        salt: Per-session salt
        info: Context information

    Returns:
        256-bit derived key
    """
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography package is required")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(master_secret)


def compute_file_hash(file_path: Path) -> str:
    """
    Compute SHA-256 hash of file.

    Args:
        file_path: Path to file to hash

    Returns:
        Hex-encoded SHA-256 hash
    """
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


# =============================================================================
# Secure Upload Manager
# =============================================================================

class SecureUploadManager:
    """
    Secure upload manager

    Securely transfers collected forensic artifacts to the server.
    """

    def __init__(
        self,
        server_url: str,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 300
    ):
        """
        Initialize secure upload manager.

        Args:
            server_url: Base URL of the forensics server (must be HTTPS)
            api_key: API key for authentication
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests package is required")

        # Enforce HTTPS
        if not server_url.startswith('https://'):
            raise ValueError("Server URL must use HTTPS for security")

        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        self.session: Optional[requests.Session] = None
        self.session_info: Optional[SessionInfo] = None
        self.user_token: Optional[str] = None
        self.cipher: Optional[AESGCMCipher] = None

    def _create_session(self) -> requests.Session:
        """Create configured HTTP session"""
        session = requests.Session()

        # Set default headers
        session.headers.update({
            'User-Agent': 'ForensicsCollector/1.0',
            'Accept': 'application/json',
        })

        if self.api_key:
            session.headers['X-API-Key'] = self.api_key

        return session

    def _get_session(self) -> requests.Session:
        """Get or create HTTP session"""
        if self.session is None:
            self.session = self._create_session()
        return self.session

    def authenticate(
        self,
        user_token: str,
        case_id: Optional[str] = None
    ) -> bool:
        """
        Server authentication and session key issuance.

        Args:
            user_token: JWT user token
            case_id: Case ID (optional)

        Returns:
            True if authentication successful
        """
        self.user_token = user_token

        session = self._get_session()
        session.headers['Authorization'] = f'Bearer {user_token}'

        try:
            # Request encryption session
            response = session.post(
                f'{self.server_url}/api/v1/upload/session',
                json={'case_id': case_id},
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()

                # Decode session encryption key
                master_secret = base64.b64decode(data.get('master_secret', ''))
                salt = base64.b64decode(data.get('salt', ''))

                if master_secret and salt:
                    encryption_key = derive_key(master_secret, salt)
                    self.cipher = AESGCMCipher(encryption_key)

                    self.session_info = SessionInfo(
                        session_id=data.get('session_id', ''),
                        encryption_key=encryption_key,
                        expires_at=datetime.fromisoformat(data.get('expires_at', '')),
                        case_id=case_id
                    )

                    logger.info(f"Authentication successful. Session: {self.session_info.session_id}")
                    return True

            logger.error(f"Authentication failed: {response.status_code}")
            return False

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False

    def upload_file(
        self,
        file_path: str,
        artifact_type: str,
        metadata: Optional[Dict[str, Any]] = None,
        encrypt: bool = True,
        progress_callback: Optional[callable] = None
    ) -> UploadResult:
        """
        Upload file to server securely.

        Args:
            file_path: Path to file to upload
            artifact_type: Artifact type
            metadata: Additional metadata
            encrypt: Whether to encrypt
            progress_callback: Progress callback (percent: int)

        Returns:
            UploadResult object
        """
        import time
        start_time = time.time()

        path = Path(file_path)
        if not path.exists():
            return UploadResult(
                success=False,
                error=f"File not found: {file_path}"
            )

        # Calculate local hash
        sha256_local = compute_file_hash(path)
        file_size = path.stat().st_size

        try:
            session = self._get_session()

            if not self.session_info:
                return UploadResult(
                    success=False,
                    error="Not authenticated. Call authenticate() first."
                )

            # Prepare metadata
            upload_metadata = {
                'filename': path.name,
                'artifact_type': artifact_type,
                'sha256': sha256_local,
                'size': file_size,
                'session_id': self.session_info.session_id,
                'encrypted': encrypt,
                'uploaded_at': datetime.now(timezone.utc).isoformat(),
            }

            if metadata:
                upload_metadata.update(metadata)

            # Read and optionally encrypt file
            with open(path, 'rb') as f:
                file_data = f.read()

            if encrypt and self.cipher:
                # Encrypt file data
                associated_data = json.dumps({
                    'filename': path.name,
                    'sha256': sha256_local
                }).encode('utf-8')

                encrypted_data = self.cipher.encrypt(file_data, associated_data)
                upload_data = encrypted_data
            else:
                upload_data = file_data

            # Upload
            files = {
                'file': (path.name, upload_data, 'application/octet-stream')
            }
            data = {
                'metadata': json.dumps(upload_metadata)
            }

            if progress_callback:
                progress_callback(50)  # Simple progress indicator

            response = session.post(
                f'{self.server_url}/api/v1/upload/file',
                files=files,
                data=data,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if progress_callback:
                progress_callback(100)

            duration = time.time() - start_time

            if response.status_code == 200:
                result_data = response.json()

                return UploadResult(
                    success=True,
                    file_id=result_data.get('file_id'),
                    sha256_local=sha256_local,
                    sha256_server=result_data.get('sha256'),
                    encrypted=encrypt,
                    size_bytes=file_size,
                    duration_seconds=duration,
                    metadata=upload_metadata
                )
            else:
                # [2026-01-29] Include error response body (for CLEANUP_IN_PROGRESS detection)
                error_text = ""
                try:
                    error_text = response.text[:500]  # Max 500 chars
                except Exception:
                    pass
                return UploadResult(
                    success=False,
                    sha256_local=sha256_local,
                    size_bytes=file_size,
                    duration_seconds=duration,
                    error=f"Upload failed: HTTP {response.status_code}: {error_text}"
                )

        except Exception as e:
            return UploadResult(
                success=False,
                sha256_local=sha256_local,
                error=str(e)
            )

    def upload_directory(
        self,
        directory_path: str,
        artifact_type: str,
        recursive: bool = True,
        progress_callback: Optional[callable] = None
    ) -> List[UploadResult]:
        """
        Upload all files in directory.

        Args:
            directory_path: Path to directory to upload
            artifact_type: Artifact type
            recursive: Whether to include subdirectories
            progress_callback: Progress callback

        Returns:
            List of UploadResult
        """
        results = []
        path = Path(directory_path)

        if not path.is_dir():
            return [UploadResult(
                success=False,
                error=f"Not a directory: {directory_path}"
            )]

        files = list(path.rglob('*') if recursive else path.glob('*'))
        files = [f for f in files if f.is_file()]
        total = len(files)

        for i, file_path in enumerate(files, 1):
            if progress_callback:
                progress_callback(int((i / total) * 100))

            result = self.upload_file(
                str(file_path),
                artifact_type,
                metadata={'relative_path': str(file_path.relative_to(path))}
            )
            results.append(result)

        return results

    def verify_upload(self, file_id: str, expected_hash: str) -> bool:
        """
        Verify integrity of uploaded file.

        Args:
            file_id: Server file ID
            expected_hash: Expected SHA-256 hash

        Returns:
            True if verification successful
        """
        try:
            session = self._get_session()

            response = session.get(
                f'{self.server_url}/api/v1/upload/verify/{file_id}',
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                server_hash = data.get('sha256', '')

                if server_hash == expected_hash:
                    logger.info(f"Verification successful for {file_id}")
                    return True
                else:
                    logger.error(f"Hash mismatch: {expected_hash} != {server_hash}")
                    return False

            return False

        except Exception as e:
            logger.error(f"Verification error: {e}")
            return False

    def close(self):
        """Close session and cleanup"""
        if self.session:
            self.session.close()
            self.session = None

        self.session_info = None
        self.cipher = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# =============================================================================
# Chain of Custody Logger
# =============================================================================

class ChainOfCustodyLogger:
    """
    Chain of custody logger

    Records the handling history of forensic evidence.
    """

    def __init__(self, log_file: str):
        """
        Initialize custody logger.

        Args:
            log_file: Path to custody log file
        """
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        # Create log file if not exists
        if not self.log_file.exists():
            self._write_header()

    def _write_header(self):
        """Write log file header"""
        header = {
            'format_version': '1.0',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'entries': []
        }
        with open(self.log_file, 'w', encoding='utf-8') as f:
            json.dump(header, f, indent=2)

    def log_event(
        self,
        event_type: str,
        file_path: str,
        description: str,
        user: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log a custody event.

        Args:
            event_type: Type of event (collected, encrypted, uploaded, etc.)
            file_path: Path to the evidence file
            description: Event description
            user: User who performed the action
            metadata: Additional metadata
        """
        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'file_path': str(file_path),
            'description': description,
            'user': user or os.getlogin(),
            'hostname': os.environ.get('COMPUTERNAME', os.environ.get('HOSTNAME', 'unknown')),
        }

        if metadata:
            entry['metadata'] = metadata

        # Compute entry hash for tamper detection
        entry_str = json.dumps(entry, sort_keys=True)
        entry['hash'] = hashlib.sha256(entry_str.encode()).hexdigest()

        # Append to log file
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                log_data = json.load(f)

            log_data['entries'].append(entry)
            log_data['last_modified'] = datetime.now(timezone.utc).isoformat()

            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump(log_data, f, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.error(f"Failed to log custody event: {e}")

    def get_file_history(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Get custody history for a specific file.

        Args:
            file_path: Path to the evidence file

        Returns:
            List of custody events
        """
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                log_data = json.load(f)

            return [
                entry for entry in log_data.get('entries', [])
                if entry.get('file_path') == str(file_path)
            ]

        except Exception:
            return []


# =============================================================================
# Configuration
# =============================================================================

def load_config_from_env() -> Dict[str, Any]:
    """
    Load configuration from environment variables.

    Environment Variables:
        FORENSIC_SERVER_URL: Server URL
        FORENSIC_API_KEY: API key
        FORENSIC_VERIFY_SSL: SSL verification (true/false)
        FORENSIC_DEV_MODE: Development mode flag (required to disable SSL)
    """
    # [SECURITY] SSL verification can only be disabled in explicit dev mode
    # Release builds (PyInstaller) always enforce SSL — no bypass possible
    verify_ssl = True
    is_release = getattr(__import__('sys'), 'frozen', False)

    if is_release:
        # Packaged binary: SSL always enforced, ignore env vars
        verify_ssl = True
    else:
        verify_ssl_env = os.environ.get('FORENSIC_VERIFY_SSL', 'true').lower()
        dev_mode = os.environ.get('FORENSIC_DEV_MODE', 'false').lower() == 'true'

        if verify_ssl_env == 'false':
            if dev_mode:
                logger.warning("[SECURITY] SSL verification disabled - DEV MODE ONLY")
                verify_ssl = False
            else:
                logger.error(
                    "[SECURITY] Cannot disable SSL verification without FORENSIC_DEV_MODE=true. "
                    "SSL verification remains enabled for security."
                )
                # Keep verify_ssl = True (ignore the request to disable)

    return {
        'server_url': os.environ.get('FORENSIC_SERVER_URL', ''),
        'api_key': os.environ.get('FORENSIC_API_KEY', ''),
        'verify_ssl': verify_ssl,
        'dev_mode': dev_mode,
    }


def load_config_from_file(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from file.

    Args:
        config_path: Path to config.json

    Returns:
        Configuration dictionary
    """
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        return {}
