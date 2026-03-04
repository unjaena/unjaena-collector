"""
Real-time Upload Module

Handles file uploads with WebSocket progress reporting.
P2-2: User-friendly error message support
"""
import asyncio
import json
import aiohttp
import websockets
import requests  # For synchronous upload
from pathlib import Path
from datetime import datetime
from typing import Callable, Optional
from dataclasses import dataclass
import os

from utils.error_messages import translate_error, UserFriendlyError

import logging
import re

logger = logging.getLogger(__name__)


def _sanitize_error_for_logging(error_text: str, max_length: int = 200) -> str:
    """
    [SECURITY] Sanitize error messages before logging to prevent sensitive data exposure.

    Removes or masks:
    - SQL queries and database errors
    - Stack traces with file paths
    - API keys and tokens
    - Internal IP addresses and hostnames
    """
    if not error_text:
        return "(empty)"

    sanitized = error_text

    # Mask potential SQL content
    if re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b', sanitized, re.IGNORECASE):
        sanitized = "[SQL content redacted]"

    # Mask stack traces
    elif 'Traceback' in sanitized or 'File "' in sanitized:
        sanitized = "[Stack trace redacted]"

    # Mask potential tokens/keys (long alphanumeric strings)
    sanitized = re.sub(r'[a-zA-Z0-9_-]{32,}', '[REDACTED]', sanitized)

    # Mask internal paths
    sanitized = re.sub(r'(/[a-zA-Z0-9_.-]+){3,}', '[PATH]', sanitized)
    sanitized = re.sub(r'[A-Z]:\\[^\s]+', '[PATH]', sanitized)

    # Truncate
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."

    return sanitized


@dataclass
class UploadResult:
    """Upload result (P2-2: Extended error information)"""
    success: bool
    artifact_id: Optional[str] = None
    error: Optional[str] = None
    error_title: Optional[str] = None      # P2-2: User-friendly error title
    error_solution: Optional[str] = None   # P2-2: Solution/resolution
    is_recoverable: bool = True            # P2-2: Whether retry is possible

    @classmethod
    def from_error(cls, technical_error: str) -> 'UploadResult':
        """Create UploadResult preserving original error for debugging"""
        friendly = translate_error(technical_error)
        return cls(
            success=False,
            # Preserve original technical error for log display
            error=technical_error,
            error_title=friendly.title,
            error_solution=friendly.solution,
            is_recoverable=friendly.is_recoverable,
        )


class RealTimeUploader:
    """
    Real-time file uploader with WebSocket progress.

    Uploads encrypted files to the forensics server while
    reporting progress via WebSocket connection.
    """

    # M2 Security: Default maximum file size (10GB)
    DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB

    def __init__(
        self,
        server_url: str,
        ws_url: str,
        session_id: str,
        collection_token: str,
        case_id: str = None,
        consent_record: dict = None,
        max_file_size: int = None,
        config: dict = None,
        request_signer=None,
    ):
        """
        Initialize the uploader.

        Args:
            server_url: HTTP server URL (e.g., http://localhost:8000)
            ws_url: WebSocket URL (e.g., ws://localhost:8000)
            session_id: Collection session ID
            collection_token: Authentication token for uploads
            case_id: Case ID for the collection
            consent_record: Legal consent record (P0 legally required)
            max_file_size: Maximum file size in bytes (M2 security)
            config: Application config (for dev_mode flag)
            request_signer: RequestSigner instance for HMAC signing (optional)
        """
        self.server_url = server_url.rstrip('/')
        self.ws_url = ws_url.rstrip('/')
        self.session_id = session_id
        self.collection_token = collection_token
        self.case_id = case_id
        self.consent_record = consent_record
        self.max_file_size = max_file_size or self.DEFAULT_MAX_FILE_SIZE
        self._dev_mode = config.get('dev_mode', False) if config else False
        self.request_signer = request_signer
        self.ws = None

    async def connect_websocket(self):
        """Establish WebSocket connection for progress reporting."""
        import ssl
        import logging

        try:
            ws_endpoint = f"{self.ws_url}/ws/collection/{self.session_id}"
            extra_headers = {
                'X-Collection-Token': self.collection_token,
            }

            # [Security] SSL certificate verification for WSS connections
            ssl_context = None
            if ws_endpoint.startswith('wss://'):
                ssl_context = ssl.create_default_context()
                # Certificate verification is required in production environment
                ssl_context.check_hostname = True
                ssl_context.verify_mode = ssl.CERT_REQUIRED
            elif not self._dev_mode:
                logging.getLogger(__name__).warning(
                    "[SECURITY] Unencrypted WebSocket (ws://) in non-dev mode"
                )

            self.ws = await websockets.connect(
                ws_endpoint,
                extra_headers=extra_headers,
                ssl=ssl_context
            )
            logging.getLogger(__name__).info(f"[WebSocket] Connected to {ws_endpoint[:50]}...")
        except ssl.SSLError as ssl_err:
            logging.getLogger(__name__).error(f"[WebSocket] SSL error: {ssl_err}")
            print(f"WebSocket SSL authentication failed - please verify server certificate")
            self.ws = None
        except Exception as e:
            logging.getLogger(__name__).warning(f"[WebSocket] Connection failed: {e}")
            print(f"WebSocket connection failed: {e}")
            self.ws = None

    async def disconnect_websocket(self):
        """Close WebSocket connection."""
        if self.ws:
            await self.ws.close()
            self.ws = None

    async def send_progress(
        self,
        progress: float,
        message: str,
        current_file: str = None,
    ):
        """
        Send progress update via WebSocket.

        Args:
            progress: Progress percentage (0.0 - 1.0)
            message: Status message
            current_file: Current file being processed
        """
        if self.ws:
            try:
                await self.ws.send(json.dumps({
                    'type': 'progress',
                    'progress': progress,
                    'message': message,
                    'current_file': current_file,
                    'timestamp': datetime.utcnow().isoformat(),
                }))
            except Exception as e:
                print(f"Failed to send progress: {e}")

    async def upload_file(
        self,
        file_path: str,
        artifact_type: str,
        metadata: dict,
        progress_callback: Callable[[float], None] = None,
    ) -> UploadResult:
        """
        Upload a single file to the server.

        Args:
            file_path: Path to the encrypted file
            artifact_type: Type of artifact (e.g., 'prefetch', 'eventlog')
            metadata: File metadata
            progress_callback: Optional callback for upload progress

        Returns:
            UploadResult with status
        """
        # M2 Security: File size validation (prevent storage exhaustion)
        import os
        try:
            file_size = os.path.getsize(file_path)
        except OSError as e:
            return UploadResult.from_error(f"Cannot access file: {e}")

        if file_size > self.max_file_size:
            max_size_gb = self.max_file_size / (1024 * 1024 * 1024)
            file_size_gb = file_size / (1024 * 1024 * 1024)
            return UploadResult(
                success=False,
                error=f"File size ({file_size_gb:.2f}GB) exceeds maximum allowed size ({max_size_gb:.1f}GB).",
                error_title="File Size Exceeded",
                error_solution="Split the file or contact the administrator.",
                is_recoverable=False,
            )

        if file_size == 0:
            return UploadResult(
                success=False,
                error="Empty files cannot be uploaded.",
                error_title="Empty File",
                error_solution="Please verify the file contents.",
                is_recoverable=False,
            )

        try:
            # Dynamic timeout calculation based on file size (min 5 min, max 30 min)
            # Assuming 10MB/s upload speed + 2 min buffer time
            upload_timeout = max(300, min(1800, (file_size / (10 * 1024 * 1024)) + 120))
            timeout = aiohttp.ClientTimeout(total=upload_timeout)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                with open(file_path, 'rb') as f:
                    data = aiohttp.FormData()
                    data.add_field(
                        'file',
                        f,
                        filename=Path(file_path).name,
                        content_type='application/octet-stream'
                    )
                    data.add_field('artifact_type', artifact_type)
                    data.add_field('metadata', json.dumps(metadata))
                    if self.case_id:
                        data.add_field('case_id', self.case_id)
                    # P0 Legally required: Send consent record to server
                    if self.consent_record:
                        data.add_field('consent_record', json.dumps(self.consent_record))

                    upload_headers = {
                        'X-Session-ID': self.session_id,
                        'X-Collection-Token': self.collection_token,
                    }
                    if self.request_signer:
                        upload_headers.update(self.request_signer.sign_request(
                            "POST", "/api/v1/collector/raw-files/upload",
                            None, self.collection_token,
                        ))

                    async with session.post(
                        f"{self.server_url}/api/v1/collector/raw-files/upload",
                        data=data,
                        headers=upload_headers,
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            return UploadResult(
                                success=True,
                                artifact_id=result.get('artifact_id'),
                            )
                        else:
                            error_text = await response.text()
                            # P2-2: User-friendly error message
                            return UploadResult.from_error(
                                f"Upload failed ({response.status}): {error_text}"
                            )

        except aiohttp.ClientError as e:
            # P2-2: User-friendly error message
            return UploadResult.from_error(f"Connection error: {str(e)}")
        except Exception as e:
            # P2-2: User-friendly error message
            return UploadResult.from_error(f"Upload error: {str(e)}")

    async def upload_batch(
        self,
        files: list,
        progress_callback: Callable[[float, str], None] = None,
    ) -> list:
        """
        Upload multiple files with progress tracking.

        Args:
            files: List of (file_path, artifact_type, metadata) tuples
            progress_callback: Callback(progress, filename)

        Returns:
            List of UploadResult for each file
        """
        results = []
        total = len(files)

        for i, (file_path, artifact_type, metadata) in enumerate(files):
            # Send progress
            progress = i / total
            filename = Path(file_path).name

            await self.send_progress(progress, f"Uploading {i+1}/{total}", filename)

            if progress_callback:
                progress_callback(progress, filename)

            # Upload file
            result = await self.upload_file(file_path, artifact_type, metadata)
            results.append(result)

        # Send completion
        await self.send_progress(1.0, "Upload complete", None)

        return results


class SyncUploader:
    """
    Synchronous uploader using requests library.

    Uses requests instead of asyncio for compatibility with PyQt QThread.
    asyncio.run() can cause blocking issues inside QThread.
    """

    # Default maximum file size (10GB)
    DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024

    def __init__(
        self,
        server_url: str,
        ws_url: str,
        session_id: str,
        collection_token: str,
        case_id: str = None,
        consent_record: dict = None,
        max_file_size: int = None,
        config: dict = None,
        request_signer=None,
    ):
        self.server_url = server_url.rstrip('/')
        self.ws_url = ws_url.rstrip('/')
        self.session_id = session_id
        self.collection_token = collection_token
        self.case_id = case_id
        self.consent_record = consent_record
        self.max_file_size = max_file_size or self.DEFAULT_MAX_FILE_SIZE
        self._dev_mode = config.get('dev_mode', False) if config else False
        self.request_signer = request_signer

    def upload_file(
        self,
        file_path: str,
        artifact_type: str,
        metadata: dict,
        progress_callback: Callable[[float], None] = None,
    ) -> UploadResult:
        """
        Synchronous file upload (using requests).

        Can be safely called from PyQt QThread.
        """
        # File size validation
        try:
            file_size = os.path.getsize(file_path)
        except OSError as e:
            return UploadResult.from_error(f"Cannot access file: {e}")

        if file_size > self.max_file_size:
            max_size_gb = self.max_file_size / (1024 * 1024 * 1024)
            file_size_gb = file_size / (1024 * 1024 * 1024)
            return UploadResult(
                success=False,
                error=f"File size ({file_size_gb:.2f}GB) exceeds maximum allowed size ({max_size_gb:.1f}GB).",
                error_title="File Size Exceeded",
                error_solution="Split the file or contact the administrator.",
                is_recoverable=False,
            )

        if file_size == 0:
            return UploadResult(
                success=False,
                error="Empty files cannot be uploaded.",
                error_title="Empty File",
                error_solution="Please verify the file contents.",
                is_recoverable=False,
            )

        # Dynamic timeout: 1MB/s baseline + 5min buffer, no upper cap for large files
        upload_timeout = max(300, (file_size / (1 * 1024 * 1024)) + 300)

        # Retry with exponential backoff (network instability during large uploads)
        MAX_RETRIES = 3
        last_error = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                with open(file_path, 'rb') as f:
                    files = {
                        'file': (Path(file_path).name, f, 'application/octet-stream')
                    }
                    data = {
                        'artifact_type': artifact_type,
                        'metadata': json.dumps(metadata),
                    }
                    if self.case_id:
                        data['case_id'] = self.case_id
                    if self.consent_record:
                        data['consent_record'] = json.dumps(self.consent_record)

                    headers = {
                        'X-Session-ID': self.session_id,
                        'X-Collection-Token': self.collection_token,
                    }
                    if self.request_signer:
                        headers.update(self.request_signer.sign_request(
                            "POST", "/api/v1/collector/raw-files/upload",
                            None, self.collection_token,
                        ))

                    # Debug token transmission (first upload only)
                    # Security: log token hash instead of raw value
                    if attempt == 1 and not hasattr(self, '_debug_logged'):
                        self._debug_logged = True
                        token_val = self.collection_token
                        import hashlib
                        token_hash = hashlib.sha256(token_val.encode()).hexdigest()[:8] if token_val else 'None'
                        logger.debug(
                            f"[UPLOAD_DEBUG] session_id={self.session_id}, "
                            f"token_type={type(token_val).__name__}, "
                            f"token_len={len(token_val) if token_val else 0}, "
                            f"has_dot={'.' in token_val if token_val else False}, "
                            f"token_hash={token_hash}"
                        )

                    response = requests.post(
                        f"{self.server_url}/api/v1/collector/raw-files/upload",
                        files=files,
                        data=data,
                        headers=headers,
                        timeout=upload_timeout,
                    )

                    if response.status_code == 200:
                        result = response.json()
                        if attempt > 1:
                            logger.info(f"[UPLOAD] Succeeded on attempt {attempt}")
                        return UploadResult(
                            success=True,
                            artifact_id=result.get('artifact_id'),
                        )
                    else:
                        error_text = response.text
                        # Non-retryable HTTP errors (4xx = client error)
                        if 400 <= response.status_code < 500:
                            sanitized_error = _sanitize_error_for_logging(error_text)
                            logger.error(f"[UPLOAD] HTTP {response.status_code}: {sanitized_error}")
                            return UploadResult.from_error(
                                f"Upload failed ({response.status_code}): {error_text}"
                            )
                        # Server errors (5xx) are retryable
                        last_error = f"Upload failed ({response.status_code}): {error_text}"
                        sanitized_error = _sanitize_error_for_logging(error_text)
                        logger.warning(f"[UPLOAD] HTTP {response.status_code} (attempt {attempt}/{MAX_RETRIES}): {sanitized_error}")

            except requests.exceptions.Timeout:
                last_error = f"Upload timeout after {upload_timeout}s"
                logger.warning(f"[UPLOAD] Timeout (attempt {attempt}/{MAX_RETRIES})")
            except requests.exceptions.ConnectionError as e:
                last_error = f"Connection error: {str(e)}"
                sanitized_error = _sanitize_error_for_logging(str(e))
                logger.warning(f"[UPLOAD] Connection error (attempt {attempt}/{MAX_RETRIES}): {sanitized_error}")
            except Exception as e:
                last_error = f"Upload error: {str(e)}"
                sanitized_error = _sanitize_error_for_logging(str(e))
                logger.warning(f"[UPLOAD] Exception (attempt {attempt}/{MAX_RETRIES}): {type(e).__name__}: {sanitized_error}")

            # Exponential backoff before retry (5s, 15s, 45s)
            if attempt < MAX_RETRIES:
                import time
                backoff = 5 * (3 ** (attempt - 1))
                logger.info(f"[UPLOAD] Retrying in {backoff}s...")
                time.sleep(backoff)

        # All retries exhausted
        return UploadResult.from_error(last_error or "Upload failed after all retries")

    def upload_batch(
        self,
        files: list,
        progress_callback: Callable[[float, str], None] = None,
    ) -> list:
        """Batch upload."""
        results = []
        total = len(files)

        for i, (file_path, artifact_type, metadata) in enumerate(files):
            progress = i / total
            filename = Path(file_path).name

            if progress_callback:
                progress_callback(progress, filename)

            result = self.upload_file(file_path, artifact_type, metadata)
            results.append(result)

        return results
