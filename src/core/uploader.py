"""
Real-time Upload Module

Handles file uploads with WebSocket progress reporting.
P2-2: User-friendly error message support
Direct upload to cloud storage via presigned URLs

[2026-04-27 Phase 4] Bidirectional WebSocket: collector now also RECEIVES
control messages from the server (cancel, terminate, snapshot, etc.) and
sends a periodic heartbeat. The receive loop is non-blocking with respect
to upload work — control messages are dispatched onto self._cancelled and
self._control_callback so the synchronous upload loop can poll them.
"""
import asyncio
import hashlib
import json
import logging
import os
import re
import ssl
import sys
import threading
import time

import aiohttp
import requests
import websockets
from pathlib import Path
from datetime import datetime, timezone

from core.token_validator import _get_ssl_verify
from typing import Callable, Optional
from dataclasses import dataclass

# [2026-04-27 Phase 4] WebSocket control protocol tunables
HEARTBEAT_INTERVAL_SECONDS = 15
RECONNECT_BACKOFF_INITIAL = 3
RECONNECT_BACKOFF_MAX = 60
WS_RECEIVE_TIMEOUT = 30  # if no message for this long, assume dead

# Consolidated API endpoint paths for maintainability.
_ENDPOINTS = {
    'raw_upload': '/api/v1/collector/raw-files/upload',
    'presigned_url': '/api/v1/collector/r2/presigned-url',
    'upload_complete': '/api/v1/collector/r2/upload-complete',
    'abort_upload': '/api/v1/collector/r2/abort-upload',
}


class SessionCancelledError(Exception):
    """Raised when the server returns 409 (session invalidated/cancelled)."""
    pass


class CreditPausedError(Exception):
    """Raised when the server returns 402 (upload paused by server)."""
    def __init__(self, message: str = "Upload paused by server.", detail: dict = None):
        super().__init__(message)
        self.detail = detail or {}

from utils.error_messages import translate_error

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


def _zeroize_key(key_ref: str) -> None:
    """Request garbage collection of sensitive key material.

    Note: CPython's immutable strings cannot be reliably zeroed in memory.
    This function deletes the reference to encourage GC. For stronger
    guarantees, consider using ctypes or a secure memory library.
    """
    del key_ref


@dataclass
class UploadResult:
    """Upload result (P2-2: Extended error information)"""
    success: bool
    artifact_id: Optional[str] = None
    error: Optional[str] = None
    error_title: Optional[str] = None      # P2-2: User-friendly error title
    error_solution: Optional[str] = None   # P2-2: Solution/resolution
    is_recoverable: bool = True            # P2-2: Whether retry is possible
    is_credit_paused: bool = False         # True when server returns 402 (upload paused)

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

    Uploads protected files to the forensics server while
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

        # [2026-04-27 Phase 4] Control-protocol state
        # Threading-safe flag — synchronous upload code reads this between chunks
        # to decide whether to abort. Set by _handle_server_message when server
        # sends 'cancel' or 'terminate'.
        self._cancel_event = threading.Event()
        self._terminate_reason: Optional[str] = None
        # Optional callback the GUI can register to surface control messages
        # (cancel/terminate/snapshot) into the activity log immediately.
        # Signature: (msg_type: str, payload: dict) -> None
        self._control_callback: Optional[Callable[[str, dict], None]] = None
        # Background tasks created by connect_websocket()
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._receiver_task: Optional[asyncio.Task] = None
        self._reconnect_stop = asyncio.Event()

    def is_cancelled(self) -> bool:
        """[Phase 4] Synchronous check used by upload loops between chunks."""
        return self._cancel_event.is_set()

    def get_terminate_reason(self) -> Optional[str]:
        """[Phase 4] Last termination reason from server, or None."""
        return self._terminate_reason

    def set_control_callback(self, cb: Callable[[str, dict], None]) -> None:
        """[Phase 4] GUI registers a callback to receive control events.

        The callback is invoked from the asyncio loop thread; the GUI must
        marshal back to the Qt main thread (e.g., via QMetaObject.invokeMethod
        or pyqtSignal.emit which is thread-safe).
        """
        self._control_callback = cb

    async def connect_websocket(self):
        """Establish bidirectional WebSocket and start heartbeat + receiver tasks.

        [2026-04-27 Phase 4] Previously this was a one-way send-only channel.
        It now:
          - Connects to /ws/collection/{session_id}
          - Spawns a background heartbeat sender (15s interval)
          - Spawns a background receiver that dispatches server control messages
          - On any disconnect, schedules reconnect with exponential backoff
            (unless self._reconnect_stop is set by disconnect_websocket()).
        Failure to connect is non-fatal — uploads still work over HTTP.
        """
        self._reconnect_stop.clear()
        await self._connect_once()
        # Start reconnect supervisor (no-op if connect succeeded; retries if not)
        asyncio.ensure_future(self._reconnect_supervisor())

    async def _connect_once(self) -> bool:
        """Single connection attempt. Returns True on success."""
        try:
            ws_endpoint = f"{self.ws_url}/ws/collection/{self.session_id}"

            # [Security] Block insecure ws:// in release builds (except localhost)
            if ws_endpoint.startswith('ws://') and not ws_endpoint.startswith('ws://localhost') and not ws_endpoint.startswith('ws://127.0.0.1'):
                if getattr(sys, 'frozen', False):
                    raise RuntimeError("Insecure WebSocket (ws://) not allowed in release builds. Use wss://")
                else:
                    logger.warning("[WebSocket] Insecure ws:// connection — development mode only")

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

            self.ws = await websockets.connect(
                ws_endpoint,
                extra_headers=extra_headers,
                ssl=ssl_context
            )
            logger.info(f"[WebSocket] Connected to {ws_endpoint[:50]}...")

            # Start heartbeat + receiver tasks
            self._heartbeat_task = asyncio.ensure_future(self._heartbeat_loop())
            self._receiver_task = asyncio.ensure_future(self._receive_loop())
            return True
        except ssl.SSLError as ssl_err:
            logger.error(f"[WebSocket] SSL error: {ssl_err}")
            logger.error("WebSocket SSL authentication failed - please verify server certificate")
            self.ws = None
            return False
        except Exception as e:
            logger.warning(f"[WebSocket] Connection failed: {e}")
            self.ws = None
            return False

    async def _heartbeat_loop(self):
        """[Phase 4] Send heartbeat every HEARTBEAT_INTERVAL_SECONDS."""
        try:
            while self.ws is not None:
                try:
                    await self.ws.send(json.dumps({
                        'type': 'heartbeat',
                        'ts': datetime.now(timezone.utc).isoformat(),
                    }))
                except Exception as e:
                    logger.debug(f"[WebSocket] heartbeat send failed: {e}")
                    return  # connection broken; receiver will reconnect
                await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            pass

    async def _receive_loop(self):
        """[Phase 4] Receive server control messages until connection drops."""
        try:
            while self.ws is not None:
                try:
                    raw = await asyncio.wait_for(self.ws.recv(), timeout=WS_RECEIVE_TIMEOUT * 2)
                except asyncio.TimeoutError:
                    # No message for too long — likely a half-open connection. Force reconnect.
                    logger.warning("[WebSocket] receive timeout — assuming dead, reconnecting")
                    try:
                        await self.ws.close()
                    except Exception:
                        pass
                    self.ws = None
                    return
                except Exception as e:
                    logger.debug(f"[WebSocket] recv ended: {e}")
                    self.ws = None
                    return

                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(msg, dict):
                    continue

                self._handle_server_message(msg)
        except asyncio.CancelledError:
            pass

    def _handle_server_message(self, msg: dict) -> None:
        """[Phase 4] Dispatch a single inbound server message.

        Server message types (see server-side api/routes/collector_ws.py):
          - snapshot:      initial / on-reconnect state — includes cancel_flag
          - cancel:        server-side cancel happened (web UI or auto-cleanup)
          - terminate:     hard termination (superseded, token expired, ...)
          - status:        relayed pipeline_progress envelope
          - heartbeat_ack: response to our heartbeat
          - pipeline_progress: full envelope for clients that understand it
        """
        mtype = msg.get('type')

        if mtype == 'snapshot':
            # Initial state. Surface cancel_flag if set.
            if msg.get('cancel_flag'):
                self._cancel_event.set()
                self._terminate_reason = 'snapshot_indicated_cancelled'
            if self._control_callback:
                try:
                    self._control_callback('snapshot', msg)
                except Exception as e:
                    logger.debug(f"[WebSocket] control_callback(snapshot) error: {e}")

        elif mtype == 'cancel':
            reason = str(msg.get('reason') or 'unspecified')
            logger.warning(f"[WebSocket] Server-side CANCEL received: {reason}")
            self._cancel_event.set()
            self._terminate_reason = f"cancel:{reason}"
            if self._control_callback:
                try:
                    self._control_callback('cancel', msg)
                except Exception as e:
                    logger.debug(f"[WebSocket] control_callback(cancel) error: {e}")

        elif mtype == 'terminate':
            reason = str(msg.get('reason') or 'unspecified')
            logger.warning(f"[WebSocket] Server TERMINATE received: {reason}")
            self._cancel_event.set()
            self._terminate_reason = f"terminate:{reason}"
            if self._control_callback:
                try:
                    self._control_callback('terminate', msg)
                except Exception as e:
                    logger.debug(f"[WebSocket] control_callback(terminate) error: {e}")
            # Stop reconnect attempts on hard terminate
            self._reconnect_stop.set()

        elif mtype == 'status' or mtype == 'pipeline_progress':
            # Just surface to the GUI if it cares — no protocol-level action needed.
            if self._control_callback:
                try:
                    self._control_callback('status', msg)
                except Exception as e:
                    logger.debug(f"[WebSocket] control_callback(status) error: {e}")

        elif mtype == 'heartbeat_ack':
            pass  # noop

    async def _reconnect_supervisor(self):
        """[Phase 4] Re-establish WS with exponential backoff on disconnect."""
        backoff = RECONNECT_BACKOFF_INITIAL
        while not self._reconnect_stop.is_set():
            # Wait until ws is None (disconnected)
            while self.ws is not None and not self._reconnect_stop.is_set():
                await asyncio.sleep(2)
            if self._reconnect_stop.is_set():
                return
            # Reconnect
            logger.info(f"[WebSocket] Reconnecting in {backoff}s...")
            try:
                await asyncio.wait_for(self._reconnect_stop.wait(), timeout=backoff)
                return  # stop signaled during sleep
            except asyncio.TimeoutError:
                pass
            ok = await self._connect_once()
            if ok:
                backoff = RECONNECT_BACKOFF_INITIAL  # reset on success
            else:
                backoff = min(backoff * 2, RECONNECT_BACKOFF_MAX)

    async def send_intent_shutdown(self, reason: str = 'user_close') -> None:
        """[Phase 4] Send graceful shutdown intent over WS before close.

        Signals the server that we're closing cleanly so it can immediately
        release the case slot (instead of waiting for the server's idle timeout).
        Best-effort — failure is non-fatal.
        """
        if not self.ws:
            return
        try:
            await asyncio.wait_for(
                self.ws.send(json.dumps({
                    'type': 'intent',
                    'action': 'shutdown',
                    'reason': reason,
                    'ts': datetime.now(timezone.utc).isoformat(),
                })),
                timeout=2.0,
            )
        except Exception as e:
            logger.debug(f"[WebSocket] intent.shutdown send failed: {e}")

    async def disconnect_websocket(self):
        """Close WebSocket connection and stop background tasks."""
        # Stop reconnect supervisor first so it doesn't fight us
        self._reconnect_stop.set()
        # Cancel background tasks
        for t in (self._heartbeat_task, self._receiver_task):
            if t is not None and not t.done():
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass
        self._heartbeat_task = None
        self._receiver_task = None
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass
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
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                }))
            except Exception as e:
                logger.warning(f"Failed to send progress: {e}")

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
            file_path: Path to the protected file
            artifact_type: Type of artifact (e.g., 'prefetch', 'eventlog')
            metadata: File metadata
            progress_callback: Optional callback for upload progress

        Returns:
            UploadResult with status
        """
        # M2 Security: File size validation (prevent storage exhaustion)
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
                            "POST", _ENDPOINTS['raw_upload'],
                            None, self.collection_token,
                        ))

                    async with session.post(
                        f"{self.server_url}{_ENDPOINTS['raw_upload']}",
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
                            "POST", _ENDPOINTS['raw_upload'],
                            None, self.collection_token,
                        ))

                    # Debug token transmission (first upload only)
                    # Security: log token hash instead of raw value
                    if attempt == 1 and not hasattr(self, '_debug_logged'):
                        self._debug_logged = True
                        token_val = self.collection_token
                        token_hash = hashlib.sha256(token_val.encode()).hexdigest()[:8] if token_val else 'None'
                        logger.debug(
                            f"[UPLOAD_DEBUG] session_id={self.session_id}, "
                            f"token_type={type(token_val).__name__}, "
                            f"token_len={len(token_val) if token_val else 0}, "
                            f"has_dot={'.' in token_val if token_val else False}, "
                            f"token_hash={token_hash}"
                        )

                    response = requests.post(
                        f"{self.server_url}{_ENDPOINTS['raw_upload']}",
                        files=files,
                        data=data,
                        headers=headers,
                        timeout=upload_timeout,
                        verify=_get_ssl_verify(),
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
                        # Server paused — stop uploading
                        if response.status_code == 402:
                            logger.warning(f"[UPLOAD] Server paused — stopping upload")
                            return UploadResult(
                                success=False,
                                error="Upload paused — insufficient account balance.",
                                error_title="Upload Paused",
                                error_solution="Please check your account balance on the web platform. After resolving, restart the collector to continue. Already processed files are preserved.",
                                is_recoverable=False,
                                is_credit_paused=True,
                            )
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


class DirectUploader:
    """
    Direct Uploader — uploads files directly to cloud storage via presigned URLs.

    The server only issues presigned URLs and confirms completion; actual file
    transfer goes directly from client to storage, eliminating server bandwidth load.

    - Under 100MB: Single PUT upload
    - 100MB and above: Multipart upload (per-part PUT)
    """

    DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB

    def __init__(
        self,
        server_url: str,
        session_id: str,
        collection_token: str,
        case_id: str = None,
        consent_record: dict = None,
        max_file_size: int = None,
        config: dict = None,
        request_signer=None,
    ):
        """
        Args:
            server_url: API server URL (e.g., https://api.example.com)
            session_id: Collection session ID
            collection_token: Collection auth token
            case_id: Case ID
            consent_record: Legal consent record
            max_file_size: Maximum file size (bytes)
            config: App settings (dev_mode, etc.)
            request_signer: RequestSigner instance (HMAC signing)
        """
        self.server_url = server_url.rstrip('/')
        self.session_id = session_id
        self.collection_token = collection_token
        self.case_id = case_id
        self.consent_record = consent_record
        self.max_file_size = max_file_size or self.DEFAULT_MAX_FILE_SIZE
        self._dev_mode = config.get('dev_mode', False) if config else False
        self.request_signer = request_signer

    def _get_auth_headers(self, method: str = "POST", path: str = "", body=None) -> dict:
        """Build auth headers (session + token + HMAC signature)."""
        headers = {
            'X-Session-ID': self.session_id,
            'X-Collection-Token': self.collection_token,
        }
        if self.request_signer:
            headers.update(self.request_signer.sign_request(
                method, path, body, self.collection_token
            ))
        return headers

    def _compute_file_hash(self, file_path: str) -> str:
        """Compute SHA-256 hash."""
        h = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()

    def _request_presigned_url(self, file_path: str, artifact_type: str, file_hash: str) -> dict:
        """Request presigned URL from server (up to 5 retries)."""
        file_size = os.path.getsize(file_path)
        file_name = Path(file_path).name
        endpoint = _ENDPOINTS['presigned_url']

        payload = {
            "case_id": self.case_id,
            "file_name": file_name,
            "file_size": file_size,
            "file_hash": file_hash,
            "artifact_type": artifact_type,
        }

        max_retries = 5
        for attempt in range(1, max_retries + 1):
            try:
                headers = self._get_auth_headers("POST", endpoint)
                headers['Content-Type'] = 'application/json'

                response = requests.post(
                    f"{self.server_url}{endpoint}",
                    json=payload,
                    headers=headers,
                    timeout=60,
                    verify=_get_ssl_verify(),
                )

                if response.status_code == 402:
                    try:
                        detail = response.json()
                    except Exception:
                        detail = {}
                    logger.warning(f"[UPLOAD] Server paused upload (case {self.case_id})")
                    raise CreditPausedError(
                        detail.get("message", "Upload paused by server."),
                        detail=detail,
                    )

                if response.status_code == 429:
                    wait = attempt * 10
                    logger.warning(f"[DIRECT] Presigned URL rate limited, retrying in {wait}s (attempt {attempt}/{max_retries})")
                    time.sleep(wait)
                    continue

                if response.status_code == 409:
                    # Session invalidated or case cancelled — do NOT retry
                    detail = ""
                    try:
                        detail = response.json().get("detail", "")
                    except Exception:
                        detail = response.text[:200]
                    raise SessionCancelledError(f"Collection cancelled: {detail}")

                if response.status_code != 200:
                    raise RuntimeError(f"Presigned URL request failed ({response.status_code}): {response.text[:200]}")

                return response.json()
            except SessionCancelledError:
                raise  # Don't retry cancelled sessions — propagate immediately
            except RuntimeError:
                if attempt < max_retries:
                    wait = attempt * 5
                    logger.warning(f"[DIRECT] Presigned URL attempt {attempt}/{max_retries} failed, retrying in {wait}s")
                    time.sleep(wait)
                else:
                    raise
            except Exception as e:
                if attempt < max_retries:
                    wait = attempt * 5
                    logger.warning(f"[DIRECT] Presigned URL attempt {attempt}/{max_retries} error: {e}, retrying in {wait}s")
                    time.sleep(wait)
                else:
                    raise

        raise RuntimeError("Presigned URL request failed after all retries")

    def _validate_presigned_url(self, presigned_url: str) -> None:
        """[Security] Validate presigned URL — must be HTTPS (or localhost for dev)."""
        from urllib.parse import urlparse
        parsed = urlparse(presigned_url)
        allowed_dev_hosts = ('127.0.0.1', 'localhost')
        if not parsed.hostname:
            raise RuntimeError("[SECURITY] Presigned URL has no hostname")
        if parsed.hostname in allowed_dev_hosts:
            return  # dev mode
        if parsed.scheme != 'https':
            raise RuntimeError(
                f"[SECURITY] Presigned URL must use HTTPS, got: {parsed.scheme}"
            )

    def _upload_single(self, file_path: str, presigned_url: str) -> None:
        """Single PUT direct upload (< 100MB), up to 3 retries."""
        self._validate_presigned_url(presigned_url)
        file_size = os.path.getsize(file_path)
        timeout = max(120, file_size / (1 * 1024 * 1024) + 60)  # 1MB/s + 60s buffer
        max_retries = 3

        for attempt in range(1, max_retries + 1):
            try:
                with open(file_path, 'rb') as f:
                    response = requests.put(
                        presigned_url,
                        data=f,
                        headers={'Content-Type': 'application/octet-stream'},
                        timeout=timeout,
                    )
                if response.status_code not in (200, 201):
                    raise RuntimeError(f"PUT upload failed ({response.status_code}): {response.text[:200]}")
                return  # success
            except Exception as e:
                if attempt < max_retries:
                    wait = attempt * 5
                    logger.warning(f"[DIRECT] Upload attempt {attempt}/{max_retries} failed, retrying in {wait}s: {e}")
                    time.sleep(wait)
                else:
                    raise

    def _upload_multipart(self, file_path: str, presigned_info: dict) -> list:
        """Multipart upload (>= 100MB): parallel part PUT (max 4 concurrent)."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        urls = presigned_info['upload_url']
        # [Security] Validate all part URLs before uploading
        for part_info in urls:
            self._validate_presigned_url(part_info['url'])
        part_size = presigned_info.get('part_size', 50 * 1024 * 1024)
        actual_file_size = os.path.getsize(file_path)
        total_parts = len(urls)

        # Pre-read part data into memory for parallel PUT
        parts_data = []
        with open(file_path, 'rb') as f:
            for idx, part_info in enumerate(urls):
                part_number = part_info['part_number']
                start = (part_number - 1) * part_size
                if idx == total_parts - 1:
                    end = actual_file_size
                else:
                    end = min(start + part_size, actual_file_size)
                f.seek(start)
                data = f.read(end - start)
                parts_data.append((part_info, data))

        def _upload_one_part(part_info, data):
            part_number = part_info['part_number']
            part_url = part_info['url']
            chunk_size = len(data)
            timeout = max(120, chunk_size / (1 * 1024 * 1024) + 60)
            max_retries = 3

            for attempt in range(1, max_retries + 1):
                try:
                    response = requests.put(
                        part_url,
                        data=data,
                        headers={'Content-Type': 'application/octet-stream'},
                        timeout=timeout,
                    )
                    if response.status_code not in (200, 201):
                        raise RuntimeError(
                            f"Multipart part {part_number} upload failed "
                            f"({response.status_code}): {response.text[:200]}"
                        )
                    etag = response.headers.get('ETag', '').strip('"')
                    logger.debug(f"[DIRECT] Part {part_number}/{total_parts} uploaded ({chunk_size:,} bytes)")
                    return {"PartNumber": part_number, "ETag": etag}
                except Exception as e:
                    if attempt < max_retries:
                        wait = attempt * 5
                        logger.warning(f"[DIRECT] Part {part_number} attempt {attempt}/{max_retries} failed, retrying in {wait}s: {e}")
                        time.sleep(wait)
                    else:
                        raise

        # Parallel part upload (max 4 concurrent)
        max_workers = min(4, total_parts)
        completed_parts = [None] * total_parts

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for idx, (part_info, data) in enumerate(parts_data):
                future = executor.submit(_upload_one_part, part_info, data)
                futures[future] = idx

            for future in as_completed(futures):
                idx = futures[future]
                completed_parts[idx] = future.result()  # propagates exceptions

        # Sort by part number (CompleteMultipartUpload requirement)
        completed_parts.sort(key=lambda p: p['PartNumber'])
        return completed_parts

    def _confirm_upload(
        self, key: str, upload_id: str, file_hash: str,
        file_name: str, artifact_type: str, parts: list = None,
        is_encrypted: bool = False, original_path: str = "",
    ) -> dict:
        """Confirm upload completion with server (up to 5 retries)."""
        endpoint = _ENDPOINTS['upload_complete']

        payload = {
            "case_id": self.case_id,
            "key": key,
            "upload_id": upload_id,
            "file_hash": file_hash,
            "file_name": file_name,
            "artifact_type": artifact_type,
            "parts": parts,
            "is_encrypted": is_encrypted,
            "consent_record": self.consent_record,
            "original_path": original_path,
        }

        max_retries = 5
        for attempt in range(1, max_retries + 1):
            try:
                headers = self._get_auth_headers("POST", endpoint)
                headers['Content-Type'] = 'application/json'

                response = requests.post(
                    f"{self.server_url}{endpoint}",
                    json=payload,
                    headers=headers,
                    timeout=60,
                    verify=_get_ssl_verify(),
                )

                if response.status_code == 402:
                    try:
                        detail = response.json()
                    except Exception:
                        detail = {}
                    raise CreditPausedError(
                        detail.get("message", "Upload paused by server."),
                        detail=detail,
                    )

                if response.status_code == 429:
                    wait = attempt * 10
                    logger.warning(f"[DIRECT] Upload confirm rate limited, retrying in {wait}s (attempt {attempt}/{max_retries})")
                    time.sleep(wait)
                    continue

                if response.status_code != 200:
                    raise RuntimeError(f"Upload confirmation failed ({response.status_code}): {response.text[:200]}")

                return response.json()
            except CreditPausedError:
                raise  # Don't retry credit pause — propagate immediately
            except RuntimeError:
                if attempt < max_retries:
                    wait = attempt * 5
                    logger.warning(f"[DIRECT] Upload confirm attempt {attempt}/{max_retries} failed, retrying in {wait}s")
                    time.sleep(wait)
                else:
                    raise
            except Exception as e:
                if attempt < max_retries:
                    wait = attempt * 5
                    logger.warning(f"[DIRECT] Upload confirm attempt {attempt}/{max_retries} error: {e}, retrying in {wait}s")
                    time.sleep(wait)
                else:
                    raise

        raise RuntimeError("Upload confirmation failed after all retries")

    def _abort_upload(self, case_id: str, key: str, upload_id: str) -> None:
        """Abort multipart upload (cleanup on failure)."""
        try:
            endpoint = _ENDPOINTS['abort_upload']
            headers = self._get_auth_headers("POST", endpoint)

            requests.post(
                f"{self.server_url}{endpoint}",
                params={"case_id": case_id, "key": key, "upload_id": upload_id},
                headers=headers,
                timeout=15,
            )
            logger.info(f"[DIRECT] Multipart upload aborted: {key}")
        except Exception as e:
            logger.warning(f"[DIRECT] Failed to abort multipart upload: {e}")

    def upload_file(
        self,
        file_path: str,
        artifact_type: str,
        metadata: dict,
        progress_callback: Callable[[float], None] = None,
    ) -> UploadResult:
        """
        Direct upload via presigned URL.

        1. Compute SHA-256 hash
        2. Request presigned URL from server
        3. PUT upload directly to cloud storage (single or multipart)
        4. Confirm upload completion with server
        """
        # Validate file size
        try:
            file_size = os.path.getsize(file_path)
        except OSError as e:
            return UploadResult.from_error(f"Cannot access file: {e}")

        if file_size > self.max_file_size:
            max_gb = self.max_file_size / (1024 ** 3)
            file_gb = file_size / (1024 ** 3)
            return UploadResult(
                success=False,
                error=f"File size ({file_gb:.2f}GB) exceeds maximum ({max_gb:.1f}GB).",
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

        # Compute SHA-256 hash
        try:
            file_hash = self._compute_file_hash(file_path)
        except Exception as e:
            return UploadResult.from_error(f"Hash computation failed: {e}")

        file_name = Path(file_path).name
        presigned_info = None
        encrypted_path = None

        try:
            # Step 1: Request presigned URL
            presigned_info = self._request_presigned_url(file_path, artifact_type, file_hash)
            key = presigned_info['key']
            is_multipart = presigned_info.get('multipart', False)
            upload_id = presigned_info.get('upload_id')

            # Step 1.5: Per-Case Data Protection — protect file if server provides key
            encryption_key_hex = presigned_info.get('encryption_key')
            # [SECURITY] Remove key from presigned_info dict immediately to limit
            # the number of references holding sensitive key material in memory.
            presigned_info.pop('encryption_key', None)
            is_encrypted = False
            encrypted_path = None

            if encryption_key_hex:
                # Data protection requires full plaintext in memory; skip for large files to avoid OOM
                MAX_ENCRYPT_SIZE = 500 * 1024 * 1024  # 500MB
                if file_size > MAX_ENCRYPT_SIZE:
                    logger.warning(
                        f"[DIRECT] File too large for in-memory protection ({file_size / (1024**2):.0f}MB > "
                        f"{MAX_ENCRYPT_SIZE / (1024**2):.0f}MB), uploading without client-side protection. "
                        f"⚠️ Evidence will be protected by TLS in transit and server-side protection at rest."
                    )
                    _pcb = getattr(self, '_progress_callback', None)
                    if _pcb:
                        _pcb(
                            f"⚠️ {file_name}: Large file ({file_size / (1024**2):.0f}MB) — "
                            f"client-side protection skipped, protected by server-side security"
                        )
                    # [SECURITY] Zero out key material before releasing reference
                    _zeroize_key(encryption_key_hex)
                    del encryption_key_hex
                else:
                    try:
                        from core.secure_upload import AESGCMCipher
                        cipher = AESGCMCipher(bytes.fromhex(encryption_key_hex))
                        with open(file_path, 'rb') as f:
                            plaintext = f.read()
                        aad = file_hash.encode('utf-8')
                        encrypted_data = cipher.encrypt(plaintext, aad)
                        del plaintext

                        encrypted_path = file_path + '.enc'
                        with open(encrypted_path, 'wb') as f:
                            f.write(encrypted_data)
                        del encrypted_data

                        is_encrypted = True
                        logger.info(f"[DIRECT] File protected: {file_name} ({os.path.getsize(encrypted_path):,} bytes)")
                    except Exception as enc_err:
                        logger.error(f"[DIRECT] Data protection failed — aborting upload for evidence safety: {enc_err}")
                        return UploadResult.from_error(
                            f"Data protection failed for {file_name}: {enc_err}. Upload aborted to prevent unprotected evidence exposure."
                        )
                    finally:
                        # [SECURITY] Zero out key material before releasing reference
                        _zeroize_key(encryption_key_hex)
                        del encryption_key_hex

            upload_path = encrypted_path if is_encrypted else file_path

            # Step 2: Direct upload to cloud storage
            completed_parts = None
            if is_multipart:
                completed_parts = self._upload_multipart(upload_path, presigned_info)
            else:
                upload_url = presigned_info['upload_url']
                self._upload_single(upload_path, upload_url)

            # Clean up protected temp file
            if encrypted_path and os.path.exists(encrypted_path):
                os.remove(encrypted_path)

            # Step 3: Confirm completion with server
            original_path = metadata.get('original_path', '') if metadata else ''
            confirm_result = self._confirm_upload(
                key=key,
                upload_id=upload_id,
                file_hash=file_hash,
                file_name=file_name,
                artifact_type=artifact_type,
                parts=completed_parts,
                is_encrypted=is_encrypted,
                original_path=original_path,
            )

            logger.info(f"[DIRECT] Upload complete: {file_name} → {key}")
            return UploadResult(
                success=True,
                artifact_id=confirm_result.get('file_id'),
            )

        except SessionCancelledError as sce:
            logger.warning(f"[UPLOAD] Session cancelled by server: {sce}")
            if encrypted_path and os.path.exists(encrypted_path):
                os.remove(encrypted_path)
            return UploadResult(
                success=False,
                error="Collection cancelled by server.",
                error_title="Collection Cancelled",
                error_solution="The collection was cancelled from the web platform. Please close the collector.",
                is_recoverable=False,
            )

        except CreditPausedError as cpe:
            logger.warning(f"[UPLOAD] Upload stopped by server: {cpe}")
            if encrypted_path and os.path.exists(encrypted_path):
                os.remove(encrypted_path)
            return UploadResult(
                success=False,
                error="Upload paused — insufficient account balance.",
                error_title="Upload Paused",
                error_solution="Please check your account balance on the web platform. After resolving, restart the collector to continue. Already processed files are preserved.",
                is_recoverable=False,
                is_credit_paused=True,
            )

        except Exception as e:
            sanitized_error = _sanitize_error_for_logging(str(e))
            logger.error(f"[DIRECT] Direct upload failed: {sanitized_error}")

            # Clean up protected temp file
            if encrypted_path and os.path.exists(encrypted_path):
                os.remove(encrypted_path)

            # Abort multipart cleanup
            if presigned_info and presigned_info.get('upload_id'):
                self._abort_upload(
                    self.case_id,
                    presigned_info.get('key', ''),
                    presigned_info['upload_id'],
                )

            return UploadResult.from_error(f"Direct upload failed: {e}")

    def upload_batch(
        self,
        files: list,
        progress_callback: Callable[[float, str], None] = None,
    ) -> list:
        """Batch upload with direct upload (parallel, max 4 concurrent)."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading

        total = len(files)
        if total == 0:
            return []

        # Store results by index to preserve original order
        results = [None] * total
        completed_count = 0
        lock = threading.Lock()

        credit_paused = threading.Event()

        def _upload_one(idx, file_path, artifact_type, metadata):
            nonlocal completed_count
            if credit_paused.is_set():
                return UploadResult(
                    success=False, error="Upload paused — insufficient account balance.",
                    error_title="Upload Paused",
                    error_solution="Please check your account balance on the web platform. After resolving, restart the collector to continue. Already processed files are preserved.",
                    is_recoverable=False, is_credit_paused=True,
                )
            result = self.upload_file(file_path, artifact_type, metadata)
            if getattr(result, 'is_credit_paused', False):
                credit_paused.set()  # Signal other threads to stop
            with lock:
                results[idx] = result
                completed_count += 1
                if progress_callback:
                    progress_callback(completed_count / total, Path(file_path).name)
            return result

        max_workers = min(4, total)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for i, (file_path, artifact_type, metadata) in enumerate(files):
                future = executor.submit(_upload_one, i, file_path, artifact_type, metadata)
                futures[future] = i

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    idx = futures[future]
                    logger.error(f"[DIRECT] Parallel upload failed (index {idx}): {e}")
                    if results[idx] is None:
                        results[idx] = UploadResult.from_error(str(e))

        return results
