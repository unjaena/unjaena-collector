"""
Real-time Upload Module

Handles file uploads with WebSocket progress reporting.
P2-2: User-friendly error message support
R2: Direct upload to Cloudflare R2 via presigned URLs
"""
import hashlib
import json
import logging
import os
import re
import ssl
import time

import aiohttp
import requests
import websockets
from pathlib import Path
from datetime import datetime
from typing import Callable, Optional
from dataclasses import dataclass

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
                logger.warning(
                    "[SECURITY] Unencrypted WebSocket (ws://) in non-dev mode"
                )

            self.ws = await websockets.connect(
                ws_endpoint,
                extra_headers=extra_headers,
                ssl=ssl_context
            )
            logger.info(f"[WebSocket] Connected to {ws_endpoint[:50]}...")
        except ssl.SSLError as ssl_err:
            logger.error(f"[WebSocket] SSL error: {ssl_err}")
            print(f"WebSocket SSL authentication failed - please verify server certificate")
            self.ws = None
        except Exception as e:
            logger.warning(f"[WebSocket] Connection failed: {e}")
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


class R2DirectUploader:
    """
    R2 Direct Uploader — presigned URL을 통해 Cloudflare R2에 직접 업로드.

    서버는 presigned URL 발급과 완료 확인만 담당하며, 실제 파일 전송은
    클라이언트 → R2 직접 연결로 이루어져 서버 대역폭 부하를 제거합니다.

    - 100MB 미만: 단일 PUT 업로드
    - 100MB 이상: Multipart 업로드 (파트별 PUT)
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
            server_url: API 서버 URL (e.g., https://api.example.com)
            session_id: 수집 세션 ID
            collection_token: 수집 인증 토큰
            case_id: 케이스 ID
            consent_record: 법적 동의 기록
            max_file_size: 최대 파일 크기 (bytes)
            config: 앱 설정 (dev_mode 등)
            request_signer: RequestSigner 인스턴스 (HMAC 서명)
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
        """인증 헤더 생성 (세션 + 토큰 + HMAC 서명)"""
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
        """SHA-256 해시 계산"""
        h = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()

    def _request_presigned_url(self, file_path: str, artifact_type: str, file_hash: str) -> dict:
        """서버에서 presigned URL 발급 요청 (최대 5회 재시도)"""
        file_size = os.path.getsize(file_path)
        file_name = Path(file_path).name
        endpoint = "/api/v1/collector/r2/presigned-url"

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
                )

                if response.status_code == 429:
                    wait = attempt * 10
                    logger.warning(f"[R2] Presigned URL rate limited, retrying in {wait}s (attempt {attempt}/{max_retries})")
                    time.sleep(wait)
                    continue

                if response.status_code != 200:
                    raise RuntimeError(f"Presigned URL request failed ({response.status_code}): {response.text[:200]}")

                return response.json()
            except RuntimeError:
                if attempt < max_retries:
                    wait = attempt * 5
                    logger.warning(f"[R2] Presigned URL attempt {attempt}/{max_retries} failed, retrying in {wait}s")
                    time.sleep(wait)
                else:
                    raise
            except Exception as e:
                if attempt < max_retries:
                    wait = attempt * 5
                    logger.warning(f"[R2] Presigned URL attempt {attempt}/{max_retries} error: {e}, retrying in {wait}s")
                    time.sleep(wait)
                else:
                    raise

        raise RuntimeError("Presigned URL request failed after all retries")

    def _validate_presigned_url(self, presigned_url: str) -> None:
        """[Security] Presigned URL 도메인 검증 — R2/S3 이외 도메인 거부"""
        from urllib.parse import urlparse
        parsed = urlparse(presigned_url)
        # Allow: Cloudflare R2 (*.r2.cloudflarestorage.com), AWS S3, localhost (dev)
        allowed_suffixes = (
            '.r2.cloudflarestorage.com',
            '.s3.amazonaws.com',
        )
        allowed_hosts = ('127.0.0.1', 'localhost')
        if not parsed.hostname:
            raise RuntimeError("[SECURITY] Presigned URL has no hostname")
        if parsed.hostname in allowed_hosts:
            return  # dev mode
        if not any(parsed.hostname.endswith(s) for s in allowed_suffixes):
            raise RuntimeError(
                f"[SECURITY] Presigned URL points to unauthorized domain: {parsed.hostname}. "
                f"Expected Cloudflare R2 or AWS S3 domain."
            )

    def _upload_single(self, file_path: str, presigned_url: str) -> None:
        """단일 PUT으로 R2에 직접 업로드 (< 100MB), 최대 3회 재시도"""
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
                    raise RuntimeError(f"R2 PUT upload failed ({response.status_code}): {response.text[:200]}")
                return  # success
            except Exception as e:
                if attempt < max_retries:
                    wait = attempt * 5
                    logger.warning(f"[R2] Upload attempt {attempt}/{max_retries} failed, retrying in {wait}s: {e}")
                    time.sleep(wait)
                else:
                    raise

    def _upload_multipart(self, file_path: str, presigned_info: dict) -> list:
        """Multipart 업로드 (>= 100MB): 파트 병렬 PUT (최대 4 동시)"""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        urls = presigned_info['upload_url']
        # [Security] Validate all part URLs before uploading
        for part_info in urls:
            self._validate_presigned_url(part_info['url'])
        part_size = presigned_info.get('part_size', 50 * 1024 * 1024)
        actual_file_size = os.path.getsize(file_path)
        total_parts = len(urls)

        # 파트별 데이터를 미리 읽어서 메모리에 준비 (병렬 PUT을 위해)
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
                            f"R2 multipart part {part_number} upload failed "
                            f"({response.status_code}): {response.text[:200]}"
                        )
                    etag = response.headers.get('ETag', '').strip('"')
                    logger.debug(f"[R2] Part {part_number}/{total_parts} uploaded ({chunk_size:,} bytes)")
                    return {"PartNumber": part_number, "ETag": etag}
                except Exception as e:
                    if attempt < max_retries:
                        wait = attempt * 5
                        logger.warning(f"[R2] Part {part_number} attempt {attempt}/{max_retries} failed, retrying in {wait}s: {e}")
                        time.sleep(wait)
                    else:
                        raise

        # 파트 병렬 업로드 (최대 4 동시)
        max_workers = min(4, total_parts)
        completed_parts = [None] * total_parts

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for idx, (part_info, data) in enumerate(parts_data):
                future = executor.submit(_upload_one_part, part_info, data)
                futures[future] = idx

            for future in as_completed(futures):
                idx = futures[future]
                completed_parts[idx] = future.result()  # 예외 시 전파

        # 파트 번호 순서대로 정렬 (S3/R2 CompleteMultipartUpload 요구사항)
        completed_parts.sort(key=lambda p: p['PartNumber'])
        return completed_parts

    def _confirm_upload(
        self, key: str, upload_id: str, file_hash: str,
        file_name: str, artifact_type: str, parts: list = None,
        is_encrypted: bool = False, original_path: str = "",
    ) -> dict:
        """서버에 업로드 완료 확인 요청 (최대 5회 재시도)"""
        endpoint = "/api/v1/collector/r2/upload-complete"

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
                )

                if response.status_code == 429:
                    wait = attempt * 10
                    logger.warning(f"[R2] Upload confirm rate limited, retrying in {wait}s (attempt {attempt}/{max_retries})")
                    time.sleep(wait)
                    continue

                if response.status_code != 200:
                    raise RuntimeError(f"Upload confirmation failed ({response.status_code}): {response.text[:200]}")

                return response.json()
            except RuntimeError:
                if attempt < max_retries:
                    wait = attempt * 5
                    logger.warning(f"[R2] Upload confirm attempt {attempt}/{max_retries} failed, retrying in {wait}s")
                    time.sleep(wait)
                else:
                    raise
            except Exception as e:
                if attempt < max_retries:
                    wait = attempt * 5
                    logger.warning(f"[R2] Upload confirm attempt {attempt}/{max_retries} error: {e}, retrying in {wait}s")
                    time.sleep(wait)
                else:
                    raise

        raise RuntimeError("Upload confirmation failed after all retries")

    def _abort_upload(self, case_id: str, key: str, upload_id: str) -> None:
        """Multipart 업로드 중단 (실패 시 정리)"""
        try:
            endpoint = "/api/v1/collector/r2/abort-upload"
            headers = self._get_auth_headers("POST", endpoint)

            requests.post(
                f"{self.server_url}{endpoint}",
                params={"case_id": case_id, "key": key, "upload_id": upload_id},
                headers=headers,
                timeout=15,
            )
            logger.info(f"[R2] Multipart upload aborted: {key}")
        except Exception as e:
            logger.warning(f"[R2] Failed to abort multipart upload: {e}")

    def upload_file(
        self,
        file_path: str,
        artifact_type: str,
        metadata: dict,
        progress_callback: Callable[[float], None] = None,
    ) -> UploadResult:
        """
        R2 직접 업로드 (presigned URL).

        1. SHA-256 해시 계산
        2. 서버에서 presigned URL 발급
        3. R2에 직접 PUT 업로드 (단일/멀티파트)
        4. 서버에 업로드 완료 확인 → Celery 파싱 트리거
        """
        # 파일 크기 검증
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

        # SHA-256 해시 계산
        try:
            file_hash = self._compute_file_hash(file_path)
        except Exception as e:
            return UploadResult.from_error(f"Hash computation failed: {e}")

        file_name = Path(file_path).name
        presigned_info = None
        encrypted_path = None

        try:
            # Step 1: Presigned URL 요청
            presigned_info = self._request_presigned_url(file_path, artifact_type, file_hash)
            key = presigned_info['key']
            is_multipart = presigned_info.get('multipart', False)
            upload_id = presigned_info.get('upload_id')

            # Step 1.5: Per-Case Encryption — 서버에서 DEK 수신 시 파일 암호화
            encryption_key_hex = presigned_info.get('encryption_key')
            is_encrypted = False
            encrypted_path = None

            if encryption_key_hex:
                # AES-GCM requires full plaintext in memory; skip for large files to avoid OOM
                MAX_ENCRYPT_SIZE = 500 * 1024 * 1024  # 500MB
                if file_size > MAX_ENCRYPT_SIZE:
                    logger.warning(
                        f"[R2] File too large for in-memory encryption ({file_size / (1024**2):.0f}MB > "
                        f"{MAX_ENCRYPT_SIZE / (1024**2):.0f}MB), uploading without encryption. "
                        f"⚠️ Evidence will be protected by TLS in transit and R2 server-side encryption at rest."
                    )
                    _pcb = getattr(self, '_progress_callback', None)
                    if _pcb:
                        _pcb(
                            f"⚠️ {file_name}: Large file ({file_size / (1024**2):.0f}MB) — "
                            f"client-side encryption skipped, protected by server-side encryption"
                        )
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
                        logger.info(f"[R2] File encrypted: {file_name} ({os.path.getsize(encrypted_path):,} bytes)")
                    except Exception as enc_err:
                        logger.error(f"[R2] Encryption failed — aborting upload for evidence safety: {enc_err}")
                        return UploadResult.from_error(
                            f"Encryption failed for {file_name}: {enc_err}. Upload aborted to prevent plaintext evidence exposure."
                        )
                    finally:
                        del encryption_key_hex

            upload_path = encrypted_path if is_encrypted else file_path

            # Step 2: R2에 직접 업로드
            completed_parts = None
            if is_multipart:
                completed_parts = self._upload_multipart(upload_path, presigned_info)
            else:
                upload_url = presigned_info['upload_url']
                self._upload_single(upload_path, upload_url)

            # 암호화 임시 파일 정리
            if encrypted_path and os.path.exists(encrypted_path):
                os.remove(encrypted_path)

            # Step 3: 서버에 완료 확인
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

            logger.info(f"[R2] Upload complete: {file_name} → {key}")
            return UploadResult(
                success=True,
                artifact_id=confirm_result.get('file_id'),
            )

        except Exception as e:
            sanitized_error = _sanitize_error_for_logging(str(e))
            logger.error(f"[R2] Direct upload failed: {sanitized_error}")

            # 암호화 임시 파일 정리
            if encrypted_path and os.path.exists(encrypted_path):
                os.remove(encrypted_path)

            # Multipart 중단 정리
            if presigned_info and presigned_info.get('upload_id'):
                self._abort_upload(
                    self.case_id,
                    presigned_info.get('key', ''),
                    presigned_info['upload_id'],
                )

            return UploadResult.from_error(f"R2 upload failed: {e}")

    def upload_batch(
        self,
        files: list,
        progress_callback: Callable[[float, str], None] = None,
    ) -> list:
        """Batch upload with R2 direct upload (parallel, max 4 concurrent)."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading

        total = len(files)
        if total == 0:
            return []

        # 결과를 원래 순서대로 유지하기 위해 인덱스 기반 저장
        results = [None] * total
        completed_count = 0
        lock = threading.Lock()

        def _upload_one(idx, file_path, artifact_type, metadata):
            nonlocal completed_count
            result = self.upload_file(file_path, artifact_type, metadata)
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

            # 모든 작업 완료 대기 (예외 전파)
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    idx = futures[future]
                    logger.error(f"[R2] Parallel upload failed (index {idx}): {e}")
                    if results[idx] is None:
                        results[idx] = UploadResult.from_error(str(e))

        return results
