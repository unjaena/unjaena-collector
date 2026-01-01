"""
Real-time Upload Module

Handles file uploads with WebSocket progress reporting.
P2-2: 사용자 친화적 에러 메시지 지원
"""
import asyncio
import json
import aiohttp
import websockets
import requests  # 동기 업로드용
from pathlib import Path
from datetime import datetime
from typing import Callable, Optional
from dataclasses import dataclass
import os

from utils.error_messages import translate_error, UserFriendlyError


@dataclass
class UploadResult:
    """Upload result (P2-2: 확장된 에러 정보)"""
    success: bool
    artifact_id: Optional[str] = None
    error: Optional[str] = None
    error_title: Optional[str] = None      # P2-2: 사용자 친화적 에러 제목
    error_solution: Optional[str] = None   # P2-2: 해결 방법
    is_recoverable: bool = True            # P2-2: 재시도 가능 여부

    @classmethod
    def from_error(cls, technical_error: str) -> 'UploadResult':
        """기술적 에러로부터 사용자 친화적 UploadResult 생성"""
        friendly = translate_error(technical_error)
        return cls(
            success=False,
            error=friendly.message,
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

    # M2 보안: 기본 최대 파일 크기 (10GB)
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
    ):
        """
        Initialize the uploader.

        Args:
            server_url: HTTP server URL (e.g., http://localhost:8000)
            ws_url: WebSocket URL (e.g., ws://localhost:8000)
            session_id: Collection session ID
            collection_token: Authentication token for uploads
            case_id: Case ID for the collection
            consent_record: Legal consent record (P0 법적 필수)
            max_file_size: Maximum file size in bytes (M2 보안)
        """
        self.server_url = server_url.rstrip('/')
        self.ws_url = ws_url.rstrip('/')
        self.session_id = session_id
        self.collection_token = collection_token
        self.case_id = case_id
        self.consent_record = consent_record
        self.max_file_size = max_file_size or self.DEFAULT_MAX_FILE_SIZE
        self.ws = None

    async def connect_websocket(self):
        """Establish WebSocket connection for progress reporting."""
        try:
            ws_endpoint = f"{self.ws_url}/ws/collection/{self.session_id}"
            extra_headers = {
                'X-Collection-Token': self.collection_token,
            }
            self.ws = await websockets.connect(ws_endpoint, extra_headers=extra_headers)
        except Exception as e:
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
        # M2 보안: 파일 크기 검증 (스토리지 고갈 방지)
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
                error=f"파일 크기({file_size_gb:.2f}GB)가 최대 허용 크기({max_size_gb:.1f}GB)를 초과합니다.",
                error_title="파일 크기 초과",
                error_solution="파일을 분할하거나 관리자에게 문의하세요.",
                is_recoverable=False,
            )

        if file_size == 0:
            return UploadResult(
                success=False,
                error="빈 파일은 업로드할 수 없습니다.",
                error_title="빈 파일",
                error_solution="파일 내용을 확인하세요.",
                is_recoverable=False,
            )

        try:
            # 파일 크기 기반 동적 타임아웃 계산 (최소 5분, 최대 30분)
            # 10MB/s 업로드 속도 가정 + 여유 시간 2분
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
                    # P0 법적 필수: 동의 기록 서버 전송
                    if self.consent_record:
                        data.add_field('consent_record', json.dumps(self.consent_record))

                    async with session.post(
                        f"{self.server_url}/api/v1/collector/raw-files/upload",
                        data=data,
                        headers={
                            'X-Session-ID': self.session_id,
                            'X-Collection-Token': self.collection_token,
                        },
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            return UploadResult(
                                success=True,
                                artifact_id=result.get('artifact_id'),
                            )
                        else:
                            error_text = await response.text()
                            # P2-2: 사용자 친화적 에러 메시지
                            return UploadResult.from_error(
                                f"Upload failed ({response.status}): {error_text}"
                            )

        except aiohttp.ClientError as e:
            # P2-2: 사용자 친화적 에러 메시지
            return UploadResult.from_error(f"Connection error: {str(e)}")
        except Exception as e:
            # P2-2: 사용자 친화적 에러 메시지
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

    PyQt QThread와 호환되도록 asyncio 대신 requests 사용.
    asyncio.run()은 QThread 내에서 블로킹 문제를 일으킬 수 있음.
    """

    # 기본 최대 파일 크기 (10GB)
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
    ):
        self.server_url = server_url.rstrip('/')
        self.ws_url = ws_url.rstrip('/')
        self.session_id = session_id
        self.collection_token = collection_token
        self.case_id = case_id
        self.consent_record = consent_record
        self.max_file_size = max_file_size or self.DEFAULT_MAX_FILE_SIZE

    def upload_file(
        self,
        file_path: str,
        artifact_type: str,
        metadata: dict,
        progress_callback: Callable[[float], None] = None,
    ) -> UploadResult:
        """
        동기 파일 업로드 (requests 사용).

        PyQt QThread에서 안전하게 호출 가능.
        """
        # 파일 크기 검증
        try:
            file_size = os.path.getsize(file_path)
        except OSError as e:
            return UploadResult.from_error(f"Cannot access file: {e}")

        if file_size > self.max_file_size:
            max_size_gb = self.max_file_size / (1024 * 1024 * 1024)
            file_size_gb = file_size / (1024 * 1024 * 1024)
            return UploadResult(
                success=False,
                error=f"파일 크기({file_size_gb:.2f}GB)가 최대 허용 크기({max_size_gb:.1f}GB)를 초과합니다.",
                error_title="파일 크기 초과",
                error_solution="파일을 분할하거나 관리자에게 문의하세요.",
                is_recoverable=False,
            )

        if file_size == 0:
            return UploadResult(
                success=False,
                error="빈 파일은 업로드할 수 없습니다.",
                error_title="빈 파일",
                error_solution="파일 내용을 확인하세요.",
                is_recoverable=False,
            )

        # 파일 크기 기반 동적 타임아웃 (최소 5분, 최대 30분)
        # 1MB/s 업로드 속도 가정 + 여유 시간 2분
        upload_timeout = max(300, min(1800, (file_size / (1 * 1024 * 1024)) + 120))

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

                response = requests.post(
                    f"{self.server_url}/api/v1/collector/raw-files/upload",
                    files=files,
                    data=data,
                    headers=headers,
                    timeout=upload_timeout,
                )

                if response.status_code == 200:
                    result = response.json()
                    return UploadResult(
                        success=True,
                        artifact_id=result.get('artifact_id'),
                    )
                else:
                    error_text = response.text
                    return UploadResult.from_error(
                        f"Upload failed ({response.status_code}): {error_text}"
                    )

        except requests.exceptions.Timeout:
            return UploadResult.from_error(f"Upload timeout after {upload_timeout}s")
        except requests.exceptions.ConnectionError as e:
            return UploadResult.from_error(f"Connection error: {str(e)}")
        except Exception as e:
            return UploadResult.from_error(f"Upload error: {str(e)}")

    def upload_batch(
        self,
        files: list,
        progress_callback: Callable[[float, str], None] = None,
    ) -> list:
        """배치 업로드."""
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
