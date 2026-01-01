"""
Token Validation Module

Validates session tokens with the forensics server.
P1 보안 강화: 토큰 일회용 검증 및 하드웨어 바인딩
P2-2: 사용자 친화적 에러 메시지 지원
"""
import requests
import hashlib
import time
from typing import Optional, Set
from dataclasses import dataclass

from utils.hardware_id import get_hardware_id, get_system_info, get_hardware_components
from utils.error_messages import translate_error


@dataclass
class ValidationResult:
    """Token validation result"""
    valid: bool
    session_id: Optional[str] = None
    case_id: Optional[str] = None
    allowed_artifacts: Optional[list] = None
    collection_token: Optional[str] = None
    server_url: Optional[str] = None
    ws_url: Optional[str] = None
    expires_at: Optional[str] = None
    error: Optional[str] = None


@dataclass
class SessionValidationResult:
    """Session validation result (for pre-collection check)"""
    valid: bool
    case_id: Optional[str] = None
    case_status: Optional[str] = None
    reason: Optional[str] = None
    can_proceed: bool = False


# P1 보안: 사용된 토큰 추적 (세션 내 재사용 방지)
_used_tokens: Set[str] = set()
_token_timestamps: dict = {}  # 토큰 해시 -> 사용 시간


def _hash_token(token: str) -> str:
    """토큰 해시 생성 (보안상 원본 저장 방지)"""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def _is_token_used(token: str) -> bool:
    """토큰이 이미 사용되었는지 확인"""
    token_hash = _hash_token(token)
    return token_hash in _used_tokens


def _mark_token_used(token: str):
    """토큰을 사용됨으로 표시"""
    token_hash = _hash_token(token)
    _used_tokens.add(token_hash)
    _token_timestamps[token_hash] = time.time()

    # 오래된 토큰 정리 (1시간 이상 경과)
    current_time = time.time()
    expired_hashes = [
        h for h, t in _token_timestamps.items()
        if current_time - t > 3600
    ]
    for h in expired_hashes:
        _used_tokens.discard(h)
        _token_timestamps.pop(h, None)


class TokenValidator:
    """
    Session token validator.

    Authenticates the collector with the forensics server
    using session tokens issued from the web platform.
    """

    def __init__(self, server_url: str):
        """
        Initialize the validator.

        Args:
            server_url: Base URL of the forensics server (e.g., http://localhost:8000)
        """
        self.server_url = server_url.rstrip('/')
        self.timeout = 30

    def validate(self, session_token: str, allow_revalidation: bool = False) -> ValidationResult:
        """
        Validate a session token with the server.
        P1 보안 강화: 토큰 일회용 검증 및 하드웨어 바인딩

        Args:
            session_token: Token issued from the web platform
            allow_revalidation: 재검증 허용 여부 (기본 False)

        Returns:
            ValidationResult with authentication details
        """
        try:
            # P1 보안: 토큰 재사용 방지
            if not allow_revalidation and _is_token_used(session_token):
                return ValidationResult(
                    valid=False,
                    error="이 토큰은 이미 사용되었습니다. 새 토큰을 발급받으세요.",
                )

            # Get hardware info for binding (P0-3: 다중 요소)
            hardware_id = get_hardware_id()
            hardware_components = get_hardware_components()
            system_info = get_system_info()

            # Call authentication endpoint
            response = requests.post(
                f"{self.server_url}/api/v1/collector/authenticate",
                json={
                    "session_token": session_token,
                    "hardware_id": hardware_id,
                    "hardware_components": hardware_components,  # P0-3: 개별 요소 전송
                    "client_info": system_info,
                },
                timeout=self.timeout,
            )

            if response.status_code == 200:
                data = response.json()

                # P1 보안: 성공 시 토큰 사용 표시
                _mark_token_used(session_token)

                return ValidationResult(
                    valid=True,
                    session_id=data.get('session_id'),
                    case_id=data.get('case_id'),
                    allowed_artifacts=data.get('allowed_artifacts', []),
                    collection_token=data.get('collection_token'),
                    server_url=data.get('server_url'),
                    ws_url=data.get('ws_url'),
                    expires_at=data.get('expires_at'),
                )
            else:
                # M1 보안: 서버 에러 정보 노출 방지 - 사용자 친화적 메시지로 변환
                status_code = response.status_code
                try:
                    error_detail = response.json().get('detail', '')
                except Exception:
                    error_detail = ''

                # 상태 코드별 사용자 친화적 메시지
                if status_code == 401:
                    user_message = "인증에 실패했습니다. 토큰이 만료되었거나 유효하지 않습니다."
                elif status_code == 403:
                    user_message = "접근 권한이 없습니다. 관리자에게 문의하세요."
                elif status_code == 404:
                    user_message = "요청한 리소스를 찾을 수 없습니다."
                elif status_code == 429:
                    user_message = "너무 많은 요청이 발생했습니다. 잠시 후 다시 시도하세요."
                elif status_code >= 500:
                    user_message = "서버에 일시적인 문제가 발생했습니다. 잠시 후 다시 시도하세요."
                else:
                    user_message = "요청을 처리할 수 없습니다."

                # 디버깅용 로그 (사용자에게는 노출하지 않음)
                import logging
                logging.getLogger(__name__).warning(
                    f"[TokenValidator] Server error: status={status_code}, detail={error_detail[:200] if error_detail else 'N/A'}"
                )

                return ValidationResult(
                    valid=False,
                    error=user_message,
                )

        except requests.exceptions.ConnectionError as e:
            # P2-2: 사용자 친화적 에러 메시지
            friendly = translate_error(f"Connection error: {str(e)}")
            return ValidationResult(
                valid=False,
                error=f"{friendly.title}\n{friendly.message}\n\n💡 해결 방법:\n{friendly.solution}",
            )
        except requests.exceptions.Timeout:
            # P2-2: 사용자 친화적 에러 메시지
            friendly = translate_error("Connection timeout")
            return ValidationResult(
                valid=False,
                error=f"{friendly.title}\n{friendly.message}\n\n💡 해결 방법:\n{friendly.solution}",
            )
        except Exception as e:
            # P2-2: 사용자 친화적 에러 메시지
            friendly = translate_error(str(e))
            return ValidationResult(
                valid=False,
                error=f"{friendly.title}\n{friendly.message}\n\n💡 해결 방법:\n{friendly.solution}",
            )

    def check_server_health(self) -> bool:
        """Check if the server is reachable."""
        try:
            response = requests.get(
                f"{self.server_url}/health",
                timeout=10,
            )
            return response.status_code == 200
        except Exception:
            return False

    def validate_session(self, session_id: str, collection_token: str) -> SessionValidationResult:
        """
        세션 유효성 검증 (수집 시작 전 확인용)
        
        원본 토큰 없이 session_id와 collection_token만으로 세션 상태를 확인합니다.
        취소된 케이스, 만료된 세션 등을 감지하여 사용자에게 안내합니다.
        
        Args:
            session_id: 수집 세션 ID (인증 시 받은 값)
            collection_token: 컬렉션 토큰 (인증 시 받은 값)
        
        Returns:
            SessionValidationResult: 세션 유효성 검증 결과
        """
        try:
            response = requests.post(
                f"{self.server_url}/api/v1/collector/validate-session",
                json={
                    "session_id": session_id,
                    "collection_token": collection_token,
                },
                timeout=self.timeout,
            )
            
            if response.status_code == 200:
                data = response.json()
                return SessionValidationResult(
                    valid=data.get("valid", False),
                    case_id=data.get("case_id"),
                    case_status=data.get("case_status"),
                    reason=data.get("reason"),
                    can_proceed=data.get("can_proceed", False),
                )
            else:
                # 서버 에러
                try:
                    error_detail = response.json().get("detail", "")
                except Exception:
                    error_detail = response.text[:200] if response.text else ""
                
                return SessionValidationResult(
                    valid=False,
                    reason=f"서버 오류 ({response.status_code}): {error_detail}",
                    can_proceed=False,
                )
                
        except requests.exceptions.ConnectionError as e:
            friendly = translate_error(f"Connection error: {str(e)}")
            return SessionValidationResult(
                valid=False,
                reason=f"{friendly.title}: {friendly.message}",
                can_proceed=False,
            )
        except requests.exceptions.Timeout:
            friendly = translate_error("Connection timeout")
            return SessionValidationResult(
                valid=False,
                reason=f"{friendly.title}: {friendly.message}",
                can_proceed=False,
            )
        except Exception as e:
            friendly = translate_error(str(e))
            return SessionValidationResult(
                valid=False,
                reason=f"{friendly.title}: {friendly.message}",
                can_proceed=False,
            )
