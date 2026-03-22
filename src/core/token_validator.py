"""
Token Validation Module

Validates session tokens with the forensics server.
P1 Security Enhancement: One-time token validation and hardware binding
P2-2: User-friendly error message support
"""
import hashlib
import logging
import os
import time
from typing import Optional, Set
from dataclasses import dataclass

import requests

from utils.hardware_id import get_hardware_id, get_system_info, get_hardware_components
from utils.error_messages import translate_error


def _get_ssl_verify():
    """Get SSL verification parameter for requests.

    In PyInstaller builds, explicitly use certifi CA bundle
    to avoid SSL errors on machines without Python installed.
    """
    try:
        import certifi
        ca_path = certifi.where()
        if os.path.exists(ca_path):
            return ca_path
    except ImportError:
        pass
    # Fallback: env var set by main.py
    for env_key in ('REQUESTS_CA_BUNDLE', 'SSL_CERT_FILE'):
        ca_path = os.environ.get(env_key)
        if ca_path and os.path.exists(ca_path):
            return ca_path
    return True


logger = logging.getLogger(__name__)


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
    challenge_salt: Optional[str] = None
    signing_key: Optional[str] = None


@dataclass
class SessionValidationResult:
    """Session validation result (for pre-collection check)"""
    valid: bool
    case_id: Optional[str] = None
    case_status: Optional[str] = None
    reason: Optional[str] = None
    can_proceed: bool = False


# P1 Security: Track used tokens (prevent reuse within session)
_used_tokens: Set[str] = set()
_token_timestamps: dict = {}  # Token hash -> usage time


def _hash_token(token: str) -> str:
    """Generate token hash (prevent storing original for security)"""
    return hashlib.sha256(token.encode()).hexdigest()


def _is_token_used(token: str) -> bool:
    """Check if token has already been used"""
    token_hash = _hash_token(token)
    return token_hash in _used_tokens


def _mark_token_used(token: str):
    """Mark token as used"""
    token_hash = _hash_token(token)
    _used_tokens.add(token_hash)
    _token_timestamps[token_hash] = time.time()

    # Clean up old tokens (expired after 1 hour)
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
        P1 Security Enhancement: One-time token validation and hardware binding

        Args:
            session_token: Token issued from the web platform
            allow_revalidation: Whether to allow revalidation (default False)

        Returns:
            ValidationResult with authentication details
        """
        try:
            # P1 Security: Prevent token reuse
            if not allow_revalidation and _is_token_used(session_token):
                return ValidationResult(
                    valid=False,
                    error="This token has already been used. Please obtain a new token.",
                )

            # Get hardware info for binding (P0-3: Multiple factors)
            hardware_id = get_hardware_id()
            hardware_components = get_hardware_components()
            system_info = get_system_info()

            # Call authentication endpoint
            # Enforce SSL certificate verification
            response = requests.post(
                f"{self.server_url}/api/v1/collector/authenticate",
                json={
                    "session_token": session_token,
                    "hardware_id": hardware_id,
                    "hardware_components": hardware_components,  # P0-3: Send individual components
                    "client_info": system_info,
                },
                timeout=self.timeout,
                verify=_get_ssl_verify(),
            )

            if response.status_code == 200:
                data = response.json()

                # [2026-02-16] Check status field (defensive: server may return
                # HTTP 200 with status="denied" for failures)
                resp_status = data.get('status', '')
                if resp_status and resp_status in ('denied', 'error', 'failed'):
                    error_msg = data.get('error', '') or data.get('message', '') or data.get('detail', '')
                    logger.warning(
                        f"[TokenValidator] Server returned 200 with denied status: {resp_status}, msg={error_msg[:200] if error_msg else 'N/A'}"
                    )
                    return ValidationResult(
                        valid=False,
                        error=error_msg or "Authentication denied by server.",
                    )

                # P1 Security: Mark token as used on success
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
                    challenge_salt=data.get('challenge_salt'),
                    signing_key=data.get('signing_key'),
                )
            else:
                # M1 Security: Prevent server error exposure - convert to user-friendly message
                status_code = response.status_code
                try:
                    error_json = response.json()
                    error_detail = error_json.get('detail', '')
                    # Extract message field if detail is dict (e.g., 409 error)
                    if isinstance(error_detail, dict):
                        error_detail = error_detail.get('message', str(error_detail))
                except Exception:
                    error_detail = ''

                # User-friendly messages by status code
                if status_code == 401:
                    user_message = "Authentication failed. Token has expired or is invalid."
                elif status_code == 403:
                    user_message = "Access denied. Please contact the administrator."
                elif status_code == 404:
                    user_message = "Requested resource not found."
                elif status_code == 409:
                    # Concurrent collection conflict - use server's detailed message
                    user_message = error_detail if error_detail else "Collection session conflict occurred. Please try again later."
                elif status_code == 429:
                    user_message = "Too many requests. Please try again later."
                elif status_code >= 500:
                    user_message = "Server is experiencing temporary issues. Please try again later."
                else:
                    user_message = "Unable to process the request."

                # Debug log (not exposed to user)
                logger.warning(
                    f"[TokenValidator] Server error: status={status_code}, detail={str(error_detail)[:200] if error_detail else 'N/A'}"
                )

                return ValidationResult(
                    valid=False,
                    error=user_message,
                )

        except requests.exceptions.ConnectionError as e:
            # [Security Logging] Record connection error details
            logger.error(
                f"[TokenValidator] Connection error: server={self.server_url}, error={e}"
            )
            # P2-2: User-friendly error message
            friendly = translate_error(f"Connection error: {str(e)}")
            return ValidationResult(
                valid=False,
                error=f"{friendly.title}\n{friendly.message}\n\nSolution:\n{friendly.solution}",
            )
        except requests.exceptions.Timeout:
            # [Security Logging] Record timeout
            logger.warning(
                f"[TokenValidator] Connection timeout: server={self.server_url}"
            )
            # P2-2: User-friendly error message
            friendly = translate_error("Connection timeout")
            return ValidationResult(
                valid=False,
                error=f"{friendly.title}\n{friendly.message}\n\nSolution:\n{friendly.solution}",
            )
        except Exception as e:
            # P2-2: User-friendly error message
            friendly = translate_error(str(e))
            return ValidationResult(
                valid=False,
                error=f"{friendly.title}\n{friendly.message}\n\nSolution:\n{friendly.solution}",
            )

    def check_server_health(self) -> tuple:
        """Check if the server is reachable.

        Returns:
            (success: bool, error_detail: str | None)
        """
        url = f"{self.server_url}/health"
        ssl_verify = _get_ssl_verify()
        try:
            response = requests.get(url, timeout=10, verify=ssl_verify)
            return response.status_code == 200, None
        except requests.exceptions.SSLError as e:
            detail = f"SSL certificate error: {e}"
            logger.error(f"[Health] {detail} (verify={ssl_verify})")
            return False, detail
        except requests.exceptions.ConnectionError as e:
            detail = f"Connection failed: {e}"
            logger.error(f"[Health] {detail}")
            return False, detail
        except Exception as e:
            detail = f"{type(e).__name__}: {e}"
            logger.error(f"[Health] {detail}")
            return False, detail

    def validate_session(self, session_id: str, collection_token: str) -> SessionValidationResult:
        """
        Validate session (for pre-collection check)

        Checks session status using only session_id and collection_token without the original token.
        Detects cancelled cases, expired sessions, etc. and notifies the user.

        Args:
            session_id: Collection session ID (received during authentication)
            collection_token: Collection token (received during authentication)

        Returns:
            SessionValidationResult: Session validation result
        """
        try:
            # Enforce SSL certificate verification
            response = requests.post(
                f"{self.server_url}/api/v1/collector/validate-session",
                json={
                    "session_id": session_id,
                    "collection_token": collection_token,
                },
                timeout=self.timeout,
                verify=_get_ssl_verify(),
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
                # Server error
                try:
                    error_detail = response.json().get("detail", "")
                except Exception:
                    error_detail = response.text[:200] if response.text else ""

                return SessionValidationResult(
                    valid=False,
                    reason=f"Server error ({response.status_code}): {error_detail}",
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
