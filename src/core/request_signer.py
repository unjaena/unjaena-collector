"""
Request Signing Module

HMAC-SHA256 request signing for collector → server communication.
Prevents unauthorized API calls (curl, Postman) by requiring a signature
derived from a server-issued ephemeral key + hardware binding + server challenge.

Key derivation chain:
  [Server] /authenticate → signing_key (hex, per-session ephemeral)
  [Client]
    1. signing_key (hex) → bytes
    2. HKDF(signing_key, salt=challenge_salt+hardware_id, info=CONTEXT)
       → derived_key (per-machine, per-session)

NO embedded secrets in the binary. The signing key is delivered over TLS
at authentication time and never persisted to disk.
"""
import hashlib
import hmac
import os
import time
from typing import Dict, Optional

_HKDF_INFO = b"collector-request-signing-v1"


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """
    HKDF-SHA256 (RFC 5869) — extract-then-expand.
    No external dependency required.
    """
    # Extract
    if not salt:
        salt = b'\x00' * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    # Expand
    t = b""
    okm = b""
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


class RequestSigner:
    """
    Signs outgoing HTTP requests with HMAC-SHA256.

    Usage:
        signer = RequestSigner(hardware_id, challenge_salt, signing_key)
        headers = signer.sign_request("POST", "/api/v1/collector/raw-files/upload", body, token)
        # Merge headers into the request
    """

    def __init__(self, hardware_id: str, challenge_salt: str, signing_key: str):
        """
        Derive a per-session signing key.

        Args:
            hardware_id: SHA-256 hardware fingerprint from this machine
            challenge_salt: Random salt issued by the server during /authenticate
            signing_key: Hex-encoded ephemeral key issued by the server during /authenticate
        """
        if not signing_key:
            raise ValueError("signing_key is required (issued by server at /authenticate)")

        # Step 1: Decode server-issued ephemeral key
        base_key = bytes.fromhex(signing_key)

        # Step 2: HKDF with machine + session binding
        salt = (challenge_salt + hardware_id).encode("utf-8")
        self._derived_key = _hkdf_sha256(base_key, salt, _HKDF_INFO, length=32)

    def sign_request(
        self,
        method: str,
        path: str,
        body: Optional[bytes] = None,
        collection_token: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Compute HMAC-SHA256 signature for a request.

        Args:
            method: HTTP method (GET, POST, ...)
            path: URL path (e.g. /api/v1/collector/raw-files/upload)
            body: Raw request body bytes (None or b"" for multipart/no-body)
            collection_token: The collection token (first 32 chars used)

        Returns:
            Dict with 3 headers to merge into the request:
              X-Client-Signature, X-Client-Timestamp, X-Client-Nonce
        """
        timestamp = str(int(time.time()))
        nonce = os.urandom(16).hex()  # 32 hex chars

        # Body hash (empty string hash for multipart / no body)
        if isinstance(body, str):
            body = body.encode("utf-8")
        body_hash = hashlib.sha256(body if body else b"").hexdigest()

        # Token prefix for binding (prevents cross-token replay)
        token_prefix = (collection_token or "")[:32]  # [SEC] 32자로 확대

        # Canonical string
        canonical = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_hash}\n{token_prefix}"

        signature = hmac.new(
            self._derived_key,
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return {
            "X-Client-Signature": signature,
            "X-Client-Timestamp": timestamp,
            "X-Client-Nonce": nonce,
        }
