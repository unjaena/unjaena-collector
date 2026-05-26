import base64
import hashlib
import hmac
import json
import os
import platform
import tempfile
import time
from pathlib import Path
from typing import Any

import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .models import AuthSession, CollectionProfile, ProfileTarget


def _canonical(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hardware_id() -> str:
    raw = f"{platform.node()}:{platform.platform()}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _headers(session: AuthSession) -> dict[str, str]:
    return {
        "X-Session-ID": session.session_id,
        "X-Collection-Token": session.collection_token,
    }


class ServiceClient:
    def __init__(self, server_url: str, timeout: int = 30):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout

    def authenticate(self, token: str) -> AuthSession:
        payload = {
            "session_token": token,
            "hardware_id": _hardware_id(),
            "client_info": {
                "hostname": platform.node(),
                "platform": platform.platform(),
                "client": "unjaena-collector",
            },
        }
        res = requests.post(
            f"{self.server_url}/api/v1/collector/authenticate",
            json=payload,
            timeout=self.timeout,
        )
        res.raise_for_status()
        data = res.json()
        return AuthSession(
            session_id=data["session_id"],
            case_id=data["case_id"],
            collection_token=data["collection_token"],
            server_url=data.get("server_url") or self.server_url,
            signing_key=data.get("signing_key"),
        )

    def get_profile(self, session: AuthSession) -> CollectionProfile:
        res = requests.post(
            f"{self.server_url}/api/v1/collector/collection/profile",
            headers=_headers(session),
            timeout=self.timeout,
        )
        res.raise_for_status()
        data = res.json()
        profile = CollectionProfile(
            profile_id=data["profile_id"],
            case_id=data["case_id"],
            expires_at=data["expires_at"],
            upload_mode=data.get("upload_mode", "r2_presigned"),
            signature=data.get("signature"),
            targets=[
                ProfileTarget(
                    artifact_type=item["artifact_type"],
                    kind=item.get("kind", "glob"),
                    patterns=list(item.get("patterns") or []),
                    max_bytes=item.get("max_bytes"),
                    metadata=dict(item.get("metadata") or {}),
                )
                for item in data.get("targets", [])
            ],
        )
        if session.signing_key and profile.signature:
            signed = dict(data)
            signature = signed.pop("signature", None)
            expected = base64.urlsafe_b64encode(
                hmac.new(session.signing_key.encode("utf-8"), _canonical(signed), hashlib.sha256).digest()
            ).decode("ascii").rstrip("=")
            if not hmac.compare_digest(signature or "", expected):
                raise RuntimeError("Collection profile signature verification failed")
        return profile

    def presign(self, session: AuthSession, path: Path, artifact_type: str, digest: str, profile_id: str | None = None) -> dict[str, Any]:
        payload = {
            "case_id": session.case_id,
            "file_name": path.name,
            "file_size": path.stat().st_size,
            "file_hash": digest,
            "artifact_type": artifact_type,
            "content_type": "application/octet-stream",
            "profile_id": profile_id,
        }
        res = requests.post(
            f"{self.server_url}/api/v1/collector/r2/presigned-url",
            headers=_headers(session),
            json=payload,
            timeout=self.timeout,
        )
        res.raise_for_status()
        return res.json()

    def complete(self, session: AuthSession, path: Path, artifact_type: str, digest: str, key: str, upload_id: str | None = None, parts: list[dict[str, Any]] | None = None, is_encrypted: bool = False, profile_id: str | None = None) -> dict[str, Any]:
        payload = {
            "case_id": session.case_id,
            "key": key,
            "upload_id": upload_id,
            "file_hash": digest,
            "file_name": path.name,
            "artifact_type": artifact_type,
            "parts": parts,
            "is_encrypted": is_encrypted,
            "original_path": str(path),
            "profile_id": profile_id,
        }
        res = requests.post(
            f"{self.server_url}/api/v1/collector/r2/upload-complete",
            headers=_headers(session),
            json=payload,
            timeout=self.timeout,
        )
        res.raise_for_status()
        return res.json()

    def upload_file(self, upload_url: str, path: Path) -> None:
        with path.open("rb") as handle:
            res = requests.put(upload_url, data=handle, timeout=max(self.timeout, 300))
        res.raise_for_status()

    def upload_multipart(self, upload_urls: list[dict[str, Any]], path: Path) -> list[dict[str, Any]]:
        parts = []
        with path.open("rb") as handle:
            for item in sorted(upload_urls, key=lambda p: int(p["part_number"])):
                start = int(item["start"])
                end = int(item["end"])
                handle.seek(start)
                data = handle.read(end - start)
                res = requests.put(item["url"], data=data, timeout=max(self.timeout, 300))
                res.raise_for_status()
                etag = res.headers.get("ETag") or res.headers.get("etag")
                if not etag:
                    raise RuntimeError("Multipart upload response did not include ETag")
                parts.append({"PartNumber": int(item["part_number"]), "ETag": etag})
        return parts


def encrypted_temp_file(path: Path, key_hex: str, digest: str) -> Path:
    key = bytes.fromhex(key_hex)
    nonce = os.urandom(12)
    aad = digest.encode("utf-8")
    handle = tempfile.NamedTemporaryFile(delete=False)
    temp_path = Path(handle.name)
    try:
        handle.write(nonce)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(aad)
        with path.open("rb") as src:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                encrypted = encryptor.update(chunk)
                if encrypted:
                    handle.write(encrypted)
        final = encryptor.finalize()
        if final:
            handle.write(final)
        handle.write(encryptor.tag)
        return temp_path
    except Exception:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise
    finally:
        handle.close()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
