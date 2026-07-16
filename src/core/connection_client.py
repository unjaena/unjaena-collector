"""Trusted collector device pairing and signed connection synchronization."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import http.server
import json
import os
import platform
import secrets
import socket
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.token_validator import _get_ssl_verify
from utils.hardware_id import get_hardware_id, get_system_info


KEYRING_SERVICE = "com.unjaena.collector.connection"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _server_key(server_url: str) -> str:
    return hashlib.sha256(server_url.rstrip("/").lower().encode("utf-8")).hexdigest()[:24]


@dataclass
class DeviceIdentity:
    private_key: str
    public_key: str
    device_id: Optional[str] = None

    @classmethod
    def generate(cls) -> "DeviceIdentity":
        key = Ed25519PrivateKey.generate()
        private_bytes = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cls(private_key=_b64(private_bytes), public_key=_b64(public_bytes))

    def signer(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(_b64decode(self.private_key))


class DeviceIdentityStore:
    """Persist the device key in the operating system credential store."""

    def __init__(self, server_url: str):
        self.username = f"device:{_server_key(server_url)}"

    @staticmethod
    def _keyring():
        try:
            import keyring
            from keyring.errors import KeyringError, NoKeyringError

            return keyring, (KeyringError, NoKeyringError)
        except ImportError as exc:
            raise RuntimeError("Secure credential storage is unavailable; install the keyring package") from exc

    def load(self) -> Optional[DeviceIdentity]:
        keyring, errors = self._keyring()
        try:
            raw = keyring.get_password(KEYRING_SERVICE, self.username)
        except errors as exc:
            raise RuntimeError(f"Unable to read the operating system credential store: {exc}") from exc
        if not raw:
            return None
        try:
            return DeviceIdentity(**json.loads(raw))
        except Exception as exc:
            raise RuntimeError("Stored collector device identity is invalid") from exc

    def save(self, identity: DeviceIdentity) -> None:
        keyring, errors = self._keyring()
        try:
            keyring.set_password(KEYRING_SERVICE, self.username, json.dumps(asdict(identity)))
        except errors as exc:
            raise RuntimeError(f"Unable to write the operating system credential store: {exc}") from exc

    def load_or_create(self) -> DeviceIdentity:
        identity = self.load()
        if identity:
            return identity
        identity = DeviceIdentity.generate()
        self.save(identity)
        return identity


class PendingCollectionSessionStore:
    """Store an authenticated but unfinished trusted run in the OS keyring."""

    def __init__(self, server_url: str):
        self.username = f"pending-run:{_server_key(server_url)}"

    def load(self) -> Optional[Dict[str, Any]]:
        keyring, errors = DeviceIdentityStore._keyring()
        try:
            raw = keyring.get_password(KEYRING_SERVICE, self.username)
        except errors as exc:
            raise RuntimeError(f"Unable to read the pending collection session: {exc}") from exc
        if not raw:
            return None
        try:
            value = json.loads(raw)
            return value if isinstance(value, dict) else None
        except Exception as exc:
            raise RuntimeError("Stored pending collection session is invalid") from exc

    def save(self, value: Dict[str, Any]) -> None:
        keyring, errors = DeviceIdentityStore._keyring()
        try:
            keyring.set_password(
                KEYRING_SERVICE,
                self.username,
                json.dumps(value, separators=(",", ":"), sort_keys=True),
            )
        except errors as exc:
            raise RuntimeError(f"Unable to save the pending collection session: {exc}") from exc

    def clear(self) -> None:
        keyring, errors = DeviceIdentityStore._keyring()
        try:
            if keyring.get_password(KEYRING_SERVICE, self.username):
                keyring.delete_password(KEYRING_SERVICE, self.username)
        except errors as exc:
            raise RuntimeError(f"Unable to clear the pending collection session: {exc}") from exc


class BrowserAuthorizationSession:
    """One-shot loopback receiver for collector-originated web authorization."""

    CALLBACK_PATH = "/collector/callback"

    def __init__(
        self,
        *,
        server_url: str,
        identity: DeviceIdentity,
        client_version: str,
        locale: str,
        callback_copy: Optional[Dict[str, str]] = None,
    ):
        self.server_url = server_url.rstrip("/")
        self.identity = identity
        self.client_version = client_version or "0.0.0"
        self.locale = locale if locale in {"en", "ko", "ja"} else "en"
        callback_defaults = {
            "title": "Collector authentication complete",
            "message": "The browser approval was securely returned to the collector.",
            "next_title": "Continue in the collector",
            "next_steps": (
                "Return to the collector window. After the connection finishes, "
                "choose the evidence source to continue. You may close this browser tab."
            ),
        }
        supplied_copy = callback_copy or {}
        self.callback_copy = {
            key: str(supplied_copy.get(key) or fallback)
            for key, fallback in callback_defaults.items()
        }
        self.code_verifier = secrets.token_urlsafe(64)
        self.callback_state = secrets.token_urlsafe(32)
        self.request_nonce = secrets.token_urlsafe(32)
        self._authorization_code = ""
        self._server = http.server.HTTPServer(("127.0.0.1", 0), self._handler_class())
        self._server.timeout = 0.5

        challenge = _b64(hashlib.sha256(self.code_verifier.encode("ascii")).digest())
        request_payload = {
            "version": 1,
            "issued_at": int(time.time()),
            "request_nonce": self.request_nonce,
            "public_key": identity.public_key,
            "pkce_challenge": challenge,
            "callback_port": int(self._server.server_port),
            "callback_state": self.callback_state,
            "display_name": "Collector",
            "platform": platform.system().lower(),
            "client_version": self.client_version,
        }
        encoded_request = _b64(
            json.dumps(request_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        canonical = f"collector-browser-authorization-v1\n{encoded_request}".encode("utf-8")
        request_signature = _b64(identity.signer().sign(canonical))
        query = urlencode(
            {
                "quickStart": "1",
                "collector_request": encoded_request,
                "collector_signature": request_signature,
            }
        )
        self.authorization_url = f"{self.server_url}/{self.locale}?{query}"

    def _handler_class(self):
        session = self

        class LoopbackHandler(http.server.BaseHTTPRequestHandler):
            server_version = "CollectorLoopback/1"
            sys_version = ""

            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def _respond(
                self,
                status: int,
                title: str,
                message: str,
                next_title: str = "",
                next_steps: str = "",
            ) -> None:
                safe_title = html.escape(title)
                safe_message = html.escape(message)
                safe_next_title = html.escape(next_title)
                safe_next_steps = html.escape(next_steps)
                next_section = ""
                if safe_next_title and safe_next_steps:
                    next_section = (
                        "<section style='margin-top:2rem;padding:1.25rem;"
                        "border:1px solid #d1d5db;border-radius:.5rem;background:#f8fafc'>"
                        f"<h2 style='margin:0 0 .5rem;font-size:1.15rem'>{safe_next_title}</h2>"
                        f"<p style='margin:0'>{safe_next_steps}</p></section>"
                    )
                body = (
                    f"<!doctype html><html lang='{session.locale}'><head><meta charset='utf-8'>"
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                    f"<title>{safe_title}</title></head>"
                    "<body style='font-family:system-ui;margin:3rem auto;padding:0 1.25rem;"
                    "max-width:42rem;line-height:1.6;color:#111827'>"
                    f"<h1>{safe_title}</h1><p>{safe_message}</p>{next_section}</body></html>"
                ).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Pragma", "no-cache")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
                )
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

            def do_GET(self) -> None:
                if self.client_address[0] != "127.0.0.1":
                    self._respond(403, "Connection rejected", "Only this computer can finish authorization.")
                    return
                expected_host = f"127.0.0.1:{session._server.server_port}"
                if self.headers.get("Host", "") != expected_host:
                    self._respond(400, "Connection rejected", "The loopback host did not match.")
                    return
                parsed = urlparse(self.path)
                if parsed.path != session.CALLBACK_PATH:
                    self._respond(404, "Not found", "This callback path is not available.")
                    return
                query = parse_qs(parsed.query, keep_blank_values=True)
                state_values = query.get("state") or []
                code_values = query.get("code") or []
                state = state_values[0] if len(state_values) == 1 else ""
                code = code_values[0] if len(code_values) == 1 else ""
                if not hmac.compare_digest(state, session.callback_state):
                    self._respond(400, "Connection rejected", "The authorization state did not match.")
                    return
                if not (20 <= len(code) <= 256):
                    self._respond(400, "Connection rejected", "The authorization code was invalid.")
                    return
                if session._authorization_code:
                    self._respond(409, "Already connected", "This authorization was already received.")
                    return
                session._authorization_code = code
                self._respond(
                    200,
                    session.callback_copy["title"],
                    session.callback_copy["message"],
                    session.callback_copy["next_title"],
                    session.callback_copy["next_steps"],
                )

        return LoopbackHandler

    def poll_for_code(self) -> str:
        self._server.handle_request()
        return self._authorization_code

    def wait_for_code(self, should_continue, timeout_seconds: int = 10 * 60) -> str:
        deadline = time.monotonic() + timeout_seconds
        try:
            while should_continue() and time.monotonic() < deadline:
                self._server.handle_request()
                if self._authorization_code:
                    return self._authorization_code
        finally:
            self._server.server_close()
        if not should_continue():
            raise RuntimeError("Collector browser authorization was cancelled")
        raise TimeoutError("Collector browser authorization expired")

    def close(self) -> None:
        self._server.server_close()


class CollectorConnectionClient:
    def __init__(self, server_url: str, timeout: int = 15):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.store = DeviceIdentityStore(self.server_url)
        self.identity = self.store.load_or_create()

    def _request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> requests.Response:
        body = b""
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.identity.device_id:
            timestamp = str(int(time.time()))
            nonce = secrets.token_urlsafe(18)
            canonical = "\n".join(
                [timestamp, nonce, method.upper(), path, hashlib.sha256(body).hexdigest()]
            ).encode("utf-8")
            headers.update(
                {
                    "X-Device-Timestamp": timestamp,
                    "X-Device-Nonce": nonce,
                    "X-Device-Signature": _b64(self.identity.signer().sign(canonical)),
                }
            )
        return requests.request(
            method,
            f"{self.server_url}{path}",
            data=body if body else None,
            headers=headers,
            timeout=self.timeout,
            verify=_get_ssl_verify(),
        )

    def begin_browser_authorization(
        self,
        client_version: str,
        locale: str = "en",
        callback_copy: Optional[Dict[str, str]] = None,
    ) -> BrowserAuthorizationSession:
        return BrowserAuthorizationSession(
            server_url=self.server_url,
            identity=self.identity,
            client_version=client_version,
            locale=locale,
            callback_copy=callback_copy,
        )

    def claim(
        self,
        pairing_code: str,
        client_version: str,
        code_verifier: str = "",
    ) -> Dict[str, Any]:
        system_info = get_system_info()
        hardware_id = get_hardware_id()
        proof = "\n".join(
            ["collector-pairing-v1", pairing_code, self.identity.public_key, hardware_id]
        ).encode("utf-8")
        payload = {
            "pairing_code": pairing_code,
            "public_key": self.identity.public_key,
            "proof_signature": _b64(self.identity.signer().sign(proof)),
            "code_verifier": code_verifier,
            "hardware_id": hardware_id,
            "display_name": socket.gethostname() or platform.node() or "Collector",
            "platform": platform.system().lower(),
            "client_version": client_version or "0.0.0",
            "metadata": {
                "platform_release": platform.release(),
                "architecture": platform.machine(),
                "system_info": system_info,
            },
        }
        response = self._request("POST", "/api/v1/collector/connections/claim", payload)
        response.raise_for_status()
        data = response.json()
        self.identity.device_id = str(data["device_id"])
        self.store.save(self.identity)
        return data

    def sync(self) -> Dict[str, Any]:
        if not self.identity.device_id:
            return {"commands": [], "state": "unpaired"}
        path = f"/api/v1/collector/connections/devices/{self.identity.device_id}/sync"
        response = self._request("POST", path, {})
        response.raise_for_status()
        return response.json()

    def acknowledge(self, command_id: str, success: bool, result: Optional[Dict[str, Any]] = None) -> None:
        if not self.identity.device_id:
            return
        path = (
            f"/api/v1/collector/connections/devices/{self.identity.device_id}"
            f"/commands/{command_id}/ack"
        )
        response = self._request("POST", path, {"success": success, "result": result or {}})
        response.raise_for_status()


def register_windows_protocol_handler() -> None:
    """Register the per-user web-to-collector URL handler on Windows releases."""
    if os.name != "nt":
        return
    import sys
    import winreg

    executable = os.path.abspath(sys.executable)
    command = f'"{executable}" "%1"'
    root = r"Software\Classes\unjaena-collector"
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, root) as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "URL:unJaena Collector")
        winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, root + r"\shell\open\command") as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, command)
