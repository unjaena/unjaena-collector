"""URL validation helpers for collector network endpoints."""
from __future__ import annotations

import ipaddress
from typing import Optional, Tuple
from urllib.parse import urlparse


HTTP_SCHEMES = {"http", "https"}
WS_SCHEMES = {"ws", "wss"}


def is_loopback_host(hostname: Optional[str]) -> bool:
    """Return True for localhost or loopback IP addresses."""
    if not hostname:
        return False
    host = hostname.strip().strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def derive_ws_url(server_url: str) -> str:
    """Derive a websocket URL from an HTTP server URL."""
    parsed = urlparse(server_url.strip().rstrip("/"))
    if parsed.scheme == "https":
        return server_url.strip().rstrip("/").replace("https://", "wss://", 1)
    if parsed.scheme == "http":
        return server_url.strip().rstrip("/").replace("http://", "ws://", 1)
    raise ValueError("Server URL must start with https:// or http://")


def normalize_server_urls(
    server_url: str,
    ws_url: Optional[str] = None,
    *,
    allow_loopback_http: bool = True,
) -> Tuple[str, str]:
    """
    Normalize and validate collector HTTP/WebSocket endpoints.

    Remote endpoints must use HTTPS/WSS. Plain HTTP/WS is accepted only for
    loopback development endpoints when explicitly allowed.
    """
    server_url = (server_url or "").strip().rstrip("/")
    if not server_url:
        return "", ""

    parsed = urlparse(server_url)
    if parsed.scheme not in HTTP_SCHEMES or not parsed.netloc:
        raise ValueError("Server URL must be an absolute http(s) URL.")

    is_loopback = is_loopback_host(parsed.hostname)
    if parsed.scheme != "https" and not (allow_loopback_http and is_loopback):
        raise ValueError("Remote collector server URLs must use HTTPS.")

    ws_url = (ws_url or derive_ws_url(server_url)).strip().rstrip("/")
    ws_parsed = urlparse(ws_url)
    if ws_parsed.scheme not in WS_SCHEMES or not ws_parsed.netloc:
        raise ValueError("WebSocket URL must be an absolute ws(s) URL.")

    ws_is_loopback = is_loopback_host(ws_parsed.hostname)
    if ws_parsed.scheme != "wss" and not (allow_loopback_http and ws_is_loopback):
        raise ValueError("Remote collector WebSocket URLs must use WSS.")

    return server_url, ws_url
