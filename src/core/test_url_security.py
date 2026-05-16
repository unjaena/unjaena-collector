from __future__ import annotations

import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
SRC_DIR = HERE.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def test_remote_https_derives_wss():
    from core.url_security import normalize_server_urls

    server_url, ws_url = normalize_server_urls("https://app.example.com/")

    assert server_url == "https://app.example.com"
    assert ws_url == "wss://app.example.com"


def test_remote_http_is_rejected():
    from core.url_security import normalize_server_urls

    try:
        normalize_server_urls("http://app.example.com")
    except ValueError as exc:
        assert "HTTPS" in str(exc)
    else:
        raise AssertionError("remote HTTP endpoint should be rejected")


def test_loopback_http_is_allowed():
    from core.url_security import normalize_server_urls

    server_url, ws_url = normalize_server_urls("http://127.0.0.1:8000")

    assert server_url == "http://127.0.0.1:8000"
    assert ws_url == "ws://127.0.0.1:8000"


def test_wildcard_bind_address_is_not_loopback():
    from core.url_security import normalize_server_urls

    try:
        normalize_server_urls("http://0.0.0.0:8000")
    except ValueError as exc:
        assert "HTTPS" in str(exc)
    else:
        raise AssertionError("0.0.0.0 must not be treated as a safe loopback endpoint")
