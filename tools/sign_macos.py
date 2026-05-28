import base64
import binascii
import os
import re
import uuid
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(args: list[str]) -> str:
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if result.returncode != 0:
        raise SystemExit((result.stdout + result.stderr).strip())
    return (result.stdout + result.stderr).strip()


def _target() -> Path:
    app = ROOT / "dist" / "UnjaenaCollector.app"
    if app.exists():
        return app
    binary = ROOT / "dist" / "UnjaenaCollector"
    if binary.exists():
        return binary
    raise SystemExit("Missing macOS desktop build")


def _identity(keychain: str) -> str:
    configured = os.environ.get("APPLE_SIGNING_IDENTITY", "").strip()
    if configured:
        return configured
    output = _run(["security", "find-identity", "-v", "-p", "codesigning", keychain])
    for line in output.splitlines():
        if "Developer ID Application" in line:
            match = re.search(r'"(.+?)"', line)
            if match:
                return match.group(1)
    raise SystemExit("Developer ID Application identity was not found")


def signing_required() -> bool:
    value = os.environ.get("UNJAENA_SIGNING_REQUIRED", "").strip().lower()
    return value in {"1", "true", "yes", "required"}


def _decode_certificate_b64(value: str) -> bytes:
    normalized = "".join(value.split())
    if not normalized:
        return b""
    padding = (-len(normalized)) % 4
    if padding:
        normalized += "=" * padding
    try:
        return base64.b64decode(normalized, validate=True)
    except binascii.Error as exc:
        raise SystemExit("Invalid APPLE_DEVELOPER_ID_CERT_BASE64: expected base64-encoded .p12 data") from exc


def _import_certificate(cert_decoded: str, keychain: str, cert_password: str) -> None:
    _run([
        "security",
        "import",
        cert_decoded,
        "-f",
        "pkcs12",
        "-k",
        keychain,
        "-P",
        cert_password,
        "-T",
        "/usr/bin/codesign",
        "-T",
        "/usr/bin/security",
    ])


def _handle_optional_signing_failure(exc: BaseException) -> int:
    if signing_required():
        raise exc
    print(f"macOS signing skipped: {exc}")
    return 0


def main() -> int:
    cert_b64 = "".join(os.environ.get("APPLE_DEVELOPER_ID_CERT_BASE64", "").split())
    cert_password = os.environ.get("APPLE_DEVELOPER_ID_CERT_PASSWORD", "")
    if not cert_b64 or not cert_password:
        if signing_required():
            raise SystemExit("macOS signing material is required for release builds")
        print("macOS signing skipped")
        return 0

    target = _target()
    keychain_password = os.environ.get("APPLE_KEYCHAIN_PASSWORD") or (uuid.uuid4().hex + uuid.uuid4().hex)
    keychain = str(Path(tempfile.gettempdir()) / "unjaena-build-signing.keychain-db")
    cert_path = Path(tempfile.gettempdir()) / "unjaena-developer-id.p12"
    try:
        cert_decoded_path = cert_path.with_suffix(".decoded.p12")
        cert_decoded_path.write_bytes(_decode_certificate_b64(cert_b64))
        cert_decoded = str(cert_decoded_path)
        _run(["security", "create-keychain", "-p", keychain_password, keychain])
        _run(["security", "set-keychain-settings", "-lut", "21600", keychain])
        _run(["security", "unlock-keychain", "-p", keychain_password, keychain])
        try:
            _import_certificate(cert_decoded, keychain, cert_password)
            _run(["security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s", "-k", keychain_password, keychain])
            identity = _identity(keychain)
            _run(["codesign", "--force", "--timestamp", "--options", "runtime", "--deep", "--sign", identity, str(target)])
            _run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(target)])
        except SystemExit as exc:
            return _handle_optional_signing_failure(exc)
        print("macOS signing complete")
        return 0
    finally:
        for path in [cert_path, cert_path.with_suffix(".decoded.p12")]:
            try:
                path.unlink()
            except OSError:
                pass
        try:
            subprocess.run(["security", "delete-keychain", keychain], text=True, capture_output=True)
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
