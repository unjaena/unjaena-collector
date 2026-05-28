import base64
import hashlib
import hmac
import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from unjaena_collector.client import ServiceClient, _canonical, _derive_key, _signed_headers, encrypted_temp_file, sha256_file
from unjaena_collector.models import AuthSession, CollectionProfile, ProfileTarget
from unjaena_collector.runner import ProfileRunner
from unjaena_collector.source_formats import candidate_artifacts_for_path, classify_source_path
from tools import sign_macos


class FakeClient:
    def __init__(self):
        self.presigned = []
        self.uploaded = []
        self.completed = []
        self.ended = []

    def presign(self, session, path, artifact_type, digest, profile_id=None):
        self.presigned.append((session, path, artifact_type, digest, profile_id))
        return {"upload_url": "memory://upload", "key": f"cases/{session.case_id}/{path.name}"}

    def upload_file(self, upload_url, path):
        self.uploaded.append((upload_url, Path(path).read_bytes()))

    def complete(self, session, path, artifact_type, digest, key, upload_id=None, parts=None, is_encrypted=False, profile_id=None):
        self.completed.append({
            "session": session,
            "path": path,
            "artifact_type": artifact_type,
            "digest": digest,
            "key": key,
            "profile_id": profile_id,
            "is_encrypted": is_encrypted,
        })
        return {"ok": True}

    def end_collection(self, session, trigger_analysis=True):
        self.ended.append({"session": session, "trigger_analysis": trigger_analysis})
        return {"status": "completed"}


class ClientRunnerTests(unittest.TestCase):
    def test_canonical_signature_payload_is_stable(self):
        payload = {"b": 2, "a": {"d": 4, "c": 3}}
        self.assertEqual(_canonical(payload), b'{"a":{"c":3,"d":4},"b":2}')
        sig = base64.urlsafe_b64encode(
            hmac.new(b"signing-key", _canonical(payload), hashlib.sha256).digest()
        ).decode().rstrip("=")
        self.assertTrue(sig)

    def test_session_request_signature_matches_server_canonical_form(self):
        session = AuthSession(
            "sid",
            "case-1",
            "collection-token-prefix-value-for-test",
            "https://example.test",
            signing_key="11" * 32,
            challenge_salt="challenge",
            hardware_id="hardware",
        )
        body = _canonical({"b": 2, "a": 1})
        with patch("unjaena_collector.client.time.time", return_value=1710000000), \
             patch("unjaena_collector.client.os.urandom", return_value=b"\x01" * 18):
            headers = _signed_headers(session, "POST", "/api/v1/collector/r2/presigned-url", body)

        nonce = base64.urlsafe_b64encode(b"\x01" * 18).decode("ascii").rstrip("=")
        canonical = "\n".join([
            "POST",
            "/api/v1/collector/r2/presigned-url",
            "1710000000",
            nonce,
            hashlib.sha256(body).hexdigest(),
            session.collection_token[:32],
        ])
        expected = hmac.new(
            _derive_key(session.signing_key, session.hardware_id, session.challenge_salt),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(headers["X-Client-Signature"], expected)
        self.assertEqual(headers["X-Client-Timestamp"], "1710000000")
        self.assertEqual(headers["X-Client-Nonce"], nonce)

    def test_upload_file_sends_octet_stream_content_type(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sample.bin"
            path.write_bytes(b"data")
            fake_response = type("Response", (), {"raise_for_status": lambda self: None})()
            with patch("unjaena_collector.client.requests.put", return_value=fake_response) as put:
                ServiceClient("https://example.test").upload_file("https://r2.example/upload", path)
            self.assertEqual(put.call_args.kwargs["headers"], {"Content-Type": "application/octet-stream"})

    def test_end_collection_uses_signed_empty_body_request(self):
        session = AuthSession(
            "session-1",
            "case-1",
            "collection-token-prefix-value-for-test",
            "https://example.test",
            signing_key="22" * 32,
            challenge_salt="challenge",
            hardware_id="hardware",
        )
        fake_response = type("Response", (), {"raise_for_status": lambda self: None, "json": lambda self: {"status": "completed"}})()
        with patch("unjaena_collector.client.time.time", return_value=1710000000), \
             patch("unjaena_collector.client.os.urandom", return_value=b"\x02" * 18), \
             patch("unjaena_collector.client.requests.post", return_value=fake_response) as post:
            result = ServiceClient("https://example.test").end_collection(session, trigger_analysis=False)
        self.assertEqual(result, {"status": "completed"})
        self.assertEqual(post.call_args.args[0], "https://example.test/api/v1/collector/collection/end/session-1")
        self.assertEqual(post.call_args.kwargs["params"], {"trigger_analysis": "false"})
        self.assertIn("X-Client-Signature", post.call_args.kwargs["headers"])

    def test_sha256_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sample.txt"
            path.write_text("hello", encoding="utf-8")
            self.assertEqual(sha256_file(path), hashlib.sha256(b"hello").hexdigest())

    def test_encrypted_temp_file_round_trip_with_digest_aad(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "plain.bin"
            src.write_bytes(b"plain evidence" * 1024)
            digest = sha256_file(src)
            key = bytes(range(32))
            enc_path = encrypted_temp_file(src, key.hex(), digest)
            try:
                blob = enc_path.read_bytes()
                nonce, body, tag = blob[:12], blob[12:-16], blob[-16:]
                decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
                decryptor.authenticate_additional_data(digest.encode("utf-8"))
                plain = decryptor.update(body) + decryptor.finalize()
                self.assertEqual(plain, src.read_bytes())
            finally:
                enc_path.unlink(missing_ok=True)

    def test_profile_runner_uploads_matching_files_once(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keep = root / "keep.log"
            skip = root / "skip.log"
            keep.write_text("ok", encoding="utf-8")
            skip.write_text("too-large", encoding="utf-8")
            session = AuthSession("sid", "case-1", "ct", "https://example.test")
            profile = CollectionProfile(
                profile_id="profile-1",
                case_id="case-1",
                expires_at="2099-01-01T00:00:00Z",
                targets=[ProfileTarget("test_artifact", "glob", [str(root / "*.log")], max_bytes=4)],
            )
            client = FakeClient()
            result = ProfileRunner(client, session, profile).run()
            self.assertEqual(result, {"scanned": 2, "uploaded": 1, "skipped": 1, "failed": 0})
            self.assertEqual(len(client.uploaded), 1)
            self.assertEqual(len(client.ended), 1)
            self.assertTrue(client.ended[0]["trigger_analysis"])
            self.assertEqual(client.completed[0]["profile_id"], "profile-1")
            self.assertEqual(client.completed[0]["artifact_type"], "test_artifact")



    def test_source_format_detection_covers_supported_image_families(self):
        cases = {
            "case.E02": "e01_image",
            "logical.L01": "e01_image",
            "disk.dd": "raw_image",
            "split.002": "raw_image",
            "container.aff4": "forensic_container_image",
            "logical.ad1": "forensic_container_image",
            "vm.vdi": "virtual_disk_image",
            "vm.qcow2": "virtual_disk_image",
            "volume.ntfs": "filesystem_image",
            "volume.exfat": "filesystem_image",
            "image.iso": "optical_disk_image",
            "phone.zip": "mobile_ffs_bundle",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertIn(expected, candidate_artifacts_for_path(Path(name)))
                self.assertEqual(classify_source_path(Path(name)).artifact_type, expected)

    def test_profile_runner_uploads_authorized_source_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            image = root / "evidence.E01"
            image.write_bytes(b"image")
            session = AuthSession("sid", "case-1", "ct", "https://example.test")
            profile = CollectionProfile(
                profile_id="profile-1",
                case_id="case-1",
                expires_at="2099-01-01T00:00:00Z",
                targets=[ProfileTarget("e01_image", "source_file", ["*.E01", "*.e01"], metadata={"source_upload": True})],
            )
            client = FakeClient()
            result = ProfileRunner(client, session, profile).run(
                selected_artifacts={"e01_image"},
                source_files=[image],
                include_local_profile_targets=False,
            )
            self.assertEqual(result, {"scanned": 1, "uploaded": 1, "skipped": 0, "failed": 0})
            self.assertEqual(client.completed[0]["artifact_type"], "e01_image")
            self.assertEqual(client.completed[0]["profile_id"], "profile-1")

    def test_profile_runner_respects_selected_source_targets(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            image = root / "evidence.E01"
            image.write_bytes(b"image")
            session = AuthSession("sid", "case-1", "ct", "https://example.test")
            profile = CollectionProfile(
                profile_id="profile-1",
                case_id="case-1",
                expires_at="2099-01-01T00:00:00Z",
                targets=[ProfileTarget("e01_image", "source_file", ["*.E[0-9][0-9]"], metadata={"source_upload": True})],
            )
            client = FakeClient()
            with self.assertRaises(RuntimeError):
                ProfileRunner(client, session, profile).run(
                    selected_artifacts=set(),
                    source_files=[image],
                    include_local_profile_targets=False,
                )

    def test_profile_runner_uploads_extensionless_filesystem_with_override(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            image = root / "volume"
            image.write_bytes(b"filesystem")
            session = AuthSession("sid", "case-1", "ct", "https://example.test")
            profile = CollectionProfile(
                profile_id="profile-1",
                case_id="case-1",
                expires_at="2099-01-01T00:00:00Z",
                targets=[ProfileTarget("filesystem_image", "source_file", ["*.ntfs"], metadata={"source_upload": True})],
            )
            client = FakeClient()
            result = ProfileRunner(client, session, profile).run(
                selected_artifacts={"filesystem_image"},
                source_files=[image],
                include_local_profile_targets=False,
                source_artifacts={str(image): "filesystem_image"},
            )
            self.assertEqual(result, {"scanned": 1, "uploaded": 1, "skipped": 0, "failed": 0})
            self.assertEqual(client.completed[0]["artifact_type"], "filesystem_image")



class MacSigningTests(unittest.TestCase):
    def test_signing_required_accepts_release_values(self):
        with patch.dict(os.environ, {"UNJAENA_SIGNING_REQUIRED": "1"}, clear=False):
            self.assertTrue(sign_macos.signing_required())

    def test_signing_required_defaults_to_false(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(sign_macos.signing_required())

    def test_certificate_base64_decoder_accepts_missing_padding_and_whitespace(self):
        encoded = " YWJjZA\n"
        encoded = encoded.rstrip("=")
        self.assertEqual(sign_macos._decode_certificate_b64(encoded), b"abcd")

    def test_certificate_base64_decoder_rejects_invalid_value(self):
        with self.assertRaises(SystemExit) as ctx:
            sign_macos._decode_certificate_b64("not base64!")
        self.assertIn("APPLE_DEVELOPER_ID_CERT_BASE64", str(ctx.exception))

    def test_certificate_import_uses_explicit_pkcs12_format(self):
        commands = []
        with patch.object(sign_macos, "_run", side_effect=lambda args: commands.append(args) or ""):
            sign_macos._import_certificate("cert.p12", "build.keychain", "pw-value")
        self.assertIn("-f", commands[0])
        self.assertIn("pkcs12", commands[0])

    def test_optional_signing_failure_is_skipped(self):
        with patch.dict(os.environ, {"UNJAENA_SIGNING_REQUIRED": "0"}, clear=True):
            self.assertEqual(sign_macos._handle_optional_signing_failure(SystemExit("bad p12")), 0)

    def test_required_signing_failure_is_raised(self):
        with patch.dict(os.environ, {"UNJAENA_SIGNING_REQUIRED": "1"}, clear=True):
            with self.assertRaises(SystemExit):
                sign_macos._handle_optional_signing_failure(SystemExit("bad p12"))


if __name__ == "__main__":
    unittest.main()
