import base64
import hashlib
import hmac
import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from unjaena_collector.client import _canonical, encrypted_temp_file, sha256_file
from unjaena_collector.models import AuthSession, CollectionProfile, ProfileTarget
from unjaena_collector.runner import ProfileRunner
from tools import sign_macos


class FakeClient:
    def __init__(self):
        self.presigned = []
        self.uploaded = []
        self.completed = []

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


class ClientRunnerTests(unittest.TestCase):
    def test_canonical_signature_payload_is_stable(self):
        payload = {"b": 2, "a": {"d": 4, "c": 3}}
        self.assertEqual(_canonical(payload), b'{"a":{"c":3,"d":4},"b":2}')
        sig = base64.urlsafe_b64encode(
            hmac.new(b"signing-key", _canonical(payload), hashlib.sha256).digest()
        ).decode().rstrip("=")
        self.assertTrue(sig)

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
            self.assertEqual(client.completed[0]["profile_id"], "profile-1")
            self.assertEqual(client.completed[0]["artifact_type"], "test_artifact")


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


class MacSigningTests(unittest.TestCase):
    def test_signing_required_accepts_release_values(self):
        with patch.dict(os.environ, {"UNJAENA_SIGNING_REQUIRED": "1"}, clear=False):
            self.assertTrue(sign_macos.signing_required())

    def test_signing_required_defaults_to_false(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(sign_macos.signing_required())


if __name__ == "__main__":
    unittest.main()
