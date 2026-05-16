from __future__ import annotations

import hashlib
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
SRC_DIR = HERE.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def test_streaming_encrypt_file_keeps_existing_wire_format(tmp_path):
    from core.secure_upload import AESGCMCipher

    plaintext = (b"streaming evidence block\n" * 4096) + b"tail"
    source = tmp_path / "evidence.bin"
    encrypted = tmp_path / "evidence.bin.enc"
    source.write_bytes(plaintext)

    key = bytes(range(32))
    aad = hashlib.sha256(plaintext).hexdigest().encode("utf-8")
    cipher = AESGCMCipher(key)

    encrypted_size = cipher.encrypt_file(
        str(source),
        str(encrypted),
        associated_data=aad,
        chunk_size=1024,
    )

    encrypted_bytes = encrypted.read_bytes()
    assert encrypted_size == len(plaintext) + 28
    assert len(encrypted_bytes) == encrypted_size
    assert cipher.decrypt(encrypted_bytes, aad) == plaintext


def test_streaming_decrypt_file_roundtrip(tmp_path):
    from core.secure_upload import AESGCMCipher

    plaintext = bytes(range(251)) * 2048
    source = tmp_path / "source.bin"
    encrypted = tmp_path / "source.bin.enc"
    restored = tmp_path / "restored.bin"
    source.write_bytes(plaintext)

    cipher = AESGCMCipher(bytes(reversed(range(32))))
    aad = b"stable-aad"
    cipher.encrypt_file(str(source), str(encrypted), aad, chunk_size=3333)

    restored_size = cipher.decrypt_file(
        str(encrypted),
        str(restored),
        associated_data=aad,
        chunk_size=2048,
    )

    assert restored_size == len(plaintext)
    assert restored.read_bytes() == plaintext
