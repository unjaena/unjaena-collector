"""
File Hash Calculator Module

Hash calculation for integrity verification of collected files.

Security:
    - Only SHA-256 is used (MD5 removed due to collision vulnerabilities)
    - Compliant with NIST recommended hash algorithms
"""
import hashlib
import os
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import Tuple


@dataclass
class FileHashResult:
    """File hash result"""
    file_path: str
    file_size: int
    sha256_hash: str
    md5_hash: str = ""  # [DEPRECATED] MD5 removed due to security vulnerabilities. Field kept for backward compatibility.


def _coerce_hash_chunk_size(value=None) -> int:
    """Return a bounded hash read size. Larger chunks reduce syscall overhead."""
    default = 1024 * 1024
    try:
        parsed = int(value if value is not None else os.getenv("COLLECTOR_HASH_CHUNK_SIZE", default))
    except (TypeError, ValueError):
        parsed = default
    return max(64 * 1024, min(parsed, 16 * 1024 * 1024))


class FileHashCalculator:
    """
    File hash calculator.

    Calculates hashes for integrity verification of collected artifacts.
    """

    CHUNK_SIZE = _coerce_hash_chunk_size()

    def __init__(self, chunk_size: int = None):
        self.chunk_size = _coerce_hash_chunk_size(chunk_size)

    def calculate_file_hash(self, file_path: str) -> FileHashResult:
        """
        Calculate the SHA-256 hash of a file.

        Args:
            file_path: Path to the file to hash

        Returns:
            FileHashResult with hash values

        Security:
            MD5 removed due to collision vulnerabilities (NIST recommendation)
        """
        file_path = Path(file_path)

        sha256 = hashlib.sha256()
        file_size = 0

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(self.chunk_size), b''):
                sha256.update(chunk)
                file_size += len(chunk)

        return FileHashResult(
            file_path=str(file_path),
            file_size=file_size,
            sha256_hash=sha256.hexdigest(),
        )

    def calculate_bytes_hash(self, data: bytes) -> Tuple[str, str]:
        """
        Calculate the SHA-256 hash of byte data.

        Args:
            data: Data to hash

        Returns:
            Tuple of (sha256_hash, "")
            - Second value returns empty string for backward compatibility (MD5 deprecated)
        """
        sha256_hash = hashlib.sha256(data).hexdigest()
        return sha256_hash, ""

    def verify_hash(self, file_path: str, expected_sha256: str) -> bool:
        """
        Verify file hash.

        Args:
            file_path: Path to the file to verify
            expected_sha256: Expected SHA-256 hash

        Returns:
            True if hash matches, False otherwise
        """
        result = self.calculate_file_hash(file_path)
        return result.sha256_hash.lower() == expected_sha256.lower()


# Backward compatibility
class FileEncryptor:
    """
    [DEPRECATED] Hash-only wrapper for backward compatibility.

    Only performs hash calculation. Kept to avoid breaking existing imports.
    """

    def __init__(self, key: bytes = None):
        self._hash_calculator = FileHashCalculator()

    def encrypt_file(self, input_path: str, output_path: str = None):
        """
        [DEPRECATED] Returns hash result (no transformation applied).
        """
        @dataclass
        class EncryptionResult:
            encrypted_path: str
            original_size: int
            encrypted_size: int
            original_hash: str
            nonce: str

        input_path = Path(input_path)

        if output_path is None:
            output_path = input_path
        else:
            output_path = Path(output_path)
            if input_path != output_path:
                shutil.copy2(input_path, output_path)

        hash_result = self._hash_calculator.calculate_file_hash(str(input_path))

        return EncryptionResult(
            encrypted_path=str(output_path),
            original_size=hash_result.file_size,
            encrypted_size=hash_result.file_size,
            original_hash=hash_result.sha256_hash,
            nonce="hash_only",
        )

    def calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash."""
        result = self._hash_calculator.calculate_file_hash(file_path)
        return result.sha256_hash
