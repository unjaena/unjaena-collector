import glob
import os
from pathlib import Path

from .client import ServiceClient, encrypted_temp_file, sha256_file
from .models import AuthSession, CollectionProfile, ProfileTarget


def _expand_pattern(pattern: str) -> str:
    expanded = os.path.expandvars(os.path.expanduser(pattern))
    return expanded.replace("\\", os.sep)


def _iter_matches(target: ProfileTarget):
    for pattern in target.patterns:
        for value in glob.iglob(_expand_pattern(pattern), recursive=True):
            path = Path(value)
            if path.is_file():
                yield path


def _allowed(path: Path, target: ProfileTarget) -> bool:
    if target.max_bytes is None:
        return True
    try:
        return path.stat().st_size <= int(target.max_bytes)
    except OSError:
        return False


class ProfileRunner:
    def __init__(self, client: ServiceClient, session: AuthSession, profile: CollectionProfile):
        self.client = client
        self.session = session
        self.profile = profile

    def run(self) -> dict[str, int]:
        scanned = 0
        uploaded = 0
        skipped = 0
        failed = 0
        seen: set[Path] = set()
        for target in self.profile.targets:
            for path in _iter_matches(target):
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                scanned += 1
                if not _allowed(resolved, target):
                    skipped += 1
                    continue
                upload_path = resolved
                encrypted_path: Path | None = None
                try:
                    digest = sha256_file(resolved)
                    presigned = self.client.presign(self.session, resolved, target.artifact_type, digest, self.profile.profile_id)
                    is_encrypted = bool(presigned.get("encryption_key"))
                    if is_encrypted:
                        encrypted_path = encrypted_temp_file(resolved, presigned["encryption_key"], digest)
                        upload_path = encrypted_path
                    if presigned.get("multipart"):
                        parts = self.client.upload_multipart(list(presigned["upload_url"]), upload_path)
                        self.client.complete(self.session, resolved, target.artifact_type, digest, presigned["key"], presigned.get("upload_id"), parts, is_encrypted, self.profile.profile_id)
                    else:
                        self.client.upload_file(str(presigned["upload_url"]), upload_path)
                        self.client.complete(self.session, resolved, target.artifact_type, digest, presigned["key"], is_encrypted=is_encrypted, profile_id=self.profile.profile_id)
                    uploaded += 1
                except Exception:
                    failed += 1
                finally:
                    if encrypted_path:
                        try:
                            encrypted_path.unlink()
                        except OSError:
                            pass
        return {"scanned": scanned, "uploaded": uploaded, "skipped": skipped, "failed": failed}
