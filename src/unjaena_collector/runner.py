import glob
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .client import ServiceClient, encrypted_temp_file, sha256_file
from .models import AuthSession, CollectionProfile, ProfileTarget

ProgressCallback = Callable[[dict[str, Any]], None]
StopCallback = Callable[[], bool]


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
    def __init__(
        self,
        client: ServiceClient,
        session: AuthSession,
        profile: CollectionProfile,
        on_event: ProgressCallback | None = None,
        should_stop: StopCallback | None = None,
    ):
        self.client = client
        self.session = session
        self.profile = profile
        self.on_event = on_event
        self.should_stop = should_stop

    def _emit(self, event: str, **payload: Any) -> None:
        if self.on_event:
            data = {"event": event}
            data.update(payload)
            self.on_event(data)

    def _stopped(self) -> bool:
        return bool(self.should_stop and self.should_stop())

    def run(self) -> dict[str, int]:
        scanned = 0
        uploaded = 0
        skipped = 0
        failed = 0
        seen: set[Path] = set()
        self._emit("started", targets=len(self.profile.targets))
        for target in self.profile.targets:
            if self._stopped():
                self._emit("stopped", scanned=scanned, uploaded=uploaded, skipped=skipped, failed=failed)
                return {"scanned": scanned, "uploaded": uploaded, "skipped": skipped, "failed": failed}
            self._emit("target_started", artifact_type=target.artifact_type)
            for path in _iter_matches(target):
                if self._stopped():
                    self._emit("stopped", scanned=scanned, uploaded=uploaded, skipped=skipped, failed=failed)
                    return {"scanned": scanned, "uploaded": uploaded, "skipped": skipped, "failed": failed}
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                scanned += 1
                self._emit("file_scanned", name=resolved.name, scanned=scanned)
                if not _allowed(resolved, target):
                    skipped += 1
                    self._emit("file_skipped", name=resolved.name, scanned=scanned, uploaded=uploaded, skipped=skipped, failed=failed)
                    continue
                upload_path = resolved
                encrypted_path: Path | None = None
                try:
                    self._emit("hashing", name=resolved.name)
                    digest = sha256_file(resolved)
                    presigned = self.client.presign(self.session, resolved, target.artifact_type, digest, self.profile.profile_id)
                    is_encrypted = bool(presigned.get("encryption_key"))
                    if is_encrypted:
                        self._emit("protecting", name=resolved.name)
                        encrypted_path = encrypted_temp_file(resolved, presigned["encryption_key"], digest)
                        upload_path = encrypted_path
                    self._emit("uploading", name=resolved.name)
                    if presigned.get("multipart"):
                        parts = self.client.upload_multipart(list(presigned["upload_url"]), upload_path)
                        self.client.complete(self.session, resolved, target.artifact_type, digest, presigned["key"], presigned.get("upload_id"), parts, is_encrypted, self.profile.profile_id)
                    else:
                        self.client.upload_file(str(presigned["upload_url"]), upload_path)
                        self.client.complete(self.session, resolved, target.artifact_type, digest, presigned["key"], is_encrypted=is_encrypted, profile_id=self.profile.profile_id)
                    uploaded += 1
                    self._emit("file_uploaded", name=resolved.name, scanned=scanned, uploaded=uploaded, skipped=skipped, failed=failed)
                except Exception as exc:
                    failed += 1
                    self._emit("file_failed", name=resolved.name, error=str(exc), scanned=scanned, uploaded=uploaded, skipped=skipped, failed=failed)
                finally:
                    if encrypted_path:
                        try:
                            encrypted_path.unlink()
                        except OSError:
                            pass
        self._emit("finished", scanned=scanned, uploaded=uploaded, skipped=skipped, failed=failed)
        return {"scanned": scanned, "uploaded": uploaded, "skipped": skipped, "failed": failed}
