import fnmatch
import glob
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .client import ServiceClient, encrypted_temp_file, sha256_file
from .models import AuthSession, CollectionProfile, ProfileTarget
from .source_formats import candidate_artifacts_for_path

ProgressCallback = Callable[[dict[str, Any]], None]
StopCallback = Callable[[], bool]

SOURCE_UPLOAD_KINDS = {
    "source_file",
    "image_file",
    "forensic_image",
    "disk_image",
    "bundle",
    "manual_file",
    "raw_upload",
}

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


def _is_source_upload_target(target: ProfileTarget) -> bool:
    kind = str(target.kind or "").lower()
    metadata = target.metadata or {}
    return bool(
        kind in SOURCE_UPLOAD_KINDS
        or metadata.get("source_upload") is True
        or metadata.get("upload_source") is True
    )


def _target_matches_file(target: ProfileTarget, path: Path) -> bool:
    ext = path.suffix.lower()
    metadata = target.metadata or {}
    extensions = [str(item).lower() for item in metadata.get("file_extensions") or []]
    if extensions and ext in {item if item.startswith(".") else f".{item}" for item in extensions}:
        return True
    for pattern in target.patterns:
        pattern = str(pattern or "")
        if fnmatch.fnmatch(path.name.lower(), pattern.lower()):
            return True
    return target.artifact_type in candidate_artifacts_for_path(path)


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

    def _selected_targets(self, selected_artifacts: set[str] | None) -> list[ProfileTarget]:
        if selected_artifacts is None:
            return list(self.profile.targets)
        return [target for target in self.profile.targets if target.artifact_type in selected_artifacts]

    def _source_target_for(
        self,
        path: Path,
        selected_artifacts: set[str] | None,
        preferred_artifact_type: str | None = None,
    ) -> ProfileTarget:
        selected = self._selected_targets(selected_artifacts)
        if preferred_artifact_type:
            candidates = [
                target for target in selected
                if _is_source_upload_target(target) and target.artifact_type == preferred_artifact_type
            ]
        else:
            candidates = [target for target in selected if _is_source_upload_target(target) and _target_matches_file(target, path)]
        if not candidates:
            label = preferred_artifact_type or path.suffix.lower() or "file"
            raise RuntimeError(f"The server profile does not authorize upload for {label} source files")
        return candidates[0]

    def _upload_one(self, path: Path, target: ProfileTarget, counters: dict[str, int]) -> None:
        resolved = path.resolve()
        counters["scanned"] += 1
        self._emit("file_scanned", name=resolved.name, scanned=counters["scanned"])
        if not _allowed(resolved, target):
            counters["skipped"] += 1
            self._emit("file_skipped", name=resolved.name, **counters)
            return
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
            self._emit("uploading", name=resolved.name, artifact_type=target.artifact_type)
            if presigned.get("multipart"):
                parts = self.client.upload_multipart(list(presigned["upload_url"]), upload_path)
                self.client.complete(
                    self.session,
                    resolved,
                    target.artifact_type,
                    digest,
                    presigned["key"],
                    presigned.get("upload_id"),
                    parts,
                    is_encrypted,
                    self.profile.profile_id,
                )
            else:
                self.client.upload_file(str(presigned["upload_url"]), upload_path)
                self.client.complete(
                    self.session,
                    resolved,
                    target.artifact_type,
                    digest,
                    presigned["key"],
                    is_encrypted=is_encrypted,
                    profile_id=self.profile.profile_id,
                )
            counters["uploaded"] += 1
            self._emit("file_uploaded", name=resolved.name, artifact_type=target.artifact_type, **counters)
        except Exception as exc:
            counters["failed"] += 1
            self._emit("file_failed", name=resolved.name, error=str(exc), **counters)
        finally:
            if encrypted_path:
                try:
                    encrypted_path.unlink()
                except OSError:
                    pass

    def run(
        self,
        selected_artifacts: set[str] | None = None,
        source_files: list[Path] | None = None,
        include_local_profile_targets: bool = True,
        source_artifacts: dict[str, str] | None = None,
        end_session: bool = True,
        trigger_analysis: bool = True,
    ) -> dict[str, int]:
        counters = {"scanned": 0, "uploaded": 0, "skipped": 0, "failed": 0}
        seen: set[Path] = set()
        targets = self._selected_targets(selected_artifacts)
        self._emit("started", targets=len(targets), source_files=len(source_files or []))

        for source in source_files or []:
            if self._stopped():
                self._emit("stopped", **counters)
                return counters
            resolved = source.resolve()
            preferred = None
            if source_artifacts:
                preferred = source_artifacts.get(str(source)) or source_artifacts.get(str(resolved))
            target = self._source_target_for(resolved, selected_artifacts, preferred)
            self._emit("target_started", artifact_type=target.artifact_type, kind=target.kind)
            if resolved not in seen:
                seen.add(resolved)
                self._upload_one(resolved, target, counters)

        if include_local_profile_targets:
            for target in targets:
                if self._stopped():
                    self._emit("stopped", **counters)
                    return counters
                if _is_source_upload_target(target):
                    continue
                self._emit("target_started", artifact_type=target.artifact_type, kind=target.kind)
                for path in _iter_matches(target):
                    if self._stopped():
                        self._emit("stopped", **counters)
                        return counters
                    resolved = path.resolve()
                    if resolved in seen:
                        continue
                    seen.add(resolved)
                    self._upload_one(resolved, target, counters)
        if end_session and counters["uploaded"] > 0:
            try:
                self._emit("session_ending", **counters)
                self.client.end_collection(self.session, trigger_analysis=trigger_analysis)
                self._emit("session_ended", **counters)
            except Exception as exc:
                self._emit("session_end_failed", error=str(exc), **counters)
                raise
        self._emit("finished", **counters)
        return counters
