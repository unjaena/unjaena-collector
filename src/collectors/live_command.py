from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, Generator, Iterable, Tuple


MAX_LIVE_OUTPUT_BYTES = 10 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 20


def _safe_output_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._/-]+", "_", value.strip())
    name = name.strip("/._")
    return name or "live_command"


def _resolve_executable(argv0: str) -> str | None:
    if os.path.isabs(argv0) and os.path.exists(argv0):
        return argv0
    return shutil.which(argv0)


def _normalise_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8", errors="replace")


def _truncate_payload(payload: bytes, max_bytes: int) -> tuple[bytes, bool]:
    if len(payload) <= max_bytes:
        return payload, False
    marker = b"\n[collector truncated live command output]\n"
    keep = max(0, max_bytes - len(marker))
    return payload[:keep] + marker, True


def iter_live_command_outputs(
    commands: Iterable[Dict[str, Any]],
    *,
    artifact_type: str,
    platform_tag: str,
    max_output_bytes: int = MAX_LIVE_OUTPUT_BYTES,
) -> Generator[Tuple[str, bytes, Dict[str, Any]], None, None]:
    for command in commands:
        argv = command.get("argv") or []
        if not argv:
            continue

        executable = _resolve_executable(str(argv[0]))
        if not executable:
            continue

        run_argv = [executable, *[str(arg) for arg in argv[1:]]]
        timeout = int(command.get("timeout", DEFAULT_TIMEOUT_SECONDS))
        returncode = None
        timed_out = False
        stdout = b""
        stderr = b""

        try:
            result = subprocess.run(
                run_argv,
                capture_output=True,
                timeout=timeout,
                check=False,
                cwd="/",
            )
            returncode = result.returncode
            stdout = _normalise_bytes(result.stdout)
            stderr = _normalise_bytes(result.stderr)
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = _normalise_bytes(exc.stdout)
            stderr = _normalise_bytes(exc.stderr)
        except OSError as exc:
            stderr = str(exc).encode("utf-8", errors="replace")
            returncode = -1

        base_name = _safe_output_name(str(command.get("name") or argv[0]))
        collected_at = datetime.now(timezone.utc).isoformat()

        if stdout:
            payload, truncated = _truncate_payload(stdout, max_output_bytes)
            relative_path = command.get("output") or f"live/{base_name}.txt"
            relative_path = _safe_output_name(str(relative_path))
            yield relative_path, payload, {
                "artifact_type": artifact_type,
                "collection_method": "live_command",
                "platform": platform_tag,
                "live_command_name": base_name,
                "live_command": run_argv,
                "returncode": returncode,
                "timed_out": timed_out,
                "output_truncated": truncated,
                "file_size": len(payload),
                "hash_sha256": hashlib.sha256(payload).hexdigest(),
                "collected_at": collected_at,
            }

        should_save_stderr = (
            stderr
            and command.get("capture_stderr", True)
            and (timed_out or returncode not in (0, None) or not stdout)
        )
        if should_save_stderr:
            payload, truncated = _truncate_payload(stderr, max_output_bytes)
            relative_path = f"live/{base_name}.stderr.txt"
            yield relative_path, payload, {
                "artifact_type": artifact_type,
                "collection_method": "live_command_stderr",
                "platform": platform_tag,
                "live_command_name": base_name,
                "live_command": run_argv,
                "returncode": returncode,
                "timed_out": timed_out,
                "output_truncated": truncated,
                "file_size": len(payload),
                "hash_sha256": hashlib.sha256(payload).hexdigest(),
                "collected_at": collected_at,
            }
