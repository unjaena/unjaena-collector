#!/usr/bin/env python3
"""Validate an unJaena X-Ways X-Tension package.

This validator intentionally avoids third-party dependencies so it can run on a
clean Windows forensic workstation. It checks the manifest contract, relative
path safety, file presence, file size, and SHA-256 integrity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List

EXPECTED_FORMAT = "unjaena.xways.package"
EXPECTED_VERSION = 1
EXPECTED_SOURCE = "xways_xtension"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class ValidationError(Exception):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _load_manifest(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError(f"manifest is not valid JSON: {exc}") from exc
    _require(isinstance(data, dict), "manifest root must be an object")
    return data


def _safe_relative_path(value: str) -> Path:
    _require(value, "relative_path is required")
    rel = Path(value.replace("\\", "/"))
    _require(not rel.is_absolute(), f"relative_path must not be absolute: {value}")
    _require(".." not in rel.parts, f"relative_path must not traverse directories: {value}")
    _require(rel.parts and rel.parts[0] == "files", f"relative_path must be under files/: {value}")
    return rel


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_artifact(package_root: Path, artifact: Dict[str, Any], index: int) -> int:
    prefix = f"artifact[{index}]"
    for key in ("artifact_id", "artifact_type", "file_name", "relative_path", "size", "sha256", "xways"):
        _require(key in artifact, f"{prefix}.{key} is required")
    _require(isinstance(artifact["artifact_id"], str) and artifact["artifact_id"], f"{prefix}.artifact_id must be a non-empty string")
    _require(isinstance(artifact["artifact_type"], str) and artifact["artifact_type"], f"{prefix}.artifact_type must be a non-empty string")
    _require(isinstance(artifact["file_name"], str) and artifact["file_name"], f"{prefix}.file_name must be a non-empty string")
    _require(isinstance(artifact["size"], int) and artifact["size"] >= 0, f"{prefix}.size must be a non-negative integer")
    sha = str(artifact["sha256"]).lower()
    _require(len(sha) == 64 and all(ch in "0123456789abcdef" for ch in sha), f"{prefix}.sha256 must be a SHA-256 hex digest")
    _require(isinstance(artifact["xways"], dict), f"{prefix}.xways must be an object")
    _require("item_id" in artifact["xways"], f"{prefix}.xways.item_id is required")
    _require(str(artifact["xways"].get("scope") or "") in {"selected_items", "volume_snapshot", "tools_run"}, f"{prefix}.xways.scope is invalid")

    rel = _safe_relative_path(str(artifact["relative_path"]))
    file_path = package_root / rel
    _require(file_path.exists(), f"{prefix} file is missing: {rel}")
    _require(file_path.is_file(), f"{prefix} path is not a file: {rel}")

    actual_size = file_path.stat().st_size
    _require(actual_size == artifact["size"], f"{prefix} size mismatch: manifest={artifact['size']} actual={actual_size}")
    actual_hash = _sha256(file_path)
    _require(actual_hash == sha, f"{prefix} sha256 mismatch: manifest={sha} actual={actual_hash}")
    return actual_size


def validate(manifest_path: Path) -> Dict[str, Any]:
    manifest_path = manifest_path.resolve()
    package_root = manifest_path.parent
    manifest = _load_manifest(manifest_path)

    _require(manifest.get("format") == EXPECTED_FORMAT, "manifest.format is not unjaena.xways.package")
    _require(manifest.get("format_version") == EXPECTED_VERSION, "manifest.format_version is not 1")
    _require(manifest.get("source_tool") == EXPECTED_SOURCE, "manifest.source_tool is not xways_xtension")
    _require(isinstance(manifest.get("case"), dict), "manifest.case must be an object")
    _require(str(manifest["case"].get("case_id") or ""), "manifest.case.case_id is required")
    _require(isinstance(manifest.get("collection_profile"), dict), "manifest.collection_profile must be an object")
    _require(str(manifest["collection_profile"].get("profile_id") or ""), "manifest.collection_profile.profile_id is required")

    artifacts = manifest.get("artifacts")
    _require(isinstance(artifacts, list), "manifest.artifacts must be an array")

    total_bytes = 0
    seen_ids = set()
    seen_paths = set()
    for index, artifact in enumerate(artifacts):
        _require(isinstance(artifact, dict), f"artifact[{index}] must be an object")
        artifact_id = artifact.get("artifact_id")
        rel_path = artifact.get("relative_path")
        _require(artifact_id not in seen_ids, f"duplicate artifact_id: {artifact_id}")
        _require(rel_path not in seen_paths, f"duplicate relative_path: {rel_path}")
        seen_ids.add(artifact_id)
        seen_paths.add(rel_path)
        total_bytes += _validate_artifact(package_root, artifact, index)

    totals = manifest.get("totals") or {}
    if isinstance(totals, dict):
        if "artifact_count" in totals:
            _require(totals["artifact_count"] == len(artifacts), "totals.artifact_count mismatch")
        if "total_bytes" in totals:
            _require(totals["total_bytes"] == total_bytes, "totals.total_bytes mismatch")

    return {
        "manifest": str(manifest_path),
        "artifact_count": len(artifacts),
        "total_bytes": total_bytes,
        "status": "ok",
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate an unJaena X-Ways package")
    parser.add_argument("manifest", type=Path, help="Path to manifest.json")
    parser.add_argument("--json", action="store_true", help="Print machine-readable result")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        result = validate(args.manifest)
    except ValidationError as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=True))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, ensure_ascii=True))
    else:
        print(f"OK: {result['artifact_count']} artifacts, {result['total_bytes']} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
