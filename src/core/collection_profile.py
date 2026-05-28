"""Runtime application of server-issued collection profiles.

The public collector keeps acquisition engines locally, while target policy
(path patterns, MFT hints, process names, and per-artifact metadata) can be
issued by the server after session authentication.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any, MutableMapping


_SOURCE_FILE_KINDS = {"source_file", "source_upload"}
_CONFIG_ONLY_KINDS = {"collector_config", "profile_config"}


def _target_dict(target: Any) -> dict[str, Any]:
    if isinstance(target, dict):
        return target
    return {
        "artifact_type": getattr(target, "artifact_type", None),
        "kind": getattr(target, "kind", None),
        "patterns": getattr(target, "patterns", None),
        "max_bytes": getattr(target, "max_bytes", None),
        "metadata": getattr(target, "metadata", None),
    }


def apply_collection_profile_to_registry(
    targets: list[Any] | None,
    registry: MutableMapping[str, dict[str, Any]],
) -> set[str]:
    """Merge authenticated server targets into the collector registry.

    Returns the artifact types represented by the profile. The function is
    intentionally additive: existing engine-specific keys remain available,
    while server policy replaces target path lists for artifacts it defines.
    """
    if not targets:
        return set()

    profile_artifacts: set[str] = set()
    for raw_target in targets:
        target = _target_dict(raw_target)
        artifact_type = str(target.get("artifact_type") or "").strip()
        if not artifact_type:
            continue
        profile_artifacts.add(artifact_type)

        kind = str(target.get("kind") or "glob")
        patterns = [str(item) for item in target.get("patterns") or [] if item]
        metadata = dict(target.get("metadata") or {})

        if kind in _SOURCE_FILE_KINDS:
            # Evidence-source uploads are handled by the source-file workflow,
            # not by local artifact path collectors.
            continue

        existing = deepcopy(registry.get(artifact_type) or {})
        collector_config = dict(metadata.get("collector_config") or {})

        merged = {**existing, **collector_config}
        if patterns and kind not in _CONFIG_ONLY_KINDS:
            merged["paths"] = patterns
        if target.get("max_bytes") is not None:
            merged["max_bytes"] = target.get("max_bytes")

        merged.setdefault("name", metadata.get("label") or artifact_type.replace("_", " ").title())
        merged.setdefault("description", metadata.get("description") or "Server-authorized collection target")
        merged.setdefault("category", metadata.get("category") or existing.get("category") or "windows")
        merged["server_profile_managed"] = True

        registry[artifact_type] = merged

    return profile_artifacts


def _tuple_value(value: Any) -> tuple:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(value)


def apply_collection_profile_to_mobile_ffs(targets: list[Any] | None) -> tuple[int, int]:
    """Install server-issued mobile FFS path specs at runtime."""
    if not targets:
        return 0, 0

    try:
        from collectors.mobile_ffs import path_specs as spec_module
        from collectors.mobile_ffs.path_specs import (
            AndroidArtifactSpec,
            IOSArtifactSpec,
            ContainerKind,
        )
    except Exception:
        return 0, 0

    android_specs = []
    ios_specs = []
    seen_android = set()
    seen_ios = set()

    for raw_target in targets:
        target = _target_dict(raw_target)
        metadata = dict(target.get("metadata") or {})
        collector_config = dict(metadata.get("collector_config") or {})
        for raw_spec in collector_config.get("mobile_ffs_specs") or []:
            if not isinstance(raw_spec, dict):
                continue
            platform = str(raw_spec.get("platform") or "").lower()
            artifact_type = str(raw_spec.get("artifact_type") or target.get("artifact_type") or "").strip()
            relative_path = str(raw_spec.get("relative_path") or "").strip()
            if not artifact_type or not relative_path:
                continue
            try:
                container_kind = ContainerKind(raw_spec.get("container_kind") or "app_data")
            except Exception:
                continue

            if platform == "android":
                key = (artifact_type, raw_spec.get("package"), relative_path, container_kind.value)
                if key in seen_android:
                    continue
                seen_android.add(key)
                android_specs.append(AndroidArtifactSpec(
                    artifact_type=artifact_type,
                    package=str(raw_spec.get("package") or ""),
                    relative_path=relative_path,
                    container_kind=container_kind,
                    description=str(raw_spec.get("description") or artifact_type),
                    is_directory=bool(raw_spec.get("is_directory", False)),
                    child_suffix_filter=_tuple_value(raw_spec.get("child_suffix_filter")),
                    filename_globs=_tuple_value(raw_spec.get("filename_globs")),
                ))
            elif platform == "ios":
                key = (artifact_type, raw_spec.get("package"), relative_path, container_kind.value)
                if key in seen_ios:
                    continue
                seen_ios.add(key)
                ios_specs.append(IOSArtifactSpec(
                    artifact_type=artifact_type,
                    package=raw_spec.get("package"),
                    relative_path=relative_path,
                    container_kind=container_kind,
                    description=str(raw_spec.get("description") or artifact_type),
                    is_directory=bool(raw_spec.get("is_directory", False)),
                    pull_sqlite_sidecars=bool(raw_spec.get("pull_sqlite_sidecars", False)),
                    child_suffix_filter=_tuple_value(raw_spec.get("child_suffix_filter")),
                ))

    if android_specs:
        spec_module.ANDROID_PATH_SPECS = tuple(android_specs)
    if ios_specs:
        spec_module.IOS_PATH_SPECS = tuple(ios_specs)

    try:
        from collectors.mobile_ffs import cellebrite_adapter
        if android_specs:
            cellebrite_adapter.ANDROID_PATH_SPECS = spec_module.ANDROID_PATH_SPECS
        if ios_specs:
            cellebrite_adapter.IOS_PATH_SPECS = spec_module.IOS_PATH_SPECS
    except Exception:
        pass

    return len(android_specs), len(ios_specs)
