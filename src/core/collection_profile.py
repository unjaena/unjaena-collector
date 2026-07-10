"""Runtime application of server-issued collection profiles.

The public collector keeps acquisition engines locally, while target policy
(path patterns, MFT hints, process names, and per-artifact metadata) can be
issued by the server after session authentication.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping, MutableMapping


_SOURCE_FILE_KINDS = {"source_file", "source_upload", "evidence_source"}
_CONFIG_ONLY_KINDS = {"collector_config", "profile_config"}
_MFT_CONFIG_KEYS = {
    "base_path",
    "exclude_extensions",
    "exclude_path_patterns",
    "extensions",
    "files",
    "full_disk_scan",
    "include_deleted",
    "max_file_size",
    "name_pattern",
    "path_optional",
    "path_pattern",
    "path_patterns",
    "paths",
    "pattern",
    "special",
    "user_path",
}

_MERGE_SEQUENCE_KEYS = {
    "exclude_extensions",
    "exclude_path_patterns",
    "extensions",
    "files",
    "manifest_paths",
    "manifest_targets",
    "path_patterns",
    "paths",
}

_PLATFORM_CATEGORIES = {"windows", "android", "ios", "linux", "macos", "ai_activity"}
_WINDOWS_DISPLAY_CATEGORIES = {
    "forensic",
    "user_files",
    "user file",
    "user_file",
    "evidence_sources",
    "evidence source",
    "evidence_source",
    "source_upload",
    "common/source",
    "collection",
    "pc_messenger",
    "pc_apps",
}
_WINDOWS_SUBCATEGORY_HINTS = {"pc_messenger", "pc_apps", "filesystem", "developer"}
_MOBILE_FFS_PROFILE_ONLY_KEYS = {
    "category",
    "collector",
    "description",
    "mobile_ffs_specs",
    "name",
    "subcategory",
}


_IOS_SYSTEM_PREFIXES = (
    ("private/var/mobile/Library/Health/", "HealthDomain", "Health/"),
    ("private/var/mobile/Library/Caches/locationd/", "RootDomain", "Library/Caches/locationd/"),
    ("private/var/mobile/Library/", "HomeDomain", "Library/"),
    ("private/var/mobile/Media/", "MediaDomain", ""),
    ("private/var/preferences/SystemConfiguration/", "SystemPreferencesDomain", "SystemConfiguration/"),
)


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


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _sequence(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return [value]


def _merge_sequence(existing: Any, incoming: Any) -> list[Any]:
    merged = []
    seen = set()
    for item in _sequence(existing) + _sequence(incoming):
        marker = repr(item)
        if marker in seen:
            continue
        seen.add(marker)
        merged.append(item)
    return merged


def _merge_config(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(existing)
    for key, value in incoming.items():
        if key in _MERGE_SEQUENCE_KEYS and key in merged:
            merged[key] = _merge_sequence(merged.get(key), value)
        else:
            merged[key] = deepcopy(value)
    return merged


def _collector_config_from_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Return collector config regardless of where the server placed it."""
    collector_config = _as_dict(
        metadata.get("collector_config")
        or metadata.get("collection_config")
        or metadata.get("config")
    )
    if not collector_config:
        collector_config = {
            key: metadata[key]
            for key in _MFT_CONFIG_KEYS | {"mobile_ffs_specs", "collector"}
            if key in metadata
        }
    if "mft_config" in metadata and "mft_config" not in collector_config:
        collector_config["mft_config"] = metadata["mft_config"]
    return collector_config


def _category_token(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _category_candidate(value: Any) -> str | None:
    token = _category_token(value)
    if not token:
        return None
    aliases = {
        "win": "windows",
        "mac": "macos",
        "osx": "macos",
        "ai": "ai_activity",
        "ai_activity_artifacts": "ai_activity",
    }
    token = aliases.get(token, token)
    if token in _PLATFORM_CATEGORIES:
        return token
    if token in _WINDOWS_DISPLAY_CATEGORIES:
        return "windows"
    return None


def _infer_artifact_category(
    artifact_type: str,
    metadata: dict[str, Any],
    existing: dict[str, Any],
    merged: dict[str, Any],
) -> str:
    """Normalize server display categories into collector UI platform tabs."""
    for value in (
        merged.get("category"),
        existing.get("category"),
        metadata.get("category"),
    ):
        category = _category_candidate(value)
        if category:
            return category

    if artifact_type.startswith("mobile_android_"):
        return "android"
    if artifact_type.startswith("mobile_ios_"):
        return "ios"
    if artifact_type.startswith("linux_"):
        return "linux"
    if artifact_type.startswith("macos_"):
        return "macos"
    if artifact_type.startswith("ai_"):
        return "ai_activity"
    return "windows"


def _infer_artifact_subcategory(
    artifact_type: str,
    metadata: dict[str, Any],
    existing: dict[str, Any],
    merged: dict[str, Any],
) -> str | None:
    for value in (
        merged.get("subcategory"),
        existing.get("subcategory"),
        metadata.get("subcategory"),
        merged.get("category"),
        metadata.get("category"),
    ):
        token = _category_token(value)
        if token in _WINDOWS_SUBCATEGORY_HINTS:
            return token

    if artifact_type in {"mft", "usn_journal", "logfile"}:
        return "filesystem"
    if artifact_type == "source_code":
        return "developer"
    return None


def _mft_config_from_entry(
    entry: dict[str, Any],
    *,
    include_top_level_paths: bool = True,
) -> dict[str, Any]:
    mft_config = _as_dict(entry.get("mft_config"))
    for key in _MFT_CONFIG_KEYS:
        if key == "paths" and not include_top_level_paths:
            continue
        if key in entry and key not in mft_config:
            mft_config[key] = entry[key]
    return mft_config


def _normalize_ios_relative_path(path: Any) -> str:
    value = str(path or "").strip().replace("\\", "/")
    while value.startswith("/"):
        value = value[1:]
    for prefix in ("filesystem1/", "Dump/"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    return value


def _ios_system_backup_target(relative_path: str) -> tuple[str, str] | None:
    rel = _normalize_ios_relative_path(relative_path)
    for prefix, domain, replacement in _IOS_SYSTEM_PREFIXES:
        if rel.startswith(prefix):
            return domain, replacement + rel[len(prefix):]
    return None


def _ios_backup_target_from_spec(raw_spec: dict[str, Any]) -> dict[str, Any] | None:
    platform = str(raw_spec.get("platform") or "").lower()
    if platform != "ios":
        return None

    relative_path = _normalize_ios_relative_path(
        raw_spec.get("backup_manifest_path")
        or raw_spec.get("manifest_path")
        or raw_spec.get("relative_path")
    )
    if not relative_path:
        return None

    domain = str(
        raw_spec.get("backup_manifest_domain")
        or raw_spec.get("manifest_domain")
        or ""
    ).strip()

    if not domain:
        container_kind = str(raw_spec.get("container_kind") or "app_data").lower()
        package = str(raw_spec.get("package") or "").strip()

        if container_kind == "app_data" and package:
            domain = f"AppDomain-{package}"
        elif container_kind == "app_group":
            group_id = str(
                raw_spec.get("app_group")
                or raw_spec.get("group_identifier")
                or raw_spec.get("backup_group")
                or ""
            ).strip()
            if group_id.startswith("group."):
                domain = f"AppDomainGroup-{group_id}"
            elif package.startswith("group."):
                domain = f"AppDomainGroup-{package}"
            else:
                return None
        elif container_kind in {"system", "root_system", "user_media"}:
            mapped = _ios_system_backup_target(relative_path)
            if not mapped:
                return None
            domain, relative_path = mapped
        else:
            return None

    is_directory = bool(raw_spec.get("is_directory", False))
    is_pattern = is_directory or "*" in relative_path or "?" in relative_path
    if is_directory:
        relative_path = relative_path.rstrip("/") + "/*"

    target = {
        "manifest_domain": domain,
        "manifest_path": relative_path,
    }
    if is_pattern:
        target["pattern"] = True
    return target


def _ios_backup_targets_from_config(collector_config: dict[str, Any]) -> list[dict[str, Any]]:
    targets = []
    seen = set()
    for raw_spec in collector_config.get("mobile_ffs_specs") or []:
        if not isinstance(raw_spec, dict):
            continue
        converted = _ios_backup_target_from_spec(raw_spec)
        if not converted:
            continue
        key = (
            converted.get("manifest_domain"),
            converted.get("manifest_path"),
            bool(converted.get("pattern")),
        )
        if key in seen:
            continue
        seen.add(key)
        targets.append(converted)
    return targets


def _install_ios_backup_targets(
    merged: dict[str, Any],
    existing: dict[str, Any],
    collector_config: dict[str, Any],
) -> None:
    if any(
        key in existing
        for key in ("manifest_targets", "manifest_domain", "manifest_path", "manifest_paths")
    ):
        return
    if any(
        key in collector_config
        for key in ("manifest_targets", "manifest_domain", "manifest_path", "manifest_paths")
    ):
        return

    targets = _ios_backup_targets_from_config(collector_config)
    if not targets:
        return

    merged["manifest_targets"] = targets

    domains = {target["manifest_domain"] for target in targets}
    if len(domains) != 1:
        return

    merged["manifest_domain"] = targets[0]["manifest_domain"]
    paths = [target["manifest_path"] for target in targets]
    if len(paths) == 1:
        merged["manifest_path"] = paths[0]
    else:
        merged["manifest_paths"] = paths
    if any(target.get("pattern") for target in targets):
        merged["pattern"] = True


def _is_mobile_ffs_profile_only_target(
    kind_token: str,
    collector_config: Mapping[str, Any],
) -> bool:
    if kind_token not in _CONFIG_ONLY_KINDS:
        return False
    if not collector_config.get("mobile_ffs_specs"):
        return False
    return set(collector_config).issubset(_MOBILE_FFS_PROFILE_ONLY_KEYS)


def apply_collection_profile_to_registry(
    targets: list[Any] | None,
    registry: MutableMapping[str, dict[str, Any]],
    artifact_aliases: Mapping[str, str] | None = None,
    *,
    mft_registry: bool = False,
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
        raw_artifact_type = str(target.get("artifact_type") or "").strip()
        if not raw_artifact_type:
            continue
        artifact_type = str(
            (artifact_aliases or {}).get(raw_artifact_type, raw_artifact_type)
        ).strip()
        profile_artifacts.add(artifact_type)

        kind = str(target.get("kind") or "glob")
        kind_token = kind.strip().lower()
        patterns = [str(item) for item in target.get("patterns") or [] if item]
        metadata = _as_dict(target.get("metadata"))

        if kind_token in _SOURCE_FILE_KINDS:
            # Evidence-source uploads are handled by the source-file workflow,
            # not by local artifact path collectors.
            continue

        collector_config = _collector_config_from_metadata(metadata)
        if (
            artifact_type not in registry
            and _is_mobile_ffs_profile_only_target(kind_token, collector_config)
        ):
            continue

        existing = deepcopy(registry.get(artifact_type) or {})

        if mft_registry:
            # ARTIFACT_MFT_FILTERS is consumed directly by BaseMFTCollector.
            # Do not copy UI/legacy collector fields such as the enormous
            # ARTIFACT_TYPES[*]["paths"] glob expansion into the MFT filter.
            # MFT collection needs only mft_config and explicit MFT keys.
            has_nested_mft_config = bool(_as_dict(collector_config.get("mft_config")))
            mft_config = _mft_config_from_entry(
                collector_config,
                include_top_level_paths=not has_nested_mft_config and artifact_type != "source_code",
            )
            if patterns and kind not in _CONFIG_ONLY_KINDS and artifact_type != "source_code":
                mft_config["paths"] = _merge_sequence(mft_config.get("paths"), patterns)
            if target.get("max_bytes") is not None and "max_file_size" not in mft_config:
                mft_config["max_file_size"] = target.get("max_bytes")

            merged = _merge_config(existing, mft_config)
            if artifact_type == "source_code":
                merged.pop("paths", None)
            merged["server_profile_managed"] = True
            registry[artifact_type] = merged
            continue

        merged = _merge_config(existing, collector_config)
        _install_ios_backup_targets(merged, existing, collector_config)
        if patterns and kind not in _CONFIG_ONLY_KINDS:
            if existing.get("server_profile_managed"):
                merged["paths"] = _merge_sequence(merged.get("paths"), patterns)
            else:
                merged["paths"] = patterns
        if target.get("max_bytes") is not None:
            merged["max_bytes"] = target.get("max_bytes")

        # GUI ArtifactCollector routes forensic-disk collection through
        # ARTIFACT_TYPES[*]["mft_config"], while E01/BaseMFT collectors read
        # the MFT registry directly. Keep both registries effective so decrypted
        # BitLocker/LUKS readers and ordinary disk images honor the same profile.
        has_explicit_mft_config = bool(_as_dict(collector_config.get("mft_config"))) or any(
            key in collector_config for key in _MFT_CONFIG_KEYS
        )
        mft_config = _mft_config_from_entry(collector_config)
        for key in _MFT_CONFIG_KEYS:
            if key in collector_config and key not in mft_config:
                mft_config[key] = collector_config[key]
        if (
            patterns
            and kind not in _CONFIG_ONLY_KINDS
            and (not has_explicit_mft_config or existing.get("server_profile_managed"))
        ):
            mft_config["paths"] = _merge_sequence(mft_config.get("paths"), patterns)
        if target.get("max_bytes") is not None and "max_file_size" not in mft_config:
            mft_config["max_file_size"] = target.get("max_bytes")
        if mft_config:
            existing_mft_config = (
                _mft_config_from_entry(existing)
                if existing.get("server_profile_managed")
                else {}
            )
            mft_config = _merge_config(existing_mft_config, mft_config)
            merged["mft_config"] = mft_config
            for key, value in mft_config.items():
                if key in _MFT_CONFIG_KEYS:
                    merged[key] = value

        merged.setdefault("name", metadata.get("label") or artifact_type.replace("_", " ").title())
        merged.setdefault("description", metadata.get("description") or "Server-authorized collection target")
        merged["category"] = _infer_artifact_category(artifact_type, metadata, existing, merged)
        inferred_subcategory = _infer_artifact_subcategory(artifact_type, metadata, existing, merged)
        if inferred_subcategory and not merged.get("subcategory"):
            merged["subcategory"] = inferred_subcategory
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

    for spec in getattr(spec_module, "ANDROID_PATH_SPECS", ()) or ():
        key = (
            getattr(spec, "artifact_type", None),
            getattr(spec, "package", None),
            getattr(spec, "relative_path", None),
            getattr(getattr(spec, "container_kind", None), "value", None),
        )
        if key in seen_android:
            continue
        seen_android.add(key)
        android_specs.append(spec)

    for spec in getattr(spec_module, "IOS_PATH_SPECS", ()) or ():
        key = (
            getattr(spec, "artifact_type", None),
            getattr(spec, "package", None),
            getattr(spec, "relative_path", None),
            getattr(getattr(spec, "container_kind", None), "value", None),
        )
        if key in seen_ios:
            continue
        seen_ios.add(key)
        ios_specs.append(spec)

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
