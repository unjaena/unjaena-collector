from collectors.artifact_collector import ARTIFACT_TYPES
from collectors.artifact_collector import AI_BROWSER_EXTENSION_IDS
from collectors.artifact_collector import AI_BROWSER_INDEXEDDB_ORIGINS
from collectors.artifact_collector import LEVELDB_STORE_FILE_PATTERNS
from collectors.artifact_collector import LocalMFTCollector
from collectors.base_mft_collector import (
    ARTIFACT_MFT_FILTERS,
    DOCUMENT_EXTENSIONS,
    EMAIL_EXTENSIONS,
    IMAGE_EXTENSIONS,
    VIDEO_EXTENSIONS,
    USER_FILE_EXTENSION_POLICY,
)
from collectors.e01_artifact_collector import ARTIFACT_PATHS


def _pattern_extensions(pattern: str) -> set[str]:
    return {
        item.strip().replace("*", "")
        for item in pattern.split(",")
        if item.strip()
    }


def _legacy_path_extensions(paths: list[str]) -> set[str]:
    return {
        path.rsplit("*", 1)[-1].lower()
        for path in paths
        if "*" in path
    }


def test_user_file_extension_policy_matches_mft_filters():
    expected = {
        "document": DOCUMENT_EXTENSIONS,
        "email": EMAIL_EXTENSIONS,
        "image": IMAGE_EXTENSIONS,
        "video": VIDEO_EXTENSIONS,
    }

    assert USER_FILE_EXTENSION_POLICY == expected
    for artifact_type, extensions in expected.items():
        assert set(ARTIFACT_MFT_FILTERS[artifact_type]["extensions"]) == set(extensions)


def test_legacy_artifact_types_use_shared_extension_policy():
    for artifact_type, extensions in USER_FILE_EXTENSION_POLICY.items():
        config = ARTIFACT_TYPES[artifact_type]
        assert set(config["mft_config"]["extensions"]) == set(extensions)
        assert _legacy_path_extensions(config["paths"]) == set(extensions)


def test_e01_compatibility_patterns_use_shared_extension_policy():
    for artifact_type, extensions in USER_FILE_EXTENSION_POLICY.items():
        assert _pattern_extensions(ARTIFACT_PATHS[artifact_type]["pattern"]) == set(extensions)


def test_ai_browser_extension_policy_uses_known_manifest_paths_only():
    paths = ARTIFACT_TYPES["ai_browser_ai_extension"]["paths"]

    assert paths
    assert all(path.endswith("/manifest.json") for path in paths)
    assert not any("Local Extension Settings/*" in path for path in paths)
    assert not any(path.endswith("/Extensions/*") for path in paths)
    assert all(
        any(extension_id in path for extension_id in AI_BROWSER_EXTENSION_IDS)
        for path in paths
    )


def test_ai_browser_indexeddb_policy_uses_known_origin_paths_only():
    paths = ARTIFACT_TYPES["ai_browser_indexeddb"]["paths"]

    assert paths
    assert not any(path.endswith("/IndexedDB/*") for path in paths)
    assert not any("https_*.indexeddb.leveldb" in path for path in paths)
    assert all(
        (
            any(origin in path for origin in AI_BROWSER_INDEXEDDB_ORIGINS)
            or "https+++claude.ai" in path
            or "https+++chatgpt.com" in path
        )
        for path in paths
    )


def test_high_volume_browser_and_app_store_paths_are_bounded():
    forbidden_fragments = (
        "Slack/IndexedDB/*",
        "Slack/Cache/*",
        "Storage/ext/*",
        "Arc/User Data/Default/IndexedDB/*",
        "Perplexity/Comet/User Data/Default/IndexedDB/*",
        "Perplexity/Comet/User Data/Default/Local Storage/*",
        "Notion/IndexedDB/*",
        "Opera Stable/IndexedDB/*",
        "Opera Stable/Local Storage/*",
    )
    all_paths = [
        path.replace("\\", "/")
        for config in ARTIFACT_TYPES.values()
        for path in config.get("paths", [])
    ]

    for fragment in forbidden_fragments:
        assert not any(fragment in path for path in all_paths)


def test_leveldb_collection_paths_target_store_files():
    store_roots = (
        "Local Storage/leveldb/",
        "Session Storage/",
        "Teams/IndexedDB/",
        "WhatsAppDesktop_cv1g1gvanyjgm/LocalCache/EBWebView/Default/IndexedDB/",
    )
    allowed_endings = tuple(f"/{pattern}" for pattern in LEVELDB_STORE_FILE_PATTERNS)

    for artifact_type in (
        "ai_browser_localstorage",
        "windows_whatsapp",
        "windows_discord",
        "windows_facebook_web",
        "windows_instagram_web",
        "teams_v2_local_cache",
    ):
        for path in ARTIFACT_TYPES[artifact_type]["paths"]:
            normalized = path.replace("\\", "/")
            if any(root in normalized for root in store_roots):
                assert normalized.endswith(allowed_endings)


def test_directory_fallback_scans_with_shared_image_policy(monkeypatch, tmp_path):
    collector = object.__new__(LocalMFTCollector)
    collector.output_dir = tmp_path
    collector.volume = "Z"
    collector._get_source_description = lambda: "test"

    copied = []

    def fake_copy(src_path, artifact_dir, artifact_type):
        copied.append(src_path)
        return str(artifact_dir / src_path.rsplit("\\", 1)[-1]), {
            "artifact_type": artifact_type,
            "original_path": src_path,
        }

    collector._copy_file_with_metadata = fake_copy

    users_root = "Z:\\Users"
    monkeypatch.setattr(
        "collectors.artifact_collector.os.path.exists",
        lambda path: path == users_root,
    )
    monkeypatch.setattr(
        "collectors.artifact_collector.os.scandir",
        lambda path: iter(()),
    )
    monkeypatch.setattr(
        "collectors.artifact_collector.os.path.getsize",
        lambda path: 1024,
    )

    def fake_walk(path):
        assert path == users_root
        yield (
            "Z:\\Users\\alice\\Pictures",
            [],
            ["keep.webp", "keep.heif", "keep.tif", "keep.raw", "._skip.jpg"],
        )

    monkeypatch.setattr("collectors.artifact_collector.os.walk", fake_walk)

    results = list(
        collector._collect_user_file_filter_scan(
            "image",
            ARTIFACT_MFT_FILTERS["image"],
        )
    )

    assert [item[0].rsplit("\\", 1)[-1] for item in results] == [
        "keep.webp",
        "keep.heif",
        "keep.tif",
        "keep.raw",
    ]
    assert [path.rsplit("\\", 1)[-1] for path in copied] == [
        "keep.webp",
        "keep.heif",
        "keep.tif",
        "keep.raw",
    ]
