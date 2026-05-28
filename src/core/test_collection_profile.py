from core.collection_profile import apply_collection_profile_to_mobile_ffs, apply_collection_profile_to_registry


def test_apply_collection_profile_merges_paths_and_collector_config():
    registry = {
        "browser": {
            "name": "Browser",
            "paths": ["old"],
            "mft_config": {"old": True},
        }
    }
    targets = [
        {
            "artifact_type": "browser",
            "kind": "glob",
            "patterns": ["C:/Users/*/Browser/History"],
            "metadata": {
                "category": "windows",
                "collector_config": {
                    "mft_config": {"user_path": "AppData/Local", "files": ["History"]},
                    "process_name": "browser.exe",
                },
            },
        }
    ]

    applied = apply_collection_profile_to_registry(targets, registry)

    assert applied == {"browser"}
    assert registry["browser"]["paths"] == ["C:/Users/*/Browser/History"]
    assert registry["browser"]["mft_config"] == {"user_path": "AppData/Local", "files": ["History"]}
    assert registry["browser"]["process_name"] == "browser.exe"
    assert registry["browser"]["server_profile_managed"] is True


def test_apply_collection_profile_promotes_mft_keys_for_artifact_registry():
    registry = {}
    targets = [
        {
            "artifact_type": "document",
            "kind": "collector_config",
            "metadata": {
                "category": "windows",
                "collector_config": {
                    "extensions": [".txt"],
                    "full_disk_scan": True,
                    "path_optional": True,
                },
            },
        }
    ]

    applied = apply_collection_profile_to_registry(targets, registry)

    assert applied == {"document"}
    assert registry["document"]["extensions"] == [".txt"]
    assert registry["document"]["mft_config"] == {
        "extensions": [".txt"],
        "full_disk_scan": True,
        "path_optional": True,
    }


def test_apply_collection_profile_skips_source_file_targets():
    registry = {}
    targets = [
        {
            "artifact_type": "e01_image",
            "kind": "source_file",
            "patterns": ["*.E01"],
            "metadata": {"label": "E01 image"},
        }
    ]

    applied = apply_collection_profile_to_registry(targets, registry)

    assert applied == {"e01_image"}
    assert registry == {}


def test_apply_collection_profile_config_only_does_not_create_dummy_paths():
    registry = {}
    targets = [
        {
            "artifact_type": "mobile_android_sms",
            "kind": "collector_config",
            "patterns": ["profile://mobile_android_sms"],
            "metadata": {
                "category": "android",
                "collector_config": {"content_provider": {"uri": "content://sms"}},
            },
        }
    ]

    applied = apply_collection_profile_to_registry(targets, registry)

    assert applied == {"mobile_android_sms"}
    assert "paths" not in registry["mobile_android_sms"]
    assert registry["mobile_android_sms"]["content_provider"] == {"uri": "content://sms"}
    assert registry["mobile_android_sms"]["category"] == "android"


def test_apply_collection_profile_installs_mobile_ffs_specs():
    from collectors.mobile_ffs import cellebrite_adapter
    from collectors.mobile_ffs import path_specs

    old_android = path_specs.ANDROID_PATH_SPECS
    old_ios = path_specs.IOS_PATH_SPECS
    old_adapter_android = cellebrite_adapter.ANDROID_PATH_SPECS
    old_adapter_ios = cellebrite_adapter.IOS_PATH_SPECS
    try:
        path_specs.ANDROID_PATH_SPECS = ()
        path_specs.IOS_PATH_SPECS = ()
        cellebrite_adapter.ANDROID_PATH_SPECS = ()
        cellebrite_adapter.IOS_PATH_SPECS = ()
        targets = [
            {
                "artifact_type": "mobile_android_example",
                "kind": "collector_config",
                "metadata": {
                    "collector_config": {
                        "mobile_ffs_specs": [
                            {
                                "platform": "android",
                                "artifact_type": "mobile_android_example",
                                "package": "org.example.app",
                                "relative_path": "databases/example.db",
                                "container_kind": "app_data",
                                "description": "Example Android DB",
                                "is_directory": False,
                            },
                            {
                                "platform": "ios",
                                "artifact_type": "mobile_ios_example",
                                "package": "org.example.ios",
                                "relative_path": "Library/example.db",
                                "container_kind": "app_data",
                                "description": "Example iOS DB",
                                "pull_sqlite_sidecars": True,
                            },
                        ]
                    }
                },
            }
        ]

        counts = apply_collection_profile_to_mobile_ffs(targets)

        assert counts == (1, 1)
        assert path_specs.ANDROID_PATH_SPECS[0].artifact_type == "mobile_android_example"
        assert path_specs.IOS_PATH_SPECS[0].pull_sqlite_sidecars is True
        assert cellebrite_adapter.ANDROID_PATH_SPECS is path_specs.ANDROID_PATH_SPECS
        assert cellebrite_adapter.IOS_PATH_SPECS is path_specs.IOS_PATH_SPECS
    finally:
        path_specs.ANDROID_PATH_SPECS = old_android
        path_specs.IOS_PATH_SPECS = old_ios
        cellebrite_adapter.ANDROID_PATH_SPECS = old_adapter_android
        cellebrite_adapter.IOS_PATH_SPECS = old_adapter_ios
