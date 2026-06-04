from core.collection_profile import apply_collection_profile_to_registry


def test_ios_mobile_specs_create_backup_manifest_targets():
    registry = {}
    targets = [
        {
            "artifact_type": "mobile_ios_example",
            "kind": "collector_config",
            "metadata": {
                "category": "ios",
                "collector_config": {
                    "mobile_ffs_specs": [
                        {
                            "platform": "ios",
                            "artifact_type": "mobile_ios_example",
                            "package": "com.example.app",
                            "relative_path": "Documents",
                            "container_kind": "app_data",
                            "is_directory": True,
                        },
                        {
                            "platform": "ios",
                            "artifact_type": "mobile_ios_example",
                            "relative_path": "private/var/mobile/Library/Data/example.db",
                            "container_kind": "system",
                        },
                    ],
                },
            },
        }
    ]

    apply_collection_profile_to_registry(targets, registry)

    entry = registry["mobile_ios_example"]
    assert entry["category"] == "ios"
    assert entry["manifest_targets"] == [
        {
            "manifest_domain": "AppDomain-com.example.app",
            "manifest_path": "Documents/*",
            "pattern": True,
        },
        {
            "manifest_domain": "HomeDomain",
            "manifest_path": "Library/Data/example.db",
        },
    ]


def test_existing_ios_manifest_config_is_not_overwritten():
    registry = {
        "mobile_ios_existing": {
            "manifest_domain": "HomeDomain",
            "manifest_path": "Library/Existing/example.db",
        }
    }
    targets = [
        {
            "artifact_type": "mobile_ios_existing",
            "kind": "collector_config",
            "metadata": {
                "category": "ios",
                "collector_config": {
                    "mobile_ffs_specs": [
                        {
                            "platform": "ios",
                            "artifact_type": "mobile_ios_existing",
                            "package": "com.example.other",
                            "relative_path": "Documents",
                            "container_kind": "app_data",
                            "is_directory": True,
                        },
                    ],
                },
            },
        }
    ]

    apply_collection_profile_to_registry(targets, registry)

    assert registry["mobile_ios_existing"]["manifest_domain"] == "HomeDomain"
    assert registry["mobile_ios_existing"]["manifest_path"] == "Library/Existing/example.db"
    assert "manifest_targets" not in registry["mobile_ios_existing"]
