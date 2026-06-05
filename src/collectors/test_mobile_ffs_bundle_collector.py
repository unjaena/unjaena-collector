import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parent
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from collectors.mobile_ffs import cellebrite_adapter, path_specs
from collectors.mobile_ffs.path_specs import AndroidArtifactSpec
from collectors.mobile_ffs_collector import (
    MobileFFSBundleCollector,
    expand_mobile_ffs_selection,
)


def _install_android_specs(monkeypatch):
    specs = (
        AndroidArtifactSpec(
            artifact_type="mobile_android_call",
            package="org.example.contacts",
            relative_path="databases/calllog.db",
        ),
        AndroidArtifactSpec(
            artifact_type="mobile_android_example_app",
            package="org.example.chat",
            relative_path="databases/messages.db",
        ),
    )
    monkeypatch.setattr(path_specs, "ANDROID_PATH_SPECS", specs)
    monkeypatch.setattr(cellebrite_adapter, "ANDROID_PATH_SPECS", specs)


def _write_android_bundle(path: Path) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("version", "CLBX-0.3.1")
        zf.writestr(
            "Dump/data/data/org.example.contacts/databases/calllog.db",
            b"SQLite format 3\x00" + b"\x00" * 1024,
        )
        zf.writestr(
            "Dump/data/data/org.example.chat/databases/messages.db",
            b"SQLite format 3\x00" + b"\x00" * 1024,
        )


def test_android_provider_alias_uploads_canonical_artifact_type(tmp_path, monkeypatch):
    _install_android_specs(monkeypatch)
    bundle = tmp_path / "android_ffs.zip"
    _write_android_bundle(bundle)

    collector = MobileFFSBundleCollector(str(tmp_path / "out"), str(bundle))
    try:
        results = list(collector.collect("mobile_android_call_provider"))
    finally:
        collector.close()

    files = [(p, m) for p, m in results if p]
    assert len(files) == 1
    file_path, metadata = files[0]
    staged = Path(file_path)
    assert staged.is_file()
    assert "Dump" not in staged.parts
    assert metadata["source_path"].startswith("Dump/data/data/")
    assert metadata["extracted_source_path"].endswith("calllog.db")
    assert metadata["upload_artifact_type"] == "mobile_android_call"
    assert metadata["requested_artifact_type"] == "mobile_android_call_provider"


def test_android_generic_app_expands_to_present_app_artifacts(tmp_path, monkeypatch):
    _install_android_specs(monkeypatch)
    bundle = tmp_path / "android_ffs.zip"
    _write_android_bundle(bundle)

    collector = MobileFFSBundleCollector(str(tmp_path / "out"), str(bundle))
    try:
        results = list(collector.collect("mobile_android_app"))
    finally:
        collector.close()

    files = [(p, m) for p, m in results if p]
    assert len(files) == 1
    assert "Dump" not in Path(files[0][0]).parts
    assert files[0][1]["upload_artifact_type"] == "mobile_android_example_app"


def test_unknown_ffs_artifact_is_skipped_not_error(tmp_path, monkeypatch):
    _install_android_specs(monkeypatch)
    bundle = tmp_path / "android_ffs.zip"
    _write_android_bundle(bundle)

    collector = MobileFFSBundleCollector(str(tmp_path / "out"), str(bundle))
    try:
        results = list(collector.collect("mobile_android_not_supported"))
    finally:
        collector.close()

    assert results == [
        (
            "",
            {
                "status": "skipped",
                "error": (
                    "Artifact 'mobile_android_not_supported' is not supported by "
                    "this FFS bundle profile"
                ),
            },
        )
    ]


def test_selection_expansion_filters_to_available_ffs_types():
    available = {
        "mobile_android_call",
        "mobile_android_example_app",
        "mobile_android_google_maps",
    }

    assert expand_mobile_ffs_selection(
        "mobile_android_call_provider", available
    ) == ["mobile_android_call"]
    assert expand_mobile_ffs_selection(
        "mobile_android_location", available
    ) == ["mobile_android_google_maps"]
    assert expand_mobile_ffs_selection(
        "mobile_android_app", available
    ) == ["mobile_android_example_app", "mobile_android_google_maps"]
