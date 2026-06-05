import importlib.util
import sys
from pathlib import Path

import pytest


SRC_ROOT = Path(__file__).resolve().parent
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


def _load_module(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, SRC_ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _headless(tmp_path):
    cli = _load_module("collector_cli_under_test", "cli.py")
    return cli.HeadlessCollector(
        server_url="https://collector.test",
        session_id="session",
        collection_token="token",
        case_id="case",
        artifacts=[],
        output_dir=str(tmp_path),
    )


def test_headless_normalizes_collector_tuple_contract(tmp_path):
    collected_file = tmp_path / "artifact.db"
    collected_file.write_bytes(b"data")
    collector = _headless(tmp_path)

    normalized = collector._normalize_collected_item(
        (
            str(collected_file),
            {
                "status": "ok",
                "upload_artifact_type": "server_authorized_target",
                "original_path": "/source/container/artifact.db",
            },
        ),
        "selected_target",
    )

    assert normalized is not None
    file_path, artifact_type, metadata = normalized
    assert file_path == str(collected_file)
    assert artifact_type == "server_authorized_target"
    assert metadata["original_path"].endswith("artifact.db")


@pytest.mark.parametrize("status", ["error", "not_found", "skipped", "not_implemented"])
def test_headless_skips_non_uploadable_collector_statuses(tmp_path, status):
    collector = _headless(tmp_path)

    normalized = collector._normalize_collected_item(
        (None, {"status": status, "error": "not uploadable"}),
        "selected_target",
    )

    assert normalized is None


def test_headless_hash_stage_rejects_empty_files(tmp_path):
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")
    collector = _headless(tmp_path)

    hashed = collector._compute_hashes([(str(empty_file), "document", {})])

    assert hashed == []


def test_upload_completion_requires_all_preconditions():
    pytest.importorskip("PyQt6")
    app = _load_module("collector_gui_app_under_test", "gui/app.py")
    ready = app.CollectionWorker._upload_batch_ready_for_completion

    assert ready(2, 2, 0, None) is True
    assert ready(2, 1, 0, None) is False
    assert ready(2, 2, 1, None) is False
    assert ready(2, 2, 0, "quality warning") is False
    assert ready(0, 0, 0, None) is False
