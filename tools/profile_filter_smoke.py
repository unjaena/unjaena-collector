#!/usr/bin/env python3
"""Smoke test for server-issued MFT profile filtering."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from collectors.base_mft_collector import ARTIFACT_MFT_FILTERS, BaseMFTCollector
from core.collection_profile import apply_collection_profile_to_registry


@dataclass
class Entry:
    filename: str
    full_path: str
    size: int = 128
    inode: int = 1
    is_deleted: bool = False


class DummyCollector(BaseMFTCollector):
    def _initialize_accessor(self) -> bool:
        return True

    def _get_source_description(self) -> str:
        return "dummy"

    def _build_mft_index(self) -> None:
        self._mft_cache = {
            "active_files": [
                Entry("random.json", "/Users/alice/Documents/random.json", inode=10),
                Entry("state.json", "/Users/alice/AppData/Roaming/target_app/state.json", inode=11),
                Entry("activity.log", "/Users/alice/AppData/Roaming/target_app/activity.log", inode=12),
                Entry("other.log", "/ProgramData/other.log", inode=13),
            ],
            "deleted_files": [],
            "directories": [],
        }
        self._build_extension_index()
        self._mft_indexed = True

    def _extract_entry(self, artifact_type, entry, artifact_dir):
        yield str(Path(artifact_dir) / entry.filename), {
            "original_path": entry.full_path,
            "artifact_type": artifact_type,
        }


def main() -> int:
    ARTIFACT_MFT_FILTERS.clear()
    apply_collection_profile_to_registry([
        {
            "artifact_type": "server_target_alpha",
            "kind": "profile_config",
            "metadata": {
                "collector_config": {
                    "mft_config": {
                        "user_path": "AppData/Roaming/target_app",
                        "extensions": [".json", ".log"],
                        "full_disk_scan": True,
                        "include_deleted": True,
                    }
                }
            },
        }
    ], ARTIFACT_MFT_FILTERS)

    with TemporaryDirectory() as temp_dir:
        collector = DummyCollector(temp_dir)
        collector._accessor = object()
        rows = list(collector.collect("server_target_alpha"))

    paths = sorted(meta["original_path"] for _, meta in rows)
    expected = sorted([
        "/Users/alice/AppData/Roaming/target_app/state.json",
        "/Users/alice/AppData/Roaming/target_app/activity.log",
    ])
    assert paths == expected, paths
    print("profile_filter_smoke_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
