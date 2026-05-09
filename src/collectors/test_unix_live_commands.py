from __future__ import annotations

import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
SRC_DIR = HERE.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def test_linux_systemd_journal_live_command_export(monkeypatch, tmp_path):
    from collectors import live_command
    from collectors.linux_collector import LinuxCollector

    def fake_which(name: str):
        return f"/usr/bin/{name}" if name == "journalctl" else None

    def fake_run(cmd, **kwargs):
        assert cmd[:2] == ["/usr/bin/journalctl", "--output=json"]
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=b'{"MESSAGE":"accepted","__REALTIME_TIMESTAMP":"1"}\n',
            stderr=b"",
        )

    monkeypatch.setattr(live_command.shutil, "which", fake_which)
    monkeypatch.setattr(live_command.subprocess, "run", fake_run)

    collector = LinuxCollector(str(tmp_path), target_root=str(tmp_path))
    monkeypatch.setattr(collector, "_is_live_local_target", lambda: True)

    results = list(collector.collect("linux_systemd_journal"))

    assert len(results) == 1
    rel_path, content, metadata = results[0]
    assert rel_path == "live/journalctl_today.json"
    assert b'"MESSAGE":"accepted"' in content
    assert metadata["collection_method"] == "live_command"
    assert metadata["platform"] == "linux"


def test_macos_unified_log_live_command_export(monkeypatch, tmp_path):
    from collectors import live_command
    from collectors.macos_collector import macOSCollector

    def fake_which(name: str):
        return f"/usr/bin/{name}" if name == "log" else None

    def fake_run(cmd, **kwargs):
        assert cmd[:4] == ["/usr/bin/log", "show", "--style", "ndjson"]
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=b'{"process":"kernel","eventMessage":"auth denied"}\n',
            stderr=b"",
        )

    monkeypatch.setattr(live_command.shutil, "which", fake_which)
    monkeypatch.setattr(live_command.subprocess, "run", fake_run)

    collector = macOSCollector(str(tmp_path), target_root=str(tmp_path))
    monkeypatch.setattr(collector, "_is_live_local_target", lambda: True)

    results = list(collector.collect("macos_unified_log"))

    assert len(results) == 2
    assert {item[0] for item in results} == {
        "live/log_show_last_24h.ndjson",
        "live/log_show_security_last_24h.ndjson",
    }
    assert all(item[2]["collection_method"] == "live_command" for item in results)
