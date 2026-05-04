"""
Live collection tests -- run the collector against the runner's own real
filesystem and verify path resolution, file copy, hashing, and manifest
generation work end-to-end.

These tests are designed to run on GitHub Actions macOS / Linux runners
(real machines, not emulators). They write to /tmp/live_collection_output
and produce a manifest.json that gets uploaded as a workflow artifact for
inspection.

What is asserted:
  - macOSCollector / LinuxCollector instantiate without error
  - At least one system-level artifact yields non-empty content
  - Every collected entry has SHA-256 (64 hex chars) and size_bytes > 0
  - manifest.json contains expected schema fields
  - Permission-denied entries are logged in 'errors', not crashing the run

What is NOT asserted (because a fresh CI runner has no user data):
  - Browser history exists (Safari / Firefox / Chrome empty on fresh runner)
  - Chat / mail content exists (no iMessage account, no Mail accounts)
  - Notes content exists (no notes written)
  - TCC-protected paths are readable (Full Disk Access cannot be granted in CI)
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

# Make the `collectors` package importable when pytest is invoked from any cwd.
# Test file lives at: collector/src/collectors/test_live_collection.py
# We need `collector/src/` on sys.path so `from collectors.macos_collector` works.
HERE = Path(__file__).resolve().parent           # collector/src/collectors/
SRC_DIR = HERE.parent                             # collector/src/
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

OUTPUT_DIR = Path("/tmp/live_collection_output")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _reset_output_dir() -> Path:
    """Clean output directory before each run."""
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return OUTPUT_DIR


def _write_collected_file(rel_path: str, content: bytes) -> Path:
    """Write collected bytes under OUTPUT_DIR / rel_path. Returns full path."""
    target = OUTPUT_DIR / rel_path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return target


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _drive_collection(
    collector,
    artifact_types: list[str],
    label: str,
) -> dict:
    """Drive the collector's collect_all() generator, write collected bytes
    to OUTPUT_DIR, and build a manifest. Returns a summary dict."""
    manifest: dict = {
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "label": label,
        },
        "artifacts": [],
        "errors": [],
        "by_type": {},
    }

    for artifact_type in artifact_types:
        type_summary = {"file_count": 0, "total_bytes": 0}
        had_any = False

        try:
            for rel_path, content, metadata in collector.collect_all(
                artifact_types=[artifact_type]
            ):
                if not isinstance(content, (bytes, bytearray)):
                    manifest["errors"].append({
                        "artifact_type": artifact_type,
                        "reason": f"non-bytes content: {type(content).__name__}",
                    })
                    continue

                target = _write_collected_file(rel_path, bytes(content))
                sha = _sha256(content)
                size = len(content)

                manifest["artifacts"].append({
                    "artifact_type": artifact_type,
                    "source_path": rel_path,
                    "source_sha256": sha,
                    "size_bytes": size,
                    "metadata": {
                        k: v for k, v in (metadata or {}).items()
                        if isinstance(v, (str, int, float, bool, list, dict))
                    },
                })
                type_summary["file_count"] += 1
                type_summary["total_bytes"] += size
                had_any = True

        except PermissionError as exc:
            manifest["errors"].append({
                "artifact_type": artifact_type,
                "reason": "permission_denied",
                "detail": str(exc),
            })
        except FileNotFoundError as exc:
            manifest["errors"].append({
                "artifact_type": artifact_type,
                "reason": "not_found",
                "detail": str(exc),
            })
        except Exception as exc:  # noqa: BLE001
            manifest["errors"].append({
                "artifact_type": artifact_type,
                "reason": f"{type(exc).__name__}: {exc}",
            })

        if not had_any and not any(
            e["artifact_type"] == artifact_type for e in manifest["errors"]
        ):
            manifest["errors"].append({
                "artifact_type": artifact_type,
                "reason": "empty_or_not_found",
            })

        manifest["by_type"][artifact_type] = type_summary

    (OUTPUT_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False)
    )
    return manifest


def _print_summary(label: str, manifest: dict) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {label} collection summary")
    print(f"{'=' * 60}")
    print(f"Host: {manifest['host']['platform']} / {manifest['host']['machine']}")
    print(f"Artifacts collected: {len(manifest['artifacts'])}")
    print(f"Errors:              {len(manifest['errors'])}")
    print()
    print("Per-type counts:")
    for atype, summary in manifest["by_type"].items():
        marker = "OK " if summary["file_count"] > 0 else "-- "
        print(f"  {marker}{atype:38s} {summary['file_count']:>4d} files,"
              f" {summary['total_bytes']:>10,d} bytes")

    if manifest["errors"]:
        print()
        print("Errors / empty results (expected for user-data artifacts):")
        for err in manifest["errors"]:
            print(f"  -- {err['artifact_type']:38s} {err['reason']}")


def _assert_manifest_schema(manifest: dict, *, min_artifacts: int) -> None:
    """Validate the manifest schema and that some artifacts were collected."""
    assert isinstance(manifest["artifacts"], list)
    assert isinstance(manifest["errors"], list)

    assert len(manifest["artifacts"]) >= min_artifacts, (
        f"Expected at least {min_artifacts} artifacts, got "
        f"{len(manifest['artifacts'])}. Errors: "
        f"{[e['artifact_type'] for e in manifest['errors']]}"
    )

    for entry in manifest["artifacts"]:
        assert {
            "artifact_type", "source_path", "source_sha256", "size_bytes"
        } <= entry.keys(), f"missing fields in {entry}"
        assert len(entry["source_sha256"]) == 64
        assert all(c in "0123456789abcdef" for c in entry["source_sha256"])
        assert entry["size_bytes"] > 0


# ---------------------------------------------------------------------------
# macOS live collection
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform != "darwin",
    reason="macOS-only test (requires real macOS runner)",
)
def test_macos_live_collection():
    """Run macOSCollector against the runner's own filesystem."""
    from collectors.macos_collector import macOSCollector  # noqa: PLC0415

    _reset_output_dir()
    collector = macOSCollector()

    # System-level artifacts that exist on a fresh macOS runner.
    # User-level artifacts (Safari, iMessage, Notes) are included but expected
    # to be empty -- the test still validates graceful handling.
    artifact_types = [
        # Should produce real files on every macOS runner:
        "macos_unified_log",
        "macos_system_log",
        "macos_install_log",
        "macos_asl_logs",
        "macos_launch_agent",
        "macos_launch_daemon",
        "macos_user_accounts",
        "macos_finder_plist",
        "macos_recent_items",
        "macos_volume_mounts",
        # User-level (expected empty on fresh runner -- tests graceful empty):
        "macos_safari_history",
        "macos_imessage",
        "macos_notes",
        # TCC-protected (expected permission_denied -- tests graceful denial):
        "macos_tcc_db",
        "macos_keychain",
        "macos_quarantine_events",
    ]

    manifest = _drive_collection(collector, artifact_types, "macOS")
    _print_summary("macOS", manifest)

    # On a real macOS runner, at least 5 system-level artifacts MUST yield data.
    # Anything less means the resolver is broken.
    _assert_manifest_schema(manifest, min_artifacts=5)

    # Specifically these must collect something:
    must_have_data = {"macos_launch_agent", "macos_launch_daemon", "macos_user_accounts"}
    collected_types = {a["artifact_type"] for a in manifest["artifacts"]}
    missing_required = must_have_data - collected_types
    assert not missing_required, (
        f"Required system-level types returned no data: {missing_required}"
    )


# ---------------------------------------------------------------------------
# Linux live collection
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="Linux-only test (requires real Linux runner)",
)
def test_linux_live_collection():
    """Run LinuxCollector against the runner's own filesystem."""
    from collectors.linux_collector import LinuxCollector  # noqa: PLC0415

    _reset_output_dir()
    collector = LinuxCollector()

    # System-level artifacts that exist on a fresh Ubuntu runner.
    artifact_types = [
        # Should produce real files on every Linux runner:
        "linux_auth_log",
        "linux_syslog",
        "linux_kern_log",
        "linux_dmesg",
        "linux_passwd",
        "linux_shadow",          # readable only as root -- expected denial
        "linux_group",
        "linux_hosts",
        "linux_systemd_service",
        "linux_crontab",
        "linux_apt_log",
        "linux_dpkg_log",
        "linux_boot_log",
        # User-level (likely empty on fresh runner):
        "linux_bash_history",
        "linux_chrome",
        "linux_firefox",
    ]

    manifest = _drive_collection(collector, artifact_types, "Linux")
    _print_summary("Linux", manifest)

    # On a real Linux runner, at least 5 system-level artifacts MUST yield data.
    _assert_manifest_schema(manifest, min_artifacts=5)

    # Specifically these must collect something on Ubuntu:
    must_have_data = {"linux_passwd", "linux_group", "linux_hosts"}
    collected_types = {a["artifact_type"] for a in manifest["artifacts"]}
    missing_required = must_have_data - collected_types
    assert not missing_required, (
        f"Required system-level types returned no data: {missing_required}"
    )


# ---------------------------------------------------------------------------
# Local-dev sanity (not run in CI -- skipped on all OSes by default)
# ---------------------------------------------------------------------------


@pytest.mark.skip(reason="Manual sanity check only; remove skip to run locally")
def test_local_sanity_dump_artifact_types():
    """Print the full list of artifact types each collector exposes.
    Useful when adding new types and verifying registration."""
    if sys.platform == "darwin":
        from collectors.macos_collector import macOSCollector
        types = list(macOSCollector().get_artifact_types().keys())
        print(f"macOS: {len(types)} types")
        for t in sorted(types):
            print(f"  {t}")
    elif sys.platform == "linux":
        from collectors.linux_collector import LinuxCollector
        types = list(LinuxCollector().get_artifact_types().keys())
        print(f"Linux: {len(types)} types")
        for t in sorted(types):
            print(f"  {t}")
