#!/usr/bin/env python3
"""Release-blocking acceptance gate for collector source builds."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    existing = env.get("PYTHONPATH", "")
    paths = [str(SRC)]
    if existing:
        paths.append(existing)
    env["PYTHONPATH"] = os.pathsep.join(paths)
    return env


def _run(label: str, args: list[str]) -> None:
    print(f"[release-gate] {label}", flush=True)
    subprocess.run(args, cwd=ROOT, env=_env(), check=True)


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    actual_local = "--actual-local" in argv

    _run("compile source", [sys.executable, "-m", "compileall", "-q", "src", "tools"])
    _run("public preflight", [sys.executable, "tools/public_preflight.py"])
    _run("profile filter smoke", [sys.executable, "tools/profile_filter_smoke.py"])

    device_args = [sys.executable, "tools/device_enumerator_smoke.py"]
    if actual_local:
        device_args.append("--actual-local")
    _run("device enumeration smoke", device_args)

    _run("GUI workflow smoke", [sys.executable, "tools/gui_workflow_smoke.py"])
    print("release_gate_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
