import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _require_tk() -> None:
    try:
        import tkinter
        root = tkinter.Tcl()
        root.eval("info patchlevel")
    except Exception as exc:
        raise SystemExit(f"Tcl/Tk desktop support is required for GUI builds: {exc}")


def main() -> int:
    _require_tk()
    entry = ROOT / "src" / "unjaena_collector" / "desktop.py"
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--name",
        "UnjaenaCollector",
        str(entry),
    ]
    return subprocess.call(cmd, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
