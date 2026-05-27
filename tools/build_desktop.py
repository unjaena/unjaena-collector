import subprocess
import sys
import platform
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
    system = platform.system().lower()
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--windowed",
        "--name",
        "UnjaenaCollector",
        str(entry),
    ]
    if system == "darwin":
        cmd.insert(5, "--onedir")
    else:
        cmd.insert(5, "--onefile")
    return subprocess.call(cmd, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
