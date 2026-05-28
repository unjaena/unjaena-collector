import subprocess
import sys
import platform
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _require_desktop_gui() -> None:
    try:
        import PyQt6.QtWidgets  # noqa: F401
    except Exception as exc:
        raise SystemExit(f"PyQt6 desktop support is required for GUI builds: {exc}")


def main() -> int:
    _require_desktop_gui()
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
        "--hidden-import",
        "pymobiledevice3.usbmux",
        "--hidden-import",
        "pymobiledevice3.lockdown",
        str(entry),
    ]
    if system == "windows":
        cmd[5:5] = ["--onefile", "--uac-admin", "--hidden-import", "wmi", "--hidden-import", "win32com.client", "--hidden-import", "pythoncom"]
    elif system == "darwin":
        cmd.insert(5, "--onedir")
    else:
        cmd.insert(5, "--onefile")
    return subprocess.call(cmd, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
