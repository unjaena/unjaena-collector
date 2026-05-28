from __future__ import annotations

import os
import platform
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PrivilegeStatus:
    elevated: bool
    platform: str
    can_relaunch: bool
    detail: str


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def is_elevated() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    if hasattr(os, "geteuid"):
        try:
            return os.geteuid() == 0
        except Exception:
            return False
    return False


def _executable() -> str:
    return sys.executable or str(Path(sys.argv[0]).resolve())


def _args_without_executable() -> list[str]:
    return [str(arg) for arg in sys.argv[1:]]


def can_relaunch_elevated() -> bool:
    if is_elevated():
        return False
    if sys.platform == "win32":
        return True
    if sys.platform == "darwin":
        return bool(shutil.which("osascript"))
    return bool(shutil.which("pkexec") or shutil.which("sudo"))


def privilege_status() -> PrivilegeStatus:
    elevated = is_elevated()
    system = platform.system() or sys.platform
    if elevated:
        return PrivilegeStatus(True, system, False, "Administrator privileges are active.")
    if can_relaunch_elevated():
        return PrivilegeStatus(False, system, True, "Administrator privileges are required for physical disk and protected filesystem access.")
    return PrivilegeStatus(False, system, False, "Administrator privileges are not active, and no supported relaunch helper was found.")


def relaunch_elevated() -> bool:
    if is_elevated():
        return False
    executable = _executable()
    args = _args_without_executable()
    if sys.platform == "win32":
        try:
            import ctypes
            params = subprocess.list2cmdline(args)
            rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, None, 1)
            return int(rc) > 32
        except Exception:
            return False
    if sys.platform == "darwin" and shutil.which("osascript"):
        command = " ".join([shlex.quote(executable), *(shlex.quote(arg) for arg in args)])
        script = f'do shell script {command!r} with administrator privileges'
        try:
            return subprocess.call(["osascript", "-e", script]) == 0
        except Exception:
            return False
    helper = shutil.which("pkexec") or shutil.which("sudo")
    if helper:
        try:
            return subprocess.Popen([helper, executable, *args]).pid > 0
        except Exception:
            return False
    return False


def should_auto_elevate() -> bool:
    if os.environ.get("UNJAENA_SKIP_ELEVATION") == "1":
        return False
    return is_frozen() and not is_elevated() and can_relaunch_elevated()


def relaunch_if_needed() -> bool:
    if not should_auto_elevate():
        return False
    return relaunch_elevated()
