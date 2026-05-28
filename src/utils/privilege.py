"""
Privilege Management Module

Handles administrator/root privilege checks and elevation.
Cross-platform: Windows (UAC), Linux/macOS (euid check).
"""
import sys
import os
import logging
import platform


def is_admin() -> bool:
    """Check if the current process has administrator/root privileges."""
    if sys.platform == 'win32':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        # Linux / macOS: check effective user ID
        return os.geteuid() == 0


def run_as_admin() -> bool:
    """
    Restart the application with administrator privileges.
    Only supported on Windows (UAC elevation).

    Returns:
        bool: True if elevation was requested, False otherwise
    """
    if sys.platform != 'win32':
        return False

    try:
        import ctypes

        # Handle PyInstaller frozen executable
        if getattr(sys, 'frozen', False):
            # Running as compiled EXE
            executable = sys.executable
            # For frozen apps, sys.argv[0] is the exe path
            args = sys.argv[1:] if len(sys.argv) > 1 else []
        else:
            # Running as script
            executable = sys.executable
            args = sys.argv

        # Build argument string
        if args:
            arg_string = " ".join([f'"{arg}"' for arg in args])
        else:
            arg_string = ""

        # Request elevation via ShellExecuteW
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            executable,
            arg_string,
            None,
            1  # SW_SHOWNORMAL
        )

        # ShellExecuteW returns > 32 on success
        return result > 32
    except Exception:
        logging.getLogger(__name__).warning("Failed to request elevation")
        return False


def get_current_user() -> str:
    """Get the current username."""
    return os.getlogin()


def get_computer_name() -> str:
    """Get the computer/host name."""
    if sys.platform == 'win32':
        return os.environ.get('COMPUTERNAME', platform.node())
    return platform.node()
