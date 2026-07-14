#!/usr/bin/env python3
"""
Digital Forensics Collector - Main Entry Point

This tool collects forensic artifacts from target systems
and uploads them to the forensics server for analysis.

Supports:
- GUI mode (default): PyQt6 graphical interface
- CLI/Headless mode: --headless --token TOKEN --server URL
"""
import sys
import os
import json
import logging
import argparse

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Fix SSL CA bundle path for PyInstaller builds
if getattr(sys, 'frozen', False):
    _meipass = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
    _ca_bundle = os.path.join(_meipass, 'certifi', 'cacert.pem')
    if os.path.exists(_ca_bundle):
        os.environ.setdefault('SSL_CERT_FILE', _ca_bundle)
        os.environ.setdefault('REQUESTS_CA_BUNDLE', _ca_bundle)


# =============================================================================
# P1 Security Enhancement: HTTPS/WSS Required
# =============================================================================

def _get_bundled_version() -> str:
    """Read version from bundled config.json (set by build pipeline)."""
    try:
        if getattr(sys, 'frozen', False):
            base_dir = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        else:
            src_dir = os.path.dirname(os.path.abspath(__file__))
            base_dir = os.path.dirname(os.path.dirname(src_dir))
        config_path = os.path.join(base_dir, 'config.json')
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f).get('version', '0.0.0')
    except Exception:
        pass
    return '0.0.0'


def get_secure_config(cli_server_url: str = None) -> dict:
    """
    Return configuration with security settings applied

    Server URL source (single source of truth):
        - ~/.forensic-collector/config.json (saved by ServerSetupDialog)
        - If not found, ServerSetupDialog prompts user on first run
        - CLI --server argument overrides for headless mode only
    Version source:
        - Bundled config.json (set by CI/CD build pipeline)
    """
    from core.url_security import normalize_server_urls
    from gui.server_setup_dialog import load_user_config
    user_config = load_user_config() or {}

    dev_mode = os.environ.get('COLLECTOR_DEV_MODE', 'false').lower() == 'true'

    # Server URL: CLI arg > user config > empty (triggers wizard in GUI)
    server_url = cli_server_url or user_config.get('server_url', '')
    ws_url = None if cli_server_url else user_config.get('ws_url', '')

    # Remote endpoints must use HTTPS/WSS. Loopback HTTP is allowed for local testing.
    if server_url:
        server_url, ws_url = normalize_server_urls(server_url, ws_url)

    config = {
        'server_url': server_url,
        'ws_url': ws_url,
        'version': _get_bundled_version(),
        'app_name': 'Digital Forensics Collector',
        'dev_mode': dev_mode,
        'is_release': getattr(sys, 'frozen', False),
        'ui_language': user_config.get('ui_language'),
    }

    if not server_url:
        logging.getLogger(__name__).debug("No server configured - setup wizard will appear")

    return config


def _parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Digital Forensics Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # GUI mode (default)
  %(prog)s

  # Headless/CLI mode
  %(prog)s --headless --token SESSION_TOKEN --server https://server.example.com
  %(prog)s --headless --token TOKEN --server URL --artifacts prefetch,eventlog
  %(prog)s --headless --accept-consent --token TOKEN --server URL
        """
    )
    parser.add_argument(
        'launch_uri',
        nargs='?',
        help='Internal unjaena-collector:// connection URI',
    )
    parser.add_argument(
        '--headless', '--cli',
        action='store_true',
        dest='headless',
        help='Run in headless/CLI mode (no GUI)'
    )
    parser.add_argument(
        '--token',
        type=str,
        help='Session token for authentication (required in headless mode)'
    )
    parser.add_argument(
        '--server',
        type=str,
        help='Server URL (e.g., https://server.example.com)'
    )
    parser.add_argument(
        '--artifacts',
        type=str,
        help='Comma-separated list of artifact types to collect'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        help='Output directory for collected artifacts'
    )
    parser.add_argument(
        '--accept-consent',
        action='store_true',
        help='Accept the active collection consent template in headless mode'
    )
    parser.add_argument(
        '--consent-language',
        type=str,
        default=os.environ.get('COLLECTOR_CONSENT_LANGUAGE', 'en'),
        help='Consent template language for headless mode (default: en)'
    )
    parser.add_argument(
        '--device',
        type=str,
        help='Device path or ID for mobile collection'
    )
    return parser.parse_args()


def check_admin_privilege():
    """Check if running as administrator/root.

    Windows: prompts UAC elevation dialog, exits if declined.
    Linux/macOS: shows a warning but continues (some features may be limited).
    """
    from utils.privilege import is_admin, run_as_admin

    if is_admin():
        return

    from PyQt6.QtWidgets import QMessageBox

    if sys.platform == 'win32':
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Icon.Warning)
        msg_box.setWindowTitle("Administrator Privileges Required")
        msg_box.setText("This collection tool requires administrator privileges.")
        msg_box.setInformativeText(
            "Administrator privileges are required to accurately collect "
            "forensic artifacts.\n\n"
            "Would you like to restart with administrator privileges?"
        )
        msg_box.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        msg_box.setDefaultButton(QMessageBox.StandardButton.Yes)
        msg_box.button(QMessageBox.StandardButton.Yes).setText("Yes, restart")
        msg_box.button(QMessageBox.StandardButton.No).setText("No, exit")

        reply = msg_box.exec()

        if reply == QMessageBox.StandardButton.Yes:
            if run_as_admin():
                sys.exit(0)
            else:
                QMessageBox.critical(
                    None,
                    "Error",
                    "Cannot run with administrator privileges.\n"
                    "Right-click on the program and select "
                    "'Run as administrator'."
                )
        sys.exit(0)
    else:
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Icon.Information)
        msg_box.setWindowTitle("Running without root privileges")
        msg_box.setText(
            "Running without root privileges.\n\n"
            "Some collection features (e.g., raw disk access) "
            "may be unavailable.\n\n"
            "For full functionality, run with: sudo ./run.sh"
        )
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.exec()


def main_gui(config: dict):
    """Launch GUI mode."""
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import Qt
    from gui.app import CollectorWindow
    from gui.server_setup_dialog import ServerSetupDialog

    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName(config['app_name'])
    app.setApplicationVersion(config['version'])

    # No server URL configured: show setup wizard.
    if not config['server_url']:
        dialog = ServerSetupDialog()
        if dialog.exec() != ServerSetupDialog.DialogCode.Accepted:
            sys.exit(0)
        result = dialog.get_config()
        if result:
            from core.url_security import normalize_server_urls
            config['server_url'], config['ws_url'] = normalize_server_urls(
                result['server_url'],
                result['ws_url'],
            )

    try:
        from core.connection_client import register_windows_protocol_handler
        register_windows_protocol_handler()
    except Exception as protocol_error:
        logging.getLogger(__name__).warning("Protocol handler registration failed: %s", protocol_error)

    check_admin_privilege()

    window = CollectorWindow(config)
    window.show()

    sys.exit(app.exec())


def main_headless(args, config: dict):
    """Launch headless/CLI mode."""
    from cli import run_headless
    sys.exit(run_headless(args, config))


def main_ios_change_password_helper():
    """Internal helper process for iOS backup password changes.

    The GUI process uses this helper so pymobiledevice3 backup encryption
    setup cannot terminate the main collector process. Payload is read from
    stdin to avoid exposing passwords in command-line arguments.
    """
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service

    payload = json.load(sys.stdin)
    lockdown = create_using_usbmux(serial=payload["udid"])
    service = Mobilebackup2Service(lockdown=lockdown)
    service.change_password(
        backup_directory=payload["backup_dir"],
        old=payload.get("old", ""),
        new=payload.get("new", ""),
    )


def main():
    """Main entry point that dispatches to GUI or headless mode."""
    if "--ios-change-password-helper" in sys.argv:
        main_ios_change_password_helper()
        return

    args = _parse_args()

    if args.headless:
        if not args.token:
            sys.exit("Error: --token is required in headless mode")
        if not args.server:
            sys.exit("Error: --server is required in headless mode")
        config = get_secure_config(cli_server_url=args.server)
        main_headless(args, config)
    else:
        pairing_code = ""
        launch_server = None
        if args.launch_uri:
            from urllib.parse import parse_qs, urlparse

            parsed = urlparse(args.launch_uri)
            if parsed.scheme != "unjaena-collector" or parsed.netloc != "connect":
                sys.exit("Error: invalid collector connection URI")
            query = parse_qs(parsed.query)
            pairing_code = str((query.get("code") or [""])[0])
            launch_server = str((query.get("server") or [""])[0]) or None
            if not pairing_code:
                sys.exit("Error: collector connection URI has no pairing code")
        config = get_secure_config(cli_server_url=launch_server)
        if pairing_code:
            config["pairing_code"] = pairing_code
        main_gui(config)


if __name__ == '__main__':
    # Catch all unhandled exceptions and write to crash log
    # (console=False on Windows hides all stderr/stdout)
    try:
        main()
    except Exception as exc:
        import traceback
        from pathlib import Path
        crash_log = Path.home() / ".forensic-collector" / "crash.log"
        crash_log.parent.mkdir(parents=True, exist_ok=True)
        with open(crash_log, "w", encoding="utf-8") as f:
            f.write(f"Collector crash at startup\n\n")
            traceback.print_exc(file=f)
        # Also try to show a native message box (no PyQt6 dependency)
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                0,
                f"Collector failed to start.\nSee: {crash_log}",
                "unJaena Collector Error",
                0x10,  # MB_ICONERROR
            )
        except Exception:
            pass
        sys.exit(1)
