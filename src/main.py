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
import argparse

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# =============================================================================
# P1 Security Enhancement: HTTPS/WSS Required
# =============================================================================

def _get_config_paths() -> list:
    """
    Return configuration file search paths (in priority order)

    1. Same directory as executable (for PyInstaller builds)
    2. collector root directory (development environment)
    3. src directory
    """
    paths = []

    # Location of bundled data when built with PyInstaller --onefile
    if getattr(sys, 'frozen', False):
        meipass_dir = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        paths.append(os.path.join(meipass_dir, 'config.json'))
    else:
        # Development environment: prefer config.development.json
        src_dir = os.path.dirname(os.path.abspath(__file__))
        collector_dir = os.path.dirname(src_dir)
        paths.append(os.path.join(collector_dir, 'config.development.json'))

    # Fallback: config.json
    src_dir = os.path.dirname(os.path.abspath(__file__))
    collector_dir = os.path.dirname(src_dir)
    paths.append(os.path.join(collector_dir, 'config.json'))
    paths.append(os.path.join(src_dir, 'config.json'))

    return paths


def _load_config_file() -> dict | None:
    """
    Load configuration from config file

    Returns:
        Configuration dictionary or None (if file not found)
    """
    for config_path in _get_config_paths():
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    print(f"[Config] Loaded config file: {config_path}")
                    return config
            except (json.JSONDecodeError, IOError) as e:
                print(f"[Warning] Failed to load config file: {config_path} - {e}")
                continue
    return None


def _needs_server_setup(server_url: str) -> bool:
    """Check if the server URL is a placeholder or missing."""
    if not server_url:
        return True
    placeholders = ('YOUR_SERVER', 'your-server', 'example.com', '127.0.0.1:8000')
    return any(p in server_url for p in placeholders)


def get_secure_config(cli_server_url: str = None) -> dict:
    """
    Return configuration with security settings applied

    Priority:
        1. CLI argument (--server)
        2. Environment variables
        3. User home config (~/.forensic-collector/config.json)
        4. config.json file (included during build)
        5. Server setup wizard (GUI only)
    """
    # Step 1: Load defaults from config file
    file_config = _load_config_file() or {}

    # Step 2: Load user-level config (higher priority than file config)
    from gui.server_setup_dialog import load_user_config
    user_config = load_user_config() or {}

    # Merge: user config overrides file config
    merged_config = {**file_config, **user_config}

    # Step 3: Override with environment variables (highest priority after CLI)
    dev_mode_default = str(merged_config.get('dev_mode', 'false')).lower()
    allow_insecure_default = str(merged_config.get('allow_insecure', 'false')).lower()

    dev_mode = os.environ.get('COLLECTOR_DEV_MODE', dev_mode_default).lower() == 'true'
    allow_insecure = os.environ.get('COLLECTOR_ALLOW_INSECURE', allow_insecure_default).lower() == 'true'

    # URL settings: CLI > env > user config > file config > default
    server_url = cli_server_url or os.environ.get(
        'COLLECTOR_SERVER_URL',
        merged_config.get('server_url', 'https://127.0.0.1:8000')
    )
    ws_url = os.environ.get(
        'COLLECTOR_WS_URL',
        merged_config.get('ws_url', 'wss://127.0.0.1:8000')
    )

    # [Security] Enforce HTTPS/WSS and warnings
    local_patterns = ('127.0.0.1', 'localhost', '::1', '0.0.0.0')
    is_local_server = any(p in server_url for p in local_patterns)

    if allow_insecure:
        print("=" * 60)
        print("[SECURITY WARNING] allow_insecure=true is set!")
        print("[SECURITY WARNING] Data will be transmitted without encryption.")
        print("[SECURITY WARNING] Never use this in production environment!")
        print("=" * 60)
    elif not dev_mode:
        if server_url.startswith('http://'):
            if is_local_server:
                print("[Security] Local development server (HTTP) detected - allowed")
            else:
                print("[SECURITY ERROR] HTTP is not allowed in production environment.")
                print("[SECURITY ERROR] Use HTTPS URL or set COLLECTOR_DEV_MODE=true.")
                raise ValueError(f"Production requires HTTPS. Got: {server_url}")

        if ws_url.startswith('ws://'):
            if is_local_server:
                print("[Security] Local development server (WS) detected - allowed")
            else:
                print("[SECURITY ERROR] WS is not allowed in production environment.")
                print("[SECURITY ERROR] Use WSS URL or set COLLECTOR_DEV_MODE=true.")
                raise ValueError(f"Production requires WSS. Got: {ws_url}")

    config = {
        'server_url': server_url,
        'ws_url': ws_url,
        'version': merged_config.get('version', '2.1.1'),
        'app_name': merged_config.get('app_name', 'Digital Forensics Collector'),
        'dev_mode': dev_mode,
        'allow_insecure': allow_insecure,
        'is_release': getattr(sys, 'frozen', False),
    }

    mode_str = "Development" if dev_mode else "Production"
    print(f"[Config] Mode: {mode_str}, Server: {server_url}")

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
        """
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
    from gui.server_setup_dialog import ServerSetupDialog, load_user_config

    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName(config['app_name'])
    app.setApplicationVersion(config['version'])

    # Check if server setup is needed
    if _needs_server_setup(config['server_url']):
        dialog = ServerSetupDialog()
        if dialog.exec() != ServerSetupDialog.DialogCode.Accepted:
            sys.exit(0)
        result = dialog.get_config()
        if result:
            config['server_url'] = result['server_url']
            config['ws_url'] = result['ws_url']

    check_admin_privilege()

    window = CollectorWindow(config)
    window.show()

    sys.exit(app.exec())


def main_headless(args, config: dict):
    """Launch headless/CLI mode."""
    from cli import run_headless
    sys.exit(run_headless(args, config))


def main():
    """Main entry point — dispatches to GUI or headless mode."""
    args = _parse_args()

    if args.headless:
        if not args.token:
            print("[ERROR] --token is required in headless mode")
            sys.exit(1)
        config = get_secure_config(cli_server_url=args.server)
        main_headless(args, config)
    else:
        config = get_secure_config()
        main_gui(config)


if __name__ == '__main__':
    main()
