#!/usr/bin/env python3
"""
Digital Forensics Collector - Main Entry Point

This tool collects forensic artifacts from Windows systems
and uploads them to the forensics server for analysis.
"""
import sys
import os
import json

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt

from gui.app import CollectorWindow
from utils.privilege import is_admin, run_as_admin


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

    # Location of executable when built with PyInstaller
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
        paths.append(os.path.join(exe_dir, 'config.json'))
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


def get_secure_config() -> dict:
    """
    Return configuration with security settings applied

    Priority:
        1. Environment variables (highest priority)
        2. config.json file (included during build)
        3. Default values (development fallback)

    Environment variables:
        COLLECTOR_SERVER_URL: Server URL
        COLLECTOR_WS_URL: WebSocket URL
        COLLECTOR_DEV_MODE: Development mode (true/false)
        COLLECTOR_ALLOW_INSECURE: Allow insecure connections (true/false)

    For deployment builds:
        Include production server URL in config.json during build
        -> Users can run without additional configuration for auto-connection

    For development environment:
        Set COLLECTOR_DEV_MODE=true via environment variable
    """
    # Step 1: Load default values from config file
    file_config = _load_config_file() or {}

    # Step 2: Override with environment variables (environment variables have higher priority)
    # Falls back to file settings -> default values if environment variable is not set
    dev_mode_default = str(file_config.get('dev_mode', 'false')).lower()
    allow_insecure_default = str(file_config.get('allow_insecure', 'false')).lower()

    dev_mode = os.environ.get('COLLECTOR_DEV_MODE', dev_mode_default).lower() == 'true'
    allow_insecure = os.environ.get('COLLECTOR_ALLOW_INSECURE', allow_insecure_default).lower() == 'true'

    # URL settings: environment variable -> file -> default
    # NOTE: On Windows, 'localhost' may resolve to IPv6 (::1) causing Docker connection failures
    server_url = os.environ.get(
        'COLLECTOR_SERVER_URL',
        file_config.get('server_url', 'https://127.0.0.1:8000')
    )
    ws_url = os.environ.get(
        'COLLECTOR_WS_URL',
        file_config.get('ws_url', 'wss://127.0.0.1:8000')
    )

    # [Security] Enforce HTTPS/WSS and warnings
    # Local address patterns (allowed for development environment)
    local_patterns = ('127.0.0.1', 'localhost', '::1', '0.0.0.0')
    is_local_server = any(p in server_url for p in local_patterns)

    if allow_insecure:
        print("=" * 60)
        print("[SECURITY WARNING] allow_insecure=true is set!")
        print("[SECURITY WARNING] Data will be transmitted without encryption.")
        print("[SECURITY WARNING] Never use this in production environment!")
        print("=" * 60)
    elif not dev_mode:
        # Enforce HTTPS/WSS in production mode (except local addresses)
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
        'version': file_config.get('version', '2.0.0'),
        'app_name': file_config.get('app_name', 'Digital Forensics Collector'),
        'dev_mode': dev_mode,
        'allow_insecure': allow_insecure,
        'is_release': getattr(sys, 'frozen', False),
    }

    # Print configuration summary
    mode_str = "Development" if dev_mode else "Production"
    print(f"[Config] Mode: {mode_str}, Server: {server_url}")

    return config


# Configuration (P1: Apply security settings)
CONFIG = get_secure_config()


def check_admin_privilege():
    """Check if running as administrator"""
    if not is_admin():
        # Show warning message
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
                # Elevation requested successfully, exit current process
                sys.exit(0)
            else:
                # Failed to request elevation
                QMessageBox.critical(
                    None,
                    "Error",
                    "Cannot run with administrator privileges.\n"
                    "Right-click on the program and select "
                    "'Run as administrator'."
                )
        sys.exit(0)


def main():
    """Main entry point"""
    # High DPI support
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName(CONFIG['app_name'])
    app.setApplicationVersion(CONFIG['version'])

    # Check admin privilege
    check_admin_privilege()

    # Create and show main window
    window = CollectorWindow(CONFIG)
    window.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
