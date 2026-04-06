"""
Server Setup Dialog

First-run dialog for configuring the forensics server URL.
Saves to ~/.forensic-collector/config.json so a single binary
works for any organization.
"""
import json
import os
import logging
from pathlib import Path
from typing import Optional

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QGroupBox, QFormLayout,
)
from PyQt6.QtCore import Qt

logger = logging.getLogger(__name__)

# User-level config directory
USER_CONFIG_DIR = Path.home() / ".forensic-collector"
USER_CONFIG_FILE = USER_CONFIG_DIR / "config.json"


def load_user_config() -> Optional[dict]:
    """Load user-level configuration if it exists."""
    if USER_CONFIG_FILE.exists():
        try:
            with open(USER_CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
            if config.get("server_url") and config["server_url"] != "YOUR_SERVER":
                return config
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"[ServerSetup] Failed to load user config: {e}")
    return None


def save_user_config(server_url: str, ws_url: str) -> bool:
    """Save server configuration to user home directory."""
    try:
        USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        config = {
            "server_url": server_url,
            "ws_url": ws_url,
        }
        with open(USER_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        logger.info(f"[ServerSetup] Config saved to {USER_CONFIG_FILE}")
        return True
    except IOError as e:
        logger.error(f"[ServerSetup] Failed to save config: {e}")
        return False


class ServerSetupDialog(QDialog):
    """Dialog for first-run server URL configuration."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Server Setup")
        self.setMinimumWidth(480)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        self._server_url: Optional[str] = None
        self._ws_url: Optional[str] = None

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # Header
        header = QLabel("Forensics Server Configuration")
        header.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 8px;")
        layout.addWidget(header)

        desc = QLabel(
            "Enter the URL of your forensics server.\n"
            "This is a one-time setup. You can change it later in:\n"
            f"  {USER_CONFIG_FILE}"
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #888; margin-bottom: 12px;")
        layout.addWidget(desc)

        # Server URL input
        group = QGroupBox("Server Connection")
        form = QFormLayout(group)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://app.unjaena.com")
        self.url_input.setText("https://app.unjaena.com")
        self.url_input.textChanged.connect(self._on_url_changed)
        form.addRow("Server URL:", self.url_input)

        self.ws_label = QLabel("")
        self.ws_label.setStyleSheet("color: #888; font-size: 12px;")
        form.addRow("WebSocket:", self.ws_label)

        layout.addWidget(group)

        # Status
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        # Buttons
        btn_layout = QHBoxLayout()

        self.test_btn = QPushButton("Test Connection")
        self.test_btn.clicked.connect(self._test_connection)
        self.test_btn.setEnabled(False)
        btn_layout.addWidget(self.test_btn)

        btn_layout.addStretch()

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self.cancel_btn)

        self.save_btn = QPushButton("Save && Continue")
        self.save_btn.clicked.connect(self._save_and_accept)
        self.save_btn.setEnabled(False)
        self.save_btn.setDefault(True)
        btn_layout.addWidget(self.save_btn)

        layout.addLayout(btn_layout)

    def _on_url_changed(self, text: str):
        url = text.strip().rstrip("/")
        has_url = bool(url) and (url.startswith("http://") or url.startswith("https://"))
        self.test_btn.setEnabled(has_url)
        self.save_btn.setEnabled(False)
        self.status_label.setText("")

        if has_url:
            if url.startswith("https://"):
                ws = url.replace("https://", "wss://", 1)
            else:
                ws = url.replace("http://", "ws://", 1)
            self.ws_label.setText(ws)
        else:
            self.ws_label.setText("")

    def _test_connection(self):
        import requests

        url = self.url_input.text().strip().rstrip("/")
        self.status_label.setText("Testing connection...")
        self.status_label.setStyleSheet("color: #888;")
        self.test_btn.setEnabled(False)

        # Force UI repaint
        from PyQt6.QtWidgets import QApplication
        QApplication.processEvents()

        try:
            from core.token_validator import _get_ssl_verify
            resp = requests.get(f"{url}/health", timeout=10, verify=_get_ssl_verify())
            if resp.status_code == 200:
                self.status_label.setText("Connection successful!")
                self.status_label.setStyleSheet("color: #4cc9f0;")
                self.save_btn.setEnabled(True)
                self._server_url = url
                if url.startswith("https://"):
                    self._ws_url = url.replace("https://", "wss://", 1)
                else:
                    self._ws_url = url.replace("http://", "ws://", 1)
            else:
                self.status_label.setText(f"Server returned HTTP {resp.status_code}")
                self.status_label.setStyleSheet("color: #ff6b6b;")
        except requests.exceptions.SSLError:
            self.status_label.setText("SSL certificate error. Check your server's TLS configuration.")
            self.status_label.setStyleSheet("color: #ff6b6b;")
        except requests.exceptions.ConnectionError:
            self.status_label.setText("Cannot connect. Check the URL and ensure the server is running.")
            self.status_label.setStyleSheet("color: #ff6b6b;")
        except requests.exceptions.Timeout:
            self.status_label.setText("Connection timed out.")
            self.status_label.setStyleSheet("color: #ff6b6b;")
        except Exception as e:
            self.status_label.setText(f"Error: {e}")
            self.status_label.setStyleSheet("color: #ff6b6b;")
        finally:
            self.test_btn.setEnabled(True)

    def _save_and_accept(self):
        if not self._server_url:
            return

        if save_user_config(self._server_url, self._ws_url):
            self.accept()
        else:
            QMessageBox.warning(
                self, "Error",
                f"Failed to save configuration to:\n{USER_CONFIG_FILE}\n\n"
                "Check file permissions and try again."
            )

    def get_config(self) -> Optional[dict]:
        """Return the configured URLs, or None if dialog was cancelled."""
        if self._server_url:
            return {
                "server_url": self._server_url,
                "ws_url": self._ws_url,
            }
        return None
