"""
Legal Consent Dialog

Dialog for obtaining legal consent before starting collection.
Collection cannot proceed without consent.

Server API Integration:
- GET /api/v1/collector/consent - Retrieve multilingual consent template
- POST /api/v1/collector/consent/accept - Save consent record
"""
from datetime import datetime, timezone
from typing import Optional, List
import socket
import hashlib
import requests
import logging

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QCheckBox,
    QPushButton, QFrame, QScrollArea, QWidget,
    QComboBox, QMessageBox, QSizePolicy, QLayout
)
from PyQt6.QtCore import Qt, QSize, QTimer

from gui.styles import COLORS

logger = logging.getLogger(__name__)


class ConsentDialog(QDialog):
    """Legal consent dialog (with server API integration)"""

    # Supported languages list
    LANGUAGES = {
        "en": "English",
        "ko": "Korean",
        "ja": "Japanese",
        "zh": "Chinese"
    }

    def __init__(
        self,
        parent=None,
        server_url: str = None,
        session_id: str = None,
        case_id: str = None,
        language: str = "en",
        server_signing_key: str = None,
    ):
        """
        Args:
            parent: Parent widget
            server_url: API server URL (e.g., http://localhost:8000)
            session_id: Collection session ID
            case_id: Case ID
            language: Default language code (en, ko, ja, zh)
            server_signing_key: Server-provided consent signing key (from /authenticate)
        """
        super().__init__(parent)
        self.server_url = server_url
        self.session_id = session_id
        self.case_id = case_id
        self.language = language
        self.consent_given = False
        self.consent_record = None

        # Server-provided signing key for consent HMAC (preferred over env var)
        self._server_signing_key = server_signing_key

        # Template information received from server
        self.template_id = None
        self.template_version = None
        self.template_content = None
        self.required_checkboxes: List[str] = []
        self.checkboxes: List[QCheckBox] = []
        self.operator_authorization = self._default_operator_authorization()

        # Operator role + legal basis captured via the dialog widgets;
        # consumed by _create_consent_record. Default values are the
        # most restrictive so an unfilled dialog cannot accidentally
        # claim a higher authorization than the user declared.
        self.operator_role: str = "device_owner"
        self.operator_legal_basis: str = "data_subject_consent"
        self.international_transfer_ack: bool = False
        # UI handles (populated by _build_operator_section)
        self.role_combo: Optional["QComboBox"] = None
        self.basis_combo: Optional["QComboBox"] = None
        self.transfer_checkbox: Optional["QCheckBox"] = None

        self.setup_ui()

    def setup_ui(self):
        """Initialize UI with a single scroll body and fixed footer."""
        self.setWindowTitle("Digital Forensic Collection Consent")
        self.setMinimumSize(QSize(760, 620))
        self.resize(QSize(800, 680))
        self.setModal(True)
        self.setSizeGripEnabled(True)
        self.setStyleSheet(self._get_stylesheet())

        layout = QVBoxLayout(self)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        self.header_frame = QFrame()
        self.header_frame.setObjectName("consentHeaderFrame")
        header_layout = QHBoxLayout(self.header_frame)
        header_layout.setContentsMargins(20, 16, 20, 14)
        header_layout.setSpacing(12)

        title_box = QVBoxLayout()
        title_box.setContentsMargins(0, 0, 0, 0)
        title_box.setSpacing(4)
        self.header_label = QLabel("Digital Forensic Collection Consent")
        self.header_label.setObjectName("header")
        self.header_label.setWordWrap(True)
        self.header_subtitle = QLabel("Review and confirm the collection scope before starting.")
        self.header_subtitle.setObjectName("headerSubtitle")
        self.header_subtitle.setWordWrap(True)
        title_box.addWidget(self.header_label)
        title_box.addWidget(self.header_subtitle)
        header_layout.addLayout(title_box, 1)

        lang_label = QLabel("Language")
        lang_label.setObjectName("fieldLabel")
        header_layout.addWidget(lang_label, 0, Qt.AlignmentFlag.AlignVCenter)

        self.lang_combo = QComboBox()
        self.lang_combo.setMinimumWidth(120)
        self.lang_combo.setFixedHeight(32)
        for code, name in self.LANGUAGES.items():
            self.lang_combo.addItem(name, code)
        idx = self.lang_combo.findData(self.language)
        if idx >= 0:
            self.lang_combo.setCurrentIndex(idx)
        self.lang_combo.currentIndexChanged.connect(self._on_language_changed)
        header_layout.addWidget(self.lang_combo, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.header_frame, 0)

        self.body_scroll = QScrollArea()
        self.body_scroll.setObjectName("bodyScroll")
        self.body_scroll.setWidgetResizable(True)
        self.body_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.body_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.body_widget = QWidget()
        self.body_widget.setObjectName("bodyWidget")
        self.body_layout = QVBoxLayout(self.body_widget)
        self.body_layout.setContentsMargins(20, 16, 20, 16)
        self.body_layout.setSpacing(12)
        self.body_layout.setSizeConstraint(QLayout.SizeConstraint.SetMinAndMaxSize)
        self.body_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.body_scroll.setWidget(self.body_widget)
        layout.addWidget(self.body_scroll, 1)

        self.warning_frame = QFrame()
        self.warning_frame.setObjectName("warningFrame")
        self.warning_frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        warning_layout = QVBoxLayout(self.warning_frame)
        warning_layout.setContentsMargins(12, 10, 12, 10)
        warning_layout.setSpacing(0)
        self.warning_label = QLabel(
            "This tool collects and uploads selected forensic data. "
            "Confirm that you have authority before proceeding."
        )
        self.warning_label.setObjectName("warningText")
        self.warning_label.setWordWrap(True)
        warning_layout.addWidget(self.warning_label)
        self.body_layout.addWidget(self.warning_frame)

        self._build_operator_section(self.body_layout)

        self.checkbox_frame = QFrame()
        self.checkbox_frame.setObjectName("checkboxFrame")
        self.checkbox_frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        self.checkbox_layout = QVBoxLayout(self.checkbox_frame)
        self.checkbox_layout.setContentsMargins(12, 12, 12, 12)
        self.checkbox_layout.setSpacing(8)
        self.body_layout.addWidget(self.checkbox_frame)

        self.document_frame = QFrame()
        self.document_frame.setObjectName("documentFrame")
        self.document_frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        document_layout = QVBoxLayout(self.document_frame)
        document_layout.setContentsMargins(14, 12, 14, 12)
        document_layout.setSpacing(8)
        self.document_title = QLabel("Consent details")
        self.document_title.setObjectName("sectionTitle")
        document_layout.addWidget(self.document_title)
        self.consent_text = QLabel()
        self.consent_text.setObjectName("consentDocument")
        self.consent_text.setTextFormat(Qt.TextFormat.RichText)
        self.consent_text.setWordWrap(True)
        self.consent_text.setOpenExternalLinks(False)
        self.consent_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.consent_text.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        document_layout.addWidget(self.consent_text)
        self.body_layout.addWidget(self.document_frame)

        self.footer_frame = QFrame()
        self.footer_frame.setObjectName("footerFrame")
        self.footer_frame.setFixedHeight(64)
        button_layout = QHBoxLayout(self.footer_frame)
        button_layout.setContentsMargins(20, 12, 20, 12)
        button_layout.setSpacing(10)
        button_layout.addStretch(1)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        self.cancel_btn.setFixedSize(120, 40)
        button_layout.addWidget(self.cancel_btn)

        self.agree_btn = QPushButton("Agree and Start")
        self.agree_btn.setObjectName("agreeButton")
        self.agree_btn.setEnabled(False)
        self.agree_btn.clicked.connect(self._on_agree)
        self.agree_btn.setFixedSize(220, 40)
        button_layout.addWidget(self.agree_btn)
        layout.addWidget(self.footer_frame, 0)

        # Backward-compatible alias used by older smoke checks.
        self.checkbox_scroll = self.body_scroll

        self._load_consent_template()

    def _target_screen(self):
        from PyQt6.QtGui import QCursor, QGuiApplication

        parent = self.parentWidget()
        if parent is not None:
            handle = parent.windowHandle()
            if handle is not None and handle.screen() is not None:
                return handle.screen()

        screen = QGuiApplication.screenAt(QCursor.pos())
        if screen is not None:
            return screen

        return self.screen() or QGuiApplication.primaryScreen()

    def _center_on_screen(self) -> None:
        screen = self._target_screen()
        if screen is None:
            return
        self.adjustSize()
        frame = self.frameGeometry()
        frame.moveCenter(screen.availableGeometry().center())
        self.move(frame.topLeft())

    def showEvent(self, event):
        super().showEvent(event)
        self._center_on_screen()
        # Re-center after Qt/native window manager finalizes frame geometry.
        QTimer.singleShot(0, self._center_on_screen)
        QTimer.singleShot(100, self._center_on_screen)

    def _on_language_changed(self, index: int):
        """Reload consent when language changes"""
        self.language = self.lang_combo.currentData()
        self._load_consent_template()
        # Keep the operator-section labels in sync with the active language.
        self._relocalize_operator_section()

    def _load_consent_template(self):
        """Load consent template from server"""
        # The target template path resets checkbox rows atomically.

        if self.server_url:
            try:
                template = self._fetch_consent_from_server()
                if template:
                    self._apply_template(template)
                    return
            except Exception as e:
                logger.warning(f"Failed to fetch consent from server: {e}")

        # Use default fallback when server connection fails
        self._apply_fallback_template()

    def _fetch_consent_from_server(self) -> Optional[dict]:
        """Fetch consent template from server"""
        try:
            from core.token_validator import _get_ssl_verify
            url = f"{self.server_url}/api/v1/collector/consent"
            params = {"language": self.language, "category": "collection"}

            response = requests.get(url, params=params, timeout=10, verify=_get_ssl_verify())
            response.raise_for_status()

            data = response.json()
            logger.info(f"Loaded consent template: lang={data['language']}, version={data['version']}")
            return data

        except requests.RequestException as e:
            logger.error(f"Failed to fetch consent template: {e}")
            return None

    def _reset_checkbox_layout(self) -> None:
        while self.checkbox_layout.count() > 0:
            item = self.checkbox_layout.takeAt(0)
            if item is None:
                break
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
        self.checkboxes.clear()
        title = QLabel("Required confirmations")
        title.setObjectName("sectionTitle")
        self.checkbox_layout.addWidget(title)

    def _apply_template(self, template: dict):
        """Apply server template"""
        self.template_id = template.get("id")
        self.template_version = template.get("version")
        self.template_content = template.get("content", "")
        self.required_checkboxes = template.get("required_checkboxes", [])
        self.operator_authorization = self._normalize_operator_authorization(
            template.get("operator_authorization")
        )
        self._relocalize_operator_section()

        # Update header
        template_title = template.get("title", "Digital Forensic Collection Consent")
        self.header_label.setText("Digital Forensic Collection Consent")
        if hasattr(self, "header_subtitle"):
            self.header_subtitle.setText(template_title)
        self.setWindowTitle(template_title)

        # Display consent content (Markdown to HTML)
        content = template.get("content", "")
        html_content = self._markdown_to_html(content)
        self.consent_text.setText(html_content)

        self._reset_checkbox_layout()
        for item_text in self.required_checkboxes:
            self._add_consent_item(item_text)

        self.cancel_btn.setText("Cancel")
        self.agree_btn.setText("Agree and Start")
        self.warning_label.setText(
            "Warning: This tool collects analysis data from your system.\n"
            "Please read and agree to the terms below before proceeding."
        )

        self._update_button_state()

    def _apply_fallback_template(self):
        """Minimal fallback when server is unreachable."""
        self.template_id = None
        self.template_version = None
        self.template_content = None

        self.operator_authorization = self._default_operator_authorization()
        self._relocalize_operator_section()

        msg = "Consent information could not be loaded. Internet connection is required."

        self.header_label.setText("Digital Forensic Collection Consent")
        if hasattr(self, "header_subtitle"):
            self.header_subtitle.setText("Consent template unavailable")
        self.setWindowTitle("Digital Forensic Collection Consent")
        self.consent_text.setText(
            f'<div style="text-align:center;padding:40px;color:#ff6b6b;font-size:14px;">{msg}</div>'
        )
        self._reset_checkbox_layout()

        # Disable agree button -- user must connect to server
        self.agree_btn.setEnabled(False)
        self.agree_btn.setText("Agree and Start")
        self.cancel_btn.setText("Cancel")

    @staticmethod
    def _sanitize_html_tags(text: str) -> str:
        """Strip dangerous HTML tags from server-returned content.
        Allows only safe formatting tags; removes script, iframe, img, object, etc."""
        import re
        SAFE_TAGS = {'b', 'i', 'u', 'em', 'strong', 'br', 'p', 'ul', 'ol', 'li',
                     'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'table', 'tr', 'td', 'th',
                     'thead', 'tbody', 'span', 'div', 'blockquote', 'code', 'pre', 'a', 'sub', 'sup'}
        def replace_tag(match):
            tag_content = match.group(1).strip()
            tag_name = tag_content.split()[0].strip('/').lower()
            if tag_name in SAFE_TAGS:
                return match.group(0)
            return ''  # Remove unsafe tags
        return re.sub(r'<([^>]+)>', replace_tag, text)

    def _markdown_to_html(self, markdown_text: str) -> str:
        """Markdown to HTML conversion (supports tables, horizontal rules)"""
        import re

        # Sanitize raw HTML tags from server content before conversion
        markdown_text = self._sanitize_html_tags(markdown_text)

        # Remove carriage returns
        html = markdown_text.replace('\r\n', '\n').replace('\r', '\n')

        # Table conversion
        def convert_table(match):
            lines = match.group(0).strip().split('\n')
            if len(lines) < 2:
                return match.group(0)

            table_html = f'<table style="width:100%; border-collapse:collapse; margin:8px 0; font-size:12px;">'

            for i, line in enumerate(lines):
                if '---' in line:  # Skip separator line
                    continue
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if not cells:
                    continue

                tag = 'th' if i == 0 else 'td'
                bg = f'background:{COLORS["bg_secondary"]};' if i == 0 else ''
                row = ''.join([
                    f'<{tag} style="border:1px solid {COLORS["border_subtle"]}; padding:6px; {bg}">{c}</{tag}>'
                    for c in cells
                ])
                table_html += f'<tr>{row}</tr>'

            table_html += '</table>'
            return table_html

        html = re.sub(r'(\|.+\|\n)+', convert_table, html)

        # Horizontal rule (---)
        html = re.sub(r'^---+$', f'<hr style="border:none; border-top:1px solid {COLORS["border_subtle"]}; margin:12px 0;">', html, flags=re.MULTILINE)

        # Header conversion. Server templates may use either generic
        # Markdown headings (### Purpose) or numbered headings (### 1. Scope).
        html = re.sub(
            r'^### (\d+)\. (.+)$',
            rf'<h4 style="color:{COLORS["brand_primary"]}; margin:12px 0 6px 0; font-size:13px; font-weight:600;">\1. \2</h4>',
            html, flags=re.MULTILINE
        )
        html = re.sub(
            r'^### (.+)$',
            rf'<h4 style="color:{COLORS["brand_primary"]}; margin:12px 0 6px 0; font-size:13px; font-weight:600;">\1</h4>',
            html, flags=re.MULTILINE
        )
        html = re.sub(
            r'^## (.+)$',
            rf'<h3 style="color:{COLORS["brand_primary"]}; margin:0 0 10px 0; padding-bottom:8px; border-bottom:2px solid {COLORS["brand_primary"]}; font-size:16px;">\1</h3>',
            html, flags=re.MULTILINE
        )

        html = re.sub(
            r'^\*\*(Version|Effective Date|Effective)\*\*: (.+)$',
            rf'<div style="margin-top:6px; padding:6px 8px; background:{COLORS["bg_secondary"]}; border-radius:4px; font-size:11px; color:{COLORS["text_secondary"]};"><b>\1</b>: \2</div>',
            html, flags=re.MULTILINE
        )

        # Bold text
        html = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', html)

        # List items
        html = re.sub(r'^- (.+)$', r'<li style="margin:2px 0; padding-left:4px;">\1</li>', html, flags=re.MULTILINE)

        # Wrap consecutive li elements in ul
        html = re.sub(r'((?:<li[^>]*>.*?</li>\n?)+)', r'<ul style="margin:4px 0 8px 16px; padding:0;">\1</ul>', html)

        # Handle empty lines (paragraph separation)
        html = re.sub(r'\n\n+', '</p><p style="margin:8px 0;">', html)
        html = re.sub(r'\n', ' ', html)  # Single line breaks become spaces

        # Version information style
        html = re.sub(
            r'\*\*Version\*\*: (v[\d.]+) \| \*\*Effective\*\*: ([\d-]+)',
            rf'<div style="margin-top:12px; padding:8px; background:{COLORS["bg_secondary"]}; border-radius:4px; font-size:11px; color:{COLORS["text_secondary"]};">Version: \1 | Effective: \2</div>',
            html
        )

        return f'''<div style="font-family: 'Malgun Gothic', 'Segoe UI', sans-serif; line-height:1.5; color:{COLORS["text_primary"]}; font-size:12px;"><p style="margin:0;">{html}</p></div>'''

    def _submit_consent_to_server(self) -> bool:
        """Submit consent record to server.

        Fail-closed semantics - returns False if server submission cannot be
        confirmed, blocking the operator from proceeding until the consent
        record is safely transmitted. This is required for GDPR/PIPA audit
        integrity: a scan without a verified consent record is not defensible.

        Exception: explicit offline mode (no server_url configured) is allowed
        because some operators run fully disconnected; in that case the local
        tamper-evident record in _create_consent_record() is the source of
        truth and must be manually submitted later.
        """
        if not self.server_url:
            logger.warning("No server URL configured - using offline mode. "
                           "Consent stored locally only; manual upload required.")
            # Local-only mode is an explicit operator choice; allow it.
            return True

        if not self.session_id:
            logger.error("session_id missing - cannot verify consent on server. "
                         "Blocking collection until a valid session is established.")
            return False

        try:
            url = f"{self.server_url}/api/v1/collector/consent/accept"

            # List of agreed items. The visible text lives in a paired
            # QLabel so the checkbox can wrap cleanly; keep the canonical
            # statement on the checkbox as a property for audit payloads.
            agreed_items = [
                cb.property("consent_text") or cb.text()
                for cb in self.checkboxes
                if cb.isChecked()
            ]

            # System information
            try:
                hostname = socket.gethostname()
            except Exception:
                hostname = "unknown"

            # Operator role + legal basis - required for downstream accountability
            # and to support Art. 17 erasure requests against the correct controller.
            payload = {
                "session_id": self.session_id,
                "case_id": self.case_id or "",
                "template_id": self.template_id or "",
                "consent_version": self.template_version or "offline-1.0",
                "consent_language": self.language,
                "agreed_items": agreed_items,
                "collector_name": None,
                "collector_organization": None,
                "target_system_info": {
                    "hostname": hostname,
                    "operator_role": getattr(self, "operator_role", "unspecified"),
                    "operator_legal_basis": getattr(self, "operator_legal_basis", "unspecified"),
                    "international_transfer_ack": bool(getattr(self, "international_transfer_ack", False)),
                },
                "signature_type": "checkbox",
                "signature_data": hashlib.sha256(
                    f"{self.session_id}:{self.template_id or ''}:{self.template_version or ''}".encode("utf-8")
                ).hexdigest(),
            }

            headers = {"Content-Type": "application/json", "User-Agent": "unJaena-Collector"}
            try:
                from utils.hardware_id import get_hardware_id
                headers["X-Hardware-ID"] = get_hardware_id()[:64]
            except Exception:
                pass

            from core.token_validator import _get_ssl_verify
            response = requests.post(url, json=payload, headers=headers, timeout=10, verify=_get_ssl_verify())
            response.raise_for_status()

            result = response.json()
            logger.info(f"Consent submitted: consent_id={result.get('consent_id')}")
            return True

        except requests.RequestException as e:
            # Fail-closed: do not allow the operator to proceed when server
            # submission definitively failed (network error, 4xx/5xx). The
            # local tamper-evident record remains, but collection is blocked.
            logger.error(f"Failed to submit consent to server: {e}. "
                         f"Collection will be blocked per fail-closed policy.")
            return False

    # Consent text methods removed -- consent content is fetched from server.
    # See _load_consent_template() and _fetch_consent_from_server().

    # ------------------------------------------------------------------
    # Operator role / legal basis / cross-border transfer ack UI
    # ------------------------------------------------------------------

    def _default_operator_authorization(self) -> dict:
        return {
            "version": "local-fallback",
            "required": True,
            "require_transfer_ack": True,
            "labels": {
                "section_title": "Operator Authorization",
                "role_label": "Your role in this collection:",
                "basis_label": "Legal basis for processing:",
                "transfer_label": (
                    "I acknowledge that the collected data may be transmitted to and processed by the "
                    "configured analysis service and its approved service providers. Standard Contractual "
                    "Clauses may apply."
                ),
            },
            "roles": [
                {"value": "device_owner", "label": "I am the owner of this device"},
                {"value": "authorized_agent", "label": "I am authorized in writing by the device owner"},
                {"value": "employer", "label": "Company-owned device under my supervision"},
                {"value": "court_order", "label": "I have a court order or warrant"},
                {"value": "law_enforcement", "label": "Law-enforcement officer under lawful authority"},
            ],
            "legal_bases": [
                {"value": "data_subject_consent", "label": "Explicit consent of the data subject"},
                {"value": "legitimate_interest", "label": "Legitimate interest with balancing test documented"},
                {"value": "legal_obligation", "label": "Legal obligation or regulatory requirement"},
                {"value": "public_task", "label": "Public task or official authority"},
                {"value": "vital_interest", "label": "Vital interest or life safety"},
            ],
        }

    @staticmethod
    def _normalize_authorization_options(value, fallback):
        if not isinstance(value, list):
            return list(fallback)
        normalized = []
        for item in value:
            if not isinstance(item, dict):
                continue
            option_value = str(item.get("value") or "").strip()
            option_label = str(item.get("label") or option_value).strip()
            if option_value and option_label:
                normalized.append({"value": option_value, "label": option_label})
        return normalized or list(fallback)

    def _normalize_operator_authorization(self, value) -> dict:
        fallback = self._default_operator_authorization()
        if not isinstance(value, dict):
            return fallback

        labels = fallback["labels"].copy()
        server_labels = value.get("labels")
        if isinstance(server_labels, dict):
            for key in labels:
                label = str(server_labels.get(key) or "").strip()
                if label:
                    labels[key] = label

        roles = self._normalize_authorization_options(value.get("roles"), fallback["roles"])
        legal_bases = self._normalize_authorization_options(value.get("legal_bases"), fallback["legal_bases"])

        return {
            "version": str(value.get("version") or fallback["version"]),
            "required": value.get("required", fallback["required"]) is not False,
            "require_transfer_ack": value.get("require_transfer_ack", fallback["require_transfer_ack"]) is not False,
            "labels": labels,
            "roles": roles,
            "legal_bases": legal_bases,
        }

    def _set_combo_options(self, combo: QComboBox, options: list, current_value: str) -> str:
        combo.blockSignals(True)
        combo.clear()
        for item in options:
            combo.addItem(item["label"], item["value"])
        idx = combo.findData(current_value)
        if idx < 0:
            idx = 0 if combo.count() else -1
        if idx >= 0:
            combo.setCurrentIndex(idx)
        selected = combo.currentData() or ""
        combo.blockSignals(False)
        return selected

    def _build_operator_section(self, parent_layout) -> None:
        """Render the server-provided operator-authorization section."""
        frame = QFrame()
        frame.setObjectName("operatorFrame")
        vbox = QVBoxLayout(frame)
        vbox.setContentsMargins(12, 12, 12, 12)
        vbox.setSpacing(10)

        auth = getattr(self, "operator_authorization", None) or self._default_operator_authorization()
        labels = auth["labels"]

        self._operator_section_title = QLabel(labels["section_title"])
        self._operator_section_title.setObjectName("sectionTitle")
        vbox.addWidget(self._operator_section_title)

        self._role_label_widget = QLabel(labels["role_label"])
        self._role_label_widget.setObjectName("fieldLabel")
        self.role_combo = QComboBox()
        self.role_combo.setFixedHeight(32)
        self.operator_role = self._set_combo_options(self.role_combo, auth["roles"], self.operator_role)
        self.role_combo.currentIndexChanged.connect(self._on_role_changed)
        vbox.addLayout(self._form_row(self._role_label_widget, self.role_combo))

        self._basis_label_widget = QLabel(labels["basis_label"])
        self._basis_label_widget.setObjectName("fieldLabel")
        self.basis_combo = QComboBox()
        self.basis_combo.setFixedHeight(32)
        self.operator_legal_basis = self._set_combo_options(
            self.basis_combo,
            auth["legal_bases"],
            self.operator_legal_basis,
        )
        self.basis_combo.currentIndexChanged.connect(self._on_basis_changed)
        vbox.addLayout(self._form_row(self._basis_label_widget, self.basis_combo))

        transfer_row, self.transfer_checkbox, self._transfer_label_widget = self._make_check_row(labels["transfer_label"])
        self.transfer_checkbox.stateChanged.connect(self._on_transfer_changed)
        vbox.addWidget(transfer_row)

        parent_layout.addWidget(frame)

    def _form_row(self, label: QLabel, field: QWidget) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)
        label.setMinimumWidth(190)
        label.setWordWrap(True)
        row.addWidget(label, 0)
        row.addWidget(field, 1)
        return row

    def _make_check_row(self, text: str):
        row = QFrame()
        row.setObjectName("consentRow")
        row.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(10, 8, 10, 8)
        row_layout.setSpacing(10)

        cb = QCheckBox()
        cb.setObjectName("visibleConsentCheck")
        cb.setFixedSize(22, 22)
        cb.setCursor(Qt.CursorShape.PointingHandCursor)
        cb.setToolTip(text)

        label = QLabel(text)
        label.setObjectName("consentLabel")
        label.setWordWrap(True)
        label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.LinksAccessibleByMouse
        )
        label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        label.setMinimumWidth(1)
        label.setCursor(Qt.CursorShape.PointingHandCursor)
        label.mousePressEvent = lambda _e, _cb=cb: _cb.toggle()

        row_layout.addWidget(cb, 0, Qt.AlignmentFlag.AlignTop)
        row_layout.addWidget(label, 1)
        return row, cb, label

    def _on_role_changed(self, idx: int) -> None:
        if self.role_combo is not None:
            self.operator_role = self.role_combo.currentData() or "device_owner"
            self._update_button_state()

    def _on_basis_changed(self, idx: int) -> None:
        if self.basis_combo is not None:
            self.operator_legal_basis = self.basis_combo.currentData() or "data_subject_consent"
            self._update_button_state()

    def _on_transfer_changed(self, state: int) -> None:
        # Qt.CheckState enum value 2 == Checked; use truthy cast for safety.
        self.international_transfer_ack = bool(state)
        self._update_button_state()

    def _relocalize_operator_section(self) -> None:
        """Refresh operator authorization from the latest server template."""
        if not (self.role_combo and self.basis_combo and self.transfer_checkbox):
            return
        auth = getattr(self, "operator_authorization", None) or self._default_operator_authorization()
        labels = auth["labels"]
        try:
            self._operator_section_title.setText(labels["section_title"])
            self._role_label_widget.setText(labels["role_label"])
            self._basis_label_widget.setText(labels["basis_label"])
            transfer_text = labels["transfer_label"]
            self.transfer_checkbox.setToolTip(transfer_text)
            if hasattr(self, "_transfer_label_widget"):
                self._transfer_label_widget.setText(transfer_text)

            current_role = self.role_combo.currentData() or self.operator_role
            self.operator_role = self._set_combo_options(self.role_combo, auth["roles"], current_role)
            current_basis = self.basis_combo.currentData() or self.operator_legal_basis
            self.operator_legal_basis = self._set_combo_options(self.basis_combo, auth["legal_bases"], current_basis)
            self._update_button_state()
        except Exception as e:
            logger.debug(f"operator section refresh failed: {e}")

    def _add_consent_item(self, text: str) -> None:
        """Add a consent checkbox row."""
        row, cb, _label = self._make_check_row(text)
        cb.setProperty("consent_text", text)
        cb.stateChanged.connect(self._update_button_state)
        self.checkbox_layout.addWidget(row)
        self.checkboxes.append(cb)

    def _update_button_state(self):
        """Enable button based on checkbox state + operator-section
        completion. All artifact checkboxes must be checked AND the
        cross-border transfer acknowledgment must be explicit."""
        all_checked = all(cb.isChecked() for cb in self.checkboxes) if self.checkboxes else False
        auth = getattr(self, "operator_authorization", None) or self._default_operator_authorization()
        require_transfer_ack = auth.get("require_transfer_ack", True) is not False
        operator_ready = (not require_transfer_ack) or bool(self.international_transfer_ack)
        self.agree_btn.setEnabled(all_checked and operator_ready)

    def _on_agree(self):
        """Agree button clicked.

        Fail-closed: if the consent record cannot be persisted on the server,
        the dialog refuses to accept. This protects the operator from
        proceeding with a collection that has no verifiable audit trail and
        aligns with GDPR Art. 7(1) "demonstrable consent" requirement.
        (Previous implementation swallowed the submission return value and
        accepted regardless; regression re-introduced during a refactor.)
        """
        submitted = self._submit_consent_to_server()
        if not submitted:
            title = "Consent submission failed"
            body = (
                "Could not record your consent on the analysis server. "
                "Please check your network connection and try again. "
                "If the problem persists, contact your administrator."
            )
            try:
                from PyQt6.QtWidgets import QMessageBox
                QMessageBox.critical(self, title, body)
            except Exception:
                # GUI not available (e.g. headless mode) - log only
                logger.error("Consent submission failed; refusing to proceed")
            return

        try:
            self.consent_record = self._create_consent_record()
        except RuntimeError as rec_err:
            # Signing-key unavailable - fail closed with user-facing error.
            logger.error(f"Consent record generation failed: {rec_err}")
            key_title = "Consent signing unavailable"
            key_body = (
                "A secure signing key is required to record consent. "
                "The server did not provide one. Please retry; if the problem "
                "continues, contact your administrator."
            )
            try:
                from PyQt6.QtWidgets import QMessageBox
                QMessageBox.critical(self, key_title, key_body)
            except Exception:
                pass
            return

        self.consent_given = True
        self.accept()

    def _create_consent_record(self) -> dict:
        """Create consent record (server API integration version)"""
        import hmac
        import os

        timestamp = datetime.now(timezone.utc).isoformat()

        # System information
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            hostname = "unknown"
            ip_address = "unknown"

        # [Security] Privacy protection: Hash IP address and hostname
        hostname_hash = hashlib.sha256(hostname.encode()).hexdigest()[:16]
        ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()[:16]

        # List of agreed items (from dynamic checkboxes)
        agreed_items = [
            cb.property("consent_text") or cb.text()
            for cb in self.checkboxes
            if cb.isChecked()
        ]

        record = {
            "consent_timestamp": timestamp,
            "consent_version": self.template_version or "offline-1.0",
            "consent_language": self.language,
            "template_id": self.template_id,
            "hostname_hash": hostname_hash,
            "ip_hash": ip_hash,
            "session_id": self.session_id,
            "case_id": self.case_id,
            "agreed_items": agreed_items,
            "operator_role": getattr(self, "operator_role", "unspecified"),
            "operator_legal_basis": getattr(self, "operator_legal_basis", "unspecified"),
            "international_transfer_ack": bool(getattr(self, "international_transfer_ack", False)),
            "legal_basis": {
                "pipa_article_15": "Collection and Use Consent",
                "pipa_article_17": "Third-party Provision Consent",
                "pipa_article_28_8": "Overseas Transfer Consent",
                "pipa_article_37_2": "Automated Decision-making Notice",
                "pipa_article_35_3": "Data Portability Right"
            }
        }

        # [2026-04-20] Enhanced consent integrity.
        #
        # The previous binding signed only (timestamp|version|content_hash).
        # An attacker swapping the server-provided template text could not be
        # detected by the signature, and consent records could be replayed
        # across cases/sessions.
        #
        # The new record hash covers every field that constitutes the legal
        # record: template_id, a SHA-256 of the raw template content, the
        # session and case identifiers, the user's selected items, and the
        # host fingerprints. HMAC then binds that hash + the signing
        # context into a tamper-evident tag.
        template_content = self.template_content or ""
        template_content_hash = hashlib.sha256(
            template_content.encode("utf-8", errors="replace")
        ).hexdigest()
        record["template_content_sha256"] = template_content_hash

        items_str = "|".join(agreed_items)
        record_components = [
            f"ts={timestamp}",
            f"tpl={self.template_id or ''}",
            f"tplhash={template_content_hash}",
            f"ver={record['consent_version']}",
            f"lang={self.language}",
            f"session={self.session_id or ''}",
            f"case={self.case_id or ''}",
            f"host={hostname_hash}",
            f"ip={ip_hash}",
            f"items={items_str}",
        ]
        record_str = "|".join(record_components)
        record["consent_hash"] = hashlib.sha256(record_str.encode()).hexdigest()

        # HMAC signature - REQUIRE a real key. We never produce a random
        # fallback because it yields a legally worthless signature that
        # cannot be verified by the server.
        signing_key = self._server_signing_key or os.getenv("CONSENT_SIGNING_KEY")
        if not signing_key:
            logger.error(
                "[CONSENT] No signing key available - refusing to generate record. "
                "Set CONSENT_SIGNING_KEY or wait for the server to issue one."
            )
            raise RuntimeError("CONSENT_SIGNING_KEY missing - cannot produce verifiable consent record")

        # The signed payload mirrors the fields we want the server to
        # re-validate, NOT just timestamp/version/content_hash like before.
        verify_payload = "|".join([
            timestamp,
            record['consent_version'],
            record['consent_hash'],
            self.session_id or "",
            self.case_id or "",
            self.template_id or "",
            template_content_hash,
        ])
        record["server_verify_signature"] = hmac.new(
            signing_key.encode(),
            verify_payload.encode(),
            hashlib.sha256
        ).hexdigest()

        record["_verification"] = {
            "algorithm": "HMAC-SHA256",
            "signed_at": timestamp,
            "payload_fields": [
                "consent_timestamp",
                "consent_version",
                "consent_hash",
                "session_id",
                "case_id",
                "template_id",
                "template_content_sha256",
            ],
        }

        return record

    def get_consent_record(self) -> Optional[dict]:
        """Return consent record"""
        return self.consent_record if self.consent_given else None

    def _get_stylesheet(self) -> str:
        """Dialog-local stylesheet with no custom-painted widgets."""
        return f"""
            QDialog {{
                background-color: {COLORS['bg_primary']};
            }}
            #consentHeaderFrame {{
                background-color: {COLORS['bg_secondary']};
                border-bottom: 1px solid {COLORS['border_subtle']};
            }}
            #header {{
                color: {COLORS['brand_primary']};
                font-size: 18px;
                font-weight: 700;
                background: transparent;
            }}
            #headerSubtitle {{
                color: {COLORS['text_secondary']};
                font-size: 12px;
                background: transparent;
            }}
            #bodyScroll, #bodyWidget {{
                background-color: {COLORS['bg_primary']};
                border: none;
            }}
            #warningFrame {{
                background-color: rgba(248, 81, 73, 0.12);
                border: 1px solid {COLORS['error']};
                border-radius: 6px;
            }}
            #warningText {{
                color: {COLORS['text_primary']};
                background: transparent;
                font-size: 12px;
            }}
            #documentFrame, #operatorFrame, #checkboxFrame {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 6px;
            }}
            #consentDocument {{
                color: {COLORS['text_primary']};
                background: transparent;
                font-size: 12px;
                line-height: 1.45;
            }}
            #sectionTitle {{
                color: {COLORS['brand_primary']};
                background: transparent;
                font-weight: 700;
                font-size: 13px;
            }}
            #fieldLabel {{
                color: {COLORS['text_secondary']};
                background: transparent;
                font-size: 12px;
            }}
            #consentRow {{
                background-color: {COLORS['bg_tertiary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 5px;
            }}
            #consentLabel {{
                color: {COLORS['text_primary']};
                background: transparent;
                font-size: 12px;
                line-height: 1.35;
            }}
            QCheckBox#visibleConsentCheck {{
                background: transparent;
                border: none;
                padding: 0;
                margin: 0;
                spacing: 0;
            }}
            QCheckBox#visibleConsentCheck::indicator {{
                width: 16px;
                height: 16px;
                border: 1px solid {COLORS['border_default']};
                border-radius: 3px;
                background-color: {COLORS['bg_primary']};
            }}
            QCheckBox#visibleConsentCheck::indicator:hover {{
                border-color: {COLORS['brand_primary']};
            }}
            QCheckBox#visibleConsentCheck::indicator:checked {{
                background-color: {COLORS['brand_primary']};
                border-color: {COLORS['brand_primary']};
            }}
            #footerFrame {{
                background-color: {COLORS['bg_secondary']};
                border-top: 1px solid {COLORS['border_subtle']};
            }}
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 5px;
                color: {COLORS['text_primary']};
                padding: 0 14px;
                font-size: 12px;
                font-weight: 500;
            }}
            QPushButton:hover {{
                background-color: {COLORS['bg_hover']};
                border-color: {COLORS['border_default']};
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_tertiary']};
                border-color: {COLORS['border_muted']};
            }}
            #agreeButton {{
                background-color: {COLORS['brand_primary']};
                border-color: {COLORS['brand_primary']};
                color: {COLORS['bg_primary']};
                font-weight: 700;
            }}
            #agreeButton:hover {{
                background-color: {COLORS['brand_accent']};
                border-color: {COLORS['brand_accent']};
            }}
            QComboBox {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 5px;
                padding: 0 8px;
                font-size: 12px;
            }}
            QComboBox:hover {{
                border-color: {COLORS['border_default']};
            }}
            QScrollBar:vertical {{
                background: {COLORS['bg_primary']};
                width: 10px;
                margin: 2px;
            }}
            QScrollBar::handle:vertical {{
                background: {COLORS['border_default']};
                border-radius: 4px;
                min-height: 28px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
                width: 0;
            }}
        """


def show_consent_dialog(
    parent=None,
    server_url: str = None,
    session_id: str = None,
    case_id: str = None,
    language: str = "en",
    server_signing_key: str = None,
) -> Optional[dict]:
    """
    Display consent dialog and return result

    Args:
        parent: Parent widget
        server_url: API server URL (e.g., http://localhost:8000)
        session_id: Collection session ID
        case_id: Case ID
        language: Default language code (en, ko, ja, zh)
        server_signing_key: Server-provided consent signing key (if available)

    Returns:
        Consent record dict (if agreed) or None (if cancelled)
    """
    dialog = ConsentDialog(
        parent=parent,
        server_url=server_url,
        session_id=session_id,
        case_id=case_id,
        language=language,
        server_signing_key=server_signing_key,
    )
    result = dialog.exec()

    if result == QDialog.DialogCode.Accepted:
        return dialog.get_consent_record()
    return None


if __name__ == "__main__":
    # For testing
    from PyQt6.QtWidgets import QApplication
    import sys

    app = QApplication(sys.argv)

    # Server integration test
    record = show_consent_dialog(
        server_url="http://localhost:8000",
        session_id="test-session-123",
        case_id="test-case-456",
        language="ko"
    )

    if record:
        logger.info("Consent accepted")
    else:
        logger.info("Consent rejected or cancelled")
