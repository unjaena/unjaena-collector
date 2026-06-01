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
    QComboBox, QMessageBox, QSizePolicy
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
        "ja": "日本語",
        "zh": "中文"
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
        self.body_scroll.setWidget(self.body_widget)
        layout.addWidget(self.body_scroll, 1)

        self.warning_frame = QFrame()
        self.warning_frame.setObjectName("warningFrame")
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
        self.checkbox_layout = QVBoxLayout(self.checkbox_frame)
        self.checkbox_layout.setContentsMargins(12, 12, 12, 12)
        self.checkbox_layout.setSpacing(8)
        self.body_layout.addWidget(self.checkbox_frame)

        self.document_frame = QFrame()
        self.document_frame.setObjectName("documentFrame")
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
        self.body_layout.addStretch(1)

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

        # Button text (by language)
        btn_texts = {
            "ko": ("Cancel", "Agree and Start"),
            "ja": ("キャンセル", "同意して開始"),
            "zh": ("取消", "同意并开始"),
            "en": ("Cancel", "Agree and Start")
        }
        cancel_text, agree_text = btn_texts.get(self.language, btn_texts["en"])
        self.cancel_btn.setText(cancel_text)
        self.agree_btn.setText(agree_text)

        # Warning text (by language)
        warning_texts = {
            "ko": "Warning: This tool collects analysis data from your system.\nPlease read and agree to the terms below before proceeding.",
            "ja": "警告：このツールはシステムから分析データを収集します。\n以下の内容をお読みになり、同意の上お進みください。",
            "zh": "警告：此工具将从您的系统中收集分析数据。\n请阅读以下内容并同意后再继续。",
            "en": "Warning: This tool collects analysis data from your system.\nPlease read and agree to the terms below before proceeding."
        }
        self.warning_label.setText(warning_texts.get(self.language, warning_texts["en"]))

        self._update_button_state()

    def _apply_fallback_template(self):
        """Minimal fallback when server is unreachable."""
        self.template_id = None
        self.template_version = None
        self.template_content = None

        fallback_msgs = {
            'ko': 'Consent information could not be loaded. Internet connection is required.',
            'en': 'Consent information could not be loaded. Internet connection is required.',
            'ja': '同意書を読み込めませんでした。インターネット接続が必要です。',
            'zh': '无法加载同意书。需要互联网连接。',
        }
        msg = fallback_msgs.get(self.language, fallback_msgs['en'])

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

        Fail-closed semantics — returns False if server submission cannot be
        confirmed, blocking the operator from proceeding until the consent
        record is safely transmitted. This is required for GDPR/PIPA audit
        integrity: a scan without a verified consent record is not defensible.

        Exception: explicit offline mode (no server_url configured) is allowed
        because some operators run fully disconnected; in that case the local
        tamper-evident record in _create_consent_record() is the source of
        truth and must be manually submitted later.
        """
        if not self.server_url:
            logger.warning("No server URL configured — using offline mode. "
                           "Consent stored locally only; manual upload required.")
            # Local-only mode is an explicit operator choice; allow it.
            return True

        if not self.session_id:
            logger.error("session_id missing — cannot verify consent on server. "
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

            # Operator role + legal basis — required for downstream accountability
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

    _ROLE_OPTIONS = [
        # (internal_value, i18n_key, english_label)
        ("device_owner",      "role_device_owner",      "I am the owner of this device"),
        ("authorized_agent",  "role_authorized_agent",  "I am authorized in writing by the device owner"),
        ("employer",          "role_employer",          "This is a company-owned device under my supervision"),
        ("court_order",       "role_court_order",       "I have a court order / warrant for this device"),
        ("law_enforcement",   "role_law_enforcement",   "I am a law-enforcement officer acting under lawful authority"),
    ]

    _BASIS_OPTIONS = [
        ("data_subject_consent",   "basis_consent",              "Explicit consent of the data subject"),
        ("legitimate_interest",    "basis_legitimate_interest",  "Legitimate interest (balancing test documented)"),
        ("legal_obligation",       "basis_legal_obligation",     "Legal obligation / regulatory requirement"),
        ("public_task",            "basis_public_task",          "Public task / official authority"),
        ("vital_interest",         "basis_vital_interest",       "Vital interest / life safety"),
    ]

    # Labels shown above the selectors; kept in-dialog (no server round-trip)
    # so the operator can see them even if the consent template fetch fails.
    _OPERATOR_LABELS = {
        "section_title": {
            "en": "Operator Authorization",
            "ko": "Operator Authorization",
            "ja": "実施者の権限",
            "zh": "操作员授权",
        },
        "role_label": {
            "en": "Your role in this collection:",
            "ko": "Your role in this collection:",
            "ja": "本収集におけるあなたの役割:",
            "zh": "您在本次采集中的角色:",
        },
        "basis_label": {
            "en": "Legal basis for processing:",
            "ko": "Legal basis for processing:",
            "ja": "処理の法的根拠:",
            "zh": "处理的法律依据:",
        },
        "transfer_label": {
            "en": "I acknowledge that the collected data may be transmitted to and processed by the configured analysis service and its approved service providers. Standard Contractual Clauses may apply.",
            "ko": "I acknowledge that the collected data may be transmitted to and processed by the configured analysis service and its approved service providers. Standard Contractual Clauses may apply.",
            "ja": "収集されたデータは、設定済みの分析サービスおよび承認済みサービスプロバイダーに送信・処理される場合があります。標準契約条項が適用される場合があります。",
            "zh": "本人确认所采集数据可能会传输至已配置的分析服务及其授权服务提供商进行处理,并可能适用标准合同条款。",
        },
    }

    # Localized labels for the combo entries.
    _ROLE_LABELS_LOCALIZED = {
        "en": {
            "role_device_owner":     "I am the owner of this device",
            "role_authorized_agent": "I am authorized in writing by the device owner",
            "role_employer":         "Company-owned device under my supervision",
            "role_court_order":      "I have a court order / warrant",
            "role_law_enforcement":  "Law-enforcement officer under lawful authority",
        },
        "ko": {
            "role_device_owner":     "I am the owner of this device",
            "role_authorized_agent": "I am authorized in writing by the device owner",
            "role_employer":         "Company-owned device under my supervision",
            "role_court_order":      "I have a court order / warrant",
            "role_law_enforcement":  "Law-enforcement officer under lawful authority",
        },
        "ja": {
            "role_device_owner":     "私はこの端末の所有者です",
            "role_authorized_agent": "所有者から書面で委任を受けました",
            "role_employer":         "会社所有の端末で、私が管理責任者です",
            "role_court_order":      "裁判所命令/令状を有しています",
            "role_law_enforcement":  "法執行機関の職員として適法に実施します",
        },
        "zh": {
            "role_device_owner":     "我是本设备的所有者",
            "role_authorized_agent": "我获得设备所有者的书面授权",
            "role_employer":         "公司所有设备,由我负责监督",
            "role_court_order":      "我持有法院命令或搜查令",
            "role_law_enforcement":  "我是依法执行任务的执法人员",
        },
    }

    _BASIS_LABELS_LOCALIZED = {
        "en": {
            "basis_consent":              "Explicit consent of the data subject",
            "basis_legitimate_interest":  "Legitimate interest (balancing test documented)",
            "basis_legal_obligation":     "Legal obligation / regulatory requirement",
            "basis_public_task":          "Public task / official authority",
            "basis_vital_interest":       "Vital interest / life safety",
        },
        "ko": {
            "basis_consent":              "Explicit consent of the data subject",
            "basis_legitimate_interest":  "Legitimate interest (balancing test documented)",
            "basis_legal_obligation":     "Legal obligation / regulatory requirement",
            "basis_public_task":          "Public task / official authority",
            "basis_vital_interest":       "Vital interest / life safety",
        },
        "ja": {
            "basis_consent":              "データ主体の明示的同意",
            "basis_legitimate_interest":  "正当な利益(比較考量を文書化)",
            "basis_legal_obligation":     "法的義務 / 規制要件",
            "basis_public_task":          "公的任務 / 公的権限",
            "basis_vital_interest":       "重大な利益 / 生命安全",
        },
        "zh": {
            "basis_consent":              "数据主体的明示同意",
            "basis_legitimate_interest":  "正当利益(已记录利益权衡)",
            "basis_legal_obligation":     "法律义务 / 监管要求",
            "basis_public_task":          "公共任务 / 法定职权",
            "basis_vital_interest":       "重大利益 / 生命安全",
        },
    }

    def _build_operator_section(self, parent_layout) -> None:
        """Render the operator-authorization section of the dialog."""
        frame = QFrame()
        frame.setObjectName("operatorFrame")
        vbox = QVBoxLayout(frame)
        vbox.setContentsMargins(12, 12, 12, 12)
        vbox.setSpacing(10)

        self._operator_section_title = QLabel(self._OPERATOR_LABELS["section_title"][self.language])
        self._operator_section_title.setObjectName("sectionTitle")
        vbox.addWidget(self._operator_section_title)

        self._role_label_widget = QLabel(self._OPERATOR_LABELS["role_label"][self.language])
        self._role_label_widget.setObjectName("fieldLabel")
        self.role_combo = QComboBox()
        self.role_combo.setFixedHeight(32)
        for value, key, _ in self._ROLE_OPTIONS:
            label = self._ROLE_LABELS_LOCALIZED[self.language].get(key, value)
            self.role_combo.addItem(label, value)
        self.role_combo.currentIndexChanged.connect(self._on_role_changed)
        vbox.addLayout(self._form_row(self._role_label_widget, self.role_combo))

        self._basis_label_widget = QLabel(self._OPERATOR_LABELS["basis_label"][self.language])
        self._basis_label_widget.setObjectName("fieldLabel")
        self.basis_combo = QComboBox()
        self.basis_combo.setFixedHeight(32)
        for value, key, _ in self._BASIS_OPTIONS:
            label = self._BASIS_LABELS_LOCALIZED[self.language].get(key, value)
            self.basis_combo.addItem(label, value)
        self.basis_combo.currentIndexChanged.connect(self._on_basis_changed)
        vbox.addLayout(self._form_row(self._basis_label_widget, self.basis_combo))

        transfer_text = self._OPERATOR_LABELS["transfer_label"][self.language]
        transfer_row, self.transfer_checkbox, self._transfer_label_widget = self._make_check_row(transfer_text)
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
        """Called from _on_language_changed so the section re-renders
        labels without losing the user's current selection."""
        if not (self.role_combo and self.basis_combo and self.transfer_checkbox):
            return
        try:
            self._operator_section_title.setText(self._OPERATOR_LABELS["section_title"][self.language])
            self._role_label_widget.setText(self._OPERATOR_LABELS["role_label"][self.language])
            self._basis_label_widget.setText(self._OPERATOR_LABELS["basis_label"][self.language])
            new_transfer = self._OPERATOR_LABELS["transfer_label"][self.language]
            self.transfer_checkbox.setToolTip(new_transfer)
            if hasattr(self, "_transfer_label_widget"):
                self._transfer_label_widget.setText(new_transfer)
            # Re-populate combo labels, preserving current selection.
            cur_role = self.role_combo.currentData() or self.operator_role
            self.role_combo.blockSignals(True)
            self.role_combo.clear()
            for value, key, _ in self._ROLE_OPTIONS:
                self.role_combo.addItem(self._ROLE_LABELS_LOCALIZED[self.language].get(key, value), value)
            idx = self.role_combo.findData(cur_role)
            if idx >= 0:
                self.role_combo.setCurrentIndex(idx)
            self.role_combo.blockSignals(False)

            cur_basis = self.basis_combo.currentData() or self.operator_legal_basis
            self.basis_combo.blockSignals(True)
            self.basis_combo.clear()
            for value, key, _ in self._BASIS_OPTIONS:
                self.basis_combo.addItem(self._BASIS_LABELS_LOCALIZED[self.language].get(key, value), value)
            idx = self.basis_combo.findData(cur_basis)
            if idx >= 0:
                self.basis_combo.setCurrentIndex(idx)
            self.basis_combo.blockSignals(False)
        except Exception as e:
            logger.debug(f"operator section relocalize failed: {e}")

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
        operator_ready = bool(self.international_transfer_ack)
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
            title_by_lang = {
                "en": "Consent submission failed",
                "ko": "Consent submission failed",
                "ja": "同意記録の送信に失敗",
                "zh": "同意记录提交失败",
            }
            body_by_lang = {
                "en": (
                    "Could not record your consent on the analysis server. "
                    "Please check your network connection and try again. "
                    "If the problem persists, contact your administrator."
                ),
                "ko": (
                    "Could not record your consent on the analysis server. "
                    "Please check your network connection and try again. "
                    "If the problem persists, contact your administrator."
                ),
                "ja": (
                    "同意記録を解析サーバーに保存できませんでした。"
                    "ネットワーク接続を確認して再試行してください。"
                    "問題が続く場合は管理者にご連絡ください。"
                ),
                "zh": (
                    "无法将您的同意记录保存到分析服务器。"
                    "请检查网络连接后重试。"
                    "如问题持续,请联系管理员。"
                ),
            }
            title = title_by_lang.get(self.language, title_by_lang["en"])
            body = body_by_lang.get(self.language, body_by_lang["en"])
            try:
                from PyQt6.QtWidgets import QMessageBox
                QMessageBox.critical(self, title, body)
            except Exception:
                # GUI not available (e.g. headless mode) — log only
                logger.error("Consent submission failed; refusing to proceed")
            return

        try:
            self.consent_record = self._create_consent_record()
        except RuntimeError as rec_err:
            # Signing-key unavailable — fail closed with user-facing error.
            logger.error(f"Consent record generation failed: {rec_err}")
            key_title = {
                "en": "Consent signing unavailable",
                "ko": "Consent signing unavailable",
                "ja": "同意書の署名が利用できません",
                "zh": "无法对同意书进行签名",
            }.get(self.language, "Consent signing unavailable")
            key_body = {
                "en": (
                    "A secure signing key is required to record consent. "
                    "The server did not provide one. Please retry; if the problem "
                    "continues, contact your administrator."
                ),
                "ko": (
                    "A secure signing key is required to record consent. "
                    "The server did not provide one. Please retry; if the problem "
                    "continues, contact your administrator."
                ),
                "ja": (
                    "安全な署名キーが取得できず、同意記録を生成できません。"
                    "再試行してください。問題が続く場合は管理者にご連絡ください。"
                ),
                "zh": (
                    "无法获取安全签名密钥,同意记录无法生成。"
                    "请重试,如问题持续,请联系管理员。"
                ),
            }.get(self.language, "A secure signing key is required to record consent. Please retry.")
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

        # HMAC signature — REQUIRE a real key. We never produce a random
        # fallback because it yields a legally worthless signature that
        # cannot be verified by the server.
        signing_key = self._server_signing_key or os.getenv("CONSENT_SIGNING_KEY")
        if not signing_key:
            logger.error(
                "[CONSENT] No signing key available — refusing to generate record. "
                "Set CONSENT_SIGNING_KEY or wait for the server to issue one."
            )
            raise RuntimeError("CONSENT_SIGNING_KEY missing — cannot produce verifiable consent record")

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
