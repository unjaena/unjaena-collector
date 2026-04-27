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
    QPushButton, QTextEdit, QFrame, QScrollArea, QWidget,
    QComboBox, QMessageBox
)
from PyQt6.QtCore import Qt

from gui.styles import COLORS

logger = logging.getLogger(__name__)


class ConsentDialog(QDialog):
    """Legal consent dialog (with server API integration)"""

    # Supported languages list
    LANGUAGES = {
        "en": "English",
        "ko": "한국어",
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
        """Initialize UI (with server API integration)"""
        self.setWindowTitle("AI Forensic Lab - Data Collection Consent")
        # [2026-04-27] Round 6.6 — taller default + larger maximum so the
        # required-consent checkbox panel is not squashed into single-line
        # rows. Operators reported that long consent items (e.g. PIPA/GDPR
        # full-sentence statements) were being truncated because the
        # checkbox area only got ~40px of vertical space after the header,
        # warning, scrolling content, and operator section claimed the
        # rest of a 620px window.
        self.setMinimumSize(760, 760)
        self.setMaximumSize(900, 900)
        self.setModal(True)
        self.setStyleSheet(self._get_stylesheet())

        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(16, 16, 16, 16)

        # Header + language selection
        header_layout = QHBoxLayout()

        self.header_label = QLabel("AI Forensic Lab - Data Collection Consent")
        self.header_label.setObjectName("header")
        header_layout.addWidget(self.header_label)

        header_layout.addStretch()

        # Language selection dropdown
        lang_label = QLabel("Language:")
        lang_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        header_layout.addWidget(lang_label)

        self.lang_combo = QComboBox()
        self.lang_combo.setMinimumWidth(100)
        for code, name in self.LANGUAGES.items():
            self.lang_combo.addItem(name, code)
        # Select current language
        idx = self.lang_combo.findData(self.language)
        if idx >= 0:
            self.lang_combo.setCurrentIndex(idx)
        self.lang_combo.currentIndexChanged.connect(self._on_language_changed)
        header_layout.addWidget(self.lang_combo)

        layout.addLayout(header_layout)

        # Warning banner
        self.warning_frame = QFrame()
        self.warning_frame.setObjectName("warningFrame")
        warning_layout = QHBoxLayout(self.warning_frame)
        self.warning_label = QLabel(
            "Warning: This tool collects analysis data from your system.\n"
            "Please read and agree to the terms below before proceeding."
        )
        self.warning_label.setObjectName("warningText")
        warning_layout.addWidget(self.warning_label)
        layout.addWidget(self.warning_frame)

        # Scroll area (consent content)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setSpacing(12)

        # Display consent content
        self.consent_text = QTextEdit()
        self.consent_text.setReadOnly(True)
        self.consent_text.setMinimumHeight(280)
        self.consent_text.setMaximumHeight(380)
        content_layout.addWidget(self.consent_text)

        scroll.setWidget(content_widget)
        layout.addWidget(scroll)

        # ------------------------------------------------------------------
        # Operator role + legal basis + international transfer acknowledgment
        # ------------------------------------------------------------------
        # [2026-04-20] Forensic-legal integrity. The consent record MUST
        # capture WHO is performing the collection and UNDER WHAT AUTHORITY,
        # so that later review (court, opposing counsel, DPO) can determine
        # whether the operator had standing to collect from this device.
        # Previous builds stored `operator_role="unspecified"` silently;
        # this block binds the fields at collection time.
        self._build_operator_section(layout)

        # Checkbox area (dynamically generated from server items)
        # [2026-04-27 Round 6.6] Each consent item can be a full sentence
        # (e.g. "I consent to the international transfer of my collected
        # data to the United States in accordance with PIPA Article 28
        # and GDPR Article 49(1)(a) ..."). QCheckBox does not natively
        # word-wrap its label, so long items were truncated to a single
        # line and the operator could not see what they were agreeing
        # to. We wrap the entire panel in a ScrollArea (so adding new
        # items doesn't push the buttons off-screen) and the checkbox
        # itself is paired with a wrapping QLabel in _add_consent_item().
        self.checkbox_scroll = QScrollArea()
        self.checkbox_scroll.setWidgetResizable(True)
        self.checkbox_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.checkbox_scroll.setMinimumHeight(140)
        self.checkbox_scroll.setMaximumHeight(280)

        self.checkbox_frame = QFrame()
        self.checkbox_frame.setObjectName("checkboxFrame")
        self.checkbox_layout = QVBoxLayout(self.checkbox_frame)
        self.checkbox_layout.setContentsMargins(12, 12, 12, 12)
        self.checkbox_layout.setSpacing(12)
        self.checkbox_layout.addStretch()

        self.checkbox_scroll.setWidget(self.checkbox_frame)
        layout.addWidget(self.checkbox_scroll)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        self.cancel_btn.setMinimumWidth(100)
        button_layout.addWidget(self.cancel_btn)

        self.agree_btn = QPushButton("Agree and Start Collection")
        self.agree_btn.setObjectName("agreeButton")
        self.agree_btn.setEnabled(False)
        self.agree_btn.clicked.connect(self._on_agree)
        self.agree_btn.setMinimumWidth(180)
        button_layout.addWidget(self.agree_btn)

        layout.addLayout(button_layout)

        # Load consent template from server
        self._load_consent_template()

    def _on_language_changed(self, index: int):
        """Reload consent when language changes"""
        self.language = self.lang_combo.currentData()
        self._load_consent_template()
        # Keep the operator-section labels in sync with the active language.
        self._relocalize_operator_section()

    def _load_consent_template(self):
        """Load consent template from server"""
        # Remove existing checkboxes
        for cb in self.checkboxes:
            cb.deleteLater()
        self.checkboxes.clear()

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

    def _apply_template(self, template: dict):
        """Apply server template"""
        self.template_id = template.get("id")
        self.template_version = template.get("version")
        self.template_content = template.get("content", "")
        self.required_checkboxes = template.get("required_checkboxes", [])

        # Update header
        self.header_label.setText(template.get("title", "AI Forensic Lab - Data Collection Consent"))
        self.setWindowTitle(template.get("title", "Consent"))

        # Display consent content (Markdown to HTML)
        content = template.get("content", "")
        html_content = self._markdown_to_html(content)
        self.consent_text.setHtml(html_content)

        # Generate dynamic checkboxes (full-text wrapping via _add_consent_item)
        # [2026-04-27 Round 6.6] Drop existing widgets before re-rendering
        # so language switches don't accumulate stale rows.
        while self.checkbox_layout.count() > 0:
            item = self.checkbox_layout.takeAt(0)
            if item is None:
                break
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()
        self.checkboxes.clear()

        for item_text in self.required_checkboxes:
            self._add_consent_item(item_text)
        # Trailing stretch keeps short item lists hugging the top of the
        # scroll area instead of being centred.
        self.checkbox_layout.addStretch()

        # Button text (by language)
        btn_texts = {
            "ko": ("취소", "동의 후 수집 시작"),
            "ja": ("キャンセル", "同意して収集を開始"),
            "zh": ("取消", "同意并开始收集"),
            "en": ("Cancel", "Agree and Start Collection")
        }
        cancel_text, agree_text = btn_texts.get(self.language, btn_texts["en"])
        self.cancel_btn.setText(cancel_text)
        self.agree_btn.setText(agree_text)

        # Warning text (by language)
        warning_texts = {
            "ko": "경고: 이 도구는 시스템에서 분석 데이터를 수집합니다.\n아래 내용을 읽고 동의한 후 진행하세요.",
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
            'ko': '동의서를 불러올 수 없습니다. 인터넷 연결이 필요합니다.',
            'en': 'Consent information could not be loaded. Internet connection is required.',
            'ja': '同意書を読み込めませんでした。インターネット接続が必要です。',
            'zh': '无法加载同意书。需要互联网连接。',
        }
        msg = fallback_msgs.get(self.language, fallback_msgs['en'])

        self.header_label.setText("AI Forensic Lab - Data Collection Consent")
        self.setWindowTitle("AI Forensic Lab - Data Collection Consent")
        self.consent_text.setHtml(
            f'<div style="text-align:center;padding:40px;color:#ff6b6b;font-size:14px;">{msg}</div>'
        )

        # Disable agree button -- user must connect to server
        self.agree_btn.setEnabled(False)
        self.agree_btn.setText("Agree and Start Collection")
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

        # Header (displayed as number. title format)
        html = re.sub(
            r'^### (\d+)\. (.+)$',
            rf'<h4 style="color:{COLORS["brand_primary"]}; margin:12px 0 6px 0; font-size:13px; font-weight:600;">\1. \2</h4>',
            html, flags=re.MULTILINE
        )
        html = re.sub(
            r'^## (.+)$',
            rf'<h3 style="color:{COLORS["brand_primary"]}; margin:0 0 10px 0; padding-bottom:8px; border-bottom:2px solid {COLORS["brand_primary"]}; font-size:16px;">\1</h3>',
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
            r'\*\*버전\*\*: (v[\d.]+) \| \*\*시행일\*\*: ([\d-]+)',
            rf'<div style="margin-top:12px; padding:8px; background:{COLORS["bg_secondary"]}; border-radius:4px; font-size:11px; color:{COLORS["text_secondary"]};">Version: \1 | Effective: \2</div>',
            html
        )
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

            # List of agreed items
            agreed_items = [cb.text() for cb in self.checkboxes if cb.isChecked()]

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
                "target_system_info": {"hostname": hostname},
                "signature_type": "checkbox",
                "operator_role": getattr(self, "operator_role", "unspecified"),
                "operator_legal_basis": getattr(self, "operator_legal_basis", "unspecified"),
                "international_transfer_ack": bool(getattr(self, "itransfer_ack", False)),
            }

            headers = {"Content-Type": "application/json"}

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
            "ko": "수행자 권한 고지",
            "ja": "実施者の権限",
            "zh": "操作员授权",
        },
        "role_label": {
            "en": "Your role in this collection:",
            "ko": "본 수집에서 귀하의 역할:",
            "ja": "本収集におけるあなたの役割:",
            "zh": "您在本次采集中的角色:",
        },
        "basis_label": {
            "en": "Legal basis for processing:",
            "ko": "처리의 법적 근거:",
            "ja": "処理の法的根拠:",
            "zh": "处理的法律依据:",
        },
        "transfer_label": {
            "en": "I acknowledge that the collected data will be transmitted to and processed on servers located in the United States (RunPod, Cloudflare) and the United Kingdom (Paddle). Standard Contractual Clauses apply.",
            "ko": "수집된 데이터가 미국(RunPod, Cloudflare) 및 영국(Paddle)에 위치한 서버로 전송·처리되며, 표준계약조항(SCC)이 적용됨을 확인합니다.",
            "ja": "収集されたデータは米国(RunPod, Cloudflare)および英国(Paddle)所在のサーバーに送信・処理され、標準契約条項(SCC)が適用されることを確認します。",
            "zh": "本人确认所采集数据将传输至位于美国(RunPod、Cloudflare)和英国(Paddle)的服务器进行处理,并适用标准合同条款(SCC)。",
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
            "role_device_owner":     "본인 소유 기기입니다",
            "role_authorized_agent": "기기 소유자로부터 서면 위임을 받았습니다",
            "role_employer":         "회사 소유 기기이며 제가 관리 책임자입니다",
            "role_court_order":      "법원 영장 또는 명령을 소지하고 있습니다",
            "role_law_enforcement":  "수사기관 공무원으로 적법 권한을 행사합니다",
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
            "basis_consent":              "정보주체의 명시적 동의",
            "basis_legitimate_interest":  "정당한 이익 (balancing test 문서화됨)",
            "basis_legal_obligation":     "법적 의무 / 규제 요건",
            "basis_public_task":          "공공 직무 / 공적 권한",
            "basis_vital_interest":       "중대한 이익 / 생명 안전",
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
        """Render the operator-authorization section of the dialog.

        Placed between the consent template text and the dynamic
        per-artifact checkboxes so the operator answers "who am I and
        on what authority?" BEFORE ticking collection items.
        """
        from PyQt6.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QCheckBox

        frame = QFrame()
        frame.setObjectName("operatorFrame")
        # Reuse the warningFrame palette so it visually reads as a
        # "pay attention" section without needing a new style token.
        frame.setStyleSheet(
            f"""
            QFrame#operatorFrame {{
                background-color: {COLORS.get('bg_secondary', '#1f2937')};
                border: 1px solid {COLORS.get('border', '#374151')};
                border-radius: 8px;
                padding: 8px;
            }}
            """
        )
        vbox = QVBoxLayout(frame)
        vbox.setContentsMargins(10, 8, 10, 8)
        vbox.setSpacing(6)

        # Section title
        self._operator_section_title = QLabel(self._OPERATOR_LABELS["section_title"][self.language])
        self._operator_section_title.setStyleSheet(
            f"color: {COLORS.get('brand_primary', '#d4a574')}; font-weight: 600; font-size: 13px;"
        )
        vbox.addWidget(self._operator_section_title)

        # Role selector
        self._role_label_widget = QLabel(self._OPERATOR_LABELS["role_label"][self.language])
        self._role_label_widget.setStyleSheet(f"color: {COLORS.get('text_secondary', '#9ca3af')}; font-size: 12px;")
        vbox.addWidget(self._role_label_widget)

        self.role_combo = QComboBox()
        for value, key, _ in self._ROLE_OPTIONS:
            label = self._ROLE_LABELS_LOCALIZED[self.language].get(key, value)
            self.role_combo.addItem(label, value)
        self.role_combo.currentIndexChanged.connect(self._on_role_changed)
        vbox.addWidget(self.role_combo)

        # Legal basis selector
        self._basis_label_widget = QLabel(self._OPERATOR_LABELS["basis_label"][self.language])
        self._basis_label_widget.setStyleSheet(f"color: {COLORS.get('text_secondary', '#9ca3af')}; font-size: 12px;")
        vbox.addWidget(self._basis_label_widget)

        self.basis_combo = QComboBox()
        for value, key, _ in self._BASIS_OPTIONS:
            label = self._BASIS_LABELS_LOCALIZED[self.language].get(key, value)
            self.basis_combo.addItem(label, value)
        self.basis_combo.currentIndexChanged.connect(self._on_basis_changed)
        vbox.addWidget(self.basis_combo)

        # International transfer acknowledgment (required under PIPA §28-8
        # + GDPR Chap. V). Disables the Agree button until ticked.
        self.transfer_checkbox = QCheckBox(self._OPERATOR_LABELS["transfer_label"][self.language])
        self.transfer_checkbox.setStyleSheet(f"color: {COLORS.get('text_primary', '#f3f4f6')}; font-size: 12px;")
        self.transfer_checkbox.setToolTip(
            "PIPA §28-8 / GDPR Art. 44-49 cross-border transfer disclosure"
        )
        self.transfer_checkbox.stateChanged.connect(self._on_transfer_changed)
        vbox.addWidget(self.transfer_checkbox)

        parent_layout.addWidget(frame)

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
            self.transfer_checkbox.setText(self._OPERATOR_LABELS["transfer_label"][self.language])
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
        """Add a single consent checkbox row with full word-wrapped text.

        [2026-04-27 Round 6.6] QCheckBox does not natively word-wrap its
        own label, which truncated long PIPA / GDPR / cross-border-
        transfer statements to a single line in the dialog. We pair the
        checkbox with a separate QLabel that has wordWrap=True; clicking
        the label toggles the checkbox so the pair behaves like a single
        widget for the operator. The full statement is also set as the
        checkbox tooltip so on-hover preview works for very long items.
        """
        row = QFrame()
        row.setObjectName("consentRow")
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(8)

        cb = QCheckBox()
        cb.setObjectName("consentCheck")
        cb.setToolTip(text)
        cb.stateChanged.connect(self._update_button_state)

        label = QLabel(text)
        label.setObjectName("consentLabel")
        label.setWordWrap(True)
        label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.LinksAccessibleByMouse
        )
        # Clicking the label toggles the checkbox — the row behaves as one widget
        # for the operator. We use mousePressEvent override via lambda
        # because QLabel has no native click signal.
        label.mousePressEvent = lambda _e, _cb=cb: _cb.toggle()
        label.setCursor(Qt.CursorShape.PointingHandCursor)

        row_layout.addWidget(cb, 0, Qt.AlignmentFlag.AlignTop)
        row_layout.addWidget(label, 1)

        # Insert before the trailing stretch (last item in layout)
        insert_at = max(0, self.checkbox_layout.count() - 1)
        self.checkbox_layout.insertWidget(insert_at, row)
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
                "ko": "동의 기록 전송 실패",
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
                    "동의 기록을 분석 서버에 저장하지 못했습니다. "
                    "네트워크 연결을 확인한 후 다시 시도해 주세요. "
                    "문제가 지속되면 관리자에게 문의하세요."
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
                "ko": "동의서 서명 불가",
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
                    "안전한 서명 키가 없어서 동의 기록을 생성할 수 없습니다. "
                    "서버에서 키가 전달되지 않았습니다. 다시 시도해 주시고, "
                    "문제가 지속되면 관리자에게 문의하세요."
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
        agreed_items = [cb.text() for cb in self.checkboxes if cb.isChecked()]

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
        """Stylesheet - platform unified theme"""
        return f"""
            QDialog {{
                background-color: {COLORS['bg_primary']};
            }}
            #header {{
                font-size: 20px;
                font-weight: bold;
                color: {COLORS['brand_primary']};
                padding: 8px;
            }}
            #warningFrame {{
                background-color: rgba(248, 81, 73, 0.15);
                border: 1px solid {COLORS['error']};
                border-radius: 8px;
                padding: 12px;
            }}
            #warningText {{
                color: {COLORS['error']};
                font-size: 13px;
            }}
            #checkboxFrame {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 6px;
                padding: 8px;
            }}
            #consentCheck {{
                color: {COLORS['text_primary']};
                background-color: transparent;
                font-size: 11px;
                spacing: 6px;
                padding: 2px 0;
            }}
            #consentCheck::indicator {{
                width: 16px;
                height: 16px;
                border: 2px solid {COLORS['border_subtle']};
                border-radius: 3px;
                background-color: {COLORS['bg_tertiary']};
            }}
            #consentCheck::indicator:checked {{
                background-color: {COLORS['brand_primary']};
                border-color: {COLORS['brand_primary']};
            }}
            QTextEdit {{
                background-color: {COLORS['bg_tertiary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 8px;
                color: {COLORS['text_primary']};
                padding: 12px;
                font-size: 13px;
            }}
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 6px;
                color: {COLORS['text_primary']};
                padding: 10px 20px;
                font-size: 13px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['bg_hover']};
                border-color: {COLORS['border_default']};
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_tertiary']};
            }}
            #agreeButton {{
                background-color: {COLORS['brand_primary']};
                border: none;
                color: {COLORS['bg_primary']};
                font-weight: bold;
            }}
            #agreeButton:hover {{
                background-color: {COLORS['brand_accent']};
            }}
            #agreeButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_tertiary']};
            }}
            QScrollArea {{
                background-color: transparent;
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
