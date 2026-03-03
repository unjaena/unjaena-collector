"""
Legal Consent Dialog

Dialog for obtaining legal consent before starting collection.
Collection cannot proceed without consent.

2026-01 Server API Integration:
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
from PyQt6.QtGui import QFont

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
        language: str = "en"
    ):
        """
        Args:
            parent: Parent widget
            server_url: API server URL (e.g., http://localhost:8000)
            session_id: Collection session ID
            case_id: Case ID
            language: Default language code (en, ko, ja, zh)
        """
        super().__init__(parent)
        self.server_url = server_url
        self.session_id = session_id
        self.case_id = case_id
        self.language = language
        self.consent_given = False
        self.consent_record = None

        # Template information received from server
        self.template_id = None
        self.template_version = None
        self.template_content = None
        self.required_checkboxes: List[str] = []
        self.checkboxes: List[QCheckBox] = []

        self.setup_ui()

    def setup_ui(self):
        """Initialize UI (with server API integration)"""
        self.setWindowTitle("Digital Data Collection Consent")
        self.setMinimumSize(700, 620)
        self.setMaximumSize(800, 720)
        self.setModal(True)
        self.setStyleSheet(self._get_stylesheet())

        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(16, 16, 16, 16)

        # Header + language selection
        header_layout = QHBoxLayout()

        self.header_label = QLabel("Digital Data Collection Consent")
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

        # Checkbox area (dynamically generated from server items)
        self.checkbox_frame = QFrame()
        self.checkbox_frame.setObjectName("checkboxFrame")
        self.checkbox_layout = QVBoxLayout(self.checkbox_frame)
        self.checkbox_layout.setContentsMargins(8, 8, 8, 8)
        self.checkbox_layout.setSpacing(4)

        layout.addWidget(self.checkbox_frame)

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
            url = f"{self.server_url}/api/v1/collector/consent"
            params = {"language": self.language, "category": "collection"}

            response = requests.get(url, params=params, timeout=10)
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
        self.header_label.setText(template.get("title", "Digital Data Collection Consent"))
        self.setWindowTitle(template.get("title", "Consent"))

        # Display consent content (Markdown to HTML)
        content = template.get("content", "")
        html_content = self._markdown_to_html(content)
        self.consent_text.setHtml(html_content)

        # Generate dynamic checkboxes
        for item in self.required_checkboxes:
            cb = QCheckBox(item)
            cb.setObjectName("consentCheck")
            cb.stateChanged.connect(self._update_button_state)
            self.checkbox_layout.addWidget(cb)
            self.checkboxes.append(cb)

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
        """Apply offline fallback template"""
        self.template_id = None
        self.template_version = "offline-2.0"
        self.template_content = self._get_consent_html()

        # Header text (by language)
        header_texts = {
            "ko": "디지털 데이터 수집 동의서",
            "ja": "デジタルデータ収集同意書",
            "zh": "数字数据收集同意书",
            "en": "Digital Data Collection Consent"
        }
        self.header_label.setText(header_texts.get(self.language, header_texts["en"]))
        self.setWindowTitle(header_texts.get(self.language, header_texts["en"]))
        self.consent_text.setHtml(self.template_content)

        # Button text (by language) - also needed in offline fallback
        btn_texts = {
            "ko": ("취소", "동의 후 수집 시작"),
            "ja": ("キャンセル", "同意して収集を開始"),
            "zh": ("取消", "同意并开始收集"),
            "en": ("Cancel", "Agree and Start Collection")
        }
        cancel_text, agree_text = btn_texts.get(self.language, btn_texts["en"])
        self.cancel_btn.setText(cancel_text)
        self.agree_btn.setText(agree_text)

        # Warning text (by language) - also needed in offline fallback
        warning_texts = {
            "ko": "경고: 이 도구는 시스템에서 분석 데이터를 수집합니다.\n아래 내용을 읽고 동의한 후 진행하세요.",
            "ja": "警告：このツールはシステムから分析データを収集します。\n以下の内容をお読みになり、同意の上お進みください。",
            "zh": "警告：此工具将从您的系统中收集分析数据。\n请阅读以下内容并同意后再继续。",
            "en": "Warning: This tool collects analysis data from your system.\nPlease read and agree to the terms below before proceeding."
        }
        self.warning_label.setText(warning_texts.get(self.language, warning_texts["en"]))

        # Default checkboxes - 5 items per section (B2: PIPA/PIPL/GDPR compliance)
        default_items_map = {
            "ko": [
                "개인정보 수집·이용에 동의합니다 (Section 1)",
                "해외 데이터 이전에 동의합니다 (Section 2)",
                "AI 분석 및 자동화된 의사결정에 동의합니다 (Section 3)",
                "데이터 주체 권리를 확인하였습니다 (Section 4)",
                "법적 경고 및 면책사항을 확인하였으며, 적법한 권한을 보유하고 있음을 확인합니다 (Section 5)"
            ],
            "ja": [
                "個人情報の収集・利用に同意します（Section 1）",
                "海外データ移転に同意します（Section 2）",
                "AI分析および自動化された意思決定に同意します（Section 3）",
                "データ主体の権利を確認しました（Section 4）",
                "法的警告および免責事項を確認し、適法な権限を保有していることを確認します（Section 5）"
            ],
            "zh": [
                "同意个人信息的收集和使用（Section 1）",
                "同意海外数据传输（Section 2）",
                "同意AI分析及自动化决策（Section 3）",
                "已确认数据主体权利（Section 4）",
                "已确认法律警告及免责条款，并确认拥有合法权限（Section 5）"
            ],
            "en": [
                "I consent to the collection and use of personal information (Section 1)",
                "I consent to cross-border data transfer (Section 2)",
                "I consent to AI analysis and automated decision-making (Section 3)",
                "I have reviewed data subject rights (Section 4)",
                "I confirm legal warnings and disclaimers, and that I have lawful authority (Section 5)"
            ]
        }
        default_items = default_items_map.get(self.language, default_items_map["en"])

        for item in default_items:
            cb = QCheckBox(item)
            cb.setObjectName("consentCheck")
            cb.stateChanged.connect(self._update_button_state)
            self.checkbox_layout.addWidget(cb)
            self.checkboxes.append(cb)
            self.required_checkboxes.append(item)

        self._update_button_state()

    def _markdown_to_html(self, markdown_text: str) -> str:
        """Markdown to HTML conversion (supports tables, horizontal rules)"""
        import re

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
        """Submit consent record to server"""
        if not self.server_url or not self.session_id:
            logger.warning("Server URL or session_id not set, skipping server submission")
            return True  # Continue even without server

        try:
            url = f"{self.server_url}/api/v1/collector/consent/accept"

            # List of agreed items
            agreed_items = [cb.text() for cb in self.checkboxes if cb.isChecked()]

            # System information
            try:
                hostname = socket.gethostname()
            except Exception:
                hostname = "unknown"

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
                "signature_type": "checkbox"
            }

            headers = {"Content-Type": "application/json"}

            response = requests.post(url, json=payload, headers=headers, timeout=10)
            response.raise_for_status()

            result = response.json()
            logger.info(f"Consent submitted: consent_id={result.get('consent_id')}")
            return True

        except requests.RequestException as e:
            logger.error(f"Failed to submit consent to server: {e}")
            # Keep local record even if server submission fails
            return True

    def _get_consent_html(self) -> str:
        """Consent HTML content (Privacy law compliant, multilingual)"""
        return self._get_consent_html_by_lang(self.language)

    def _get_consent_html_by_lang(self, lang: str) -> str:
        """Return consent HTML by language"""
        if lang == "ko":
            return self._get_consent_html_ko()
        elif lang == "ja":
            return self._get_consent_html_ja()
        elif lang == "zh":
            return self._get_consent_html_zh()
        return self._get_consent_html_en()

    def _consent_html_wrapper(self, body: str) -> str:
        """Common HTML wrapper"""
        return f'''<div style="font-family: 'Malgun Gothic', 'Segoe UI', sans-serif; line-height: 1.8; color: {COLORS['text_primary']};">{body}</div>'''

    def _consent_table_style(self) -> str:
        return f'width: 100%; border-collapse: collapse; margin: 12px 0;'

    def _consent_th_style(self) -> str:
        return f'border: 1px solid {COLORS["border_subtle"]}; padding: 10px; background: {COLORS["bg_secondary"]};'

    def _consent_td_style(self) -> str:
        return f'border: 1px solid {COLORS["border_subtle"]}; padding: 10px;'

    def _consent_transfer_table(self, lang: str) -> str:
        """Data transfer table placeholder — actual content provided by server consent API"""
        notice = {
            "en": "Data transfer details are provided in the full consent document from the server.",
            "ko": "데이터 이전 세부 사항은 서버에서 제공하는 동의서 전문에 포함되어 있습니다.",
            "ja": "データ移転の詳細は、サーバーから提供される同意書全文に記載されています。",
            "zh": "数据传输详情包含在服务器提供的完整同意书中。",
        }
        msg = notice.get(lang, notice["en"])
        return f'<p style="background: rgba(210,153,34,0.1); padding: 12px; border-radius: 8px; font-style: italic;">{msg}</p>'

    def _get_consent_html_en(self) -> str:
        """English consent HTML"""
        td = self._consent_td_style()
        th = self._consent_th_style()
        return self._consent_html_wrapper(f"""
        <h3 style="color: {COLORS['brand_primary']}; border-bottom: 2px solid {COLORS['brand_primary']}; padding-bottom: 8px;">
            1. Personal Information Collection and Use Consent</h3>
        <table style="{self._consent_table_style()}">
            <tr><th style="{th}; width:25%;">Item</th><th style="{th}">Description</th></tr>
            <tr><td style="{td}"><b>Collection Purpose</b></td><td style="{td}">Digital intelligence analysis, security incident investigation, evidence acquisition, AI-based anomaly detection</td></tr>
            <tr><td style="{td}"><b>Collection Items</b></td><td style="{td}"><b>[System]</b> Prefetch, Amcache, UserAssist, Event logs, Registry, MFT, USN Journal<br><b>[User Activity]</b> Browser history, USB history, Recycle Bin, Shortcuts, Jump lists<br><b>[Documents/Email]</b> Office documents, PDF, HWP, Email (pst/ost/eml/msg)</td></tr>
            <tr><td style="{td}"><b>Retention Period</b></td><td style="{td}"><b>30 days</b> after case closure (automatically deleted)</td></tr>
            <tr><td style="{td}"><b>Processing Method</b></td><td style="{td}">SHA-256 hash verification, TLS 1.3 encryption, AES-256-GCM storage, Chain of Custody</td></tr>
        </table>

        <h3 style="color: {COLORS['warning']}; border-bottom: 2px solid {COLORS['warning']}; padding-bottom: 8px;">
            2. Cross-Border Data Transfer Notice</h3>
        <p style="background: rgba(210,153,34,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['warning']};">
            <b>Notice:</b> Collected data may be transferred overseas. If you do not consent, service may be limited.</p>
        {self._consent_transfer_table("en")}

        <h3 style="color: {COLORS['brand_accent']}; border-bottom: 2px solid {COLORS['brand_accent']}; padding-bottom: 8px;">
            3. AI Analysis and Automated Decision-Making Notice</h3>
        <p style="background: rgba(212,165,116,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['brand_accent']};">
            <b>Notice pursuant to applicable AI and privacy regulations</b></p>
        <ul>
            <li><b>AI Usage:</b> Pattern recognition, anomaly detection, correlation analysis, automated report generation.</li>
            <li><b>Automated Decisions:</b> AI identifies suspicious activity, malware indicators, etc. for <u>reference only</u>.</li>
            <li><b>Limitations:</b> False positives/negatives may occur. AI hallucinations may generate non-existent information.</li>
            <li style="color: {COLORS['error']};"><b>Legal Risk:</b> Legal action based on AI results may lead to disputes. Always consult experts.</li>
            <li><b>Your Rights:</b> Right to refuse, right to explanation, right to human intervention regarding automated decisions.</li>
        </ul>

        <h3 style="color: {COLORS['success']}; border-bottom: 2px solid {COLORS['success']}; padding-bottom: 8px;">
            4. Data Subject Rights</h3>
        <ul>
            <li><b>Right of Access:</b> Request access to collected personal information.</li>
            <li><b>Right to Rectification:</b> Request correction of inaccurate information.</li>
            <li><b>Right to Erasure:</b> Request deletion (except during legal retention).</li>
            <li><b>Right to Restrict Processing:</b> Request suspension of processing.</li>
            <li><b>Right to Withdraw Consent:</b> Withdraw consent at any time.</li>
            <li><b>Right to Data Portability:</b> Request transfer of your data in a machine-readable format.</li>
        </ul>
        <p>Contact: support@forensics-ai.com | Privacy: privacy@forensics-ai.com</p>

        <h3 style="color: {COLORS['error']}; border-bottom: 2px solid {COLORS['error']}; padding-bottom: 8px;">
            5. Legal Warning and Disclaimer</h3>
        <p style="background: rgba(248,81,73,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['error']};">
            <b>Warning:</b> Unauthorized data collection may violate computer fraud and privacy laws.</p>
        <ul>
            <li><b>Your system:</b> This consent is sufficient.</li>
            <li><b>Another person's system:</b> Written consent from the owner or legal authority (warrant) is required.</li>
            <li><b>Corporate investigation:</b> Legal team review and labor law compliance required.</li>
        </ul>
        <p style="background: rgba(100,100,100,0.2); padding: 12px; border-radius: 8px; margin-top: 12px;">
            <b>Disclaimer:</b> The company is not liable for damages from AI analysis errors. All liability for unauthorized collection rests with the user.</p>
        """)

    def _get_consent_html_ko(self) -> str:
        """Korean consent HTML"""
        td = self._consent_td_style()
        th = self._consent_th_style()
        return self._consent_html_wrapper(f"""
        <h3 style="color: {COLORS['brand_primary']}; border-bottom: 2px solid {COLORS['brand_primary']}; padding-bottom: 8px;">
            1. 개인정보 수집·이용 동의</h3>
        <table style="{self._consent_table_style()}">
            <tr><th style="{th}; width:25%;">항목</th><th style="{th}">내용</th></tr>
            <tr><td style="{td}"><b>수집 목적</b></td><td style="{td}">디지털 인텔리전스 분석, 보안 사고 조사, 데이터 확보, AI 기반 이상 탐지</td></tr>
            <tr><td style="{td}"><b>수집 항목</b></td><td style="{td}"><b>[시스템]</b> Prefetch, Amcache, UserAssist, 이벤트 로그, 레지스트리, MFT, USN Journal<br><b>[사용자 활동]</b> 브라우저 기록, USB 연결 기록, 휴지통, 바로가기, 점프 목록<br><b>[문서/이메일]</b> Office 문서, PDF, HWP, 이메일 (pst/ost/eml/msg)</td></tr>
            <tr><td style="{td}"><b>보관 기간</b></td><td style="{td}"><b>30일</b> (케이스 종료 후 자동 삭제)</td></tr>
            <tr><td style="{td}"><b>처리 방법</b></td><td style="{td}">SHA-256 해시 검증, TLS 1.3 암호화 통신, AES-256-GCM 암호화 저장, Chain of Custody</td></tr>
        </table>

        <h3 style="color: {COLORS['warning']}; border-bottom: 2px solid {COLORS['warning']}; padding-bottom: 8px;">
            2. 해외 데이터 이전 고지</h3>
        <p style="background: rgba(210,153,34,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['warning']};">
            <b>고지:</b> 수집된 데이터는 해외 서버로 이전될 수 있습니다. 동의하지 않으실 경우 서비스 이용이 제한됩니다.</p>
        {self._consent_transfer_table("ko")}

        <h3 style="color: {COLORS['brand_accent']}; border-bottom: 2px solid {COLORS['brand_accent']}; padding-bottom: 8px;">
            3. AI 분석 및 자동화된 의사결정 고지</h3>
        <p style="background: rgba(212,165,116,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['brand_accent']};">
            <b>개인정보보호법 제37조의2에 따른 고지</b></p>
        <ul>
            <li><b>AI 사용:</b> 패턴 인식, 이상 탐지, 상관관계 분석, 자동 보고서 생성</li>
            <li><b>자동화된 판단:</b> 의심 활동, 악성코드 지표 등을 AI가 자동 판단 (<u>참고용</u>)</li>
            <li><b>한계:</b> 오탐(False Positive), 미탐(False Negative), 환각(Hallucination) 발생 가능</li>
            <li style="color: {COLORS['error']};"><b>법적 위험:</b> AI 분석 결과 기반 법적 조치 시 분쟁 발생 가능. 반드시 전문가 자문 필요</li>
            <li><b>권리:</b> 거부권, 설명 요구권, 인적 개입 요구권을 행사할 수 있습니다</li>
        </ul>

        <h3 style="color: {COLORS['success']}; border-bottom: 2px solid {COLORS['success']}; padding-bottom: 8px;">
            4. 데이터 주체 권리 안내</h3>
        <ul>
            <li><b>열람권:</b> 수집된 개인정보에 대한 열람을 요구할 수 있습니다</li>
            <li><b>정정권:</b> 부정확한 정보의 정정을 요구할 수 있습니다</li>
            <li><b>삭제권:</b> 개인정보 삭제를 요구할 수 있습니다 (법적 보관 기간 제외)</li>
            <li><b>처리정지권:</b> 개인정보 처리 정지를 요구할 수 있습니다</li>
            <li><b>동의철회권:</b> 언제든지 동의를 철회할 수 있습니다</li>
            <li><b>전송요구권:</b> 수집된 개인정보를 기계 판독 가능한 형태로 전송받을 수 있습니다</li>
        </ul>
        <p>권리 행사: support@forensics-ai.com | 개인정보 보호책임자: privacy@forensics-ai.com</p>

        <h3 style="color: {COLORS['error']}; border-bottom: 2px solid {COLORS['error']}; padding-bottom: 8px;">
            5. 법적 경고 및 면책</h3>
        <p style="background: rgba(248,81,73,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['error']};">
            <b>경고:</b> 타인의 시스템에서 무단으로 데이터를 수집하는 행위는 관련 법률에 따라 처벌될 수 있습니다.</p>
        <ul>
            <li><b>본인 시스템:</b> 본 동의서로 충분합니다</li>
            <li><b>타인 시스템:</b> 시스템 소유자의 서면 동의 또는 법적 근거(영장 등)가 필요합니다</li>
            <li><b>기업 내부 조사:</b> 법무팀 검토 및 노동법 준수가 필요합니다</li>
        </ul>
        <p style="background: rgba(100,100,100,0.2); padding: 12px; border-radius: 8px; margin-top: 12px;">
            <b>면책:</b> AI 분석 결과의 오류로 인한 손해에 대해 회사는 책임지지 않습니다. 무단 수집에 대한 법적 책임은 사용자에게 있습니다.</p>
        """)

    def _get_consent_html_ja(self) -> str:
        """Japanese consent HTML"""
        td = self._consent_td_style()
        th = self._consent_th_style()
        return self._consent_html_wrapper(f"""
        <h3 style="color: {COLORS['brand_primary']}; border-bottom: 2px solid {COLORS['brand_primary']}; padding-bottom: 8px;">
            1. 個人情報の収集・利用に関する同意</h3>
        <table style="{self._consent_table_style()}">
            <tr><th style="{th}; width:25%;">項目</th><th style="{th}">内容</th></tr>
            <tr><td style="{td}"><b>収集目的</b></td><td style="{td}">デジタルインテリジェンス分析、セキュリティインシデント調査、データ取得、AI異常検知</td></tr>
            <tr><td style="{td}"><b>収集項目</b></td><td style="{td}"><b>[システム]</b> Prefetch、Amcache、UserAssist、イベントログ、レジストリ、MFT、USN Journal<br><b>[ユーザー活動]</b> ブラウザ履歴、USB接続履歴、ごみ箱、ショートカット、ジャンプリスト<br><b>[文書/メール]</b> Office文書、PDF、HWP、メール</td></tr>
            <tr><td style="{td}"><b>保存期間</b></td><td style="{td}"><b>30日間</b>（ケース終了後自動削除）</td></tr>
            <tr><td style="{td}"><b>処理方法</b></td><td style="{td}">SHA-256ハッシュ検証、TLS 1.3暗号化通信、AES-256-GCM暗号化保存</td></tr>
        </table>

        <h3 style="color: {COLORS['warning']}; border-bottom: 2px solid {COLORS['warning']}; padding-bottom: 8px;">
            2. 海外データ移転に関する告知</h3>
        <p style="background: rgba(210,153,34,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['warning']};">
            <b>告知：</b>収集されたデータは海外サーバーに移転される場合があります。同意されない場合、サービス利用が制限されます。</p>
        {self._consent_transfer_table("ja")}

        <h3 style="color: {COLORS['brand_accent']}; border-bottom: 2px solid {COLORS['brand_accent']}; padding-bottom: 8px;">
            3. AI分析および自動化された意思決定に関する告知</h3>
        <ul>
            <li><b>AI使用：</b>パターン認識、異常検知、相関分析、自動レポート生成</li>
            <li><b>自動判定：</b>不審な活動、マルウェア指標等をAIが自動判定（<u>参考用</u>）</li>
            <li><b>制限事項：</b>誤検知、検知漏れ、ハルシネーションが発生する可能性があります</li>
            <li><b>権利：</b>拒否権、説明要求権、人的介入要求権を行使できます</li>
        </ul>

        <h3 style="color: {COLORS['success']}; border-bottom: 2px solid {COLORS['success']}; padding-bottom: 8px;">
            4. データ主体の権利</h3>
        <ul>
            <li><b>アクセス権：</b>収集された個人情報へのアクセスを要求できます</li>
            <li><b>訂正権：</b>不正確な情報の訂正を要求できます</li>
            <li><b>消去権：</b>個人情報の削除を要求できます</li>
            <li><b>処理制限権：</b>個人情報処理の停止を要求できます</li>
            <li><b>同意撤回権：</b>いつでも同意を撤回できます</li>
            <li><b>データポータビリティ権：</b>収集された個人情報を機械可読形式で受け取ることができます</li>
        </ul>
        <p>お問い合わせ：support@forensics-ai.com | 個人情報保護責任者：privacy@forensics-ai.com</p>

        <h3 style="color: {COLORS['error']}; border-bottom: 2px solid {COLORS['error']}; padding-bottom: 8px;">
            5. 法的警告および免責事項</h3>
        <p style="background: rgba(248,81,73,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['error']};">
            <b>警告：</b>他人のシステムから無断でデータを収集する行為は法律により処罰される場合があります。</p>
        <ul>
            <li><b>ご自身のシステム：</b>本同意書で十分です</li>
            <li><b>他人のシステム：</b>システム所有者の書面による同意または法的根拠（令状等）が必要です</li>
            <li><b>企業内部調査：</b>法務チームの検証および労働法の遵守が必要です</li>
        </ul>
        """)

    def _get_consent_html_zh(self) -> str:
        """Chinese consent HTML"""
        td = self._consent_td_style()
        th = self._consent_th_style()
        return self._consent_html_wrapper(f"""
        <h3 style="color: {COLORS['brand_primary']}; border-bottom: 2px solid {COLORS['brand_primary']}; padding-bottom: 8px;">
            1. 个人信息收集和使用同意</h3>
        <table style="{self._consent_table_style()}">
            <tr><th style="{th}; width:25%;">项目</th><th style="{th}">说明</th></tr>
            <tr><td style="{td}"><b>收集目的</b></td><td style="{td}">数字智能分析、安全事件调查、数据获取、基于AI的异常检测</td></tr>
            <tr><td style="{td}"><b>收集项目</b></td><td style="{td}"><b>[系统]</b> Prefetch、Amcache、UserAssist、事件日志、注册表、MFT、USN Journal<br><b>[用户活动]</b> 浏览器历史、USB连接记录、回收站、快捷方式、跳转列表<br><b>[文档/邮件]</b> Office文档、PDF、HWP、邮件</td></tr>
            <tr><td style="{td}"><b>保留期限</b></td><td style="{td}"><b>30天</b>（案件结束后自动删除）</td></tr>
            <tr><td style="{td}"><b>处理方法</b></td><td style="{td}">SHA-256哈希验证、TLS 1.3加密通信、AES-256-GCM加密存储</td></tr>
        </table>

        <h3 style="color: {COLORS['warning']}; border-bottom: 2px solid {COLORS['warning']}; padding-bottom: 8px;">
            2. 跨境数据传输告知</h3>
        <p style="background: rgba(210,153,34,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['warning']};">
            <b>告知：</b>收集的数据可能会传输到海外服务器。如不同意，服务使用可能受到限制。</p>
        {self._consent_transfer_table("zh")}

        <h3 style="color: {COLORS['brand_accent']}; border-bottom: 2px solid {COLORS['brand_accent']}; padding-bottom: 8px;">
            3. AI分析及自动化决策告知</h3>
        <ul>
            <li><b>AI使用：</b>模式识别、异常检测、关联分析、自动报告生成</li>
            <li><b>自动判断：</b>AI自动识别可疑活动、恶意软件指标等（<u>仅供参考</u>）</li>
            <li><b>局限性：</b>可能出现误报、漏报和AI幻觉</li>
            <li><b>您的权利：</b>拒绝权、解释请求权、人工干预请求权</li>
        </ul>

        <h3 style="color: {COLORS['success']}; border-bottom: 2px solid {COLORS['success']}; padding-bottom: 8px;">
            4. 数据主体权利</h3>
        <ul>
            <li><b>访问权：</b>可请求访问收集的个人信息</li>
            <li><b>更正权：</b>可请求更正不准确的信息</li>
            <li><b>删除权：</b>可请求删除个人信息</li>
            <li><b>限制处理权：</b>可请求暂停个人信息处理</li>
            <li><b>撤回同意权：</b>可随时撤回同意</li>
            <li><b>数据可携权：</b>可请求以机器可读格式获取收集的个人信息</li>
        </ul>
        <p>联系方式：support@forensics-ai.com | 个人信息保护负责人：privacy@forensics-ai.com</p>

        <h3 style="color: {COLORS['error']}; border-bottom: 2px solid {COLORS['error']}; padding-bottom: 8px;">
            5. 法律警告及免责声明</h3>
        <p style="background: rgba(248,81,73,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['error']};">
            <b>警告：</b>未经授权从他人系统收集数据可能违反相关法律。</p>
        <ul>
            <li><b>本人系统：</b>本同意书即可</li>
            <li><b>他人系统：</b>需要系统所有者的书面同意或法律依据（搜查令等）</li>
            <li><b>企业内部调查：</b>需要法务团队审查及劳动法合规</li>
        </ul>
        """)

    def _update_button_state(self):
        """Enable button based on checkbox state (all checkboxes must be checked)"""
        all_checked = all(cb.isChecked() for cb in self.checkboxes) if self.checkboxes else False
        self.agree_btn.setEnabled(all_checked)

    def _on_agree(self):
        """Agree button clicked"""
        # Submit consent record to server
        self._submit_consent_to_server()

        self.consent_given = True
        self.consent_record = self._create_consent_record()
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

        # Consent record hash (integrity)
        items_str = "|".join(agreed_items)
        record_str = f"{timestamp}|{hostname_hash}|{ip_hash}|{items_str}"
        record["consent_hash"] = hashlib.sha256(record_str.encode()).hexdigest()

        # HMAC signature
        signing_key = os.getenv("CONSENT_SIGNING_KEY")
        if not signing_key:
            # Fallback: random key (signature for local integrity only)
            signing_key = hashlib.sha256(os.urandom(32)).hexdigest()[:32]

        verify_payload = f"{timestamp}|{record['consent_version']}|{record['consent_hash']}"
        record["server_verify_signature"] = hmac.new(
            signing_key.encode(),
            verify_payload.encode(),
            hashlib.sha256
        ).hexdigest()

        record["_verification"] = {
            "algorithm": "HMAC-SHA256",
            "signed_at": timestamp,
            "payload_fields": ["consent_timestamp", "consent_version", "consent_hash"]
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
    language: str = "en"
) -> Optional[dict]:
    """
    Display consent dialog and return result

    Args:
        parent: Parent widget
        server_url: API server URL (e.g., http://localhost:8000)
        session_id: Collection session ID
        case_id: Case ID
        language: Default language code (en, ko, ja, zh)

    Returns:
        Consent record dict (if agreed) or None (if cancelled)
    """
    dialog = ConsentDialog(
        parent=parent,
        server_url=server_url,
        session_id=session_id,
        case_id=case_id,
        language=language
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
        print("Consent accepted:", record)
    else:
        print("Consent rejected or cancelled")
