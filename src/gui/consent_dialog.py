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
        self.setWindowTitle("AI Forensic Lab - Data Collection Consent")
        self.setMinimumSize(700, 620)
        self.setMaximumSize(800, 720)
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
        self.header_label.setText(template.get("title", "AI Forensic Lab - Data Collection Consent"))
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
        self.template_version = "offline-2.2"
        self.template_content = self._get_consent_html()

        # Header text (by language)
        header_texts = {
            "ko": "디지털 데이터 수집 동의서",
            "ja": "デジタルデータ収集同意書",
            "zh": "数字数据收集同意书",
            "en": "AI Forensic Lab - Data Collection Consent"
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
        """Data transfer table with provider details (offline fallback included)"""
        th = self._consent_th_style()
        td = self._consent_td_style()
        headers = {
            "ko": ("수탁 업체", "위탁 업무", "이전 국가", "이전 항목"),
            "en": ("Provider", "Service", "Country", "Data Items"),
            "ja": ("受託業者", "委託業務", "移転先国", "移転項目"),
            "zh": ("受托方", "委托业务", "传输国家", "传输项目"),
        }
        h = headers.get(lang, headers["en"])
        # (name, contact, service, country, items, retention)
        providers = [
            ('RunPod', 'support@runpod.io',
             {'ko':'AI 분석, DB/캐시', 'en':'AI analysis, DB/cache', 'ja':'AI分析、DB/キャッシュ', 'zh':'AI分析、DB/缓存'},
             {'ko':'일본/북미/유럽', 'en':'Japan/NA/EU', 'ja':'日本/北米/欧州', 'zh':'日本/北美/欧洲'},
             {'ko':'암호화 분석 데이터', 'en':'Encrypted analysis data', 'ja':'暗号化分析データ', 'zh':'加密分析数据'},
             {'ko':'분석 완료 즉시 삭제', 'en':'Deleted upon completion', 'ja':'分析完了後即時削除', 'zh':'分析完成后立即删除'}),
            ('Cloudflare R2', 'https://cloudflare.com/trust-hub/contact',
             {'ko':'아티팩트 보관', 'en':'Artifact storage', 'ja':'アーティファクト保管', 'zh':'工件存储'},
             {'ko':'글로벌 CDN', 'en':'Global CDN', 'ja':'グローバルCDN', 'zh':'全球CDN'},
             {'ko':'암호화 아티팩트', 'en':'Encrypted artifacts', 'ja':'暗号化アーティファクト', 'zh':'加密工件'},
             {'ko':'사용자 설정 기간 (기본 30일)', 'en':'User-set period (default 30 days)', 'ja':'ユーザー設定期間（デフォルト30日）', 'zh':'用户设定期限（默认30天）'}),
            ('Clerk, Inc.', 'support@clerk.dev',
             {'ko':'회원 인증', 'en':'Authentication', 'ja':'会員認証', 'zh':'会员认证'},
             {'ko':'미국', 'en':'USA', 'ja':'米国', 'zh':'美国'},
             {'ko':'이메일, OAuth 정보', 'en':'Email, OAuth info', 'ja':'メール、OAuth情報', 'zh':'邮箱、OAuth信息'},
             {'ko':'회원 탈퇴 시 삭제', 'en':'Deleted on account closure', 'ja':'退会時削除', 'zh':'注销账户时删除'}),
            ('Stripe, Inc.', 'https://stripe.com/contact',
             {'ko':'결제 처리', 'en':'Payment processing', 'ja':'決済処理', 'zh':'支付处理'},
             {'ko':'미국', 'en':'USA', 'ja':'米国', 'zh':'美国'},
             {'ko':'결제 정보', 'en':'Payment info', 'ja':'決済情報', 'zh':'支付信息'},
             {'ko':'법정 보존 기간 (5년)', 'en':'Legal retention (5 years)', 'ja':'法定保存期間（5年）', 'zh':'法定保存期限（5年）'}),
        ]
        # Add retention period column header
        headers_ext = {
            'ko': ('수탁 업체 (연락처)', '위탁 업무', '이전 국가', '이전 항목', '보유 기간'),
            'en': ('Provider (Contact)', 'Service', 'Country', 'Data Items', 'Retention'),
            'ja': ('受託業者（連絡先）', '委託業務', '移転先国', '移転項目', '保有期間'),
            'zh': ('受托方（联系方式）', '委托业务', '传输国家', '传输项目', '保留期限'),
        }
        h = headers_ext.get(lang, headers_ext['en'])
        th_cells = ''.join(f"<th style='{th}'>{c}</th>" for c in h)
        tbl = f'<table style="{self._consent_table_style()}"><tr>{th_cells}</tr>'
        for name, contact, svc, ctry, itm, ret in providers:
            s = svc.get(lang, svc['en'])
            c = ctry.get(lang, ctry['en'])
            i = itm.get(lang, itm['en'])
            r = ret.get(lang, ret['en'])
            tbl += f'<tr><td style="{td}"><b>{name}</b><br><small>{contact}</small></td><td style="{td}">{s}</td><td style="{td}">{c}</td><td style="{td}">{i}</td><td style="{td}">{r}</td></tr>'
        tbl += '</table>'
        # Transfer method and refusal notice
        notices = {
            'ko': '<p><b>이전 시기:</b> 서비스 이용 시 실시간 | <b>이전 방법:</b> TLS 1.3 암호화 전송, AES-256-GCM 암호화 저장</p><p><b>이전 거부:</b> 동의 체크박스를 선택하지 않으면 이전이 거부됩니다. 거부 시 데이터 수집·분석 서비스를 이용할 수 없습니다.</p>',
            'en': '<p><b>Transfer timing:</b> Real-time during service use | <b>Transfer method:</b> TLS 1.3 encrypted transmission, AES-256-GCM encrypted storage</p><p><b>Refusal:</b> Uncheck the consent checkbox to refuse. If refused, data collection and analysis services cannot be used.</p>',
            'ja': '<p><b>移転時期：</b>サービス利用時にリアルタイム | <b>移転方法：</b>TLS 1.3暗号化通信、AES-256-GCM暗号化保存</p><p><b>移転拒否：</b>同意チェックボックスを選択しなければ移転が拒否されます。拒否した場合、データ収集・分析サービスをご利用いただけません。</p>',
            'zh': '<p><b>传输时间：</b>使用服务时实时传输 | <b>传输方法：</b>TLS 1.3加密传输、AES-256-GCM加密存储</p><p><b>拒绝传输：</b>不选择同意复选框即可拒绝。拒绝后将无法使用数据收集和分析服务。</p>',
        }
        tbl += notices.get(lang, notices['en'])
        return tbl

    def _get_consent_html_en(self) -> str:
        """English consent HTML"""
        td = self._consent_td_style()
        th = self._consent_th_style()
        return self._consent_html_wrapper(f"""
        <div style="margin-bottom:12px; padding:8px; background:{COLORS['bg_secondary']}; border-radius:4px; font-size:11px; color:{COLORS['text_secondary']};">
            Version: v2.2 | Effective: 2026-03-21 | unJaena AI</div>
        <h3 style="color: {COLORS['brand_primary']}; border-bottom: 2px solid {COLORS['brand_primary']}; padding-bottom: 8px;">
            1. Personal Information Collection and Use Consent</h3>
        <table style="{self._consent_table_style()}">
            <tr><th style="{th}; width:25%;">Item</th><th style="{th}">Description</th></tr>
            <tr><td style="{td}"><b>Collection Purpose</b></td><td style="{td}">Digital intelligence analysis, security incident investigation, evidence acquisition, AI-based anomaly detection</td></tr>
            <tr><td style="{td}"><b>Collection Items</b></td><td style="{td}"><b>[Windows]</b> Registry, Event logs, Prefetch, Amcache, UserAssist, MFT, USN Journal, $LogFile, SRUM, Jump lists, Shortcuts, Recycle Bin, Browser history/cookies, USB history, Scheduled tasks, WMI, PowerShell history, Remote access logs (TeamViewer/AnyDesk), pagefile.sys, hiberfil.sys<br><b>[Android]</b> SMS/MMS, Call logs, Contacts, Calendar, Media files (photos/videos), WiFi settings, Location history, Installed apps, System logs, Messenger data (KakaoTalk, WhatsApp, Telegram, LINE, etc.)<br><b>[iOS]</b> iMessage/SMS, Call history, Contacts, Safari/Chrome history, Location data, System logs, Messenger data, Backup metadata, Device information<br><b>[Linux]</b> System/Auth/Kernel logs, Shell history, Crontab, SSH keys, Network config, Package history, Docker config<br><b>[macOS]</b> Unified logs, Launch agents/daemons, Browser history, Keychain metadata, FSEvents, Spotlight, TCC permissions, KnowledgeC<br><b>[Memory]</b> Physical RAM acquisition (WinPmem), Process memory of running applications<br><b>[Documents/Email]</b> Office documents, PDF, HWP, Email (pst/ost/eml/msg), Images/Videos with metadata</td></tr>
            <tr><td style="{td}"><b>Retention Period</b></td><td style="{td}"><b>30 days</b> after case closure (automatically deleted). Retention may be extended using credits via the web platform.</td></tr>
            <tr><td style="{td}"><b>Processing Method</b></td><td style="{td}">SHA-256 hash verification, TLS 1.3 encryption, AES-256-GCM storage, Evidence Integrity Tracking. While we apply industry-leading security measures, absolute security over internet transmission is technically impossible.</td></tr>
            <tr><td style="{td}"><b>Right to Refuse</b></td><td style="{td}">You have the right to refuse consent. If you refuse, data collection and analysis services cannot be provided.</td></tr>
        </table>

        <h3 style="color: {COLORS['warning']}; border-bottom: 2px solid {COLORS['warning']}; padding-bottom: 8px;">
            2. Cross-Border Data Transfer Notice</h3>
        <p style="background: rgba(210,153,34,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['warning']};">
            <b>Notice:</b> Collected data may be transferred overseas. If you do not consent, service may be limited.</p>
        {self._consent_transfer_table("en")}

        <h3 style="color: {COLORS['brand_accent']}; border-bottom: 2px solid {COLORS['brand_accent']}; padding-bottom: 8px;">
            3. AI Analysis and Automated Decision-Making Notice</h3>
        <p style="background: rgba(212,165,116,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['brand_accent']};">
            <b>Notice pursuant to applicable AI and privacy regulations (PIPA Art. 37-2, GDPR Art. 22)</b></p>
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
        <p>Contact: admin@unjaena.com | Company: unJaena AI | Representative: Sangjun Park</p>

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
            <b>Disclaimer:</b> unJaena AI does not guarantee the accuracy, completeness, or reliability of collected data or AI analysis results. Metadata timestamps may not reflect actual events due to system clock variations or file system behavior. unJaena AI is not liable for damages from AI analysis errors. However, this does not apply to damages caused by willful misconduct or gross negligence. All liability for unauthorized collection rests with the user.</p>

        <h3 style="color: {COLORS['text_secondary']}; border-bottom: 2px solid {COLORS['text_secondary']}; padding-bottom: 8px;">
            6. Age Restriction</h3>
        <p style="background: rgba(100,100,100,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['text_secondary']};">
            This service is intended for users aged <b>16 or older</b>. Users under 16 require consent from a parent or legal guardian. Users under 13 may not use this service under any circumstances (COPPA).</p>

        <h3 style="color: {COLORS['text_secondary']}; border-bottom: 2px solid {COLORS['text_secondary']}; padding-bottom: 8px;">
            7. Governing Law &amp; Jurisdiction</h3>
        <p style="background: rgba(100,100,100,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['text_secondary']};">
            This agreement and all disputes arising from the use of this service shall be governed by the laws of the <b>Republic of Korea</b>. The <b>Seoul Central District Court</b> shall have exclusive jurisdiction over any disputes.</p>
        """)

    def _get_consent_html_ko(self) -> str:
        """Korean consent HTML"""
        td = self._consent_td_style()
        th = self._consent_th_style()
        return self._consent_html_wrapper(f"""
        <div style="margin-bottom:12px; padding:8px; background:{COLORS['bg_secondary']}; border-radius:4px; font-size:11px; color:{COLORS['text_secondary']};">
            버전: v2.2 | 시행일: 2026-03-21 | unJaena AI</div>
        <h3 style="color: {COLORS['brand_primary']}; border-bottom: 2px solid {COLORS['brand_primary']}; padding-bottom: 8px;">
            1. 개인정보 수집·이용 동의</h3>
        <table style="{self._consent_table_style()}">
            <tr><th style="{th}; width:25%;">항목</th><th style="{th}">내용</th></tr>
            <tr><td style="{td}"><b>수집 목적</b></td><td style="{td}">디지털 인텔리전스 분석, 보안 사고 조사, 증거 확보, AI 기반 이상 탐지</td></tr>
            <tr><td style="{td}"><b>수집 항목</b></td><td style="{td}"><b>[Windows]</b> 레지스트리, 이벤트 로그, Prefetch, Amcache, UserAssist, MFT, USN Journal, $LogFile, SRUM, 점프 목록, 바로가기, 휴지통, 브라우저 기록/쿠키, USB 기록, 예약 작업, WMI, PowerShell 기록, 원격접속 로그(TeamViewer/AnyDesk), pagefile.sys, hiberfil.sys<br><b>[Android]</b> SMS/MMS, 통화 기록, 연락처, 캘린더, 미디어 파일(사진/영상), WiFi 설정, 위치 기록, 설치된 앱, 시스템 로그, 메신저 데이터(카카오톡, WhatsApp, Telegram, LINE 등)<br><b>[iOS]</b> iMessage/SMS, 통화 기록, 연락처, Safari/Chrome 기록, 위치 데이터, 시스템 로그, 메신저 데이터, 백업 메타데이터, 기기 정보<br><b>[Linux]</b> 시스템/인증/커널 로그, 쉘 히스토리, Crontab, SSH 키, 네트워크 설정, 패키지 이력, Docker 설정<br><b>[macOS]</b> 통합 로그, Launch Agent/Daemon, 브라우저 기록, Keychain 메타데이터, FSEvents, Spotlight, TCC 권한, KnowledgeC<br><b>[메모리]</b> 물리 메모리 수집(RAM 덤프), 실행 중인 앱 프로세스 메모리<br><b>[문서/이메일]</b> Office 문서, PDF, HWP, 이메일(pst/ost/eml/msg), 이미지/영상 및 메타데이터</td></tr>
            <tr><td style="{td}"><b>보관 기간</b></td><td style="{td}"><b>30일</b> (케이스 종료 후 자동 삭제). 웹 플랫폼에서 크레딧을 사용하여 보관 기간을 연장할 수 있습니다.</td></tr>
            <tr><td style="{td}"><b>처리 방법</b></td><td style="{td}">SHA-256 해시 검증, TLS 1.3 암호화 통신, AES-256-GCM 암호화 저장, 증거 무결성 추적(Evidence Integrity Tracking). 업계 최고 수준의 보안 조치를 적용하고 있으나, 인터넷 전송 환경에서 절대적인 보안은 기술적으로 불가능합니다.</td></tr>
            <tr><td style="{td}"><b>동의 거부권</b></td><td style="{td}">귀하는 동의를 거부할 권리가 있습니다. 동의를 거부하실 경우 데이터 수집 및 분석 서비스 이용이 불가합니다.</td></tr>
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
        <p>권리 행사: admin@unjaena.com | 회사: unJaena AI | 대표자: 박상준</p>

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
            <b>면책:</b> unJaena AI는 수집된 데이터 또는 AI 분석 결과의 정확성, 완전성, 신뢰성을 보증하지 않습니다. 메타데이터 타임스탬프는 시스템 시계 변동이나 파일 시스템 동작으로 인해 실제 이벤트를 반영하지 않을 수 있습니다. AI 분석 결과의 오류로 인한 손해에 대해 unJaena AI는 책임지지 않습니다. 단, 고의 또는 중대한 과실로 인한 손해는 제외합니다. 무단 수집에 대한 법적 책임은 사용자에게 있습니다.</p>

        <h3 style="color: {COLORS['text_secondary']}; border-bottom: 2px solid {COLORS['text_secondary']}; padding-bottom: 8px;">
            6. 연령 제한</h3>
        <p style="background: rgba(100,100,100,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['text_secondary']};">
            본 서비스는 <b>만 16세 이상</b>의 사용자를 대상으로 합니다. 만 16세 미만은 부모 또는 법정 대리인의 동의가 필요합니다. 만 13세 미만은 어떠한 경우에도 본 서비스를 이용할 수 없습니다 (COPPA).</p>

        <h3 style="color: {COLORS['text_secondary']}; border-bottom: 2px solid {COLORS['text_secondary']}; padding-bottom: 8px;">
            7. 준거법 및 관할법원</h3>
        <p style="background: rgba(100,100,100,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['text_secondary']};">
            본 동의서 및 서비스 이용과 관련된 모든 분쟁은 <b>대한민국 법률</b>에 따라 해석되며, <b>서울중앙지방법원</b>을 전속 관할법원으로 합니다.</p>
        """)

    def _get_consent_html_ja(self) -> str:
        """Japanese consent HTML"""
        td = self._consent_td_style()
        th = self._consent_th_style()
        return self._consent_html_wrapper(f"""
        <div style="margin-bottom:12px; padding:8px; background:{COLORS['bg_secondary']}; border-radius:4px; font-size:11px; color:{COLORS['text_secondary']};">
            バージョン: v2.2 | 施行日: 2026-03-21 | unJaena AI</div>
        <h3 style="color: {COLORS['brand_primary']}; border-bottom: 2px solid {COLORS['brand_primary']}; padding-bottom: 8px;">
            1. 個人情報の収集・利用に関する同意</h3>
        <table style="{self._consent_table_style()}">
            <tr><th style="{th}; width:25%;">項目</th><th style="{th}">内容</th></tr>
            <tr><td style="{td}"><b>収集目的</b></td><td style="{td}">デジタルインテリジェンス分析、セキュリティインシデント調査、証拠取得、AI異常検知</td></tr>
            <tr><td style="{td}"><b>収集項目</b></td><td style="{td}"><b>[Windows]</b> レジストリ、イベントログ、Prefetch、Amcache、UserAssist、MFT、USN Journal、$LogFile、SRUM、ジャンプリスト、ショートカット、ごみ箱、ブラウザ履歴/Cookie、USB履歴、タスクスケジューラ、WMI、PowerShell履歴、リモートアクセスログ（TeamViewer/AnyDesk）、pagefile.sys、hiberfil.sys<br><b>[Android]</b> SMS/MMS、通話履歴、連絡先、カレンダー、メディアファイル（写真/動画）、WiFi設定、位置情報、インストール済みアプリ、システムログ、メッセンジャーデータ（KakaoTalk、WhatsApp、Telegram、LINE等）<br><b>[iOS]</b> iMessage/SMS、通話履歴、連絡先、Safari/Chrome履歴、位置データ、システムログ、メッセンジャーデータ、バックアップメタデータ、デバイス情報<br><b>[Linux]</b> システム/認証/カーネルログ、シェル履歴、Crontab、SSHキー、ネットワーク設定、パッケージ履歴、Docker設定<br><b>[macOS]</b> 統合ログ、Launch Agent/Daemon、ブラウザ履歴、Keychainメタデータ、FSEvents、Spotlight、TCC権限、KnowledgeC<br><b>[メモリ]</b> 物理メモリ取得（RAMダンプ）、実行中アプリのプロセスメモリ<br><b>[文書/メール]</b> Office文書、PDF、HWP、メール（pst/ost/eml/msg）、画像/動画及びメタデータ</td></tr>
            <tr><td style="{td}"><b>保存期間</b></td><td style="{td}"><b>30日間</b>（ケース終了後自動削除）。Webプラットフォームでクレジットを使用して保存期間を延長できます。</td></tr>
            <tr><td style="{td}"><b>処理方法</b></td><td style="{td}">SHA-256ハッシュ検証、TLS 1.3暗号化通信、AES-256-GCM暗号化保存、証拠完全性追跡（Evidence Integrity Tracking）。業界最高水準のセキュリティ対策を講じていますが、インターネット通信における絶対的なセキュリティは技術的に不可能です。</td></tr>
            <tr><td style="{td}"><b>同意拒否権</b></td><td style="{td}">同意を拒否する権利があります。拒否された場合、データ収集・分析サービスをご利用いただけません。</td></tr>
        </table>

        <h3 style="color: {COLORS['warning']}; border-bottom: 2px solid {COLORS['warning']}; padding-bottom: 8px;">
            2. 海外データ移転に関する告知</h3>
        <p style="background: rgba(210,153,34,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['warning']};">
            <b>告知：</b>収集されたデータは海外サーバーに移転される場合があります。同意されない場合、サービス利用が制限されます。</p>
        {self._consent_transfer_table("ja")}

        <h3 style="color: {COLORS['brand_accent']}; border-bottom: 2px solid {COLORS['brand_accent']}; padding-bottom: 8px;">
            3. AI分析および自動化された意思決定に関する告知</h3>
        <p style="background: rgba(212,165,116,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['brand_accent']};">
            <b>個人情報保護法および関連するAI規制に基づく告知</b></p>
        <ul>
            <li><b>AI使用：</b>パターン認識、異常検知、相関分析、自動レポート生成</li>
            <li><b>自動判定：</b>不審な活動、マルウェア指標等をAIが自動判定（<u>参考用</u>）</li>
            <li><b>制限事項：</b>誤検知（False Positive）、検知漏れ（False Negative）、ハルシネーション（Hallucination）が発生する可能性があります</li>
            <li style="color: {COLORS['error']};"><b>法的リスク：</b>AI分析結果に基づく法的措置は紛争を招く可能性があります。必ず専門家にご相談ください</li>
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
        <p>お問い合わせ：admin@unjaena.com | 会社：unJaena AI | 代表者：朴相俊</p>

        <h3 style="color: {COLORS['error']}; border-bottom: 2px solid {COLORS['error']}; padding-bottom: 8px;">
            5. 法的警告および免責事項</h3>
        <p style="background: rgba(248,81,73,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['error']};">
            <b>警告：</b>他人のシステムから無断でデータを収集する行為は法律により処罰される場合があります。</p>
        <ul>
            <li><b>ご自身のシステム：</b>本同意書で十分です</li>
            <li><b>他人のシステム：</b>システム所有者の書面による同意または法的根拠（令状等）が必要です</li>
            <li><b>企業内部調査：</b>法務チームの検証および労働法の遵守が必要です</li>
        </ul>
        <p style="background: rgba(100,100,100,0.2); padding: 12px; border-radius: 8px; margin-top: 12px;">
            <b>免責事項：</b>unJaena AIは、収集されたデータまたはAI分析結果の正確性、完全性、信頼性を保証しません。メタデータのタイムスタンプは、システムクロックの変動やファイルシステムの動作により、実際のイベントを反映していない場合があります。AI分析結果の誤りに起因する損害について、unJaena AIは責任を負いません。ただし、故意または重大な過失による損害は除きます。無断でのデータ収集に起因するすべての法的責任は利用者が負うものとします。</p>

        <h3 style="color: {COLORS['text_secondary']}; border-bottom: 2px solid {COLORS['text_secondary']}; padding-bottom: 8px;">
            6. 年齢制限</h3>
        <p style="background: rgba(100,100,100,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['text_secondary']};">
            本サービスは<b>16歳以上</b>のユーザーを対象としています。16歳未満の方は、保護者または法定代理人の同意が必要です。13歳未満の方は、いかなる場合も本サービスをご利用いただけません（COPPA）。</p>

        <h3 style="color: {COLORS['text_secondary']}; border-bottom: 2px solid {COLORS['text_secondary']}; padding-bottom: 8px;">
            7. 準拠法および管轄裁判所</h3>
        <p style="background: rgba(100,100,100,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['text_secondary']};">
            本同意書およびサービス利用に関するすべての紛争は、<b>大韓民国の法律</b>に従い解釈され、<b>ソウル中央地方裁判所</b>を専属管轄裁判所とします。</p>
        """)

    def _get_consent_html_zh(self) -> str:
        """Chinese consent HTML"""
        td = self._consent_td_style()
        th = self._consent_th_style()
        return self._consent_html_wrapper(f"""
        <div style="margin-bottom:12px; padding:8px; background:{COLORS['bg_secondary']}; border-radius:4px; font-size:11px; color:{COLORS['text_secondary']};">
            版本: v2.2 | 生效日期: 2026-03-21 | unJaena AI</div>
        <h3 style="color: {COLORS['brand_primary']}; border-bottom: 2px solid {COLORS['brand_primary']}; padding-bottom: 8px;">
            1. 个人信息收集和使用同意</h3>
        <table style="{self._consent_table_style()}">
            <tr><th style="{th}; width:25%;">项目</th><th style="{th}">说明</th></tr>
            <tr><td style="{td}"><b>收集目的</b></td><td style="{td}">数字智能分析、安全事件调查、证据获取、基于AI的异常检测</td></tr>
            <tr><td style="{td}"><b>收集项目</b></td><td style="{td}"><b>[Windows]</b> 注册表、事件日志、Prefetch、Amcache、UserAssist、MFT、USN Journal、$LogFile、SRUM、跳转列表、快捷方式、回收站、浏览器历史/Cookie、USB记录、计划任务、WMI、PowerShell历史、远程访问日志（TeamViewer/AnyDesk）、pagefile.sys、hiberfil.sys<br><b>[Android]</b> SMS/MMS、通话记录、联系人、日历、媒体文件（照片/视频）、WiFi设置、位置记录、已安装应用、系统日志、即时通讯数据（KakaoTalk、WhatsApp、Telegram、LINE等）<br><b>[iOS]</b> iMessage/SMS、通话记录、联系人、Safari/Chrome历史、位置数据、系统日志、即时通讯数据、备份元数据、设备信息<br><b>[Linux]</b> 系统/认证/内核日志、Shell历史、Crontab、SSH密钥、网络配置、软件包历史、Docker配置<br><b>[macOS]</b> 统一日志、Launch Agent/Daemon、浏览器历史、Keychain元数据、FSEvents、Spotlight、TCC权限、KnowledgeC<br><b>[内存]</b> 物理内存获取（RAM转储）、运行中应用的进程内存<br><b>[文档/邮件]</b> Office文档、PDF、HWP、邮件（pst/ost/eml/msg）、图片/视频及元数据</td></tr>
            <tr><td style="{td}"><b>保留期限</b></td><td style="{td}"><b>30天</b>（案件结束后自动删除）。可通过Web平台使用积分延长保留期限。</td></tr>
            <tr><td style="{td}"><b>处理方法</b></td><td style="{td}">SHA-256哈希验证、TLS 1.3加密通信、AES-256-GCM加密存储、证据完整性追踪（Evidence Integrity Tracking）。我们采用业界领先的安全措施，但互联网传输环境下的绝对安全在技术上是不可能的。</td></tr>
            <tr><td style="{td}"><b>拒绝同意权</b></td><td style="{td}">您有权拒绝同意。拒绝后将无法使用数据收集和分析服务。</td></tr>
        </table>

        <h3 style="color: {COLORS['warning']}; border-bottom: 2px solid {COLORS['warning']}; padding-bottom: 8px;">
            2. 跨境数据传输告知</h3>
        <p style="background: rgba(210,153,34,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['warning']};">
            <b>告知：</b>收集的数据可能会传输到海外服务器。如不同意，服务使用可能受到限制。</p>
        {self._consent_transfer_table("zh")}

        <h3 style="color: {COLORS['brand_accent']}; border-bottom: 2px solid {COLORS['brand_accent']}; padding-bottom: 8px;">
            3. AI分析及自动化决策告知</h3>
        <p style="background: rgba(212,165,116,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['brand_accent']};">
            <b>根据适用的AI及隐私保护相关法规的告知</b></p>
        <ul>
            <li><b>AI使用：</b>模式识别、异常检测、关联分析、自动报告生成</li>
            <li><b>自动判断：</b>AI自动识别可疑活动、恶意软件指标等（<u>仅供参考</u>）</li>
            <li><b>局限性：</b>可能出现误报（False Positive）、漏报（False Negative）和AI幻觉（Hallucination）</li>
            <li style="color: {COLORS['error']};"><b>法律风险：</b>基于AI分析结果采取法律行动可能引发争议。请务必咨询专业人士</li>
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
        <p>联系方式：admin@unjaena.com | 公司：unJaena AI | 代表人：朴相俊</p>

        <h3 style="color: {COLORS['error']}; border-bottom: 2px solid {COLORS['error']}; padding-bottom: 8px;">
            5. 法律警告及免责声明</h3>
        <p style="background: rgba(248,81,73,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['error']};">
            <b>警告：</b>未经授权从他人系统收集数据可能违反相关法律。</p>
        <ul>
            <li><b>本人系统：</b>本同意书即可</li>
            <li><b>他人系统：</b>需要系统所有者的书面同意或法律依据（搜查令等）</li>
            <li><b>企业内部调查：</b>需要法务团队审查及劳动法合规</li>
        </ul>
        <p style="background: rgba(100,100,100,0.2); padding: 12px; border-radius: 8px; margin-top: 12px;">
            <b>免责声明：</b>unJaena AI不保证所收集数据或AI分析结果的准确性、完整性或可靠性。元数据时间戳可能因系统时钟偏差或文件系统行为而无法反映实际事件。对于因AI分析结果错误导致的损失，unJaena AI不承担责任。但因故意或重大过失造成的损失除外。因未经授权收集数据而产生的所有法律责任由用户自行承担。</p>

        <h3 style="color: {COLORS['text_secondary']}; border-bottom: 2px solid {COLORS['text_secondary']}; padding-bottom: 8px;">
            6. 年龄限制</h3>
        <p style="background: rgba(100,100,100,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['text_secondary']};">
            本服务面向<b>16周岁及以上</b>用户。16周岁以下用户需获得父母或法定监护人的同意。13周岁以下用户在任何情况下均不得使用本服务（COPPA）。</p>

        <h3 style="color: {COLORS['text_secondary']}; border-bottom: 2px solid {COLORS['text_secondary']}; padding-bottom: 8px;">
            7. 准据法及管辖法院</h3>
        <p style="background: rgba(100,100,100,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['text_secondary']};">
            本同意书及因使用本服务产生的所有争议，适用<b>大韩民国法律</b>，由<b>首尔中央地方法院</b>专属管辖。</p>
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
