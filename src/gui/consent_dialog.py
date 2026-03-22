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
        self.template_version = "offline-2.3"
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
            Version: v2.3 | Effective: 2026-03-22 | unJaena AI</div>
        <h3 style="color: {COLORS['brand_primary']}; border-bottom: 2px solid {COLORS['brand_primary']}; padding-bottom: 8px;">
            1. Personal Information Collection and Use Consent</h3>
        <table style="{self._consent_table_style()}">
            <tr><th style="{th}; width:25%;">Item</th><th style="{th}">Description</th></tr>
            <tr><td style="{td}"><b>Legal Basis</b></td><td style="{td}">Your explicit consent (GDPR Art. 6(1)(a), PIPA Art. 15, APPI Art. 17, PIPL Art. 13). For law enforcement use: legitimate interest or legal obligation may apply.</td></tr>
            <tr><td style="{td}"><b>Collection Purpose</b></td><td style="{td}">Digital intelligence analysis, security incident investigation, evidence acquisition, AI-based anomaly detection</td></tr>
            <tr><td style="{td}"><b>Collection Items</b></td><td style="{td}"><b>[Windows]</b> Registry, Event logs, Prefetch, Amcache, UserAssist, MFT, USN Journal, $LogFile, SRUM, ShellBags, ThumbCache, Jump lists, Shortcuts, Recycle Bin, Browser data (history, cookies, saved passwords), USB history, Scheduled tasks, WMI, PowerShell history, Remote access logs (TeamViewer/AnyDesk/RDP), Activities Cache, Windows Defender logs, BITS jobs, Zone.Identifier, pagefile.sys, hiberfil.sys<br><b>[Android]</b> SMS/MMS, Call logs, Contacts, Calendar, Media files (photos/videos), WiFi settings, Location history, System logs, Installed apps, <u>Screen data via Accessibility Service</u>; <b>Messengers:</b> KakaoTalk, WhatsApp, Telegram, LINE, Signal, Discord, Viber, WeChat, Facebook Messenger, Instagram, Snapchat, Skype, BAND; <b>SNS:</b> Facebook, Twitter/X, TikTok, Reddit, Pinterest, LinkedIn, Threads; <b>Finance/Shopping:</b> KakaoBank, Toss, Upbit, BankSalad, KakaoPay, Baemin, Coupang, CoupangEats, Karrot, Yanolja; <b>Navigation:</b> TMAP, KakaoMap, NaverMap, KakaoTaxi; <b>Email/Browser:</b> Gmail, Samsung Email, Chrome, Samsung Browser; <b>Work:</b> Hiworks<br><b>[iOS]</b> iMessage/SMS, Call history, Contacts, Safari/Chrome history, Location data (consolidated.db), System/crash logs, Device info, Backup metadata; <b>Messengers:</b> KakaoTalk, WhatsApp, Telegram, LINE, Signal, Discord, Viber, WeChat, Facebook Messenger, Instagram, Snapchat, Skype; <b>SNS:</b> Facebook, TikTok, Reddit, Twitter/X, Pinterest, LinkedIn, Threads; <b>System:</b> Notes, Photos DB, Calendar, Reminders, Health (HealthKit), Screen Time, Voice Memos, Apple Maps, Find My, Wallet, Spotlight, Siri history, Voicemail, WiFi, Bluetooth, TCC permissions, KnowledgeC, VPN configs, Data usage, Accounts; <b>Search:</b> Naver, Google, NaverMap, Safari/Chrome tracking<br><b>[Linux]</b> System/Auth/Kernel logs, Shell history (bash/zsh/fish), Crontab, Systemd services/timers, SSH keys (including private keys), /etc/passwd, /etc/shadow (password hashes), /etc/group, sudoers, Network config (hosts, resolv, interfaces, iptables), Login records (wtmp/btmp/lastlog), Web server logs (Apache/Nginx), Package history (apt/yum), Docker config, Startup scripts<br><b>[macOS]</b> Unified logs, System/Install logs, Launch Agent/Daemon, Browser history (Safari/Chrome), Keychain metadata, FSEvents, Spotlight, TCC permissions, KnowledgeC, WiFi known networks, SSH keys, Quarantine events, Login items, Audit logs, Recent items, Dock/Terminal history<br><b>[Memory]</b> Physical RAM acquisition (WinPmem), Process memory of running applications, <u>Credential extraction (password hashes from memory)</u><br><b>[Documents/Email]</b> Office documents, PDF, HWP, Email (pst/ost/eml/msg), Images/Videos with EXIF/GPS metadata</td></tr>
            <tr><td style="{td}"><b>Retention Period</b></td><td style="{td}"><b>30 days</b> after case closure (automatically deleted). Retention may be extended using credits via the web platform.</td></tr>
            <tr><td style="{td}"><b>Processing Method</b></td><td style="{td}">SHA-256 hash verification, TLS 1.3 encryption, AES-256-GCM storage, Evidence Integrity Tracking. While we apply industry-leading security measures, absolute security over internet transmission is technically impossible.</td></tr>
            <tr><td style="{td}"><b>Right to Refuse</b></td><td style="{td}">You have the right to refuse consent. If you refuse, data collection and analysis services cannot be provided.</td></tr>
            <tr><td style="{td}"><b>Special Categories</b></td><td style="{td}">Collected data may incidentally include special categories of personal data (health, political opinions, religious beliefs, biometric data). By consenting, you provide explicit consent for processing such data for forensic analysis purposes only, pursuant to GDPR Art. 9(2)(a).</td></tr>
        </table>

        <h3 style="color: {COLORS['warning']}; border-bottom: 2px solid {COLORS['warning']}; padding-bottom: 8px;">
            2. Cross-Border Data Transfer Notice</h3>
        <p style="background: rgba(210,153,34,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['warning']};">
            <b>Notice:</b> Collected data may be transferred overseas. If you do not consent, service may be limited.</p>
        {self._consent_transfer_table("en")}
        <p style="margin-top:8px;"><b>Legal Transfer Mechanisms:</b> EU Standard Contractual Clauses (SCCs) with all providers. Korea PIPA Art. 28-8 entrustment agreements. Japan APPI Art. 28 safeguards. China PIPL Art. 38 standard contracts. Transfer safeguards are supplemented by technical measures (TLS 1.3, AES-256-GCM, zero-knowledge architecture).</p>

        <h3 style="color: {COLORS['brand_accent']}; border-bottom: 2px solid {COLORS['brand_accent']}; padding-bottom: 8px;">
            3. AI Analysis and Automated Decision-Making Notice</h3>
        <p style="background: rgba(212,165,116,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['brand_accent']};">
            <b>Notice pursuant to EU AI Act (2024/1689), PIPA Art. 37-2, GDPR Art. 22</b></p>
        <ul>
            <li><b>AI System Classification:</b> This system may be classified as high-risk under EU AI Act Annex III, 6(e) when used in law enforcement contexts. Appropriate human oversight is required.</li>
            <li><b>AI Processing:</b> Open-source LLM models (e.g., Qwen, LLaMA family, 14B+ parameters) process data <u>locally on the analysis server</u>. No data is sent to third-party AI providers (OpenAI, Google, etc.) unless explicitly configured.</li>
            <li><b>Analysis Methods:</b> MITRE ATT&CK kill-chain mapping (14 phases), evidence scoring with weighted algorithms, vector similarity search, cross-evidence correlation, temporal clustering. Note: routine activity may be categorized under attack phases — this does not indicate an actual attack occurred.</li>
            <li><b>Algorithmic Scoring:</b> Evidence is prioritized using automated scoring (keyword matching, temporal anomaly detection including night/weekend activity weighting, privilege indicators). These embedded assumptions may constitute algorithmic bias.</li>
            <li><b>Automated Decisions:</b> AI identifies suspicious activity, malware indicators, etc. for <u>reference only</u>.</li>
            <li style="color: {COLORS['error']};"><b>AI results are NOT independent legal evidence.</b> All findings must be verified by a qualified digital forensics examiner before any legal, disciplinary, or employment action. AI outputs must not be the sole basis for such actions.</li>
            <li><b>Limitations:</b> False positives/negatives may occur. AI hallucinations may fabricate file names, timestamps, malware identifiers, or causal relationships. Known false positive categories include standard Windows components, common business applications, and routine NTFS operations.</li>
            <li><b>Adversarial Risk:</b> Analyzed evidence may contain content designed to manipulate AI analysis. Protective measures are in place, but AI outputs could be influenced by adversarial data.</li>
            <li><b>Your Rights:</b> Right to refuse AI processing, right to explanation of AI decisions (contact admin@unjaena.com), right to human intervention within 5 business days of request.</li>
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
            <li><b>Right to Lodge Complaint:</b> You may file a complaint with your relevant data protection authority (e.g., PIPC (Korea), CNIL (France), ICO (UK), BfDI (Germany), CAC (China), PPC (Japan)).</li>
        </ul>
        <p style="background: rgba(46,160,67,0.15); padding: 10px; border-radius: 6px; margin-top:8px;"><b>Consent Withdrawal:</b> To withdraw consent, contact admin@unjaena.com or use the web platform. Withdrawal will trigger deletion of your data within 30 days. Withdrawal does not affect the lawfulness of processing performed before withdrawal.</p>
        <p>Contact: admin@unjaena.com | Company: unJaena AI</p>

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
            버전: v2.3 | 시행일: 2026-03-22 | unJaena AI</div>
        <h3 style="color: {COLORS['brand_primary']}; border-bottom: 2px solid {COLORS['brand_primary']}; padding-bottom: 8px;">
            1. 개인정보 수집·이용 동의</h3>
        <table style="{self._consent_table_style()}">
            <tr><th style="{th}; width:25%;">항목</th><th style="{th}">내용</th></tr>
            <tr><td style="{td}"><b>법적 근거</b></td><td style="{td}">귀하의 명시적 동의 (GDPR Art. 6(1)(a), 개인정보보호법 제15조, APPI 제17조, PIPL 제13조). 법 집행 목적: 정당한 이익 또는 법적 의무가 적용될 수 있습니다.</td></tr>
            <tr><td style="{td}"><b>수집 목적</b></td><td style="{td}">디지털 인텔리전스 분석, 보안 사고 조사, 증거 확보, AI 기반 이상 탐지</td></tr>
            <tr><td style="{td}"><b>수집 항목</b></td><td style="{td}"><b>[Windows]</b> 레지스트리, 이벤트 로그, Prefetch, Amcache, UserAssist, MFT, USN Journal, $LogFile, SRUM, ShellBags, ThumbCache, 점프 목록, 바로가기, 휴지통, 브라우저 데이터(기록, 쿠키, 저장된 비밀번호), USB 기록, 예약 작업, WMI, PowerShell 기록, 원격접속 로그(TeamViewer/AnyDesk/RDP), Activities Cache, Windows Defender 로그, BITS 작업, Zone.Identifier, pagefile.sys, hiberfil.sys<br><b>[Android]</b> SMS/MMS, 통화 기록, 연락처, 캘린더, 미디어 파일(사진/영상), WiFi 설정, 위치 기록, 시스템 로그, 설치된 앱, <u>접근성 서비스를 통한 화면 데이터</u>; <b>메신저:</b> 카카오톡, WhatsApp, Telegram, LINE, Signal, Discord, Viber, WeChat, Facebook Messenger, Instagram, Snapchat, Skype, BAND; <b>SNS:</b> Facebook, Twitter/X, TikTok, Reddit, Pinterest, LinkedIn, Threads; <b>금융/쇼핑:</b> 카카오뱅크, 토스, 업비트, 뱅크샐러드, 카카오페이, 배달의민족, 쿠팡, 쿠팡이츠, 당근마켓, 야놀자; <b>내비게이션:</b> TMAP, 카카오맵, 네이버지도, 카카오택시; <b>이메일/브라우저:</b> Gmail, 삼성 이메일, Chrome, 삼성 브라우저; <b>업무:</b> 하이웍스<br><b>[iOS]</b> iMessage/SMS, 통화 기록, 연락처, Safari/Chrome 기록, 위치 데이터(consolidated.db), 시스템/크래시 로그, 기기 정보, 백업 메타데이터; <b>메신저:</b> 카카오톡, WhatsApp, Telegram, LINE, Signal, Discord, Viber, WeChat, Facebook Messenger, Instagram, Snapchat, Skype; <b>SNS:</b> Facebook, TikTok, Reddit, Twitter/X, Pinterest, LinkedIn, Threads; <b>시스템:</b> 메모, 사진 DB, 캘린더, 미리알림, 건강(HealthKit), 스크린타임, 음성메모, Apple 지도, 나의 찾기, Wallet, Spotlight, Siri 기록, 음성사서함, WiFi, Bluetooth, TCC 권한, KnowledgeC, VPN 설정, 데이터 사용량, 계정; <b>검색:</b> 네이버, 구글, 네이버지도, Safari/Chrome 추적<br><b>[Linux]</b> 시스템/인증/커널 로그, 쉘 히스토리(bash/zsh/fish), Crontab, Systemd 서비스/타이머, SSH 키(개인키 포함), /etc/passwd, /etc/shadow(비밀번호 해시), /etc/group, sudoers, 네트워크 설정(hosts, resolv, interfaces, iptables), 로그인 기록(wtmp/btmp/lastlog), 웹서버 로그(Apache/Nginx), 패키지 이력(apt/yum), Docker 설정, 시작 스크립트<br><b>[macOS]</b> 통합 로그, 시스템/설치 로그, Launch Agent/Daemon, 브라우저 기록(Safari/Chrome), Keychain 메타데이터, FSEvents, Spotlight, TCC 권한, KnowledgeC, WiFi 알려진 네트워크, SSH 키, 격리 이벤트, 로그인 항목, 감사 로그, 최근 항목, Dock/터미널 기록<br><b>[메모리]</b> 물리 메모리 수집(RAM 덤프), 실행 중인 앱 프로세스 메모리, <u>자격증명 추출(메모리 내 비밀번호 해시)</u><br><b>[문서/이메일]</b> Office 문서, PDF, HWP, 이메일(pst/ost/eml/msg), 이미지/영상 및 EXIF/GPS 메타데이터</td></tr>
            <tr><td style="{td}"><b>보관 기간</b></td><td style="{td}"><b>30일</b> (케이스 종료 후 자동 삭제). 웹 플랫폼에서 크레딧을 사용하여 보관 기간을 연장할 수 있습니다.</td></tr>
            <tr><td style="{td}"><b>처리 방법</b></td><td style="{td}">SHA-256 해시 검증, TLS 1.3 암호화 통신, AES-256-GCM 암호화 저장, 증거 무결성 추적(Evidence Integrity Tracking). 업계 최고 수준의 보안 조치를 적용하고 있으나, 인터넷 전송 환경에서 절대적인 보안은 기술적으로 불가능합니다.</td></tr>
            <tr><td style="{td}"><b>동의 거부권</b></td><td style="{td}">귀하는 동의를 거부할 권리가 있습니다. 동의를 거부하실 경우 데이터 수집 및 분석 서비스 이용이 불가합니다.</td></tr>
            <tr><td style="{td}"><b>특수 범주 데이터</b></td><td style="{td}">수집된 데이터에는 건강, 정치적 견해, 종교적 신념, 생체 정보 등 민감한 개인정보가 포함될 수 있습니다. 동의하시면 GDPR 제9조 제2항 (a)호에 따라 포렌식 분석 목적으로만 이러한 데이터를 처리하는 데 명시적으로 동의하는 것입니다.</td></tr>
        </table>

        <h3 style="color: {COLORS['warning']}; border-bottom: 2px solid {COLORS['warning']}; padding-bottom: 8px;">
            2. 해외 데이터 이전 고지</h3>
        <p style="background: rgba(210,153,34,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['warning']};">
            <b>고지:</b> 수집된 데이터는 해외 서버로 이전될 수 있습니다. 동의하지 않으실 경우 서비스 이용이 제한됩니다.</p>
        {self._consent_transfer_table("ko")}
        <p style="margin-top:8px;"><b>이전 법적 근거:</b> EU 표준계약조항(SCC)을 모든 수탁업체와 체결. 개인정보보호법 제28조의8 위탁 계약. 일본 APPI 제28조 안전 조치. 중국 PIPL 제38조 표준 계약. 기술적 보호 조치(TLS 1.3, AES-256-GCM, 제로 지식 아키텍처)로 보완.</p>

        <h3 style="color: {COLORS['brand_accent']}; border-bottom: 2px solid {COLORS['brand_accent']}; padding-bottom: 8px;">
            3. AI 분석 및 자동화된 의사결정 고지</h3>
        <p style="background: rgba(212,165,116,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['brand_accent']};">
            <b>EU AI Act (2024/1689), 개인정보보호법 제37조의2, GDPR 제22조에 따른 고지</b></p>
        <ul>
            <li><b>AI 시스템 분류:</b> 본 시스템은 법 집행 맥락에서 사용 시 EU AI Act 부속서 III, 6(e)에 따라 고위험으로 분류될 수 있습니다. 적절한 인적 감독이 필요합니다.</li>
            <li><b>AI 처리:</b> 오픈소스 LLM 모델(예: Qwen, LLaMA 계열, 14B+ 파라미터)이 <u>분석 서버에서 로컬로</u> 데이터를 처리합니다. 명시적으로 설정하지 않는 한 제3자 AI 제공자(OpenAI, Google 등)에 데이터가 전송되지 않습니다.</li>
            <li><b>분석 방법:</b> MITRE ATT&CK 킬체인 매핑(14단계), 가중 알고리즘 기반 증거 점수화, 벡터 유사도 검색, 교차 증거 상관분석, 시간적 클러스터링. 참고: 일상적 활동이 공격 단계로 분류될 수 있으나, 이는 실제 공격이 발생했음을 의미하지 않습니다.</li>
            <li><b>알고리즘 점수화:</b> 증거는 자동 점수화(키워드 매칭, 야간/주말 활동 가중치 등 시간적 이상 감지, 권한 지표)를 통해 우선순위가 결정됩니다. 이러한 내장 가정은 알고리즘 편향을 구성할 수 있습니다.</li>
            <li><b>자동화된 판단:</b> 의심 활동, 악성코드 지표 등을 AI가 자동 판단 (<u>참고용</u>)</li>
            <li style="color: {COLORS['error']};"><b>AI 결과는 독립적인 법적 증거가 아닙니다.</b> 모든 발견 사항은 법적, 징계, 고용 조치 전에 자격을 갖춘 디지털 포렌식 전문가가 검증해야 합니다. AI 결과만으로 그러한 조치의 근거로 삼아서는 안 됩니다.</li>
            <li><b>한계:</b> 오탐(False Positive), 미탐(False Negative) 발생 가능. AI 환각(Hallucination)이 존재하지 않는 파일명, 타임스탬프, 악성코드 식별자, 인과관계를 생성할 수 있습니다. 알려진 오탐 카테고리: 표준 Windows 구성요소, 일반 비즈니스 앱, 정상 NTFS 작업.</li>
            <li><b>적대적 위험:</b> 분석 대상 증거에 AI 분석을 조작하도록 설계된 콘텐츠가 포함될 수 있습니다. 보호 조치가 적용되어 있지만, AI 출력이 적대적 데이터의 영향을 받을 수 있습니다.</li>
            <li><b>권리:</b> AI 처리 거부권, AI 결정에 대한 설명 요구권(admin@unjaena.com), 요청 후 영업일 5일 이내 인적 개입 요구권</li>
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
            <li><b>감독기관 민원권:</b> 관할 개인정보 보호 감독기관에 민원을 제기할 수 있습니다 (예: 개인정보보호위원회(한국), CNIL(프랑스), ICO(영국), BfDI(독일), CAC(중국), PPC(일본)).</li>
        </ul>
        <p style="background: rgba(46,160,67,0.15); padding: 10px; border-radius: 6px; margin-top:8px;"><b>동의 철회:</b> admin@unjaena.com으로 연락하거나 웹 플랫폼을 통해 동의를 철회할 수 있습니다. 철회 시 30일 이내에 데이터가 삭제됩니다. 철회 전에 수행된 처리의 적법성에는 영향을 미치지 않습니다.</p>
        <p>권리 행사: admin@unjaena.com | 회사: unJaena AI</p>

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
            バージョン: v2.3 | 施行日: 2026-03-22 | unJaena AI</div>
        <h3 style="color: {COLORS['brand_primary']}; border-bottom: 2px solid {COLORS['brand_primary']}; padding-bottom: 8px;">
            1. 個人情報の収集・利用に関する同意</h3>
        <table style="{self._consent_table_style()}">
            <tr><th style="{th}; width:25%;">項目</th><th style="{th}">内容</th></tr>
            <tr><td style="{td}"><b>法的根拠</b></td><td style="{td}">お客様の明示的な同意（GDPR第6条第1項(a)、PIPA第15条、APPI第17条、PIPL第13条）。法執行目的：正当な利益または法的義務が適用される場合があります。</td></tr>
            <tr><td style="{td}"><b>収集目的</b></td><td style="{td}">デジタルインテリジェンス分析、セキュリティインシデント調査、証拠取得、AI異常検知</td></tr>
            <tr><td style="{td}"><b>収集項目</b></td><td style="{td}"><b>[Windows]</b> レジストリ、イベントログ、Prefetch、Amcache、UserAssist、MFT、USN Journal、$LogFile、SRUM、ShellBags、ThumbCache、ジャンプリスト、ショートカット、ごみ箱、ブラウザデータ（履歴、Cookie、保存されたパスワード）、USB履歴、タスクスケジューラ、WMI、PowerShell履歴、リモートアクセスログ（TeamViewer/AnyDesk/RDP）、Activities Cache、Windows Defenderログ、BITSジョブ、Zone.Identifier、pagefile.sys、hiberfil.sys<br><b>[Android]</b> SMS/MMS、通話履歴、連絡先、カレンダー、メディアファイル（写真/動画）、WiFi設定、位置情報、システムログ、インストール済みアプリ、<u>アクセシビリティサービスによる画面データ</u>；<b>メッセンジャー：</b>KakaoTalk、WhatsApp、Telegram、LINE、Signal、Discord、Viber、WeChat、Facebook Messenger、Instagram、Snapchat、Skype、BAND；<b>SNS：</b>Facebook、Twitter/X、TikTok、Reddit、Pinterest、LinkedIn、Threads；<b>金融/ショッピング：</b>KakaoBank、Toss、Upbit、BankSalad、KakaoPay、Baemin、Coupang、CoupangEats、Karrot、Yanolja；<b>ナビ：</b>TMAP、KakaoMap、NaverMap、KakaoTaxi；<b>メール/ブラウザ：</b>Gmail、Samsung Email、Chrome、Samsung Browser；<b>業務：</b>Hiworks<br><b>[iOS]</b> iMessage/SMS、通話履歴、連絡先、Safari/Chrome履歴、位置データ（consolidated.db）、システム/クラッシュログ、デバイス情報、バックアップメタデータ；<b>メッセンジャー：</b>KakaoTalk、WhatsApp、Telegram、LINE、Signal、Discord、Viber、WeChat、Facebook Messenger、Instagram、Snapchat、Skype；<b>SNS：</b>Facebook、TikTok、Reddit、Twitter/X、Pinterest、LinkedIn、Threads；<b>システム：</b>メモ、写真DB、カレンダー、リマインダー、ヘルスケア（HealthKit）、スクリーンタイム、ボイスメモ、Apple Maps、探す、Wallet、Spotlight、Siri履歴、ボイスメール、WiFi、Bluetooth、TCC権限、KnowledgeC、VPN設定、データ使用量、アカウント；<b>検索：</b>Naver、Google、NaverMap、Safari/Chrome追跡<br><b>[Linux]</b> システム/認証/カーネルログ、シェル履歴（bash/zsh/fish）、Crontab、Systemdサービス/タイマー、SSHキー（秘密鍵含む）、/etc/passwd、/etc/shadow（パスワードハッシュ）、/etc/group、sudoers、ネットワーク設定（hosts、resolv、interfaces、iptables）、ログイン記録（wtmp/btmp/lastlog）、Webサーバーログ（Apache/Nginx）、パッケージ履歴（apt/yum）、Docker設定、起動スクリプト<br><b>[macOS]</b> 統合ログ、システム/インストールログ、Launch Agent/Daemon、ブラウザ履歴（Safari/Chrome）、Keychainメタデータ、FSEvents、Spotlight、TCC権限、KnowledgeC、既知のWiFiネットワーク、SSHキー、隔離イベント、ログイン項目、監査ログ、最近の項目、Dock/ターミナル履歴<br><b>[メモリ]</b> 物理メモリ取得（RAMダンプ）、実行中アプリのプロセスメモリ、<u>資格情報抽出（メモリ内のパスワードハッシュ）</u><br><b>[文書/メール]</b> Office文書、PDF、HWP、メール（pst/ost/eml/msg）、画像/動画及びEXIF/GPSメタデータ</td></tr>
            <tr><td style="{td}"><b>保存期間</b></td><td style="{td}"><b>30日間</b>（ケース終了後自動削除）。Webプラットフォームでクレジットを使用して保存期間を延長できます。</td></tr>
            <tr><td style="{td}"><b>処理方法</b></td><td style="{td}">SHA-256ハッシュ検証、TLS 1.3暗号化通信、AES-256-GCM暗号化保存、証拠完全性追跡（Evidence Integrity Tracking）。業界最高水準のセキュリティ対策を講じていますが、インターネット通信における絶対的なセキュリティは技術的に不可能です。</td></tr>
            <tr><td style="{td}"><b>同意拒否権</b></td><td style="{td}">同意を拒否する権利があります。拒否された場合、データ収集・分析サービスをご利用いただけません。</td></tr>
            <tr><td style="{td}"><b>特別カテゴリー</b></td><td style="{td}">収集されたデータには、健康、政治的見解、宗教的信条、生体データなどの特別カテゴリーの個人データが偶発的に含まれる場合があります。同意することにより、GDPR第9条第2項(a)に基づき、フォレンジック分析目的に限りそのようなデータの処理に明示的に同意するものとします。</td></tr>
        </table>

        <h3 style="color: {COLORS['warning']}; border-bottom: 2px solid {COLORS['warning']}; padding-bottom: 8px;">
            2. 海外データ移転に関する告知</h3>
        <p style="background: rgba(210,153,34,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['warning']};">
            <b>告知：</b>収集されたデータは海外サーバーに移転される場合があります。同意されない場合、サービス利用が制限されます。</p>
        {self._consent_transfer_table("ja")}
        <p style="margin-top:8px;"><b>移転の法的根拠：</b>全プロバイダーとEU標準契約条項（SCC）を締結。PIPA第28条の8委託契約。APPI第28条安全措置。PIPL第38条標準契約。技術的保護措置（TLS 1.3、AES-256-GCM、ゼロナレッジアーキテクチャ）で補完。</p>

        <h3 style="color: {COLORS['brand_accent']}; border-bottom: 2px solid {COLORS['brand_accent']}; padding-bottom: 8px;">
            3. AI分析および自動化された意思決定に関する告知</h3>
        <p style="background: rgba(212,165,116,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['brand_accent']};">
            <b>EU AI Act (2024/1689)、個人情報保護法関連規制、GDPR第22条に基づく告知</b></p>
        <ul>
            <li><b>AIシステム分類：</b>本システムは法執行の文脈で使用される場合、EU AI Act附属書III、6(e)に基づき高リスクに分類される可能性があります。適切な人的監視が必要です。</li>
            <li><b>AI処理：</b>オープンソースLLMモデル（例：Qwen、LLaMAファミリー、14B+パラメータ）が<u>分析サーバーでローカルに</u>データを処理します。明示的に設定しない限り、第三者AIプロバイダー（OpenAI、Google等）にデータは送信されません。</li>
            <li><b>分析手法：</b>MITRE ATT&CKキルチェーンマッピング（14フェーズ）、重み付けアルゴリズムによる証拠スコアリング、ベクトル類似度検索、証拠間相関分析、時間的クラスタリング。注：日常的な活動が攻撃フェーズに分類される場合がありますが、実際に攻撃が発生したことを意味するものではありません。</li>
            <li><b>アルゴリズムスコアリング：</b>証拠は自動スコアリング（キーワードマッチング、夜間/週末活動の重み付けなどの時間的異常検知、権限指標）により優先順位が決定されます。これらの内蔵仮定はアルゴリズムバイアスを構成する可能性があります。</li>
            <li><b>自動判定：</b>不審な活動、マルウェア指標等をAIが自動判定（<u>参考用</u>）</li>
            <li style="color: {COLORS['error']};"><b>AI結果は独立した法的証拠ではありません。</b>すべての発見事項は、法的、懲戒、雇用に関する措置の前に、資格を持つデジタルフォレンジック専門家による検証が必要です。AI結果のみを根拠としてそのような措置を取ってはなりません。</li>
            <li><b>制限事項：</b>誤検知（False Positive）、検知漏れ（False Negative）が発生する可能性があります。AIハルシネーション（幻覚）により、存在しないファイル名、タイムスタンプ、マルウェア識別子、因果関係が生成される場合があります。既知の誤検知カテゴリ：標準Windowsコンポーネント、一般的なビジネスアプリケーション、通常のNTFS操作。</li>
            <li><b>敵対的リスク：</b>分析対象の証拠にAI分析を操作するよう設計されたコンテンツが含まれている場合があります。保護措置は講じていますが、AIの出力が敵対的データの影響を受ける可能性があります。</li>
            <li><b>権利：</b>AI処理の拒否権、AI判定に対する説明要求権（admin@unjaena.com）、要求後5営業日以内の人的介入要求権</li>
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
            <li><b>監督機関への苦情申立権：</b>関連するデータ保護監督機関に苦情を申し立てることができます（例：PIPC（韓国）、CNIL（フランス）、ICO（英国）、BfDI（ドイツ）、CAC（中国）、PPC（日本））。</li>
        </ul>
        <p style="background: rgba(46,160,67,0.15); padding: 10px; border-radius: 6px; margin-top:8px;"><b>同意の撤回：</b>admin@unjaena.comに連絡するか、Webプラットフォームを通じて同意を撤回できます。撤回後30日以内にデータが削除されます。撤回前に行われた処理の適法性には影響しません。</p>
        <p>お問い合わせ：admin@unjaena.com | 会社：unJaena AI</p>

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
            版本: v2.3 | 生效日期: 2026-03-22 | unJaena AI</div>
        <h3 style="color: {COLORS['brand_primary']}; border-bottom: 2px solid {COLORS['brand_primary']}; padding-bottom: 8px;">
            1. 个人信息收集和使用同意</h3>
        <table style="{self._consent_table_style()}">
            <tr><th style="{th}; width:25%;">项目</th><th style="{th}">说明</th></tr>
            <tr><td style="{td}"><b>法律依据</b></td><td style="{td}">您的明确同意（GDPR第6条第1款(a)、PIPA第15条、APPI第17条、PIPL第13条）。执法目的：可能适用合法利益或法律义务。</td></tr>
            <tr><td style="{td}"><b>收集目的</b></td><td style="{td}">数字智能分析、安全事件调查、证据获取、基于AI的异常检测</td></tr>
            <tr><td style="{td}"><b>收集项目</b></td><td style="{td}"><b>[Windows]</b> 注册表、事件日志、Prefetch、Amcache、UserAssist、MFT、USN Journal、$LogFile、SRUM、ShellBags、ThumbCache、跳转列表、快捷方式、回收站、浏览器数据（历史、Cookie、保存的密码）、USB记录、计划任务、WMI、PowerShell历史、远程访问日志（TeamViewer/AnyDesk/RDP）、Activities Cache、Windows Defender日志、BITS作业、Zone.Identifier、pagefile.sys、hiberfil.sys<br><b>[Android]</b> SMS/MMS、通话记录、联系人、日历、媒体文件（照片/视频）、WiFi设置、位置记录、系统日志、已安装应用、<u>无障碍服务屏幕数据</u>；<b>即时通讯：</b>KakaoTalk、WhatsApp、Telegram、LINE、Signal、Discord、Viber、WeChat、Facebook Messenger、Instagram、Snapchat、Skype、BAND；<b>社交网络：</b>Facebook、Twitter/X、TikTok、Reddit、Pinterest、LinkedIn、Threads；<b>金融/购物：</b>KakaoBank、Toss、Upbit、BankSalad、KakaoPay、Baemin、Coupang、CoupangEats、Karrot、Yanolja；<b>导航：</b>TMAP、KakaoMap、NaverMap、KakaoTaxi；<b>邮件/浏览器：</b>Gmail、Samsung Email、Chrome、Samsung Browser；<b>办公：</b>Hiworks<br><b>[iOS]</b> iMessage/SMS、通话记录、联系人、Safari/Chrome历史、位置数据（consolidated.db）、系统/崩溃日志、设备信息、备份元数据；<b>即时通讯：</b>KakaoTalk、WhatsApp、Telegram、LINE、Signal、Discord、Viber、WeChat、Facebook Messenger、Instagram、Snapchat、Skype；<b>社交网络：</b>Facebook、TikTok、Reddit、Twitter/X、Pinterest、LinkedIn、Threads；<b>系统：</b>备忘录、照片数据库、日历、提醒事项、健康（HealthKit）、屏幕使用时间、语音备忘录、Apple地图、查找、Wallet、Spotlight、Siri历史、语音信箱、WiFi、蓝牙、TCC权限、KnowledgeC、VPN配置、数据使用量、账户；<b>搜索：</b>Naver、Google、NaverMap、Safari/Chrome追踪<br><b>[Linux]</b> 系统/认证/内核日志、Shell历史（bash/zsh/fish）、Crontab、Systemd服务/定时器、SSH密钥（含私钥）、/etc/passwd、/etc/shadow（密码哈希）、/etc/group、sudoers、网络配置（hosts、resolv、interfaces、iptables）、登录记录（wtmp/btmp/lastlog）、Web服务器日志（Apache/Nginx）、软件包历史（apt/yum）、Docker配置、启动脚本<br><b>[macOS]</b> 统一日志、系统/安装日志、Launch Agent/Daemon、浏览器历史（Safari/Chrome）、Keychain元数据、FSEvents、Spotlight、TCC权限、KnowledgeC、已知WiFi网络、SSH密钥、隔离事件、登录项、审计日志、最近项目、Dock/终端历史<br><b>[内存]</b> 物理内存获取（RAM转储）、运行中应用的进程内存、<u>凭证提取（内存中的密码哈希）</u><br><b>[文档/邮件]</b> Office文档、PDF、HWP、邮件（pst/ost/eml/msg）、图片/视频及EXIF/GPS元数据</td></tr>
            <tr><td style="{td}"><b>保留期限</b></td><td style="{td}"><b>30天</b>（案件结束后自动删除）。可通过Web平台使用积分延长保留期限。</td></tr>
            <tr><td style="{td}"><b>处理方法</b></td><td style="{td}">SHA-256哈希验证、TLS 1.3加密通信、AES-256-GCM加密存储、证据完整性追踪（Evidence Integrity Tracking）。我们采用业界领先的安全措施，但互联网传输环境下的绝对安全在技术上是不可能的。</td></tr>
            <tr><td style="{td}"><b>拒绝同意权</b></td><td style="{td}">您有权拒绝同意。拒绝后将无法使用数据收集和分析服务。</td></tr>
            <tr><td style="{td}"><b>特殊类别数据</b></td><td style="{td}">收集的数据可能附带包含健康、政治观点、宗教信仰、生物特征等特殊类别的个人数据。同意即表示您根据GDPR第9条第2款(a)明确同意仅为取证分析目的处理此类数据。</td></tr>
        </table>

        <h3 style="color: {COLORS['warning']}; border-bottom: 2px solid {COLORS['warning']}; padding-bottom: 8px;">
            2. 跨境数据传输告知</h3>
        <p style="background: rgba(210,153,34,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['warning']};">
            <b>告知：</b>收集的数据可能会传输到海外服务器。如不同意，服务使用可能受到限制。</p>
        {self._consent_transfer_table("zh")}
        <p style="margin-top:8px;"><b>传输法律依据：</b>与所有提供商签订EU标准合同条款（SCC）。PIPA第28条之8委托协议。APPI第28条安全措施。PIPL第38条标准合同。以技术保护措施（TLS 1.3、AES-256-GCM、零知识架构）作为补充。</p>

        <h3 style="color: {COLORS['brand_accent']}; border-bottom: 2px solid {COLORS['brand_accent']}; padding-bottom: 8px;">
            3. AI分析及自动化决策告知</h3>
        <p style="background: rgba(212,165,116,0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['brand_accent']};">
            <b>根据EU AI Act (2024/1689)、适用AI及隐私法规、GDPR第22条的告知</b></p>
        <ul>
            <li><b>AI系统分类：</b>本系统在执法场景下使用时，可能根据EU AI Act附件III第6(e)条被归类为高风险系统。需要适当的人工监督。</li>
            <li><b>AI处理：</b>开源LLM模型（如Qwen、LLaMA系列，14B+参数）<u>在分析服务器上本地</u>处理数据。除非明确配置，数据不会发送给第三方AI提供商（OpenAI、Google等）。</li>
            <li><b>分析方法：</b>MITRE ATT&CK杀伤链映射（14阶段）、加权算法证据评分、向量相似度搜索、交叉证据关联分析、时间聚类。注意：日常活动可能被归类为攻击阶段——这并不意味着实际发生了攻击。</li>
            <li><b>算法评分：</b>证据通过自动评分（关键词匹配、包括夜间/周末活动加权的时间异常检测、权限指标）确定优先级。这些内置假设可能构成算法偏见。</li>
            <li><b>自动判断：</b>AI自动识别可疑活动、恶意软件指标等（<u>仅供参考</u>）</li>
            <li style="color: {COLORS['error']};"><b>AI结果不是独立的法律证据。</b>所有发现在采取任何法律、纪律或雇佣行动之前，必须经过合格的数字取证专家验证。不得仅以AI结果作为此类行动的依据。</li>
            <li><b>局限性：</b>可能出现误报（False Positive）和漏报（False Negative）。AI幻觉可能伪造文件名、时间戳、恶意软件标识符或因果关系。已知误报类别：标准Windows组件、常见商业应用、正常NTFS操作。</li>
            <li><b>对抗风险：</b>被分析的证据中可能包含旨在操纵AI分析的内容。虽然已采取保护措施，但AI输出仍可能受到对抗性数据的影响。</li>
            <li><b>您的权利：</b>拒绝AI处理权、AI决策解释请求权（admin@unjaena.com）、请求后5个工作日内人工干预权</li>
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
            <li><b>向监管机构投诉权：</b>可向相关数据保护监管机构提出投诉（例：PIPC（韩国）、CNIL（法国）、ICO（英国）、BfDI（德国）、CAC（中国）、PPC（日本））。</li>
        </ul>
        <p style="background: rgba(46,160,67,0.15); padding: 10px; border-radius: 6px; margin-top:8px;"><b>撤回同意：</b>通过admin@unjaena.com联系或使用Web平台撤回同意。撤回后30天内删除数据。撤回不影响撤回前已执行处理的合法性。</p>
        <p>联系方式：admin@unjaena.com | 公司：unJaena AI</p>

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
