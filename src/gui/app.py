"""
Main GUI Application

PyQt6-based graphical interface for the forensic collector.
통합 디바이스 관리 및 병렬 수집 지원.
"""
import asyncio
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QPushButton, QLabel, QProgressBar, QListWidget, QListWidgetItem,
    QLineEdit, QCheckBox, QGroupBox, QMessageBox, QFrame, QTextEdit,
    QStatusBar, QSplitter, QStackedWidget, QScrollArea, QTabWidget,
    QComboBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QElapsedTimer
from PyQt6.QtGui import QFont, QColor, QIcon

from core.token_validator import TokenValidator, ValidationResult
from core.encryptor import FileEncryptor
from core.uploader import SyncUploader
from collectors.artifact_collector import ArtifactCollector, ARTIFACT_TYPES

# 플랫폼 통일 테마 및 새 컴포넌트
from gui.styles import get_platform_stylesheet, COLORS
from core.device_manager import UnifiedDeviceManager, DeviceType, DeviceStatus
from gui.device_panel import DeviceListPanel
from gui.e01_dialog import E01SelectionDialog
from core.multi_device_collector import MultiDeviceCollector, TaskStatus
from gui.multi_progress_panel import MultiProgressPanel

# BitLocker 지원
try:
    from utils.bitlocker import (
        detect_bitlocker_on_system_drive,
        BitLockerDecryptor,
        BitLockerKeyType,
        is_pybde_installed,
        BitLockerError
    )
    BITLOCKER_AVAILABLE = True
except ImportError:
    BITLOCKER_AVAILABLE = False

# 서버 아티팩트 이름 -> Collector 아티팩트 이름 매핑
# 서버는 ArtifactType enum 이름을 사용하고, Collector는 짧은 이름을 사용
SERVER_TO_COLLECTOR_MAPPING = {
    # MFT 관련
    'filesystem_entry': 'mft',
    'usnjrnl_entry': 'usn_journal',
    'logfile_entry': 'logfile',

    # 브라우저 - 통합 (Chrome, Edge, Firefox)
    'history': 'browser',
    'searchkeyword': 'browser',
    'download': 'browser',
    'chrome': 'browser',
    'chrome_history': 'browser',
    'edge': 'browser',
    'edge_history': 'browser',
    'firefox': 'browser',
    'browser': 'browser',
    'browser_chrome': 'browser',  # 레거시 호환
    'browser_edge': 'browser',    # 레거시 호환

    # 파일시스템
    'recycle_bin': 'recycle_bin',
    'recyclebin': 'recycle_bin',  # 레거시 호환
    'partition': 'mft',

    # 실행 흔적
    'prefetch': 'prefetch',
    'amcache': 'amcache',
    'shimcache': 'registry',  # ShimCache는 레지스트리 기반
    'userassist': 'userassist',
    'bam_dam': 'registry',
    'jumplist': 'recent',
    'lnk': 'recent',
    'shortcut': 'recent',
    'runmru': 'registry',

    # 이벤트/로그
    'eventlog': 'eventlog',
    'login': 'eventlog',

    # USB
    'usb': 'usb',
    'mountpoint': 'usb',

    # 레지스트리
    'registry': 'registry',
    'opensavemru': 'registry',
    'typedpaths': 'registry',
    'typedurls': 'registry',
    'explorerkeyword': 'registry',
    'lastvisitedmru': 'registry',
    'streamsmru': 'registry',

    # 탐색기
    'shellbags': 'registry',
    'recent': 'recent',
    'thumbcache': 'recent',

    # 시스템
    'system_info': 'registry',
    'user_profile': 'registry',
    'windows_info': 'registry',
    'srum': 'srum',

    # 계정
    'account_info': 'registry',
    'sam': 'registry',
    'ntuser': 'registry',

    # 기타
    'autorun': 'registry',
    'service': 'registry',
    'scheduled_task': 'registry',

    # === Android 포렌식 ===
    'mobile_android_sms': 'mobile_android_sms',
    'mobile_android_call': 'mobile_android_call',
    'mobile_android_contacts': 'mobile_android_contacts',
    'mobile_android_app': 'mobile_android_app',
    'mobile_android_wifi': 'mobile_android_wifi',
    'mobile_android_location': 'mobile_android_location',
    'mobile_android_media': 'mobile_android_media',

    # === iOS 포렌식 ===
    'mobile_ios_sms': 'mobile_ios_sms',
    'mobile_ios_call': 'mobile_ios_call',
    'mobile_ios_contacts': 'mobile_ios_contacts',
    'mobile_ios_app': 'mobile_ios_app',
    'mobile_ios_safari': 'mobile_ios_safari',
    'mobile_ios_location': 'mobile_ios_location',
    'mobile_ios_backup': 'mobile_ios_backup',

    # === 추후 지원 예정 ===
    # 'email': 'email',
    # 'document': 'document',
    # 'compress': 'compress',
    # 'image': 'media',
    # 'video': 'media',
}


class CollectorWindow(QMainWindow):
    """Main application window with unified device management"""

    def __init__(self, config: dict):
        super().__init__()
        self.config = config
        self.session_token = None
        self.session_id = None
        self.case_id = None
        self.collection_token = None
        self.server_url = None
        self.ws_url = None
        self.allowed_artifacts = []

        # 통합 디바이스 관리자
        self.device_manager = UnifiedDeviceManager()
        self.device_manager.device_added.connect(self._on_device_added)
        self.device_manager.device_removed.connect(self._on_device_removed)

        self.setup_ui()
        self.check_server_connection()

        # 디바이스 모니터링 시작
        self.device_manager.start_monitoring(poll_interval_ms=3000)

    def setup_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle(f"{self.config['app_name']} v{self.config['version']}")
        self.setMinimumSize(1000, 700)
        # 플랫폼 통일 테마 적용
        self.setStyleSheet(get_platform_stylesheet())

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        # Header
        header = self._create_header()
        main_layout.addWidget(header)

        # Main content with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel - Controls
        left_panel = self._create_left_panel()
        splitter.addWidget(left_panel)

        # Right panel - Log
        right_panel = self._create_right_panel()
        splitter.addWidget(right_panel)

        splitter.setSizes([500, 300])
        main_layout.addWidget(splitter)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def _create_header(self) -> QWidget:
        """Create header section"""
        frame = QFrame()
        frame.setObjectName("header")
        layout = QHBoxLayout(frame)

        title = QLabel(self.config['app_name'])
        title.setObjectName("title")
        layout.addWidget(title)

        layout.addStretch()

        # Server status indicator
        self.server_status = QLabel("Server: Checking...")
        self.server_status.setObjectName("serverStatus")
        layout.addWidget(self.server_status)

        return frame

    def _create_left_panel(self) -> QWidget:
        """Create left panel with controls (scrollable)"""
        # 스크롤 가능한 패널 생성
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)

        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setSpacing(8)

        # Step 0: Device Selection (새로 추가)
        device_group = QGroupBox("0. Select Devices")
        device_layout = QVBoxLayout(device_group)
        device_layout.setContentsMargins(5, 15, 5, 5)

        self.device_panel = DeviceListPanel(self.device_manager)
        self.device_panel.selection_changed.connect(self._on_device_selection_changed)
        self.device_panel.image_file_requested.connect(self._on_image_file_added)
        device_layout.addWidget(self.device_panel)

        layout.addWidget(device_group)

        # Step 1: Token
        token_group = QGroupBox("1. Session Token")
        token_layout = QVBoxLayout(token_group)

        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Paste your session token here")
        self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
        token_layout.addWidget(self.token_input)

        token_btn_layout = QHBoxLayout()
        self.show_token_btn = QPushButton("Show")
        self.show_token_btn.setCheckable(True)
        self.show_token_btn.clicked.connect(self._toggle_token_visibility)
        self.validate_btn = QPushButton("Validate Token")
        self.validate_btn.clicked.connect(self._validate_token)
        token_btn_layout.addWidget(self.show_token_btn)
        token_btn_layout.addWidget(self.validate_btn)
        token_layout.addLayout(token_btn_layout)

        self.token_status = QLabel("")
        token_layout.addWidget(self.token_status)

        layout.addWidget(token_group)

        # Step 2: Artifacts (탭 기반 - Phase 2.1)
        artifacts_group = QGroupBox("2. Select Artifacts")
        artifacts_outer_layout = QVBoxLayout(artifacts_group)
        artifacts_outer_layout.setContentsMargins(5, 15, 5, 5)

        # 탭 위젯 생성
        self.artifacts_tab = QTabWidget()
        self.artifacts_tab.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #333;
                border-radius: 4px;
                background-color: #0f3460;
            }
            QTabBar::tab {
                background-color: #1a1a2e;
                border: 1px solid #333;
                padding: 6px 12px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #0f3460;
                border-bottom-color: #0f3460;
            }
            QTabBar::tab:hover:!selected {
                background-color: #16213e;
            }
        """)

        # 아티팩트 체크박스 저장소
        self.artifact_checks: Dict[str, QCheckBox] = {}

        # Tab 1: Windows Artifacts
        windows_tab = self._create_windows_tab()
        self.artifacts_tab.addTab(windows_tab, "Windows")

        # Tab 2: Android
        android_tab = self._create_android_tab()
        self.artifacts_tab.addTab(android_tab, "Android")

        # Tab 3: iOS
        ios_tab = self._create_ios_tab()
        self.artifacts_tab.addTab(ios_tab, "iOS")

        artifacts_outer_layout.addWidget(self.artifacts_tab)

        # Select All (현재 탭에만 적용)
        select_all_layout = QHBoxLayout()
        self.select_all_cb = QCheckBox("Select All (current tab)")
        self.select_all_cb.stateChanged.connect(self._toggle_select_all)
        select_all_layout.addWidget(self.select_all_cb)
        select_all_layout.addStretch()
        artifacts_outer_layout.addLayout(select_all_layout)

        layout.addWidget(artifacts_group)

        # Step 3: Progress (P2-1: 단계별 진행률 표시, 스크롤 가능)
        progress_group = QGroupBox("3. Collection Progress")
        progress_outer_layout = QVBoxLayout(progress_group)
        progress_outer_layout.setContentsMargins(5, 15, 5, 5)

        # QScrollArea로 감싸기
        progress_scroll = QScrollArea()
        progress_scroll.setWidgetResizable(True)
        progress_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        progress_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        progress_scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        progress_content = QWidget()
        progress_content.setStyleSheet("background: transparent;")
        progress_layout = QVBoxLayout(progress_content)
        progress_layout.setContentsMargins(0, 0, 0, 0)
        progress_layout.setSpacing(8)

        # 전체 진행률
        overall_layout = QHBoxLayout()
        overall_label = QLabel("전체 진행률:")
        overall_label.setMinimumWidth(80)
        self.overall_progress = QProgressBar()
        self.overall_progress.setTextVisible(True)
        self.overall_progress.setValue(0)
        overall_layout.addWidget(overall_label)
        overall_layout.addWidget(self.overall_progress)
        progress_layout.addLayout(overall_layout)

        # 단계별 진행률
        stages_frame = QFrame()
        stages_frame.setObjectName("stagesFrame")
        stages_layout = QGridLayout(stages_frame)
        stages_layout.setContentsMargins(5, 5, 5, 5)
        stages_layout.setSpacing(8)

        # 1. 수집 단계
        self.stage1_indicator = QLabel("○")
        self.stage1_indicator.setObjectName("stageIndicator")
        self.stage1_label = QLabel("1. 수집")
        self.stage1_progress = QProgressBar()
        self.stage1_progress.setMaximumHeight(12)
        self.stage1_progress.setTextVisible(False)
        stages_layout.addWidget(self.stage1_indicator, 0, 0)
        stages_layout.addWidget(self.stage1_label, 0, 1)
        stages_layout.addWidget(self.stage1_progress, 0, 2)

        # 2. 암호화 단계
        self.stage2_indicator = QLabel("○")
        self.stage2_indicator.setObjectName("stageIndicator")
        self.stage2_label = QLabel("2. 암호화")
        self.stage2_progress = QProgressBar()
        self.stage2_progress.setMaximumHeight(12)
        self.stage2_progress.setTextVisible(False)
        stages_layout.addWidget(self.stage2_indicator, 1, 0)
        stages_layout.addWidget(self.stage2_label, 1, 1)
        stages_layout.addWidget(self.stage2_progress, 1, 2)

        # 3. 업로드 단계
        self.stage3_indicator = QLabel("○")
        self.stage3_indicator.setObjectName("stageIndicator")
        self.stage3_label = QLabel("3. 업로드")
        self.stage3_progress = QProgressBar()
        self.stage3_progress.setMaximumHeight(12)
        self.stage3_progress.setTextVisible(False)
        stages_layout.addWidget(self.stage3_indicator, 2, 0)
        stages_layout.addWidget(self.stage3_label, 2, 1)
        stages_layout.addWidget(self.stage3_progress, 2, 2)

        stages_layout.setColumnStretch(2, 1)
        progress_layout.addWidget(stages_frame)

        # 현재 작업 및 예상 시간
        status_layout = QHBoxLayout()
        self.current_file_label = QLabel("준비 완료")
        self.current_file_label.setWordWrap(True)
        status_layout.addWidget(self.current_file_label, 1)

        self.time_estimate_label = QLabel("")
        self.time_estimate_label.setObjectName("timeEstimate")
        self.time_estimate_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        status_layout.addWidget(self.time_estimate_label)
        progress_layout.addLayout(status_layout)

        # 수집된 파일 목록
        self.collected_list = QListWidget()
        self.collected_list.setMaximumHeight(120)
        progress_layout.addWidget(self.collected_list)

        progress_scroll.setWidget(progress_content)
        progress_outer_layout.addWidget(progress_scroll)

        layout.addWidget(progress_group)

        # Buttons
        btn_layout = QHBoxLayout()
        self.collect_btn = QPushButton("Start Collection")
        self.collect_btn.setEnabled(False)
        self.collect_btn.clicked.connect(self._start_collection)
        self.collect_btn.setObjectName("primaryButton")

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_collection)

        btn_layout.addWidget(self.collect_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)

        layout.addStretch()

        # 스크롤 영역에 패널 설정
        scroll_area.setWidget(panel)
        return scroll_area

    def _create_right_panel(self) -> QWidget:
        """Create right panel with log"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        log_group = QGroupBox("Activity Log")
        log_layout = QVBoxLayout(log_group)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        log_layout.addWidget(self.log_text)

        layout.addWidget(log_group)

        return panel

    # =========================================================================
    # Tab Creation Methods (Phase 2.1)
    # =========================================================================

    def _create_windows_tab(self) -> QWidget:
        """Create Windows artifacts tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(5, 5, 5, 5)

        # QScrollArea로 감싸기
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        content = QWidget()
        content.setStyleSheet("background: transparent;")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(2)

        # Windows 카테고리 아티팩트만 표시
        for artifact_type, info in ARTIFACT_TYPES.items():
            category = info.get('category', 'windows')
            if category != 'windows' and 'category' in info:
                continue
            # 모바일 제외 (별도 탭)
            if artifact_type.startswith('mobile_'):
                continue

            cb = QCheckBox(f"{info['name']}")
            cb.setEnabled(False)  # Enable after token validation
            cb.setProperty("artifact_type", artifact_type)

            tooltip_parts = [info.get('description', '')]
            if info.get('requires_admin'):
                tooltip_parts.append("Requires administrator privileges")
            if info.get('requires_mft'):
                tooltip_parts.append("Requires MFT collection (pytsk3)")
            cb.setToolTip(" | ".join(tooltip_parts))

            self.artifact_checks[artifact_type] = cb
            content_layout.addWidget(cb)

        content_layout.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll)

        return tab

    def _create_android_tab(self) -> QWidget:
        """Create Android Forensics tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(5, 5, 5, 5)

        # 상태 정보 섹션
        status_frame = QFrame()
        status_frame.setStyleSheet("QFrame { background-color: #1a1a2e; border-radius: 4px; padding: 5px; }")
        status_layout = QGridLayout(status_frame)

        # ADB 상태
        from collectors.artifact_collector import ADB_AVAILABLE
        adb_status = "Available" if ADB_AVAILABLE else "Not Found"
        self.adb_status_label = QLabel(f"ADB: {adb_status}")
        self.adb_status_label.setStyleSheet(
            f"color: {'#4cc9f0' if ADB_AVAILABLE else '#ff6b6b'};"
        )
        status_layout.addWidget(self.adb_status_label, 0, 0)

        # 기기 연결 상태
        self.android_device_label = QLabel("Device: Not connected")
        self.android_device_label.setStyleSheet("color: #888;")
        status_layout.addWidget(self.android_device_label, 0, 1)

        # 기기 새로고침 버튼
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setMaximumWidth(80)
        refresh_btn.clicked.connect(self._refresh_android_devices)
        status_layout.addWidget(refresh_btn, 0, 2)

        # 기기 정보 (루팅 상태 등)
        self.android_info_label = QLabel("")
        status_layout.addWidget(self.android_info_label, 1, 0, 1, 3)

        layout.addWidget(status_frame)

        # USB 디버깅 가이드
        guide_label = QLabel("Enable USB Debugging: Settings > Developer Options > USB Debugging")
        guide_label.setStyleSheet("color: #888; font-size: 10px;")
        guide_label.setWordWrap(True)
        layout.addWidget(guide_label)

        # 스크롤 영역
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        content = QWidget()
        content.setStyleSheet("background: transparent;")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(2)

        # Android 카테고리 아티팩트
        for artifact_type, info in ARTIFACT_TYPES.items():
            if info.get('category') != 'android':
                continue

            cb = QCheckBox(f"{info['name']}")
            cb.setEnabled(False)  # Enable after token validation
            cb.setProperty("artifact_type", artifact_type)

            tooltip_parts = [info.get('description', '')]
            if info.get('requires_root'):
                tooltip_parts.append("Requires rooted device")
            cb.setToolTip(" | ".join(tooltip_parts))

            # 루트 필요 항목 표시
            if info.get('requires_root'):
                cb.setText(f"{info['name']} (Root)")

            self.artifact_checks[artifact_type] = cb
            content_layout.addWidget(cb)

        content_layout.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll)

        return tab

    def _create_ios_tab(self) -> QWidget:
        """Create iOS Forensics tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(5, 5, 5, 5)

        # 상태 정보 섹션
        status_frame = QFrame()
        status_frame.setStyleSheet("QFrame { background-color: #1a1a2e; border-radius: 4px; padding: 5px; }")
        status_layout = QVBoxLayout(status_frame)

        # 백업 선택
        backup_row = QHBoxLayout()
        backup_label = QLabel("Backup:")
        self.ios_backup_combo = QComboBox()
        self.ios_backup_combo.setMinimumWidth(200)
        self.ios_backup_combo.currentIndexChanged.connect(self._on_ios_backup_selected)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setMaximumWidth(80)
        refresh_btn.clicked.connect(self._refresh_ios_backups)

        backup_row.addWidget(backup_label)
        backup_row.addWidget(self.ios_backup_combo, 1)
        backup_row.addWidget(refresh_btn)
        status_layout.addLayout(backup_row)

        # 백업 정보
        self.ios_info_label = QLabel("No backup selected")
        self.ios_info_label.setStyleSheet("color: #888; font-size: 11px;")
        self.ios_info_label.setWordWrap(True)
        status_layout.addWidget(self.ios_info_label)

        layout.addWidget(status_frame)

        # 백업 생성 가이드
        guide_label = QLabel("Create backup: Connect device to iTunes/Finder > Back Up Now (unencrypted)")
        guide_label.setStyleSheet("color: #888; font-size: 10px;")
        guide_label.setWordWrap(True)
        layout.addWidget(guide_label)

        # 스크롤 영역
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        content = QWidget()
        content.setStyleSheet("background: transparent;")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(2)

        # iOS 카테고리 아티팩트
        for artifact_type, info in ARTIFACT_TYPES.items():
            if info.get('category') != 'ios':
                continue

            cb = QCheckBox(f"{info['name']}")
            cb.setEnabled(False)  # Enable after token validation
            cb.setProperty("artifact_type", artifact_type)
            cb.setToolTip(info.get('description', ''))

            self.artifact_checks[artifact_type] = cb
            content_layout.addWidget(cb)

        content_layout.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll)

        # 초기 백업 목록 로드
        QTimer.singleShot(100, self._refresh_ios_backups)

        return tab

    def _refresh_android_devices(self):
        """Refresh Android device list"""
        try:
            from collectors.artifact_collector import ADB_AVAILABLE
            if not ADB_AVAILABLE:
                self.android_device_label.setText("Device: ADB not available")
                return

            import subprocess
            result = subprocess.run(
                ['adb', 'devices', '-l'],
                capture_output=True,
                text=True,
                timeout=5
            )

            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            devices = []
            for line in lines:
                if line.strip() and 'device' in line:
                    parts = line.split()
                    serial = parts[0]
                    model = "Unknown"
                    for part in parts:
                        if part.startswith('model:'):
                            model = part.split(':')[1]
                    devices.append((serial, model))

            if devices:
                serial, model = devices[0]
                self.android_device_label.setText(f"Device: {model}")
                self.android_device_label.setStyleSheet("color: #4cc9f0;")
                self.android_info_label.setText(f"Serial: {serial}")
                # Store for collection
                self._android_device_serial = serial
            else:
                self.android_device_label.setText("Device: Not connected")
                self.android_device_label.setStyleSheet("color: #ff6b6b;")
                self.android_info_label.setText("")
                self._android_device_serial = None

        except Exception as e:
            self.android_device_label.setText(f"Device: Error")
            self.android_info_label.setText(str(e))
            self._android_device_serial = None

    def _refresh_ios_backups(self):
        """Refresh iOS backup list"""
        self.ios_backup_combo.clear()
        self.ios_backup_combo.addItem("-- Select Backup --", None)

        try:
            from collectors.artifact_collector import IOS_AVAILABLE
            if not IOS_AVAILABLE:
                self.ios_info_label.setText("iOS backup support not available")
                return

            from collectors.ios_collector import find_ios_backups

            backups = find_ios_backups()
            for backup in backups:
                display = f"{backup.device_name} ({backup.ios_version}) - {backup.backup_date.strftime('%Y-%m-%d')}"
                if backup.encrypted:
                    display += " [Encrypted]"
                self.ios_backup_combo.addItem(display, str(backup.path))

            if not backups:
                self.ios_info_label.setText("No iOS backups found on this system")

        except Exception as e:
            self.ios_info_label.setText(f"Error loading backups: {e}")

    def _on_ios_backup_selected(self, index: int):
        """Handle iOS backup selection"""
        if index <= 0:
            self.ios_info_label.setText("No backup selected")
            self._ios_backup_path = None
            return

        backup_path = self.ios_backup_combo.currentData()
        self._ios_backup_path = backup_path

        try:
            from collectors.ios_collector import parse_backup_info
            from pathlib import Path

            backup_info = parse_backup_info(Path(backup_path))
            if backup_info:
                info_text = f"Device: {backup_info.device_name} | iOS: {backup_info.ios_version} | Size: {backup_info.size_mb:.1f} MB"
                if backup_info.encrypted:
                    info_text += " | ENCRYPTED (cannot extract)"
                    self.ios_info_label.setStyleSheet("color: #ff6b6b;")
                else:
                    self.ios_info_label.setStyleSheet("color: #4cc9f0;")
                self.ios_info_label.setText(info_text)
        except Exception as e:
            self.ios_info_label.setText(f"Error: {e}")

    # =========================================================================
    # Device Management Event Handlers (새로 추가)
    # =========================================================================

    def _on_device_added(self, device):
        """디바이스 추가됨 (DeviceListPanel이 자동 처리)"""
        self._log(f"Device detected: {device.display_name}")

    def _on_device_removed(self, device_id: str):
        """디바이스 제거됨 (DeviceListPanel이 자동 처리)"""
        self._log(f"Device removed: {device_id}")

    def _on_device_selection_changed(self):
        """디바이스 선택 변경됨"""
        selected = self.device_manager.get_selected_devices()
        count = len(selected)
        self._log(f"Selected {count} device(s)")

        # 디바이스가 선택되면 수집 버튼 상태 업데이트
        self._update_collect_button_state()

    def _on_image_file_added(self):
        """포렌식 이미지 파일 추가됨 (DeviceListPanel에서 처리)"""
        self._log("Forensic image added")
        self._update_collect_button_state()

    def _update_collect_button_state(self):
        """수집 버튼 상태 업데이트"""
        has_token = self.collection_token is not None
        has_devices = len(self.device_manager.get_selected_devices()) > 0
        has_artifacts = any(cb.isChecked() for cb in self.artifact_checks.values())

        self.collect_btn.setEnabled(has_token and has_devices and has_artifacts)

    def _get_stylesheet(self) -> str:
        """Get application stylesheet"""
        return """
            QMainWindow {
                background-color: #1a1a2e;
            }
            QWidget {
                color: #eee;
                font-size: 12px;
            }
            #header {
                background-color: #16213e;
                border-radius: 8px;
                padding: 10px;
            }
            #title {
                font-size: 18px;
                font-weight: bold;
                color: #4cc9f0;
            }
            #serverStatus {
                color: #888;
            }
            QGroupBox {
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #16213e;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #4cc9f0;
            }
            QLineEdit {
                background-color: #0f3460;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 8px;
                color: #fff;
            }
            QLineEdit:focus {
                border-color: #4cc9f0;
            }
            QPushButton {
                background-color: #0f3460;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 8px 16px;
                color: #fff;
            }
            QPushButton:hover {
                background-color: #1a4a7a;
            }
            QPushButton:disabled {
                background-color: #333;
                color: #666;
            }
            #primaryButton {
                background-color: #4cc9f0;
                color: #000;
                font-weight: bold;
            }
            #primaryButton:hover {
                background-color: #3db8df;
            }
            QProgressBar {
                border: 1px solid #333;
                border-radius: 4px;
                background-color: #0f3460;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #4cc9f0;
                border-radius: 3px;
            }
            QCheckBox {
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QListWidget, QTextEdit {
                background-color: #0f3460;
                border: 1px solid #333;
                border-radius: 4px;
            }
            QStatusBar {
                background-color: #16213e;
                color: #888;
            }
            #stagesFrame {
                background-color: #0f3460;
                border-radius: 6px;
                padding: 8px;
            }
            #stageIndicator {
                font-size: 14px;
                min-width: 20px;
            }
            #timeEstimate {
                color: #4cc9f0;
                font-size: 11px;
                min-width: 100px;
            }
        """

    def check_server_connection(self):
        """Check if server is reachable"""
        validator = TokenValidator(self.config['server_url'])
        if validator.check_server_health():
            self.server_status.setText("Server: Connected")
            self.server_status.setStyleSheet("color: #4cc9f0;")
            self._log("Server connection established")
        else:
            self.server_status.setText("Server: Disconnected")
            self.server_status.setStyleSheet("color: #f72585;")
            self._log("Warning: Cannot connect to server", error=True)

    def _toggle_token_visibility(self):
        """Toggle token visibility"""
        if self.show_token_btn.isChecked():
            self.token_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_token_btn.setText("Hide")
        else:
            self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_token_btn.setText("Show")

    def _toggle_select_all(self, state):
        """Toggle artifact checkboxes for current tab only"""
        checked = state == Qt.CheckState.Checked.value

        # 현재 탭 인덱스에 따라 카테고리 결정
        current_tab = self.artifacts_tab.currentIndex()
        category_map = {0: 'windows', 1: 'android', 2: 'ios'}
        current_category = category_map.get(current_tab, 'windows')

        for artifact_type, cb in self.artifact_checks.items():
            if not cb.isEnabled():
                continue

            # 아티팩트 카테고리 확인
            artifact_info = ARTIFACT_TYPES.get(artifact_type, {})
            artifact_category = artifact_info.get('category', 'windows')

            # Windows 탭: category가 없거나 'windows'인 것, 모바일 제외
            if current_category == 'windows':
                if artifact_type.startswith('mobile_'):
                    continue
                if artifact_category not in ('windows', None) and 'category' in artifact_info:
                    continue

            # 다른 탭: 해당 카테고리만
            elif artifact_category != current_category:
                continue

            cb.setChecked(checked)

    def _validate_token(self):
        """Validate the session token"""
        token = self.token_input.text().strip()
        if not token:
            QMessageBox.warning(self, "Error", "Please enter a session token")
            return

        self._log("Validating token...")
        self.validate_btn.setEnabled(False)

        validator = TokenValidator(self.config['server_url'])
        result = validator.validate(token)

        if result.valid:
            # [보안] 원본 세션 토큰은 저장하지 않음 (검증 완료 후 불필요)
            # 필요한 정보만 유지: session_id, case_id, collection_token
            self.session_token = None  # 메모리에서 원본 토큰 제거
            self.session_id = result.session_id
            self.case_id = result.case_id
            self.collection_token = result.collection_token
            self.server_url = result.server_url or self.config['server_url']
            self.ws_url = result.ws_url or self.config['ws_url']
            self.allowed_artifacts = result.allowed_artifacts or list(ARTIFACT_TYPES.keys())

            self.token_status.setText(f"Valid - Case: {self.case_id[:8]}...")
            self.token_status.setStyleSheet("color: #4cc9f0;")
            self._log(f"Token validated. Case ID: {self.case_id}")
            self._log(f"Session ID: {self.session_id}")
            self._log(f"Allowed artifacts: {', '.join(self.allowed_artifacts)}")

            # Enable artifact selection
            # 서버 아티팩트 이름을 Collector 이름으로 변환하여 매칭
            mapped_allowed = set()
            for server_name in self.allowed_artifacts:
                # 직접 매핑 확인
                if server_name in SERVER_TO_COLLECTOR_MAPPING:
                    mapped_allowed.add(SERVER_TO_COLLECTOR_MAPPING[server_name])
                # 이미 Collector 이름인 경우
                if server_name in ARTIFACT_TYPES:
                    mapped_allowed.add(server_name)

            # 'all'이 포함되었거나 allowed_artifacts가 없으면 모든 아티팩트 허용
            allow_all = 'all' in self.allowed_artifacts or not result.allowed_artifacts

            self._log(f"Mapped artifacts for GUI: {', '.join(sorted(mapped_allowed))}")
            if allow_all:
                self._log("All artifacts are allowed - selecting all by default")

            for artifact_type, cb in self.artifact_checks.items():
                # 모든 아티팩트 허용이거나 매핑된 목록에 있으면 활성화 및 선택
                if allow_all or artifact_type in mapped_allowed:
                    cb.setEnabled(True)
                    cb.setChecked(True)  # 기본으로 모든 허용된 아티팩트 선택

            # 디바이스 선택 상태 포함하여 수집 버튼 상태 업데이트
            self._update_collect_button_state()
        else:
            self.token_status.setText(f"Invalid: {result.error}")
            self.token_status.setStyleSheet("color: #f72585;")
            self._log(f"Token validation failed: {result.error}", error=True)

        self.validate_btn.setEnabled(True)

    def _start_collection(self):
        """Start the collection process"""
        # 디바이스 선택 확인
        selected_devices = self.device_manager.get_selected_devices()
        if not selected_devices:
            QMessageBox.warning(self, "Error", "Please select at least one device")
            return

        selected = [k for k, cb in self.artifact_checks.items() if cb.isChecked()]
        if not selected:
            QMessageBox.warning(self, "Error", "Please select at least one artifact type")
            return

        self._log(f"Starting collection from {len(selected_devices)} device(s)")

        # 법적 동의 확인 (필수)
        from gui.consent_dialog import show_consent_dialog
        consent_record = show_consent_dialog(self)

        if not consent_record:
            self._log("Collection cancelled: User did not consent", error=True)
            QMessageBox.information(
                self,
                "수집 취소",
                "법적 동의가 필요합니다.\n동의 없이는 수집을 진행할 수 없습니다."
            )
            return

        # 동의 기록 저장
        self.consent_record = consent_record
        self._log(f"Legal consent obtained: {consent_record['consent_hash'][:16]}...")

        # BitLocker 감지 및 복호화 처리
        bitlocker_decryptor = None
        bitlocker_info = None

        if BITLOCKER_AVAILABLE:
            self._log("BitLocker 암호화 볼륨 확인 중...")
            bitlocker_result = detect_bitlocker_on_system_drive()

            if bitlocker_result.is_encrypted:
                self._log(f"BitLocker 암호화 볼륨 감지됨 (파티션 #{bitlocker_result.partition_index})")

                # BitLocker 다이얼로그 표시
                from gui.bitlocker_dialog import show_bitlocker_dialog

                dialog_result = show_bitlocker_dialog(
                    partition_info={
                        'partition_index': bitlocker_result.partition_index,
                        'partition_offset': bitlocker_result.partition_offset,
                        'partition_size': bitlocker_result.partition_size,
                        'encryption_method': bitlocker_result.encryption_method,
                    },
                    pybde_available=is_pybde_installed(),
                    parent=self
                )

                if dialog_result.success and not dialog_result.skip:
                    # 복호화 시도
                    self._log(f"BitLocker 복호화 시도 중... (키 타입: {dialog_result.key_type})")

                    try:
                        decryptor = BitLockerDecryptor.from_physical_disk(
                            drive_number=0,
                            partition_index=bitlocker_result.partition_index
                        )

                        # 키 타입에 따라 복호화
                        if dialog_result.key_type == "recovery_password":
                            unlock_result = decryptor.unlock_with_recovery_password(
                                dialog_result.key_value
                            )
                        elif dialog_result.key_type == "password":
                            unlock_result = decryptor.unlock_with_password(
                                dialog_result.key_value
                            )
                        elif dialog_result.key_type == "bek_file":
                            unlock_result = decryptor.unlock_with_bek_file(
                                dialog_result.bek_path
                            )
                        else:
                            unlock_result = None

                        if unlock_result and unlock_result.success:
                            bitlocker_decryptor = decryptor
                            bitlocker_info = unlock_result.volume_info
                            self._log("BitLocker 복호화 성공! 암호화된 볼륨에서 수집을 진행합니다.")
                        else:
                            error_msg = unlock_result.error_message if unlock_result else "Unknown error"
                            self._log(f"BitLocker 복호화 실패: {error_msg}", error=True)
                            QMessageBox.warning(
                                self,
                                "BitLocker 복호화 실패",
                                f"복호화에 실패했습니다: {error_msg}\n\n"
                                "이전 방식(암호화된 상태)으로 수집을 진행합니다."
                            )
                            # decryptor 정리
                            decryptor.close()

                    except BitLockerError as e:
                        self._log(f"BitLocker 오류: {e}", error=True)
                        QMessageBox.warning(
                            self,
                            "BitLocker 오류",
                            f"BitLocker 처리 중 오류가 발생했습니다:\n{e}\n\n"
                            "이전 방식으로 수집을 진행합니다."
                        )
                    except Exception as e:
                        self._log(f"예상치 못한 오류: {e}", error=True)
                        QMessageBox.warning(
                            self,
                            "오류",
                            f"오류가 발생했습니다:\n{e}\n\n"
                            "이전 방식으로 수집을 진행합니다."
                        )

                elif dialog_result.skip:
                    self._log("BitLocker 복호화를 건너뛰고 암호화된 상태로 수집을 진행합니다.")
                else:
                    # 취소됨
                    self._log("BitLocker 다이얼로그가 취소되었습니다.")
            else:
                self._log("BitLocker 암호화 볼륨이 감지되지 않았습니다.")

        self._log(f"Starting collection for: {', '.join(selected)}")

        # Disable controls
        self.collect_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.validate_btn.setEnabled(False)
        for cb in self.artifact_checks.values():
            cb.setEnabled(False)

        # Phase 2.1: Android/iOS 옵션 가져오기
        android_serial = getattr(self, '_android_device_serial', None)
        ios_backup = getattr(self, '_ios_backup_path', None)

        # Start worker thread
        self.worker = CollectionWorker(
            server_url=self.server_url,
            ws_url=self.ws_url,
            session_id=self.session_id,
            collection_token=self.collection_token,
            case_id=self.case_id,
            artifacts=selected,
            consent_record=self.consent_record,  # P0 법적 필수
            # Phase 2.1: 메모리/모바일 옵션
            android_device_serial=android_serial,
            ios_backup_path=ios_backup,
            # BitLocker 복호화된 볼륨
            bitlocker_decryptor=bitlocker_decryptor,
        )
        self.worker.progress_updated.connect(self._update_progress)
        self.worker.file_collected.connect(self._add_collected_file)
        self.worker.log_message.connect(self._log)
        self.worker.finished.connect(self._collection_finished)
        self.worker.start()

    def _cancel_collection(self):
        """Cancel ongoing collection"""
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.cancel()
            self._log("Collection cancelled by user")

    def _update_progress(self, stage: int, stage_progress: int, overall_progress: int,
                         message: str, time_remaining: str):
        """
        Update progress bars (P2-1: 단계별 진행률)

        Args:
            stage: 현재 단계 (1=수집, 2=암호화, 3=업로드)
            stage_progress: 현재 단계 내 진행률 (0-100)
            overall_progress: 전체 진행률 (0-100)
            message: 현재 작업 설명
            time_remaining: 예상 남은 시간 문자열
        """
        # 전체 진행률
        self.overall_progress.setValue(overall_progress)

        # 단계별 UI 업데이트
        indicators = [self.stage1_indicator, self.stage2_indicator, self.stage3_indicator]
        progress_bars = [self.stage1_progress, self.stage2_progress, self.stage3_progress]
        labels = [self.stage1_label, self.stage2_label, self.stage3_label]

        for i, (indicator, progress, label) in enumerate(zip(indicators, progress_bars, labels), 1):
            if i < stage:
                # 완료된 단계
                indicator.setText("✓")
                indicator.setStyleSheet("color: #4cc9f0;")
                progress.setValue(100)
                progress.setStyleSheet("QProgressBar::chunk { background-color: #4cc9f0; }")
            elif i == stage:
                # 현재 진행 중인 단계
                indicator.setText("●")
                indicator.setStyleSheet("color: #f0c14c;")
                progress.setValue(stage_progress)
                progress.setStyleSheet("QProgressBar::chunk { background-color: #f0c14c; }")
            else:
                # 대기 중인 단계
                indicator.setText("○")
                indicator.setStyleSheet("color: #666;")
                progress.setValue(0)
                progress.setStyleSheet("")

        # 현재 작업 및 시간 표시
        self.current_file_label.setText(message)
        if time_remaining:
            self.time_estimate_label.setText(f"예상: {time_remaining}")

    def _add_collected_file(self, filename: str, success: bool):
        """Add file to collected list"""
        item = QListWidgetItem(filename)
        if success:
            item.setForeground(QColor("#4cc9f0"))
        else:
            item.setForeground(QColor("#f72585"))
        self.collected_list.addItem(item)
        self.collected_list.scrollToBottom()

    def _collection_finished(self, success: bool, message: str):
        """Handle collection completion"""
        # Re-enable controls
        self.collect_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.validate_btn.setEnabled(True)

        if success:
            self._log(f"Collection completed: {message}")
            QMessageBox.information(self, "Success", message)
        else:
            self._log(f"Collection failed: {message}", error=True)
            QMessageBox.critical(self, "Error", message)

        self.status_bar.showMessage("Ready")

    def _log(self, message: str, error: bool = False):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = "ERROR" if error else "INFO"
        color = "#f72585" if error else "#4cc9f0"

        html = f'<span style="color: #888;">[{timestamp}]</span> '
        html += f'<span style="color: {color};">[{prefix}]</span> '
        html += f'<span style="color: #eee;">{message}</span>'

        self.log_text.append(html)

    def closeEvent(self, event):
        """윈도우 종료 시 정리"""
        # 디바이스 모니터링 중지
        self.device_manager.stop_monitoring()

        # 진행 중인 수집 취소
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.cancel()
            self.worker.wait(3000)  # 최대 3초 대기

        super().closeEvent(event)


class CollectionWorker(QThread):
    """Background worker for collection (P2-1: 단계별 진행률)"""

    # P2-1: 확장된 시그널 (stage, stage_progress, overall_progress, message, time_remaining)
    progress_updated = pyqtSignal(int, int, int, str, str)
    file_collected = pyqtSignal(str, bool)
    log_message = pyqtSignal(str, bool)
    finished = pyqtSignal(bool, str)

    # 단계별 가중치 (총 100%)
    STAGE_WEIGHTS = {
        1: 30,   # 수집: 30%
        2: 30,   # 암호화: 30%
        3: 40,   # 업로드: 40%
    }

    def __init__(
        self,
        server_url: str,
        ws_url: str,
        session_id: str,
        collection_token: str,
        case_id: str,
        artifacts: List[str],
        consent_record: dict = None,
        # Phase 2.1: 모바일 옵션
        android_device_serial: str = None,
        ios_backup_path: str = None,
        # BitLocker 복호화된 볼륨
        bitlocker_decryptor=None,
    ):
        super().__init__()
        self.server_url = server_url
        self.ws_url = ws_url
        self.session_id = session_id
        self.collection_token = collection_token
        self.case_id = case_id
        self.artifacts = artifacts
        self.consent_record = consent_record  # P0 법적 필수
        self._cancelled = False

        # Phase 2.1: 모바일 옵션
        self.android_device_serial = android_device_serial
        self.ios_backup_path = ios_backup_path

        # BitLocker 복호화된 볼륨
        self.bitlocker_decryptor = bitlocker_decryptor

        # P2-1: 시간 추적
        self._start_time = None
        self._stage_start_time = None
        self._processed_bytes = 0
        self._total_bytes_estimate = 0

    def cancel(self):
        """Cancel the collection"""
        self._cancelled = True

    def _calculate_overall_progress(self, stage: int, stage_progress: int) -> int:
        """전체 진행률 계산"""
        completed_weight = sum(
            self.STAGE_WEIGHTS[s] for s in range(1, stage)
        )
        current_weight = self.STAGE_WEIGHTS[stage] * stage_progress / 100
        return int(completed_weight + current_weight)

    def _estimate_remaining_time(self, stage: int, stage_progress: int, items_done: int, total_items: int) -> str:
        """예상 남은 시간 계산"""
        import time

        if not self._start_time or stage_progress <= 0:
            return ""

        elapsed = time.time() - self._start_time
        overall_progress = self._calculate_overall_progress(stage, stage_progress)

        if overall_progress <= 0:
            return ""

        # 예상 총 시간 계산
        estimated_total = elapsed / (overall_progress / 100)
        remaining = max(0, estimated_total - elapsed)

        if remaining < 60:
            return f"{int(remaining)}초"
        elif remaining < 3600:
            minutes = int(remaining / 60)
            seconds = int(remaining % 60)
            return f"{minutes}분 {seconds}초"
        else:
            hours = int(remaining / 3600)
            minutes = int((remaining % 3600) / 60)
            return f"{hours}시간 {minutes}분"

    def run(self):
        """Run collection in background (P2-1: 단계별 진행률)"""
        import time
        import os

        try:
            self._start_time = time.time()

            import tempfile
            output_dir = tempfile.mkdtemp(prefix="forensic_")

            # BitLocker 복호화된 볼륨이 있으면 decrypted_reader 전달
            decrypted_reader = None
            if self.bitlocker_decryptor:
                try:
                    decrypted_reader = self.bitlocker_decryptor.get_decrypted_reader()
                    self.log_message.emit("BitLocker 복호화된 볼륨을 사용합니다.", False)
                except Exception as e:
                    self.log_message.emit(f"BitLocker 볼륨 접근 실패: {e}", True)

            collector = ArtifactCollector(output_dir, decrypted_reader=decrypted_reader)
            encryptor = FileEncryptor()

            # ========================================
            # STAGE 1: 수집 (30%)
            # ========================================
            self.log_message.emit("📂 아티팩트 수집을 시작합니다...", False)
            collected_raw_files = []  # (file_path, artifact_type, metadata)
            total_artifacts = len(self.artifacts)

            for i, artifact_type in enumerate(self.artifacts):
                if self._cancelled:
                    self.finished.emit(False, "수집이 취소되었습니다")
                    return

                stage_progress = int(((i + 1) / total_artifacts) * 100)
                overall_progress = self._calculate_overall_progress(1, stage_progress)
                remaining = self._estimate_remaining_time(1, stage_progress, i + 1, total_artifacts)

                self.progress_updated.emit(
                    1, stage_progress, overall_progress,
                    f"수집 중: {artifact_type}...",
                    remaining
                )
                self.log_message.emit(f"수집 중: {artifact_type}", False)

                try:
                    # Phase 2.1: 카테고리별 kwargs 전달
                    collect_kwargs = {}
                    artifact_info = ARTIFACT_TYPES.get(artifact_type, {})
                    category = artifact_info.get('category', 'windows')

                    if category == 'android' and self.android_device_serial:
                        collect_kwargs['device_serial'] = self.android_device_serial
                    elif category == 'ios' and self.ios_backup_path:
                        collect_kwargs['backup_path'] = self.ios_backup_path

                    files = list(collector.collect(artifact_type, **collect_kwargs))

                    # [Phase 4] 수집 결과 상세 로깅
                    if not files:
                        self.log_message.emit(f"⚠️ {artifact_type}: 파일을 찾을 수 없습니다", True)
                    else:
                        self.log_message.emit(f"✓ {artifact_type}: {len(files)}개 파일 수집됨", False)

                    for file_path, metadata in files:
                        if self._cancelled:
                            break
                        collected_raw_files.append((file_path, artifact_type, metadata))
                        self.file_collected.emit(Path(file_path).name, True)

                except Exception as e:
                    import traceback
                    import logging
                    self.log_message.emit(f"수집 실패 ({artifact_type}): {e}", True)
                    # 보안: 스택 트레이스는 logging 모듈로 레벨 제어 (stdout 노출 방지)
                    logging.debug(f"Collection error for {artifact_type}: {e}")

            if self._cancelled:
                self.finished.emit(False, "수집이 취소되었습니다")
                return

            # ========================================
            # STAGE 2: 암호화 (30%)
            # ========================================
            self.log_message.emit(f"🔐 {len(collected_raw_files)}개 파일 암호화 중...", False)
            encrypted_files = []  # (enc_path, artifact_type, metadata)
            total_files = len(collected_raw_files)

            for j, (file_path, artifact_type, metadata) in enumerate(collected_raw_files):
                if self._cancelled:
                    self.finished.emit(False, "암호화가 취소되었습니다")
                    return

                filename = Path(file_path).name
                stage_progress = int(((j + 1) / max(total_files, 1)) * 100)
                overall_progress = self._calculate_overall_progress(2, stage_progress)
                remaining = self._estimate_remaining_time(2, stage_progress, j + 1, total_files)

                self.progress_updated.emit(
                    2, stage_progress, overall_progress,
                    f"암호화 중: {filename}",
                    remaining
                )

                try:
                    enc_result = encryptor.encrypt_file(file_path)

                    # Add required metadata fields for server
                    metadata['original_hash'] = enc_result.original_hash
                    metadata['original_size'] = enc_result.original_size
                    metadata['collection_time'] = datetime.utcnow().isoformat()

                    # Legacy encryption info (now handled by server)
                    metadata['encryption'] = {
                        'nonce': enc_result.nonce,
                        'original_hash': enc_result.original_hash,
                    }

                    encrypted_files.append((
                        enc_result.encrypted_path,
                        artifact_type,
                        metadata
                    ))

                except Exception as e:
                    self.log_message.emit(f"암호화 실패 ({filename}): {e}", True)

            if self._cancelled:
                self.finished.emit(False, "암호화가 취소되었습니다")
                return

            # ========================================
            # STAGE 3: 업로드 (40%)
            # ========================================
            self.log_message.emit(f"☁️ {len(encrypted_files)}개 파일 업로드 중...", False)

            uploader = SyncUploader(
                server_url=self.server_url,
                ws_url=self.ws_url,
                session_id=self.session_id,
                collection_token=self.collection_token,
                case_id=self.case_id,
                consent_record=self.consent_record,  # P0 법적 필수
            )

            success_count = 0
            total_upload = len(encrypted_files)

            for k, (file_path, artifact_type, metadata) in enumerate(encrypted_files):
                if self._cancelled:
                    break

                filename = Path(file_path).name
                stage_progress = int(((k + 1) / max(total_upload, 1)) * 100)
                overall_progress = self._calculate_overall_progress(3, stage_progress)
                remaining = self._estimate_remaining_time(3, stage_progress, k + 1, total_upload)

                self.progress_updated.emit(
                    3, stage_progress, overall_progress,
                    f"업로드 중: {filename}",
                    remaining
                )

                result = uploader.upload_file(file_path, artifact_type, metadata)
                if result.success:
                    success_count += 1
                    self.log_message.emit(f"✓ 업로드 성공: {filename}", False)
                else:
                    # [취소 확인] 서버에서 취소 응답을 받았는지 확인
                    if result.error and "CANCELLED" in result.error:
                        self.log_message.emit("🛑 서버에서 수집이 취소되었습니다. 업로드를 중단합니다.", True)
                        self._cancelled = True
                        break
                    # [Phase 4] 업로드 실패 상세 로깅
                    self.log_message.emit(f"✗ 업로드 실패 ({artifact_type}): {result.error}", True)
                    # 보안: 디버그 정보는 logging 모듈로 레벨 제어
                    import logging
                    logging.debug(f"Upload failed: artifact={artifact_type}, error={result.error}")

            # 완료
            elapsed = time.time() - self._start_time
            elapsed_str = f"{int(elapsed)}초" if elapsed < 60 else f"{int(elapsed / 60)}분 {int(elapsed % 60)}초"

            # [취소 확인] 취소된 경우 완료 신호를 보내지 않음
            if self._cancelled:
                self.log_message.emit(f"🛑 수집 취소됨: {success_count}/{total_upload}개 파일 업로드 후 중단 (소요시간: {elapsed_str})", True)
                self.progress_updated.emit(3, 0, 0, "취소됨", "")
                self.finished.emit(False, f"수집 취소됨: {success_count}/{total_upload}개 파일 업로드 후 중단")
                return

            # === 업로드 완료 신호 전송 (파이프라인 상태 전환 트리거) ===
            if success_count > 0:
                try:
                    complete_url = f"{self.server_url}/api/v1/collector/collection/end/{self.session_id}"
                    complete_response = requests.post(
                        complete_url,
                        headers={
                            'X-Collection-Token': self.collection_token,
                            'Content-Type': 'application/json',
                        },
                        json={'trigger_analysis': True},
                        timeout=30
                    )
                    if complete_response.ok:
                        self.log_message.emit("✓ 수집 세션 완료 신호 전송 (임베딩 시작)", False)
                    else:
                        self.log_message.emit(f"⚠ 세션 완료 신호 실패: {complete_response.status_code}", True)
                except Exception as e:
                    self.log_message.emit(f"⚠ 세션 완료 신호 오류: {e}", True)

            self.progress_updated.emit(3, 100, 100, "완료!", "")
            self.finished.emit(
                True,
                f"수집 완료: {success_count}/{total_upload}개 파일 업로드 (소요시간: {elapsed_str})"
            )

        except Exception as e:
            self.finished.emit(False, f"오류 발생: {str(e)}")

        finally:
            # BitLocker decryptor 리소스 정리
            if self.bitlocker_decryptor:
                try:
                    self.bitlocker_decryptor.close()
                    self.log_message.emit("BitLocker 리소스 정리 완료", False)
                except Exception as e:
                    self.log_message.emit(f"BitLocker 정리 중 오류: {e}", True)
