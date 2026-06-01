"""
Main GUI Application

PyQt6-based graphical interface for the forensic collector.
Supports unified device management and parallel collection.
"""
import asyncio
import logging
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QPushButton, QLabel, QProgressBar,
    QLineEdit, QCheckBox, QGroupBox, QMessageBox, QFrame, QTextEdit,
    QStatusBar, QSplitter, QScrollArea, QTabWidget,
    QApplication
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont

from core.token_validator import TokenValidator, _get_ssl_verify
from core.encryptor import FileHashCalculator
from core.uploader import SyncUploader, R2DirectUploader, RealTimeUploader
from core.request_signer import RequestSigner
from core.collection_profile import apply_collection_profile_to_mobile_ffs, apply_collection_profile_to_registry
from collectors.artifact_collector import (
    ArtifactCollector, ARTIFACT_TYPES,
    ANDROID_ARTIFACT_TYPES, IOS_ARTIFACT_TYPES,
    LINUX_ARTIFACT_TYPES, MACOS_ARTIFACT_TYPES,
    LocalMFTCollector, BASE_MFT_AVAILABLE,
    LocalSystemCollector,
)
from collectors.base_mft_collector import ARTIFACT_MFT_FILTERS

# E01 collector requires pytsk3 — may be unavailable on Linux/macOS
try:
    from collectors.e01_artifact_collector import E01ArtifactCollector
    E01_AVAILABLE = True
except ImportError:
    E01ArtifactCollector = None
    E01_AVAILABLE = False

# Platform unified theme and new components
from gui.styles import get_platform_stylesheet, COLORS
from core.device_manager import UnifiedDeviceManager, DeviceType
from core.device_enumerators import create_default_enumerators
from gui.device_panel import DeviceListPanel
from utils.error_messages import translate_error

# BitLocker support
try:
    from utils.bitlocker import (
        detect_bitlocker_on_system_drive,
        BitLockerDecryptor,
        BitLockerKeyType,
        is_pybde_installed,
        BitLockerError,
        is_fve_available,
        is_luks_partition,
        LUKSDecryptor,
    )
    from utils.bitlocker.bitlocker_decryptor import BitLockerUnlockResult
    BITLOCKER_AVAILABLE = True
except ImportError:
    BITLOCKER_AVAILABLE = False

# Artifact type mapping — future: load dynamically from server /authenticate response
SERVER_TO_COLLECTOR_MAPPING = {}




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
        self.collection_profile_id = None
        self.collection_profile_targets = []
        self.profile_artifact_types = set()
        self.allowed_artifacts = []
        self._allow_all_artifacts = False
        self._mapped_allowed_artifacts = set()
        self._collection_starting = False
        self._collection_running = False
        self.request_signer = None

        # Unified device manager
        self.device_manager = UnifiedDeviceManager()
        self.device_manager.device_added.connect(self._on_device_added)
        self.device_manager.device_removed.connect(self._on_device_removed)

        # Register device enumerators (Windows, Android, iOS, E01/RAW)
        enumerators = create_default_enumerators()
        for name, enumerator in enumerators.items():
            self.device_manager.register_enumerator(name, enumerator)

        self.setup_ui()
        self.check_server_connection()

        # Start device monitoring
        self.device_manager.start_monitoring(poll_interval_ms=3000)

        # Check for updates 5 seconds after startup (non-blocking)
        QTimer.singleShot(5000, self._check_for_updates)

    def setup_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle(f"{self.config['app_name']} v{self.config['version']}")
        self.setMinimumSize(900, 650)
        # Apply platform unified theme
        self.setStyleSheet(get_platform_stylesheet())

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(8)

        # Header (compact)
        header = self._create_header()
        header.setFixedHeight(40)
        main_layout.addWidget(header)

        # Main content with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel - Controls
        left_panel = self._create_left_panel()
        splitter.addWidget(left_panel)

        # Right panel - Log
        right_panel = self._create_right_panel()
        splitter.addWidget(right_panel)

        splitter.setSizes([550, 350])
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        main_layout.addWidget(splitter, 1)  # stretch factor 1

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def _create_header(self) -> QWidget:
        """Create header section (compact)"""
        frame = QFrame()
        frame.setObjectName("header")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(12, 4, 12, 4)
        layout.setSpacing(8)

        title = QLabel(self.config['app_name'])
        title.setObjectName("title")
        title.setFont(QFont("Malgun Gothic", 12, QFont.Weight.Bold))
        layout.addWidget(title)

        layout.addStretch()

        # Server status indicator
        self.server_status = QLabel("Server: Checking...")
        self.server_status.setObjectName("serverStatus")
        self.server_status.setFont(QFont("Malgun Gothic", 9))
        layout.addWidget(self.server_status)

        return frame

    def _create_left_panel(self) -> QWidget:
        """Create left panel with controls (scrollable)"""
        # Create scrollable panel
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        scroll_area.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        panel = QWidget()
        panel.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(6)

        # Step 0: Device Selection
        device_group = QGroupBox("0. Select Devices")
        self.device_group = device_group
        device_layout = QVBoxLayout(device_group)
        device_layout.setContentsMargins(6, 14, 6, 6)
        device_layout.setSpacing(4)

        self.device_panel = DeviceListPanel(self.device_manager)
        self.device_manager.selection_changed.connect(self._on_device_selection_changed)
        self.device_panel.image_file_requested.connect(self._on_image_file_added)
        device_layout.addWidget(self.device_panel)

        layout.addWidget(device_group)

        # Step 1: Token
        token_group = QGroupBox("1. Session Token")
        self.token_group = token_group
        token_layout = QVBoxLayout(token_group)
        token_layout.setContentsMargins(6, 14, 6, 6)
        token_layout.setSpacing(4)

        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Paste your session token here")
        self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
        token_layout.addWidget(self.token_input)

        token_btn_layout = QHBoxLayout()
        token_btn_layout.setSpacing(4)
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

        # Step 2: Artifacts (tab-based)
        artifacts_group = QGroupBox("2. Select Artifacts")
        self.artifacts_group = artifacts_group
        artifacts_outer_layout = QVBoxLayout(artifacts_group)
        artifacts_outer_layout.setContentsMargins(6, 14, 6, 6)
        artifacts_outer_layout.setSpacing(4)

        # Create tab widget
        self.artifacts_tab = QTabWidget()
        self.artifacts_tab.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 4px;
                background-color: {COLORS['bg_tertiary']};
            }}
            QTabBar::tab {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border_subtle']};
                padding: 4px 10px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                font-size: 11px;
            }}
            QTabBar::tab:selected {{
                background-color: {COLORS['bg_tertiary']};
                border-bottom-color: {COLORS['bg_tertiary']};
            }}
            QTabBar::tab:hover:!selected {{
                background-color: {COLORS['bg_hover']};
            }}
        """)

        # Artifact checkboxes storage
        self.artifact_checks: Dict[str, QCheckBox] = {}

        self._build_artifact_tabs()

        artifacts_outer_layout.addWidget(self.artifacts_tab)

        self.source_scope_label = QLabel("Select an evidence source to load the applicable collection scope.")
        self.source_scope_label.setWordWrap(True)
        self.source_scope_label.setStyleSheet(
            f"background: {COLORS['bg_secondary']}; color: {COLORS['text_tertiary']}; "
            f"font-size: 9px; border-radius: 4px; padding: 4px 8px;"
        )
        artifacts_outer_layout.addWidget(self.source_scope_label)

        # Select All + Include Deleted option
        select_all_layout = QHBoxLayout()
        self.select_all_cb = QCheckBox("Select All (current tab)")
        self.select_all_cb.setEnabled(False)
        self.select_all_cb.setToolTip("Authenticate a token and select an evidence source first")
        self.select_all_cb.stateChanged.connect(self._toggle_select_all)
        select_all_layout.addWidget(self.select_all_cb)
        select_all_layout.addStretch()
        self.include_deleted_cb = QCheckBox("Include deleted files")
        self.include_deleted_cb.setChecked(True)
        self.include_deleted_cb.setEnabled(False)
        self.include_deleted_cb.setToolTip("Recover and collect deleted files from MFT after an evidence source is selected")
        select_all_layout.addWidget(self.include_deleted_cb)
        artifacts_outer_layout.addLayout(select_all_layout)

        layout.addWidget(artifacts_group)

        # Step 3: Progress (stage-based progress display)
        progress_group = QGroupBox("3. Collection Progress")
        progress_outer_layout = QVBoxLayout(progress_group)
        progress_outer_layout.setContentsMargins(6, 14, 6, 6)
        progress_outer_layout.setSpacing(4)

        progress_content = QWidget()
        progress_content.setStyleSheet("background: transparent;")
        progress_layout = QVBoxLayout(progress_content)
        progress_layout.setContentsMargins(0, 0, 0, 0)
        progress_layout.setSpacing(8)

        # Overall progress
        overall_layout = QHBoxLayout()
        overall_label = QLabel("Overall Progress:")
        overall_label.setMinimumWidth(80)
        self.overall_progress = QProgressBar()
        self.overall_progress.setTextVisible(True)
        self.overall_progress.setValue(0)
        overall_layout.addWidget(overall_label)
        overall_layout.addWidget(self.overall_progress)
        progress_layout.addLayout(overall_layout)

        # Stage-based progress
        stages_frame = QFrame()
        stages_frame.setObjectName("stagesFrame")
        stages_layout = QGridLayout(stages_frame)
        stages_layout.setContentsMargins(5, 5, 5, 5)
        stages_layout.setSpacing(8)

        # 1. Collection stage
        self.stage1_indicator = QLabel("○")
        self.stage1_indicator.setObjectName("stageIndicator")
        self.stage1_label = QLabel("1. Collect")
        self.stage1_progress = QProgressBar()
        self.stage1_progress.setMaximumHeight(12)
        self.stage1_progress.setTextVisible(False)
        stages_layout.addWidget(self.stage1_indicator, 0, 0)
        stages_layout.addWidget(self.stage1_label, 0, 1)
        stages_layout.addWidget(self.stage1_progress, 0, 2)

        # 2. Encryption stage
        self.stage2_indicator = QLabel("○")
        self.stage2_indicator.setObjectName("stageIndicator")
        self.stage2_label = QLabel("2. Encrypt")
        self.stage2_progress = QProgressBar()
        self.stage2_progress.setMaximumHeight(12)
        self.stage2_progress.setTextVisible(False)
        stages_layout.addWidget(self.stage2_indicator, 1, 0)
        stages_layout.addWidget(self.stage2_label, 1, 1)
        stages_layout.addWidget(self.stage2_progress, 1, 2)

        # 3. Upload stage
        self.stage3_indicator = QLabel("○")
        self.stage3_indicator.setObjectName("stageIndicator")
        self.stage3_label = QLabel("3. Upload")
        self.stage3_progress = QProgressBar()
        self.stage3_progress.setMaximumHeight(12)
        self.stage3_progress.setTextVisible(False)
        stages_layout.addWidget(self.stage3_indicator, 2, 0)
        stages_layout.addWidget(self.stage3_label, 2, 1)
        stages_layout.addWidget(self.stage3_progress, 2, 2)

        stages_layout.setColumnStretch(2, 1)
        progress_layout.addWidget(stages_frame)

        # Current task and estimated time
        status_layout = QHBoxLayout()
        self.current_file_label = QLabel("Ready")
        self.current_file_label.setWordWrap(True)
        status_layout.addWidget(self.current_file_label, 1)

        # Elapsed time + heartbeat (proves the app is alive)
        self.elapsed_label = QLabel("")
        self.elapsed_label.setObjectName("elapsedLabel")
        self.elapsed_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.elapsed_label.setStyleSheet("color: #888; font-size: 9px;")
        status_layout.addWidget(self.elapsed_label)

        self.time_estimate_label = QLabel("")
        self.time_estimate_label.setObjectName("timeEstimate")
        self.time_estimate_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        status_layout.addWidget(self.time_estimate_label)
        progress_layout.addLayout(status_layout)

        # Heartbeat timer: updates elapsed time every second while collection is running
        self._heartbeat_timer = QTimer(self)
        self._heartbeat_timer.setInterval(1000)
        self._heartbeat_timer.timeout.connect(self._update_heartbeat)
        self._collection_start_time = None
        self._heartbeat_frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self._heartbeat_idx = 0

        progress_outer_layout.addWidget(progress_content)

        layout.addWidget(progress_group)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        self.collect_btn = QPushButton("Start Collection")
        self.collect_btn.setEnabled(False)
        self.collect_btn.setFixedHeight(32)
        self.collect_btn.setMinimumWidth(120)
        self.collect_btn.clicked.connect(self._start_collection)
        self.collect_btn.setObjectName("primaryButton")
        # Explicit style settings (visible in both disabled/enabled states)
        self.collect_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['brand_primary']};
                border: none;
                border-radius: 4px;
                color: {COLORS['bg_primary']};
                font-weight: 600;
                font-size: 11px;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['brand_tertiary']};
                color: {COLORS['text_tertiary']};
            }}
            QPushButton:hover:!disabled {{
                background-color: {COLORS['brand_accent']};
            }}
        """)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setFixedHeight(32)
        self.cancel_btn.clicked.connect(self._cancel_collection)

        btn_layout.addWidget(self.collect_btn, 1)  # stretch factor 1
        btn_layout.addWidget(self.cancel_btn, 1)  # stretch factor 1
        layout.addLayout(btn_layout)

        # Fill remaining space with stretch
        layout.addStretch()

        # Set panel to scroll area
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

    def _build_artifact_tabs(self, preserve_index: bool = False):
        current_index = 0
        if preserve_index and hasattr(self, 'artifacts_tab'):
            current_index = max(0, self.artifacts_tab.currentIndex())

        self.artifact_checks.clear()
        while self.artifacts_tab.count():
            widget = self.artifacts_tab.widget(0)
            self.artifacts_tab.removeTab(0)
            if widget is not None:
                widget.deleteLater()

        for label, factory in (
            ("Windows", self._create_windows_tab),
            ("Android", self._create_android_tab),
            ("iOS", self._create_ios_tab),
            ("Linux", self._create_linux_tab),
            ("macOS", self._create_macos_tab),
            ("AI Activity", self._create_ai_activity_tab),
        ):
            self.artifacts_tab.addTab(factory(), label)

        if self.artifacts_tab.count():
            self.artifacts_tab.setCurrentIndex(min(current_index, self.artifacts_tab.count() - 1))

        self._wire_artifact_checkbox_state_handlers()

    def _wire_artifact_checkbox_state_handlers(self) -> None:
        for cb in self.artifact_checks.values():
            cb.stateChanged.connect(self._on_artifact_selection_changed)

    def _on_artifact_selection_changed(self, _state: int = 0) -> None:
        self._update_collect_button_state()

    def _create_windows_tab(self) -> QWidget:
        """Create Windows artifacts tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(5, 5, 5, 5)

        # Wrap with QScrollArea
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        content = QWidget()
        content.setStyleSheet("background: transparent;")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(2)

        # Group Windows artifacts by subcategory
        subcategory_items: dict = {}
        for artifact_type, info in ARTIFACT_TYPES.items():
            category = info.get('category', 'windows')
            if category != 'windows' and 'category' in info:
                continue
            if artifact_type.startswith('mobile_'):
                continue
            subcat = info.get('subcategory', 'system')
            subcategory_items.setdefault(subcat, []).append((artifact_type, info))

        # Render each subcategory group in defined order
        for subcat_key, subcat_label in self.WINDOWS_SUBCATEGORIES:
            items = subcategory_items.get(subcat_key, [])
            if not items:
                continue

            # Section header
            header = QLabel(f"  {subcat_label}")
            header.setStyleSheet(
                f"color: {COLORS['brand_primary']}; font-size: 9px; font-weight: bold; "
                f"margin-top: 6px; margin-bottom: 2px;"
            )
            content_layout.addWidget(header)

            # Artifact checkboxes
            for artifact_type, info in items:
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

    # Windows subcategory display order and labels
    WINDOWS_SUBCATEGORIES = [
        ('system',          'System Artifacts'),
        ('filesystem',      'File System (MFT)'),
        ('developer',       'Developer / Source Code'),
        ('pc_messenger',    'PC Messenger'),
        ('pc_apps',         'PC Applications'),
    ]

    # iOS subcategory display order and labels
    IOS_SUBCATEGORIES = [
        ('core',            'Core'),
        ('system',          'System'),
        ('messenger',       'Messenger'),
        ('sns',             'SNS'),
        ('email_browser',   'Email / Browser'),
        ('korean',          'Korean Apps'),
        ('productivity',    'Productivity / Media'),
    ]

    # Android subcategory display order and labels
    ANDROID_SUBCATEGORIES = [
        ('basic',               'Basic Collection (Non-Root)'),
        ('app_system',          'System DB [Root]'),
        ('app_messenger',       'Messenger'),
        ('app_sns',             'SNS [Root Only]'),
        ('app_korean',          'Korean Apps'),
        ('app_email_browser',   'Email / Browser'),
    ]

    # Android Tier headers (inserted as dividers before certain subcategories)
    ANDROID_TIER_HEADERS = {
        'basic':        'Tier 1 — Basic Collection (Non-Root)',
        'app_system':   'Tier 2 — App Data (Root→DB / Non-Root→SDCard)',
    }

    def _create_android_tab(self) -> QWidget:
        """Create Android Forensics tab with auto-detect root and auto-select"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Root status banner
        self.android_root_banner = QLabel("Android device not connected")
        self.android_root_banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.android_root_banner.setFixedHeight(22)
        self.android_root_banner.setStyleSheet(
            f"background: {COLORS['bg_tertiary']}; color: {COLORS['text_tertiary']}; "
            f"font-size: 9px; border-radius: 4px; padding: 2px 8px;"
        )
        layout.addWidget(self.android_root_banner)

        # Limitation info label (shown for non-root devices)
        self.android_limitation_label = QLabel("")
        self.android_limitation_label.setWordWrap(True)
        self.android_limitation_label.setVisible(False)
        self.android_limitation_label.setStyleSheet(
            f"background: {COLORS['bg_secondary']}; color: {COLORS['text_secondary']}; "
            f"font-size: 8px; border-radius: 4px; padding: 4px 8px; margin: 2px 0px;"
        )
        layout.addWidget(self.android_limitation_label)

        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        content = QWidget()
        content.setStyleSheet("background: transparent;")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(2)

        # Group artifacts by subcategory
        subcategory_items: dict = {}
        for artifact_type, info in ARTIFACT_TYPES.items():
            if info.get('category') != 'android':
                continue
            subcat = info.get('subcategory', 'system')
            if subcat not in subcategory_items:
                subcategory_items[subcat] = []
            subcategory_items[subcat].append((artifact_type, info))

        # Render each subcategory group in defined order
        for subcat_key, subcat_label in self.ANDROID_SUBCATEGORIES:
            items = subcategory_items.get(subcat_key, [])
            if not items:
                continue

            # Tier divider (horizontal line + tier header before certain subcategories)
            if subcat_key in self.ANDROID_TIER_HEADERS:
                # Horizontal separator line
                line = QFrame()
                line.setFrameShape(QFrame.Shape.HLine)
                line.setStyleSheet(f"color: {COLORS['border_subtle']};")
                line.setFixedHeight(1)
                content_layout.addWidget(line)
                # Tier header
                tier_label = QLabel(f"  {self.ANDROID_TIER_HEADERS[subcat_key]}")
                tier_label.setStyleSheet(
                    f"color: {COLORS['info']}; font-size: 10px; font-weight: bold; "
                    f"margin-top: 4px; margin-bottom: 2px;"
                )
                content_layout.addWidget(tier_label)

            # Subcategory header
            header = QLabel(f"  {subcat_label}")
            header.setStyleSheet(
                f"color: {COLORS['brand_primary']}; font-size: 9px; font-weight: bold; "
                f"margin-top: 6px; margin-bottom: 2px;"
            )
            content_layout.addWidget(header)

            # Artifact checkboxes
            for artifact_type, info in items:
                # Show root requirement in name for clarity
                name = info['name']
                if info.get('requires_root') and '(Root)' not in name:
                    name = f"{name} [Root]"
                cb = QCheckBox(name)
                cb.setEnabled(False)  # Enable after device detection
                cb.setProperty("artifact_type", artifact_type)

                tooltip_parts = [info.get('description', '')]
                if info.get('requires_root'):
                    tooltip_parts.append("Requires rooted device")
                cb.setToolTip(" | ".join(tooltip_parts))

                self.artifact_checks[artifact_type] = cb
                content_layout.addWidget(cb)

        content_layout.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll)

        return tab

    def _is_artifact_allowed(self, artifact_type: str) -> bool:
        return self._allow_all_artifacts or artifact_type in self._mapped_allowed_artifacts

    def _disable_disallowed_artifact(
        self,
        artifact_type: str,
        cb: QCheckBox,
        base_tooltip: str = ""
    ) -> bool:
        if self._is_artifact_allowed(artifact_type):
            return False
        cb.setEnabled(False)
        cb.setChecked(False)
        tooltip = base_tooltip or ARTIFACT_TYPES.get(artifact_type, {}).get('description', '')
        cb.setToolTip((tooltip + " | " if tooltip else "") + "Not allowed by collection token")
        return True

    def _mobile_supported_artifacts(self, platform: str, source: str) -> set:
        """Return artifact types supported by the active mobile source."""
        try:
            if platform == "android":
                if source == "ffs":
                    from collectors.mobile_ffs.path_specs import ANDROID_PATH_SPECS
                    return {spec.artifact_type for spec in ANDROID_PATH_SPECS}
                from collectors.android_collector import ANDROID_ARTIFACT_TYPES
                return set(ANDROID_ARTIFACT_TYPES.keys())

            if platform == "ios":
                if source == "ffs":
                    from collectors.mobile_ffs.path_specs import IOS_PATH_SPECS
                    return {spec.artifact_type for spec in IOS_PATH_SPECS}
                from collectors.ios_collector import IOS_ARTIFACT_TYPES
                return set(IOS_ARTIFACT_TYPES.keys())
        except Exception:
            return set()

        return set()

    def _disable_unsupported_mobile_artifact(
        self,
        artifact_type: str,
        cb: QCheckBox,
        supported: set,
        source_label: str,
    ) -> bool:
        """Disable artifacts that the selected mobile source cannot emit."""
        if artifact_type in supported:
            return False

        cb.setEnabled(False)
        cb.setChecked(False)
        info = ARTIFACT_TYPES.get(artifact_type, {})
        tooltip = info.get('description', '')
        suffix = f"Not supported by current {source_label} collection path"
        cb.setToolTip((tooltip + " | " if tooltip else "") + suffix)
        return True

    def _bundle_supported_artifacts(self, bundle_device, platform: str) -> set:
        """Prefer artifact types actually present in an FFS bundle."""
        metadata = bundle_device.metadata or {}
        present = set(metadata.get("present_artifacts") or [])
        if metadata.get("present_artifact_scan_complete"):
            return present
        if present:
            return present
        return self._mobile_supported_artifacts(platform, "ffs")

    def _update_android_root_status(self, is_rooted: bool, connected: bool):
        """Update Android tab: root status banner, auto-select artifacts, show limitations"""
        if not hasattr(self, 'android_root_banner'):
            return

        if not connected:
            self.android_root_banner.setText("Android device not connected")
            self.android_root_banner.setStyleSheet(
                f"background: {COLORS['bg_tertiary']}; color: {COLORS['text_tertiary']}; "
                f"font-size: 9px; border-radius: 4px; padding: 2px 8px;"
            )
            self.android_limitation_label.setVisible(False)
            # Disable all android checkboxes
            for artifact_type, cb in self.artifact_checks.items():
                info = ARTIFACT_TYPES.get(artifact_type, {})
                if info.get('category') == 'android':
                    cb.setEnabled(False)
                    cb.setChecked(False)
            return

        if is_rooted:
            self.android_root_banner.setText(
                "Root Detected \u2014 Full DB extraction enabled"
            )
            self.android_root_banner.setStyleSheet(
                f"background: {COLORS['success_bg']}; color: {COLORS['success']}; "
                f"font-size: 9px; border-radius: 4px; padding: 2px 8px;"
            )
            self.android_limitation_label.setVisible(False)
        else:
            self.android_root_banner.setText(
                "Non-Root \u2014 External storage collection"
            )
            self.android_root_banner.setStyleSheet(
                f"background: {COLORS['warning_bg']}; color: {COLORS['warning']}; "
                f"font-size: 9px; border-radius: 4px; padding: 2px 8px;"
            )
            self.android_limitation_label.setText(
                "Non-Root: Messenger apps auto-adapt to collect external storage data. "
                "System info and media collection are available. "
                "Root-only items (marked [Root]) are disabled."
            )
            self.android_limitation_label.setVisible(True)

        # Auto-select all applicable artifacts
        # Import ANDROID_ARTIFACT_TYPES to detect dual-mode apps
        try:
            from collectors.android_collector import ANDROID_ARTIFACT_TYPES as _AAT
        except ImportError:
            _AAT = {}
        supported = set(_AAT.keys())

        for artifact_type, cb in self.artifact_checks.items():
            info = ARTIFACT_TYPES.get(artifact_type, {})
            if info.get('category') != 'android':
                continue
            if self._disable_disallowed_artifact(artifact_type, cb):
                continue
            if self._disable_unsupported_mobile_artifact(
                artifact_type, cb, supported, "Android USB"
            ):
                continue

            requires_root = info.get('requires_root', False)
            # Dual-mode: has both 'root' and 'nonroot' in ANDROID_ARTIFACT_TYPES
            android_info = _AAT.get(artifact_type, {})
            is_dual_mode = 'root' in android_info and 'nonroot' in android_info

            if requires_root and not is_rooted and not is_dual_mode:
                # Root-only, device not rooted → disable + uncheck
                cb.setEnabled(False)
                cb.setChecked(False)
                cb.setToolTip(
                    info.get('description', '') +
                    " | Root required \u2014 root device for full access"
                )
            else:
                # Available → enable + auto-check
                cb.setEnabled(True)
                cb.setChecked(True)
                tooltip_parts = [info.get('description', '')]
                if is_dual_mode:
                    if is_rooted:
                        tooltip_parts.append("Root: DB extraction")
                    else:
                        tooltip_parts.append("Non-Root: external storage + run-as")
                elif requires_root:
                    tooltip_parts.append("Root access used")
                cb.setToolTip(" | ".join(tooltip_parts))

    def _create_ios_tab(self) -> QWidget:
        """Create iOS Forensics tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Status label (simplified - backup selection handled by DeviceListPanel)
        self.ios_info_label = QLabel("Select iOS backup from list")
        self.ios_info_label.setStyleSheet(f"color: {COLORS['text_tertiary']}; font-size: 9px;")
        layout.addWidget(self.ios_info_label)

        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        content = QWidget()
        content.setStyleSheet("background: transparent;")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(2)

        # Group iOS artifacts by subcategory
        subcategory_items: dict = {}
        for artifact_type, info in ARTIFACT_TYPES.items():
            if info.get('category') != 'ios':
                continue
            subcat = info.get('subcategory', 'core')
            subcategory_items.setdefault(subcat, []).append((artifact_type, info))

        # Render each subcategory group in defined order
        for subcat_key, subcat_label in self.IOS_SUBCATEGORIES:
            items = subcategory_items.get(subcat_key, [])
            if not items:
                continue

            # Section header
            header = QLabel(f"  {subcat_label}")
            header.setStyleSheet(
                f"color: {COLORS['brand_primary']}; font-size: 9px; font-weight: bold; "
                f"margin-top: 6px; margin-bottom: 2px;"
            )
            content_layout.addWidget(header)

            # Artifact checkboxes
            for artifact_type, info in items:
                cb = QCheckBox(f"{info['name']}")
                cb.setEnabled(False)  # Enable after token validation
                cb.setProperty("artifact_type", artifact_type)
                cb.setToolTip(info.get('description', ''))

                self.artifact_checks[artifact_type] = cb
                content_layout.addWidget(cb)

        content_layout.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll)

        return tab

    def _create_linux_tab(self) -> QWidget:
        """Create Linux Forensics tab - E01 direct collection support"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Status label (simplified)
        self.linux_info_label = QLabel("Select Linux disk image")
        self.linux_info_label.setStyleSheet(f"color: {COLORS['text_tertiary']}; font-size: 9px;")
        layout.addWidget(self.linux_info_label)

        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        content = QWidget()
        content.setStyleSheet("background: transparent;")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(2)

        # Linux category artifacts
        for artifact_type, info in ARTIFACT_TYPES.items():
            if info.get('category') != 'linux':
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

        return tab

    def _create_ai_activity_tab(self) -> QWidget:
        """Create server-authorized activity tab (cross-platform).

        Lists server-authorized activity targets. The service controls exact target paths at runtime.
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        info_label = QLabel(
            "Server-authorized activity targets are available after session authentication."
            ""
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet(
            f"color: {COLORS['text_tertiary']}; font-size: 9px;"
        )
        layout.addWidget(info_label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        scroll.setStyleSheet(
            "QScrollArea { border: none; background: transparent; }"
        )

        content = QWidget()
        content.setStyleSheet("background: transparent;")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(2)

        for artifact_type, info in ARTIFACT_TYPES.items():
            if info.get('category') != 'ai_activity':
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

        return tab

    def _create_macos_tab(self) -> QWidget:
        """Create macOS Forensics tab - E01 direct collection support"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Status label (simplified)
        self.macos_info_label = QLabel("Select macOS disk image")
        self.macos_info_label.setStyleSheet(f"color: {COLORS['text_tertiary']}; font-size: 9px;")
        layout.addWidget(self.macos_info_label)

        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        content = QWidget()
        content.setStyleSheet("background: transparent;")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(2)

        # macOS category artifacts
        for artifact_type, info in ARTIFACT_TYPES.items():
            if info.get('category') != 'macos':
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

        return tab

    # [Removed] _refresh_android_devices, _refresh_ios_backups, _on_ios_backup_selected
    # Device/backup selection is managed centrally by DeviceListPanel

    # =========================================================================
    # Device Management Event Handlers
    # =========================================================================

    def _on_device_added(self, device):
        """Device added (DeviceListPanel handles automatically)"""
        self._log(f"Device detected: {device.display_name}")

    def _on_device_removed(self, device_id: str):
        """Device removed (DeviceListPanel handles automatically)"""
        self._log(f"Device removed: {device_id}")

    def _on_device_selection_changed(self):
        """Device selection changed"""
        selected = self.device_manager.get_selected_devices()
        count = len(selected)
        self._log(f"Selected {count} device(s)")

        # [New] Auto-enable/disable platform tabs
        self._update_platform_tab_states()

        # Update collect button state when device is selected
        self._update_collect_button_state()

    def _on_image_file_added(self):
        """Forensic image file added (handled by DeviceListPanel)"""
        self._log("Forensic image added")

        # [New] Auto-enable/disable platform tabs
        self._update_platform_tab_states()

        self._update_collect_button_state()

    def _artifact_category(self, artifact_type: str) -> str:
        """Return the platform category for an artifact type."""
        info = ARTIFACT_TYPES.get(artifact_type, {})
        category = str(info.get('category') or '').lower()
        if category in ('windows', 'android', 'ios', 'linux', 'macos', 'ai_activity'):
            return category
        lowered = str(artifact_type or '').lower()
        if lowered.startswith(('mobile_ios_', 'ios_')):
            return 'ios'
        if lowered.startswith(('mobile_android_', 'android_')):
            return 'android'
        if lowered.startswith('linux_'):
            return 'linux'
        if lowered.startswith('macos_'):
            return 'macos'
        return 'windows'

    def _disk_image_device_types(self) -> tuple:
        return (
            DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE,
            DeviceType.VMDK_IMAGE, DeviceType.VHD_IMAGE,
            DeviceType.VHDX_IMAGE, DeviceType.QCOW2_IMAGE,
            DeviceType.VDI_IMAGE, DeviceType.DMG_IMAGE,
        )

    def _all_source_categories(self) -> set:
        return {'windows', 'android', 'ios', 'linux', 'macos'}

    def _source_categories_for_device(self, device) -> set:
        """Return artifact categories that should run for one evidence source."""
        device_type = getattr(device, 'device_type', None)
        metadata = getattr(device, 'metadata', None) or {}
        if device_type == DeviceType.WINDOWS_PHYSICAL_DISK:
            return {'windows'}
        if device_type in (DeviceType.ANDROID_DEVICE, DeviceType.MOBILE_FFS_BUNDLE_ANDROID):
            return {'android'}
        if device_type in (DeviceType.IOS_BACKUP, DeviceType.IOS_DEVICE, DeviceType.MOBILE_FFS_BUNDLE_IOS):
            return {'ios'}
        if device_type == DeviceType.LINUX_LOCAL_SYSTEM:
            return {'linux'}
        if device_type == DeviceType.MACOS_LOCAL_SYSTEM:
            return {'macos'}
        if device_type in self._disk_image_device_types():
            detected_os = str(metadata.get('detected_os') or '').lower()
            if detected_os in ('windows', 'linux', 'macos'):
                return {detected_os}
            # OS detection can be inconclusive for damaged, encrypted,
            # virtualized, or mobile-origin images. Fail-open so collection
            # does not miss evidence solely because the source OS is unknown.
            return self._all_source_categories()
        return set()

    def _is_unknown_os_image_source(self, device) -> bool:
        metadata = getattr(device, 'metadata', None) or {}
        detected_os = str(metadata.get('detected_os') or '').lower()
        return (
            getattr(device, 'device_type', None) in self._disk_image_device_types()
            and detected_os not in ('windows', 'linux', 'macos')
        )

    def _selected_source_categories(self, selected_devices: Optional[list] = None) -> set:
        """Return artifact categories applicable to selected evidence sources."""
        devices = selected_devices if selected_devices is not None else self.device_manager.get_selected_devices()
        categories = set()
        for device in devices:
            categories.update(self._source_categories_for_device(device))
        if devices and not categories:
            return self._all_source_categories()
        return categories

    def _apply_selected_source_scope(self, selected_devices: Optional[list] = None, force: bool = False):
        """Disable artifacts that cannot be emitted by the selected source type."""
        if not force and (getattr(self, '_collection_starting', False) or getattr(self, '_collection_running', False)):
            return
        categories = self._selected_source_categories(selected_devices)
        if not categories:
            return
        controls_enabled = self.collection_token is not None
        if hasattr(self, 'select_all_cb'):
            self.select_all_cb.setEnabled(controls_enabled)
            self.select_all_cb.setToolTip(
                'Select or clear all artifacts in the current tab'
                if controls_enabled else 'Authenticate a session token first'
            )
        if hasattr(self, 'include_deleted_cb'):
            self.include_deleted_cb.setEnabled(controls_enabled)
            self.include_deleted_cb.setToolTip(
                'Recover and collect deleted files from MFT (slower but more thorough)'
                if controls_enabled else 'Authenticate a session token first'
            )
        for artifact_type, cb in self.artifact_checks.items():
            category = self._artifact_category(artifact_type)
            info = ARTIFACT_TYPES.get(artifact_type, {})
            tooltip = info.get('description', '')

            if category == 'ai_activity':
                if controls_enabled and self._is_artifact_allowed(artifact_type):
                    cb.setEnabled(True)
                    if not cb.isChecked() and info.get('default_enabled') is not False:
                        cb.setChecked(True)
                else:
                    cb.setChecked(False)
                    cb.setEnabled(False)
                    cb.setToolTip((tooltip + " | " if tooltip else "") + "Not allowed by collection token")
                continue

            if category in categories and self._is_artifact_allowed(artifact_type):
                cb.setEnabled(True)
                if not cb.isChecked() and info.get('default_enabled') is not False:
                    cb.setChecked(True)
            elif category in categories:
                cb.setChecked(False)
                cb.setEnabled(False)
                cb.setToolTip((tooltip + " | " if tooltip else "") + "Not allowed by collection token")
            else:
                cb.setChecked(False)
                cb.setEnabled(False)
                cb.setToolTip((tooltip + " | " if tooltip else "") + "Not applicable to the selected evidence source")

    def _category_label(self, category: str) -> str:
        labels = {
            'windows': 'Windows',
            'android': 'Android',
            'ios': 'iOS',
            'linux': 'Linux',
            'macos': 'macOS',
            'ai_activity': 'AI Activity',
        }
        return labels.get(category, category or 'Unknown')

    def _format_category_scope(self, categories: set) -> str:
        order = ['windows', 'android', 'ios', 'linux', 'macos']
        return ', '.join(self._category_label(c) for c in order if c in categories) or 'Unspecified'

    def _set_source_scope_label(self, text: str, tone: str = 'info') -> None:
        if not hasattr(self, 'source_scope_label'):
            return
        color_key = {
            'success': 'success',
            'warning': 'warning',
            'error': 'error',
            'info': 'info',
        }.get(tone, 'info')
        bg_key = f'{color_key}_bg'
        self.source_scope_label.setText(text)
        self.source_scope_label.setStyleSheet(
            f"background: {COLORS.get(bg_key, COLORS['bg_secondary'])}; "
            f"color: {COLORS.get(color_key, COLORS['text_secondary'])}; "
            f"font-size: 9px; border-radius: 4px; padding: 4px 8px;"
        )

    def _set_artifacts_waiting_for_source(self) -> None:
        has_token = self.collection_token is not None
        if has_token:
            message = 'Authorized profile loaded. Select an evidence source to apply collection scope.'
            tooltip_suffix = 'Select an evidence source to apply the authorized collection profile'
        else:
            message = 'Authenticate a session token, then select an evidence source to load collection scope.'
            tooltip_suffix = 'Authenticate a session token and select an evidence source first'

        self._set_source_scope_label(message, 'info')

        if hasattr(self, 'select_all_cb'):
            self.select_all_cb.blockSignals(True)
            self.select_all_cb.setChecked(False)
            self.select_all_cb.blockSignals(False)
            self.select_all_cb.setEnabled(False)
            self.select_all_cb.setToolTip(tooltip_suffix)
        if hasattr(self, 'include_deleted_cb'):
            self.include_deleted_cb.setEnabled(False)
            self.include_deleted_cb.setToolTip(
                'Recover deleted files after an evidence source is selected'
            )

        for artifact_type, cb in self.artifact_checks.items():
            cb.setChecked(False)
            cb.setEnabled(False)
            tooltip = ARTIFACT_TYPES.get(artifact_type, {}).get('description', '')
            cb.setToolTip((tooltip + ' | ' if tooltip else '') + tooltip_suffix)

    def _update_source_scope_status(self, selected_devices: Optional[list] = None) -> None:
        devices = selected_devices if selected_devices is not None else self.device_manager.get_selected_devices()
        if not devices:
            if self.collection_token is not None:
                self._set_source_scope_label(
                    'Authorized profile loaded. Select an evidence source to apply collection scope.',
                    'info',
                )
            else:
                self._set_source_scope_label(
                    'Authenticate a session token, then select an evidence source to load collection scope.',
                    'info',
                )
            return

        categories = self._selected_source_categories(devices)
        unknown_images = [d for d in devices if self._is_unknown_os_image_source(d)]
        if unknown_images:
            names = ', '.join(d.display_name for d in unknown_images[:2])
            suffix = '...' if len(unknown_images) > 2 else ''
            self._set_source_scope_label(
                f'OS not identified for {len(unknown_images)} image source(s): {names}{suffix}. '
                f'Full collection scope is enabled: {self._format_category_scope(categories)}.',
                'warning',
            )
            return

        self._set_source_scope_label(
            f'Collection scope: {self._format_category_scope(categories)}. '
            f'{len(devices)} evidence source(s) selected.',
            'success',
        )

    def _artifact_count_for_source(self, device, selected_artifacts: list) -> int:
        categories = self._source_categories_for_device(device)
        if not categories:
            return len(selected_artifacts)
        return sum(1 for artifact_type in selected_artifacts if self._artifact_category(artifact_type) in categories)

    def _device_type_label(self, device) -> str:
        device_type = getattr(device, 'device_type', None)
        if device_type is None:
            return 'Unknown source'
        return device_type.name.replace('_', ' ').title()

    def _detected_os_label(self, device) -> str:
        metadata = getattr(device, 'metadata', None) or {}
        detected_os = str(metadata.get('detected_os') or '').lower()
        if detected_os in ('windows', 'linux', 'macos'):
            return self._category_label(detected_os)
        if self._is_unknown_os_image_source(device):
            return 'Unknown - full scope'
        return metadata.get('os_family') or metadata.get('platform') or 'N/A'

    def _build_collection_plan_lines(self, selected_devices: list, selected_artifacts: list) -> list:
        lines = []
        for index, device in enumerate(selected_devices, 1):
            categories = self._source_categories_for_device(device)
            artifact_count = self._artifact_count_for_source(device, selected_artifacts)
            size = getattr(device, 'size_display', '') or 'size unknown'
            lines.append(
                f"{index}. {device.display_name} | {self._device_type_label(device)} | "
                f"OS: {self._detected_os_label(device)} | "
                f"scope: {self._format_category_scope(categories)} | "
                f"artifacts: {artifact_count} | {size}"
            )
        return lines

    def _collection_preflight_warnings(self, selected_devices: list, selected_artifacts: list) -> list:
        warnings = []
        if len(selected_devices) > 1:
            warnings.append('Multiple evidence sources will be collected into the same case. Confirm they belong to the same investigation scope.')

        unknown_count = sum(1 for d in selected_devices if self._is_unknown_os_image_source(d))
        if unknown_count:
            warnings.append('One or more image sources have unknown OS. Full profile mode is enabled to avoid missed collection; it may take longer.')

        requires_admin = any(getattr(d, 'requires_admin', False) for d in selected_devices)
        if requires_admin:
            try:
                from utils.privilege import is_admin
                admin_ok = is_admin()
            except Exception:
                admin_ok = None
            if admin_ok is False:
                warnings.append('Administrator/root privileges are not active. Physical disk and local filesystem collection may be incomplete.')
            elif admin_ok is None:
                warnings.append('Administrator/root privilege state could not be verified before collection.')

        android_nonroot = [
            d for d in selected_devices
            if d.device_type == DeviceType.ANDROID_DEVICE and not (getattr(d, 'metadata', None) or {}).get('rooted')
        ]
        if android_nonroot:
            warnings.append('Android non-root mode is selected. Root-only app databases will be skipped when unavailable.')

        if any(d.device_type == DeviceType.IOS_DEVICE for d in selected_devices):
            warnings.append('iOS USB collection uses backup-based extraction. Keep the device unlocked and trusted until preparation completes.')

        if not selected_artifacts:
            warnings.append('No artifacts are selected.')

        return warnings

    def _confirm_collection_plan(self, selected_devices: list, selected_artifacts: list) -> bool:
        lines = self._build_collection_plan_lines(selected_devices, selected_artifacts)
        warnings = self._collection_preflight_warnings(selected_devices, selected_artifacts)

        body = 'Review the collection plan before starting.\n\n'
        body += '\n'.join(lines[:12])
        if len(lines) > 12:
            body += f"\n... and {len(lines) - 12} more source(s)"
        if warnings:
            body += '\n\nPreflight notes:\n' + '\n'.join(f'- {w}' for w in warnings)
        body += '\n\nContinue collection?'

        confirm = QMessageBox.question(
            self,
            'Review Collection Plan',
            body,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return confirm == QMessageBox.StandardButton.Yes

    def _set_collection_inputs_locked(self, locked: bool) -> None:
        for attr in ('device_group', 'token_group', 'artifacts_group'):
            widget = getattr(self, attr, None)
            if widget is not None:
                widget.setEnabled(not locked)
        if hasattr(self, 'collect_btn'):
            self.collect_btn.setEnabled(False if locked else self.collect_btn.isEnabled())

    def _update_platform_tab_states(self):
        """
        Auto-navigate to relevant platform tab based on selected device

        - All tabs remain accessible (not disabled)
        - Auto-focus to appropriate tab based on detected OS
        """
        selected_devices = self.device_manager.get_selected_devices()

        if not selected_devices:
            self._update_linux_macos_info_labels([])
            self._update_android_root_status(is_rooted=False, connected=False)
            self._update_ios_info_label(None, [])
            self._set_artifacts_waiting_for_source()
            return

        # Determine tab for auto-focus (priority: first selected device)
        tab_map = {'windows': 0, 'android': 1, 'ios': 2, 'linux': 3, 'macos': 4}
        target_tab = None

        for device in selected_devices:
            if device.device_type == DeviceType.WINDOWS_PHYSICAL_DISK:
                target_tab = tab_map['windows']
                break

            elif device.device_type == DeviceType.MACOS_LOCAL_SYSTEM:
                target_tab = tab_map['macos']
                break

            elif device.device_type == DeviceType.LINUX_LOCAL_SYSTEM:
                target_tab = tab_map['linux']
                break

            elif device.device_type == DeviceType.ANDROID_DEVICE:
                target_tab = tab_map['android']
                break

            elif device.device_type in (DeviceType.IOS_BACKUP, DeviceType.IOS_DEVICE):
                target_tab = tab_map['ios']
                break

            elif device.device_type == DeviceType.MOBILE_FFS_BUNDLE_ANDROID:
                target_tab = tab_map['android']
                break

            elif device.device_type == DeviceType.MOBILE_FFS_BUNDLE_IOS:
                target_tab = tab_map['ios']
                break

            elif device.device_type in (DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE,
                                        DeviceType.VMDK_IMAGE, DeviceType.VHD_IMAGE,
                                        DeviceType.VHDX_IMAGE, DeviceType.QCOW2_IMAGE,
                                        DeviceType.VDI_IMAGE, DeviceType.DMG_IMAGE):
                detected_os = device.metadata.get('detected_os', 'unknown')
                if detected_os == 'windows':
                    target_tab = tab_map['windows']
                elif detected_os == 'linux':
                    target_tab = tab_map['linux']
                elif detected_os == 'macos':
                    target_tab = tab_map['macos']
                # Don't auto-navigate for unknown (let user choose)
                if target_tab is not None:
                    break

        # Update Linux/macOS tab info labels
        self._update_linux_macos_info_labels(selected_devices)

        # Detect FFS bundle devices (offline forensic image — no live phone controls)
        android_bundle = next(
            (d for d in selected_devices
             if d.device_type == DeviceType.MOBILE_FFS_BUNDLE_ANDROID),
            None,
        )
        ios_bundle = next(
            (d for d in selected_devices
             if d.device_type == DeviceType.MOBILE_FFS_BUNDLE_IOS),
            None,
        )

        # Update Android tab: prefer bundle banner over live-device root banner
        if android_bundle:
            self._update_android_bundle_status(android_bundle)
        else:
            android_device = next(
                (d for d in selected_devices
                 if d.device_type == DeviceType.ANDROID_DEVICE),
                None,
            )
            if android_device:
                is_rooted = android_device.metadata.get('rooted', False)
                self._update_android_root_status(is_rooted=is_rooted, connected=True)
            else:
                self._update_android_root_status(is_rooted=False, connected=False)

        # Update iOS tab info label
        self._update_ios_info_label(ios_bundle, selected_devices)

        # Keep the artifact list scoped to the selected evidence source.
        # Example: iOS USB on a Windows PC must not leave Windows artifacts
        # checked from the host profile.
        self._apply_selected_source_scope(selected_devices)
        self._update_source_scope_status(selected_devices)

        # Auto-navigate to detected tab (only if different from current)
        if target_tab is not None and self.artifacts_tab.currentIndex() != target_tab:
            self.artifacts_tab.setCurrentIndex(target_tab)

    def _update_linux_macos_info_labels(self, selected_devices: list):
        """Update Linux/macOS tab info labels"""
        linux_images = []
        macos_images = []

        for device in selected_devices:
            # Local system devices
            if device.device_type == DeviceType.LINUX_LOCAL_SYSTEM:
                is_root = device.metadata.get('is_root', False)
                root_tag = " [root]" if is_root else " [non-root]"
                linux_images.append(f"Local system{root_tag}")
            elif device.device_type == DeviceType.MACOS_LOCAL_SYSTEM:
                is_root = device.metadata.get('is_root', False)
                root_tag = " [root]" if is_root else " [non-root]"
                macos_images.append(f"Local system{root_tag}")
            # Disk images
            elif device.device_type in (DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE,
                                        DeviceType.VMDK_IMAGE, DeviceType.VHD_IMAGE,
                                        DeviceType.VHDX_IMAGE, DeviceType.QCOW2_IMAGE,
                                        DeviceType.VDI_IMAGE, DeviceType.DMG_IMAGE):
                detected_os = device.metadata.get('detected_os', 'unknown')
                fs_type = device.metadata.get('filesystem_type', 'Unknown')

                if detected_os == 'linux':
                    linux_images.append(f"{device.display_name} ({fs_type})")
                elif detected_os == 'macos':
                    macos_images.append(f"{device.display_name} ({fs_type})")

        # Update Linux tab info
        if hasattr(self, 'linux_info_label'):
            if linux_images:
                self.linux_info_label.setText(
                    f"✓ Selected: {', '.join(linux_images)}"
                )
                self.linux_info_label.setStyleSheet(f"color: {COLORS['success']}; font-size: 9px;")
            else:
                self.linux_info_label.setText("Select a Linux disk image or local system from device list")
                self.linux_info_label.setStyleSheet(f"color: {COLORS['text_tertiary']}; font-size: 9px;")

        # Update macOS tab info
        if hasattr(self, 'macos_info_label'):
            if macos_images:
                self.macos_info_label.setText(
                    f"✓ Selected: {', '.join(macos_images)}"
                )
                self.macos_info_label.setStyleSheet(f"color: {COLORS['success']}; font-size: 9px;")
            else:
                self.macos_info_label.setText("Select a macOS disk image or local system from device list")
                self.macos_info_label.setStyleSheet(f"color: {COLORS['text_tertiary']}; font-size: 9px;")

    def _update_android_bundle_status(self, bundle_device):
        """Display Android tab status for an FFS bundle (offline filesystem image)."""
        if not hasattr(self, 'android_root_banner'):
            return

        fmt = bundle_device.metadata.get('format_id', 'FFS')
        size = bundle_device.size_display
        self.android_root_banner.setText(
            f"FFS Bundle Loaded — {fmt} ({size}) — Full filesystem access"
        )
        self.android_root_banner.setStyleSheet(
            f"background: {COLORS['success_bg']}; color: {COLORS['success']}; "
            f"font-size: 9px; border-radius: 4px; padding: 2px 8px;"
        )
        if hasattr(self, 'android_limitation_label'):
            self.android_limitation_label.setVisible(False)

        supported = self._bundle_supported_artifacts(bundle_device, "android")
        for artifact_type, cb in self.artifact_checks.items():
            info = ARTIFACT_TYPES.get(artifact_type, {})
            if info.get('category') != 'android':
                continue
            if self._disable_disallowed_artifact(artifact_type, cb):
                continue
            if self._disable_unsupported_mobile_artifact(
                artifact_type, cb, supported, "Android FFS bundle"
            ):
                continue
            cb.setEnabled(True)
            cb.setChecked(True)
            cb.setToolTip(
                info.get('description', '') +
                " | Source: FFS bundle (offline filesystem image)"
            )

    def _set_ios_artifact_states(
        self,
        source: str,
        source_label: str,
        supported_override: Optional[set] = None,
    ):
        """Enable only iOS artifacts supported by the selected iOS source."""
        supported = supported_override or self._mobile_supported_artifacts("ios", source)
        for artifact_type, cb in self.artifact_checks.items():
            info = ARTIFACT_TYPES.get(artifact_type, {})
            if info.get('category') != 'ios':
                continue
            if self._disable_disallowed_artifact(artifact_type, cb):
                continue
            if self._disable_unsupported_mobile_artifact(
                artifact_type, cb, supported, source_label
            ):
                continue
            cb.setEnabled(True)
            cb.setChecked(True)
            cb.setToolTip(
                info.get('description', '') +
                f" | Source: {source_label}"
            )

    def _disable_ios_artifacts_without_source(self):
        """Disable iOS artifacts until an iOS source is selected."""
        for artifact_type, cb in self.artifact_checks.items():
            info = ARTIFACT_TYPES.get(artifact_type, {})
            if info.get('category') != 'ios':
                continue
            cb.setEnabled(False)
            cb.setChecked(False)
            tooltip = info.get('description', '')
            cb.setToolTip((tooltip + " | " if tooltip else "") + "Select an iOS source first")

    def _update_ios_info_label(self, ios_bundle, selected_devices):
        """Update iOS tab info label for backup or FFS bundle selection."""
        if not hasattr(self, 'ios_info_label'):
            return

        if ios_bundle:
            fmt = ios_bundle.metadata.get('format_id', 'FFS')
            size = ios_bundle.size_display
            self.ios_info_label.setText(
                f"✓ FFS Bundle: {ios_bundle.display_name} — {fmt} ({size})"
            )
            self.ios_info_label.setStyleSheet(
                f"color: {COLORS['success']}; font-size: 9px;"
            )

            self._set_ios_artifact_states(
                "ffs",
                "iOS FFS bundle (offline filesystem image)",
                supported_override=self._bundle_supported_artifacts(ios_bundle, "ios"),
            )
            return

        ios_backup = next(
            (d for d in selected_devices if d.device_type == DeviceType.IOS_BACKUP),
            None,
        )
        if ios_backup:
            self.ios_info_label.setText(f"✓ Backup: {ios_backup.display_name}")
            self.ios_info_label.setStyleSheet(f"color: {COLORS['success']}; font-size: 9px;")
            self._set_ios_artifact_states("backup", "iOS backup extraction")
            return

        ios_device = next(
            (d for d in selected_devices if d.device_type == DeviceType.IOS_DEVICE),
            None,
        )
        if ios_device:
            self.ios_info_label.setText(
                f"✓ iOS USB: {ios_device.display_name} - backup-based extraction"
            )
            self.ios_info_label.setStyleSheet(f"color: {COLORS['success']}; font-size: 9px;")
            self._set_ios_artifact_states("backup", "iOS USB backup extraction")
            return

        self.ios_info_label.setText("Select iOS backup, iOS device, or FFS bundle from device list")
        self.ios_info_label.setStyleSheet(f"color: {COLORS['text_tertiary']}; font-size: 9px;")
        self._disable_ios_artifacts_without_source()

    def _update_collect_button_state(self):
        """Update collect button state and explain why it is disabled."""
        if getattr(self, '_collection_starting', False) or getattr(self, '_collection_running', False):
            self.collect_btn.setEnabled(False)
            self.collect_btn.setToolTip("Collection is already starting or running")
            return

        has_token = self.collection_token is not None
        has_devices = len(self.device_manager.get_selected_devices()) > 0
        has_artifacts = bool(self._selected_artifact_types())
        ready = has_token and has_devices and has_artifacts

        self.collect_btn.setEnabled(ready)
        if ready:
            self.collect_btn.setToolTip("Ready to start collection")
            return

        missing = []
        if not has_token:
            missing.append("authenticate the session token")
        if not has_devices:
            missing.append("select at least one evidence source")
        if not has_artifacts:
            missing.append("select at least one artifact")
        self.collect_btn.setToolTip("Start Collection is disabled: " + ", ".join(missing))

    def _artifact_checkbox_enabled_for_collection(self, cb) -> bool:
        """Return checkbox state ignoring temporary parent locks during start."""
        artifacts_group = getattr(self, 'artifacts_group', None)
        if artifacts_group is not None:
            try:
                return cb.isEnabledTo(artifacts_group)
            except Exception:
                pass
        return cb.isEnabled()

    def _selected_artifact_types(self) -> list:
        """Return artifact types that are both enabled by policy/source and selected."""
        return [
            artifact_type
            for artifact_type, cb in self.artifact_checks.items()
            if self._artifact_checkbox_enabled_for_collection(cb) and cb.isChecked()
        ]

    def _log_mobile_preflight(self, selected_devices: list, selected_artifacts: list):
        """Log mobile collection readiness without changing collection behavior."""
        selected_set = set(selected_artifacts or [])
        for device in selected_devices:
            try:
                if device.device_type == DeviceType.ANDROID_DEVICE:
                    self._log_android_preflight(device, selected_set)
                elif device.device_type == DeviceType.IOS_BACKUP:
                    self._log_ios_backup_preflight(device, selected_set)
                elif device.device_type == DeviceType.IOS_DEVICE:
                    self._log_ios_device_preflight(device, selected_set)
                elif device.device_type in (
                    DeviceType.MOBILE_FFS_BUNDLE_ANDROID,
                    DeviceType.MOBILE_FFS_BUNDLE_IOS,
                ):
                    self._log_mobile_ffs_preflight(device, selected_set)
            except Exception as e:
                self._log(
                    f"[WARN] Mobile preflight skipped for {device.display_name}: {e}"
                )

    def _log_android_preflight(self, device, selected_set: set):
        meta = device.metadata or {}
        capability = meta.get('collection_capability') or {}
        rooted = meta.get('rooted', False)
        mode = "root" if rooted else "non-root"
        available = capability.get('available_artifacts')
        implemented = capability.get('implemented_artifacts')
        root_only = capability.get('root_only_artifacts')

        if available is not None and implemented is not None:
            self._log(
                f"Android preflight: {device.display_name} [{mode}] - "
                f"{available}/{implemented} implemented artifact types available"
            )
        else:
            self._log(f"Android preflight: {device.display_name} [{mode}]")

        if not rooted and root_only:
            self._log(
                f"[WARN] Android non-root mode: {root_only} root-only artifact types "
                "will remain unavailable unless the device is rooted."
            )

        try:
            from collectors.android_collector import ANDROID_ARTIFACT_TYPES
            root_only_selected = [
                artifact_type for artifact_type in selected_set
                if artifact_type in ANDROID_ARTIFACT_TYPES
                and ANDROID_ARTIFACT_TYPES[artifact_type].get('requires_root')
                and not (
                    'root' in ANDROID_ARTIFACT_TYPES[artifact_type]
                    and 'nonroot' in ANDROID_ARTIFACT_TYPES[artifact_type]
                )
            ]
            if root_only_selected and not rooted:
                self._log(
                    "[WARN] Android selection contains root-only artifacts; "
                    "they will be skipped by the collector in non-root mode."
                )
        except Exception:
            pass

    def _log_ios_backup_preflight(self, device, selected_set: set):
        meta = device.metadata or {}
        encrypted = meta.get('encrypted', False)
        state = "encrypted" if encrypted else "unencrypted"
        selected_ios = [
            artifact_type for artifact_type in selected_set
            if ARTIFACT_TYPES.get(artifact_type, {}).get('category') == 'ios'
        ]
        self._log(
            f"iOS backup preflight: {device.display_name} [{state}] - "
            f"{len(selected_ios)} iOS artifact types selected"
        )
        if encrypted:
            self._log("iOS encrypted backup: password prompt will be shown before collection.")
        else:
            self._log(
                "[WARN] iOS unencrypted backup: collection is supported, "
                "but protected data classes may be incomplete."
            )

    def _log_ios_device_preflight(self, device, selected_set: set):
        selected_ios = [
            artifact_type for artifact_type in selected_set
            if ARTIFACT_TYPES.get(artifact_type, {}).get('category') == 'ios'
        ]
        self._log(
            f"iOS USB preflight: {device.display_name} - "
            "backup-based extraction will be used "
            f"({len(selected_ios)} iOS artifact types selected)"
        )

    def _log_mobile_ffs_preflight(self, device, selected_set: set):
        meta = device.metadata or {}
        present = set(meta.get("present_artifacts") or [])
        platform = meta.get("platform") or device.device_type.name
        selected_mobile = [
            artifact_type for artifact_type in selected_set
            if ARTIFACT_TYPES.get(artifact_type, {}).get('category') in ('android', 'ios')
        ]
        if present:
            unsupported_selected = sorted(set(selected_mobile) - present)
            self._log(
                f"Mobile FFS preflight: {device.display_name} [{platform}] - "
                f"{len(present)} artifact types present in bundle"
            )
            if unsupported_selected:
                self._log(
                    "[WARN] Mobile FFS selection contains artifacts not present in "
                    "the bundle; they should be disabled by the source-aware UI."
                )
        else:
            self._log(
                f"[WARN] Mobile FFS preflight: {device.display_name} [{platform}] - "
                "present-artifact scan unavailable; using path-spec support."
            )

    def check_server_connection(self):
        """Check if server is reachable"""
        validator = TokenValidator(self.config['server_url'])
        result = validator.check_server_health()
        # Support both old (bool) and new (tuple) return
        if isinstance(result, tuple):
            success, error_detail = result
        else:
            success, error_detail = result, None

        if success:
            self.server_status.setText("Server: Connected")
            self.server_status.setStyleSheet("color: #4cc9f0;")
            self._log("Server connection established")
        else:
            self.server_status.setText("Server: Disconnected")
            self.server_status.setStyleSheet("color: #f72585;")
            if error_detail and "SSL" in error_detail:
                self._log(f"SSL certificate error connecting to server", error=True)
            else:
                self._log(f"Cannot connect to server: {self.config['server_url']}", error=True)
            if error_detail:
                self._log(f"Detail: {error_detail}", error=True)

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

        # Determine category based on current tab index
        current_tab = self.artifacts_tab.currentIndex()
        category_map = {0: 'windows', 1: 'android', 2: 'ios', 3: 'linux', 4: 'macos', 5: 'ai_activity'}
        current_category = category_map.get(current_tab, 'windows')

        for artifact_type, cb in self.artifact_checks.items():
            if not self._artifact_checkbox_enabled_for_collection(cb):
                continue

            # Check artifact category
            artifact_info = ARTIFACT_TYPES.get(artifact_type, {})
            artifact_category = artifact_info.get('category', 'windows')

            # Windows tab: items without category or 'windows', exclude mobile
            if current_category == 'windows':
                if artifact_type.startswith('mobile_'):
                    continue
                if artifact_category not in ('windows', None) and 'category' in artifact_info:
                    continue

            # Other tabs: matching category only
            elif artifact_category != current_category:
                continue

            cb.setChecked(checked)

        self._update_collect_button_state()

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
            # [Security] Original session token not stored (unnecessary after validation)
            # Session verified with session_id + collection_token at collection start
            self.session_token = None  # Remove original token from memory
            self.session_id = result.session_id
            self.case_id = result.case_id
            self.collection_token = result.collection_token
            self.collection_profile_id = getattr(result, 'collection_profile_id', None)
            self.collection_profile_targets = getattr(result, 'collection_profile_targets', None) or []
            self.profile_artifact_types = set()
            for registry in (
                ARTIFACT_TYPES, ARTIFACT_MFT_FILTERS,
                ANDROID_ARTIFACT_TYPES, IOS_ARTIFACT_TYPES,
                LINUX_ARTIFACT_TYPES, MACOS_ARTIFACT_TYPES,
            ):
                self.profile_artifact_types.update(
                    apply_collection_profile_to_registry(self.collection_profile_targets, registry)
                )
            android_ffs_count, ios_ffs_count = apply_collection_profile_to_mobile_ffs(
                self.collection_profile_targets
            )
            refreshed_ffs_bundles = 0
            if android_ffs_count or ios_ffs_count:
                refreshed_ffs_bundles = self.device_manager.refresh_mobile_ffs_bundles()
            self._build_artifact_tabs(preserve_index=True)
            # Wire server-issued consent signing key through to the consent
            # dialog. Without this, the dialog falls back to the
            # CONSENT_SIGNING_KEY env var on the user's PC (typically unset)
            # and refuses to record consent.
            self.consent_signing_key = getattr(result, 'consent_signing_key', None)

            # [Security] Initialize request signer for HMAC-signed API calls
            from utils.hardware_id import get_hardware_id
            try:
                hw_id = get_hardware_id()
                # Pass server-provided hkdf_info if available (backward compatible)
                hkdf_info = getattr(result, 'hkdf_info', None)
                hkdf_info_bytes = hkdf_info.encode('utf-8') if hkdf_info else None
                self.request_signer = RequestSigner(hw_id, result.challenge_salt or "", result.signing_key or "", hkdf_info=hkdf_info_bytes)
            except Exception as e:
                logging.getLogger(__name__).warning(f"[RequestSigner] Init failed: {e}")
                self.request_signer = None
            # [Security] Always use config URL — never trust server_url from auth response
            # Prevents MITM attack via malicious server_url injection in auth response
            config_server_url = self.config['server_url']
            config_ws_url = self.config['ws_url']
            if result.server_url and result.server_url != config_server_url:
                logging.getLogger(__name__).warning(
                    f"[SECURITY] Server returned different URL in auth response — ignored. "
                    f"Config: {config_server_url}, Response: {result.server_url}"
                )
            # On Windows, localhost resolves to IPv6 (::1) causing Docker connection failure
            self.server_url = config_server_url.replace('://localhost', '://127.0.0.1')
            self.ws_url = config_ws_url.replace('://localhost', '://127.0.0.1')
            self.allowed_artifacts = result.allowed_artifacts or list(ARTIFACT_TYPES.keys())

            self.token_status.setText(f"Valid - Case: {self.case_id[:8]}...")
            self.token_status.setStyleSheet("color: #4cc9f0;")
            self._log(f"Token validated. Case ID: {self.case_id}")
            self._log(f"Session ID: {self.session_id}")
            self._log(f"Allowed artifacts: {', '.join(self.allowed_artifacts)}")
            if self.collection_profile_id:
                self._log(f"Server collection profile loaded: {len(self.collection_profile_targets)} authorized target(s)")
                if self.profile_artifact_types:
                    self._log(f"Runtime profile applied: {len(self.profile_artifact_types)} artifact type(s)")
                if android_ffs_count or ios_ffs_count:
                    message = (
                        f"Mobile FFS profile applied: {android_ffs_count} Android spec(s), "
                        f"{ios_ffs_count} iOS spec(s)"
                    )
                    if refreshed_ffs_bundles:
                        message += f"; refreshed {refreshed_ffs_bundles} loaded bundle(s)"
                    self._log(message)
            else:
                self._log("Server collection profile missing; uploads will be blocked", error=True)

            # [2026-04-27 Track 3] Start bidirectional control WebSocket worker.
            # The server can now push cancel/terminate/snapshot to this collector
            # in real time (was previously polling-on-next-API-call only).
            try:
                if hasattr(self, '_ws_worker') and self._ws_worker.isRunning():
                    self._ws_worker.stop()
                    self._ws_worker.wait(1000)
                self._ws_worker = WsControlWorker(
                    server_url=self.server_url,
                    ws_url=self.ws_url,
                    session_id=self.session_id,
                    collection_token=self.collection_token,
                    case_id=self.case_id,
                    request_signer=self.request_signer,
                    config=self.config,
                )
                self._ws_worker.control_event.connect(self._on_ws_control_event)
                self._ws_worker.start()
                self._log("Control WebSocket starting (real-time server notifications enabled)")
            except Exception as ws_init_err:
                # Non-fatal — collector still works via legacy 409 fallback
                self._log(f"[WARN] Control WebSocket init failed: {ws_init_err}", error=False)

            # Enable artifact selection
            # Map server artifact names to Collector names for matching
            mapped_allowed = set()
            for server_name in self.allowed_artifacts:
                # Check direct mapping
                if server_name in SERVER_TO_COLLECTOR_MAPPING:
                    mapped_allowed.add(SERVER_TO_COLLECTOR_MAPPING[server_name])
                # If already a Collector name
                if server_name in ARTIFACT_TYPES:
                    mapped_allowed.add(server_name)
                for artifact_type, info in ARTIFACT_TYPES.items():
                    if info.get('category') == server_name:
                        mapped_allowed.add(artifact_type)

            # Allow all artifacts if 'all' is included or allowed_artifacts is empty
            allow_all = 'all' in self.allowed_artifacts or '*' in self.allowed_artifacts or not result.allowed_artifacts
            self._allow_all_artifacts = allow_all
            self._mapped_allowed_artifacts = mapped_allowed

            self._log(f"Mapped artifacts for GUI: {', '.join(sorted(mapped_allowed))}")
            if allow_all:
                self._log("All artifacts are authorized by the collection token")

            enabled_count = 0
            for artifact_type, cb in self.artifact_checks.items():
                allowed = self._is_artifact_allowed(artifact_type)
                info = ARTIFACT_TYPES.get(artifact_type, {})
                default_checked = allowed and not (allow_all and info.get('default_enabled') is False)
                cb.setEnabled(allowed)
                cb.setChecked(default_checked)
                if allowed:
                    enabled_count += 1
                    if info.get('default_enabled') is False:
                        tooltip = info.get('description', '')
                        cb.setToolTip((tooltip + " | " if tooltip else "") + "Optional high-volume collection; select explicitly when needed")
                else:
                    tooltip = info.get('description', '')
                    cb.setToolTip((tooltip + " | " if tooltip else "") + "Not allowed by collection token")

            self._log(f"Authorized artifact types loaded: {enabled_count}/{len(self.artifact_checks)}")
            self._update_platform_tab_states()

            # Update collect button state including device selection status
            self._update_collect_button_state()
        else:
            self.token_status.setText(f"Invalid: {result.error}")
            self.token_status.setStyleSheet("color: #f72585;")

            # Display user-friendly error message popup
            friendly_error = translate_error(result.error or "Unknown error")
            self._log(f"Token validation failed: {friendly_error.title} - {friendly_error.message}", error=True)
            self._log(f"Solution: {friendly_error.solution}", error=True)
            QMessageBox.warning(
                self,
                f"⚠️ {friendly_error.title}",
                f"{friendly_error.message}\n\nSolution:\n{friendly_error.solution}"
            )
        self.validate_btn.setEnabled(True)

    def _start_collection(self):
        """Start collection with a guard against duplicate clicks."""
        if getattr(self, '_collection_starting', False) or getattr(self, '_collection_running', False):
            self._log("Collection is already starting or running; duplicate click ignored.")
            return

        self._collection_starting = True
        self._set_collection_inputs_locked(True)
        self.collect_btn.setEnabled(False)
        self.validate_btn.setEnabled(False)
        self.cancel_btn.setEnabled(False)
        QApplication.processEvents()

        worker_started = False
        try:
            worker_started = bool(self._start_collection_impl())
        except Exception as exc:
            self._log(f"Collection start failed: {exc}", error=True)
            QMessageBox.critical(self, "Collection Start Failed", str(exc))
            worker_started = False
        finally:
            if worker_started:
                self._collection_starting = False
                self._collection_running = True
            else:
                self._collection_starting = False
                self._collection_running = False
                self._set_collection_inputs_locked(False)
                self.validate_btn.setEnabled(True)
                self.cancel_btn.setEnabled(False)
                self._update_collect_button_state()

    def _start_collection_impl(self):
        """Start the collection process"""
        # === Session validation (required before collection start) ===
        # Detect cancelled cases, expired sessions, etc.
        # [Security] Use session_id + collection_token instead of original token
        if not self.session_id or not self.collection_token:
            QMessageBox.warning(
                self,
                "Session Required",
                "No valid session found.\nPlease enter a token and click 'Validate Token'."
            )
            return

        self._log("Validating session before starting collection...")
        validator = TokenValidator(self.config['server_url'])
        result = validator.validate_session(self.session_id, self.collection_token)

        if not result.can_proceed:
            reason = result.reason or "Unknown error"
            self._log(f"Session validation failed: {reason}", error=True)
            self.token_status.setText("Invalid - New token required")
            self.token_status.setStyleSheet("color: #f72585;")

            # Guide user to get new token
            QMessageBox.warning(
                self,
                "Session Validation Failed",
                f"Cannot proceed with collection using current session.\n\n"
                f"Reason: {reason}\n\n"
                f"Solution:\n"
                f"1. Get a new token from the web platform.\n"
                f"2. Enter the new token and click 'Validate Token'."
            )
            # Clear session information
            self.session_id = None
            self.collection_token = None
            self.collect_btn.setEnabled(False)
            return

        # Session validation success
        self._log(f"Session validated (Case: {result.case_id}, Status: {result.case_status})")

        # Check device selection
        selected_devices = self.device_manager.get_selected_devices()
        if not selected_devices:
            QMessageBox.warning(self, "Error", "Please select at least one device")
            return

        self._apply_selected_source_scope(selected_devices, force=True)
        selected = self._selected_artifact_types()
        if not selected:
            checked = [
                artifact_type
                for artifact_type, cb in self.artifact_checks.items()
                if cb.isChecked()
            ]
            blocked_checked = [
                artifact_type
                for artifact_type, cb in self.artifact_checks.items()
                if cb.isChecked() and not self._artifact_checkbox_enabled_for_collection(cb)
            ]
            self._log(
                f"No collectable artifacts selected at start "
                f"(checked={len(checked)}, blocked_by_source_or_policy={len(blocked_checked)})",
                error=True,
            )
            QMessageBox.warning(self, "Error", "Please select at least one artifact type")
            return

        self._log_mobile_preflight(selected_devices, selected)
        self._update_source_scope_status(selected_devices)

        if not self._confirm_collection_plan(selected_devices, selected):
            self._log("Collection cancelled: User did not confirm the collection plan")
            return

        self._log(f"Starting collection from {len(selected_devices)} evidence source(s)")

        # Legal consent check (required) - server API integration
        from gui.consent_dialog import show_consent_dialog

        # Detect system language (default: English)
        import locale
        try:
            system_lang = locale.getlocale()[0] or "en"
        except (ValueError, TypeError):
            system_lang = "en"
        lang_code = system_lang.split("_")[0] if "_" in system_lang else system_lang
        if lang_code not in ("en", "ko", "ja", "zh"):
            lang_code = "en"

        consent_record = show_consent_dialog(
            parent=self,
            server_url=self.server_url,
            session_id=self.session_id,
            case_id=self.case_id,
            language=lang_code,
            server_signing_key=getattr(self, 'consent_signing_key', None),
        )

        if not consent_record:
            self._log("Collection cancelled: User did not consent", error=True)
            QMessageBox.information(
                self,
                "Collection Cancelled",
                "Legal consent is required.\nCollection cannot proceed without consent."
            )
            return

        # Save consent record
        self.consent_record = consent_record
        self._log(f"Legal consent obtained: {consent_record['consent_hash'][:16]}...")

        # BitLocker detection and decryption handling
        # Note: BitLocker detection applies only to physical disks (excludes E01/RAW images)
        bitlocker_decryptor = None
        bitlocker_info = None

        # Check if any selected device is a physical disk
        has_physical_disk = any(
            d.device_type == DeviceType.WINDOWS_PHYSICAL_DISK
            for d in selected_devices
        )

        if BITLOCKER_AVAILABLE and has_physical_disk:
            self._log("Checking for BitLocker encrypted volumes...")
            bitlocker_result = detect_bitlocker_on_system_drive()

            if bitlocker_result.is_encrypted:
                self._log(f"BitLocker encrypted volume detected (Partition #{bitlocker_result.partition_index})")

                # Show BitLocker dialog
                from gui.bitlocker_dialog import show_bitlocker_dialog

                dialog_result = show_bitlocker_dialog(
                    partition_info={
                        'partition_index': bitlocker_result.partition_index,
                        'partition_offset': bitlocker_result.partition_offset,
                        'partition_size': bitlocker_result.partition_size,
                        'encryption_method': bitlocker_result.encryption_method,
                    },
                    pybde_available=is_pybde_installed(),
                    config=self.config,
                    parent=self
                )

                if dialog_result.success and not dialog_result.skip:
                    # Auto-unlock mode (manage-bde)
                    if dialog_result.auto_decrypt:
                        self._log("BitLocker auto-unlock mode selected (manage-bde)")
                        try:
                            from utils.bitlocker import disable_bitlocker, get_bitlocker_status

                            # Show progress dialog
                            from PyQt6.QtWidgets import QProgressDialog
                            progress = QProgressDialog(
                                "Decrypting BitLocker...\n"
                                "This may take several minutes to hours depending on disk size.",
                                "Cancel",
                                0, 100,
                                self
                            )
                            progress.setWindowTitle("Decrypting BitLocker")
                            progress.setWindowModality(Qt.WindowModality.WindowModal)
                            progress.setMinimumDuration(0)
                            progress.setValue(0)
                            progress.show()

                            # Update progress via callback
                            def update_progress(percentage, message):
                                if progress.wasCanceled():
                                    return
                                progress.setLabelText(message)
                                progress.setValue(int(percentage))
                                QApplication.processEvents()

                            # Execute BitLocker unlock
                            result = disable_bitlocker(
                                drive="C:",
                                progress_callback=update_progress,
                                wait_for_completion=True,
                                check_interval=5
                            )

                            progress.close()

                            if result.success:
                                self._log("BitLocker unlock complete! Proceeding with MFT-based collection.")
                                # Set auto-unlock flag (for re-encryption after collection)
                                self._bitlocker_auto_decrypt_used = True
                            else:
                                self._log(f"BitLocker unlock failed: {result.error}", error=True)
                                QMessageBox.warning(
                                    self,
                                    "BitLocker Unlock Failed",
                                    f"Failed to unlock BitLocker:\n{result.error}\n\n"
                                    "Proceeding with fallback method (directory traversal)."
                                )
                                self._bitlocker_auto_decrypt_used = False

                        except Exception as e:
                            if 'progress' in dir() and progress:
                                progress.close()
                            self._log(f"BitLocker auto-unlock error: {e}", error=True)
                            QMessageBox.warning(
                                self,
                                "Error",
                                f"Error during BitLocker unlock:\n{e}\n\n"
                                "Proceeding with fallback method."
                            )
                            self._bitlocker_auto_decrypt_used = False
                    else:
                        # Try pybde-based volume unlock with retry on wrong input
                        while True:
                            self._log(f"Attempting BitLocker unlock... (Key type: {dialog_result.key_type})")

                            try:
                                decryptor = BitLockerDecryptor.from_detection_result(
                                    drive_number=0,
                                    detection_result=bitlocker_result
                                )

                                # Unlock based on selected method
                                self._log(f"[DEBUG] BitLocker key_type='{dialog_result.key_type}'")
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
                                    self._log(f"[ERROR] Unsupported key type: '{dialog_result.key_type}'", error=True)
                                    unlock_result = BitLockerUnlockResult(
                                        success=False,
                                        error_message=f"Unsupported key type: {dialog_result.key_type}"
                                    )

                                # [Security] Clear key from memory after use
                                dialog_result.key_value = None

                                if unlock_result and unlock_result.success:
                                    bitlocker_decryptor = decryptor
                                    bitlocker_info = unlock_result.volume_info
                                    self._log("BitLocker decryption successful! Proceeding with collection from encrypted volume.")
                                    break  # Success
                                else:
                                    error_msg = (unlock_result.error_message if unlock_result else "") or "Decryption failed"
                                    self._log(f"BitLocker decryption failed: {error_msg}", error=True)
                                    decryptor.close()

                                    # Ask user: retry or abort
                                    retry = QMessageBox.question(
                                        self,
                                        "BitLocker Decryption Failed",
                                        f"Decryption failed: {error_msg}\n\n"
                                        "Try again with a different key?",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                        QMessageBox.StandardButton.Yes
                                    )
                                    if retry == QMessageBox.StandardButton.Yes:
                                        dialog_result = show_bitlocker_dialog(
                                            partition_info={
                                                'partition_index': bitlocker_result.partition_index,
                                                'partition_offset': bitlocker_result.partition_offset,
                                                'partition_size': bitlocker_result.partition_size,
                                                'encryption_method': bitlocker_result.encryption_method,
                                            },
                                            pybde_available=is_pybde_installed(),
                                            config=self.config,
                                            parent=self
                                        )
                                        if not dialog_result.success and not dialog_result.skip:
                                            # Cancel pressed — abort collection
                                            self._log("BitLocker dialog cancelled. Aborting collection.")
                                            QMessageBox.information(
                                                self, "Collection Cancelled",
                                                "BitLocker configuration was cancelled.\nCollection will not proceed."
                                            )
                                            return
                                        elif dialog_result.skip:
                                            self._log("User skipped decryption. Proceeding without decryption.")
                                            break
                                        continue  # Retry with new key
                                    else:
                                        # No = abort collection
                                        self._log("BitLocker decryption cancelled. Aborting collection.")
                                        QMessageBox.information(
                                            self, "Collection Cancelled",
                                            "BitLocker decryption was cancelled.\nCollection will not proceed."
                                        )
                                        return

                            except BitLockerError as e:
                                self._log(f"BitLocker error: {e}", error=True)
                                retry = QMessageBox.question(
                                    self,
                                    "BitLocker Error",
                                    f"Error processing BitLocker:\n{e}\n\n"
                                    "Try again?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                    QMessageBox.StandardButton.Yes
                                )
                                if retry == QMessageBox.StandardButton.No:
                                    self._log("BitLocker decryption cancelled. Aborting collection.")
                                    QMessageBox.information(
                                        self, "Collection Cancelled",
                                        "BitLocker decryption was cancelled.\nCollection will not proceed."
                                    )
                                    return
                                continue  # Retry
                            except Exception as e:
                                self._log(f"Unexpected error: {e}", error=True)
                                if 'decryptor' in locals():
                                    try:
                                        decryptor.close()
                                    except Exception:
                                        pass
                                retry = QMessageBox.question(
                                    self,
                                    "Error",
                                    f"An error occurred:\n{e}\n\n"
                                    "Try again?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                    QMessageBox.StandardButton.Yes
                                )
                                if retry == QMessageBox.StandardButton.No:
                                    self._log("BitLocker error. Aborting collection.")
                                    QMessageBox.information(
                                        self, "Collection Cancelled",
                                        "Collection will not proceed due to an error."
                                    )
                                    return
                                continue  # Retry

                elif dialog_result.skip:
                    self._log("Skipping BitLocker decryption, proceeding with collection in encrypted state.")
                else:
                    # Cancelled - abort collection
                    self._log("BitLocker dialog cancelled. Aborting collection.")
                    QMessageBox.information(
                        self,
                        "Collection Cancelled",
                        "BitLocker configuration was cancelled. Collection will not proceed."
                    )
                    return
            else:
                self._log("No BitLocker encrypted volume detected.")

        # Encryption detection for disk images (BitLocker + LUKS)
        # Scans partitions in E01/RAW/VMDK/VHD/VHDX/QCOW2/VDI for encryption signatures
        image_bitlocker_decryptors = {}  # device_id -> BitLockerDecryptor
        luks_decryptors = {}  # device_id -> LUKSDecryptor
        if BITLOCKER_AVAILABLE:
            disk_image_types = (
                DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE,
                DeviceType.VMDK_IMAGE, DeviceType.VHD_IMAGE,
                DeviceType.VHDX_IMAGE, DeviceType.QCOW2_IMAGE,
                DeviceType.VDI_IMAGE, DeviceType.DMG_IMAGE,
            )
            for device in selected_devices:
                if device.device_type not in disk_image_types:
                    continue

                file_path = device.metadata.get('file_path')
                if not file_path:
                    continue

                try:
                    from utils.bitlocker.disk_backends import create_disk_backend
                    backend = create_disk_backend(file_path)
                    try:
                        partitions = BitLockerDecryptor._detect_partitions(backend)
                        for p in partitions:
                            # --- BitLocker in disk image ---
                            if p.filesystem == 'BitLocker':
                                self._log(f"BitLocker encrypted partition detected: {device.display_name} (Partition #{p.index})")

                                from gui.bitlocker_dialog import show_bitlocker_dialog
                                dialog_result = show_bitlocker_dialog(
                                    partition_info={
                                        'partition_index': p.index,
                                        'partition_offset': p.offset,
                                        'partition_size': p.size,
                                        'encryption_method': '',
                                    },
                                    pybde_available=is_pybde_installed(),
                                    config=self.config,
                                    parent=self
                                )

                                # Retry loop for disk image BitLocker
                                while True:
                                    if dialog_result.success and not dialog_result.skip:
                                        # manage-bde (auto_decrypt) is only for live systems
                                        if getattr(dialog_result, 'auto_decrypt', False):
                                            self._log("Auto-decrypt (manage-bde) is not available for disk images.", error=True)
                                            QMessageBox.warning(
                                                self, "Not Supported",
                                                "Auto-decrypt (manage-bde) only works on live Windows systems.\n"
                                                "Please use Recovery Key, Password, or BEK file instead."
                                            )
                                            # Re-show dialog
                                            dialog_result = show_bitlocker_dialog(
                                                partition_info={'partition_index': p.index, 'partition_offset': p.offset,
                                                                'partition_size': p.size, 'encryption_method': ''},
                                                pybde_available=is_pybde_installed(), config=self.config, parent=self
                                            )
                                            continue

                                        decryptor = None
                                        try:
                                            decryptor = BitLockerDecryptor(
                                                disk_backend=backend,
                                                partition_offset=p.offset,
                                                partition_size=p.size,
                                                partition_index=p.index
                                            )

                                            self._log(f"[DEBUG] BitLocker key_type='{dialog_result.key_type}'")
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
                                                self._log(f"[ERROR] Unsupported key type: '{dialog_result.key_type}'", error=True)
                                                unlock_result = BitLockerUnlockResult(
                                                    success=False,
                                                    error_message=f"Unsupported key type: {dialog_result.key_type}"
                                                )

                                            # [Security] Clear key from memory after use
                                            dialog_result.key_value = None

                                            if unlock_result and unlock_result.success:
                                                image_bitlocker_decryptors[device.device_id] = decryptor
                                                self._log("BitLocker decryption successful!")
                                                backend = None  # don't close — owned by decryptor
                                                break  # Success — exit retry loop
                                            else:
                                                error_msg = (unlock_result.error_message if unlock_result else "") or "Decryption failed"
                                                self._log(f"BitLocker decryption failed: {error_msg}", error=True)
                                                decryptor.close()
                                                decryptor = None

                                        except (BitLockerError, Exception) as e:
                                            self._log(f"BitLocker error: {e}", error=True)
                                            error_msg = str(e) or "Decryption error"
                                            if decryptor:
                                                try:
                                                    decryptor.close()
                                                except Exception:
                                                    pass
                                                decryptor = None

                                        # Unlock failed — ask retry or abort
                                        retry = QMessageBox.question(
                                            self, "BitLocker Decryption Failed",
                                            f"Decryption failed: {error_msg}\n\n"
                                            "Try again with a different key?",
                                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                            QMessageBox.StandardButton.Yes
                                        )
                                        if retry == QMessageBox.StandardButton.No:
                                            self._log("BitLocker decryption cancelled. Aborting collection.")
                                            if backend:
                                                backend.close()
                                            QMessageBox.information(
                                                self, "Collection Cancelled",
                                                "BitLocker decryption was cancelled.\nCollection will not proceed."
                                            )
                                            return
                                        # Yes — re-show dialog
                                        dialog_result = show_bitlocker_dialog(
                                            partition_info={'partition_index': p.index, 'partition_offset': p.offset,
                                                            'partition_size': p.size, 'encryption_method': ''},
                                            pybde_available=is_pybde_installed(), config=self.config, parent=self
                                        )
                                        continue  # Retry with new key

                                    elif dialog_result.skip:
                                        self._log("Skipping BitLocker decryption for disk image.")
                                        break
                                    else:
                                        # Cancelled — abort entire collection
                                        self._log("BitLocker dialog cancelled. Aborting collection.")
                                        if backend:
                                            backend.close()
                                        QMessageBox.information(
                                            self, "Collection Cancelled",
                                            "BitLocker configuration was cancelled.\nCollection will not proceed."
                                        )
                                        return

                            # --- LUKS in disk image ---
                            elif p.filesystem == 'LUKS':
                                self._log(f"LUKS encrypted partition detected: {device.display_name} (Partition #{p.index})")

                                from gui.luks_dialog import show_luks_dialog
                                luks_result = show_luks_dialog(
                                    partition_info={
                                        'partition_index': p.index,
                                        'partition_offset': p.offset,
                                        'partition_size': p.size,
                                    },
                                    fve_available=is_fve_available(),
                                    parent=self
                                )

                                # Retry loop for disk image LUKS
                                while True:
                                    if luks_result.success and not luks_result.skip:
                                        luks_dec = None
                                        error_msg = "Decryption failed"
                                        try:
                                            luks_dec = LUKSDecryptor(
                                                disk_backend=backend,
                                                partition_offset=p.offset,
                                                partition_size=p.size,
                                                partition_index=p.index
                                            )
                                            unlock_res = luks_dec.unlock_with_passphrase(luks_result.passphrase)
                                            # [Security] Clear secret from memory after use
                                            luks_result.passphrase = None
                                            if unlock_res.success:
                                                luks_decryptors[device.device_id] = luks_dec
                                                self._log("LUKS decryption successful!")
                                                backend = None  # don't close — owned by luks_dec
                                                break  # Success — exit retry loop
                                            else:
                                                error_msg = unlock_res.error_message or "Decryption failed"
                                                self._log(f"LUKS decryption failed: {error_msg}", error=True)
                                                luks_dec.close()
                                                luks_dec = None
                                        except Exception as e:
                                            self._log(f"LUKS error: {e}", error=True)
                                            error_msg = str(e) or "LUKS error"
                                            if luks_dec:
                                                try:
                                                    luks_dec.close()
                                                except Exception:
                                                    pass
                                                luks_dec = None

                                        # Unlock failed — ask retry or abort
                                        retry = QMessageBox.question(
                                            self, "LUKS Decryption Failed",
                                            f"Decryption failed: {error_msg}\n\n"
                                            "Try again with a different secret?",
                                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                            QMessageBox.StandardButton.Yes
                                        )
                                        if retry == QMessageBox.StandardButton.No:
                                            self._log("LUKS decryption cancelled. Aborting collection.")
                                            if backend:
                                                backend.close()
                                            QMessageBox.information(
                                                self, "Collection Cancelled",
                                                "LUKS decryption was cancelled.\nCollection will not proceed."
                                            )
                                            return
                                        # Yes — re-show dialog
                                        luks_result = show_luks_dialog(
                                            partition_info={'partition_index': p.index, 'partition_offset': p.offset,
                                                            'partition_size': p.size},
                                            fve_available=is_fve_available(), parent=self
                                        )
                                        continue  # Retry with new secret

                                    elif luks_result.skip:
                                        self._log("Skipping LUKS decryption.")
                                        break
                                    else:
                                        # Cancelled — abort entire collection
                                        self._log("LUKS dialog cancelled. Aborting collection.")
                                        if backend:
                                            backend.close()
                                        QMessageBox.information(
                                            self, "Collection Cancelled",
                                            "Encryption configuration was cancelled.\nCollection will not proceed."
                                        )
                                        return
                    finally:
                        if backend:
                            backend.close()
                except Exception as e:
                    self._log(f"Encryption detection failed for {device.display_name}: {e}", error=True)

        # iOS encrypted backup detection and password handling
        ios_backup_password = None
        has_encrypted_ios = any(
            d.device_type == DeviceType.IOS_BACKUP and d.metadata.get('encrypted')
            for d in selected_devices
        )

        if has_encrypted_ios:
            self._log("Encrypted iOS backup detected, requesting password...")

            # Get backup info for dialog
            encrypted_device = next(
                d for d in selected_devices
                if d.device_type == DeviceType.IOS_BACKUP and d.metadata.get('encrypted')
            )

            from gui.ios_password_dialog import show_ios_password_dialog

            # Check if decryption library is available
            from collectors.ios_backup_decryptor import IPHONE_BACKUP_DECRYPT_AVAILABLE

            dialog_result = show_ios_password_dialog(
                backup_info={
                    'device_name': encrypted_device.metadata.get('device_name', 'Unknown'),
                    'ios_version': encrypted_device.metadata.get('ios_version', ''),
                    'backup_date': encrypted_device.metadata.get('backup_date', ''),
                    'size_mb': encrypted_device.size_bytes / (1024 * 1024) if encrypted_device.size_bytes else 0,
                    'path': encrypted_device.metadata.get('path', ''),
                },
                library_available=IPHONE_BACKUP_DECRYPT_AVAILABLE,
                parent=self
            )

            if dialog_result.success:
                ios_backup_password = dialog_result.password
                dialog_result.password = ""  # Clear from dialog result
                self._log("iOS backup password accepted. Will verify during collection.")
            elif dialog_result.skip:
                self._log("Skipping encrypted iOS backup, excluding from collection.")
                selected_devices = [
                    d for d in selected_devices
                    if not (d.device_type == DeviceType.IOS_BACKUP and d.metadata.get('encrypted'))
                ]
                if not selected_devices:
                    self._log("No devices remaining after skip.", error=True)
                    QMessageBox.information(
                        self,
                        "Collection Cancelled",
                        "All selected devices were encrypted iOS backups.\n"
                        "No devices left to collect from."
                    )
                    return
            else:
                # Cancelled
                self._log("iOS backup password dialog cancelled. Aborting collection.")
                QMessageBox.information(
                    self,
                    "Collection Cancelled",
                    "iOS backup password was cancelled. Collection will not proceed."
                )
                return

        # Android device info dialog — show before collection starts
        android_devices = [
            d for d in selected_devices
            if d.device_type == DeviceType.ANDROID_DEVICE
        ]
        if android_devices:
            from gui.android_info_dialog import show_android_info_dialog
            android_result = show_android_info_dialog(
                device_info=android_devices[0].metadata,
                parent=self
            )
            if not android_result.proceed:
                self._log("Collection cancelled: Android device info dialog cancelled.")
                return

        categories = self._selected_source_categories(selected_devices)
        category_text = ", ".join(sorted(categories)) if categories else "unspecified"
        self._log(
            f"Starting collection: {len(selected_devices)} source(s), "
            f"{len(selected)} selected artifact type(s), source scope: {category_text}"
        )

        # Disable controls
        self.collect_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.validate_btn.setEnabled(False)
        self.select_all_cb.setEnabled(False)
        self.include_deleted_cb.setEnabled(False)
        for cb in self.artifact_checks.values():
            cb.setEnabled(False)

        # Phase 2.1: Get Android/iOS options
        android_serial = getattr(self, '_android_device_serial', None)
        ios_backup = getattr(self, '_ios_backup_path', None)

        # Phase 3.1: Get Linux/macOS mount paths
        linux_mount = self.linux_mount_path.text().strip() if hasattr(self, 'linux_mount_path') else None
        macos_mount = self.macos_mount_path.text().strip() if hasattr(self, 'macos_mount_path') else None

        # Start worker thread
        self.worker = CollectionWorker(
            server_url=self.server_url,
            ws_url=self.ws_url,
            session_id=self.session_id,
            collection_token=self.collection_token,
            case_id=self.case_id,
            artifacts=selected,
            consent_record=self.consent_record,  # P0 legal requirement
            # Selected devices list
            selected_devices=selected_devices,
            # Phase 2.1: Memory/mobile options
            android_device_serial=android_serial,
            ios_backup_path=ios_backup,
            # Phase 3.1: Linux/macOS options
            linux_mount_path=linux_mount if linux_mount else None,
            macos_mount_path=macos_mount if macos_mount else None,
            # BitLocker decrypted volume (physical disk)
            bitlocker_decryptor=bitlocker_decryptor,
            # BitLocker decrypted volumes (disk images)
            image_bitlocker_decryptors=image_bitlocker_decryptors,
            # LUKS decrypted volumes (disk images)
            luks_decryptors=luks_decryptors,
            # iOS encrypted backup password
            ios_backup_password=ios_backup_password,
            # Include deleted files option
            include_deleted=self.include_deleted_cb.isChecked(),
            # Application config (for security settings)
            config=self.config,
            # Request signing
            request_signer=self.request_signer,
            collection_profile_id=self.collection_profile_id,
        )
        self.worker.progress_updated.connect(self._update_progress)
        self.worker.file_collected.connect(self._add_collected_file)
        self.worker.log_message.connect(self._log)
        self.worker.finished.connect(self._collection_finished)
        # iOS USB: password dialog + status update callbacks
        self.worker.password_requested.connect(self._on_ios_password_requested)
        self.worker.ios_status_update.connect(
            lambda msg: self._show_ios_status(msg) if hasattr(self, '_ios_status_dialog') and self._ios_status_dialog else None
        )
        # Reserved extension signal: device unlock dialog
        self.worker.unlock_requested.connect(self._on_unlock_requested)
        self.worker.start()

        # Start heartbeat timer (elapsed time indicator)
        self._collection_start_time = datetime.now()
        self._heartbeat_idx = 0
        self.elapsed_label.setText("")
        self._heartbeat_timer.start()

        # Show preparing dialog for iOS USB devices
        # (closes when backup progress fires or collection finishes)
        if any(d.device_type == DeviceType.IOS_DEVICE for d in selected_devices):
            self._show_ios_status(
                "Preparing iOS backup...\n"
                "Connecting to device and checking encryption status."
            )

        return True

    def _check_for_updates(self):
        """Check for updates via GitHub Releases API (background)"""
        try:
            from core.updater import check_for_update, show_update_dialog
            update_info = check_for_update()
            if update_info:
                show_update_dialog(self, update_info)
        except Exception:
            pass  # Never block the app for update check failures

    def _cancel_collection(self):
        """Cancel ongoing collection"""
        if hasattr(self, 'worker') and self.worker.isRunning():
            confirm = QMessageBox.question(
                self,
                "Cancel Collection",
                "Are you sure you want to cancel the collection?\n"
                "All progress will be lost.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if confirm != QMessageBox.StandardButton.Yes:
                return

            self._close_ios_status()
            self.worker.cancel()
            self._log("Collection cancelled by user")

            # [Security] Notify server of cancellation (clear Redis active collection state)
            # Must run BEFORE _clear_session_data() since it needs session_id/collection_token
            self._notify_server_cancel()

            # Immediately clear session data so user must enter new token
            # Prevents accidentally re-authenticating with the old (used) token
            self._clear_session_data()
            self.token_status.setText("Cancelled - New token required")
            self.token_status.setStyleSheet("color: #ffc107;")

    def _on_ios_password_requested(self, error_msg: str):
        """
        Handle iOS USB password request from collector thread.

        Runs in GUI thread (Qt signal connection). Shows dialog, then
        unblocks the worker thread with the result.
        """
        # Close preparing indicator before showing password dialog
        self._close_ios_status()

        # Don't show dialog if collection was already cancelled
        if hasattr(self, 'worker') and self.worker and self.worker._cancelled:
            self.worker._pw_response = None
            if self.worker._pw_event:
                self.worker._pw_event.set()
            return

        from gui.ios_password_dialog import (
            show_ios_backup_password_dialog,
            show_ios_encryption_setup_dialog,
        )

        if error_msg == "ENCRYPTION_SETUP":
            # Encryption OFF → ask user to set a temporary password
            result = show_ios_encryption_setup_dialog(parent=self)
        else:
            # Encryption ON → ask user for existing password
            result = show_ios_backup_password_dialog(
                error_msg=error_msg if error_msg else "",
                parent=self
            )

        if hasattr(self, 'worker') and self.worker:
            self.worker._pw_response = result.password if result.success else None
            if self.worker._pw_event:
                self.worker._pw_event.set()

        # Show verifying indicator while collector checks the password
        has_password = result.success and result.password
        result.clear_sensitive()
        if has_password:
            self._show_ios_status(
                "Verifying backup password...\n"
                "This may take a few seconds.",
                title="Verifying Password"
            )

    def _on_unlock_requested(self, error_msg: str):
        """
        Handle optional extension unlock request from worker thread.

        Shows a modal dialog asking the user to unlock the device,
        then unblocks the worker thread with retry/skip decision.
        """
        if hasattr(self, 'worker') and self.worker and self.worker._cancelled:
            self.worker._unlock_response = False
            if self.worker._unlock_event:
                self.worker._unlock_event.set()
            return

        result = QMessageBox.warning(
            self,
            "Device Unlock Required",
            "This collection method requires the device to be unlocked.\n\n"
            "Please:\n"
            "  1. Turn on the device screen\n"
            "  2. Enter PIN / pattern / fingerprint to unlock\n"
            "  3. Click 'Retry' to continue\n\n"
            "Click 'Skip' to continue with other artifacts.",
            QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Discard,
            QMessageBox.StandardButton.Retry
        )

        if hasattr(self, 'worker') and self.worker:
            self.worker._unlock_response = (result == QMessageBox.StandardButton.Retry)
            if self.worker._unlock_event:
                self.worker._unlock_event.set()

    def _show_ios_status(self, text: str, title: str = "iOS Backup"):
        """Show or update the unified iOS status progress dialog.

        If dialog already exists, just updates label text.
        Otherwise creates a new indeterminate QProgressDialog.
        """
        from PyQt6.QtWidgets import QProgressDialog
        if hasattr(self, '_ios_status_dialog') and self._ios_status_dialog:
            # Update existing dialog text
            self._ios_status_dialog.setLabelText(text)
            self._ios_status_dialog.setWindowTitle(title)
            QApplication.processEvents()
            return
        dlg = QProgressDialog(self)
        dlg.setWindowTitle(title)
        dlg.setLabelText(text)
        dlg.setRange(0, 0)
        dlg.setCancelButton(None)
        dlg.setWindowModality(Qt.WindowModality.WindowModal)
        dlg.setMinimumDuration(0)
        dlg.setMinimumWidth(320)
        dlg.setValue(0)
        dlg.show()
        QApplication.processEvents()
        self._ios_status_dialog = dlg

    def _close_ios_status(self):
        """Close the unified iOS status dialog if open."""
        if hasattr(self, '_ios_status_dialog') and self._ios_status_dialog:
            self._ios_status_dialog.close()
            self._ios_status_dialog = None

    def _update_progress(self, stage: int, stage_progress: int, overall_progress: int,
                         message: str, time_remaining: str):
        """
        Update progress bars (stage-based progress)

        Args:
            stage: Current stage (1=collection, 2=encryption, 3=upload)
            stage_progress: Progress within current stage (0-100)
            overall_progress: Overall progress (0-100)
            message: Current task description
            time_remaining: Estimated remaining time string
        """
        # Close any iOS preparing / password-verify dialog once real progress fires
        self._close_ios_status()

        # Overall progress
        self.overall_progress.setValue(overall_progress)

        # Update stage UI
        indicators = [self.stage1_indicator, self.stage2_indicator, self.stage3_indicator]
        progress_bars = [self.stage1_progress, self.stage2_progress, self.stage3_progress]
        labels = [self.stage1_label, self.stage2_label, self.stage3_label]

        for i, (indicator, progress, label) in enumerate(zip(indicators, progress_bars, labels), 1):
            if i < stage:
                # Completed stage
                indicator.setText("✓")
                indicator.setStyleSheet("color: #4cc9f0;")
                progress.setValue(100)
                progress.setStyleSheet("QProgressBar::chunk { background-color: #4cc9f0; }")
            elif i == stage:
                # Currently active stage
                indicator.setText("●")
                indicator.setStyleSheet("color: #f0c14c;")
                progress.setValue(stage_progress)
                progress.setStyleSheet("QProgressBar::chunk { background-color: #f0c14c; }")
            else:
                # Pending stage
                indicator.setText("○")
                indicator.setStyleSheet("color: #666;")
                progress.setValue(0)
                progress.setStyleSheet("")

        # Display current task and time
        self.current_file_label.setText(message)
        if time_remaining:
            self.time_estimate_label.setText(f"Est: {time_remaining}")

    def _update_heartbeat(self):
        """Update elapsed time label with spinner animation (proves app is alive)"""
        if self._collection_start_time is None:
            return
        elapsed = datetime.now() - self._collection_start_time
        total_seconds = int(elapsed.total_seconds())
        minutes, seconds = divmod(total_seconds, 60)
        hours, minutes = divmod(minutes, 60)

        spinner = self._heartbeat_frames[self._heartbeat_idx % len(self._heartbeat_frames)]
        self._heartbeat_idx += 1

        if hours > 0:
            time_str = f"{hours}:{minutes:02d}:{seconds:02d}"
        else:
            time_str = f"{minutes:02d}:{seconds:02d}"

        self.elapsed_label.setText(f"{spinner} {time_str}")

    def _add_collected_file(self, filename: str, success: bool):
        """Add file to collected list — disabled (file names shown in log only)"""
        pass

    def _collection_finished(self, success: bool, message: str):
        """Handle collection completion"""
        self._collection_starting = False
        self._collection_running = False

        # Stop heartbeat timer and show final elapsed time
        self._heartbeat_timer.stop()
        if self._collection_start_time is not None:
            elapsed = datetime.now() - self._collection_start_time
            total_seconds = int(elapsed.total_seconds())
            minutes, seconds = divmod(total_seconds, 60)
            hours, minutes = divmod(minutes, 60)
            if hours > 0:
                final_time = f"{hours}:{minutes:02d}:{seconds:02d}"
            else:
                final_time = f"{minutes:02d}:{seconds:02d}"
            status = "✓" if success else "✗"
            self.elapsed_label.setText(f"{status} {final_time}")
            self._collection_start_time = None

        # Close any remaining iOS status dialog
        self._close_ios_status()

        # Re-encrypt if BitLocker auto-unlock was used
        if getattr(self, '_bitlocker_auto_decrypt_used', False):
            self._reenable_bitlocker()
            self._bitlocker_auto_decrypt_used = False

        # Re-enable controls
        self._set_collection_inputs_locked(False)
        self.collect_btn.setEnabled(False)  # Disable after collection complete/cancelled (new token required)
        self.cancel_btn.setEnabled(False)
        self.validate_btn.setEnabled(True)
        # [Security] Clear session data - prevent token reuse
        # After collection complete/cancelled, must re-authenticate with new token
        self._clear_session_data()
        self._set_artifacts_waiting_for_source()

        if success:
            self._collection_completed = True
            self._log(f"Collection completed: {message}")
            self._log("")
            self._log("✅ All evidence has been uploaded to the server.")
            self._log("👉 Return to your web browser and start AI Analysis.")
            self._log("")
            self._log("New token required for new collection.")
            QMessageBox.information(
                self, "Collection Complete",
                f"{message}\n\n"
                "✅ All evidence has been uploaded.\n\n"
                "Next step:\n"
                "Return to your web browser and start AI Analysis.\n\n"
                "A new token is required for additional collections."
            )
        else:
            self._log(f"Collection failed: {message}", error=True)
            self._log("New token required for new collection.")
            QMessageBox.critical(self, "Error", f"{message}\n\nPlease get a new token for additional collections.")

        self.status_bar.showMessage("Ready - New token required")
        self.token_status.setText("New token required")
        self.token_status.setStyleSheet("color: #ffc107;")

    def _reenable_bitlocker(self):
        """Re-enable BitLocker after collection"""
        self._log("Starting BitLocker re-encryption...")

        try:
            from utils.bitlocker import enable_bitlocker

            # Show progress dialog
            from PyQt6.QtWidgets import QProgressDialog
            progress = QProgressDialog(
                "Re-enabling BitLocker encryption...\n"
                "Encryption will continue in background.",
                None,  # No cancel button (security requirement)
                0, 0,
                self
            )
            progress.setWindowTitle("BitLocker Re-encryption")
            progress.setWindowModality(Qt.WindowModality.WindowModal)
            progress.setMinimumDuration(0)
            progress.show()
            QApplication.processEvents()

            # Start BitLocker re-encryption (background - don't wait for completion)
            result = enable_bitlocker(
                drive="C:",
                wait_for_completion=False  # Encryption continues in background
            )

            progress.close()

            if result.success:
                self._log("BitLocker re-encryption started. Continuing in background.")
                QMessageBox.information(
                    self,
                    "BitLocker Re-encryption",
                    "BitLocker encryption has started in the background.\n\n"
                    "You can check encryption progress in Windows Settings.\n"
                    "(Settings > Privacy & Security > Device Encryption)"
                )
            else:
                self._log(f"BitLocker re-encryption failed: {result.error}", error=True)
                QMessageBox.warning(
                    self,
                    "BitLocker Re-encryption Failed",
                    f"Failed to re-enable BitLocker:\n{result.error}\n\n"
                    "Please manually re-enable BitLocker:\n"
                    "manage-bde -on C:"
                )

        except Exception as e:
            self._log(f"BitLocker re-encryption error: {e}", error=True)
            QMessageBox.warning(
                self,
                "Error",
                f"Error during BitLocker re-encryption:\n{e}\n\n"
                "Please manually re-enable BitLocker:\n"
                "manage-bde -on C:"
            )

    def _clear_session_data(self):
        """
        Clear session data - prevent token reuse

        Called after collection complete/cancelled to delete cached session info.
        New collection requires re-authentication with new token.
        """
        self.session_id = None
        self.case_id = None
        self.collection_token = None
        self.server_url = None
        self.ws_url = None
        self.collection_profile_id = None
        self.collection_profile_targets = []
        self.profile_artifact_types = set()
        self.allowed_artifacts = []
        self._allow_all_artifacts = False
        self._mapped_allowed_artifacts = set()

        # Clear token input field
        if hasattr(self, 'token_input') and self.token_input:
            self.token_input.clear()

    def _notify_server_cancel(self):
        """
        Notify server of collection abort (clear Redis active collection state)

        Clears server's active_collection state on cancel to allow
        new collection for the same case.
        UI operation unaffected on failure (best-effort).
        """
        import requests

        if not self.session_id or not self.collection_token:
            return

        try:
            # Prefer server_url from authentication, fallback to config
            server_url = getattr(self, 'server_url', None) or self.config.get('server_url', '')
            if not server_url:
                return

            # Use collector-specific abort endpoint
            abort_path = f"/api/v1/collector/collection/abort/{self.session_id}"
            abort_url = f"{server_url}{abort_path}"
            abort_headers = {
                'X-Collection-Token': self.collection_token,
                'X-Session-ID': self.session_id,
            }
            if self.request_signer:
                abort_headers.update(self.request_signer.sign_request(
                    "POST", abort_path, None, self.collection_token,
                ))
            response = requests.post(
                abort_url,
                headers=abort_headers,
                timeout=5,
                verify=_get_ssl_verify(),
            )

            if response.status_code == 200:
                self._log("Server abort notification complete")
            else:
                self._log(f"Server abort notification failed: {response.status_code}", error=True)
        except Exception as e:
            # Ignore failure - server stale check handles cleanup
            self._log(f"Server abort notification failed (ignored): {e}", error=True)

    # Log level styles: (color, display_prefix)
    _LOG_STYLES = {
        'info':  ('#4cc9f0', 'INFO'),
        'warn':  ('#ffc107', 'WARN'),
        'skip':  ('#888888', 'SKIP'),
        'error': ('#f72585', 'ERROR'),
    }

    def _log(self, message: str, error: bool = False):
        """Add message to activity log.

        Level is determined by message prefix tags (stripped before display):
          [SKIP] → grey   "SKIP"  — artifact not present, normal
          [WARN] → yellow "WARN"  — non-critical issue
          else   → error flag: True → red "ERROR", False → blue "INFO"
        """
        timestamp = datetime.now().strftime("%H:%M:%S")

        # Extract level from message prefix tag
        level = None
        for tag in ('[SKIP]', '[WARN]'):
            if message.startswith(tag):
                level = tag[1:-1].lower()  # 'skip' or 'warn'
                message = message[len(tag):].lstrip()
                break

        if level is None:
            level = 'error' if error else 'info'

        color, prefix = self._LOG_STYLES.get(level, self._LOG_STYLES['info'])

        html = f'<span style="color: #888;">[{timestamp}]</span> '
        html += f'<span style="color: {color};">[{prefix}]</span> '
        html += f'<span style="color: #eee;">{message}</span>'

        self.log_text.append(html)

        # Show log file path on first error for user diagnostics
        if level == 'error' and hasattr(self, '_log_path') and not getattr(self, '_log_path_shown', False):
            self._log_path_shown = True
            log_hint = f'<span style="color: #888;">Log file: {self._log_path}</span>'
            self.log_text.append(log_hint)

    def closeEvent(self, event):
        """Cleanup on window close"""
        # Stop device monitoring
        self.device_manager.stop_monitoring()

        # [2026-04-27 Track 3] Send graceful shutdown intent over WS first,
        # then stop the worker thread. The server uses this to immediately
        # release the case slot (instead of waiting for the server's idle timeout).
        if hasattr(self, '_ws_worker') and self._ws_worker.isRunning():
            try:
                self._ws_worker.request_shutdown('user_close')
            except Exception:
                pass
            try:
                self._ws_worker.stop()
                self._ws_worker.wait(2000)
            except Exception:
                pass

        # Cancel ongoing collection
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.cancel()
            self.worker.wait(3000)  # Wait max 3 seconds
        elif not getattr(self, '_collection_completed', False):
            # Notify server only if collection was NOT completed
            # (closed after token auth but before collection start/finish)
            self._notify_server_cancel()

        super().closeEvent(event)

    def _on_ws_control_event(self, msg_type: str, payload: dict):
        """[2026-04-27 Track 3] Slot for WsControlWorker.control_event signal.

        Runs in the Qt main thread (signal-marshalled), so it's safe to call
        UI methods (self._log, etc.) directly here. The asyncio worker thread
        emits this signal whenever the server pushes a control message.
        """
        try:
            if msg_type == 'cancel':
                reason = str(payload.get('reason') or 'unspecified')
                self._log(f"[CANCEL] Server requested cancellation: {reason}", error=False)
                # If a collection is currently running, abort it immediately
                if hasattr(self, 'worker') and self.worker and self.worker.isRunning():
                    self._log("[CANCEL] Aborting active collection worker")
                    self.worker.cancel()
            elif msg_type == 'terminate':
                reason = str(payload.get('reason') or 'unspecified')
                self._log(f"[TERMINATE] Session terminated by server: {reason}", error=True)
                # Hard abort — slot is already released server-side
                if hasattr(self, 'worker') and self.worker and self.worker.isRunning():
                    self.worker.cancel()
                # Clear local session state to prevent further API calls
                self.session_id = None
                self.collection_token = None
            elif msg_type == 'snapshot':
                if payload.get('cancel_flag'):
                    self._log("[SYNC] Server reports this case was previously cancelled", error=False)
                stage = payload.get('stage')
                if stage:
                    self._log(f"[SYNC] Server stage: {stage}")
            elif msg_type == 'status':
                # Pipeline_progress relay — informational
                data = payload.get('data') if isinstance(payload, dict) else None
                if isinstance(data, dict):
                    stage = data.get('stage')
                    if stage:
                        self._log(f"[SERVER] Pipeline: {stage}")
        except Exception as e:
            logging.getLogger(__name__).warning(f"[_on_ws_control_event] handler error: {e}")


class WsControlWorker(QThread):
    """[2026-04-27 Track 3] Background QThread that runs an asyncio loop hosting the
    bidirectional /ws/collection/{session_id} WebSocket via RealTimeUploader.

    Why a separate thread:
      - PyQt main thread runs the Qt event loop and must not block.
      - asyncio needs its own event loop in the same thread it runs in.
      - Cross-thread comms via pyqtSignal (thread-safe; slot runs in receiver thread).

    Lifecycle:
      MainWindow creates after token validation → start() → run() spawns asyncio loop
      → uploader.connect_websocket() → reconnect_supervisor handles drops.
      On window close: request_shutdown(reason) sends intent.shutdown over WS,
      then stop() flips _stop flag, run() exits cleanly.
    """
    # (msg_type, payload) — see RealTimeUploader._handle_server_message types
    control_event = pyqtSignal(str, dict)

    def __init__(self, server_url, ws_url, session_id, collection_token, case_id,
                 consent_record=None, request_signer=None, config=None, parent=None):
        super().__init__(parent)
        self._args = dict(
            server_url=server_url,
            ws_url=ws_url,
            session_id=session_id,
            collection_token=collection_token,
            case_id=case_id,
            consent_record=consent_record,
            request_signer=request_signer,
            config=config,
        )
        self._loop = None
        self._uploader: Optional[RealTimeUploader] = None
        self._stop = False

    def run(self):
        # Each thread needs its own event loop
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._main())
        except Exception as e:
            logging.getLogger(__name__).warning(f"[WsControlWorker] loop crashed: {e}")
        finally:
            try:
                self._loop.close()
            except Exception:
                pass
            self._loop = None

    async def _main(self):
        try:
            self._uploader = RealTimeUploader(**self._args)
            # Wire control callback — runs in asyncio thread, pyqtSignal marshals to main thread
            def _on_msg(msg_type: str, payload: dict):
                try:
                    self.control_event.emit(msg_type, payload or {})
                except RuntimeError:
                    # Qt object deleted (e.g., during shutdown) — ignore
                    pass
            self._uploader.set_control_callback(_on_msg)

            await self._uploader.connect_websocket()

            # Idle until stop is signaled
            while not self._stop:
                await asyncio.sleep(0.5)
        finally:
            try:
                if self._uploader:
                    await self._uploader.disconnect_websocket()
            except Exception:
                pass

    def stop(self):
        """Signal the asyncio loop to exit. Caller should wait()."""
        self._stop = True

    def request_shutdown(self, reason: str = 'user_close'):
        """Schedule send_intent_shutdown on the asyncio loop (thread-safe).

        Best-effort — if the loop is gone, this is a no-op. After this, call stop()+wait().
        """
        if self._loop is None or self._uploader is None:
            return
        try:
            asyncio.run_coroutine_threadsafe(
                self._uploader.send_intent_shutdown(reason),
                self._loop,
            )
        except Exception:
            pass


class CollectionWorker(QThread):
    """Background worker for collection (stage-based progress)"""

    # Extended signals (stage, stage_progress, overall_progress, message, time_remaining)
    progress_updated = pyqtSignal(int, int, int, str, str)
    file_collected = pyqtSignal(str, bool)
    log_message = pyqtSignal(str, bool)
    finished = pyqtSignal(bool, str)
    # iOS USB backup password request (error_msg -> GUI dialog)
    password_requested = pyqtSignal(str)
    # iOS status text update (shown in preparing/verify dialog)
    ios_status_update = pyqtSignal(str)
    # Optional extension: device unlock required
    unlock_requested = pyqtSignal(str)

    # Stage weights (total 100%)
    STAGE_WEIGHTS = {
        1: 30,   # Collection: 30%
        2: 30,   # Encryption: 30%
        3: 40,   # Upload: 40%
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
        # Selected device list
        selected_devices: List = None,
        # Phase 2.1: Mobile options
        android_device_serial: str = None,
        ios_backup_path: str = None,
        # Phase 3.1: Linux/macOS options
        linux_mount_path: str = None,
        macos_mount_path: str = None,
        # BitLocker decrypted volume (physical disk)
        bitlocker_decryptor=None,
        # BitLocker decrypted volumes (disk images, device_id -> BitLockerDecryptor)
        image_bitlocker_decryptors=None,
        # LUKS decrypted volumes (disk images, device_id -> LUKSDecryptor)
        luks_decryptors=None,
        # iOS encrypted backup password
        ios_backup_password: str = None,
        # Include deleted files
        include_deleted: bool = True,
        # Application config (for security settings)
        config: dict = None,
        # Request signing
        request_signer=None,
        collection_profile_id: str = None,
    ):
        super().__init__()
        self.server_url = server_url
        self.ws_url = ws_url
        self.session_id = session_id
        self.collection_token = collection_token
        self.case_id = case_id
        self.artifacts = artifacts
        self.consent_record = consent_record  # P0 legal requirement
        self._cancelled = False
        self.config = config or {}
        self.request_signer = request_signer
        self.collection_profile_id = collection_profile_id

        # Selected devices list
        self.selected_devices = selected_devices or []

        # Phase 2.1: Mobile options
        self.android_device_serial = android_device_serial
        self.ios_backup_path = ios_backup_path

        # Phase 3.1: Linux/macOS options
        self.linux_mount_path = linux_mount_path
        self.macos_mount_path = macos_mount_path

        # BitLocker decrypted volume (physical disk)
        self.bitlocker_decryptor = bitlocker_decryptor

        # BitLocker decrypted volumes (disk images)
        self.image_bitlocker_decryptors = image_bitlocker_decryptors or {}

        # LUKS decrypted volumes (disk images)
        self.luks_decryptors = luks_decryptors or {}

        # iOS encrypted backup password
        self.ios_backup_password = ios_backup_password

        # Include deleted files
        self.include_deleted = include_deleted

        # iOS USB password callback: threading.Event for GUI/worker sync
        self._pw_event = None
        self._pw_response = None

        # Optional unlock callback: threading.Event for GUI/worker sync
        self._unlock_event = None
        self._unlock_response = None  # True = retry, False/None = skip

        # Time tracking
        self._start_time = None
        self._stage_start_time = None
        self._processed_bytes = 0
        self._total_bytes_estimate = 0

        # Heartbeat thread to keep collection session alive
        self._heartbeat_stop_event = None
        self._heartbeat_thread = None

    def _start_heartbeat(self):
        """
        Start heartbeat thread to keep collection session alive.

        Periodically calls validate-session endpoint during long operations
        (iOS backup creation, key derivation, extraction) to prevent Redis TTL expiry.
        """
        import threading

        self._heartbeat_stop_event = threading.Event()

        def heartbeat_loop():
            import logging as _log
            logger = _log.getLogger(__name__)
            while not self._heartbeat_stop_event.wait(timeout=300):  # Every 5 minutes
                if self._cancelled:
                    break
                try:
                    resp = requests.post(
                        f"{self.server_url}/api/v1/collector/validate-session",
                        json={
                            'session_id': self.session_id,
                            'collection_token': self.collection_token,
                        },
                        timeout=10,
                        verify=_get_ssl_verify(),
                    )
                    if resp.ok:
                        data = resp.json()
                        if not data.get('valid', True):
                            logger.warning(f"[Heartbeat] Session invalidated: {data.get('reason', 'unknown')}")
                    else:
                        logger.debug(f"[Heartbeat] Server returned {resp.status_code}")
                except Exception as e:
                    logger.debug(f"[Heartbeat] Failed: {e}")

        self._heartbeat_thread = threading.Thread(
            target=heartbeat_loop, daemon=True, name="collection-heartbeat"
        )
        self._heartbeat_thread.start()

    def _stop_heartbeat(self):
        """Stop heartbeat thread."""
        if self._heartbeat_stop_event:
            self._heartbeat_stop_event.set()
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=5)
        self._heartbeat_stop_event = None
        self._heartbeat_thread = None

    def _request_password(self, error_msg=None):
        """
        Password callback: called from collector thread → emits signal → blocks until GUI responds.

        Returns password string or None if cancelled (also sets _cancelled to stop collection).
        """
        import threading as _thr
        self._pw_response = None
        self._pw_event = _thr.Event()
        self.password_requested.emit(error_msg or "")
        self._pw_event.wait()  # Block until GUI sets response
        if self._pw_response is None:
            # User cancelled or doesn't know → stop entire collection
            self._cancelled = True
        return self._pw_response

    def cancel(self):
        """Cancel the collection"""
        self._cancelled = True
        self._stop_heartbeat()
        # Unblock password callback if waiting
        if self._pw_event:
            self._pw_response = None
            self._pw_event.set()
        # Send abort signal to server (clear active collection flag)
        self._abort_session()

    def _abort_session(self):
        """Notify server of session abort (clear active collection flag)"""
        if not self.session_id or not self.collection_token:
            return
        try:
            abort_path = f"/api/v1/collector/collection/abort/{self.session_id}"
            abort_url = f"{self.server_url}{abort_path}"
            abort_headers = {
                'X-Collection-Token': self.collection_token,
                'X-Session-ID': self.session_id,
            }
            if self.request_signer:
                abort_headers.update(self.request_signer.sign_request(
                    "POST", abort_path, None, self.collection_token,
                ))
            requests.post(
                abort_url,
                headers=abort_headers,
                timeout=5,  # Quick timeout (don't wait during shutdown)
                verify=_get_ssl_verify(),
            )
        except Exception:
            pass  # Ignore failure (shutting down)

    def _calculate_overall_progress(self, stage: int, stage_progress: int) -> int:
        """Calculate overall progress"""
        completed_weight = sum(
            self.STAGE_WEIGHTS[s] for s in range(1, stage)
        )
        current_weight = self.STAGE_WEIGHTS[stage] * stage_progress / 100
        return int(completed_weight + current_weight)

    def _estimate_remaining_time(self, stage: int, stage_progress: int, items_done: int, total_items: int) -> str:
        """Estimate remaining time"""
        import time

        if not self._start_time or stage_progress <= 0:
            return ""

        elapsed = time.time() - self._start_time
        overall_progress = self._calculate_overall_progress(stage, stage_progress)

        if overall_progress <= 0:
            return ""

        # Calculate estimated total time
        estimated_total = elapsed / (overall_progress / 100)
        remaining = max(0, estimated_total - elapsed)

        if remaining < 60:
            return f"{int(remaining)}s"
        elif remaining < 3600:
            minutes = int(remaining / 60)
            seconds = int(remaining % 60)
            return f"{minutes}m {seconds}s"
        else:
            hours = int(remaining / 3600)
            minutes = int((remaining % 3600) / 60)
            return f"{hours}h {minutes}m"

    def _artifact_category(self, artifact_type: str) -> str:
        info = ARTIFACT_TYPES.get(artifact_type, {})
        category = str(info.get('category') or '').lower()
        if category in ('windows', 'android', 'ios', 'linux', 'macos', 'ai_activity'):
            return category
        lowered = str(artifact_type or '').lower()
        if lowered.startswith(('mobile_ios_', 'ios_')):
            return 'ios'
        if lowered.startswith(('mobile_android_', 'android_')):
            return 'android'
        if lowered.startswith('linux_'):
            return 'linux'
        if lowered.startswith('macos_'):
            return 'macos'
        return 'windows'

    def _device_artifact_categories(self, device) -> set:
        device_type = device.device_type
        if device_type == DeviceType.WINDOWS_PHYSICAL_DISK:
            return {'windows'}
        if device_type in (DeviceType.ANDROID_DEVICE, DeviceType.MOBILE_FFS_BUNDLE_ANDROID):
            return {'android'}
        if device_type in (DeviceType.IOS_BACKUP, DeviceType.IOS_DEVICE, DeviceType.MOBILE_FFS_BUNDLE_IOS):
            return {'ios'}
        if device_type == DeviceType.LINUX_LOCAL_SYSTEM:
            return {'linux'}
        if device_type == DeviceType.MACOS_LOCAL_SYSTEM:
            return {'macos'}
        if device_type in (DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE,
                           DeviceType.VMDK_IMAGE, DeviceType.VHD_IMAGE,
                           DeviceType.VHDX_IMAGE, DeviceType.QCOW2_IMAGE,
                           DeviceType.VDI_IMAGE, DeviceType.DMG_IMAGE):
            detected_os = str(device.metadata.get('detected_os') or '').lower()
            if detected_os in ('windows', 'linux', 'macos'):
                return {detected_os}
            # Fail-open for unknown images so collection does not miss
            # evidence because OS detection was inconclusive. Inapplicable
            # artifacts are skipped by the concrete collector.
            return {'windows', 'android', 'ios', 'linux', 'macos'}
        return set()

    def _artifacts_for_device(self, device) -> List[str]:
        categories = self._device_artifact_categories(device)
        if not categories:
            return list(self.artifacts)
        filtered = [
            artifact_type for artifact_type in self.artifacts
            if self._artifact_category(artifact_type) in categories
        ]
        skipped = len(self.artifacts) - len(filtered)
        if skipped:
            self.log_message.emit(
                f"[{device.display_name}] Skipped {skipped} artifact(s) not applicable to this source type.",
                False,
            )
        return filtered

    def _create_collector_for_device(self, device, output_dir: str):
        """
        Create appropriate collector for device type

        Args:
            device: UnifiedDeviceInfo object
            output_dir: Output directory

        Returns:
            Appropriate collector instance or None
        """
        try:
            device_type = device.device_type

            # E01/RAW/VMDK/VHD/VHDX/QCOW2/VDI image
            if device_type in (DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE,
                               DeviceType.VMDK_IMAGE, DeviceType.VHD_IMAGE,
                               DeviceType.VHDX_IMAGE, DeviceType.QCOW2_IMAGE,
                               DeviceType.VDI_IMAGE, DeviceType.DMG_IMAGE):
                # BitLocker-decrypted partition in disk image
                bl_dec = self.image_bitlocker_decryptors.get(device.device_id)
                if bl_dec:
                    try:
                        decrypted_reader = bl_dec.get_decrypted_reader()
                        self.log_message.emit("Using BitLocker decrypted volume for collection.", False)
                        return ArtifactCollector(output_dir, decrypted_reader=decrypted_reader)
                    except Exception as e:
                        self.log_message.emit(f"BitLocker decrypted volume access failed: {e}", True)

                # LUKS-decrypted partition in disk image
                luks_dec = self.luks_decryptors.get(device.device_id)
                if luks_dec:
                    try:
                        decrypted_reader = luks_dec.get_decrypted_reader()
                        self.log_message.emit("Using LUKS decrypted volume for collection.", False)
                        return ArtifactCollector(output_dir, decrypted_reader=decrypted_reader)
                    except Exception as e:
                        self.log_message.emit(f"LUKS decrypted volume access failed: {e}", True)

                # Fall through to normal E01 collector

                if E01ArtifactCollector is None:
                    self.log_message.emit("Disk image analysis is not available on this platform.", True)
                    return None
                file_path = device.metadata.get('file_path')
                if not file_path:
                    self.log_message.emit(f"Image file path missing: {device.display_name}", True)
                    return None

                collector = E01ArtifactCollector(file_path, output_dir)
                if getattr(collector, '_accessor', None) is None:
                    error = getattr(collector, 'load_error', '') or 'Unsupported or invalid disk image'
                    self.log_message.emit(f"Disk image open failed: {error}", True)
                    if hasattr(collector, 'close'):
                        collector.close()
                    return None

                # Auto-select best partition by priority: NTFS > APFS > HFS+ > ext4 > largest
                partitions = collector.list_partitions()
                if not partitions:
                    self.log_message.emit(
                        f"No supported partitions or volume filesystem found: {device.display_name}",
                        True,
                    )
                    if hasattr(collector, 'close'):
                        collector.close()
                    return None

                selected = False
                priority_fs = ['NTFS', 'APFS', 'HFS+', 'HFSX', 'HFS', 'ext4', 'ext3', 'ext2', 'XFS', 'Btrfs', 'ZFS', 'UFS', 'FAT32', 'FAT16', 'FAT12', 'exFAT']
                for target_fs in priority_fs:
                    for p in partitions:
                        if getattr(p, 'filesystem', '').upper() == target_fs.upper():
                            if collector.select_partition(p.index):
                                self.log_message.emit(f"Partition selected: {p.filesystem} ({getattr(p, 'size_display', '')})", False)
                                selected = True
                                break
                    if selected:
                        break

                if not selected and partitions:
                    self.log_message.emit(
                        f"No supported filesystem partition found: {device.display_name}",
                        True,
                    )
                    if hasattr(collector, 'close'):
                        collector.close()
                    return None

                return collector

            # Windows physical disk
            elif device_type == DeviceType.WINDOWS_PHYSICAL_DISK:
                # Get decrypted reader if BitLocker was unlocked via dialog
                decrypted_reader = None
                if self.bitlocker_decryptor:
                    try:
                        decrypted_reader = self.bitlocker_decryptor.get_decrypted_reader()
                        self.log_message.emit("BitLocker decrypted volume available for MFT collection.", False)
                    except Exception as e:
                        self.log_message.emit(f"BitLocker decrypted volume access failed: {e}", True)

                # Use LocalMFTCollector (BitLocker auto-detection + directory fallback)
                if BASE_MFT_AVAILABLE:
                    volume = device.metadata.get('volume') or 'C'
                    self.log_message.emit(f"Using volume: {volume}:", False)
                    collector = LocalMFTCollector(output_dir, volume=volume, decrypted_reader=decrypted_reader)
                    self.log_message.emit(
                        f"Collection mode: {collector.get_collection_mode()}", False
                    )
                    return collector
                else:
                    # Use legacy ArtifactCollector if BaseMFTCollector unavailable
                    return ArtifactCollector(output_dir, decrypted_reader=decrypted_reader)

            # Android device
            elif device_type == DeviceType.ANDROID_DEVICE:
                from collectors.android_collector import AndroidCollector
                serial = device.metadata.get('serial')
                collector = AndroidCollector(output_dir)
                # Pass server credentials to optional collection extensions.
                collector._server_url = self.server_url
                collector._collection_token = self.collection_token
                if serial:
                    collector.connect(serial)
                return collector

            # iOS backup
            elif device_type == DeviceType.IOS_BACKUP:
                from collectors.ios_collector import iOSCollector
                backup_path = device.metadata.get('path')
                is_encrypted = device.metadata.get('encrypted', False)

                encrypted_backup_obj = None
                if is_encrypted and self.ios_backup_password and backup_path:
                    # Create EncryptedBackup in collection thread (single setup pass)
                    # This is the ONLY place where the password is consumed.
                    from collectors.ios_backup_decryptor import create_encrypted_backup
                    self.log_message.emit("Verifying iOS backup password (this may take 1-2 minutes)...", False)
                    encrypted_backup_obj, error_msg = create_encrypted_backup(backup_path, self.ios_backup_password)
                    if not encrypted_backup_obj:
                        self.log_message.emit(f"iOS backup password verification failed: {error_msg}", True)
                        return None

                    self.log_message.emit("iOS backup password verified successfully.", False)

                collector = iOSCollector(output_dir, encrypted_backup=encrypted_backup_obj)
                if backup_path:
                    collector.select_backup(backup_path)
                return collector

            # Cellebrite UFED FFS / CLBX zip bundle (offline mobile image)
            elif device_type in (DeviceType.MOBILE_FFS_BUNDLE_IOS,
                                 DeviceType.MOBILE_FFS_BUNDLE_ANDROID):
                from collectors.mobile_ffs_collector import MobileFFSBundleCollector
                bundle_path = device.metadata.get('bundle_path')
                if not bundle_path:
                    self.log_message.emit(
                        f"FFS bundle path missing: {device.display_name}", True
                    )
                    return None
                collector = MobileFFSBundleCollector(output_dir, bundle_path)
                fmt = device.metadata.get('format_id', 'FFS')
                self.log_message.emit(
                    f"FFS bundle loaded: {fmt} ({device.size_display})", False
                )
                return collector

            # iOS USB direct connection device
            elif device_type == DeviceType.IOS_DEVICE:
                from collectors.ios_collector import iOSDeviceConnector, PYMOBILEDEVICE3_AVAILABLE
                if not PYMOBILEDEVICE3_AVAILABLE:
                    self.log_message.emit("pymobiledevice3 is not installed", True)
                    return None
                udid = device.metadata.get('udid') or device.metadata.get('serial')
                if not udid:
                    self.log_message.emit("iOS device UDID not found", True)
                    return None
                collector = iOSDeviceConnector(output_dir, udid=udid)
                # Device connection (required)
                try:
                    if not collector.connect(udid):
                        self.log_message.emit("iOS device connection failed", True)
                        return None
                except Exception as e:
                    self.log_message.emit(f"iOS connection error: {e}", True)
                    return None

                # Set password callback for encrypted device dialog
                collector.set_password_callback(self._request_password)

                udid_short = udid[:8] if len(udid) > 8 else udid
                self.log_message.emit(f"iOS USB direct connection (UDID: {udid_short}...)", False)
                return collector

            # macOS local system
            elif device_type == DeviceType.MACOS_LOCAL_SYSTEM:
                target_root = device.metadata.get('target_root', '/')
                is_root = device.metadata.get('is_root', False)
                if not is_root:
                    self.log_message.emit(
                        "WARNING: Running without root privileges. "
                        "Some artifacts (unified log, TCC.db, audit logs) may be inaccessible.",
                        True
                    )
                collector = LocalSystemCollector(output_dir, os_type='macos', target_root=target_root)
                self.log_message.emit(
                    f"macOS local collection mode: {collector.get_collection_mode()}", False
                )
                return collector

            # Linux local system
            elif device_type == DeviceType.LINUX_LOCAL_SYSTEM:
                target_root = device.metadata.get('target_root', '/')
                is_root = device.metadata.get('is_root', False)
                if not is_root:
                    self.log_message.emit(
                        "WARNING: Running without root privileges. "
                        "Some artifacts (shadow, audit logs, journald) may be inaccessible.",
                        True
                    )
                collector = LocalSystemCollector(output_dir, os_type='linux', target_root=target_root)
                self.log_message.emit(
                    f"Linux local collection mode: {collector.get_collection_mode()}", False
                )
                return collector

            else:
                self.log_message.emit(f"Unsupported device type: {device_type.name}", True)
                return None

        except Exception as e:
            self.log_message.emit(f"Collector creation failed: {e}", True)
            import logging
            logging.debug(f"Collector creation failed for {device.display_name}: {e}")
            return None

    def run(self):
        """Run collection in background (stage-based progress)"""
        import time
        import os

        # File logging for collector diagnostics
        import logging

        # Filter to prevent credential VALUES from reaching log files.
        # Only blocks messages containing actual credential patterns/values,
        # NOT operational messages about protected-volume handling.
        class _SensitiveFilter(logging.Filter):
            _BLOCK_PATTERNS = (
                'f0r_',
                'pass' + 'phrase=',  # Named param with credential value
                'change_password',   # API call that handles raw passwords
                'old=""', "old=''",  # change_password param
                'new=""', "new=''",  # change_password param
                'bearer ',           # JWT token
                'x-api-key',         # API key header
                'enc' + 'ryption' + '_' + 'k' + 'ey',
                'recovery_key',      # BitLocker recovery key
            )
            def filter(self, record):
                msg = record.getMessage().lower()
                return not any(p in msg for p in self._BLOCK_PATTERNS)

        from logging.handlers import RotatingFileHandler

        if self.config.get('dev_mode', False) and not getattr(__import__('sys'), 'frozen', False):
            # Dev: DEBUG log in TEMP directory (only in source mode, never in release builds)
            import tempfile
            _collector_log_path = os.path.join(
                os.environ.get('TEMP') or tempfile.gettempdir(),
                'collector_debug.log',
            )
            _log_level = logging.DEBUG
        else:
            # Prod: INFO+ log in user home directory with rotation
            import sys as _sys
            _log_dir = os.path.join(os.path.expanduser("~"), ".forensic-collector")
            os.makedirs(_log_dir, exist_ok=True)
            if _sys.platform != 'win32':
                os.chmod(_log_dir, 0o700)
            _collector_log_path = os.path.join(_log_dir, 'collector.log')
            _log_level = logging.INFO

        _fh = RotatingFileHandler(
            _collector_log_path, mode='a', encoding='utf-8',
            maxBytes=10 * 1024 * 1024,  # 10MB per file
            backupCount=3,              # Keep 3 rotated backups
        )
        _fh.setLevel(_log_level)
        _fh.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d — %(message)s'
        ))
        _fh.addFilter(_SensitiveFilter())
        logging.getLogger().addHandler(_fh)
        logging.getLogger().setLevel(_log_level)
        logging.getLogger().info(f"[CollectorGUI] Logging to {_collector_log_path}")

        # Store log path for user access
        self._log_path = _collector_log_path

        try:
            self._start_time = time.time()

            # Start heartbeat to keep session alive during long operations
            self._start_heartbeat()

            import tempfile
            import sys as _sys
            output_dir = tempfile.mkdtemp(prefix="forensic_")
            if _sys.platform != 'win32':
                os.chmod(output_dir, 0o700)  # Unix: owner-only access

            hash_calculator = FileHashCalculator()

            # ========================================
            # STAGE 1: Collection (30%)
            # ========================================
            self.log_message.emit("Starting artifact collection...", False)
            collected_raw_files = []  # (file_path, artifact_type, metadata)
            _ios_collectors = []  # Track iOS collectors for cleanup

            # If devices are selected, collect per device
            if self.selected_devices:
                per_device_artifacts = {
                    device.device_id: self._artifacts_for_device(device)
                    for device in self.selected_devices
                }
                total_items = sum(len(items) for items in per_device_artifacts.values())
                item_index = 0

                for device in self.selected_devices:
                    if self._cancelled:
                        self.finished.emit(False, "Collection cancelled")
                        return

                    device_name = device.display_name
                    self.log_message.emit(f"Device: {device_name}", False)

                    # Create appropriate collector based on device type
                    collector = self._create_collector_for_device(device, output_dir)
                    if not collector:
                        self.log_message.emit(f"{device_name}: Collector creation failed", True)
                        continue

                    # Track iOS collectors for cleanup (encrypted backup temp files)
                    if hasattr(collector, 'close'):
                        _ios_collectors.append(collector)

                    # Pre-warm MFT scan cache so all artifact types use cached data.
                    # Without this, the first artifact type triggers the full MFT scan
                    # and index build. Doing it upfront with progress feedback is better UX.
                    if hasattr(collector, 'forensic_disk_accessor') and collector.forensic_disk_accessor:
                        self.log_message.emit(f"[{device_name}] Building artifact index...", False)
                        self.progress_updated.emit(1, 0, 0, f"[{device_name}] Building artifact index...", "")
                        try:
                            if hasattr(collector, '_scan_cache') and collector._scan_cache is None:
                                collector._scan_cache = collector.forensic_disk_accessor.scan_all_files(
                                    include_deleted=True
                                )
                                if hasattr(collector, '_build_scan_index') and collector._scan_index is None:
                                    collector._scan_index = collector._build_scan_index(collector._scan_cache)
                                active_count = len(collector._scan_cache.get('active_files', []))
                                self.log_message.emit(
                                    f"[{device_name}] Index ready: {active_count} files", False
                                )
                        except Exception as e:
                            self.log_message.emit(f"[{device_name}] Index build skipped: {e}", True)

                    device_artifacts = per_device_artifacts.get(device.device_id, [])
                    if not device_artifacts:
                        self.log_message.emit(f"[{device_name}] No applicable artifacts selected for this source.", False)

                    for artifact_type in device_artifacts:
                        if self._cancelled:
                            break

                        item_index += 1
                        stage_progress = int((item_index / max(total_items, 1)) * 100)
                        overall_progress = self._calculate_overall_progress(1, stage_progress)
                        remaining = self._estimate_remaining_time(1, stage_progress, item_index, total_items)

                        self.progress_updated.emit(
                            1, stage_progress, overall_progress,
                            f"[{device_name}] Collecting: {artifact_type}...",
                            remaining
                        )

                        try:
                            # Chunk streaming: process 100 at a time to prevent GUI freeze
                            CHUNK_SIZE = 100
                            file_count = 0
                            error_count = 0

                            # iOS backup progress callback
                            def ios_progress_callback(msg: str):
                                # Progress percentage → update progress bar only (no log spam)
                                if "progress:" in msg.lower():
                                    try:
                                        pct = float(msg.split(":")[-1].strip().rstrip("%"))
                                        self.progress_updated.emit(
                                            1, int(pct), self._calculate_overall_progress(1, int(pct)),
                                            f"[{device_name}] {artifact_type}: {pct:.1f}%",
                                            ""
                                        )
                                    except (ValueError, IndexError):
                                        pass
                                else:
                                    # Non-progress messages (e.g. "Creating iOS backup") → log + status dialog
                                    self.log_message.emit(f"[{device_name}] {msg}", False)
                                    self.ios_status_update.emit(msg)

                            # Pass progress callback for iOS artifacts
                            _include_deleted = self.include_deleted
                            if hasattr(collector, 'collect') and 'ios' in str(type(collector)).lower():
                                collect_iter = collector.collect(artifact_type, progress_callback=ios_progress_callback)
                            else:
                                collect_iter = collector.collect(artifact_type, include_deleted=_include_deleted)

                            for file_path, metadata in collect_iter:
                                if self._cancelled:
                                    break

                                # FIX: filter error responses (empty path or status=error)
                                if not file_path or metadata.get('status') in ('error', 'not_found', 'not_implemented'):
                                    error_msg = metadata.get('error', metadata.get('message', 'Unknown error'))
                                    status = metadata.get('status', 'error')

                                    # not_found = file absent from backup (normal for uninstalled apps)
                                    # Unknown artifact type = other platform artifact (silent skip)
                                    if status == 'not_found':
                                        self.log_message.emit(f"[SKIP] [{device_name}] {artifact_type}: Not in backup", False)
                                    elif status == 'skipped':
                                        self.log_message.emit(f"[SKIP] [{device_name}] {artifact_type}: {error_msg}", False)
                                    elif 'Root access required' in error_msg or 'not rooted' in error_msg:
                                        self.log_message.emit(f"[SKIP] [{device_name}] {artifact_type}: Requires root", False)
                                    elif error_msg not in ['Unknown artifact type: ' + artifact_type]:
                                        self.log_message.emit(f"[{device_name}] {artifact_type}: {error_msg}", True)
                                    error_count += 1
                                    continue

                                # Add device info to metadata
                                metadata['device_id'] = device.device_id
                                metadata['device_name'] = device_name
                                metadata['device_type'] = device.device_type.name
                                collected_raw_files.append((file_path, artifact_type, metadata))
                                file_count += 1

                                # Rate-limit UI signals to prevent progressive slowdown
                                # (QListWidget.addItem + scrollToBottom with thousands of items)
                                if file_count <= 200 or file_count % CHUNK_SIZE == 0:
                                    self.file_collected.emit(Path(file_path).name, True)

                                # Update progress every 100 items + process GUI events
                                if file_count % CHUNK_SIZE == 0:
                                    self.log_message.emit(f"[{device_name}] {artifact_type}: {file_count} files collecting...", False)

                            if file_count == 0 and error_count == 0:
                                self.log_message.emit(f"[SKIP] [{device_name}] {artifact_type}: No files found", False)
                            elif file_count > 0:
                                self.log_message.emit(f"[{device_name}] {artifact_type}: {file_count} files collected", False)

                        except Exception as e:
                            import logging
                            err_str = str(e)
                            if 'Unknown artifact type' in err_str:
                                # Cross-platform artifact sent to wrong collector (e.g. Windows type → Android)
                                # Silently skip — not an error
                                logging.debug(f"Skipped cross-platform artifact: {artifact_type} on {device_name}")
                            else:
                                self.log_message.emit(f"Collection failed [{device_name}] ({artifact_type}): {e}", True)
                                logging.debug(f"Collection error for {artifact_type} on {device_name}: {e}")

                    # Release scan cache before closing collector
                    if hasattr(collector, 'release_scan_cache'):
                        collector.release_scan_cache()

                    # Report permission errors for local system collection
                    if hasattr(collector, 'permission_error_count') and collector.permission_error_count > 0:
                        self.log_message.emit(
                            f"[{device_name}] {collector.permission_error_count} files skipped "
                            f"(permission denied). Run with sudo/root for full access.",
                            True
                        )

                    # Cleanup collector
                    if hasattr(collector, 'close'):
                        collector.close()

            else:
                # Legacy mode: if no devices selected, collect from local system
                # Use LocalMFTCollector (BitLocker auto-detection + directory fallback)
                if BASE_MFT_AVAILABLE:
                    collector = LocalMFTCollector(output_dir, volume='C')
                    self.log_message.emit(
                        f"Collection mode: {collector.get_collection_mode()}", False
                    )
                    if collector._bitlocker_detected:
                        self.log_message.emit(
                            "BitLocker encryption detected - using directory fallback", False
                        )
                else:
                    # Use legacy ArtifactCollector if BaseMFTCollector unavailable
                    decrypted_reader = None
                    if self.bitlocker_decryptor:
                        try:
                            decrypted_reader = self.bitlocker_decryptor.get_decrypted_reader()
                            self.log_message.emit("Using BitLocker decrypted volume.", False)
                        except Exception as e:
                            self.log_message.emit(f"BitLocker volume access failed: {e}", True)
                    collector = ArtifactCollector(output_dir, decrypted_reader=decrypted_reader)

                total_artifacts = len(self.artifacts)

                for i, artifact_type in enumerate(self.artifacts):
                    if self._cancelled:
                        self.finished.emit(False, "Collection cancelled")
                        return

                    stage_progress = int(((i + 1) / total_artifacts) * 100)
                    overall_progress = self._calculate_overall_progress(1, stage_progress)
                    remaining = self._estimate_remaining_time(1, stage_progress, i + 1, total_artifacts)

                    self.progress_updated.emit(
                        1, stage_progress, overall_progress,
                        f"Collecting: {artifact_type}...",
                        remaining
                    )
                    self.log_message.emit(f"Collecting: {artifact_type}", False)

                    try:
                        # Phase 2.1: Pass kwargs per category
                        collect_kwargs = {}
                        artifact_info = ARTIFACT_TYPES.get(artifact_type, {})
                        category = artifact_info.get('category', 'windows')

                        if category == 'android' and self.android_device_serial:
                            collect_kwargs['device_serial'] = self.android_device_serial
                        elif category == 'ios' and self.ios_backup_path:
                            collect_kwargs['backup_path'] = self.ios_backup_path
                        elif category == 'linux' and self.linux_mount_path:
                            collect_kwargs['target_root'] = self.linux_mount_path
                        elif category == 'macos' and self.macos_mount_path:
                            collect_kwargs['target_root'] = self.macos_mount_path

                        # Chunk streaming: process 100 at a time to prevent GUI freeze
                        CHUNK_SIZE = 100
                        file_count = 0

                        collect_kwargs['include_deleted'] = self.include_deleted
                        for file_path, metadata in collector.collect(artifact_type, **collect_kwargs):
                            if self._cancelled:
                                break
                            collected_raw_files.append((file_path, artifact_type, metadata))
                            file_count += 1

                            # Rate-limit UI signals to prevent progressive slowdown
                            if file_count <= 200 or file_count % CHUNK_SIZE == 0:
                                self.file_collected.emit(Path(file_path).name, True)

                            # Update progress every 100 items + process GUI events
                            if file_count % CHUNK_SIZE == 0:
                                self.log_message.emit(f"{artifact_type}: {file_count} files collecting...", False)

                        if file_count == 0:
                            self.log_message.emit(f"[SKIP] {artifact_type}: No files found", False)
                        else:
                            self.log_message.emit(f"✓ {artifact_type}: {file_count} files collected", False)

                    except Exception as e:
                        import logging
                        self.log_message.emit(f"Collection failed ({artifact_type}): {e}", True)
                        logging.debug(f"Collection error for {artifact_type}: {e}")

                # Release scan cache after all artifact types collected
                if hasattr(collector, 'release_scan_cache'):
                    collector.release_scan_cache()

            if self._cancelled:
                self.finished.emit(False, "Collection cancelled")
                return

            # ========================================
            # STAGE 2: Prepare metadata (30%)
            # ========================================
            self.log_message.emit(f"🔐 Preparing {len(collected_raw_files)} files for upload...", False)
            encrypted_files = []  # (file_path, artifact_type, metadata)
            total_files = len(collected_raw_files)

            for j, (file_path, artifact_type, metadata) in enumerate(collected_raw_files):
                if self._cancelled:
                    self.finished.emit(False, "Preparation cancelled")
                    return

                filename = Path(file_path).name
                stage_progress = int(((j + 1) / max(total_files, 1)) * 100)
                overall_progress = self._calculate_overall_progress(2, stage_progress)
                remaining = self._estimate_remaining_time(2, stage_progress, j + 1, total_files)

                self.progress_updated.emit(
                    2, stage_progress, overall_progress,
                    f"Preparing: {filename}",
                    remaining
                )

                try:
                    # File may have been removed between Stage 1 (collect) and
                    # Stage 2 (prepare) by real-time antivirus / EDR software
                    # scanning the temp directory. Skip gracefully instead of
                    # failing the whole batch.
                    if not os.path.exists(file_path):
                        self.log_message.emit(
                            f"[SKIP] {filename}: file disappeared before "
                            f"preparation (likely quarantined by security software)",
                            True,
                        )
                        continue

                    # Reuse hash from Stage 1 (already computed during collection).
                    # Preferring the cached hash also avoids reopening the file,
                    # which would fail if AV quarantined it mid-pipeline.
                    original_hash = metadata.get('hash_sha256', '')
                    if not original_hash:
                        # Fallback: compute hash only if Stage 1 didn't provide it
                        hash_result = hash_calculator.calculate_file_hash(file_path)
                        original_hash = hash_result.sha256_hash

                    # Prefer cached size from Stage 1; avoid filesystem stat
                    # when possible so AV-quarantined files don't take down
                    # the whole preparation step.
                    original_size = metadata.get('size')
                    if original_size is None:
                        original_size = os.path.getsize(file_path)

                    # Add required metadata fields for server
                    metadata['original_hash'] = original_hash
                    metadata['original_size'] = original_size
                    metadata['collection_time'] = datetime.utcnow().isoformat()

                    # Legacy wire-format metadata (server-side processed)
                    metadata['encryption'] = {
                        'nonce': 'hash_only',
                        'original_hash': original_hash,
                    }

                    encrypted_files.append((
                        file_path,
                        artifact_type,
                        metadata
                    ))

                except FileNotFoundError:
                    self.log_message.emit(
                        f"[SKIP] {filename}: file removed mid-pipeline "
                        f"(quarantined by AV/EDR)",
                        True,
                    )
                except Exception as e:
                    self.log_message.emit(f"Preparation failed ({filename}): {e}", True)

            if self._cancelled:
                self.finished.emit(False, "Preparation cancelled")
                return

            # ========================================
            # STAGE 3: Upload (40%)
            # ========================================
            self.log_message.emit(f"☁️ Uploading {len(encrypted_files)} files...", False)

            # Direct upload via presigned URLs, with server-streaming fallback.
            sync_uploader = SyncUploader(
                server_url=self.server_url,
                ws_url=self.ws_url,
                session_id=self.session_id,
                collection_token=self.collection_token,
                case_id=self.case_id,
                consent_record=self.consent_record,
                config=self.config,
                request_signer=self.request_signer,
                profile_id=self.collection_profile_id,
            )
            uploader = R2DirectUploader(
                server_url=self.server_url,
                session_id=self.session_id,
                collection_token=self.collection_token,
                case_id=self.case_id,
                consent_record=self.consent_record,
                config=self.config,
                request_signer=self.request_signer,
                profile_id=self.collection_profile_id,
                fallback_uploader=sync_uploader,
            )

            success_count = 0
            total_upload = len(encrypted_files)

            # Parallel upload (up to 5 concurrent) - 3-5x faster than sequential
            from concurrent.futures import ThreadPoolExecutor, as_completed
            import threading

            upload_lock = threading.Lock()
            completed_count = 0

            def _upload_one_file(idx, file_path, artifact_type, metadata):
                nonlocal completed_count, success_count
                result = uploader.upload_file(file_path, artifact_type, metadata)
                filename = Path(file_path).name

                with upload_lock:
                    completed_count += 1
                    stage_progress = int((completed_count / max(total_upload, 1)) * 100)
                    overall_progress = self._calculate_overall_progress(3, stage_progress)
                    remaining = self._estimate_remaining_time(3, stage_progress, completed_count, total_upload)

                    self.progress_updated.emit(
                        3, stage_progress, overall_progress,
                        f"Uploading: {filename} ({completed_count}/{total_upload})",
                        remaining
                    )

                    if result.success:
                        success_count += 1
                        self.log_message.emit(f"✓ Upload successful: {filename}", False)
                    else:
                        if result.error and ("CANCELLED" in result.error or "cancelled" in result.error.lower()):
                            self.log_message.emit("🛑 Collection cancelled by server. Stopping upload.", True)
                            self._cancelled = True
                        elif result.error and "CLEANUP_IN_PROGRESS" in result.error:
                            self.log_message.emit("⏳ Previous data cleanup in progress. Please try again after cleanup completes.", True)
                            self._cancelled = True
                        else:
                            self.log_message.emit(f"✗ Upload failed ({artifact_type}): {result.error}", True)

                return result

            max_workers = min(5, max(total_upload, 1))
            if total_upload == 0:
                self.log_message.emit(
                    "No files were collected. Verify the selected evidence source, "
                    "authorized targets, and filesystem support before retrying.",
                    True,
                )
                self.progress_updated.emit(3, 0, self._calculate_overall_progress(3, 0), "No files collected", "")
                self.finished.emit(False, "No files were collected; nothing was uploaded or queued for analysis.")
                return

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {}
                for k, (file_path, artifact_type, metadata) in enumerate(encrypted_files):
                    if self._cancelled:
                        break
                    future = executor.submit(_upload_one_file, k, file_path, artifact_type, metadata)
                    futures[future] = k

                for future in as_completed(futures):
                    if self._cancelled:
                        # Cancel remaining futures
                        for f in futures:
                            f.cancel()
                        break
                    try:
                        future.result()
                    except Exception as e:
                        import logging
                        logging.debug(f"Upload exception: {e}")

            # Complete
            elapsed = time.time() - self._start_time
            elapsed_str = f"{int(elapsed)}s" if elapsed < 60 else f"{int(elapsed / 60)}m {int(elapsed % 60)}s"

            # [Cancel check] Don't send completion signal if cancelled
            if self._cancelled:
                self.log_message.emit(f"🛑 Collection cancelled: {success_count}/{total_upload} files uploaded before stop (elapsed: {elapsed_str})", True)
                self.progress_updated.emit(3, 0, 0, "Cancelled", "")
                self.finished.emit(False, f"Collection cancelled: {success_count}/{total_upload} files uploaded before stop")
                return

            # === Send upload completion signal (pipeline state transition trigger) ===
            if success_count > 0:
                try:
                    complete_path = f"/api/v1/collector/collection/end/{self.session_id}"
                    complete_url = f"{self.server_url}{complete_path}"
                    complete_headers = {
                        'X-Collection-Token': self.collection_token,
                        'X-Session-ID': self.session_id,
                        'Content-Type': 'application/json',
                    }
                    if self.request_signer:
                        complete_headers.update(self.request_signer.sign_request(
                            "POST", complete_path, None, self.collection_token,
                        ))
                    complete_response = requests.post(
                        complete_url,
                        headers=complete_headers,
                        params={'trigger_analysis': 'true'},
                        timeout=30,
                        verify=_get_ssl_verify(),
                    )
                    if complete_response.ok:
                        self.log_message.emit("✓ Collection session completion signal sent", False)
                    else:
                        self.log_message.emit(f"⚠ Session completion signal failed: {complete_response.status_code}", True)
                except Exception as e:
                    self.log_message.emit(f"⚠ Session completion signal error: {e}", True)

            self.progress_updated.emit(3, 100, 100, "Complete!", "")
            self.finished.emit(
                True,
                f"Collection complete: {success_count}/{total_upload} files uploaded (elapsed: {elapsed_str})"
            )

        except Exception as e:
            self.finished.emit(False, f"Error occurred: {str(e)}")

        finally:
            # Stop heartbeat thread
            self._stop_heartbeat()

            # Close iOS collectors BEFORE removing temp directory
            # (releases decrypted Manifest.db temp files)
            for _col in locals().get('_ios_collectors', []):
                try:
                    _col.close()
                except Exception:
                    pass

            # Cleanup temporary directory (delete collected files)
            if output_dir and os.path.exists(output_dir):
                try:
                    import shutil
                    shutil.rmtree(output_dir)
                    self.log_message.emit("Temporary files cleaned up", False)
                except Exception as e:
                    self.log_message.emit(f"Error cleaning up temporary files: {e}", True)

            # Clear iOS backup passwords from memory
            self.ios_backup_password = None

            # BitLocker decryptor resource cleanup (physical disk)
            if self.bitlocker_decryptor:
                try:
                    self.bitlocker_decryptor.close()
                    self.log_message.emit("BitLocker resources cleaned up", False)
                except Exception as e:
                    self.log_message.emit(f"Error cleaning up BitLocker: {e}", True)

            # BitLocker decryptor resource cleanup (disk images)
            for dev_id, bl_dec in self.image_bitlocker_decryptors.items():
                try:
                    bl_dec.close()
                except Exception:
                    pass
            if self.image_bitlocker_decryptors:
                self.log_message.emit("Disk image BitLocker resources cleaned up", False)
                self.image_bitlocker_decryptors.clear()

            # LUKS decryptor resource cleanup
            for dev_id, luks_dec in self.luks_decryptors.items():
                try:
                    luks_dec.close()
                except Exception:
                    pass
            if self.luks_decryptors:
                self.log_message.emit("LUKS resources cleaned up", False)
                self.luks_decryptors.clear()
