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
from core.uploader import RealTimeUploader, build_collector_uploader
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


class TokenValidationWorker(QThread):
    """Run token validation away from the UI thread."""

    result_ready = pyqtSignal(object)
    error_ready = pyqtSignal(str)

    def __init__(self, server_url: str, token: str):
        super().__init__()
        self.server_url = server_url
        self.token = token

    def run(self):
        try:
            validator = TokenValidator(self.server_url)
            self.result_ready.emit(validator.validate(self.token))
        except Exception as exc:
            logging.getLogger(__name__).exception("Token validation worker failed")
            self.error_ready.emit(str(exc) or exc.__class__.__name__)
        finally:
            self.token = ""


class ServerHealthWorker(QThread):
    """Run server health checks away from the UI thread."""

    result_ready = pyqtSignal(object, object)  # (success, error_detail)

    def __init__(self, server_url: str):
        super().__init__()
        self.server_url = server_url

    def run(self):
        try:
            validator = TokenValidator(self.server_url)
            success, error_detail = validator.check_server_health()
            self.result_ready.emit(success, error_detail)
        except Exception as exc:
            logging.getLogger(__name__).exception("Server health worker failed")
            self.result_ready.emit(False, str(exc) or exc.__class__.__name__)


class UpdateCheckWorker(QThread):
    """Run update checks away from the UI thread."""

    update_ready = pyqtSignal(object)

    def run(self):
        try:
            from core.updater import check_for_update
            self.update_ready.emit(check_for_update())
        except Exception:
            self.update_ready.emit(None)


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
        self.request_signer = None
        self._token_validation_worker = None
        self._server_health_worker = None
        self._update_check_worker = None
        self._token_validation_in_progress = False
        self._collection_in_progress = False
        self._close_after_worker_finish = False

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

        # Quick start status
        quick_group = QGroupBox("Quick Start")
        quick_layout = QVBoxLayout(quick_group)
        quick_layout.setContentsMargins(6, 14, 6, 6)
        quick_layout.setSpacing(4)
        self.workflow_status = QLabel("")
        self.workflow_status.setWordWrap(True)
        self.workflow_status.setTextFormat(Qt.TextFormat.RichText)
        quick_layout.addWidget(self.workflow_status)
        layout.addWidget(quick_group)

        # Step 1: Token
        token_group = QGroupBox("1. Authenticate")
        token_layout = QVBoxLayout(token_group)
        token_layout.setContentsMargins(6, 14, 6, 6)
        token_layout.setSpacing(4)

        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Paste the session token from the web case")
        self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
        token_layout.addWidget(self.token_input)

        token_btn_layout = QHBoxLayout()
        token_btn_layout.setSpacing(4)
        self.show_token_btn = QPushButton("Show")
        self.show_token_btn.setCheckable(True)
        self.show_token_btn.clicked.connect(self._toggle_token_visibility)
        self.validate_btn = QPushButton("Validate Token")
        self.validate_btn.setObjectName("validateTokenButton")
        self.validate_btn.setStyleSheet(f"""
            QPushButton#validateTokenButton {{
                background-color: {COLORS['bg_elevated']};
                border: 1px solid {COLORS['brand_primary']};
                border-radius: 4px;
                color: {COLORS['brand_accent']};
                font-weight: 700;
                padding: 4px 12px;
            }}
            QPushButton#validateTokenButton:hover:!disabled {{
                background-color: rgba(212, 165, 116, 0.16);
                border-color: {COLORS['brand_accent']};
                color: {COLORS['text_primary']};
            }}
            QPushButton#validateTokenButton:pressed {{
                background-color: rgba(212, 165, 116, 0.24);
                border-color: {COLORS['brand_secondary']};
            }}
            QPushButton#validateTokenButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                border: 1px solid {COLORS['border_muted']};
                color: {COLORS['text_tertiary']};
            }}
        """)
        self.validate_btn.clicked.connect(self._validate_token)
        token_btn_layout.addWidget(self.show_token_btn)
        token_btn_layout.addWidget(self.validate_btn)
        token_layout.addLayout(token_btn_layout)

        self.token_status = QLabel("")
        token_layout.addWidget(self.token_status)

        self.token_progress = QProgressBar()
        self.token_progress.setRange(0, 0)
        self.token_progress.setTextVisible(False)
        self.token_progress.setFixedHeight(6)
        self.token_progress.setVisible(False)
        token_layout.addWidget(self.token_progress)

        layout.addWidget(token_group)

        # Step 2: Evidence source
        device_group = QGroupBox("2. Select Evidence Source")
        device_layout = QVBoxLayout(device_group)
        device_layout.setContentsMargins(6, 14, 6, 6)
        device_layout.setSpacing(4)

        self.device_panel = DeviceListPanel(self.device_manager)
        self.device_panel.selection_changed.connect(self._on_device_selection_changed)
        self.device_panel.image_file_requested.connect(self._on_image_file_added)
        device_layout.addWidget(self.device_panel)

        layout.addWidget(device_group)

        # Step 3: Artifacts (tab-based)
        artifacts_group = QGroupBox("3. Collection Scope")
        artifacts_outer_layout = QVBoxLayout(artifacts_group)
        artifacts_outer_layout.setContentsMargins(6, 14, 6, 6)
        artifacts_outer_layout.setSpacing(4)

        self.beginner_scope_label = QLabel(
            "Recommended artifacts are selected after authentication."
        )
        self.beginner_scope_label.setWordWrap(True)
        self.beginner_scope_label.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 10px;"
        )
        artifacts_outer_layout.addWidget(self.beginner_scope_label)

        self.advanced_scope_cb = QCheckBox("Show advanced artifact options")
        self.advanced_scope_cb.setChecked(False)
        self.advanced_scope_cb.stateChanged.connect(self._toggle_advanced_scope)
        artifacts_outer_layout.addWidget(self.advanced_scope_cb)

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
        self.artifacts_tab.setVisible(False)

        artifacts_outer_layout.addWidget(self.artifacts_tab)

        # Select All + Include Deleted option
        select_all_layout = QHBoxLayout()
        self.select_all_cb = QCheckBox("Select All (current tab)")
        self.select_all_cb.stateChanged.connect(self._toggle_select_all)
        self.select_all_cb.setVisible(False)
        select_all_layout.addWidget(self.select_all_cb)
        select_all_layout.addStretch()
        self.include_deleted_cb = QCheckBox("Include deleted files")
        self.include_deleted_cb.setChecked(True)
        self.include_deleted_cb.setToolTip("Recover and collect deleted files from MFT (slower but more thorough)")
        self.include_deleted_cb.stateChanged.connect(self._on_artifact_selection_changed)
        select_all_layout.addWidget(self.include_deleted_cb)
        artifacts_outer_layout.addLayout(select_all_layout)

        layout.addWidget(artifacts_group)

        # Step 4: Progress (stage-based progress display)
        progress_group = QGroupBox("4. Collection Progress")
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

        self._update_scope_summary()
        self._update_workflow_status()

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

        for cb in self.artifact_checks.values():
            cb.stateChanged.connect(self._on_artifact_selection_changed)

    def _toggle_advanced_scope(self, state):
        """Show or hide detailed artifact controls."""
        visible = state == Qt.CheckState.Checked.value
        self.artifacts_tab.setVisible(visible)
        self.select_all_cb.setVisible(visible)
        self._update_scope_summary()
        self._update_workflow_status()

    def _on_artifact_selection_changed(self, *_args):
        """Keep beginner summaries and start button in sync."""
        self._update_scope_summary()
        self._update_collect_button_state()

    def _selected_axiom_sources(self, selected_devices=None) -> List:
        devices = selected_devices
        if devices is None:
            devices = self.device_manager.get_selected_devices()
        return [d for d in devices if d.device_type == DeviceType.AXIOM_CASE_DB]

    def _selected_third_party_export_sources(self, selected_devices=None) -> List:
        devices = selected_devices
        if devices is None:
            devices = self.device_manager.get_selected_devices()
        return [d for d in devices if d.device_type == DeviceType.THIRD_PARTY_FORENSIC_EXPORT]

    def _update_scope_summary(self):
        """Update the compact collection scope summary."""
        if not hasattr(self, 'beginner_scope_label'):
            return

        checked = sum(1 for cb in self.artifact_checks.values() if cb.isChecked())
        enabled = sum(1 for cb in self.artifact_checks.values() if cb.isEnabled())
        axiom_count = len(self._selected_axiom_sources())
        export_count = len(self._selected_third_party_export_sources())
        tool_result_count = axiom_count + export_count
        deleted_text = (
            "Deleted files included where supported."
            if getattr(self, 'include_deleted_cb', None) and self.include_deleted_cb.isChecked()
            else "Deleted files excluded."
        )

        if not self.collection_token:
            text = (
                "Authenticate first. The server profile will enable the allowed "
                "artifact set automatically."
            )
        elif checked and tool_result_count:
            text = (
                f"Scope ready: {checked} selected artifact type(s)"
                f" out of {enabled} allowed, plus {tool_result_count} verified tool result source(s). "
                f"{deleted_text}"
            )
        elif checked:
            text = (
                f"Recommended scope ready: {checked} selected artifact type(s)"
                f" out of {enabled} allowed. {deleted_text}"
            )
        elif tool_result_count:
            text = (
                f"Verified tool result scope ready: {tool_result_count} source(s). "
                "Server parsing will expand AXIOM, Cellebrite, or Autopsy results into searchable documents."
            )
        else:
            text = (
                f"No artifact type selected. Open advanced options to choose artifacts. "
                f"{enabled} artifact type(s) are allowed."
            )
        self.beginner_scope_label.setText(text)

    def _format_workflow_step(self, number: int, title: str, done: bool, detail: str) -> str:
        color = COLORS['success'] if done else COLORS['text_tertiary']
        state = "Done" if done else "Needed"
        return (
            f"<span style='color:{color};'><b>{number}. {title}</b> - {state}</span>"
            f"<br><span style='color:{COLORS['text_secondary']};'>{detail}</span>"
        )

    def _update_workflow_status(self):
        """Show the current beginner workflow state."""
        if not hasattr(self, 'workflow_status'):
            return

        token_done = bool(self.collection_token)
        selected_devices = self.device_manager.get_selected_devices()
        source_done = bool(selected_devices)
        artifact_count = sum(1 for cb in self.artifact_checks.values() if cb.isChecked())
        axiom_count = len(self._selected_axiom_sources(selected_devices))
        export_count = len(self._selected_third_party_export_sources(selected_devices))
        tool_result_count = axiom_count + export_count
        scope_done = artifact_count > 0 or tool_result_count > 0

        if self._token_validation_in_progress:
            token_detail = "Validating session token..."
        elif token_done:
            case_label = (self.case_id[:8] + "...") if self.case_id else "validated"
            token_detail = f"Authenticated case: {case_label}"
        else:
            token_detail = "Paste the session token from the web case and validate it."

        if source_done:
            if len(selected_devices) == 1:
                source_detail = selected_devices[0].display_name
            else:
                source_detail = f"{len(selected_devices)} evidence source(s) selected."
        else:
            source_detail = "Select a local drive, connected device, image file, FFS bundle, or verified tool result."

        if scope_done and artifact_count and tool_result_count:
            scope_detail = (
                f"{artifact_count} artifact type(s) and "
                f"{tool_result_count} verified tool result source(s) selected."
            )
        elif scope_done and tool_result_count:
            scope_detail = f"{tool_result_count} verified tool result source(s) selected."
        elif scope_done:
            scope_detail = f"{artifact_count} artifact type(s) selected."
        elif token_done:
            scope_detail = "Open advanced options to choose artifacts."
        else:
            scope_detail = "Collection scope is enabled after authentication."

        ready_done = token_done and source_done and scope_done
        ready_detail = "Ready to start collection." if ready_done else "Complete the required steps above."

        html = "<br><br>".join([
            self._format_workflow_step(1, "Authenticate", token_done, token_detail),
            self._format_workflow_step(2, "Evidence", source_done, source_detail),
            self._format_workflow_step(3, "Scope", scope_done, scope_detail),
            self._format_workflow_step(4, "Start", ready_done, ready_detail),
        ])
        self.workflow_status.setText(html)

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
                include_device = source == "usb_backup"
                supported = set()
                for item_type, item_info in IOS_ARTIFACT_TYPES.items():
                    if item_info.get('requires_device'):
                        if include_device:
                            supported.add(item_type)
                        continue
                    if (
                        'files' in item_info
                        or 'manifest_targets' in item_info
                        or (
                            'manifest_domain' in item_info
                            and (
                                'manifest_path' in item_info
                                or 'manifest_paths' in item_info
                            )
                        )
                    ):
                        supported.add(item_type)
                return supported
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
        self._update_workflow_status()

    def _on_device_removed(self, device_id: str):
        """Device removed (DeviceListPanel handles automatically)"""
        self._log(f"Device removed: {device_id}")
        self._update_collect_button_state()

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

    def _update_platform_tab_states(self):
        """
        Auto-navigate to relevant platform tab based on selected device

        - All tabs remain accessible (not disabled)
        - Auto-focus to appropriate tab based on detected OS
        """
        if getattr(self, '_collection_in_progress', False):
            return

        selected_devices = self.device_manager.get_selected_devices()

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
            self._set_ios_artifact_states("usb_backup", "iOS USB backup extraction")
            return

        self.ios_info_label.setText("Select iOS backup, iOS device, or FFS bundle from device list")
        self.ios_info_label.setStyleSheet(f"color: {COLORS['text_tertiary']}; font-size: 9px;")
        self._disable_ios_artifacts_without_source()

    def _update_collect_button_state(self):
        """Update collect button state"""
        if getattr(self, '_token_validation_in_progress', False) or getattr(self, '_collection_in_progress', False):
            self.collect_btn.setEnabled(False)
            self._update_scope_summary()
            self._update_workflow_status()
            return

        has_token = self.collection_token is not None
        selected_devices = self.device_manager.get_selected_devices()
        has_devices = len(selected_devices) > 0
        has_artifacts = any(cb.isChecked() for cb in self.artifact_checks.values())
        has_axiom_sources = bool(self._selected_axiom_sources(selected_devices))
        has_export_sources = bool(self._selected_third_party_export_sources(selected_devices))

        self.collect_btn.setEnabled(has_token and has_devices and (has_artifacts or has_axiom_sources or has_export_sources))
        self._update_scope_summary()
        self._update_workflow_status()

    def _set_collection_controls_locked(self, locked: bool):
        """Freeze all collection inputs while a collection/upload run is active."""
        self._collection_in_progress = bool(locked)
        self.collect_btn.setEnabled(False)
        self.cancel_btn.setEnabled(bool(locked))
        self.validate_btn.setEnabled(not locked and not getattr(self, '_token_validation_in_progress', False))
        self.show_token_btn.setEnabled(not locked and not getattr(self, '_token_validation_in_progress', False))
        self.token_input.setEnabled(not locked and not getattr(self, '_token_validation_in_progress', False))
        self.select_all_cb.setEnabled(not locked)
        self.include_deleted_cb.setEnabled(not locked)
        self.advanced_scope_cb.setEnabled(not locked)
        self.artifacts_tab.setEnabled(not locked)
        if hasattr(self, 'linux_mount_path'):
            self.linux_mount_path.setEnabled(not locked)
        if hasattr(self, 'macos_mount_path'):
            self.macos_mount_path.setEnabled(not locked)
        if hasattr(self, 'device_panel'):
            self.device_panel.set_interaction_locked(locked)
        for cb in self.artifact_checks.values():
            cb.setEnabled(False if locked else self._is_artifact_allowed(cb.property("artifact_type") or ""))
        if not locked:
            self._update_platform_tab_states()
            self._update_collect_button_state()
        self._update_scope_summary()
        self._update_workflow_status()

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
        """Check if server is reachable without blocking the GUI."""
        if self._server_health_worker and self._server_health_worker.isRunning():
            return

        self.server_status.setText("Server: Checking...")
        self.server_status.setStyleSheet("color: #ffc107;")
        worker = ServerHealthWorker(self.config['server_url'])
        self._server_health_worker = worker
        worker.result_ready.connect(self._on_server_health_result)
        worker.finished.connect(self._on_server_health_finished)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _on_server_health_result(self, success, error_detail):
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

    def _on_server_health_finished(self):
        worker = self.sender()
        if self._server_health_worker is worker:
            self._server_health_worker = None

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
        if getattr(self, '_collection_in_progress', False):
            return

        checked = state == Qt.CheckState.Checked.value

        # Determine category based on current tab index
        current_tab = self.artifacts_tab.currentIndex()
        category_map = {0: 'windows', 1: 'android', 2: 'ios', 3: 'linux', 4: 'macos', 5: 'ai_activity'}
        current_category = category_map.get(current_tab, 'windows')

        for artifact_type, cb in self.artifact_checks.items():
            if not cb.isEnabled():
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
        self._update_scope_summary()
        self._update_collect_button_state()

    def _validate_token(self):
        """Validate the session token"""
        if getattr(self, '_collection_in_progress', False):
            self.status_bar.showMessage("Collection is already running...")
            return

        token = self.token_input.text().strip()
        if not token:
            QMessageBox.warning(self, "Error", "Please enter a session token")
            return

        if self._token_validation_in_progress:
            self.status_bar.showMessage("Token validation is already running...")
            return

        self._log("Validating token...")
        self._set_token_validation_busy(True)
        QApplication.processEvents()

        worker = TokenValidationWorker(self.config['server_url'], token)
        self._token_validation_worker = worker
        worker.result_ready.connect(self._on_token_validation_result)
        worker.error_ready.connect(self._on_token_validation_error)
        worker.finished.connect(self._on_token_validation_worker_finished)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _set_token_validation_busy(self, busy: bool):
        """Show validation progress and prevent duplicate authentication."""
        self._token_validation_in_progress = busy
        controls_enabled = not busy and not getattr(self, '_collection_in_progress', False)
        self.validate_btn.setEnabled(controls_enabled)
        self.show_token_btn.setEnabled(controls_enabled)
        self.token_input.setEnabled(controls_enabled)

        if busy:
            self.validate_btn.setText("Validating...")
            self.token_status.setText("Validating token...")
            self.token_status.setStyleSheet("color: #fbbf24;")
            self.token_progress.setRange(0, 0)
            self.token_progress.setVisible(True)
            self.collect_btn.setEnabled(False)
            self.status_bar.showMessage("Validating session token...")
            self._update_workflow_status()
            return

        self.validate_btn.setText("Validate Token")
        self.token_progress.setVisible(False)
        self.token_progress.setRange(0, 100)
        self.token_input.setEnabled(not getattr(self, '_collection_in_progress', False))
        self.show_token_btn.setEnabled(not getattr(self, '_collection_in_progress', False))
        self.status_bar.showMessage("Ready")
        self._update_collect_button_state()

    def _on_token_validation_worker_finished(self):
        """Drop the completed validation worker reference."""
        worker = self.sender()
        if self._token_validation_worker is worker:
            self._token_validation_worker = None

    def _on_token_validation_error(self, error: str):
        """Handle unexpected validation worker failures."""
        self._set_token_validation_busy(False)
        self.token_status.setText("Invalid: validation failed")
        self.token_status.setStyleSheet("color: #f72585;")
        self._log(f"Token validation failed: {error}", error=True)
        QMessageBox.warning(
            self,
            "Token Validation Failed",
            f"Unable to validate the token.\n\n{error}"
        )

    def _on_token_validation_result(self, result):
        """Apply token validation result on the UI thread."""
        try:
            self.token_status.setText("Applying collection profile...")
            self._handle_token_validation_result(result)
        finally:
            self._set_token_validation_busy(False)

    def _handle_token_validation_result(self, result):
        """Apply successful or failed token validation results."""

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
            for registry, is_mft_registry in (
                (ARTIFACT_TYPES, False),
                (ARTIFACT_MFT_FILTERS, True),
                (ANDROID_ARTIFACT_TYPES, False),
                (IOS_ARTIFACT_TYPES, False),
                (LINUX_ARTIFACT_TYPES, False),
                (MACOS_ARTIFACT_TYPES, False),
            ):
                self.profile_artifact_types.update(
                    apply_collection_profile_to_registry(
                        self.collection_profile_targets,
                        registry,
                        artifact_aliases=SERVER_TO_COLLECTOR_MAPPING,
                        mft_registry=is_mft_registry,
                    )
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

            self.token_status.setText(f"Validated - Case: {self.case_id[:8]}...")
            self.token_status.setStyleSheet(
                f"background: {COLORS['success_bg']}; "
                f"border: 1px solid {COLORS['success']}; "
                f"border-radius: 4px; "
                f"color: {COLORS['success']}; "
                "font-weight: 700; padding: 4px 6px;"
            )
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
            allow_all = 'all' in self.allowed_artifacts or not result.allowed_artifacts
            self._allow_all_artifacts = allow_all
            self._mapped_allowed_artifacts = mapped_allowed

            self._log(f"Mapped artifacts for GUI: {', '.join(sorted(mapped_allowed))}")
            if allow_all:
                self._log("All artifacts are allowed - selecting all by default")

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

            self._log(f"[DEBUG] Enabled and checked {enabled_count}/{len(self.artifact_checks)} checkboxes")
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

    def _start_collection(self):
        """Start the collection process"""
        if getattr(self, '_collection_in_progress', False):
            self._log("Collection is already running. Wait for it to finish or cancel it first.", error=True)
            return

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
        result = validator.validate_session(
            self.session_id,
            self.collection_token,
            profile_id=self.collection_profile_id,
        )

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

        selected = [k for k, cb in self.artifact_checks.items() if cb.isChecked()]
        axiom_sources = self._selected_axiom_sources(selected_devices)
        export_sources = self._selected_third_party_export_sources(selected_devices)
        if not selected and not axiom_sources and not export_sources:
            QMessageBox.warning(self, "Error", "Please select at least one artifact type or verified tool result source")
            return

        self._log_mobile_preflight(selected_devices, selected)

        # Confirm selected devices (show clearly when multiple)
        if len(selected_devices) > 1:
            device_list = "\n".join([f"  • {d.display_name}" for d in selected_devices])
            confirm = QMessageBox.question(
                self,
                "Confirm Collection Targets",
                f"Collecting from {len(selected_devices)} device(s):\n\n{device_list}\n\n"
                f"Selected artifacts: {len(selected)}\n"
                f"Verified tool result sources: {len(axiom_sources) + len(export_sources)}\n\n"
                "Evidence scope warning:\n"
                "Only continue if all selected sources belong to the same "
                "investigation scope.\n"
                "Uncheck any unrelated device, disk image, or removable media "
                "before starting collection.\n\n"
                f"Continue?\n\n"
                f"(To collect from specific devices only, select 'No'\n"
                f"and uncheck unwanted devices)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if confirm != QMessageBox.StandardButton.Yes:
                self._log("Collection cancelled: User wants to reconfirm device selection")
                return

        self._log(f"Starting collection from {len(selected_devices)} device(s)")

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
            unauthorized_android = [
                d for d in android_devices
                if not d.metadata.get('usb_debugging')
            ]
            if unauthorized_android:
                self._log(
                    "Android collection blocked: USB debugging is not authorized.",
                    error=True,
                )
                QMessageBox.warning(
                    self,
                    "Android Authorization Required",
                    "Unlock the Android device, approve the USB debugging "
                    "prompt, then click Refresh and select the device again."
                )
                return

            from gui.android_info_dialog import show_android_info_dialog
            android_result = show_android_info_dialog(
                device_info=android_devices[0].metadata,
                parent=self
            )
            if not android_result.proceed:
                self._log("Collection cancelled: Android device info dialog cancelled.")
                return

        if selected:
            self._log(f"Starting collection for: {', '.join(selected)}")
        tool_result_total = len(axiom_sources) + len(export_sources)
        if tool_result_total:
            self._log(f"Starting verified tool result upload for {tool_result_total} source(s)")

        # Freeze every source/scope/auth input for the full collection and
        # upload lifetime. Individual UI events can otherwise re-enable the
        # start button or mutate selected sources while the worker is running.
        self._set_collection_controls_locked(True)

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

    def _check_for_updates(self):
        """Check for updates via GitHub Releases API without blocking the GUI."""
        if self._update_check_worker and self._update_check_worker.isRunning():
            return

        worker = UpdateCheckWorker()
        self._update_check_worker = worker
        worker.update_ready.connect(self._on_update_check_result)
        worker.finished.connect(self._on_update_check_finished)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _on_update_check_result(self, update_info):
        if not update_info:
            return
        try:
            from core.updater import show_update_dialog
            show_update_dialog(self, update_info)
        except Exception:
            pass

    def _on_update_check_finished(self):
        worker = self.sender()
        if self._update_check_worker is worker:
            self._update_check_worker = None

    def _confirm_abort_collection(self, action: str = "cancel") -> bool:
        """Ask before destructive collection abort/reset."""
        if action == "close":
            title = "Stop Collection and Close?"
            action_text = "close the collector"
        else:
            title = "Cancel Collection?"
            action_text = "cancel the collection"
        confirm = QMessageBox.question(
            self,
            title,
            "Collection is still running.\n\n"
            "If you stop now, the server-side case work will be cancelled "
            "and any partial uploaded data will be removed.\n\n"
            f"Do you want to {action_text}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return confirm == QMessageBox.StandardButton.Yes

    def _shutdown_ws_worker(self, reason: str = 'user_close'):
        """Stop collector control WebSocket without touching evidence data."""
        if hasattr(self, '_ws_worker') and self._ws_worker.isRunning():
            try:
                self._ws_worker.request_shutdown(reason)
            except Exception:
                pass
            try:
                self._ws_worker.stop()
                self._ws_worker.wait(2000)
            except Exception:
                pass

    def _cancel_collection(self):
        """Cancel ongoing collection"""
        if hasattr(self, 'worker') and self.worker.isRunning():
            try:
                if self.worker.can_close_without_abort():
                    QMessageBox.information(
                        self,
                        "Upload Complete",
                        "All files have been uploaded. Server processing will continue; "
                        "you can close this window without cancelling the case.",
                    )
                    return
            except Exception:
                pass
            if not self._confirm_abort_collection("cancel"):
                return

            self._close_ios_status()
            self.worker.cancel()
            self._log("Collection cancelled by user")

            # Immediately clear session data so user must enter new token.
            # worker.cancel() sends the destructive server abort exactly once.
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
            if result.success:
                self.worker._pw_response = result.password
            elif error_msg == "ENCRYPTION_SETUP" and result.skip:
                from collectors.ios_collector import IOS_ENCRYPTION_SKIP_SENTINEL
                self.worker._pw_response = IOS_ENCRYPTION_SKIP_SENTINEL
            else:
                self.worker._pw_response = None
            if self.worker._pw_event:
                self.worker._pw_event.set()

        # Show verifying indicator while collector checks the password
        has_password = result.success and result.password
        result.clear_sensitive()
        if has_password:
            if error_msg == "ENCRYPTION_SETUP":
                self._show_ios_status(
                    "Check the iPhone screen now.\n"
                    "Unlock the iPhone and enter the device passcode on the iPhone "
                    "when prompted to enable encrypted backup.\n"
                    "Do not enter the iPhone passcode in this collector window.",
                    title="iPhone Passcode Required"
                )
            else:
                self._show_ios_status(
                    "Verifying backup password...\n"
                    "This may take several minutes. Keep the iPhone unlocked "
                    "and do not disconnect it.",
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
        close_after_finish = getattr(self, '_close_after_worker_finish', False)

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

        # [Security] Clear session data - prevent token reuse
        # After collection complete/cancelled, must re-authenticate with new token
        self._clear_session_data()
        self._set_collection_controls_locked(False)
        self.collect_btn.setEnabled(False)  # Disable after collection complete/cancelled (new token required)
        self.cancel_btn.setEnabled(False)

        if success:
            self._collection_completed = True
            self._log(f"Collection completed: {message}")
            self._log("")
            self._log("✅ All evidence has been uploaded to the server.")
            self._log("👉 Return to your web browser and start AI Analysis.")
            self._log("")
            self._log("New token required for new collection.")
            if not close_after_finish:
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
            if not close_after_finish:
                QMessageBox.critical(self, "Error", f"{message}\n\nPlease get a new token for additional collections.")

        self.status_bar.showMessage("Ready - New token required")
        self.token_status.setText("New token required")
        self.token_status.setStyleSheet("color: #ffc107;")

        if close_after_finish:
            self._shutdown_ws_worker('collection_finished')
            app = QApplication.instance()
            if app:
                app.quit()

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
        self._update_scope_summary()
        self._update_workflow_status()

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
        """Cleanup on window close."""
        if hasattr(self, 'worker') and self.worker.isRunning():
            try:
                if self.worker.can_close_without_abort():
                    self._close_after_worker_finish = True
                    self._close_ios_status()
                    self.device_manager.stop_monitoring()
                    self.hide()
                    self._log(
                        "Upload complete. Finalizing the server handoff before exiting."
                    )
                    event.ignore()
                    return
            except Exception:
                pass

            if not self._confirm_abort_collection("close"):
                event.ignore()
                return

            self._close_ios_status()
            self.device_manager.stop_monitoring()
            self._shutdown_ws_worker('user_cancel_close')
            self.worker.cancel()
            self.worker.wait(3000)  # Wait max 3 seconds
        else:
            self.device_manager.stop_monitoring()
            self._shutdown_ws_worker('user_close')
            if not getattr(self, '_collection_completed', False):
                # Closed after token auth but before collection start/finish.
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
        self._upload_batch_complete = False
        self._completion_signal_in_flight = False
        self._server_completion_accepted = False
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
                    payload = {
                        'session_id': self.session_id,
                        'collection_token': self.collection_token,
                    }
                    if self.collection_profile_id:
                        payload['profile_id'] = self.collection_profile_id
                    resp = requests.post(
                        f"{self.server_url}/api/v1/collector/validate-session",
                        json=payload,
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

    def _tuning_int(self, key: str, env_name: str, default: int, min_value: int, max_value: int) -> int:
        import os

        raw_value = os.getenv(env_name, self.config.get(key))
        try:
            parsed = int(raw_value)
        except (TypeError, ValueError):
            parsed = default
        return max(min_value, min(max_value, parsed))

    def _prepare_upload_item(self, output_dir: str, item: tuple) -> dict:
        import os
        import time

        index, file_path, artifact_type, metadata = item
        filename = Path(file_path).name
        timings = {}
        item_start = time.perf_counter()

        try:
            if not os.path.exists(file_path):
                return {
                    'ok': False,
                    'index': index,
                    'filename': filename,
                    'error': f"[ERROR] {filename}: file disappeared before upload preparation",
                }
            if not os.path.isfile(file_path):
                return {
                    'ok': False,
                    'index': index,
                    'filename': filename,
                    'error': f"[ERROR] {filename}: non-file path cannot be uploaded",
                }

            actual_size = os.path.getsize(file_path)
            if actual_size <= 0:
                if self._is_empty_placeholder_artifact(file_path, artifact_type, metadata):
                    return {
                        'ok': False,
                        'skipped': True,
                        'index': index,
                        'filename': filename,
                        'message': f"[SKIP] {filename}: empty Android placeholder ignored",
                    }
                return {
                    'ok': False,
                    'index': index,
                    'filename': filename,
                    'error': f"[ERROR] {filename}: empty file cannot be uploaded",
                }

            try:
                with open(file_path, 'rb') as readable:
                    readable.read(1)
            except OSError as access_error:
                return {
                    'ok': False,
                    'index': index,
                    'filename': filename,
                    'error': f"[ERROR] {filename}: file is not readable before upload ({access_error})",
                }

            hash_start = time.perf_counter()
            hash_result = FileHashCalculator().calculate_file_hash(file_path)
            original_hash = hash_result.sha256_hash
            original_size = hash_result.file_size
            timings['hash_ms'] = int((time.perf_counter() - hash_start) * 1000)

            cached_hash = metadata.get('hash_sha256') or metadata.get('sha256')
            if cached_hash and cached_hash != original_hash:
                metadata['collector_reported_hash'] = cached_hash
            metadata['hash_sha256'] = original_hash
            metadata['sha256'] = original_hash
            metadata['original_hash'] = original_hash
            metadata['original_size'] = original_size
            self._record_upload_hash_metadata(
                metadata,
                file_path,
                original_hash,
                original_size,
            )
            metadata['collection_time'] = datetime.utcnow().isoformat()
            metadata['encryption'] = {
                'nonce': 'hash_only',
                'original_hash': original_hash,
            }

            upload_file_path = file_path
            timings['stable_copy_ms'] = 0
            if self._requires_stable_upload_copy(artifact_type, metadata):
                copy_start = time.perf_counter()
                upload_file_path = self._stage_stable_upload_copy(
                    output_dir=output_dir,
                    file_path=file_path,
                    artifact_type=artifact_type,
                    metadata=metadata,
                    original_hash=original_hash,
                )
                timings['stable_copy_ms'] = int((time.perf_counter() - copy_start) * 1000)

            timings['total_ms'] = int((time.perf_counter() - item_start) * 1000)
            return {
                'ok': True,
                'index': index,
                'filename': filename,
                'file_path': upload_file_path,
                'artifact_type': artifact_type,
                'metadata': metadata,
                'file_size': original_size,
                'timings': timings,
            }
        except FileNotFoundError:
            return {
                'ok': False,
                'index': index,
                'filename': filename,
                'error': f"[ERROR] {filename}: file removed mid-pipeline",
            }
        except Exception as exc:
            return {
                'ok': False,
                'index': index,
                'filename': filename,
                'error': f"Preparation failed ({filename}): {exc}",
            }

    @staticmethod
    def _is_empty_placeholder_artifact(file_path: str, artifact_type: str, metadata: dict) -> bool:
        """Return True for mobile placeholder files that should not block upload.

        Android external storage often contains zero-byte marker files such as
        `.nomedia`. They have directory-display semantics on the device but no
        forensic payload to upload. Treat them as skipped so they do not fail an
        otherwise valid collection batch.
        """
        filename = Path(file_path).name.lower()
        if artifact_type.startswith("mobile_android_") and filename in {".nomedia"}:
            return True
        if metadata.get("placeholder") is True:
            return True
        return False

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
        if self._server_completion_accepted:
            self._stop_heartbeat()
            return
        self._cancelled = True
        self._stop_heartbeat()
        # Unblock password callback if waiting
        if self._pw_event:
            self._pw_response = None
            self._pw_event.set()
        # Send abort signal to server (clear active collection flag)
        self._abort_session()

    def is_completion_signal_in_flight(self) -> bool:
        return self._completion_signal_in_flight and not self._server_completion_accepted

    def is_server_completion_accepted(self) -> bool:
        return self._server_completion_accepted

    def can_close_without_abort(self) -> bool:
        return (
            self._upload_batch_complete
            or self._completion_signal_in_flight
            or self._server_completion_accepted
        )

    def _mobile_ffs_available_artifacts(self, device) -> set:
        meta = device.metadata or {}
        present = set(meta.get("present_artifacts") or [])
        if meta.get("present_artifact_scan_complete"):
            return present
        if present:
            return present

        try:
            if device.device_type == DeviceType.MOBILE_FFS_BUNDLE_ANDROID:
                from collectors.mobile_ffs.path_specs import ANDROID_PATH_SPECS
                return {spec.artifact_type for spec in ANDROID_PATH_SPECS}
            if device.device_type == DeviceType.MOBILE_FFS_BUNDLE_IOS:
                from collectors.mobile_ffs.path_specs import IOS_PATH_SPECS
                return {spec.artifact_type for spec in IOS_PATH_SPECS}
        except Exception:
            return set()
        return set()

    def _artifact_category_for_device(self, artifact_type: str, device) -> str:
        info = ARTIFACT_TYPES.get(artifact_type, {})
        category = info.get("category", "")
        if category == "ai_activity" and artifact_type.startswith("ai_mobile_"):
            if device.device_type == DeviceType.MOBILE_FFS_BUNDLE_ANDROID:
                return "android"
            if device.device_type == DeviceType.MOBILE_FFS_BUNDLE_IOS:
                return "ios"
        return category

    def _artifacts_for_device(self, device) -> List[str]:
        if device.device_type == DeviceType.AXIOM_CASE_DB:
            return ["axiom_case_db"]
        if device.device_type == DeviceType.THIRD_PARTY_FORENSIC_EXPORT:
            metadata = device.metadata or {}
            upload_type = metadata.get("upload_artifact_type")
            return [upload_type] if upload_type else []
        if device.device_type not in (
            DeviceType.MOBILE_FFS_BUNDLE_ANDROID,
            DeviceType.MOBILE_FFS_BUNDLE_IOS,
        ):
            return list(self.artifacts)

        platform = (
            "android"
            if device.device_type == DeviceType.MOBILE_FFS_BUNDLE_ANDROID
            else "ios"
        )
        available = self._mobile_ffs_available_artifacts(device)
        if not available:
            self.log_message.emit(
                f"[WARN] [{device.display_name}] FFS present-artifact scan unavailable; "
                "using selected mobile artifacts as-is.",
                True,
            )
            return [
                artifact_type for artifact_type in self.artifacts
                if self._artifact_category_for_device(artifact_type, device) == platform
            ]

        try:
            from collectors.mobile_ffs_collector import expand_mobile_ffs_selection
        except Exception:
            expand_mobile_ffs_selection = None

        filtered = []
        seen = set()
        mobile_selected = 0

        for artifact_type in self.artifacts:
            if self._artifact_category_for_device(artifact_type, device) != platform:
                continue
            mobile_selected += 1
            if expand_mobile_ffs_selection:
                candidates = expand_mobile_ffs_selection(
                    artifact_type,
                    available,
                    platform=platform,
                )
            else:
                candidates = [artifact_type] if artifact_type in available else []
            for candidate in candidates:
                if candidate not in seen:
                    filtered.append(candidate)
                    seen.add(candidate)

        skipped = max(mobile_selected - len(seen), 0)
        if skipped:
            self.log_message.emit(
                f"[SKIP] [{device.display_name}] {skipped} selected mobile artifact "
                "type(s) are not present or not supported by this FFS bundle.",
                False,
            )
        return filtered

    @staticmethod
    def _upload_batch_ready_for_completion(
        total_upload: int,
        success_count: int,
        preparation_error_count: int,
        ios_quality_error: Optional[str],
    ) -> bool:
        return (
            total_upload > 0
            and success_count == total_upload
            and preparation_error_count == 0
            and not ios_quality_error
        )

    @staticmethod
    def _is_ios_runtime_collector(collector) -> bool:
        module_name = type(collector).__module__.lower()
        class_name = type(collector).__name__.lower()
        return (
            module_name.endswith("ios_collector")
            or class_name in {"ioscollector", "iosdeviceconnector"}
        )

    @staticmethod
    def _target_label(index: int, total: int) -> str:
        return f"Selected target {index}/{max(total, 1)}"

    @staticmethod
    def _sanitize_collector_status(message: str) -> str:
        text = str(message or "")
        if "progress:" in text.lower():
            return text
        lowered = text.lower()
        if lowered.startswith("preparing backup for "):
            return "Preparing backup access..."
        if lowered.startswith("extracting ") and " from backup" in lowered:
            return "Extracting selected target from backup..."
        return text

    @staticmethod
    def _requires_stable_upload_copy(artifact_type: str, metadata: dict) -> bool:
        method = str(metadata.get('collection_method', '')).lower()
        if method == 'ffs_bundle':
            return False
        if method in {'ios_backup_extraction', 'pymobiledevice3', 'ios_backup'}:
            return True
        return artifact_type.startswith('mobile_ios_')

    @staticmethod
    def _stable_upload_path(output_dir: str, artifact_type: str, file_path: str, original_hash: str) -> Path:
        safe_artifact = ''.join(
            c if c.isalnum() or c in ('_', '-', '.') else '_'
            for c in artifact_type
        )
        hash_dir = original_hash[:16] if original_hash else 'unhashed'
        return Path(output_dir) / '_upload_queue' / safe_artifact / hash_dir / Path(file_path).name

    @staticmethod
    def _record_upload_hash_metadata(
        metadata: dict,
        file_path: str,
        file_hash: str,
        file_size: int,
    ) -> None:
        import os

        stat_result = os.stat(file_path)
        metadata['upload_hash_sha256'] = file_hash
        metadata['upload_hash_size'] = file_size
        metadata['upload_hash_mtime_ns'] = getattr(
            stat_result,
            'st_mtime_ns',
            int(stat_result.st_mtime * 1_000_000_000),
        )
        metadata['upload_hash_path'] = os.path.abspath(file_path)

    @staticmethod
    def _calculate_sha256(file_path: str) -> str:
        import hashlib

        h = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()

    @classmethod
    def _stage_stable_upload_copy(
        cls,
        output_dir: str,
        file_path: str,
        artifact_type: str,
        metadata: dict,
        original_hash: str,
    ) -> str:
        import os
        import shutil

        source_path = Path(file_path)
        staged_path = cls._stable_upload_path(
            output_dir=output_dir,
            artifact_type=artifact_type,
            file_path=file_path,
            original_hash=original_hash,
        )
        staged_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            if source_path.resolve() == staged_path.resolve():
                return str(source_path)
        except OSError:
            pass

        shutil.copy2(source_path, staged_path)
        if not staged_path.is_file():
            raise FileNotFoundError(str(staged_path))
        staged_size = os.path.getsize(staged_path)
        if staged_size != os.path.getsize(source_path):
            staged_path.unlink(missing_ok=True)
            raise OSError(f"staged copy size mismatch for {source_path.name}")

        staged_hash = cls._calculate_sha256(str(staged_path))
        if staged_hash != original_hash:
            staged_path.unlink(missing_ok=True)
            raise OSError(f"staged copy hash mismatch for {source_path.name}")

        metadata['upload_staged'] = True
        cls._record_upload_hash_metadata(
            metadata,
            str(staged_path),
            staged_hash,
            staged_size,
        )
        return str(staged_path)

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

    def _prewarm_collector_index(self, collector, device_name: str) -> None:
        """Build reusable filesystem indexes before per-artifact collection starts."""
        import time

        started = time.perf_counter()
        try:
            # ArtifactCollector forensic-disk mode keeps its own scan cache.
            if hasattr(collector, 'forensic_disk_accessor') and collector.forensic_disk_accessor:
                self.log_message.emit(f"[{device_name}] Building artifact index...", False)
                self.progress_updated.emit(1, 0, 0, f"[{device_name}] Building artifact index...", "")
                if hasattr(collector, '_scan_cache') and collector._scan_cache is None:
                    collector._scan_cache = collector.forensic_disk_accessor.scan_all_files(
                        include_deleted=True
                    )
                    if hasattr(collector, '_build_scan_index') and collector._scan_index is None:
                        collector._scan_index = collector._build_scan_index(collector._scan_cache)
                    active_count = len(collector._scan_cache.get('active_files', []))
                    elapsed_ms = int((time.perf_counter() - started) * 1000)
                    self.log_message.emit(
                        f"[{device_name}] Index ready: {active_count} files ({elapsed_ms}ms)",
                        False,
                    )
                return

            # BaseMFTCollector subclasses, including E01ArtifactCollector and
            # LocalMFTCollector, expose _build_mft_index(). Restrict prewarm to
            # NTFS/native extractor mode so non-NTFS direct-path collection is not
            # forced into an expensive full filesystem scan.
            accessor = getattr(collector, '_accessor', None)
            if (
                accessor is not None
                and hasattr(collector, '_build_mft_index')
                and not getattr(collector, '_mft_indexed', False)
                and getattr(accessor, '_extractor', None) is not None
            ):
                self.log_message.emit(f"[{device_name}] Building artifact index...", False)
                self.progress_updated.emit(1, 0, 0, f"[{device_name}] Building artifact index...", "")
                collector._build_mft_index()
                cache = getattr(collector, '_mft_cache', {}) or {}
                active_count = len(cache.get('active_files', []))
                deleted_count = len(cache.get('deleted_files', []))
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                self.log_message.emit(
                    f"[{device_name}] Index ready: {active_count} active, "
                    f"{deleted_count} deleted ({elapsed_ms}ms)",
                    False,
                )
        except Exception as e:
            self.log_message.emit(f"[{device_name}] Index build skipped: {e}", True)

    WINDOWS_BASELINE_ARTIFACTS = frozenset({
        'mft',
        'registry',
        'eventlog',
        'document',
    })
    WINDOWS_RECOMMENDED_ARTIFACTS = frozenset({
        'logfile',
        'usn_journal',
        'prefetch',
        'browser',
        'recent',
        'jumplist',
        'shellbags',
        'windows_search_index',
    })
    DISK_IMAGE_DEVICE_TYPES = frozenset({
        DeviceType.WINDOWS_PHYSICAL_DISK,
        DeviceType.E01_IMAGE,
        DeviceType.RAW_IMAGE,
        DeviceType.VMDK_IMAGE,
        DeviceType.VHD_IMAGE,
        DeviceType.VHDX_IMAGE,
        DeviceType.QCOW2_IMAGE,
        DeviceType.VDI_IMAGE,
    })

    def _selected_partition_summary(self, collector) -> dict:
        """Return non-sensitive metadata for the currently selected partition."""
        selected_index = getattr(collector, '_selected_partition', None)
        partitions = getattr(collector, '_partitions', []) or []
        selected = next((p for p in partitions if getattr(p, 'index', None) == selected_index), None)
        if not selected:
            return {"selected_partition": selected_index}

        size = int(getattr(selected, 'size', 0) or 0)
        return {
            "selected_partition": int(getattr(selected, 'index', -1)),
            "filesystem": str(getattr(selected, 'filesystem', '') or ''),
            "type_name": str(getattr(selected, 'type_name', '') or ''),
            "size_bytes": size,
            "size_gb": round(size / (1024 ** 3), 2) if size else 0,
        }

    def _is_windows_disk_source(self, device, collector) -> bool:
        if device.device_type not in self.DISK_IMAGE_DEVICE_TYPES:
            return False
        partition = self._selected_partition_summary(collector)
        filesystem = str(partition.get('filesystem') or '').upper()
        if filesystem == 'NTFS':
            return True
        if device.device_type == DeviceType.WINDOWS_PHYSICAL_DISK:
            return True
        return False

    def _collection_scope_summary(self, device, collector, artifacts: List[str]) -> dict:
        artifact_set = set(artifacts or [])
        baseline_missing = sorted(self.WINDOWS_BASELINE_ARTIFACTS - artifact_set)
        recommended_missing = sorted(self.WINDOWS_RECOMMENDED_ARTIFACTS - artifact_set)
        return {
            "device_type": device.device_type.name,
            "source_kind": "disk_image" if device.device_type in self.DISK_IMAGE_DEVICE_TYPES else "device",
            "partition": self._selected_partition_summary(collector),
            "selected_artifact_count": len(artifact_set),
            "windows_baseline_missing": baseline_missing,
            "windows_recommended_missing": recommended_missing,
            "windows_disk_source": self._is_windows_disk_source(device, collector),
        }

    def _log_collection_scope(self, device_name: str, summary: dict) -> None:
        partition = summary.get('partition') or {}
        partition_label = (
            f"#{partition.get('selected_partition')} "
            f"{partition.get('filesystem') or 'unknown'} "
            f"{partition.get('type_name') or 'unknown'} "
            f"({partition.get('size_gb', 0)} GB)"
        )
        self.log_message.emit(
            f"[{device_name}] Collection scope: source={summary.get('device_type')}, "
            f"partition={partition_label}, selected_artifacts={summary.get('selected_artifact_count')}",
            False,
        )
        recommended_missing = summary.get('windows_recommended_missing') or []
        if summary.get('windows_disk_source') and recommended_missing:
            self.log_message.emit(
                f"[{device_name}] Recommended Windows artifacts not selected: "
                f"{', '.join(recommended_missing)}",
                False,
            )

    def _validate_collection_scope(self, device_name: str, summary: dict) -> bool:
        if not summary.get('windows_disk_source'):
            return True

        missing = summary.get('windows_baseline_missing') or []
        if not missing:
            return True

        self.log_message.emit(
            f"[BLOCK] [{device_name}] Windows disk image baseline is incomplete. "
            f"Select required artifacts: {', '.join(missing)}.",
            True,
        )
        self.log_message.emit(
            f"[BLOCK] [{device_name}] Collection stopped before upload to prevent "
            "a partial case that cannot support case-level analysis.",
            True,
        )
        return False

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
                attempted_partition_indexes = set()

                def _partition_label(partition):
                    size = getattr(partition, 'size', 0) or 0
                    size_gb = size / (1024 ** 3) if size else 0
                    type_name = getattr(partition, 'type_name', '') or 'unknown'
                    return (
                        f"#{partition.index} {partition.filesystem} {type_name} "
                        f"({size_gb:.1f} GB)"
                    )

                preferred_partition_index = None
                if hasattr(collector, 'get_windows_partition'):
                    preferred_partition_index = collector.get_windows_partition()

                if preferred_partition_index is not None:
                    attempted_partition_indexes.add(preferred_partition_index)
                    preferred_partition = next(
                        (p for p in partitions if p.index == preferred_partition_index),
                        None,
                    )
                    if collector.select_partition(preferred_partition_index):
                        label = _partition_label(preferred_partition) if preferred_partition else f"#{preferred_partition_index}"
                        self.log_message.emit(f"Partition selected: {label}", False)
                        selected = True

                priority_fs = ['NTFS', 'APFS', 'HFS+', 'HFSX', 'HFS', 'ext4', 'ext3', 'ext2', 'XFS', 'Btrfs', 'ZFS', 'UFS', 'FAT32', 'FAT16', 'FAT12', 'exFAT']
                for target_fs in priority_fs:
                    if selected:
                        break
                    for p in partitions:
                        if p.index in attempted_partition_indexes:
                            continue
                        if getattr(p, 'filesystem', '').upper() == target_fs.upper():
                            attempted_partition_indexes.add(p.index)
                            if collector.select_partition(p.index):
                                self.log_message.emit(f"Partition selected: {_partition_label(p)}", False)
                                selected = True
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

            # ========================================
            # STAGE 1: Collection (30%)
            # ========================================
            self.log_message.emit("Starting artifact collection...", False)
            collected_raw_files = []  # (file_path, artifact_type, metadata)
            _ios_collectors = []  # Track iOS collectors for cleanup
            ios_backup_target_count = 0
            ios_backup_file_count = 0
            ios_backup_no_match_count = 0
            ios_backup_error_count = 0
            ios_backup_blocking_error = ""
            ios_backup_blocked_target_count = 0

            # If devices are selected, collect per device
            if self.selected_devices:
                artifacts_by_device = {
                    device.device_id: self._artifacts_for_device(device)
                    for device in self.selected_devices
                }
                total_items = sum(len(v) for v in artifacts_by_device.values())
                item_index = 0

                for device in self.selected_devices:
                    if self._cancelled:
                        self.finished.emit(False, "Collection cancelled")
                        return

                    device_name = device.display_name
                    self.log_message.emit(f"Device: {device_name}", False)

                    if device.device_type == DeviceType.AXIOM_CASE_DB:
                        item_index += 1
                        stage_progress = int((item_index / max(total_items, 1)) * 100)
                        overall_progress = self._calculate_overall_progress(1, stage_progress)
                        remaining = self._estimate_remaining_time(1, stage_progress, item_index, total_items)
                        self.progress_updated.emit(
                            1, stage_progress, overall_progress,
                            f"[{device_name}] Preparing AXIOM DB upload...",
                            remaining,
                        )

                        axiom_path = (device.metadata or {}).get('file_path')
                        if not axiom_path or not Path(axiom_path).is_file():
                            self.log_message.emit(
                                f"[ERROR] [{device_name}] AXIOM DB file is missing or unreadable",
                                True,
                            )
                            continue

                        metadata = dict(device.metadata or {})
                        metadata.update({
                            'artifact_type': 'axiom_case_db',
                            'upload_artifact_type': 'axiom_case_db',
                            'collection_method': 'axiom_case_db_upload',
                            'device_id': device.device_id,
                            'device_name': device_name,
                            'device_type': device.device_type.name,
                            'original_path': metadata.get('original_path') or axiom_path,
                            'source_tool': metadata.get('source_tool') or 'magnet_axiom',
                        })
                        collected_raw_files.append((axiom_path, 'axiom_case_db', metadata))
                        self.file_collected.emit(Path(axiom_path).name, True)
                        self.log_message.emit(
                            f"[{device_name}] AXIOM DB queued for upload: {Path(axiom_path).name}",
                            False,
                        )
                        continue


                    if device.device_type == DeviceType.THIRD_PARTY_FORENSIC_EXPORT:
                        item_index += 1
                        stage_progress = int((item_index / max(total_items, 1)) * 100)
                        overall_progress = self._calculate_overall_progress(1, stage_progress)
                        remaining = self._estimate_remaining_time(1, stage_progress, item_index, total_items)
                        self.progress_updated.emit(
                            1, stage_progress, overall_progress,
                            f"[{device_name}] Preparing forensic tool result upload...",
                            remaining,
                        )

                        export_path = (device.metadata or {}).get('file_path')
                        if not export_path or not Path(export_path).is_file():
                            self.log_message.emit(
                                f"[ERROR] [{device_name}] Forensic tool result file is missing or unreadable",
                                True,
                            )
                            continue

                        metadata = dict(device.metadata or {})
                        upload_artifact_type = metadata.get('upload_artifact_type')
                        if upload_artifact_type not in {'axiom_case_db', 'cellebrite_ufdr_xml', 'autopsy_case_db'}:
                            self.log_message.emit(
                                f"[ERROR] [{device_name}] Unsupported or missing tool result type",
                                True,
                            )
                            continue
                        metadata.update({
                            'artifact_type': upload_artifact_type,
                            'upload_artifact_type': upload_artifact_type,
                            'collection_method': metadata.get('collection_method') or f'{upload_artifact_type}_upload',
                            'device_id': device.device_id,
                            'device_name': device_name,
                            'device_type': device.device_type.name,
                            'original_path': metadata.get('original_path') or export_path,
                            'source_tool': metadata.get('source_tool') or 'unknown_third_party_forensic_result',
                            'legal_boundary': metadata.get('legal_boundary') or 'verified_user_selected_forensic_result',
                        })
                        collected_raw_files.append((export_path, upload_artifact_type, metadata))
                        self.file_collected.emit(Path(export_path).name, True)
                        self.log_message.emit(
                            f"[{device_name}] Forensic tool result queued for upload: "
                            f"{Path(export_path).name} ({upload_artifact_type})",
                            False,
                        )
                        continue

                    # Create appropriate collector based on device type
                    collector = self._create_collector_for_device(device, output_dir)
                    if not collector:
                        self.log_message.emit(f"{device_name}: Collector creation failed", True)
                        continue

                    # iOS backup/device collectors keep decryptor resources open until
                    # uploads finish; closing them immediately can invalidate extracted
                    # backup files before the upload worker reads them.
                    close_after_upload = self._is_ios_runtime_collector(collector)
                    if close_after_upload and hasattr(collector, 'close'):
                        _ios_collectors.append(collector)

                    device_artifacts = artifacts_by_device.get(device.device_id, [])
                    if not device_artifacts:
                        self.log_message.emit(
                            f"[SKIP] [{device_name}] No selected artifact types apply to this source.",
                            False,
                        )
                        if hasattr(collector, 'close') and not close_after_upload:
                            collector.close()
                        continue

                    scope_summary = self._collection_scope_summary(device, collector, device_artifacts)
                    self._log_collection_scope(device_name, scope_summary)
                    if not self._validate_collection_scope(device_name, scope_summary):
                        if hasattr(collector, 'close') and not close_after_upload:
                            collector.close()
                        self.finished.emit(False, "Windows disk image baseline artifacts are incomplete")
                        return

                    # Pre-warm reusable filesystem indexes so all artifact types
                    # use cached metadata and the expensive MFT scan is visible as
                    # its own stage instead of being hidden under the first artifact.
                    self._prewarm_collector_index(collector, device_name)

                    for artifact_type in device_artifacts:
                        if self._cancelled:
                            break

                        item_index += 1
                        target_label = self._target_label(item_index, total_items)
                        stage_progress = int((item_index / max(total_items, 1)) * 100)
                        overall_progress = self._calculate_overall_progress(1, stage_progress)
                        remaining = self._estimate_remaining_time(1, stage_progress, item_index, total_items)

                        self.progress_updated.emit(
                            1, stage_progress, overall_progress,
                            f"[{device_name}] Collecting {target_label}...",
                            remaining
                        )

                        is_ios_backup_artifact = False
                        try:
                            # Chunk streaming: process 100 at a time to prevent GUI freeze
                            CHUNK_SIZE = 100
                            file_count = 0
                            error_count = 0
                            artifact_info = ARTIFACT_TYPES.get(artifact_type, {})
                            is_ios_backup_artifact = (
                                artifact_info.get('category') == 'ios'
                                and artifact_type not in {
                                    'mobile_ios_device_info',
                                    'mobile_ios_syslog',
                                    'mobile_ios_crash_logs',
                                    'mobile_ios_installed_apps',
                                    'mobile_ios_device_backup',
                                    'mobile_ios_backup',
                                    'mobile_ios_unified_logs',
                                }
                            )
                            if is_ios_backup_artifact:
                                ios_backup_target_count += 1
                                if ios_backup_blocking_error:
                                    ios_backup_blocked_target_count += 1
                                    continue

                            # iOS backup progress callback
                            def ios_progress_callback(msg: str):
                                # Progress percentage → update progress bar only (no log spam)
                                if "progress:" in msg.lower():
                                    try:
                                        pct = float(msg.split(":")[-1].strip().rstrip("%"))
                                        self.progress_updated.emit(
                                            1, int(pct), self._calculate_overall_progress(1, int(pct)),
                                            f"[{device_name}] {target_label}: {pct:.1f}%",
                                            ""
                                        )
                                    except (ValueError, IndexError):
                                        pass
                                else:
                                    # Non-progress messages (e.g. "Creating iOS backup") → log + status dialog
                                    safe_msg = self._sanitize_collector_status(msg)
                                    self.log_message.emit(f"[{device_name}] {safe_msg}", False)
                                    self.ios_status_update.emit(safe_msg)

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
                                        self.log_message.emit(f"[SKIP] [{device_name}] {target_label}: not present", False)
                                    elif status == 'skipped':
                                        self.log_message.emit(f"[SKIP] [{device_name}] {target_label}: {error_msg}", False)
                                    elif 'Root access required' in error_msg or 'not rooted' in error_msg:
                                        self.log_message.emit(f"[SKIP] [{device_name}] {target_label}: requires root", False)
                                    elif error_msg not in ['Unknown artifact type: ' + artifact_type]:
                                        self.log_message.emit(f"[{device_name}] {target_label}: {error_msg}", True)
                                        if is_ios_backup_artifact and not ios_backup_blocking_error:
                                            blocking_markers = (
                                                'iOS encrypted backup is not enabled',
                                                'Unable to decrypt iOS backup manifest',
                                                'Failed to read iOS backup encryption state',
                                                'Failed to prepare encrypted backup access',
                                            )
                                            if any(marker in error_msg for marker in blocking_markers):
                                                ios_backup_blocking_error = error_msg
                                    error_count += 1
                                    continue

                                collected_path = Path(file_path)
                                if not collected_path.is_file():
                                    self.log_message.emit(
                                        f"[SKIP] [{device_name}] {target_label}: "
                                        f"non-file collection result ignored ({collected_path.name})",
                                        False,
                                    )
                                    error_count += 1
                                    continue

                                # Add device info to metadata
                                metadata['device_id'] = device.device_id
                                metadata['device_name'] = device_name
                                metadata['device_type'] = device.device_type.name
                                upload_artifact_type = metadata.get(
                                    'upload_artifact_type',
                                    artifact_type,
                                )
                                collected_raw_files.append((file_path, upload_artifact_type, metadata))
                                file_count += 1

                                # Rate-limit UI signals to prevent progressive slowdown
                                # (QListWidget.addItem + scrollToBottom with thousands of items)
                                if file_count <= 200 or file_count % CHUNK_SIZE == 0:
                                    self.file_collected.emit(Path(file_path).name, True)

                                # Update progress every 100 items + process GUI events
                                if file_count % CHUNK_SIZE == 0:
                                    self.log_message.emit(f"[{device_name}] {target_label}: {file_count} files queued...", False)

                            if file_count == 0 and error_count == 0:
                                self.log_message.emit(f"[SKIP] [{device_name}] {target_label}: no matching files found", False)
                                if is_ios_backup_artifact:
                                    ios_backup_no_match_count += 1
                            elif file_count > 0:
                                self.log_message.emit(f"[{device_name}] {target_label}: {file_count} files queued for upload", False)
                                if is_ios_backup_artifact:
                                    ios_backup_file_count += file_count
                            elif is_ios_backup_artifact:
                                ios_backup_error_count += error_count

                        except Exception as e:
                            import logging
                            err_str = str(e)
                            if 'Unknown artifact type' in err_str:
                                # Cross-platform artifact sent to wrong collector (e.g. Windows type → Android)
                                # Silently skip — not an error
                                logging.debug(f"Skipped cross-platform artifact: {artifact_type} on {device_name}")
                            else:
                                self.log_message.emit(f"Collection failed [{device_name}] ({target_label}): {e}", True)
                                logging.debug(f"Collection error for {artifact_type} on {device_name}: {e}")
                                if is_ios_backup_artifact:
                                    ios_backup_error_count += 1

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
                    if hasattr(collector, 'close') and not close_after_upload:
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

                    target_label = self._target_label(i + 1, total_artifacts)
                    stage_progress = int(((i + 1) / total_artifacts) * 100)
                    overall_progress = self._calculate_overall_progress(1, stage_progress)
                    remaining = self._estimate_remaining_time(1, stage_progress, i + 1, total_artifacts)

                    self.progress_updated.emit(
                        1, stage_progress, overall_progress,
                        f"Collecting {target_label}...",
                        remaining
                    )
                    self.log_message.emit(f"Collecting {target_label}", False)

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
                            if not file_path or not Path(file_path).is_file():
                                self.log_message.emit(
                                    f"[SKIP] {target_label}: non-file collection result ignored",
                                    False,
                                )
                                continue
                            collected_raw_files.append((file_path, artifact_type, metadata))
                            file_count += 1

                            # Rate-limit UI signals to prevent progressive slowdown
                            if file_count <= 200 or file_count % CHUNK_SIZE == 0:
                                self.file_collected.emit(Path(file_path).name, True)

                            # Update progress every 100 items + process GUI events
                            if file_count % CHUNK_SIZE == 0:
                                self.log_message.emit(f"{target_label}: {file_count} files queued...", False)

                        if file_count == 0:
                            self.log_message.emit(f"[SKIP] {target_label}: no matching files found", False)
                        else:
                            self.log_message.emit(f"{target_label}: {file_count} files queued for upload", False)

                    except Exception as e:
                        import logging
                        self.log_message.emit(f"Collection failed ({target_label}): {e}", True)
                        logging.debug(f"Collection error for {artifact_type}: {e}")

                # Release scan cache after all artifact types collected
                if hasattr(collector, 'release_scan_cache'):
                    collector.release_scan_cache()

            if self._cancelled:
                self.finished.emit(False, "Collection cancelled")
                return

            ios_quality_error = ""
            if ios_backup_blocking_error:
                ios_quality_error = (
                    "iOS backup extraction was not started: "
                    f"{ios_backup_blocking_error}"
                )
                if ios_backup_blocked_target_count:
                    self.log_message.emit(
                        f"[SKIP] {ios_backup_blocked_target_count} iOS backup target(s) skipped "
                        "after the blocking backup error.",
                        False,
                    )
                self.log_message.emit(f"[WARNING] {ios_quality_error}", True)
            elif ios_backup_target_count > 0 and ios_backup_file_count == 0:
                ios_quality_error = (
                    "iOS backup extraction produced 0 app/artifact files "
                    f"from {ios_backup_target_count} selected backup target(s). "
                    "Only device metadata may have been collected. "
                    "Check manifest_diagnostic.txt and verify that the encrypted "
                    "backup Manifest.db was decrypted and that target apps have "
                    "backup data on this device."
                )
                self.log_message.emit(f"[WARNING] {ios_quality_error}", True)
            elif ios_backup_no_match_count > 0:
                self.log_message.emit(
                    "[WARNING] "
                    f"{ios_backup_no_match_count} iOS backup target(s) had no matching files; "
                    "check manifest_diagnostic.txt for APP_MISSING or PATH_ERR details.",
                    True,
                )

            # ========================================
            # STAGE 2: Prepare metadata (30%)
            # ========================================
            self.log_message.emit(f"🔐 Preparing {len(collected_raw_files)} files for upload...", False)
            encrypted_files = []  # (file_path, artifact_type, metadata)
            total_files = len(collected_raw_files)
            preparation_error_count = 0
            prepared_results = []
            prepare_workers = self._tuning_int(
                'prepare_workers', 'COLLECTOR_PREPARE_WORKERS', 2, 1, 8
            )
            prepare_start = time.perf_counter()
            prepare_hash_ms = 0
            prepare_copy_ms = 0
            prepare_bytes = 0

            if total_files:
                from concurrent.futures import ThreadPoolExecutor, as_completed

                max_prepare_workers = min(prepare_workers, total_files)
                self.log_message.emit(
                    f"Preparation concurrency: {max_prepare_workers} worker(s)",
                    False,
                )

                with ThreadPoolExecutor(max_workers=max_prepare_workers) as executor:
                    futures = {}
                    for j, (file_path, artifact_type, metadata) in enumerate(collected_raw_files):
                        if self._cancelled:
                            break
                        future = executor.submit(
                            self._prepare_upload_item,
                            output_dir,
                            (j, file_path, artifact_type, metadata),
                        )
                        futures[future] = j

                    completed_prepare = 0
                    for future in as_completed(futures):
                        completed_prepare += 1
                        result = future.result()
                        filename = result.get('filename') or 'Unknown'
                        stage_progress = int((completed_prepare / max(total_files, 1)) * 100)
                        overall_progress = self._calculate_overall_progress(2, stage_progress)
                        remaining = self._estimate_remaining_time(
                            2, stage_progress, completed_prepare, total_files
                        )

                        self.progress_updated.emit(
                            2, stage_progress, overall_progress,
                            f"Preparing: {filename}",
                            remaining
                        )

                        if result.get('ok'):
                            timings = result.get('timings') or {}
                            prepare_hash_ms += int(timings.get('hash_ms') or 0)
                            prepare_copy_ms += int(timings.get('stable_copy_ms') or 0)
                            prepare_bytes += int(result.get('file_size') or 0)
                            prepared_results.append(result)
                        elif result.get('skipped'):
                            self.log_message.emit(str(result.get('message') or 'Preparation skipped'), False)
                        else:
                            preparation_error_count += 1
                            self.log_message.emit(str(result.get('error') or 'Preparation failed'), True)

                        if self._cancelled:
                            for pending in futures:
                                pending.cancel()
                            break

                prepared_results.sort(key=lambda item: int(item.get('index') or 0))
                encrypted_files = [
                    (item['file_path'], item['artifact_type'], item['metadata'])
                    for item in prepared_results
                ]

            prepare_elapsed_ms = int((time.perf_counter() - prepare_start) * 1000)
            if total_files:
                self.log_message.emit(
                    "Preparation timing: "
                    f"files={len(encrypted_files)}/{total_files}, "
                    f"bytes={prepare_bytes:,}, "
                    f"hash_total={prepare_hash_ms}ms, "
                    f"stable_copy_total={prepare_copy_ms}ms, "
                    f"elapsed={prepare_elapsed_ms}ms",
                    False,
                )

            if self._cancelled:
                self.finished.emit(False, "Preparation cancelled")
                return

            if preparation_error_count:
                self.log_message.emit(
                    f"[ERROR] Preparation failed for {preparation_error_count} file(s); "
                    "analysis will not be started.",
                    True,
                )

            # ========================================
            # STAGE 3: Upload (40%)
            # ========================================
            self.log_message.emit(f"☁️ Uploading {len(encrypted_files)} files...", False)

            # Upload policy is centralized so production can default to
            # direct-to-R2 while operators can force server streaming when
            # R2 is unavailable or during local validation.
            uploader = build_collector_uploader(
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
            self.log_message.emit(
                "Upload mode: "
                f"{getattr(uploader, 'collector_upload_mode', 'unknown')} "
                f"(fallback={getattr(uploader, 'collector_fallback_enabled', False)})",
                False,
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
                        self.log_message.emit(f"Upload | Status: Success | File: {filename}", False)
                        if getattr(uploader, 'upload_timing_enabled', False) and result.metrics:
                            metrics = result.metrics
                            self.log_message.emit(
                                "Upload | Status: Timing | "
                                f"File: {filename} | "
                                f"Duration: {metrics.get('total_ms', 0)} ms",
                                False,
                            )
                    else:
                        message = result.error or "The upload could not be completed. Please try again."
                        if result.error and ("CANCELLED" in result.error or "cancelled" in result.error.lower()):
                            self.log_message.emit(
                                f"Upload | Status: Stopped | File: {filename} | Message: The collection was cancelled from the web platform.",
                                True,
                            )
                            self._cancelled = True
                        elif result.error and "CLEANUP_IN_PROGRESS" in result.error:
                            self.log_message.emit(
                                f"Upload | Status: Waiting | File: {filename} | Message: Previous data cleanup is still running. Please try again shortly.",
                                True,
                            )
                            self._cancelled = True
                        else:
                            self.log_message.emit(
                                f"Upload | Status: Failed | File: {filename} | Message: {message}",
                                True,
                            )

                return result

            max_workers = min(uploader.upload_workers, max(total_upload, 1))
            if total_upload == 0:
                self.log_message.emit(
                    "No files were collected. Verify the selected evidence source, "
                    "authorized targets, and filesystem support before retrying.",
                    True,
                )
                self.progress_updated.emit(3, 0, self._calculate_overall_progress(3, 0), "No files queued for upload", "")
                self.finished.emit(False, "No files were collected; nothing was uploaded or queued for analysis.")
                return

            self.log_message.emit(f"Upload concurrency: {max_workers} worker(s)", False)

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

            upload_batch_ok = self._upload_batch_ready_for_completion(
                total_upload=total_upload,
                success_count=success_count,
                preparation_error_count=preparation_error_count,
                ios_quality_error=ios_quality_error,
            )
            self._upload_batch_complete = upload_batch_ok
            completion_signal_ok = False

            # === Send upload completion signal (pipeline state transition trigger) ===
            if upload_batch_ok:
                try:
                    self._completion_signal_in_flight = True
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
                        completion_signal_ok = True
                        self._server_completion_accepted = True
                        self.log_message.emit("✓ Collection session completion signal sent", False)
                    else:
                        self.log_message.emit(f"⚠ Session completion signal failed: {complete_response.status_code}", True)
                except Exception as e:
                    self.log_message.emit(f"⚠ Session completion signal error: {e}", True)
                finally:
                    self._completion_signal_in_flight = False
            elif success_count > 0:
                self.log_message.emit(
                    "Collection completion signal was not sent because the upload batch "
                    "was incomplete or failed quality checks.",
                    True,
                )

            completed_ok = upload_batch_ok and completion_signal_ok

            self.progress_updated.emit(3, 100, 100, "Complete!" if completed_ok else "Completed with warnings", "")
            final_message = (
                f"Collection complete: {success_count}/{total_upload} files uploaded "
                f"(elapsed: {elapsed_str})"
            )
            if ios_quality_error:
                final_message = f"{final_message}; {ios_quality_error}"
            elif preparation_error_count:
                final_message = (
                    f"{final_message}; preparation failed for "
                    f"{preparation_error_count} file(s)"
                )
            elif success_count != total_upload:
                final_message = f"{final_message}; one or more uploads failed"
            elif upload_batch_ok and not completion_signal_ok:
                final_message = f"{final_message}; session completion signal failed"
            self.finished.emit(
                completed_ok,
                final_message
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
