# -*- coding: utf-8 -*-
"""
Device List Panel

Displays detected devices and mobile connection status with
beginner-friendly setup guidance.
"""

import sys
from typing import Dict, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QCheckBox, QLabel, QPushButton, QFileDialog,
    QProgressDialog
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread

from core.device_manager import (
    UnifiedDeviceManager,
    UnifiedDeviceInfo,
    DeviceType,
)
from core.device_enumerators import diagnose_device_prerequisites
from gui.styles import COLORS


class _BundleRegistrationWorker(QThread):
    """Run device_manager.add_bundle_file off the GUI thread.

    A 30-50 GB Cellebrite zip's central directory + msgpack metadata
    parse takes ~10s; running it on the GUI thread freezes the window.
    """
    finished_with_device = pyqtSignal(object, str)  # (device|None, error_msg)

    def __init__(self, device_manager: UnifiedDeviceManager, file_path: str,
                 parent=None):
        super().__init__(parent)
        self._device_manager = device_manager
        self._file_path = file_path

    def run(self):
        try:
            device = self._device_manager.add_bundle_file(self._file_path)
            self.finished_with_device.emit(device, "")
        except Exception as e:
            self.finished_with_device.emit(None, str(e))


class DeviceListPanel(QWidget):
    """
    Device list panel with mobile connection guide.
    """

    selection_changed = pyqtSignal()
    image_file_requested = pyqtSignal()

    def __init__(self, device_manager: UnifiedDeviceManager, parent=None):
        super().__init__(parent)
        self.device_manager = device_manager
        self.device_checkboxes: Dict[str, QCheckBox] = {}
        self._interaction_locked = False
        self._file_actions_visible = True
        self.setAcceptDrops(True)
        self._setup_ui()
        self._connect_signals()

    def set_interaction_locked(self, locked: bool):
        """Disable source changes while collection or upload is running."""
        self._interaction_locked = bool(locked)
        self.refresh_btn.setEnabled(not locked)
        self.add_btn.setEnabled(not locked)
        if hasattr(self, 'add_export_btn'):
            self.add_export_btn.setEnabled(not locked)
        self.setAcceptDrops(not locked)
        for device_id, cb in self.device_checkboxes.items():
            device = self.device_manager.get_device(device_id)
            cb.setEnabled(False if locked else bool(device and device.is_selectable))

    def set_file_action_buttons_visible(self, visible: bool):
        """Show or hide file/action buttons when a parent UI provides them."""
        self._file_actions_visible = bool(visible)
        self.add_btn.setVisible(visible)
        if hasattr(self, 'add_export_btn'):
            self.add_export_btn.setVisible(visible)
        if hasattr(self, 'evidence_hint'):
            self.evidence_hint.setVisible(visible)
        self._update_mobile_guide()

    def _setup_ui(self):
        """Setup UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Header row
        header = QHBoxLayout()
        header.setSpacing(4)
        header.setContentsMargins(0, 0, 0, 0)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setFixedHeight(24)
        self.refresh_btn.clicked.connect(self._on_refresh_clicked)
        header.addWidget(self.refresh_btn)

        self.add_btn = QPushButton("+ Add Disk Image / FFS")
        self.add_btn.setFixedHeight(24)
        self.add_btn.setObjectName("addEvidenceButton")
        self.add_btn.setStyleSheet(f"""
            QPushButton#addEvidenceButton {{
                background-color: {COLORS['bg_elevated']};
                border: 1px solid {COLORS['brand_primary']};
                border-radius: 4px;
                color: {COLORS['brand_accent']};
                font-weight: 700;
                padding: 4px 12px;
            }}
            QPushButton#addEvidenceButton:hover {{
                background-color: rgba(212, 165, 116, 0.16);
                border-color: {COLORS['brand_accent']};
                color: {COLORS['text_primary']};
            }}
            QPushButton#addEvidenceButton:pressed {{
                background-color: rgba(212, 165, 116, 0.24);
                border-color: {COLORS['brand_secondary']};
            }}
        """)
        self.add_btn.clicked.connect(self._on_add_image_clicked)
        header.addWidget(self.add_btn)

        self.add_export_btn = QPushButton("+ Add Tool Result")
        self.add_export_btn.setFixedHeight(24)
        self.add_export_btn.setObjectName("addToolExportButton")
        self.add_export_btn.setStyleSheet(f"""
            QPushButton#addToolExportButton {{
                background-color: {COLORS['bg_elevated']};
                border: 1px solid {COLORS['border_muted']};
                border-radius: 4px;
                color: {COLORS['text_primary']};
                font-weight: 700;
                padding: 4px 12px;
            }}
            QPushButton#addToolExportButton:hover {{
                background-color: rgba(88, 166, 255, 0.12);
                border-color: {COLORS['brand_accent']};
            }}
            QPushButton#addToolExportButton:pressed {{
                background-color: rgba(88, 166, 255, 0.2);
            }}
        """)
        self.add_export_btn.clicked.connect(self._on_add_export_clicked)
        header.addWidget(self.add_export_btn)

        header.addStretch()

        self.summary_label = QLabel("0 selected")
        self.summary_label.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 10px;"
        )
        header.addWidget(self.summary_label)

        layout.addLayout(header)

        self.evidence_hint = QLabel(
            "Add E01/RAW/VDI/VMDK/VHD/DMG/QCOW2, a mobile FFS ZIP/CLBX, "
            "or a verified tool result: AXIOM DB, Cellebrite UFDR/XML, or Autopsy autopsy.db. "
            "Ordinary ZIP, ISO, and memory dump files are not disk-image sources; "
            "generic DB, JSON, CSV, and TSV exports are not enabled until validated."
        )
        self.evidence_hint.setWordWrap(True)
        self.evidence_hint.setStyleSheet(
            f"color: {COLORS['text_tertiary']}; font-size: 9px;"
        )
        layout.addWidget(self.evidence_hint)

        # Device list (no scroll — typically 1-5 items)
        self.devices_container = QWidget()
        self.devices_layout = QVBoxLayout(self.devices_container)
        self.devices_layout.setContentsMargins(0, 0, 0, 0)
        self.devices_layout.setSpacing(2)
        layout.addWidget(self.devices_container)

        # Mobile connection guide (always visible)
        self.mobile_guide = QLabel()
        self.mobile_guide.setWordWrap(True)
        self.mobile_guide.setTextFormat(Qt.TextFormat.RichText)
        self.mobile_guide.setOpenExternalLinks(False)
        self.mobile_guide.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 9px; "
            f"background: {COLORS['bg_tertiary']}; "
            f"border: 1px solid {COLORS['border_subtle']}; "
            f"border-radius: 4px; padding: 6px;"
        )
        self._update_mobile_guide()
        layout.addWidget(self.mobile_guide)

    def _connect_signals(self):
        """Connect signals"""
        self.device_manager.device_added.connect(self._on_device_added)
        self.device_manager.device_removed.connect(self._on_device_removed)
        self.device_manager.device_updated.connect(self._on_device_updated)

    # =========================================================================
    # Mobile Connection Guide
    # =========================================================================

    def _update_mobile_guide(self):
        """Build beginner-friendly mobile connection guide."""
        try:
            diag = diagnose_device_prerequisites()
        except Exception:
            diag = {
                'ios': {'driver_installed': False, 'library_available': False},
                'android': {'adb_available': False},
            }

        has_ios = any(
            did.startswith('ios_') for did in self.device_checkboxes
        )
        android_devices = [
            self.device_manager.get_device(did)
            for did in self.device_checkboxes
            if did.startswith('android_')
        ]
        android_devices = [d for d in android_devices if d]
        has_android = bool(android_devices)
        has_authorized_android = any(
            d.metadata.get('usb_debugging') for d in android_devices
        )

        ok = COLORS['success']       # #3fb950
        warn = COLORS['warning']     # #d29922
        err = COLORS['error']        # #f85149
        dim = COLORS['text_tertiary']

        sections = []

        # --- iOS ---
        ios = diag['ios']
        if has_ios:
            sections.append(
                f"<span style='color:{ok};'>● iOS — Connected</span>"
            )
        elif not ios['driver_installed']:
            steps = self._ios_install_steps()
            sections.append(
                f"<span style='color:{err};'>● iOS — Setup Required</span>"
                f"<br><span style='color:{dim};'>{steps}</span>"
            )
        elif not ios['library_available']:
            sections.append(
                f"<span style='color:{err};'>● iOS — Library Unavailable</span>"
                f"<br><span style='color:{dim};'>"
                "Reinstall the collector or run: pip install pymobiledevice3"
                "</span>"
            )
        else:
            sections.append(
                f"<span style='color:{warn};'>● iOS — Ready</span>"
                f"<br><span style='color:{dim};'>"
                "1. Connect iPhone/iPad via USB cable<br>"
                "2. Unlock the device<br>"
                '3. Tap <b>"Trust"</b> when prompted on the device screen'
                "</span>"
            )

        # --- Android ---
        adb = diag['android']
        if has_authorized_android:
            sections.append(
                f"<span style='color:{ok};'>● Android — Connected</span>"
            )
        elif has_android:
            sections.append(
                f"<span style='color:{warn};'>Android authorization required</span>"
                f"<br><span style='color:{dim};'>"
                "Unlock the Android device, tap <b>Allow USB Debugging</b>, "
                "then click <b>Refresh</b>. Collection starts only after ADB "
                "shell access is authorized."
                "</span>"
            )
        elif not adb['adb_available']:
            sections.append(
                f"<span style='color:{err};'>● Android — Setup Required</span>"
                f"<br><span style='color:{dim};'>"
                "On the Android device:<br>"
                "1. <b>Settings</b> > <b>About Phone</b> > "
                "tap <b>Build Number</b> 7 times<br>"
                "2. <b>Settings</b> > <b>Developer Options</b> > "
                "enable <b>USB Debugging</b><br>"
                "3. Connect via USB and tap <b>Allow</b> on the device"
                "</span>"
            )
        else:
            sections.append(
                f"<span style='color:{warn};'>● Android — Ready</span>"
                f"<br><span style='color:{dim};'>"
                "1. Connect the device via USB cable<br>"
                '2. Tap <b>"Allow USB Debugging"</b> on the device screen'
                "</span>"
            )

        if not self._file_actions_visible:
            hint = (
                "E01/RAW/FFS: use <b>Add Evidence File</b> above; "
                "AXIOM/Cellebrite/Autopsy: use <b>Add Tool Result</b> above"
            )
            sections.append(f"<span style='color:{dim};'>{hint}</span>")
            self.mobile_guide.setText("<br>".join(sections))
            return

        # --- E01/RAW hint ---
        sections.append(
            f"<span style='color:{dim};'>"
            "● <b>E01/RAW</b>: Use <b>+ Add Disk Image / FFS</b>; "
            "<b>AXIOM/Cellebrite/Autopsy</b>: use <b>+ Add Tool Result</b>"
            "</span>"
        )

        self.mobile_guide.setText(
            "<br>".join(sections)
        )

    @staticmethod
    def _ios_install_steps() -> str:
        """Return iOS driver install steps based on OS."""
        if sys.platform == 'win32':
            return (
                "iTunes is required for iOS connection:<br>"
                "1. Open <b>Microsoft Store</b> and search "
                "<b>\"Apple Devices\"</b><br>"
                "2. Install and restart this collector<br>"
                "3. Connect iPhone/iPad via USB cable<br>"
                '4. Tap <b>"Trust"</b> on the device screen'
            )
        elif sys.platform == 'darwin':
            return (
                "On macOS 10.15+, iOS support is built-in.<br>"
                "1. Connect iPhone/iPad via USB cable<br>"
                '2. Tap <b>"Trust"</b> on the device screen<br>'
                "If not detected: install Xcode Command Line Tools"
            )
        else:
            return (
                "Install required packages:<br>"
                "1. <b>sudo apt install libimobiledevice-utils "
                "usbmuxd</b><br>"
                "2. <b>sudo systemctl start usbmuxd</b><br>"
                "3. Connect iPhone/iPad via USB cable<br>"
                '4. Tap <b>"Trust"</b> on the device screen'
            )

    # =========================================================================
    # Device Events
    # =========================================================================

    def _on_device_added(self, device: UnifiedDeviceInfo):
        """Device added"""
        if device.device_id in self.device_checkboxes:
            return

        cb = QCheckBox(self._get_device_label(device))
        cb.setChecked(device.is_selected)
        cb.setEnabled(device.is_selectable and not self._interaction_locked)
        cb.setProperty("device_id", device.device_id)
        cb.stateChanged.connect(
            lambda state, d=device.device_id: self._on_checkbox_changed(d, state)
        )
        cb.setToolTip(self._get_device_tooltip(device))

        self.device_checkboxes[device.device_id] = cb
        self.devices_layout.addWidget(cb)
        self._update_summary()
        self._update_mobile_guide()

    def _on_device_removed(self, device_id: str):
        """Device removed"""
        if device_id in self.device_checkboxes:
            cb = self.device_checkboxes.pop(device_id)
            self.devices_layout.removeWidget(cb)
            cb.deleteLater()
            self._update_summary()
            self._update_mobile_guide()

    def _on_device_updated(self, device: UnifiedDeviceInfo):
        """Device updated"""
        if device.device_id in self.device_checkboxes:
            cb = self.device_checkboxes[device.device_id]
            was_checked = cb.isChecked()
            cb.setText(self._get_device_label(device))
            cb.setToolTip(self._get_device_tooltip(device))
            cb.setEnabled(device.is_selectable and not self._interaction_locked)
            cb.blockSignals(True)
            cb.setChecked(device.is_selected)
            cb.blockSignals(False)
            self._update_summary()
            self._update_mobile_guide()
            if was_checked != device.is_selected:
                self.selection_changed.emit()

    def _on_checkbox_changed(self, device_id: str, state: int):
        """Checkbox changed"""
        if self._interaction_locked:
            return
        selected = state == Qt.CheckState.Checked.value
        self.device_manager.select_device(device_id, selected)
        self._update_summary()
        self.selection_changed.emit()

    def _on_refresh_clicked(self):
        """Refresh"""
        if self._interaction_locked:
            return
        self.device_manager.refresh()
        self._update_mobile_guide()

    def request_add_evidence_file(self):
        """Open the existing disk image / mobile FFS registration flow."""
        self._on_add_image_clicked()

    def request_add_tool_result(self):
        """Open the existing verified tool-result registration flow."""
        self._on_add_export_clicked()

    def _on_add_image_clicked(self):
        """Add image or mobile FFS bundle"""
        if self._interaction_locked:
            return
        file_path, selected_filter = QFileDialog.getOpenFileName(
            self,
            "Select Disk Image or Mobile FFS Bundle",
            "",
            "Forensic Images (*.E01 *.e01 *.Ex01 *.ex01 *.L01 *.l01 *.Lx01 *.lx01 *.S01 *.s01 *.dd *.raw *.img *.bin *.000 *.001 *.vmdk *.vhd *.vhdx *.qcow2 *.vdi *.dmg *.DMG *.ntfs *.fat *.fat12 *.fat16 *.fat32 *.exfat *.ext *.ext2 *.ext3 *.ext4 *.xfs *.btrfs *.hfs *.hfsx *.apfs *.ufs)"
            ";;Mobile FFS Bundle (*.zip *.clbx)"
            ";;All Files (*)"
        )
        if not file_path:
            return

        self._register_evidence_file(file_path)

    def _on_add_axiom_clicked(self):
        """Add Magnet AXIOM case result database."""
        if self._interaction_locked:
            return
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Magnet AXIOM Result Database",
            "",
            "Magnet AXIOM Result DB (*.mfdb *.db *.sqlite *.sqlite3);;All Files (*)"
        )
        if not file_path:
            return

        self._register_axiom_db_file(file_path)


    def _on_add_export_clicked(self):
        """Add a verified third-party forensic result file."""
        if self._interaction_locked:
            return
        file_path, selected_filter = QFileDialog.getOpenFileName(
            self,
            "Select Verified Tool Result",
            "",
            "Magnet AXIOM Result DB (*.mfdb *.db *.sqlite *.sqlite3);;Cellebrite UFDR (*.ufdr);;Cellebrite XML Report (*.xml);;Autopsy Case DB (*.db *.sqlite *.sqlite3);;All Files (*)"
        )
        if not file_path:
            return

        self._register_third_party_export_file(
            file_path,
            self._artifact_type_from_tool_result_filter(selected_filter, file_path),
        )

    def _register_evidence_file(self, file_path: str):
        """Register a supported image or mobile FFS bundle."""
        if self._interaction_locked:
            return
        if not self._is_supported_evidence_file(file_path):
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(
                self,
                "Unsupported Evidence Source",
                self._unsupported_file_message(file_path),
            )
            return
        is_mobile_bundle = file_path.lower().endswith((".zip", ".clbx"))
        if is_mobile_bundle:
            self._register_ffs_bundle(file_path)
        else:
            device = self.device_manager.add_image_file(file_path)
            if device:
                self._select_registered_device(device)
                self.image_file_requested.emit()
            else:
                from PyQt6.QtWidgets import QMessageBox
                QMessageBox.warning(
                    self,
                    "Evidence Registration Failed",
                    "Could not register this evidence source. Verify that the "
                    "file exists and is a supported disk image or filesystem "
                    "volume image.",
                )

    def _register_axiom_db_file(self, file_path: str):
        """Register a Magnet AXIOM result DB for direct upload."""
        if self._interaction_locked:
            return
        device = self.device_manager.add_axiom_case_db_file(file_path)
        if device:
            self._select_registered_device(device)
            self.image_file_requested.emit()
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(
                self,
                "AXIOM DB Registered",
                f"<b>{device.display_name}</b><br><br>"
                f"<b>Size</b>: {device.size_display}<br>"
                "This database will be uploaded as one AXIOM evidence source. "
                "Server parsing will expand AXIOM hits into searchable documents.",
            )
        else:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(
                self,
                "AXIOM DB Registration Failed",
                "Could not register this AXIOM result database. Verify that the "
                "file exists, is readable, and is a SQLite-based AXIOM result DB.",
            )


    def _register_third_party_export_file(self, file_path: str, artifact_type: str = None):
        """Register a verified third-party forensic result for direct upload."""
        if self._interaction_locked:
            return
        device = self.device_manager.add_third_party_forensic_export_file(file_path, artifact_type)
        if device:
            self._select_registered_device(device)
            self.image_file_requested.emit()
            from PyQt6.QtWidgets import QMessageBox
            upload_type = device.metadata.get('upload_artifact_type') or 'verified_tool_result'
            QMessageBox.information(
                self,
                "Tool Result Registered",
                f"<b>{device.display_name}</b><br><br>"
                f"<b>Upload type</b>: {upload_type}<br>"
                f"<b>Size</b>: {device.size_display}<br>"
                "This user-selected forensic result will be uploaded as one source. "
                "Server parsing will normalize supported records into searchable documents.",
            )
        else:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(
                self,
                "Tool Result Registration Failed",
                "Could not register this forensic tool result. Only verified AXIOM DB, "
                "Cellebrite UFDR/XML, and Autopsy autopsy.db files are enabled. "
                "Generic XML/JSON/CSV/TSV exports are intentionally unsupported until validated.",
            )

    @staticmethod
    def _artifact_type_from_tool_result_filter(selected_filter: str, file_path: str) -> str:
        text = (selected_filter or '').lower()
        lower_path = (file_path or '').lower()
        if 'axiom' in text or 'magnet' in text:
            return 'axiom_case_db'
        if 'cellebrite' in text:
            return 'cellebrite_ufdr_xml'
        if 'autopsy' in text:
            return 'autopsy_case_db'
        if lower_path.endswith('.mfdb') or 'axiom' in lower_path:
            return 'axiom_case_db'
        if lower_path.endswith('.ufdr') or 'cellebrite' in lower_path or 'ufdr' in lower_path:
            return 'cellebrite_ufdr_xml'
        if lower_path.endswith(('autopsy.db', '/autopsy.db', '\\autopsy.db')) or 'autopsy' in lower_path:
            return 'autopsy_case_db'
        return None

    def dragEnterEvent(self, event):
        """Accept supported evidence files dropped onto the source panel."""
        if self._interaction_locked:
            event.ignore()
            return
        if self._event_has_supported_file(event):
            event.acceptProposedAction()
            return
        event.ignore()

    def dropEvent(self, event):
        """Register a dropped evidence file."""
        if self._interaction_locked:
            event.ignore()
            return
        urls = event.mimeData().urls()
        if not urls:
            event.ignore()
            return
        file_path = urls[0].toLocalFile()
        if not self._is_supported_evidence_file(file_path):
            event.ignore()
            return
        self._register_evidence_file(file_path)
        event.acceptProposedAction()

    def _event_has_supported_file(self, event) -> bool:
        urls = event.mimeData().urls() if event.mimeData().hasUrls() else []
        return bool(urls and self._is_supported_evidence_file(urls[0].toLocalFile()))

    @staticmethod
    def _is_supported_evidence_file(file_path: str) -> bool:
        lower = file_path.lower()
        suffixes = (
            ".e01", ".ex01", ".l01", ".lx01", ".s01",
            ".dd", ".raw", ".img", ".bin", ".000", ".001",
            ".vmdk", ".vhd", ".vhdx", ".qcow2", ".vdi", ".dmg",
            ".ntfs", ".fat", ".fat12", ".fat16", ".fat32", ".exfat",
            ".ext", ".ext2", ".ext3", ".ext4", ".xfs", ".btrfs",
            ".hfs", ".hfsx", ".apfs", ".ufs", ".zip", ".clbx",
        )
        return lower.endswith(suffixes)

    @staticmethod
    def _unsupported_file_message(file_path: str) -> str:
        lower = file_path.lower()
        if lower.endswith((".iso", ".cdr", ".udf")):
            return (
                "Optical disc images are not supported by this collector build.\n\n"
                "Use E01/RAW/VMDK/VHD/VHDX/QCOW2/VDI/DMG, filesystem volume "
                "images, or a supported mobile FFS bundle."
            )
        if lower.endswith((".mem", ".vmem", ".dmp", ".dump", ".mdmp")):
            return (
                "Memory dump files are not supported as evidence sources; "
                "memory dump files are not disk-image sources in this collector "
                "screen.\n\n"
                "Use a disk image, a filesystem volume image, or a supported "
                "mobile FFS bundle."
            )
        if lower.endswith((".db", ".sqlite", ".sqlite3", ".mfdb")):
            return (
                "Database files are not disk-image sources in this collector screen.\n\n"
                "Use + Add Tool Result and choose Magnet AXIOM Result DB or Autopsy Case DB."
            )
        if lower.endswith(".zip"):
            return (
                "Only Cellebrite UFED/CLBX mobile FFS ZIP bundles are supported "
                "directly.\n\n"
                "For a normal ZIP archive that contains E01/RAW images, extract "
                "the archive first and add the first image segment, such as .E01."
            )
        return (
            "This file type is not supported as an evidence source.\n\n"
            "Supported disk sources: E01/RAW/VMDK/VHD/VHDX/QCOW2/VDI/DMG "
            "and filesystem volume images. Supported mobile source: Cellebrite "
            "UFED/CLBX FFS ZIP. For verified forensic tool results, use + Add Tool Result."
        )

    def _register_ffs_bundle(self, file_path: str) -> None:
        """Register a mobile FFS bundle off the GUI thread (large zip
        central-directory + metadata parse can take 10-30 seconds)."""
        progress = QProgressDialog(
            "Analyzing bundle...\n"
            "(Reading central directory and metadata; large extractions "
            "may take 10-30 seconds.)",
            None, 0, 0, self,
        )
        progress.setWindowTitle("Mobile FFS Bundle")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setCancelButton(None)
        progress.setMinimumDuration(0)

        worker = _BundleRegistrationWorker(self.device_manager, file_path, self)
        self._bundle_worker: Optional[_BundleRegistrationWorker] = worker

        def _on_done(device, error_msg: str):
            progress.close()
            self._bundle_worker = None
            self._show_bundle_registration_result(device, error_msg)

        worker.finished_with_device.connect(_on_done)
        worker.start()
        progress.exec()

    def _show_bundle_registration_result(self,
                                         device: Optional[UnifiedDeviceInfo],
                                         error_msg: str) -> None:
        from PyQt6.QtWidgets import QMessageBox
        if error_msg:
            body = error_msg
            if "GENERIC_ZIP" in error_msg or "Unsupported bundle format" in error_msg:
                body = (
                    "The selected ZIP is not a recognised mobile FFS bundle.\n\n"
                    "Only Cellebrite UFED/CLBX iOS or Android FFS ZIP bundles "
                    "are supported directly. If this ZIP contains E01/RAW disk "
                    "images, extract it first and add the first image segment."
                )
            QMessageBox.warning(
                self, "Bundle Registration Failed",
                f"Could not register bundle:\n{body}"
            )
            return
        if not device:
            QMessageBox.warning(
                self, "Bundle Registration Failed",
                "The selected file is not a recognised mobile FFS bundle.\n\n"
                "Supported: Cellebrite UFED CLBX (iOS / Android)."
            )
            return
        meta = device.metadata
        signals = "\n".join(f"  - {s}" for s in meta.get("signals_fired", []))
        present = meta.get("present_artifacts") or []
        scan_complete = meta.get("present_artifact_scan_complete", bool(present))
        if scan_complete:
            present_text = f"<b>Present artifact types</b>: {len(present)}<br>"
        else:
            present_text = (
                "<b>Present artifact scan</b>: unavailable; "
                "using path-spec support<br>"
            )
        body = (
            f"<b>{device.display_name}</b><br><br>"
            f"<b>Format</b>: {meta.get('format_id', '')}<br>"
            f"<b>Publisher</b>: {meta.get('publisher_software') or 'unknown'}<br>"
            f"<b>Confidence</b>: {meta.get('confidence', '')}<br>"
            f"<b>Size</b>: {device.size_display}<br>"
            f"{present_text}"
            f"<br><b>Detection signals</b>:<br><pre>{signals}</pre>"
        )
        QMessageBox.information(self, "Bundle Registered", body)
        self._select_registered_device(device)
        self.image_file_requested.emit()

    def _select_registered_device(self, device: UnifiedDeviceInfo):
        """Select a user-added source and mirror that state in the checkbox."""
        self.device_manager.select_device(device.device_id, True)
        cb = self.device_checkboxes.get(device.device_id)
        if cb is not None and not cb.isChecked():
            cb.blockSignals(True)
            cb.setChecked(True)
            cb.blockSignals(False)
        self._update_summary()
        self.selection_changed.emit()

    # =========================================================================
    # Display Helpers
    # =========================================================================

    def _update_summary(self):
        """Update selection summary"""
        count = sum(1 for cb in self.device_checkboxes.values() if cb.isChecked())
        total = len(self.device_checkboxes)
        self.summary_label.setText(f"{count}/{total} selected")

    def _get_device_label(self, device: UnifiedDeviceInfo) -> str:
        """Device display label"""
        type_icons = {
            DeviceType.WINDOWS_PHYSICAL_DISK: "💿",
            DeviceType.MACOS_LOCAL_SYSTEM: "🖥",
            DeviceType.LINUX_LOCAL_SYSTEM: "🖥",
            DeviceType.E01_IMAGE: "📀",
            DeviceType.RAW_IMAGE: "📀",
            DeviceType.VMDK_IMAGE: "📀",
            DeviceType.VHD_IMAGE: "📀",
            DeviceType.VHDX_IMAGE: "📀",
            DeviceType.QCOW2_IMAGE: "📀",
            DeviceType.VDI_IMAGE: "📀",
            DeviceType.DMG_IMAGE: "🍎",
            DeviceType.ANDROID_DEVICE: "📱",
            DeviceType.IOS_BACKUP: "🍎",
            DeviceType.IOS_DEVICE: "📲",
            DeviceType.AXIOM_CASE_DB: "🗄",
            DeviceType.THIRD_PARTY_FORENSIC_EXPORT: "📄",
        }
        icon = type_icons.get(device.device_type, "📁")
        label = device.display_name

        if device.device_type == DeviceType.WINDOWS_PHYSICAL_DISK:
            all_volumes = device.metadata.get('all_volumes', [])
            if all_volumes:
                volumes_str = ', '.join(f"{v}:" for v in all_volumes)
                label = f"{label} [{volumes_str}]"

        if device.device_type in (DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE,
                                        DeviceType.VMDK_IMAGE, DeviceType.VHD_IMAGE,
                                        DeviceType.VHDX_IMAGE, DeviceType.QCOW2_IMAGE,
                                        DeviceType.VDI_IMAGE):
            detected_os = device.metadata.get('detected_os', 'unknown')
            fs_type = device.metadata.get('filesystem_type', 'Unknown')
            os_labels = {
                'windows': 'Win', 'linux': 'Linux', 'macos': 'macOS'
            }
            os_tag = os_labels.get(detected_os)
            if os_tag:
                label = f"{label} [{os_tag}/{fs_type}]"
            elif detected_os != 'unknown':
                label = f"{label} [{detected_os}/{fs_type}]"

        if device.device_type == DeviceType.ANDROID_DEVICE:
            android_ver = device.metadata.get('android_version', '')
            sdk = device.metadata.get('sdk_version', 0)
            rooted = device.metadata.get('rooted', False)
            root_tag = " [ROOT]" if rooted else ""
            ver_tag = f" [Android {android_ver}/SDK {sdk}]" if android_ver else ""
            label = f"{label}{ver_tag}{root_tag}"

        if device.device_type == DeviceType.MACOS_LOCAL_SYSTEM:
            is_root = device.metadata.get('is_root', False)
            root_tag = " [root]" if is_root else " [non-root]"
            label = f"{label}{root_tag}"

        if device.device_type == DeviceType.LINUX_LOCAL_SYSTEM:
            is_root = device.metadata.get('is_root', False)
            root_tag = " [root]" if is_root else " [non-root]"
            label = f"{label}{root_tag}"

        if device.device_type in (
            DeviceType.MOBILE_FFS_BUNDLE_ANDROID,
            DeviceType.MOBILE_FFS_BUNDLE_IOS,
        ):
            present_count = len(device.metadata.get('present_artifacts') or [])
            if present_count:
                label = f"{label} [{present_count} artifact types]"

        if device.device_type == DeviceType.AXIOM_CASE_DB:
            label = f"{label} [AXIOM result DB]"

        if device.device_type == DeviceType.THIRD_PARTY_FORENSIC_EXPORT:
            upload_type = device.metadata.get('upload_artifact_type') or 'tool result'
            label = f"{label} [{upload_type}]"

        return f"{icon} {label}"

    def _get_device_tooltip(self, device: UnifiedDeviceInfo) -> str:
        """Device tooltip"""
        lines = [
            f"Type: {device.device_type.name}",
            f"Size: {device.size_display}",
            f"Status: {device.status.name}",
        ]

        if device.device_type in (DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE,
                                        DeviceType.VMDK_IMAGE, DeviceType.VHD_IMAGE,
                                        DeviceType.VHDX_IMAGE, DeviceType.QCOW2_IMAGE,
                                        DeviceType.VDI_IMAGE):
            detected_os = device.metadata.get('detected_os', 'unknown')
            fs_type = device.metadata.get('filesystem_type', 'Unknown')
            lines.append(f"Filesystem: {fs_type}")
            lines.append(f"Detected OS: {detected_os.upper()}")

        if device.device_type == DeviceType.AXIOM_CASE_DB:
            lines.append("Upload type: axiom_case_db")
            lines.append("Source tool: Magnet AXIOM")
            source_path = device.metadata.get('file_path') or ''
            if source_path:
                lines.append(f"Path: {source_path}")

        if device.device_type == DeviceType.THIRD_PARTY_FORENSIC_EXPORT:
            lines.append(f"Upload type: {device.metadata.get('upload_artifact_type') or 'verified_tool_result'}")
            lines.append(f"Source tool: {device.metadata.get('source_tool') or 'Unknown'}")
            lines.append("Boundary: user-selected verified forensic result")
            source_path = device.metadata.get('file_path') or ''
            if source_path:
                lines.append(f"Path: {source_path}")

        if device.device_type == DeviceType.ANDROID_DEVICE:
            m = device.metadata
            android_ver = m.get('android_version', '?')
            sdk = m.get('sdk_version', 0)
            patch = m.get('security_patch', '') or 'Unknown'
            rooted = m.get('rooted', False)
            usb_dbg = m.get('usb_debugging', False)
            serial = m.get('serial', '')

            lines.append(f"Android {android_ver} (SDK {sdk})")
            lines.append(f"Security Patch: {patch}")
            lines.append(f"Root: {'Yes' if rooted else 'No'}")
            lines.append(f"USB Debugging: {'Enabled' if usb_dbg else 'Disabled'}")
            if serial:
                lines.append(f"Serial: ...{serial[-8:]}")
            lines.append("─────────────────────")

            capability = m.get('collection_capability') or {}
            available = [
                "System information",
                "Content providers",
                "Media and external app storage",
            ]
            if rooted:
                available.append("App internal databases")
            else:
                available.append("Dual-mode app fallback where available")
            unavailable = []
            if not rooted:
                unavailable.append("App internal DB (root required)")

            lines.append("Available: " + ", ".join(available))
            if capability:
                lines.append(
                    "Artifact availability: "
                    f"{capability.get('available_artifacts', 0)}/"
                    f"{capability.get('implemented_artifacts', 0)} implemented"
                )
                if not rooted:
                    lines.append(
                        "Root-only unavailable: "
                        f"{capability.get('root_only_artifacts', 0)}"
                    )
            lines.append("Full-device ADB backup: not used; individual artifacts are collected")
            if unavailable:
                lines.append("Unavailable: " + ", ".join(unavailable))

        if device.device_type in (
            DeviceType.MOBILE_FFS_BUNDLE_ANDROID,
            DeviceType.MOBILE_FFS_BUNDLE_IOS,
        ):
            meta = device.metadata
            present = meta.get("present_artifacts") or []
            counts = meta.get("present_artifact_count_by_type") or {}
            scan_complete = meta.get("present_artifact_scan_complete", bool(present))
            lines.append(f"Format: {meta.get('format_id', '')}")
            lines.append(f"Platform: {meta.get('platform', '')}")
            if scan_complete:
                lines.append(f"Present artifact types: {len(present)}")
                if present:
                    top = sorted(
                        present,
                        key=lambda key: counts.get(key, 0),
                        reverse=True,
                    )[:8]
                    lines.append("Top present types: " + ", ".join(top))
            else:
                lines.append("Present artifact scan: unavailable; using path-spec support")

        if device.device_type == DeviceType.MACOS_LOCAL_SYSTEM:
            m = device.metadata
            is_root = m.get('is_root', False)
            lines.append(f"macOS {m.get('macos_version', '?')}")
            lines.append(f"Host: {m.get('hostname', '?')}")
            if m.get('hw_model'):
                lines.append(f"Model: {m['hw_model']}")
            lines.append(f"Privileges: {'root' if is_root else 'non-root (limited)'}")
            if not is_root:
                lines.append("Tip: Run with sudo for full artifact access")

        if device.device_type == DeviceType.LINUX_LOCAL_SYSTEM:
            m = device.metadata
            is_root = m.get('is_root', False)
            lines.append(f"{m.get('distro', 'Linux')} {m.get('distro_version', '')}")
            lines.append(f"Host: {m.get('hostname', '?')}")
            lines.append(f"Kernel: {m.get('kernel', '?')}")
            lines.append(f"Privileges: {'root' if is_root else 'non-root (limited)'}")
            if not is_root:
                lines.append("Tip: Run with sudo for full artifact access")

        if not device.is_selectable:
            lines.append(f"⚠ {device.selection_disabled_reason}")
        return "\n".join(lines)

    def get_selected_devices(self):
        """Get selected device list"""
        return self.device_manager.get_selected_devices()
