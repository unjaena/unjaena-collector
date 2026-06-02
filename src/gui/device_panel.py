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
        self._scan_seen = False
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        """Setup UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Header row
        header = QHBoxLayout()
        header.setSpacing(4)
        header.setContentsMargins(0, 0, 0, 0)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setFixedHeight(20)
        refresh_btn.clicked.connect(self._on_refresh_clicked)
        header.addWidget(refresh_btn)

        add_btn = QPushButton("+ Add Image / Bundle")
        add_btn.setFixedHeight(20)
        add_btn.clicked.connect(self._on_add_image_clicked)
        header.addWidget(add_btn)

        header.addStretch()

        self.summary_label = QLabel("0 selected")
        self.summary_label.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 10px;"
        )
        header.addWidget(self.summary_label)

        layout.addLayout(header)

        # Device list (no scroll — typically 1-5 items)
        self.devices_container = QWidget()
        self.devices_layout = QVBoxLayout(self.devices_container)
        self.devices_layout.setContentsMargins(0, 0, 0, 0)
        self.devices_layout.setSpacing(2)
        layout.addWidget(self.devices_container)

        self.empty_label = QLabel("Scanning local disks and connected devices...")
        self.empty_label.setWordWrap(True)
        self.empty_label.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 10px; "
            f"background: {COLORS['bg_secondary']}; "
            f"border: 1px dashed {COLORS['border_subtle']}; "
            f"border-radius: 4px; padding: 8px;"
        )
        layout.addWidget(self.empty_label)

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
        self.device_manager.scan_started.connect(self._on_scan_started)
        self.device_manager.scan_completed.connect(self._on_scan_completed)

    def _on_scan_started(self):
        self._update_empty_state(scanning=True)

    def _on_scan_completed(self):
        self._scan_seen = True
        self._update_empty_state(scanning=False)
        self._update_mobile_guide()

    def _update_empty_state(self, scanning: bool = False):
        if self.device_checkboxes:
            self.empty_label.setVisible(False)
            return
        self.empty_label.setVisible(True)
        if scanning and not self._scan_seen:
            self.empty_label.setText("Scanning local disks and connected devices...")
        elif scanning:
            self.empty_label.setText("Refreshing connected evidence sources...")
        else:
            self.empty_label.setText(
                "No local evidence source detected. Run the collector as administrator "
                "for physical disks, connect a USB/mobile device, or use + Add Image / Bundle."
            )

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
        has_android = any(
            did.startswith('android_') for did in self.device_checkboxes
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
        if has_android:
            sections.append(
                f"<span style='color:{ok};'>● Android — Connected</span>"
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

        # --- E01/RAW hint ---
        sections.append(
            f"<span style='color:{dim};'>"
            "● <b>Images/Bundles</b>: Use <b>+ Add Image / Bundle</b> above"
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
        cb.setEnabled(device.is_selectable)
        cb.setProperty("device_id", device.device_id)
        cb.stateChanged.connect(
            lambda state, d=device.device_id: self._on_checkbox_changed(d, state)
        )
        cb.setToolTip(self._get_device_tooltip(device))

        self.device_checkboxes[device.device_id] = cb
        self.devices_layout.addWidget(cb)
        self._update_summary()
        self._update_empty_state(scanning=False)
        self._update_mobile_guide()

    def _on_device_removed(self, device_id: str):
        """Device removed"""
        if device_id in self.device_checkboxes:
            cb = self.device_checkboxes.pop(device_id)
            self.devices_layout.removeWidget(cb)
            cb.deleteLater()
            self._update_summary()
            self._update_empty_state(scanning=False)
            self._update_mobile_guide()

    def _on_device_updated(self, device: UnifiedDeviceInfo):
        """Device updated"""
        if device.device_id in self.device_checkboxes:
            cb = self.device_checkboxes[device.device_id]
            cb.setText(self._get_device_label(device))
            cb.setToolTip(self._get_device_tooltip(device))

    def _on_checkbox_changed(self, device_id: str, state: int):
        """Checkbox changed"""
        selected = state == Qt.CheckState.Checked.value
        self.device_manager.select_device(device_id, selected)
        self._update_summary()
        self.selection_changed.emit()

    def _on_refresh_clicked(self):
        """Refresh"""
        self.device_manager.refresh()
        self._update_empty_state(scanning=True)
        self._update_mobile_guide()

    def _on_add_image_clicked(self):
        """Add image or mobile FFS bundle"""
        file_path, selected_filter = QFileDialog.getOpenFileName(
            self,
            "Select Forensic Image or Mobile Bundle",
            "",
            "Forensic Images (*.E01 *.e01 *.Ex01 *.ex01 *.L01 *.l01 *.Lx01 *.lx01 *.S01 *.s01 *.dd *.raw *.img *.bin *.000 *.001 *.vmdk *.vhd *.vhdx *.qcow2 *.vdi *.dmg *.DMG *.ntfs *.fat *.fat12 *.fat16 *.fat32 *.exfat *.ext *.ext2 *.ext3 *.ext4 *.xfs *.btrfs *.hfs *.hfsx *.apfs *.ufs)"
            ";;Mobile FFS Bundle (*.zip *.clbx)"
            ";;All Files (*)"
        )
        if not file_path:
            return

        is_mobile_bundle = file_path.lower().endswith((".zip", ".clbx"))
        if is_mobile_bundle:
            self._register_ffs_bundle(file_path)
        else:
            device = self.device_manager.add_image_file(file_path)
            if device:
                self.image_file_requested.emit()

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
            QMessageBox.warning(
                self, "Bundle Registration Failed",
                f"Could not register bundle:\n{error_msg}"
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
        self.image_file_requested.emit()

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
            DeviceType.WINDOWS_LOGICAL_DRIVE: "🗄",
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
        }
        icon = type_icons.get(device.device_type, "📁")
        label = device.display_name

        if device.device_type == DeviceType.WINDOWS_PHYSICAL_DISK:
            all_volumes = device.metadata.get('all_volumes', [])
            if all_volumes:
                volumes_str = ', '.join(f"{v}:" for v in all_volumes)
                label = f"{label} [{volumes_str}]"

        if device.device_type == DeviceType.WINDOWS_LOGICAL_DRIVE:
            fs_type = device.metadata.get('filesystem') or ''
            drive_type = device.metadata.get('drive_type') or ''
            details = ' / '.join(part for part in (drive_type, fs_type) if part)
            if details:
                label = f"{label} [{details}]"

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

        if device.device_type == DeviceType.WINDOWS_LOGICAL_DRIVE:
            m = device.metadata
            lines.append(f"Volume: {m.get('volume', '?')}:")
            lines.append(f"Drive type: {m.get('drive_type', 'Unknown')}")
            lines.append(f"Filesystem: {m.get('filesystem', 'Unknown')}")
            if m.get('volume_label'):
                lines.append(f"Label: {m.get('volume_label')}")
            lines.append("Collection: Windows local filesystem / MFT where accessible")

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
