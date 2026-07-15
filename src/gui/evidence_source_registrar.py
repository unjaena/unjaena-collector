"""Dialogs and registration flow for user-selected evidence sources."""

from typing import Optional

from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import QFileDialog, QMessageBox, QProgressDialog, QWidget

from core.device_manager import UnifiedDeviceInfo, UnifiedDeviceManager


class _BundleRegistrationWorker(QThread):
    """Register large mobile FFS bundles without blocking the main event loop."""

    finished_with_device = pyqtSignal(object, str)

    def __init__(
        self,
        device_manager: UnifiedDeviceManager,
        file_path: str,
        parent: Optional[QObject] = None,
    ):
        super().__init__(parent)
        self._device_manager = device_manager
        self._file_path = file_path

    def run(self):
        try:
            device = self._device_manager.add_bundle_file(self._file_path)
            self.finished_with_device.emit(device, "")
        except Exception as exc:
            self.finished_with_device.emit(None, str(exc))


class EvidenceSourceRegistrar(QObject):
    """Register disk images, mobile FFS bundles, and verified tool results."""

    source_registered = pyqtSignal(object)

    def __init__(
        self,
        device_manager: UnifiedDeviceManager,
        parent: Optional[QObject] = None,
    ):
        super().__init__(parent)
        self.device_manager = device_manager
        self._interaction_locked = False
        self._bundle_worker: Optional[_BundleRegistrationWorker] = None

    def set_interaction_locked(self, locked: bool) -> None:
        self._interaction_locked = bool(locked)

    def request_add_evidence_file(self) -> None:
        """Open the disk image or mobile FFS registration flow."""
        if self._interaction_locked:
            return
        file_path, _selected_filter = QFileDialog.getOpenFileName(
            self._dialog_parent(),
            "Select Disk Image or Mobile FFS Bundle",
            "",
            "Forensic Images (*.E01 *.e01 *.Ex01 *.ex01 *.L01 *.l01 *.Lx01 *.lx01 *.S01 *.s01 *.dd *.raw *.img *.bin *.000 *.001 *.vmdk *.vhd *.vhdx *.qcow2 *.vdi *.dmg *.DMG *.ntfs *.fat *.fat12 *.fat16 *.fat32 *.exfat *.ext *.ext2 *.ext3 *.ext4 *.xfs *.btrfs *.hfs *.hfsx *.apfs *.ufs)"
            ";;Mobile FFS Bundle (*.zip *.clbx)"
            ";;All Files (*)",
        )
        if file_path:
            self.register_evidence_file(file_path)

    def request_add_tool_result(self) -> None:
        """Open the verified forensic tool result registration flow."""
        if self._interaction_locked:
            return
        file_path, selected_filter = QFileDialog.getOpenFileName(
            self._dialog_parent(),
            "Select Verified Tool Result",
            "",
            "Magnet AXIOM Result DB (*.mfdb *.db *.sqlite *.sqlite3);;Cellebrite UFDR (*.ufdr);;Cellebrite XML Report (*.xml);;Autopsy Case DB (*.db *.sqlite *.sqlite3);;All Files (*)",
        )
        if file_path:
            self.register_tool_result(
                file_path,
                self.artifact_type_from_tool_result_filter(
                    selected_filter,
                    file_path,
                ),
            )

    def register_evidence_file(self, file_path: str) -> None:
        """Register a supported disk image or mobile FFS bundle."""
        if self._interaction_locked:
            return
        if not self.is_supported_evidence_file(file_path):
            QMessageBox.warning(
                self._dialog_parent(),
                "Unsupported Evidence Source",
                self.unsupported_file_message(file_path),
            )
            return

        if file_path.lower().endswith((".zip", ".clbx")):
            self._register_ffs_bundle(file_path)
            return

        device = self.device_manager.add_image_file(file_path)
        if device:
            self._select_registered_device(device)
            return
        QMessageBox.warning(
            self._dialog_parent(),
            "Evidence Registration Failed",
            "Could not register this evidence source. Verify that the file "
            "exists and is a supported disk image or filesystem volume image.",
        )

    def register_tool_result(
        self,
        file_path: str,
        artifact_type: Optional[str] = None,
    ) -> None:
        """Register a verified third-party forensic result for direct upload."""
        if self._interaction_locked:
            return
        device = self.device_manager.add_third_party_forensic_export_file(
            file_path,
            artifact_type,
        )
        if not device:
            QMessageBox.warning(
                self._dialog_parent(),
                "Tool Result Registration Failed",
                "Could not register this forensic tool result. Only verified "
                "AXIOM DB, Cellebrite UFDR/XML, and Autopsy autopsy.db files "
                "are enabled. Generic XML/JSON/CSV/TSV exports are intentionally "
                "unsupported until validated.",
            )
            return

        self._select_registered_device(device)
        upload_type = (
            device.metadata.get("upload_artifact_type")
            or "verified_tool_result"
        )
        QMessageBox.information(
            self._dialog_parent(),
            "Tool Result Registered",
            f"<b>{device.display_name}</b><br><br>"
            f"<b>Upload type</b>: {upload_type}<br>"
            f"<b>Size</b>: {device.size_display}<br>"
            "This user-selected forensic result will be uploaded as one source. "
            "Server parsing will normalize supported records into searchable "
            "documents.",
        )

    @staticmethod
    def artifact_type_from_tool_result_filter(
        selected_filter: str,
        file_path: str,
    ) -> Optional[str]:
        text = (selected_filter or "").lower()
        lower_path = (file_path or "").lower()
        if "axiom" in text or "magnet" in text:
            return "axiom_case_db"
        if "cellebrite" in text:
            return "cellebrite_ufdr_xml"
        if "autopsy" in text:
            return "autopsy_case_db"
        if lower_path.endswith(".mfdb") or "axiom" in lower_path:
            return "axiom_case_db"
        if (
            lower_path.endswith(".ufdr")
            or "cellebrite" in lower_path
            or "ufdr" in lower_path
        ):
            return "cellebrite_ufdr_xml"
        if (
            lower_path.endswith(("autopsy.db", "/autopsy.db", "\\autopsy.db"))
            or "autopsy" in lower_path
        ):
            return "autopsy_case_db"
        return None

    @staticmethod
    def is_supported_evidence_file(file_path: str) -> bool:
        lower = file_path.lower()
        return lower.endswith(
            (
                ".e01", ".ex01", ".l01", ".lx01", ".s01",
                ".dd", ".raw", ".img", ".bin", ".000", ".001",
                ".vmdk", ".vhd", ".vhdx", ".qcow2", ".vdi", ".dmg",
                ".ntfs", ".fat", ".fat12", ".fat16", ".fat32", ".exfat",
                ".ext", ".ext2", ".ext3", ".ext4", ".xfs", ".btrfs",
                ".hfs", ".hfsx", ".apfs", ".ufs", ".zip", ".clbx",
            )
        )

    @staticmethod
    def unsupported_file_message(file_path: str) -> str:
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
                "screen.\n\nUse a disk image, a filesystem volume image, or a "
                "supported mobile FFS bundle."
            )
        if lower.endswith((".db", ".sqlite", ".sqlite3", ".mfdb")):
            return (
                "Database files are not disk-image sources in this collector "
                "screen.\n\nUse Add Tool Result and choose Magnet AXIOM Result "
                "DB or Autopsy Case DB."
            )
        if lower.endswith(".zip"):
            return (
                "Only Cellebrite UFED/CLBX mobile FFS ZIP bundles are supported "
                "directly.\n\nFor a normal ZIP archive that contains E01/RAW "
                "images, extract the archive first and add the first image "
                "segment, such as .E01."
            )
        return (
            "This file type is not supported as an evidence source.\n\n"
            "Supported disk sources: E01/RAW/VMDK/VHD/VHDX/QCOW2/VDI/DMG "
            "and filesystem volume images. Supported mobile source: Cellebrite "
            "UFED/CLBX FFS ZIP. For verified forensic tool results, use Add Tool "
            "Result."
        )

    def _register_ffs_bundle(self, file_path: str) -> None:
        progress = QProgressDialog(
            "Analyzing bundle...\n"
            "(Reading central directory and metadata; large extractions may take "
            "10-30 seconds.)",
            None,
            0,
            0,
            self._dialog_parent(),
        )
        progress.setWindowTitle("Mobile FFS Bundle")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setCancelButton(None)
        progress.setMinimumDuration(0)

        worker = _BundleRegistrationWorker(self.device_manager, file_path, self)
        self._bundle_worker = worker

        def on_done(device, error_message: str) -> None:
            progress.close()
            self._bundle_worker = None
            self._show_bundle_registration_result(device, error_message)

        worker.finished_with_device.connect(on_done)
        worker.start()
        progress.exec()

    def _show_bundle_registration_result(
        self,
        device: Optional[UnifiedDeviceInfo],
        error_message: str,
    ) -> None:
        if error_message:
            body = error_message
            if (
                "GENERIC_ZIP" in error_message
                or "Unsupported bundle format" in error_message
            ):
                body = (
                    "The selected ZIP is not a recognized mobile FFS bundle.\n\n"
                    "Only Cellebrite UFED/CLBX iOS or Android FFS ZIP bundles "
                    "are supported directly. If this ZIP contains E01/RAW disk "
                    "images, extract it first and add the first image segment."
                )
            QMessageBox.warning(
                self._dialog_parent(),
                "Bundle Registration Failed",
                f"Could not register bundle:\n{body}",
            )
            return
        if not device:
            QMessageBox.warning(
                self._dialog_parent(),
                "Bundle Registration Failed",
                "The selected file is not a recognized mobile FFS bundle.\n\n"
                "Supported: Cellebrite UFED CLBX (iOS / Android).",
            )
            return

        metadata = device.metadata
        signals = "\n".join(
            f"  - {signal}" for signal in metadata.get("signals_fired", [])
        )
        present = metadata.get("present_artifacts") or []
        scan_complete = metadata.get(
            "present_artifact_scan_complete",
            bool(present),
        )
        present_text = (
            f"<b>Present artifact types</b>: {len(present)}<br>"
            if scan_complete
            else "<b>Present artifact scan</b>: unavailable; using path-spec support<br>"
        )
        QMessageBox.information(
            self._dialog_parent(),
            "Bundle Registered",
            f"<b>{device.display_name}</b><br><br>"
            f"<b>Format</b>: {metadata.get('format_id', '')}<br>"
            f"<b>Publisher</b>: {metadata.get('publisher_software') or 'unknown'}<br>"
            f"<b>Confidence</b>: {metadata.get('confidence', '')}<br>"
            f"<b>Size</b>: {device.size_display}<br>"
            f"{present_text}<br><b>Detection signals</b>:<br><pre>{signals}</pre>",
        )
        self._select_registered_device(device)

    def _select_registered_device(self, device: UnifiedDeviceInfo) -> None:
        self.device_manager.select_device(device.device_id, True)
        self.source_registered.emit(device)

    def _dialog_parent(self) -> Optional[QWidget]:
        parent = self.parent()
        return parent if isinstance(parent, QWidget) else None
