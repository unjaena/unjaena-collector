# -*- coding: utf-8 -*-
"""
BitLocker Decryption Dialog

BitLocker 암호화 볼륨 발견 시 사용자에게 복호화 키 입력을 요청하는 다이얼로그.
"""
from dataclasses import dataclass
from typing import Optional
import os

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFrame, QRadioButton, QButtonGroup,
    QFileDialog, QMessageBox, QGroupBox, QScrollArea, QWidget
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from gui.styles import COLORS


@dataclass
class BitLockerDialogResult:
    """BitLocker 다이얼로그 결과"""
    success: bool = False
    key_type: str = ""          # 'recovery_password' | 'password' | 'bek_file'
    key_value: str = ""         # Recovery password 또는 password
    bek_path: str = ""          # BEK 파일 경로
    skip: bool = False          # 건너뛰기 (이전 방식 진행)


class BitLockerDialog(QDialog):
    """BitLocker 복호화 키 입력 다이얼로그"""

    def __init__(
        self,
        partition_info: dict = None,
        pybde_available: bool = True,
        parent=None
    ):
        """
        Args:
            partition_info: BitLocker 파티션 정보
                - partition_index: 파티션 인덱스
                - partition_offset: 오프셋
                - partition_size: 크기
                - encryption_method: 암호화 방식
            pybde_available: pybde 설치 여부
            parent: 부모 위젯
        """
        super().__init__(parent)
        self.partition_info = partition_info or {}
        self.pybde_available = pybde_available
        self.result = BitLockerDialogResult()
        self.setup_ui()

    def setup_ui(self):
        """UI 초기화"""
        self.setWindowTitle("BitLocker 볼륨 감지됨")
        self.setMinimumSize(500, 400)
        self.setMaximumSize(600, 500)
        self.setModal(True)
        self.setStyleSheet(self._get_stylesheet())

        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(16, 16, 16, 16)

        # 헤더
        header = QLabel("🔒 BitLocker 암호화 볼륨 감지됨")
        header.setObjectName("header")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        # 정보 배너
        info_frame = QFrame()
        info_frame.setObjectName("infoFrame")
        info_layout = QVBoxLayout(info_frame)

        info_text = (
            "시스템에서 BitLocker로 암호화된 볼륨이 발견되었습니다.\n"
            "복호화 키를 입력하면 암호화된 데이터에서 아티팩트를 수집할 수 있습니다."
        )
        info_label = QLabel(info_text)
        info_label.setObjectName("infoText")
        info_label.setWordWrap(True)
        info_layout.addWidget(info_label)

        # 파티션 정보 표시
        if self.partition_info:
            partition_text = self._format_partition_info()
            partition_label = QLabel(partition_text)
            partition_label.setObjectName("partitionInfo")
            info_layout.addWidget(partition_label)

        layout.addWidget(info_frame)

        # pybde 미설치 경고
        if not self.pybde_available:
            warning_frame = QFrame()
            warning_frame.setObjectName("warningFrame")
            warning_layout = QHBoxLayout(warning_frame)
            warning_label = QLabel(
                "⚠️ pybde (libbde-python)가 설치되어 있지 않습니다.\n"
                "BitLocker 복호화 기능을 사용하려면 설치가 필요합니다:\n"
                "pip install libbde-python"
            )
            warning_label.setObjectName("warningText")
            warning_label.setWordWrap(True)
            warning_layout.addWidget(warning_label)
            layout.addWidget(warning_frame)

        # 키 타입 선택
        key_group = QGroupBox("복호화 키 타입 선택")
        key_group.setObjectName("keyGroup")
        key_layout = QVBoxLayout(key_group)

        self.key_type_group = QButtonGroup(self)

        # Recovery Password 옵션
        self.radio_recovery = QRadioButton("복구 키 (Recovery Password)")
        self.radio_recovery.setChecked(True)
        self.radio_recovery.setEnabled(self.pybde_available)
        self.key_type_group.addButton(self.radio_recovery)
        key_layout.addWidget(self.radio_recovery)

        recovery_desc = QLabel(
            "   48자리 숫자 (예: 123456-234567-345678-456789-567890-678901-789012-890123)"
        )
        recovery_desc.setObjectName("keyDesc")
        recovery_desc.setWordWrap(True)
        key_layout.addWidget(recovery_desc)

        # Password 옵션
        self.radio_password = QRadioButton("비밀번호 (Password)")
        self.radio_password.setEnabled(self.pybde_available)
        self.key_type_group.addButton(self.radio_password)
        key_layout.addWidget(self.radio_password)

        password_desc = QLabel("   BitLocker 설정 시 입력한 비밀번호")
        password_desc.setObjectName("keyDesc")
        key_layout.addWidget(password_desc)

        # BEK File 옵션
        self.radio_bek = QRadioButton("시작 키 파일 (BEK File)")
        self.radio_bek.setEnabled(self.pybde_available)
        self.key_type_group.addButton(self.radio_bek)
        key_layout.addWidget(self.radio_bek)

        bek_desc = QLabel("   USB 드라이브 등에 저장된 .BEK 파일")
        bek_desc.setObjectName("keyDesc")
        key_layout.addWidget(bek_desc)

        layout.addWidget(key_group)

        # 입력 필드 영역
        input_frame = QFrame()
        input_frame.setObjectName("inputFrame")
        input_layout = QVBoxLayout(input_frame)

        # 키 입력 필드 (Recovery/Password 공용)
        self.key_input_label = QLabel("복구 키:")
        input_layout.addWidget(self.key_input_label)

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText(
            "123456-234567-345678-456789-567890-678901-789012-890123"
        )
        self.key_input.setEnabled(self.pybde_available)
        input_layout.addWidget(self.key_input)

        # BEK 파일 선택
        self.bek_layout = QHBoxLayout()
        self.bek_input = QLineEdit()
        self.bek_input.setPlaceholderText(".BEK 파일 경로")
        self.bek_input.setEnabled(False)
        self.bek_layout.addWidget(self.bek_input)

        self.bek_browse_btn = QPushButton("찾아보기...")
        self.bek_browse_btn.setEnabled(False)
        self.bek_browse_btn.clicked.connect(self._browse_bek_file)
        self.bek_layout.addWidget(self.bek_browse_btn)

        input_layout.addLayout(self.bek_layout)

        # 에러 메시지 영역
        self.error_label = QLabel("")
        self.error_label.setObjectName("errorLabel")
        self.error_label.setWordWrap(True)
        self.error_label.hide()
        input_layout.addWidget(self.error_label)

        layout.addWidget(input_frame)

        # 버튼
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.skip_btn = QPushButton("건너뛰기 (암호화 상태로 수집)")
        self.skip_btn.clicked.connect(self._on_skip)
        self.skip_btn.setMinimumWidth(180)
        button_layout.addWidget(self.skip_btn)

        self.cancel_btn = QPushButton("취소")
        self.cancel_btn.clicked.connect(self.reject)
        self.cancel_btn.setMinimumWidth(80)
        button_layout.addWidget(self.cancel_btn)

        self.unlock_btn = QPushButton("잠금 해제")
        self.unlock_btn.setObjectName("unlockButton")
        self.unlock_btn.setEnabled(self.pybde_available)
        self.unlock_btn.clicked.connect(self._on_unlock)
        self.unlock_btn.setMinimumWidth(100)
        button_layout.addWidget(self.unlock_btn)

        layout.addLayout(button_layout)

        # 시그널 연결
        self.radio_recovery.toggled.connect(self._on_key_type_changed)
        self.radio_password.toggled.connect(self._on_key_type_changed)
        self.radio_bek.toggled.connect(self._on_key_type_changed)

    def _format_partition_info(self) -> str:
        """파티션 정보 포맷팅"""
        info = self.partition_info
        size_gb = info.get('partition_size', 0) / (1024 ** 3)

        text = f"파티션 #{info.get('partition_index', 0)}"
        if size_gb > 0:
            text += f" | 크기: {size_gb:.1f} GB"
        if info.get('encryption_method'):
            text += f" | 암호화: {info['encryption_method']}"

        return text

    def _on_key_type_changed(self):
        """키 타입 변경 시 UI 업데이트"""
        if self.radio_recovery.isChecked():
            self.key_input_label.setText("복구 키:")
            self.key_input.setPlaceholderText(
                "123456-234567-345678-456789-567890-678901-789012-890123"
            )
            self.key_input.setEnabled(True)
            self.key_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.bek_input.setEnabled(False)
            self.bek_browse_btn.setEnabled(False)

        elif self.radio_password.isChecked():
            self.key_input_label.setText("비밀번호:")
            self.key_input.setPlaceholderText("BitLocker 비밀번호 입력")
            self.key_input.setEnabled(True)
            self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.bek_input.setEnabled(False)
            self.bek_browse_btn.setEnabled(False)

        elif self.radio_bek.isChecked():
            self.key_input_label.setText("BEK 파일:")
            self.key_input.setEnabled(False)
            self.key_input.clear()
            self.bek_input.setEnabled(True)
            self.bek_browse_btn.setEnabled(True)

        self.error_label.hide()

    def _browse_bek_file(self):
        """BEK 파일 선택 다이얼로그"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "BEK 파일 선택",
            "",
            "BEK Files (*.bek *.BEK);;All Files (*)"
        )
        if file_path:
            self.bek_input.setText(file_path)

    def _show_error(self, message: str):
        """에러 메시지 표시"""
        self.error_label.setText(f"❌ {message}")
        self.error_label.show()

    def _validate_input(self) -> bool:
        """입력값 검증"""
        if self.radio_recovery.isChecked():
            key = self.key_input.text().strip()
            if not key:
                self._show_error("복구 키를 입력하세요.")
                return False

            # 숫자만 추출
            digits = ''.join(c for c in key if c.isdigit())
            if len(digits) != 48:
                self._show_error(
                    f"복구 키는 48자리 숫자여야 합니다. "
                    f"(현재 {len(digits)}자리)"
                )
                return False

        elif self.radio_password.isChecked():
            if not self.key_input.text():
                self._show_error("비밀번호를 입력하세요.")
                return False

        elif self.radio_bek.isChecked():
            bek_path = self.bek_input.text().strip()
            if not bek_path:
                self._show_error("BEK 파일을 선택하세요.")
                return False
            if not os.path.exists(bek_path):
                self._show_error("BEK 파일이 존재하지 않습니다.")
                return False

        return True

    def _on_unlock(self):
        """잠금 해제 버튼 클릭"""
        if not self._validate_input():
            return

        self.result.success = True
        self.result.skip = False

        if self.radio_recovery.isChecked():
            self.result.key_type = "recovery_password"
            # 복구 키 표준 형식으로 변환
            key = self.key_input.text().strip()
            digits = ''.join(c for c in key if c.isdigit())
            groups = [digits[i:i+6] for i in range(0, 48, 6)]
            self.result.key_value = '-'.join(groups)

        elif self.radio_password.isChecked():
            self.result.key_type = "password"
            self.result.key_value = self.key_input.text()

        elif self.radio_bek.isChecked():
            self.result.key_type = "bek_file"
            self.result.bek_path = self.bek_input.text().strip()

        self.accept()

    def _on_skip(self):
        """건너뛰기 버튼 클릭"""
        # 확인 다이얼로그
        reply = QMessageBox.question(
            self,
            "BitLocker 건너뛰기",
            "BitLocker 복호화를 건너뛰면 암호화된 상태로 데이터가 수집됩니다.\n"
            "일부 아티팩트를 추출할 수 없을 수 있습니다.\n\n"
            "계속하시겠습니까?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.result.success = False
            self.result.skip = True
            self.accept()

    def get_result(self) -> BitLockerDialogResult:
        """결과 반환"""
        return self.result

    def _get_stylesheet(self) -> str:
        """스타일시트 - 플랫폼 통일 테마"""
        return f"""
            QDialog {{
                background-color: {COLORS['bg_primary']};
            }}
            #header {{
                font-size: 16px;
                font-weight: bold;
                color: {COLORS['warning']};
                padding: 4px;
            }}
            #infoFrame {{
                background-color: {COLORS['info_bg']};
                border: 1px solid {COLORS['info']};
                border-radius: 6px;
                padding: 8px;
            }}
            #infoText {{
                color: {COLORS['text_primary']};
                font-size: 11px;
            }}
            #partitionInfo {{
                color: {COLORS['info']};
                font-size: 10px;
                font-weight: bold;
                margin-top: 4px;
            }}
            #warningFrame {{
                background-color: {COLORS['error_bg']};
                border: 1px solid {COLORS['error']};
                border-radius: 6px;
                padding: 8px;
            }}
            #warningText {{
                color: {COLORS['error']};
                font-size: 10px;
            }}
            #keyGroup {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 6px;
                padding: 8px;
                color: {COLORS['text_primary']};
                font-size: 11px;
            }}
            QRadioButton {{
                color: {COLORS['text_primary']};
                background-color: transparent;
                font-size: 11px;
                padding: 2px 0;
            }}
            QRadioButton::indicator {{
                width: 14px;
                height: 14px;
            }}
            QRadioButton:disabled {{
                color: {COLORS['text_tertiary']};
            }}
            #keyDesc {{
                color: {COLORS['text_secondary']};
                font-size: 9px;
                margin-left: 20px;
                margin-bottom: 4px;
            }}
            #inputFrame {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 6px;
                padding: 8px;
            }}
            QLineEdit {{
                background-color: {COLORS['bg_tertiary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 4px;
                color: {COLORS['text_primary']};
                padding: 6px;
                font-size: 11px;
            }}
            QLineEdit:disabled {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_tertiary']};
            }}
            QLineEdit::placeholder {{
                color: {COLORS['text_tertiary']};
            }}
            QLabel {{
                color: {COLORS['text_primary']};
                font-size: 11px;
            }}
            #errorLabel {{
                color: {COLORS['error']};
                font-size: 10px;
                padding: 4px;
                background-color: {COLORS['error_bg']};
                border-radius: 4px;
            }}
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 4px;
                color: {COLORS['text_primary']};
                padding: 6px 12px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['bg_hover']};
                border-color: {COLORS['border_default']};
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_tertiary']};
            }}
            #unlockButton {{
                background-color: {COLORS['brand_primary']};
                border: none;
                color: {COLORS['bg_primary']};
                font-weight: bold;
            }}
            #unlockButton:hover {{
                background-color: {COLORS['brand_accent']};
            }}
            #unlockButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_tertiary']};
            }}
        """


def show_bitlocker_dialog(
    partition_info: dict = None,
    pybde_available: bool = True,
    parent=None
) -> BitLockerDialogResult:
    """
    BitLocker 다이얼로그 표시 및 결과 반환

    Args:
        partition_info: 파티션 정보
        pybde_available: pybde 설치 여부
        parent: 부모 위젯

    Returns:
        BitLockerDialogResult
    """
    dialog = BitLockerDialog(
        partition_info=partition_info,
        pybde_available=pybde_available,
        parent=parent
    )
    result_code = dialog.exec()

    if result_code == QDialog.DialogCode.Accepted:
        return dialog.get_result()

    # 취소된 경우
    return BitLockerDialogResult(success=False, skip=False)


if __name__ == "__main__":
    # 테스트용
    from PyQt6.QtWidgets import QApplication
    import sys

    app = QApplication(sys.argv)

    # 테스트 파티션 정보
    test_info = {
        'partition_index': 0,
        'partition_offset': 1048576,
        'partition_size': 256 * 1024 * 1024 * 1024,  # 256GB
        'encryption_method': 'AES-256-XTS'
    }

    result = show_bitlocker_dialog(
        partition_info=test_info,
        pybde_available=True
    )

    # 테스트 결과 (디버그용 - 비활성화됨)
    # if result.success:
    #     print(f"잠금 해제 시도: {result.key_type}")
    # elif result.skip:
    #     print("건너뛰기 선택됨")
    # else:
    #     print("취소됨")
    pass
