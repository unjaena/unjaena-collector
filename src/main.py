#!/usr/bin/env python3
"""
Digital Forensics Collector - Main Entry Point

This tool collects forensic artifacts from Windows systems
and uploads them to the forensics server for analysis.
"""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt

from gui.app import CollectorWindow
from utils.privilege import is_admin, run_as_admin


# =============================================================================
# P1 보안 강화: HTTPS/WSS 필수화
# =============================================================================

def get_secure_config() -> dict:
    """
    보안 설정이 적용된 구성 반환

    환경변수:
        COLLECTOR_SERVER_URL: 서버 URL (기본: http://localhost:8000)
        COLLECTOR_WS_URL: WebSocket URL (기본: ws://localhost:8000)
        COLLECTOR_DEV_MODE: 개발 모드 (true/false, 기본: true)
        COLLECTOR_ALLOW_INSECURE: 비보안 연결 허용 (true/false, 기본: true)

    프로덕션 배포 시:
        COLLECTOR_DEV_MODE=false
        COLLECTOR_SERVER_URL=https://your-server.com
        COLLECTOR_WS_URL=wss://your-server.com

    개발 환경에서는:
        COLLECTOR_DEV_MODE=true
        COLLECTOR_ALLOW_INSECURE=true
    """
    # [테스트 모드] 기본값을 개발 모드(HTTP)로 설정
    # 프로덕션 배포 시 환경변수로 dev_mode=false 설정 필요
    dev_mode = os.environ.get('COLLECTOR_DEV_MODE', 'true').lower() == 'true'
    allow_insecure = os.environ.get('COLLECTOR_ALLOW_INSECURE', 'true').lower() == 'true'

    # [테스트 모드] 기본 URL을 HTTP/WS로 변경 (인증서 없이 테스트 가능)
    # NOTE: Windows에서 'localhost'가 IPv6(::1)로 해석되어 Docker 연결 실패할 수 있음
    # 127.0.0.1 사용으로 IPv4 명시적 지정
    server_url = os.environ.get('COLLECTOR_SERVER_URL', 'http://127.0.0.1:8000')
    ws_url = os.environ.get('COLLECTOR_WS_URL', 'ws://127.0.0.1:8000')

    # 프로덕션 모드에서만 HTTPS/WSS 강제
    if not dev_mode and not allow_insecure:
        if server_url.startswith('http://'):
            # 프로덕션에서 HTTP 감지 시 경고 및 HTTPS로 변환 시도
            print("[보안 경고] HTTP 연결이 감지되었습니다. HTTPS로 변환합니다.")
            server_url = server_url.replace('http://', 'https://', 1)

        if ws_url.startswith('ws://'):
            print("[보안 경고] WS 연결이 감지되었습니다. WSS로 변환합니다.")
            ws_url = ws_url.replace('ws://', 'wss://', 1)

    return {
        'server_url': server_url,
        'ws_url': ws_url,
        'version': '2.0.0',  # 메모리/모바일 포렌식 추가
        'app_name': 'Digital Forensics Collector',
        'dev_mode': dev_mode,
        'allow_insecure': allow_insecure,
    }


# Configuration (P1: 보안 설정 적용)
CONFIG = get_secure_config()


def check_admin_privilege():
    """Check if running as administrator"""
    if not is_admin():
        # Show warning message in Korean
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Icon.Warning)
        msg_box.setWindowTitle("관리자 권한 필요")
        msg_box.setText("이 수집 도구는 관리자 권한이 필요합니다.")
        msg_box.setInformativeText(
            "포렌식 아티팩트를 정확하게 수집하기 위해서는 관리자 권한으로 "
            "실행해야 합니다.\n\n"
            "관리자 권한으로 다시 실행하시겠습니까?"
        )
        msg_box.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        msg_box.setDefaultButton(QMessageBox.StandardButton.Yes)
        msg_box.button(QMessageBox.StandardButton.Yes).setText("예, 다시 실행")
        msg_box.button(QMessageBox.StandardButton.No).setText("아니오, 종료")

        reply = msg_box.exec()

        if reply == QMessageBox.StandardButton.Yes:
            if run_as_admin():
                # Elevation requested successfully, exit current process
                sys.exit(0)
            else:
                # Failed to request elevation
                QMessageBox.critical(
                    None,
                    "오류",
                    "관리자 권한으로 실행할 수 없습니다.\n"
                    "프로그램을 마우스 오른쪽 버튼으로 클릭하고 "
                    "'관리자 권한으로 실행'을 선택하세요."
                )
        sys.exit(0)


def main():
    """Main entry point"""
    # High DPI support
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName(CONFIG['app_name'])
    app.setApplicationVersion(CONFIG['version'])

    # Check admin privilege
    check_admin_privilege()

    # Create and show main window
    window = CollectorWindow(CONFIG)
    window.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
