"""
Auto-Update Checker — GitHub Releases API

앱 시작 시 백그라운드에서 최신 버전을 확인하고,
업데이트가 있으면 GUI 알림을 표시합니다.
"""
import json
import logging
import platform
import sys
from typing import Optional, Tuple

import requests

logger = logging.getLogger(__name__)

# GitHub repository for public releases
GITHUB_REPO = "spirid0n/unjaena-collector"
RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{GITHUB_REPO}/releases/latest"


def get_current_version() -> str:
    """현재 앱 버전 반환"""
    try:
        import os
        if getattr(sys, 'frozen', False):
            # PyInstaller --onefile: bundled files are in sys._MEIPASS, not next to exe
            base_dir = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
            config_path = os.path.join(base_dir, 'config.json')
        else:
            src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            collector_dir = os.path.dirname(src_dir)
            config_path = os.path.join(collector_dir, 'config.json')

        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f).get('version', '0.0.0')
    except Exception:
        pass
    return '0.0.0'


def _parse_version(version_str: str) -> Tuple[int, ...]:
    """v2.2.0 또는 2.2.0 → (2, 2, 0)"""
    cleaned = version_str.lstrip('v').split('-')[0]  # v2.2.0-beta → 2.2.0
    parts = []
    for p in cleaned.split('.'):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _get_platform_asset_name() -> str:
    """현재 OS에 맞는 릴리스 에셋 이름 패턴"""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == 'windows':
        return 'windows-x64.exe'
    elif system == 'darwin':
        if machine == 'arm64':
            return 'macos-arm64.dmg'
        return 'macos-x64.dmg'
    else:
        return 'linux-x64.tar.gz'


def check_for_update() -> Optional[dict]:
    """
    GitHub Releases API로 최신 버전 확인.

    Returns:
        업데이트 정보 dict 또는 None (최신 버전이거나 확인 실패)
        {
            'current_version': '2.1.0',
            'latest_version': '2.2.0',
            'release_name': 'Intelligence Collector v2.2.0',
            'release_notes': '...',
            'download_url': 'https://...',
            'release_page': 'https://...',
            'published_at': '2026-03-10T...',
        }
    """
    # Skip update check when running from source — developers have the latest code
    if not getattr(sys, 'frozen', False):
        logger.debug("[Updater] Skipping: running from source")
        return None

    try:
        current = get_current_version()
        current_tuple = _parse_version(current)

        response = requests.get(
            RELEASES_API,
            headers={'Accept': 'application/vnd.github+json'},
            timeout=10,
        )
        if response.status_code != 200:
            logger.debug(f"[Updater] GitHub API returned {response.status_code}")
            return None

        release = response.json()
        tag_name = release.get('tag_name', '')

        # collector-v2.2.0 → 2.2.0
        latest_version = tag_name.replace('collector-v', '').replace('collector-', '').lstrip('v')
        latest_tuple = _parse_version(latest_version)

        if latest_tuple <= current_tuple:
            logger.debug(f"[Updater] Up to date: {current} >= {latest_version}")
            return None

        # 현재 플랫폼에 맞는 다운로드 URL 찾기
        asset_pattern = _get_platform_asset_name()
        download_url = None
        for asset in release.get('assets', []):
            if asset_pattern in asset.get('name', ''):
                download_url = asset.get('browser_download_url')
                break

        return {
            'current_version': current,
            'latest_version': latest_version,
            'release_name': release.get('name', tag_name),
            'release_notes': (release.get('body') or '')[:500],
            'download_url': download_url,
            'release_page': release.get('html_url', RELEASES_PAGE),
            'published_at': release.get('published_at', ''),
        }

    except requests.RequestException as e:
        logger.debug(f"[Updater] Network error: {e}")
        return None
    except Exception as e:
        logger.debug(f"[Updater] Check failed: {e}")
        return None


def show_update_dialog(parent, update_info: dict):
    """PyQt6 업데이트 알림 다이얼로그"""
    try:
        from PyQt6.QtWidgets import QMessageBox, QPushButton
        from PyQt6.QtCore import QUrl
        from PyQt6.QtGui import QDesktopServices

        msg = QMessageBox(parent)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setWindowTitle("Update Available")
        msg.setText(
            f"A new version is available!\n\n"
            f"Current: v{update_info['current_version']}\n"
            f"Latest:  v{update_info['latest_version']}"
        )

        notes = update_info.get('release_notes', '')
        if notes:
            msg.setDetailedText(notes)

        download_btn = msg.addButton("Download", QMessageBox.ButtonRole.AcceptRole)
        msg.addButton("Later", QMessageBox.ButtonRole.RejectRole)

        msg.exec()

        if msg.clickedButton() == download_btn:
            url = update_info.get('download_url') or update_info['release_page']
            QDesktopServices.openUrl(QUrl(url))

    except Exception as e:
        logger.warning(f"[Updater] Dialog failed: {e}")
