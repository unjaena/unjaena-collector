# -*- coding: utf-8 -*-
"""
Platform Unified Theme Stylesheet

웹 플랫폼과 동일한 다크 테마를 PyQt6용으로 구현합니다.
Claude AI 영감의 브랜드 색상을 사용합니다.

Usage:
    from gui.styles import get_platform_stylesheet, COLORS

    app = QApplication(sys.argv)
    app.setStyleSheet(get_platform_stylesheet())
"""


# =============================================================================
# Color Palette (from tailwind.config.js)
# =============================================================================

COLORS = {
    # 배경색
    'bg_primary': '#0d1117',
    'bg_secondary': '#161b22',
    'bg_tertiary': '#21262d',
    'bg_elevated': '#1c2128',
    'bg_hover': '#30363d',
    'bg_active': '#484f58',

    # 텍스트색
    'text_primary': '#f0f6fc',
    'text_secondary': '#8b949e',
    'text_tertiary': '#6e7681',
    'text_link': '#58a6ff',

    # 브랜드색 (Claude 영감)
    'brand_primary': '#d4a574',
    'brand_secondary': '#b8956e',
    'brand_tertiary': '#9c7d5c',
    'brand_accent': '#e8c49a',

    # 상태색
    'success': '#3fb950',
    'success_bg': 'rgba(63, 185, 80, 0.15)',
    'warning': '#d29922',
    'warning_bg': 'rgba(210, 153, 34, 0.15)',
    'error': '#f85149',
    'error_bg': 'rgba(248, 81, 73, 0.15)',
    'info': '#58a6ff',
    'info_bg': 'rgba(88, 166, 255, 0.15)',

    # 테두리색
    'border_subtle': '#30363d',
    'border_default': '#484f58',
    'border_muted': '#21262d',

    # 아티팩트 유형별 색상
    'artifact_registry': '#60a5fa',
    'artifact_prefetch': '#34d399',
    'artifact_eventlog': '#a78bfa',
    'artifact_filesystem': '#fbbf24',
    'artifact_browser': '#fb923c',
    'artifact_usb': '#22d3ee',
    'artifact_network': '#4ade80',
    'artifact_memory': '#c084fc',
}


# =============================================================================
# Main Stylesheet
# =============================================================================

def get_platform_stylesheet() -> str:
    """
    플랫폼 통일 스타일시트 반환

    Returns:
        PyQt6용 QSS 스타일시트 문자열
    """
    return f"""
    /* =========================================
       Global Styles
       ========================================= */

    * {{
        font-family: 'Pretendard', 'Segoe UI', 'Malgun Gothic', sans-serif;
    }}

    QMainWindow, QWidget {{
        background-color: {COLORS['bg_primary']};
        color: {COLORS['text_primary']};
    }}

    QToolTip {{
        background-color: {COLORS['bg_elevated']};
        color: {COLORS['text_primary']};
        border: 1px solid {COLORS['border_subtle']};
        border-radius: 4px;
        padding: 6px 10px;
    }}

    /* =========================================
       Group Boxes & Frames
       ========================================= */

    QGroupBox {{
        background-color: {COLORS['bg_secondary']};
        border: 1px solid {COLORS['border_subtle']};
        border-radius: 8px;
        margin-top: 16px;
        padding: 16px;
        padding-top: 24px;
        font-weight: 500;
    }}

    QGroupBox::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 12px;
        padding: 0 8px;
        color: {COLORS['text_primary']};
        background-color: {COLORS['bg_secondary']};
    }}

    QFrame {{
        background-color: transparent;
    }}

    QFrame#deviceCard {{
        background-color: {COLORS['bg_secondary']};
        border: 1px solid {COLORS['border_subtle']};
        border-radius: 8px;
        padding: 12px;
    }}

    QFrame#deviceCard:hover {{
        border-color: {COLORS['border_default']};
    }}

    QFrame#deviceCardSelected {{
        background-color: rgba(212, 165, 116, 0.1);
        border: 1px solid {COLORS['brand_primary']};
        border-radius: 8px;
        padding: 12px;
    }}

    /* =========================================
       Buttons
       ========================================= */

    QPushButton {{
        background-color: {COLORS['bg_tertiary']};
        border: 1px solid {COLORS['border_subtle']};
        border-radius: 6px;
        padding: 8px 16px;
        color: {COLORS['text_primary']};
        font-weight: 500;
        min-height: 20px;
    }}

    QPushButton:hover {{
        background-color: {COLORS['bg_hover']};
        border-color: {COLORS['border_default']};
    }}

    QPushButton:pressed {{
        background-color: {COLORS['bg_active']};
    }}

    QPushButton:disabled {{
        background-color: {COLORS['bg_tertiary']};
        color: {COLORS['text_tertiary']};
        border-color: {COLORS['border_muted']};
    }}

    /* Primary Button */
    QPushButton#primaryButton {{
        background-color: {COLORS['brand_primary']};
        border: none;
        color: {COLORS['bg_primary']};
        font-weight: 600;
    }}

    QPushButton#primaryButton:hover {{
        background-color: {COLORS['brand_accent']};
    }}

    QPushButton#primaryButton:pressed {{
        background-color: {COLORS['brand_secondary']};
    }}

    QPushButton#primaryButton:disabled {{
        background-color: {COLORS['brand_tertiary']};
        color: {COLORS['bg_hover']};
    }}

    /* Danger Button */
    QPushButton#dangerButton {{
        background-color: {COLORS['error']};
        border: none;
        color: white;
    }}

    QPushButton#dangerButton:hover {{
        background-color: #ff6b63;
    }}

    /* Icon Button */
    QPushButton#iconButton {{
        background-color: transparent;
        border: none;
        padding: 8px;
        border-radius: 4px;
    }}

    QPushButton#iconButton:hover {{
        background-color: {COLORS['bg_hover']};
    }}

    /* =========================================
       Labels
       ========================================= */

    QLabel {{
        color: {COLORS['text_primary']};
        background-color: transparent;
    }}

    QLabel#headerLabel {{
        font-size: 18px;
        font-weight: 600;
        color: {COLORS['text_primary']};
    }}

    QLabel#subheaderLabel {{
        font-size: 14px;
        font-weight: 500;
        color: {COLORS['text_secondary']};
    }}

    QLabel#mutedLabel {{
        color: {COLORS['text_tertiary']};
        font-size: 12px;
    }}

    QLabel#statusReady {{
        color: {COLORS['success']};
        font-weight: 500;
    }}

    QLabel#statusBusy {{
        color: {COLORS['warning']};
        font-weight: 500;
    }}

    QLabel#statusError {{
        color: {COLORS['error']};
        font-weight: 500;
    }}

    QLabel#statusLocked {{
        color: {COLORS['text_tertiary']};
        font-weight: 500;
    }}

    /* =========================================
       Checkboxes
       ========================================= */

    QCheckBox {{
        color: {COLORS['text_primary']};
        spacing: 8px;
    }}

    QCheckBox:disabled {{
        color: {COLORS['text_tertiary']};
    }}

    QCheckBox::indicator {{
        width: 18px;
        height: 18px;
        border: 2px solid {COLORS['border_subtle']};
        border-radius: 4px;
        background-color: {COLORS['bg_secondary']};
    }}

    QCheckBox::indicator:hover {{
        border-color: {COLORS['border_default']};
    }}

    QCheckBox::indicator:checked {{
        background-color: {COLORS['brand_primary']};
        border-color: {COLORS['brand_primary']};
    }}

    QCheckBox::indicator:checked:hover {{
        background-color: {COLORS['brand_accent']};
        border-color: {COLORS['brand_accent']};
    }}

    QCheckBox::indicator:disabled {{
        background-color: {COLORS['bg_tertiary']};
        border-color: {COLORS['border_muted']};
    }}

    /* =========================================
       Input Fields
       ========================================= */

    QLineEdit, QTextEdit, QPlainTextEdit {{
        background-color: {COLORS['bg_tertiary']};
        border: 1px solid {COLORS['border_subtle']};
        border-radius: 6px;
        padding: 8px 12px;
        color: {COLORS['text_primary']};
        selection-background-color: {COLORS['brand_primary']};
        selection-color: {COLORS['bg_primary']};
    }}

    QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
        border-color: {COLORS['brand_primary']};
    }}

    QLineEdit:disabled, QTextEdit:disabled {{
        background-color: {COLORS['bg_secondary']};
        color: {COLORS['text_tertiary']};
    }}

    QLineEdit::placeholder {{
        color: {COLORS['text_tertiary']};
    }}

    /* =========================================
       Combo Box
       ========================================= */

    QComboBox {{
        background-color: {COLORS['bg_tertiary']};
        border: 1px solid {COLORS['border_subtle']};
        border-radius: 6px;
        padding: 8px 12px;
        color: {COLORS['text_primary']};
        min-width: 100px;
    }}

    QComboBox:hover {{
        border-color: {COLORS['border_default']};
    }}

    QComboBox::drop-down {{
        border: none;
        width: 24px;
    }}

    QComboBox::down-arrow {{
        image: none;
        border-left: 5px solid transparent;
        border-right: 5px solid transparent;
        border-top: 6px solid {COLORS['text_secondary']};
        margin-right: 8px;
    }}

    QComboBox QAbstractItemView {{
        background-color: {COLORS['bg_elevated']};
        border: 1px solid {COLORS['border_subtle']};
        border-radius: 6px;
        selection-background-color: {COLORS['bg_hover']};
        selection-color: {COLORS['text_primary']};
        outline: none;
    }}

    /* =========================================
       Progress Bar
       ========================================= */

    QProgressBar {{
        background-color: {COLORS['bg_tertiary']};
        border: none;
        border-radius: 4px;
        height: 8px;
        text-align: center;
    }}

    QProgressBar::chunk {{
        background-color: {COLORS['brand_primary']};
        border-radius: 4px;
    }}

    /* Large progress bar */
    QProgressBar#largeProgress {{
        height: 12px;
        border-radius: 6px;
    }}

    QProgressBar#largeProgress::chunk {{
        border-radius: 6px;
    }}

    /* =========================================
       Scroll Area
       ========================================= */

    QScrollArea {{
        border: none;
        background-color: transparent;
    }}

    QScrollBar:vertical {{
        background-color: {COLORS['bg_secondary']};
        width: 10px;
        border-radius: 5px;
        margin: 0;
    }}

    QScrollBar::handle:vertical {{
        background-color: {COLORS['bg_hover']};
        border-radius: 5px;
        min-height: 30px;
    }}

    QScrollBar::handle:vertical:hover {{
        background-color: {COLORS['bg_active']};
    }}

    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical {{
        height: 0;
    }}

    QScrollBar:horizontal {{
        background-color: {COLORS['bg_secondary']};
        height: 10px;
        border-radius: 5px;
    }}

    QScrollBar::handle:horizontal {{
        background-color: {COLORS['bg_hover']};
        border-radius: 5px;
        min-width: 30px;
    }}

    /* =========================================
       List Widget
       ========================================= */

    QListWidget {{
        background-color: {COLORS['bg_secondary']};
        border: 1px solid {COLORS['border_subtle']};
        border-radius: 8px;
        outline: none;
    }}

    QListWidget::item {{
        padding: 10px 12px;
        border-bottom: 1px solid {COLORS['border_muted']};
        color: {COLORS['text_primary']};
    }}

    QListWidget::item:last {{
        border-bottom: none;
    }}

    QListWidget::item:hover {{
        background-color: {COLORS['bg_hover']};
    }}

    QListWidget::item:selected {{
        background-color: rgba(212, 165, 116, 0.15);
        color: {COLORS['text_primary']};
    }}

    /* =========================================
       Tab Widget
       ========================================= */

    QTabWidget::pane {{
        border: 1px solid {COLORS['border_subtle']};
        border-radius: 8px;
        background-color: {COLORS['bg_secondary']};
        top: -1px;
    }}

    QTabBar::tab {{
        background-color: transparent;
        border: 1px solid transparent;
        border-bottom: none;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        padding: 10px 20px;
        margin-right: 4px;
        color: {COLORS['text_secondary']};
    }}

    QTabBar::tab:hover {{
        background-color: {COLORS['bg_hover']};
        color: {COLORS['text_primary']};
    }}

    QTabBar::tab:selected {{
        background-color: {COLORS['bg_secondary']};
        border-color: {COLORS['border_subtle']};
        color: {COLORS['text_primary']};
    }}

    /* =========================================
       Splitter
       ========================================= */

    QSplitter::handle {{
        background-color: {COLORS['border_subtle']};
    }}

    QSplitter::handle:horizontal {{
        width: 2px;
    }}

    QSplitter::handle:vertical {{
        height: 2px;
    }}

    /* =========================================
       Status Bar
       ========================================= */

    QStatusBar {{
        background-color: {COLORS['bg_secondary']};
        border-top: 1px solid {COLORS['border_subtle']};
        color: {COLORS['text_secondary']};
    }}

    /* =========================================
       Menu
       ========================================= */

    QMenuBar {{
        background-color: {COLORS['bg_secondary']};
        border-bottom: 1px solid {COLORS['border_subtle']};
        color: {COLORS['text_primary']};
    }}

    QMenuBar::item {{
        padding: 8px 12px;
        background-color: transparent;
    }}

    QMenuBar::item:selected {{
        background-color: {COLORS['bg_hover']};
    }}

    QMenu {{
        background-color: {COLORS['bg_elevated']};
        border: 1px solid {COLORS['border_subtle']};
        border-radius: 6px;
        padding: 4px;
    }}

    QMenu::item {{
        padding: 8px 24px;
        border-radius: 4px;
        color: {COLORS['text_primary']};
    }}

    QMenu::item:selected {{
        background-color: {COLORS['bg_hover']};
    }}

    QMenu::separator {{
        height: 1px;
        background-color: {COLORS['border_subtle']};
        margin: 4px 8px;
    }}

    /* =========================================
       Dialog
       ========================================= */

    QDialog {{
        background-color: {COLORS['bg_primary']};
    }}

    QMessageBox {{
        background-color: {COLORS['bg_primary']};
    }}

    QMessageBox QLabel {{
        color: {COLORS['text_primary']};
    }}
    """


# =============================================================================
# Helper Functions
# =============================================================================

def get_status_color(status: str) -> str:
    """
    상태에 따른 색상 반환

    Args:
        status: 'ready', 'busy', 'error', 'locked'

    Returns:
        색상 코드
    """
    status_colors = {
        'ready': COLORS['success'],
        'busy': COLORS['warning'],
        'error': COLORS['error'],
        'locked': COLORS['text_tertiary'],
    }
    return status_colors.get(status.lower(), COLORS['text_secondary'])


def get_device_type_color(device_type: str) -> str:
    """
    디바이스 유형에 따른 색상 반환

    Args:
        device_type: 디바이스 유형 문자열

    Returns:
        색상 코드
    """
    type_colors = {
        'WINDOWS_PHYSICAL_DISK': '#60a5fa',  # blue
        'ANDROID_DEVICE': '#34d399',          # green
        'IOS_BACKUP': '#a78bfa',              # purple
        'E01_IMAGE': '#fb923c',               # orange
        'RAW_IMAGE': '#fbbf24',               # yellow
    }
    return type_colors.get(device_type, COLORS['text_secondary'])
