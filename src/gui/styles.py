# -*- coding: utf-8 -*-
"""
Platform Unified Theme Stylesheet

Implements a dark theme for PyQt6, matching the web platform.
Uses platform brand colors.

Usage:
    from gui.styles import get_platform_stylesheet, COLORS

    app = QApplication(sys.argv)
    app.setStyleSheet(get_platform_stylesheet())
"""


# =============================================================================
# Color Palette (from tailwind.config.js)
# =============================================================================

COLORS = {
    # Background colors
    'bg_primary': '#0d1117',
    'bg_secondary': '#161b22',
    'bg_tertiary': '#21262d',
    'bg_elevated': '#1c2128',
    'bg_hover': '#30363d',
    'bg_active': '#484f58',

    # Text colors
    'text_primary': '#f0f6fc',
    'text_secondary': '#8b949e',
    'text_tertiary': '#6e7681',
    'text_link': '#58a6ff',

    # Brand colors
    'brand_primary': '#d4a574',
    'brand_secondary': '#b8956e',
    'brand_tertiary': '#9c7d5c',
    'brand_accent': '#e8c49a',

    # Status colors
    'success': '#3fb950',
    'success_bg': 'rgba(63, 185, 80, 0.15)',
    'warning': '#d29922',
    'warning_bg': 'rgba(210, 153, 34, 0.15)',
    'error': '#f85149',
    'error_bg': 'rgba(248, 81, 73, 0.15)',
    'info': '#58a6ff',
    'info_bg': 'rgba(88, 166, 255, 0.15)',

    # Border colors
    'border_subtle': '#30363d',
    'border_default': '#484f58',
    'border_muted': '#21262d',

    # Artifact type colors
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
    Returns the platform unified stylesheet.

    Returns:
        QSS stylesheet string for PyQt6
    """
    return f"""
    /* =========================================
       Global Styles
       ========================================= */

    * {{
        font-family: 'Malgun Gothic', 'Segoe UI', sans-serif;
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
        border-radius: 6px;
        margin-top: 8px;
        padding: 6px;
        padding-top: 14px;
        font-weight: 500;
        font-size: 11px;
    }}

    QGroupBox::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 8px;
        padding: 0 6px;
        color: {COLORS['brand_primary']};
        background-color: {COLORS['bg_secondary']};
        font-size: 11px;
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
        border-radius: 4px;
        padding: 4px 12px;
        color: {COLORS['text_primary']};
        font-weight: 500;
        font-size: 11px;
        min-height: 16px;
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
        font-size: 14px;
        font-weight: 600;
        color: {COLORS['text_primary']};
    }}

    QLabel#subheaderLabel {{
        font-size: 12px;
        font-weight: 500;
        color: {COLORS['text_secondary']};
    }}

    QLabel#mutedLabel {{
        color: {COLORS['text_tertiary']};
        font-size: 10px;
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
        spacing: 6px;
        font-size: 11px;
    }}

    QCheckBox:disabled {{
        color: {COLORS['text_tertiary']};
    }}

    QCheckBox::indicator {{
        width: 14px;
        height: 14px;
        border: 1px solid {COLORS['border_subtle']};
        border-radius: 3px;
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
        border-radius: 4px;
        padding: 4px 8px;
        color: {COLORS['text_primary']};
        font-size: 11px;
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
        border-radius: 4px;
        padding: 4px 8px;
        color: {COLORS['text_primary']};
        font-size: 11px;
        min-width: 80px;
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
        border-radius: 3px;
        height: 6px;
        text-align: center;
        font-size: 9px;
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
        border-radius: 4px;
        outline: none;
        font-size: 10px;
    }}

    QListWidget::item {{
        padding: 4px 8px;
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
        border-radius: 4px;
        background-color: {COLORS['bg_secondary']};
        top: -1px;
    }}

    QTabBar::tab {{
        background-color: transparent;
        border: 1px solid transparent;
        border-bottom: none;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
        padding: 6px 12px;
        margin-right: 2px;
        color: {COLORS['text_secondary']};
        font-size: 11px;
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
        font-size: 10px;
        padding: 2px 8px;
    }}

    /* =========================================
       Menu
       ========================================= */

    QMenuBar {{
        background-color: {COLORS['bg_secondary']};
        border-bottom: 1px solid {COLORS['border_subtle']};
        color: {COLORS['text_primary']};
        font-size: 11px;
    }}

    QMenuBar::item {{
        padding: 4px 8px;
        background-color: transparent;
    }}

    QMenuBar::item:selected {{
        background-color: {COLORS['bg_hover']};
    }}

    QMenu {{
        background-color: {COLORS['bg_elevated']};
        border: 1px solid {COLORS['border_subtle']};
        border-radius: 4px;
        padding: 2px;
        font-size: 11px;
    }}

    QMenu::item {{
        padding: 4px 16px;
        border-radius: 3px;
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


