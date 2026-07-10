# -*- coding: utf-8 -*-
"""
Public-safe UI translation helpers.

The open-source collector keeps English defaults in source code. Private or
customer builds can provide locale JSON files without changing application
logic. Lookup order:

1. COLLECTOR_LOCALE_DIR/<locale>.json
2. bundled locales/<locale>.json next to the frozen app payload
3. ~/.forensic-collector/locales/<locale>.json

Missing keys and missing locale files always fall back to English.
"""

import json
import locale as system_locale
import os
import sys
from pathlib import Path
from typing import Dict, Optional


SUPPORTED_LOCALES = ("en", "ko", "ja")
LOCALE_LABELS = {
    "en": "English",
    "ko": "Korean",
    "ja": "Japanese",
}

USER_CONFIG_DIR = Path.home() / ".forensic-collector"
USER_CONFIG_FILE = USER_CONFIG_DIR / "config.json"


DEFAULT_MESSAGES: Dict[str, str] = {
    "simple.title": "Simple Collection",
    "simple.intro": (
        "Collect evidence in three steps: connect the case, choose the "
        "evidence source, then start collection."
    ),
    "simple.choose_source": "Choose one evidence source type:",
    "simple.source.none": (
        "No evidence source selected. Choose this PC, a phone, an evidence "
        "file, or a verified tool result."
    ),
    "simple.source.selected": "Selected source: {source}",
    "simple.source.multiple": (
        "{count} evidence sources selected. Use expert controls to confirm "
        "the scope before starting."
    ),
    "simple.source.local.empty": (
        "No ready local disk was detected. Click Refresh in expert controls "
        "or restart the collector with administrator privileges."
    ),
    "simple.source.local.multiple": (
        "Multiple local sources are available. Expert controls were opened "
        "so you can choose the exact disk."
    ),
    "simple.source.phone.empty": (
        "No ready phone source was detected. Connect the device, approve the "
        "device prompt, then refresh."
    ),
    "simple.source.phone.multiple": (
        "Multiple phone sources are available. Expert controls were opened "
        "so you can choose the exact device or backup."
    ),
    "simple.btn.local": "This PC / Drive",
    "simple.btn.local.tooltip": "Select a local disk or local system source.",
    "simple.btn.phone": "Phone",
    "simple.btn.phone.tooltip": "Select an authorized iOS or Android source.",
    "simple.btn.evidence": "Add Evidence File",
    "simple.btn.evidence.tooltip": (
        "Add E01, RAW, VMDK, VDI, VHD, DMG, or mobile FFS."
    ),
    "simple.btn.tool": "Add Tool Result",
    "simple.btn.tool.tooltip": (
        "Add a verified AXIOM, Cellebrite, or Autopsy result."
    ),
    "simple.expert_toggle": "Show expert / backup controls",
    "simple.status.ready": (
        "Ready. Connect a case and choose an evidence source to begin."
    ),
    "simple.status.collecting": (
        "Collection is running. Keep this window open until upload completes."
    ),
    "simple.status.validating": (
        "Validating the collection key. Please wait."
    ),
    "simple.status.ready_to_collect": (
        "Ready to collect. Review the selected source, then click Start Collection."
    ),
    "simple.status.need_token": (
        "Step 1 needed: paste the collection key from the web case and validate it."
    ),
    "simple.status.need_source": (
        "Step 2 needed: choose this PC, a phone, an evidence file, or a tool result."
    ),
    "simple.status.need_scope": (
        "Step 3 needed: collection scope is not ready. Open expert controls if needed."
    ),
    "step.connect.title": "Connect case",
    "step.evidence.title": "Choose evidence",
    "step.scope.title": "Confirm scope",
    "step.start.title": "Start collection",
    "step.state.done": "Done",
    "step.state.needed": "Needed",
    "step.token.validating": "Validating session token...",
    "step.token.validated": "Authenticated case: {case}",
    "step.token.empty": "Paste the collection key from the web case and validate it.",
    "step.source.empty": (
        "Select a local drive, connected device, image file, FFS bundle, or "
        "verified tool result."
    ),
    "step.scope.mixed": (
        "{artifact_count} artifact type(s) and {tool_count} verified tool "
        "result source(s) selected."
    ),
    "step.scope.tool": "{tool_count} verified tool result source(s) selected.",
    "step.scope.artifacts": "{artifact_count} artifact type(s) selected.",
    "step.scope.choose": "Open advanced options to choose artifacts.",
    "step.scope.locked": "Collection scope is enabled after authentication.",
    "step.start.ready": "Ready to start collection.",
    "step.start.incomplete": "Complete the required steps above.",
    "group.connect": "1. Connect Case",
    "group.source_details": "2. Evidence Source Details",
    "group.expert_scope": "3. Expert Collection Scope",
    "group.progress": "Collection Progress",
    "group.status": "Collection Status",
    "group.technical_log": "Technical Activity Log",
    "token.placeholder": "Paste the collection key from the web case",
    "token.show": "Show",
    "token.validate": "Validate Token",
    "token.validating": "Validating...",
    "token.status.validating": "Validating token...",
    "scope.advanced": "Show advanced artifact options",
    "scope.select_all": "Select All (current tab)",
    "scope.deleted": "Include deleted files",
    "scope.deleted.tooltip": (
        "Recover and collect deleted files from MFT (slower but more thorough)"
    ),
    "scope.summary.auth_first": (
        "Authenticate first. The server profile will enable the allowed "
        "artifact set automatically."
    ),
    "scope.summary.deleted_on": "Deleted files included where supported.",
    "scope.summary.deleted_off": "Deleted files excluded.",
    "scope.summary.mixed": (
        "Scope ready: {checked} selected artifact type(s) out of {enabled} "
        "allowed, plus {tool_count} verified tool result source(s). {deleted}"
    ),
    "scope.summary.artifacts": (
        "Recommended scope ready: {checked} selected artifact type(s) out of "
        "{enabled} allowed. {deleted}"
    ),
    "scope.summary.tool": (
        "Verified tool result scope ready: {tool_count} source(s). Server "
        "parsing will expand AXIOM, Cellebrite, or Autopsy results into "
        "searchable documents."
    ),
    "scope.summary.empty": (
        "No artifact type selected. Open advanced options to choose artifacts. "
        "{enabled} artifact type(s) are allowed."
    ),
    "log.show": "Show technical activity log",
    "button.start": "Start Collection",
    "button.cancel": "Cancel",
    "header.language": "Language",
}


def normalize_locale(value: Optional[str]) -> str:
    raw = (value or "").strip().lower().replace("-", "_")
    if not raw:
        return "en"
    code = raw.split("_", 1)[0]
    return code if code in SUPPORTED_LOCALES else "en"


def read_user_config() -> Dict[str, object]:
    if not USER_CONFIG_FILE.exists():
        return {}
    try:
        with open(USER_CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_user_locale(locale_code: str) -> bool:
    locale_code = normalize_locale(locale_code)
    try:
        USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        config = read_user_config()
        config["ui_language"] = locale_code
        with open(USER_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        return True
    except OSError:
        return False


def detect_locale(config: Optional[dict] = None) -> str:
    env_locale = os.environ.get("COLLECTOR_UI_LANGUAGE")
    if env_locale:
        return normalize_locale(env_locale)

    if config and config.get("ui_language"):
        return normalize_locale(str(config.get("ui_language")))

    user_config = read_user_config()
    if user_config.get("ui_language"):
        return normalize_locale(str(user_config.get("ui_language")))

    try:
        detected = system_locale.getlocale()[0]
    except (TypeError, ValueError):
        detected = None
    return normalize_locale(detected)


def _candidate_locale_dirs() -> list:
    dirs = []

    env_dir = os.environ.get("COLLECTOR_LOCALE_DIR")
    if env_dir:
        dirs.append(Path(env_dir))

    if getattr(sys, "frozen", False):
        base_dir = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
        dirs.append(base_dir / "locales")
    else:
        src_dir = Path(__file__).resolve().parents[1]
        dirs.append(src_dir.parent / "locales")

    dirs.append(USER_CONFIG_DIR / "locales")
    return dirs


def _load_locale_file(locale_code: str) -> Dict[str, str]:
    filename = f"{locale_code}.json"
    for directory in _candidate_locale_dirs():
        path = directory / filename
        if not path.exists():
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
        except (OSError, json.JSONDecodeError, UnicodeError):
            continue
    return {}


class I18n:
    def __init__(self, config: Optional[dict] = None):
        self._locale = "en"
        self._messages: Dict[str, str] = {}
        self.set_locale(detect_locale(config))

    @property
    def locale(self) -> str:
        return self._locale

    def set_locale(self, locale_code: str):
        self._locale = normalize_locale(locale_code)
        self._messages = _load_locale_file(self._locale)

    def tr(self, key: str, **kwargs) -> str:
        template = self._messages.get(key, DEFAULT_MESSAGES.get(key, key))
        if not kwargs:
            return template
        try:
            return template.format(**kwargs)
        except Exception:
            return DEFAULT_MESSAGES.get(key, key)

    def locale_label(self, locale_code: str) -> str:
        return LOCALE_LABELS.get(normalize_locale(locale_code), LOCALE_LABELS["en"])
