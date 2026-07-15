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
    "wizard.step.token": "Enter key",
    "wizard.step.source": "Choose target",
    "wizard.step.status": "Check status",
    "wizard.token.kicker": "STEP 1 OF 3",
    "wizard.token.title": "Enter the collection key",
    "wizard.token.description": (
        "Use the key issued from the case page to connect this tool to the "
        "correct analysis space."
    ),
    "wizard.token.group": "Collection key",
    "wizard.token.help": (
        "Paste the key exactly as shown on the web case page. Keep it private."
    ),
    "wizard.token.continue": "Connect and continue",
    "wizard.source.kicker": "STEP 2 OF 3",
    "wizard.source.title": "Choose what to analyze",
    "wizard.source.description": (
        "Choose the computer, phone, evidence file, or tool result that contains "
        "the data you want to send."
    ),
    "wizard.source.group": "Analysis target",
    "wizard.status.kicker": "STEP 3 OF 3",
    "wizard.status.title": "Collection and upload status",
    "wizard.status.description": (
        "Keep this program open until every stage is complete. Technical details "
        "are available only when you need them."
    ),
    "wizard.status.complete": (
        "Collection and upload are complete. Return to the case page to continue analysis."
    ),
    "wizard.status.failed": (
        "Collection did not complete. Open the technical log to review the cause."
    ),
    "wizard.button.back": "Back",
    "wizard.button.new_collection": "Start another collection",
    "wizard.progress.overall": "Overall",
    "wizard.progress.collect": "1. Collect data",
    "wizard.progress.encrypt": "2. Protect data",
    "wizard.progress.upload": "3. Send data",
    "wizard.progress.ready": "Waiting to start",
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
        "{count} evidence sources selected. Choose the exact source from the "
        "details below before starting."
    ),
    "simple.source.local.empty": (
        "No ready local disk was detected. Click Refresh below "
        "or restart the collector with administrator privileges."
    ),
    "simple.source.local.multiple": (
        "Multiple local sources are available. Choose the exact disk below."
    ),
    "simple.source.phone.empty": (
        "No ready phone source was detected. Connect the device, approve the "
        "device prompt, then refresh."
    ),
    "simple.source.phone.multiple": (
        "Multiple phone sources are available. Choose the exact device or backup below."
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
    "simple.caption.local": "Use this computer or an attached local drive.",
    "simple.caption.phone": "Use an authorized iOS or Android source.",
    "simple.caption.evidence": "Open a disk image, virtual disk, or mobile FFS bundle.",
    "simple.caption.tool": "Upload a verified result from a supported forensic tool.",
    "simple.detected.title": "Detected now",
    "simple.detected.empty": "No ready source has been detected yet.",
    "simple.detected.summary": (
        "{total} ready source(s): {local} PC/drive, {phone} phone/mobile, "
        "{image} evidence file, {tool} tool result."
    ),
    "simple.next.title": "Next step",
    "simple.next.body": (
        "Choose one source. The recommended collection scope is applied "
        "automatically after authentication."
    ),
    "simple.detail.title": "Evidence source details",
    "simple.detail.caption": "Choose one or more detected sources.",
    "simple.detail.caption.local": "Choose one or more local computers or drives to collect.",
    "simple.detail.caption.phone": "Choose one or more connected phones, backups, or mobile FFS bundles.",
    "simple.detail.caption.image": "Choose one or more registered disk images or mobile FFS bundles.",
    "simple.detail.caption.tool": "Choose one or more registered forensic tool results.",
    "simple.detail.open": "Open...",
    "simple.detail.refresh": "Refresh",
    "simple.detail.empty": "No matching source is available yet.",
    "simple.detail.empty.local": (
        "No local drive is ready. Run as administrator and click Refresh."
    ),
    "simple.detail.empty.phone": (
        "No phone source is ready. Connect the device, approve the device prompt, "
        "then click Refresh."
    ),
    "simple.detail.empty.image": (
        "No evidence file has been registered yet. Click Open to add one."
    ),
    "simple.detail.empty.tool": (
        "No tool result has been registered yet. Use Add Tool Result above."
    ),
    "simple.selected.title": "Selected analysis media",
    "simple.selected.empty": "No analysis media selected.",
    "simple.selected.summary": "{count} analysis media selected. Review the list before starting collection.",
    "simple.selected.remove": "Remove",
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
        "Step 3 needed: collection scope is not ready. Check authentication and source selection."
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
    "step.scope.choose": "No authorized artifact targets are available.",
    "step.scope.locked": "Collection scope is enabled after authentication.",
    "step.start.ready": "Ready to start collection.",
    "step.start.incomplete": "Complete the required steps above.",
    "group.connect": "1. Connect Case",
    "group.progress": "Collection Progress",
    "group.status": "Collection Status",
    "group.technical_log": "Technical Activity Log",
    "token.placeholder": "Paste the collection key from the web case",
    "token.show": "Show",
    "token.hide": "Hide",
    "token.validate": "Validate Token",
    "token.validating": "Validating...",
    "token.status.validating": "Validating token...",
    "log.show": "Show technical activity log",
    "button.start": "Start Collection",
    "button.cancel": "Cancel",
    "header.language": "Language",
}

BUILTIN_LOCALE_MESSAGES: Dict[str, Dict[str, str]] = {}


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
        builtin_messages = BUILTIN_LOCALE_MESSAGES.get(self._locale, {})
        template = self._messages.get(
            key,
            builtin_messages.get(key, DEFAULT_MESSAGES.get(key, key)),
        )
        if not kwargs:
            return template
        try:
            return template.format(**kwargs)
        except Exception:
            return DEFAULT_MESSAGES.get(key, key)

    def locale_label(self, locale_code: str) -> str:
        return LOCALE_LABELS.get(normalize_locale(locale_code), LOCALE_LABELS["en"])
