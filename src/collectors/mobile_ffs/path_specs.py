"""Declarative path specifications for known forensic artifacts on
Android and iOS Cellebrite UFED Full File System extractions.

Each spec maps an `artifact_type` (the label downstream parsers
dispatch on) to the path or path-glob inside an FFS dump where the
file is found.

Design intent:
  - **Single source of truth.** The same table drives both extraction
    (collector) and the not_extracted manifest (anything matching one
    of these specs but absent in the source container is recorded as
    "expected but absent").
  - **Public-collector safety.** Specs name application bundles using
    their public bundle identifiers only. They never name internal
    container schemes, never reference cryptographic primitives, and
    never disclose downstream interpretation strategies. The collector
    knows _what_ to collect, not _how_ the server interprets it.
  - **Auditable.** Adding a new artifact_type is a one-line change
    that an examiner can review against vendor documentation.

For iOS specs, `package` is the bundle id (e.g. `net.whatsapp.WhatsApp`)
and the path is *relative to the per-app data container*. The runtime
adapter resolves bundle id → UUID → absolute path inside the FFS dump
by parsing each app's `.com.apple.mobile_container_manager.metadata.plist`.

For Android specs, `package` is the package name (e.g. `com.whatsapp`)
and the path is relative to `/data/data/<package>/` inside the FFS
dump. Mapping is direct — no UUID resolution needed.

System-level paths (not tied to an app bundle) use `package=None` and
the path is relative to the appropriate filesystem root.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple


class ContainerKind(Enum):
    """Where in the FFS layout a file lives.

    For Android:
      APP_DATA          — /data/data/<package>/...
      SYSTEM            — /data/system/, /system/, /vendor/, etc.
      USER_MEDIA        — /sdcard/, /storage/emulated/0/...

    For iOS:
      APP_DATA          — Containers/Data/Application/<UUID>/...
      APP_GROUP         — Containers/Shared/AppGroup/<UUID>/...
      APP_BUNDLE        — Containers/Bundle/Application/<UUID>/<App>.app/...
      SYSTEM            — /private/var/mobile/Library/...
      ROOT_SYSTEM       — /System/, /usr/, /Library/ (rarely useful)
    """
    APP_DATA = "app_data"
    APP_GROUP = "app_group"
    APP_BUNDLE = "app_bundle"
    SYSTEM = "system"
    ROOT_SYSTEM = "root_system"
    USER_MEDIA = "user_media"


@dataclass(frozen=True)
class AndroidArtifactSpec:
    artifact_type: str
    package: str                 # e.g. "com.whatsapp"
    relative_path: str           # under /data/data/<package>/
    container_kind: ContainerKind = ContainerKind.APP_DATA
    description: str = ""
    # When True, `relative_path` is treated as a directory PREFIX —
    # the resolver fans out to every entry under it.
    is_directory: bool = False
    # When `is_directory=True` and non-empty, restrict children to
    # filenames ending in one of these suffixes (case-insensitive).
    child_suffix_filter: Tuple[str, ...] = ()
    # When `is_directory=True` and non-empty, ONLY children whose
    # basename matches one of these fnmatch-style globs are yielded.
    # Lets a single spec handle both the modern and legacy filename
    # of an app DB that has been renamed across versions
    # (e.g. Facebook Messenger `threads_db2*` -> `msys_database_*`),
    # and lets us pull the SQLite -wal / -shm sidecars by including
    # `<name>*` in the glob list.
    filename_globs: Tuple[str, ...] = ()

    @property
    def full_path_pattern(self) -> str:
        if self.container_kind == ContainerKind.APP_DATA:
            return f"data/data/{self.package}/{self.relative_path}"
        if self.container_kind == ContainerKind.SYSTEM:
            return self.relative_path
        return self.relative_path


@dataclass(frozen=True)
class IOSArtifactSpec:
    artifact_type: str
    package: Optional[str]       # bundle id e.g. "net.whatsapp.WhatsApp",
                                 # or None for system-level paths
    relative_path: str           # under per-app container, or absolute for SYSTEM
    container_kind: ContainerKind = ContainerKind.APP_DATA
    description: str = ""
    # When True, `relative_path` is treated as a directory PREFIX —
    # the resolver fans out to every entry under it (one resolved
    # artifact per child file). Used for cases like the lockdown
    # daemon directory where the meaningful unit is the per-record
    # file rather than the parent folder. Defaults to False to keep
    # legacy specs unchanged.
    is_directory: bool = False
    # When True, the resolver ALSO pulls the SQLite -wal and -shm
    # sidecar files (if present) alongside the primary .db. Without
    # them, transactional state still in WAL is invisible to the
    # parser pipeline — this matters for deleted-row recovery and
    # for any DB the OS hasn't checkpointed before acquisition.
    pull_sqlite_sidecars: bool = False
    # When `is_directory=True` and this tuple is non-empty, the
    # resolver fans out only to children whose filename matches one
    # of the suffixes here (case-insensitive). Used to keep
    # directory dispatch from pulling in thousands of binary index
    # files when only the SQLite portion is forensically usable
    # (e.g. CoreSpotlight where only `.store.db` matters).
    child_suffix_filter: Tuple[str, ...] = ()


# =============================================================================
# Android path specs — neutral artifact_type names, public package ids only
# =============================================================================
ANDROID_PATH_SPECS: Tuple[AndroidArtifactSpec, ...] = (
    # System-level core artifacts (no app package). artifact_type values
    # mirror the server-side ArtifactType enum so the collector ships
    # uploads with labels that route directly into the existing parser
    # dispatch table — no enum churn required.
    AndroidArtifactSpec(
        artifact_type="mobile_android_sms",
        package="com.android.providers.telephony",
        relative_path="databases/mmssms.db",
        description="Android system SMS/MMS database",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_contacts",
        package="com.android.providers.contacts",
        relative_path="databases/contacts2.db",
        description="Android system contacts database",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_call",
        package="com.android.providers.contacts",
        relative_path="databases/calllog.db",
        description="Android call log database",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_calendar_provider",
        package="com.android.providers.calendar",
        relative_path="databases/calendar.db",
        description="Android calendar provider database",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_app_install_history",
        package="android",
        relative_path="data/system/packages.xml",
        container_kind=ContainerKind.SYSTEM,
        description="Android package manager state",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_chrome",
        package="com.android.chrome",
        relative_path="app_chrome/Default/History",
        description="Chrome browser history database",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_samsung_browser",
        package="com.sec.android.app.sbrowser",
        relative_path="app_sbrowser/Default/History",
        description="Samsung Internet browser history",
    ),
    # Third-party messengers — bundle IDs are public
    AndroidArtifactSpec(
        artifact_type="mobile_android_whatsapp",
        package="com.whatsapp",
        relative_path="databases/msgstore.db",
        description="WhatsApp message store",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_telegram",
        package="org.telegram.messenger",
        relative_path="files/cache4.db",
        description="Telegram cache database",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_line",
        package="jp.naver.line.android",
        relative_path="databases/naver_line",
        description="LINE message database",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_viber",
        package="com.viber.voip",
        relative_path="databases/viber_messages",
        description="Viber message database",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_facebook_messenger",
        package="com.facebook.orca",
        relative_path="databases",
        description="Facebook Messenger database (covers both legacy threads_db2 and modern msys_database_<USER_ID>)",
        is_directory=True,
        # Modern FB Messenger (Android 12+) stores the chat DB at
        # databases/msys_database_<USER_ID>. Older versions used
        # databases/threads_db2. The glob handles both, plus their
        # SQLite -wal / -shm sidecars (which the suffix `*` catches).
        filename_globs=(
            "msys_database_*",
            "threads_db2*",
        ),
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_signal",
        package="org.thoughtcrime.securesms",
        relative_path="databases/signal.db",
        description="Signal message database",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_discord",
        package="com.discord",
        relative_path="cache/STORE.db",
        description="Discord LevelDB store",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_instagram",
        package="com.instagram.android",
        relative_path="databases/direct.db",
        description="Instagram direct messages",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_snapchat",
        package="com.snapchat.android",
        relative_path="databases/arroyo.db",
        description="Snapchat arroyo database",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_kakaotalk",
        package="com.kakao.talk",
        relative_path="databases/KakaoTalk.db",
        description="KakaoTalk message database",
    ),
    # === Samsung Pay / Samsung Wallet (Phase 1H gap #2) ===
    # Samsung Pay was renamed to Samsung Wallet in 2022. Both
    # versions share the com.samsung.android.spay package id and
    # store transactional/card data in app-data SQLite databases.
    # Three primary databases per public Android forensics references
    # (Cellebrite Physical Analyzer + Belkasoft + Magnet AXIOM):
    AndroidArtifactSpec(
        artifact_type="mobile_android_samsung_pay",
        package="com.samsung.android.spay",
        relative_path="databases/pay.db",
        description="Samsung Pay payment transaction history",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_samsung_pay_cards",
        package="com.samsung.android.spay",
        relative_path="databases/card.db",
        description="Samsung Pay enrolled cards",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_samsung_pay_transit",
        package="com.samsung.android.spay",
        relative_path="databases/transit.db",
        description="Samsung Pay transit cards",
    ),
    # === Round 7 Phase 2 — DFIR baseline gap closure ===
    AndroidArtifactSpec(
        artifact_type="mobile_android_bluetooth_pairings",
        package="android",
        relative_path="data/misc/bluedroid/bt_config.conf",
        container_kind=ContainerKind.SYSTEM,
        description="Bluedroid paired devices (MACs, names, last-connected)",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_dropbox_logs",
        package="android",
        relative_path="data/system/dropbox",
        container_kind=ContainerKind.SYSTEM,
        is_directory=True,
        description="System dropbox logs (boot/restart/app crashes)",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_batterystats",
        package="android",
        relative_path="data/system/batterystats.bin",
        container_kind=ContainerKind.SYSTEM,
        description="Per-app wake/run intervals (binary)",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_downloads",
        package="com.android.providers.downloads",
        relative_path="databases/downloads.db",
        description="System downloads provider (URL, filename, status)",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_chrome_cookies",
        package="com.android.chrome",
        relative_path="app_chrome/Default/Cookies",
        description="Chrome cookies (session/login attribution)",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_chrome_login_data",
        package="com.android.chrome",
        relative_path="app_chrome/Default/Login Data",
        description="Chrome saved-credential metadata",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_chrome_bookmarks",
        package="com.android.chrome",
        relative_path="app_chrome/Default/Bookmarks",
        description="Chrome bookmarks (JSON)",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_google_maps",
        package="com.google.android.apps.maps",
        relative_path="databases/gmm_storage.db",
        description="Google Maps searches, places, routes",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_google_pay",
        package="com.google.android.gms",
        relative_path="databases/android_pay",
        description="Google Wallet / Pay card history (no extension)",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_locksettings",
        package="android",
        relative_path="data/system/locksettings.db",
        container_kind=ContainerKind.SYSTEM,
        description="Lock screen attempt counters + lockout state",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_twitter",
        package="com.twitter.android",
        relative_path="databases/0-66.db",
        description="Twitter/X DMs + timeline cache",
    ),
    AndroidArtifactSpec(
        artifact_type="mobile_android_gmail",
        package="com.google.android.gm",
        relative_path="databases/EmailProvider.db",
        description="Gmail Email provider database",
    ),
    # ------------------------------------------------------------------
    # System-level: WiFi configuration (Android 11+ apexdata path).
    # Earlier releases stored saved-network state under
    # /data/misc/wifi/WifiConfigStore.xml; the apex packaging in
    # Android 11 moved the canonical copy under apexdata. Both paths
    # are still produced by Cellebrite FFS dumps; the apex copy is
    # the modern source of truth.
    # ------------------------------------------------------------------
    AndroidArtifactSpec(
        artifact_type="mobile_android_wifi",
        package=None,
        relative_path="data/misc/apexdata/com.android.wifi/WifiConfigStore.xml",
        container_kind=ContainerKind.SYSTEM,
        description="WiFi saved-networks store (Android 11+ apex path)",
    ),
    # ------------------------------------------------------------------
    # User-media directory fan-out: DCIM, Pictures, Download. These
    # are the three canonical user-photo / screenshot / received-file
    # locations on every Android device. Mounted under /sdcard which
    # is itself a symlink to /storage/self/primary or
    # /storage/emulated/0; Cellebrite FFS dumps surface them under
    # the ANDROID_DATA root.
    # ------------------------------------------------------------------
    AndroidArtifactSpec(
        artifact_type="mobile_android_media",
        package=None,
        relative_path="data/media/0",
        container_kind=ContainerKind.SYSTEM,
        description="User media root (DCIM, Pictures, Download, Movies)",
        is_directory=True,
        child_suffix_filter=(
            ".jpg", ".jpeg", ".png", ".heic", ".webp", ".gif", ".bmp",
            ".mp4", ".mov", ".m4v", ".3gp", ".mkv", ".webm",
            ".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".zip",
        ),
    ),

    # =========================================================================
    # Round 9 - Mobile AI Apps (Android, 2026-05-06)
    # =========================================================================
    AndroidArtifactSpec(
        artifact_type="ai_mobile_chatgpt",
        package="com.openai.chatgpt",
        relative_path="databases",
        description="ChatGPT Android - plaintext conversations DB, accounts, projects",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_chatgpt",
        package="com.openai.chatgpt",
        relative_path="files",
        description="ChatGPT Android - cached attachments, voice transcripts",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_chatgpt",
        package="com.openai.chatgpt",
        relative_path="cache",
        description="ChatGPT Android cache",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_claude",
        package="com.anthropic.claude",
        relative_path="databases",
        description="Claude Android - conversation cache databases",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_claude",
        package="com.anthropic.claude",
        relative_path="files",
        description="Claude Android - Artifacts (locally stored generated content)",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_claude",
        package="com.anthropic.claude",
        relative_path="shared_prefs",
        description="Claude Android - shared preferences (account, settings)",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_copilot",
        package="com.microsoft.copilot",
        relative_path="files",
        description="Microsoft Copilot Android - location data (~0.5 mile radius), prompts, browser data",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_copilot",
        package="com.microsoft.copilot",
        relative_path="databases",
        description="Microsoft Copilot Android databases",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_gemini",
        package="com.google.android.apps.bard",
        relative_path="databases",
        description="Google Gemini Android (formerly Bard) - conversation cache (cloud-first; minimal local)",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_gemini",
        package="com.google.android.apps.bard",
        relative_path="shared_prefs",
        description="Gemini Android preferences",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_perplexity",
        package="ai.perplexity.app.android",
        relative_path="databases",
        description="Perplexity Android - search and conversation cache",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_perplexity",
        package="ai.perplexity.app.android",
        relative_path="files",
        description="Perplexity Android files",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_replika",
        package="ai.replika.app",
        relative_path="files",
        description="Replika Android - **Realm DB**, conversation files",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_replika",
        package="ai.replika.app",
        relative_path="databases",
        description="Replika Android databases",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_otter",
        package="com.aisense.otter",
        relative_path="files",
        description="Otter.ai Android - **audio recordings + transcripts**",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_otter",
        package="com.aisense.otter",
        relative_path="databases",
        description="Otter.ai Android databases",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_deepseek",
        package="com.deepseek.chat",
        relative_path="databases",
        description="DeepSeek Android - 2025 viral Chinese AI",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_deepseek",
        package="com.deepseek.chat",
        relative_path="files",
        description="DeepSeek Android files",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_wrtn",
        package="com.wrtn.app",
        relative_path="databases",
        description="Wrtn Android - GenAI portal",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_wrtn",
        package="com.wrtn.app",
        relative_path="shared_prefs",
        description="Wrtn Android - Kakao/Naver/Google login state",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_character_ai",
        package="ai.character.app",
        relative_path="databases",
        description="Character.AI Android",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_poe",
        package="com.quora.poe",
        relative_path="databases",
        description="Poe (Quora) Android - aggregator app",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_grok",
        package="ai.x.grok",
        relative_path="databases",
        description="Grok (xAI) Android",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_le_chat",
        package="ai.mistral.chat",
        relative_path="databases",
        description="Mistral Le Chat Android",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_meta_ai",
        package="com.facebook.stella",
        relative_path="databases",
        description="Meta AI Android (com.facebook.stella, April 2025)",
        is_directory=True,
    ),
    AndroidArtifactSpec(
        artifact_type="ai_mobile_pi",
        package="ai.inflection.pi",
        relative_path="databases",
        description="Pi by Inflection Android",
        is_directory=True,
    ),
)


# =============================================================================
# iOS path specs — system DBs by absolute path, app DBs by bundle id
# =============================================================================
IOS_PATH_SPECS: Tuple[IOSArtifactSpec, ...] = (
    # System databases at well-known absolute paths.
    # artifact_type values mirror the server-side ArtifactType enum
    # so each upload is dispatch-routable without adding new enum
    # values (server already has these).
    IOSArtifactSpec(
        artifact_type="mobile_ios_sms",
        package=None,
        relative_path="private/var/mobile/Library/SMS/sms.db",
        container_kind=ContainerKind.SYSTEM,
        description="iOS SMS / iMessage database",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_call",
        package=None,
        relative_path="private/var/mobile/Library/CallHistoryDB/CallHistory.storedata",
        container_kind=ContainerKind.SYSTEM,
        description="iOS call history (CallHistoryDB)",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_contacts",
        package=None,
        relative_path="private/var/mobile/Library/AddressBook/AddressBook.sqlitedb",
        container_kind=ContainerKind.SYSTEM,
        description="iOS contacts (AddressBook)",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_safari",
        package=None,
        relative_path="private/var/mobile/Library/Safari/History.db",
        container_kind=ContainerKind.SYSTEM,
        description="Safari browser history",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_safari_bookmarks",
        package=None,
        relative_path="private/var/mobile/Library/Safari/Bookmarks.db",
        container_kind=ContainerKind.SYSTEM,
        description="Safari bookmarks",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_notes",
        package=None,
        relative_path="private/var/mobile/Library/Notes/notes.sqlite",
        container_kind=ContainerKind.SYSTEM,
        description="iOS Notes database (legacy iOS 9-)",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_notes",
        package=None,
        relative_path="private/var/mobile/Containers/Shared/AppGroup",
        container_kind=ContainerKind.SYSTEM,
        is_directory=True,
        child_suffix_filter=("NoteStore.sqlite",),
        description="iOS Notes database (modern iOS 9+, AppGroup-scoped)",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_calendar",
        package=None,
        relative_path="private/var/mobile/Library/Calendar/Calendar.sqlitedb",
        container_kind=ContainerKind.SYSTEM,
        description="iOS Calendar database",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_voicememos",
        package=None,
        relative_path="private/var/mobile/Library/Recordings/CloudRecordings.db",
        container_kind=ContainerKind.SYSTEM,
        description="Voice memos (cloud recordings index)",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_photos",
        package=None,
        relative_path="private/var/mobile/Media/PhotoData/Photos.sqlite",
        container_kind=ContainerKind.SYSTEM,
        description="Photos library (PhotoData)",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_knowledgec",
        package=None,
        relative_path="private/var/mobile/Library/CoreDuet/Knowledge/knowledgeC.db",
        container_kind=ContainerKind.SYSTEM,
        description="CoreDuet KnowledgeC pattern-of-life database",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_health",
        package=None,
        relative_path="private/var/mobile/Library/Health/healthdb_secure.sqlite",
        container_kind=ContainerKind.SYSTEM,
        description="HealthKit secure database",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_wallet",
        package=None,
        relative_path="private/var/mobile/Library/Passes/passes23.sqlite",
        container_kind=ContainerKind.SYSTEM,
        description="Wallet passes + transactions",
    ),
    # Additional explicit, neutral artifact targets.
    IOSArtifactSpec(
        artifact_type="mobile_ios_notification_history",
        package=None,
        relative_path="private/var/mobile/Library/UserNotifications/ASPDeliveredNotifications.db",
        container_kind=ContainerKind.SYSTEM,
        description="Notification delivery log",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_lockdown_pairings",
        package=None,
        relative_path="private/var/db/lockdown",
        container_kind=ContainerKind.ROOT_SYSTEM,
        is_directory=True,
        description="Lockdown daemon pairing records (per-host plist)",
    ),
    # CoreSpotlight content cache. Real iOS 16/17 uses
    #   Spotlight/CoreSpotlight/<NSFileProtection*>/index.spotlightV2/
    #     .store.db
    # The .store.db is the only SQLite-shaped store in the cache;
    # the rest of the directory holds binary index files. We mark
    # this as a directory spec and the per-protection-class .store.db
    # files fan out as individual artifacts.
    IOSArtifactSpec(
        artifact_type="mobile_ios_spotlight_content",
        package=None,
        relative_path=(
            "private/var/mobile/Library/Spotlight/CoreSpotlight"
        ),
        container_kind=ContainerKind.SYSTEM,
        is_directory=True,
        # CoreSpotlight directory holds many binary index files plus
        # one SQLite store per protection class. Only the SQLite
        # store carries content snippets parseable by the server.
        child_suffix_filter=(".store.db",),
        description=(
            "CoreSpotlight content index store directory "
            "(per-protection-class .store.db files)"
        ),
    ),
    # Accounts3 — every signed-in account (iCloud / Google / Exchange / etc.)
    IOSArtifactSpec(
        artifact_type="mobile_ios_accounts",
        package=None,
        relative_path="private/var/mobile/Library/Accounts/Accounts3.sqlite",
        container_kind=ContainerKind.SYSTEM,
        description="iOS account inventory (iCloud, Google, Exchange, etc.)",
    ),
    # FrontBoard application state — install / launch / crash timeline
    IOSArtifactSpec(
        artifact_type="mobile_ios_app_state",
        package=None,
        relative_path="private/var/mobile/Library/FrontBoard/applicationState.db",
        container_kind=ContainerKind.SYSTEM,
        description="iOS application state (FrontBoard install/launch timeline)",
    ),
    # Voicemail — voicemail audio + transcripts + caller log
    IOSArtifactSpec(
        artifact_type="mobile_ios_voicemail",
        package=None,
        relative_path="private/var/mobile/Library/Voicemail/voicemail.db",
        container_kind=ContainerKind.SYSTEM,
        description="iOS voicemail database (calls + transcripts)",
    ),
    # Apple Mail — Envelope Index (headers, threads) + sidecars
    IOSArtifactSpec(
        artifact_type="mobile_ios_mail_envelope",
        package=None,
        relative_path="private/var/mobile/Library/Mail/Envelope Index",
        container_kind=ContainerKind.SYSTEM,
        description="Apple Mail Envelope Index (headers, threads, message metadata)",
    ),
    # Safari Cookies (root system store; per-app cookies fan out separately)
    IOSArtifactSpec(
        artifact_type="mobile_ios_safari_cookies",
        package=None,
        relative_path="private/var/mobile/Library/Cookies/Cookies.binarycookies",
        container_kind=ContainerKind.SYSTEM,
        description="Safari root cookie jar (binarycookies binary format)",
    ),
    # CoreDuet — interactionC (contact-of-interest scoring; communication frequency)
    IOSArtifactSpec(
        artifact_type="mobile_ios_interaction_c",
        package=None,
        relative_path="private/var/mobile/Library/CoreDuet/People/interactionC.db",
        container_kind=ContainerKind.SYSTEM,
        description="CoreDuet interactionC — contact-of-interest scoring",
    ),
    # routined — Significant Locations + visit history (location pivot)
    IOSArtifactSpec(
        artifact_type="mobile_ios_routined",
        package=None,
        relative_path="private/var/mobile/Library/Caches/com.apple.routined",
        container_kind=ContainerKind.SYSTEM,
        is_directory=True,
        child_suffix_filter=("Local.sqlite", "Cache.sqlite"),
        description="routined Significant Locations + visit cache",
    ),
    # Biome — iOS 16+ SEGB streams (app launches, Bluetooth, lock, focus)
    IOSArtifactSpec(
        artifact_type="mobile_ios_biome",
        package=None,
        relative_path="private/var/mobile/Library/Biome/streams",
        container_kind=ContainerKind.SYSTEM,
        is_directory=True,
        description="Biome SEGB streams (app launches, lock, Bluetooth, focus)",
    ),
    # WiFi known networks plist
    IOSArtifactSpec(
        artifact_type="mobile_ios_wifi",
        package=None,
        relative_path="private/var/preferences/SystemConfiguration/com.apple.wifi.plist",
        container_kind=ContainerKind.ROOT_SYSTEM,
        description="WiFi known networks (SSIDs, BSSIDs, last-join timestamps)",
    ),

    # App-specific (bundle id → resolved per-app container at runtime
    # by ios_uuid_resolver). artifact_type values match the server's
    # existing per-app enum so the dispatcher routes them.
    IOSArtifactSpec(
        artifact_type="mobile_ios_whatsapp",
        package="net.whatsapp.WhatsApp",
        relative_path="ChatStorage.sqlite",
        container_kind=ContainerKind.APP_GROUP,
        description="WhatsApp shared-group chat storage",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_telegram",
        package="ph.telegra.Telegraph",
        relative_path="Documents/tgdata.db",
        container_kind=ContainerKind.APP_DATA,
        description="Telegram iOS database",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_line",
        package="jp.naver.line",
        relative_path="Library/Application Support/LINE/Messages.sqlite",
        container_kind=ContainerKind.APP_DATA,
        description="LINE iOS messages",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_signal",
        package="org.whispersystems.signal",
        relative_path="grdb/signal.sqlite",
        container_kind=ContainerKind.APP_GROUP,
        description="Signal message database (GRDB)",
    ),
    IOSArtifactSpec(
        artifact_type="mobile_ios_kakaotalk",
        package="com.iwilab.KakaoTalk",
        relative_path="Library/PrivateDocuments/talk.sqlite",
        container_kind=ContainerKind.APP_DATA,
        description="KakaoTalk iOS message database",
    ),
    # ------------------------------------------------------------------
    # iOS Find My — searchpartyd user-data directory. Holds the
    # OwnedBeacons / BeaconStore plists, encrypted offline-finding
    # location archives, and the per-AirTag and per-device record
    # files that Find My v3 (iOS 14+) uses. Distinct from the
    # CloudKit framework cache under `Library/Caches/CloudKit/...`,
    # which only contains framework-internal asset DBs. The
    # `Library/com.apple.icloud.searchpartyd/` path is the canonical
    # user-actionable source.
    # ------------------------------------------------------------------
    IOSArtifactSpec(
        artifact_type="mobile_ios_findmy",
        package=None,
        relative_path="private/var/mobile/Library/com.apple.icloud.searchpartyd",
        container_kind=ContainerKind.SYSTEM,
        description="Find My / searchpartyd user data (OwnedBeacons, BeaconStore, location archives)",
        is_directory=True,
        child_suffix_filter=(".archive", ".plist", ".sqlite", ".db", ".record"),
    ),
    # ------------------------------------------------------------------
    # iOS TCC — Transparency, Consent, and Control. Records every
    # permission grant for microphone, camera, location, contacts,
    # photos, etc., with first-grant timestamp and granting agent.
    # Critical for understanding which apps had access to sensitive
    # subsystems during the relevant period.
    # ------------------------------------------------------------------
    IOSArtifactSpec(
        artifact_type="mobile_ios_tcc",
        package=None,
        relative_path="private/var/mobile/Library/TCC/TCC.db",
        container_kind=ContainerKind.SYSTEM,
        description="TCC permission grant history (mic / camera / location / etc.)",
        pull_sqlite_sidecars=True,
    ),

    # =========================================================================
    # Round 9 - Mobile AI Apps (iOS, 2026-05-06)
    # =========================================================================
    # Per ScienceDirect 2024/2025 published research on iOS AI app forensics.
    # Each app's container holds conversation cache, attachments, account info.

    IOSArtifactSpec(
        artifact_type="ai_mobile_chatgpt",
        package="com.openai.chat",
        relative_path="Documents",
        container_kind=ContainerKind.APP_DATA,
        description="ChatGPT iOS - conversations (plaintext JSON), drafts, projects, voice transcripts, account",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_claude",
        package="com.anthropic.claudeforios",
        relative_path="Documents",
        container_kind=ContainerKind.APP_DATA,
        description="Claude iOS - Artifacts (locally stored generated content), conversation cache",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_claude",
        package="com.anthropic.claude",
        relative_path="Library",
        container_kind=ContainerKind.APP_DATA,
        description="Claude iOS Library - cache, preferences, attachment thumbnails",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_copilot",
        package="com.microsoft.copilot",
        relative_path="Library/Caches/com.microsoft.copilot/fsCachedData",
        container_kind=ContainerKind.APP_DATA,
        description="Microsoft Copilot iOS - cached user data (email/birthdate/address/phone), prompts",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_copilot",
        package="com.microsoft.copilot",
        relative_path="Documents",
        container_kind=ContainerKind.APP_DATA,
        description="Microsoft Copilot iOS Documents",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_gemini",
        package="com.google.GoogleMobile",
        relative_path="Library/Application Support/Google/Measurement",
        container_kind=ContainerKind.APP_DATA,
        description="Google Gemini iOS (bundled into Google app) - measurement plist, minimal local artifacts",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_perplexity",
        package="ai.perplexity.app",
        relative_path="Documents",
        container_kind=ContainerKind.APP_DATA,
        description="Perplexity iOS - search history, conversation cache",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_replika",
        package="io.luka.app",
        relative_path="Documents",
        container_kind=ContainerKind.APP_DATA,
        description="Replika iOS - **Realm DB** (not SQLite), conversation history",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_otter",
        package="com.aisense.otter",
        relative_path="Documents",
        container_kind=ContainerKind.APP_DATA,
        description="Otter.ai iOS - **audio recordings + transcripts** (high evidentiary value)",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_deepseek",
        package="com.deepseek.chat",
        relative_path="Documents",
        container_kind=ContainerKind.APP_DATA,
        description="DeepSeek iOS - 2025 viral Chinese AI app, no published DFIR coverage",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_wrtn",
        package="com.wrtn.app",
        relative_path="Documents",
        container_kind=ContainerKind.APP_DATA,
        description="Wrtn iOS - GenAI portal, Kakao/Naver/Google login",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_character_ai",
        package="ai.character.app",
        relative_path="Documents",
        container_kind=ContainerKind.APP_DATA,
        description="Character.AI iOS - cloud-sync companion chat",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_poe",
        package="com.quora.poe",
        relative_path="Documents",
        container_kind=ContainerKind.APP_DATA,
        description="Poe (Quora) iOS - aggregator for GPT-4.5 / Claude / DeepSeek / Runway / ElevenLabs",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_grok",
        package="ai.x.grok",
        relative_path="Documents",
        container_kind=ContainerKind.APP_DATA,
        description="Grok (xAI) iOS - standalone app artifacts",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_le_chat",
        package="ai.mistral.chat",
        relative_path="Documents",
        container_kind=ContainerKind.APP_DATA,
        description="Mistral Le Chat iOS (Feb 2025 launch) - French sovereign AI",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_meta_ai",
        package="com.facebook.stella",
        relative_path="Documents",
        container_kind=ContainerKind.APP_DATA,
        description="Meta AI iOS standalone app (April 2025)",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_pi",
        package="ai.inflection.pi",
        relative_path="Documents",
        container_kind=ContainerKind.APP_DATA,
        description="Pi by Inflection iOS - emotional companion (acquired by Microsoft 2024)",
        is_directory=True,
    ),
    IOSArtifactSpec(
        artifact_type="ai_mobile_clova",
        package="com.naver.nozzle",
        relative_path="Documents",
        container_kind=ContainerKind.APP_DATA,
        description="Naver CLOVA app iOS - Korean voice/AI assistant",
        is_directory=True,
    ),
)


# =============================================================================
# Lookup helpers
# =============================================================================
def all_android_specs() -> List[AndroidArtifactSpec]:
    return list(ANDROID_PATH_SPECS)


def all_ios_specs() -> List[IOSArtifactSpec]:
    return list(IOS_PATH_SPECS)


def find_android_spec_by_path(zip_entry_path: str
                              ) -> Optional[AndroidArtifactSpec]:
    """Match a Cellebrite Android zip entry (e.g.
    `Dump/data/data/com.whatsapp/databases/msgstore.db`) against the
    spec table. Returns None on no match."""
    # The Cellebrite Android prefix is `Dump/`. Strip it for matching.
    if zip_entry_path.startswith("Dump/"):
        rel = zip_entry_path[len("Dump/"):]
    else:
        rel = zip_entry_path
    for spec in ANDROID_PATH_SPECS:
        if rel == spec.full_path_pattern:
            return spec
    return None


def find_ios_system_spec_by_path(zip_entry_path: str
                                 ) -> Optional[IOSArtifactSpec]:
    """Match an iOS zip entry against SYSTEM-rooted specs only.
    App-data and app-group specs require runtime UUID resolution
    handled by the adapter, not this lookup."""
    if zip_entry_path.startswith("filesystem1/"):
        rel = zip_entry_path[len("filesystem1/"):]
    else:
        rel = zip_entry_path
    for spec in IOS_PATH_SPECS:
        if spec.container_kind not in (ContainerKind.SYSTEM,
                                       ContainerKind.ROOT_SYSTEM):
            continue
        if rel == spec.relative_path:
            return spec
    return None


def all_artifact_types() -> List[str]:
    """Return every artifact_type known to this collector module.
    Useful for the capabilities.md document."""
    types = [s.artifact_type for s in ANDROID_PATH_SPECS]
    types.extend(s.artifact_type for s in IOS_PATH_SPECS)
    return types
