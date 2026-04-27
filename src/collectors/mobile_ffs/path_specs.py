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
        relative_path="databases/threads_db2",
        description="Facebook Messenger database",
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
        description="iOS Notes database",
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
    # New artifact_types — server enum extension required (added in
    # the server-side companion commit). Daubert: explicit, neutral,
    # bundle-name-free.
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
