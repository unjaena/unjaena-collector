# Changelog

All notable changes to the Intelligence Collector are documented in this file. The project follows the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.2] - 2026-05-04

### Fixed
- **macOS collection silently failed every file (CRITICAL).** In `_collect_file`, `tz=timezone.utc` was passed as a keyword argument to `getattr()` instead of `datetime.fromtimestamp()`. Because `getattr()` does not accept keyword arguments, every file collected on macOS raised `TypeError: getattr() takes no keyword arguments` and was logged as an error -- the collector returned zero files for every artifact type. Users running v2.5.1 on macOS were affected for every artifact type (Unified Log, Launch Agents/Daemons, TCC.db, Keychain, Safari, iMessage, Notes, etc.). The fix re-orders parens so `getattr(stat_info, 'st_birthtime', stat_info.st_ctime)` is the inner expression and `tz=timezone.utc` applies to `fromtimestamp`.

### Added
- **CI live-collection workflow.** New `.github/workflows/live-collection-test.yml` runs the actual collector against the GitHub Actions runner's own filesystem on macos-14 (Apple Silicon) and ubuntu-latest. Validates path resolution, file copy, SHA-256 hashing, manifest schema, and permission-denied graceful handling end-to-end. Uploads `manifest.json` plus sample collected files as workflow artifacts (14-day retention) so each run produces an inspectable baseline. The workflow caught the v2.5.1 macOS bug above on its first real run.

### Verified
- macOS arm64 (14.8.5): 517 files / 626 MB collected across 13 of 16 system-level artifact types (3 user-data types correctly empty on a fresh runner). Real `/var/db/diagnostics/*.tracev3`, `/Library/LaunchAgents/`, `/Library/LaunchDaemons/`, `/var/log/system.log`, `/var/log/install.log`, TCC.db, Keychain, chat.db, NoteStore.sqlite all collected with valid SHA-256.
- Linux x86_64 (Ubuntu 24.04): 611 files / 835 KB collected across 11 of 16 system-level artifact types. `/etc/passwd`, `/etc/group`, `/etc/hosts`, `/var/log/syslog`, `/var/log/auth.log`, `/var/log/kern.log`, dmesg, all systemd unit files, and crontabs all collected. `/etc/shadow` correctly returned permission-denied (root-only).

## [2.5.1] - 2026-05-03

### Fixed
- **FFS path-spec gap-fix.** Five mobile artifact types had `ArtifactType` registrations and server-side parsers but no corresponding path-spec, so the collector returned zero files for them when iterating a Cellebrite UFED FFS bundle. Discovered while ingesting Hickman public-corpus iOS 17 (35 GB) and Android 14 (32 GB) bundles. Added path-specs:
  - `mobile_ios_findmy` -- `private/var/mobile/Library/com.apple.icloud.searchpartyd/` (FindMy / searchpartyd archives, plists, sqlite, records -- 187 entries on the public iOS 17 image)
  - `mobile_ios_tcc` -- `private/var/mobile/Library/TCC/TCC.db` (Transparency / Consent / Control permission grants)
  - `mobile_android_wifi` -- `data/misc/wifi/WifiConfigStore.xml` (saved networks, security mode, BSSID history)
  - `mobile_android_media` -- `data/media/0/` directory tree, suffix-filtered to common photo / video / document extensions
  - `mobile_android_facebook_messenger` -- rewritten as a directory spec to handle filename schema-drift (see "Added" below)

### Added
- **Filename-glob support in `AndroidArtifactSpec`.** New `filename_globs` field lets a single directory-mode spec match files with multiple naming conventions across app versions, applied after the existing `child_suffix_filter`. Used to pull both legacy and modern Facebook Messenger DBs (`threads_db2*` plus `msys_database_*`) plus their SQLite `-wal` / `-shm` sidecars from one spec without forking into two artifact types.

### Verified
- Adapter test suite: 17/17 pass against real FFS bundles (35 GB iOS 17 + 32 GB Android 14 public corpus). Match counts: FindMy 187, TCC 1, Android WiFi 1, Android media (DCIM/Pictures/Download), Facebook Messenger 4 files including modern `msys_database_*` and SQLite sidecars.

## [2.5.0] - 2026-04-29

### Added
- **22 new iOS 17 / Android 14 artifact types** closing a long-standing baseline gap with industry-standard mobile forensic tools. These artifacts exist on typical iOS 17 / Android 14 acquisitions but the collector previously did not surface them as user-selectable evidence.
  - **iOS additions (10)**: Apple Mail Envelope Index, Safari `binarycookies`, CoreDuet `interactionC`, `routined` Significant Locations, Biome SEGB streams, `Accounts3`, FrontBoard application state, `voicemail.db`, WiFi known networks plist, modern AppGroup NoteStore (replaces the iOS 9-era `Library/Notes/notes.sqlite` path on iOS 9+).
  - **Android additions (12)**: Bluetooth pairings (`bt_config.conf`), system dropbox logs, `batterystats.bin`, downloads provider, Chrome cookies / login data / bookmarks, Google Maps `gmm_storage`, Google Pay / Wallet card history, `locksettings`, Twitter/X databases, Gmail `EmailProvider`.

### Fixed
- iOS 17 schema-drift fixes for `knowledgeC` (`ZSTREAMNAME` column moved from `ZSOURCE` to `ZOBJECT`; fallback added for `ZSTRUCTUREDMETADATA`).

## [2.4.9] - 2026-04-29

### Added
- **UFED FFS zip bundle ingest** (Cellebrite CLBX iOS / Android). Forensic agencies that already use Cellebrite UFED for mobile acquisition can now hand a CLBX zip bundle directly to the collector GUI instead of plugging the live phone in over USB.
- A new **"+ Add Image / Bundle"** entry in the device list accepts `EXTRACTION_FFS.zip` alongside the existing E01 / RAW / VHD / VMDK paths.
- Bundle detection (publisher / format / signals), surfaced as a first-class device on the iOS or Android tab, and dispatched to every per-artifact-type checkbox the operator already knows how to use.
- SHA-256 + CRC-32 + source-zip path recorded per file for chain of custody. `-wal` / `-shm` sidecars travel with their primary SQLite file so WAL state merges transparently on the parser side.
- Detection of a 30-50 GB zip's central directory + msgpack metadata runs on a worker `QThread` behind a modal progress dialog so the GUI window does not freeze during the ~10 s parse.

### Verified
- End-to-end on a public CLBX iOS 17 corpus (34.3 GB) and a public CLBX Android 14 corpus (32.0 GB). Existing GUI checkbox render and forensic-image regression tests still pass.

## [2.4.8] - 2026-04-29

### Fixed
- **Consent dialog layout**: word-wrap now uses `heightForWidth`, with no panel overlap on long PIPA / GDPR statements at narrow widths.

## [2.4.7] - 2026-04-29

### Added
- **Real-time bidirectional WebSocket sync** between collector and server. The collector now subscribes to a control channel for the duration of a session.
- 15-second heartbeat with 3->60 s exponential backoff, 30-second dead-peer detection.
- Server-side abort / take-over signaling surfaced in the GUI ("server canceled this collection" / "another session has taken over").
- `intent.shutdown` graceful-stop semantics so the operator-initiated cancel is distinguishable from connectivity loss.

### Fixed
- Threading-safe abort: cancel from the GUI no longer races the upload worker.
- Error-message regex priority order so `WS_TERMINATE` / `WS_CANCEL` user-facing strings render in the right language.

## [2.4.6] - 2026-04-27

### Fixed
- **Android Tier 3 "Screen Scraping" checkbox removed** from the GUI. The Tier 3 collector requires `ForensicAgent.apk`, which is not shipped with the public release bundle -- selecting the checkbox previously produced "Failed to install Agent APK" with zero records. The collector code path is preserved for future reactivation once the Agent APK ships.
- **Consent dialog word-wrap**: long PIPA / GDPR / cross-border-transfer consent statements are no longer truncated to a single line. The checkbox panel is scrollable, the dialog is taller, and clicking a consent label toggles its checkbox.

## [2.4.5] - 2026-04-27

### Added
- **Samsung Pay / Wallet (Android)** collection support -- three new artifact_types: `mobile_android_samsung_pay`, `mobile_android_samsung_pay_cards`, `mobile_android_samsung_pay_transit` (transactions, enrolled cards, transit-card tap events).
- **iOS Toss app** added under the Korean Apps section.

### Fixed
- **GUI auto-registration** now sets `subcategory` for `IOS_ARTIFACT_TYPES` entries so the following 10 previously-invisible iOS apps are user-selectable: BAND, Starbucks Korea, Samjeomssam, Soomgo, MobileFax, HiWorks, Google Slides, Google Docs, Samsung Card, Naver.

### Verified
- GUI render: iOS tab 144 checkboxes, Android tab 54 checkboxes, 0 orphans.

## [2.4.4] - 2026-04-27

### Added
- **SQLite `-wal` / `-shm` sidecar pull**: pull WAL state alongside SQLite primaries so deleted-row recovery downstream sees the WAL's last writes.
- **Directory-spec fan-out**: per-host pairing records under `private/var/db/lockdown` and per-protection-class CoreSpotlight stores under `index.spotlightV2` are now resolved as directories rather than skipped as missing single files.
- **Dotfile denylist**: blanket `startswith('.')` filtering previously dropped real `.store.db` artifacts; the denylist is now explicit.

### Verified
- 16/16 `cellebrite_adapter` tests including 3 real-corpus regression tests against the Hickman iPhone 11 iOS 17 corpus (1418 `-wal` sidecars).

## [2.4.3] - 2026-04-26

### Fixed
- **Hotfix -- consent signing key wire-through**: the `/authenticate` server response carries a `consent_signing_key` field but the GUI controller did not store it on `self` nor pass it through to `show_consent_dialog()`. The dialog fell back to looking for the `CONSENT_SIGNING_KEY` environment variable on the operator's PC (typically unset) and refused to record consent with the message "A secure signing key is required to record consent. The server did not provide one." The dialog is fail-closed by design -- random fallback keys produce signatures the server cannot verify and were therefore worse than a clear failure. The bug was that the wire-through from `/authenticate` to the dialog was missing.

This release contains only that wire-through fix; no other changes since v2.4.2.

## [2.4.2] - 2026-04-23

### Fixed
- **Virtual disk backends (VHD, VHDX, VMDK)**: Removed stray `.open()` call after the `dissect.hypervisor` disk object is constructed. The installed `dissect.hypervisor` 3.21 returns a stream-like object from the class constructor directly, so the trailing `.open()` raised `AttributeError: 'VHD' object has no attribute 'open'` and prevented any VHD / VHDX / VMDK evidence from being opened on current library versions. All three backends now call the class constructor only.
- **exFAT file reads**: `ForensicDiskAccessor` was passing the exFAT directory FILE entry to `dissect.fat.ExFAT.runlist()` where the library expects a starting cluster number. This produced `TypeError: unsupported operand type(s) for -: 'int' and 'FILE'` for every file read on exFAT volumes. The call now passes `starting_cluster = file_entry.stream.location` with the correct `not_fragmented` flag.
- **exFAT non-fragmented file truncation**: When a file's `not_fragmented` flag is set, `runlist()` does not consult the FAT and returns a run covering only the first cluster unless the caller also provides a `size` argument. The accessor now passes `size` so non-fragmented files of any length are read in full instead of being silently truncated to a single cluster.

### Verified
- Round-trip test corpus covering 8 image container formats (RAW, VHD, VHDX, VMDK, QCOW2, VDI, DMG, E01), 4 filesystems (NTFS, FAT32, exFAT, ext4), three partition layouts (MBR single, GPT single, MBR multi-partition), NTFS Alternate Data Streams, Unicode filenames, multi-cluster files, and damaged-image recovery scenarios.
- Real-world regression against production evidence images at 12 GB to 234 GB scale, including an Apple APFS volume inside an uncompressed UDIF DMG.

## [1.0.0] - 2026-04-14

First public release.

### Added
- Cross-platform forensic artifact collection (Windows x64, Linux x64, macOS arm64)
- Windows artifacts: MFT, registry hives, prefetch, event logs, USB connection history, browser history, user profile files
- macOS artifacts: property lists, shell history, Safari data, Bluetooth and WiFi configuration, TCC database, unified logs, launch agents and daemons
- Linux artifacts: systemd journals, authentication logs, shell history, cron schedules
- Android artifacts: APK inventory and application database backups via ADB protocol
- iOS artifacts: backup parsing via Apple MobileSync format
- Disk image support: E01 and RAW formats
- BitLocker support via `dissect.fve` when operator provides recovery credentials
- Optional physical memory acquisition via user-supplied WinPmem binary
- PyQt6 graphical interface with multi-language support
- AES-256-GCM encrypted upload channel with TLS certificate verification in production
- Per-file SHA-256 hashing bound as additional authenticated data to the encrypted upload
- Operator consent record with HMAC-SHA256 integrity tag over the user's selections

### Security
- Apple Developer ID signing and notarization for the macOS build
- Windows and Linux builds published as unsigned binaries with SHA-256 checksums in `SHA256SUMS.txt`
- One-time session tokens with replay prevention
- Environment-variable driven configuration (no secrets in config templates)

### Known Limitations
- Windows and Linux builds are not yet Authenticode / package-signed; verify via `SHA256SUMS.txt`
- Memory acquisition requires the operator to supply `winpmem_mini_x64.exe` separately (Apache-2.0 upstream)
- Output archive does not yet include a canonical manifest JSON file with per-artifact metadata; this is planned for a future release
- Server-side verification of the operator consent record is not yet wired into the release build. The HMAC tag provides tamper-evidence at archive rest, but a cryptographic binding of the consent record to a specific analysis session is planned for a future release.
- No third-party security audit has been performed on this release
