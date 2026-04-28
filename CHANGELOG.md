# Changelog

All notable changes to the Intelligence Collector are documented in this file. The project follows the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.7] - 2026-04-27

### Added
- **Real-time bidirectional WebSocket control channel** — a persistent connection between the collector and the analysis service so the server can push `cancel` / `terminate` / `snapshot` directives to a running collection in real time. Previously the collector relied only on REST polling; the operator had no way to be notified of a server-initiated abort until the next polling tick.
  - `uploader.py` — control loop with 15-second heartbeat, exponential reconnect backoff (3 s → 60 s), 30-second receive-timeout dead-peer detection, `intent.shutdown` on close.
  - Threading-safe `_cancelled` flag is set when the server pushes `cancel` or `terminate`; the synchronous upload loop polls between chunks so any in-flight upload aborts gracefully without partial-state corruption.
  - Optional `control_callback` API for the GUI to react to server directives (toast, dialog, take-over confirmation).
- **Operator visibility for server-initiated events** (`gui/app.py`) — server abort / take-over events are now surfaced to the user instead of being silently dropped.

### Fixed
- **`error_messages.py` — `ERROR_PATTERNS` priority order** — the legacy `(CANCELLED|409.*cancelled)` regex was matching the new server-pushed strings (`cancel:user_cancelled`, `terminate:superseded`, …) under `re.IGNORECASE` because every one of those strings contains the substring "cancel" case-insensitively. The activity log was therefore mis-classifying server-pushed events as legacy REST 409 cancels. More-specific `WS_TERMINATE` / `WS_CANCEL` patterns are now ordered **before** the generic `CANCELLED` rule:
  - `WS_TERMINATE` — *"Another collector took over this case, or your session expired."*
  - `WS_CANCEL` — *"The web platform cancelled this collection."*
  - `CANCELLED` — legacy 409 response from REST endpoints.

### Compatibility
- No breaking API changes. Drop-in replacement for v2.4.6.
- Older collector releases continue to work against the new server — the bidirectional channel is opt-in: a collector that has not been upgraded simply does not open the new control WebSocket and falls back to the previous polling behaviour.

## [2.4.6] - 2026-04-27

### Fixed
- **Android Tier 3 "Screen Scraping" checkbox always failed** — the screen-scrape collector requires `ForensicAgent.apk` in `resources/agent_apk/`, but only the `.sha256` stub ships with the release. Selecting the checkbox previously produced *"Failed to install Agent APK"* with zero records emitted. The checkbox is now hidden (the entire Tier 3 section auto-hides when no items are present). The `android_collector.py` `_collect_screen_scrape()` code path is preserved so the feature can be re-enabled by dropping `ForensicAgent.apk` into `resources/agent_apk/` and reinstating the `mobile_android_screen_scrape` ARTIFACT_TYPES entry.
- **Consent dialog truncated long PIPA / GDPR consent items** — `QCheckBox` does not natively word-wrap its label, so multi-sentence consent items (cross-border transfer acknowledgment, PIPA Article 28, GDPR Article 49(1)(a) ...) collapsed to a single line and the operator could not see what they were agreeing to. Three layered fixes:
  - Each consent item is now a checkbox + word-wrapped `QLabel` pair. Clicking the label toggles the checkbox; the row behaves as one widget. Full statement is also set as the checkbox tooltip.
  - The consent-checkbox panel is wrapped in a `QScrollArea` (140-280 px min/max height) so long lists scroll instead of pushing the Agree / Cancel buttons off-screen.
  - Dialog default size 700x620 -> 760x760 (max 800x720 -> 900x900) so wrapped consent text + operator section + buttons all fit without squashing.
  - Layout spacing 4 -> 12 px so adjacent items are visually distinct.

### Verified
- Android tab will render 53 user-selectable checkboxes (was 54). iOS tab unchanged at 144. Zero orphan entries.
- Headless dialog inspection confirms `_add_consent_item()`, `setMinimumSize(760, 760)`, the scrollable panel, and the click-label-to-toggle binding are all in place.

## [2.4.5] - 2026-04-27

### Added
- **Samsung Pay / Samsung Wallet (Android)** — three new artifact types covering payment transactions, enrolled cards, and transit-card tap events. Heuristic transaction-table detector handles both Samsung Pay 1.x and Wallet 2.x/3.x schemas, with a discovery fallback that emits a per-table inventory record so renamed-table rows are never silently dropped:
  - `mobile_android_samsung_pay` — `pay.db` payment transaction history
  - `mobile_android_samsung_pay_cards` — `card.db` enrolled payment instruments
  - `mobile_android_samsung_pay_transit` — `transit.db` subway / bus tap events
- **iOS Toss app** — `mobile_ios_toss` is now a user-selectable checkbox under Korean Apps so investigators can opt in or out of Toss money-transfer / payment / linked-bank-account data at consent time.

### Fixed
- **GUI checkbox visibility for 10 iOS apps** — apps registered through the auto-registration branch (`IOS_ARTIFACT_TYPES`) had `subcategory=None` and silently never rendered as user-selectable checkboxes. The auto-registration loop now infers a subcategory from the entry name (productivity / email_browser / messenger / sns / korean) so every registered iOS app is reachable from the GUI. The previously-invisible apps were:
  - BAND, Starbucks Korea, Samjeomssam, Soomgo, MobileFax, HiWorks, Google Slides, Google Docs, Samsung Card, Naver
- **mobile_ffs path-spec exposure** — three Cellebrite-FFS path specs are now wired into the GUI as user-selectable artifacts instead of being driver-internal.

### Verified
- iOS tab will render 144 user-selectable checkboxes; Android tab will render 54. Zero orphan entries (every registered artifact_type is reachable from the GUI).
- Samsung Pay heuristic detector tested against schema variants from Samsung Pay 1.x (`paymentTransactionItem` / `price` / `payee`) and Wallet 2.x (`pay_history` / `amount` / `merchant_name`); both produce records with merchant / amount / card / date roles correctly classified.
- Wallet 3.x discovery fallback emits a per-table inventory record when no transaction-shaped table is found, so future schema renames degrade gracefully instead of silently dropping data.

## [2.4.4] - 2026-04-26

### Added
- **mobile_ffs (Cellebrite Full File System) workflow** — server-side analysis can now consume publisher-FFS evidence directly:
  - **`mobile_ffs/format_detector`** — publisher-first FFS detection across Cellebrite UFED, Magnet GrayKey, Oxygen, and other vendors
  - **`mobile_ffs/safe_zip`** — adversarially-tested zip extractor with path-traversal, symlink, and decompression-bomb defenses
  - **`mobile_ffs/case_manifest`** — forensic bundle writer producing a single signed manifest per case (paths, hashes, sizes, source container)
  - **`mobile_ffs/cellebrite_adapter`** — unified Android + iOS view over Cellebrite FFS extractions
  - **`mobile_ffs/path_specs`** — declarative artifact-path registry (filename, glob, container parent), aligned with server-side ArtifactType enum names
- **SQLite WAL / SHM sidecar pull** — when the collector picks up a `*.db` file, the matching `-wal` and `-shm` sidecars are pulled in the same operation so the server-side parser can recover uncommitted-but-flushed pages.
- **Directory-spec fan-out** — single artifact entries can now declare a directory; the collector enumerates and pulls every regular file under it (used by CoreSpotlight, Apple Pay, etc.).
- **CoreSpotlight V2 path** — added the `Library/CoreSpotlight/V2` path so the V2 protection-class index store is collected alongside the legacy V1 path.

## [2.4.3] - 2026-04-25

### Fixed
- **Consent dialog hard-block when CONSENT_SIGNING_KEY is unset** — the GUI now wires the server-issued consent signing key into the consent dialog. Previously, the dialog accepted operator approval even when the server had not provided a signing key, producing legally-worthless signatures the server could not verify. The dialog now refuses to record consent when no signing key is present, surfacing the operator-visible message *"A secure signing key is required to record consent"*. This closes the fail-open path discovered in the 2026-04-20 security audit.

### Documentation
- Added a Windows GUI demo GIF to the README hero alongside the existing macOS terminal demo so readers see both supported workflows on the project landing page.

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
