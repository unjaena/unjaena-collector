# Changelog

All notable changes to the Intelligence Collector are documented in this file. The project follows the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
