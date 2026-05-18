# Changelog

All notable public collector changes are documented here.

This changelog covers the open-source collector client only. Server-side
parsing and analysis workflow logic are not part of this public repository.

## [2.6.5] - 2026-05-19

### Fixed

- Bounded AI browser extension collection to known extension manifest files
  instead of broad extension directory scans.
- Bounded AI browser, Teams, WhatsApp, Facebook, Instagram, Notion, Arc,
  Comet, Opera, and Slack-related cache collection to known store files or
  explicit export files to reduce low-value bulk uploads.
- Aligned local and disk-image user-file extension policies for documents,
  email files, images, and videos.
- Fixed the GUI WebSocket control worker startup path by making the event-loop
  dependency available at module scope.

### Verified

- Collector compile checks passed for the changed collection and GUI modules.
- User-file extension policy regression tests passed locally.

## [2.6.4] - 2026-05-17

### Fixed

- Fixed forensic image extraction on FAT, ext, and other dissect-backed
  filesystems by preferring catalog path reads when inode reads are unstable.
- Improved removable FAT/exFAT image collection so root-level user documents,
  images, videos, and email files are included.
- Added collector-side text document coverage for removable FAT/exFAT images.
- Skipped AppleDouble sidecar files during document and media collection to
  avoid collecting metadata stubs as user content.

### Verified

- Full sample-image workflow validation covered image open, partition selection,
  collection, server parsing, simulated case upload, embedding generation, and
  downstream analysis routing.

## [2.6.3] - 2026-05-16

### Added

- Added Windows Search index collection coverage for `Windows.edb` and related
  indexer log files.
- Added modern Windows collection categories for notification databases, Phone
  Link caches, Windows Search index files, and WSL-related files.
- Added modern Linux and macOS collection categories used by the current
  collector UI.
- Added regression tests for forensic disk file extraction and image
  registration behavior.

### Fixed

- Improved forensic image registration for E01 segmented images and macOS DMG
  images.
- Improved MFT file-content extraction for records larger than a single
  cluster and for logical MFT stream offsets.
- Improved device registration metadata consistency for image-based
  collection.

### Security and Scope

- Public documentation was rewritten in English-only, ASCII-safe form.
- Internal server-side analysis details remain outside this public repository.

### Verified

- Collector Python compile checks passed for the changed collector modules.
- Collector regression tests for image registration and MFT file extraction
  passed locally.
- Server-side workflow tests were executed in the private repository, but those
  tests are intentionally not included in this public collector repository.

## [2.6.2] - 2026-05-13

### Added

- Expanded collector-side artifact coverage for current Windows, macOS, Linux,
  Android, and iOS acquisition workflows.
- Improved public release hygiene for generated collector packages.

### Fixed

- Improved artifact routing and upload metadata consistency.

## [2.6.1] - 2026-05-10

### Added

- Updated collector UI artifact visibility for recent acquisition categories.
- Improved release packaging for Windows, macOS, and Linux builds.

### Fixed

- Improved upload and device-selection behavior in GUI workflows.

## [2.5.2] - 2026-05-01

### Fixed

- Fixed a macOS collection regression where some artifact types could return
  zero collected files.
- Added live-collection checks for macOS and Linux CI runners.

## [2.5.1] - 2026-04-30

### Fixed

- Improved mobile path-spec coverage for selected Android and iOS artifact
  categories.
- Improved SQLite sidecar collection for mobile application databases.

## [2.5.0] - 2026-04-29

### Added

- Added additional iOS and Android artifact categories for modern mobile
  acquisition workflows.
- Added support for selected mobile backup and application data paths.

### Fixed

- Improved resilience to mobile schema drift in selected acquisition paths.

## [2.4.9] - 2026-04-29

### Added

- Added mobile full-file-system bundle ingestion support for supported archive
  layouts.
- Added bundle detection metadata and per-file integrity metadata.

## [2.4.8] - 2026-04-29

### Fixed

- Improved consent dialog layout for long statements at narrow widths.

## [2.4.7] - 2026-04-29

### Added

- Added real-time collection status synchronization with the configured
  analysis service.
- Added heartbeat and graceful-stop handling for long uploads.

### Fixed

- Improved cancellation behavior during uploads.

## [2.4.6] - 2026-04-27

### Fixed

- Removed a non-shipping Android agent workflow from public GUI selection.
- Improved consent dialog word wrapping.

## [2.4.5] - 2026-04-27

### Added

- Added selected Android wallet artifact collection paths.
- Improved GUI visibility for selected mobile application artifacts.

## [2.4.4] - 2026-04-27

### Added

- Added SQLite `-wal` and `-shm` sidecar collection for supported artifacts.
- Improved directory-spec fan-out for selected mobile paths.

## [2.4.3] - 2026-04-26

### Fixed

- Fixed consent signing key propagation from the configured service response to
  the GUI consent workflow.

## [2.4.2] - 2026-04-23

### Fixed

- Improved virtual disk backend handling for VHD, VHDX, and VMDK images.
- Improved exFAT file read handling.

## [1.0.0] - 2026-04-14

### Added

- Initial public collector release.
- Windows, macOS, Linux, Android, and iOS collection workflows.
- Disk image collection support.
- BitLocker access with operator-provided credentials.
- Secure upload with per-file integrity metadata.
