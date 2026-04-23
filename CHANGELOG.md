# Changelog

All notable changes to the Intelligence Collector are documented in this file. The project follows the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
