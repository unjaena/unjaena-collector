# Changelog

All notable changes to the Intelligence Collector are documented in this file. The project follows the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- Per-file SHA-256 hashing and integrity verification at upload
- Ed25519-signed operator consent receipt bound to each collection run

### Security
- Apple Developer ID signing and notarization for the macOS build
- Windows and Linux builds published as unsigned binaries with SHA-256 checksums in `SHA256SUMS.txt`
- One-time session tokens with replay prevention
- Environment-variable driven configuration (no secrets in config templates)

### Known Limitations
- Windows and Linux builds are not yet Authenticode / package-signed; verify via `SHA256SUMS.txt`
- Memory acquisition requires the operator to supply `winpmem_mini_x64.exe` separately (Apache-2.0 upstream)
- Output archive does not yet include a canonical manifest JSON file with per-artifact metadata; this is planned for a future release
- No third-party security audit has been performed on this release
