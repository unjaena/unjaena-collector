# unJaena AI — Digital Intelligence Collector

> The official evidence collection tool for the **unJaena AI** forensic analysis platform.
> Collected artifacts are automatically uploaded for AI-powered analysis including MITRE ATT&CK mapping, timeline reconstruction, and multilingual investigation reports.

Cross-platform digital forensic artifact collection tool with GUI. Collects evidence from Windows, macOS, Linux, Android, and iOS devices with cryptographic integrity verification and secure upload.

![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)
![Platforms: Win/macOS/Linux/Android/iOS](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Android%20%7C%20iOS-lightgrey)
![Languages: KR/EN/JA/ZH](https://img.shields.io/badge/reports-KR%20%7C%20EN%20%7C%20JA%20%7C%20ZH-green)
![Release](https://img.shields.io/github/v/release/unjaena/unjaena-collector?label=release)
![Stars](https://img.shields.io/github/stars/unjaena/unjaena-collector?style=social)

## ⚡ Quick Start

```bash
# Clone and run from source
git clone https://github.com/unjaena/unjaena-collector.git
cd unjaena-collector
pip install -r requirements.txt
python run.py
```

Or download a pre-built binary for your platform from [Releases](https://github.com/unjaena/unjaena-collector/releases/latest) (Windows `.exe`, macOS `.dmg`, Linux AppImage).

Configure your upload endpoint in `config.json` (see [Configuration](#configuration)) — defaults to `https://app.unjaena.com` for users of the hosted analysis service.

## 🌟 What's New in v2.4.1 — Tier S 2026 Expansion

**11 new artifact types** covering gaps in Windows 11 24H2, macOS Sequoia, and modern Linux distros. These artifacts had limited or no public collector support prior to this release.

### 🍎 macOS / iOS
- **`macos_biome_stream`** — Apple pattern-of-life framework streams (Ventura+, iOS 15+). Covers notification, Safari history, location activity, and device-pairing event streams. Full **SEGB v1 + v2** container parser.
- **`macos_xprotect_remediator_db`** — Apple's built-in behavior-rule detection database (XPdb). Ventura+ only, SIP-protected (requires root + Full Disk Access).

### 🪟 Windows 11 24H2+
- **`teams_v2_local_cache`** — New Teams (MSIX) Chromium LevelDB cache for messages, calls, meetings, and attachment references.
- **`credential_manager_vault`** — Windows Credential Manager Vault record structure (`VAULT_VCRD` + attribute map + attribute body). Structure only — credential contents never surfaced.
- **`credential_protection_blobs`** — Windows credential protection key storage (filename + size + hash inventory only).
- **`onedrive_sync_log`** — OneDrive client sync activity log records.
- **`chrome_state_file`** — Chromium Local State profile inventory across Chrome / Edge / Brave / Chromium.
- **`defender_operational_log`** — Windows Defender MPLog operational events (scans, detections, quarantine).

### 🐧 Linux (modern distros)
- **`linux_auditd_log`** — Kernel audit records (syscall / execve / login events).
- **`linux_systemd_journal`** — systemd journal messages across all units.
- **`linux_container_state`** — Docker + Podman container runtime state snapshots.

See the [v2.4.1 release notes](https://github.com/unjaena/unjaena-collector/releases/tag/collector-v2.4.1) for full technical details.

## 🆚 Why unjaena-collector?

> *Pricing, license terms, and feature sets reflect publicly available information as of 2026-04-22. See each vendor's official site for the latest details. Comparison is provided for informational purposes only.*

| | **unjaena-collector** | Magnet AXIOM Cyber | Cellebrite Inseyets.PA | Oxygen Detective | Autopsy | Velociraptor |
|---|---|---|---|---|---|---|
| **License** | AGPL-3.0 (open) | Commercial (quote-based) | Commercial (quote-based) | Commercial | Apache-2.0 (open) | AGPL-3.0 (open) |
| **Public pricing** | Free | Not disclosed | Not disclosed | Not disclosed (GSA listed) | Free | Free |
| **Endpoint OS coverage** | Windows / macOS / Linux / Android / iOS | Windows / macOS / Linux / Android / iOS | Mobile-focused | Windows / macOS / Linux / Mobile | Windows-focused (macOS/Linux limited) | Windows / macOS / Linux |
| **Report UI languages** | **KO / EN / JA / ZH** (native i18n) | Translation module available (32 lang, extra) | Smart translator add-on (40 lang) | 15+ languages (Korean not listed) | English only (community translations) | English only |
| **Open source** | ✅ Full source | ❌ | ❌ | ❌ | ✅ Full source | ✅ Full source |
| **Windows 11 24H2 Tier S artifacts (2026-04)** | ✅ 11 new types shipped | ✅ (per release notes) | Limited (mobile focus) | Partial coverage | Not listed in release notes | VQL-custom (user writes queries) |
| **Court admissibility certification** | ❌ Not certified (see [Legal Notice](#legal-notice)) | Widely adopted for LE/enterprise | NIST CFTT and other certifications | LE/enterprise adoption | Partial NIST testing | No vendor certification program |

### Honest positioning

**Where unjaena-collector leads**:
1. **Native 4-language UI and reports** (Korean / English / Japanese / Chinese) — competing tools mostly require paid translation modules or lack Korean entirely.
2. **Free, AGPL-3.0, cross-platform** with both endpoint and mobile collection — Autopsy is free but macOS/Linux functionality is limited; Velociraptor is endpoint-only with English UI.
3. **Windows 11 24H2 Tier S coverage** — 11 new artifact parsers (Teams v2, Credential Manager Vault structure, Defender MPLog, OneDrive sync log, etc.) shipped in v2.4.1.

**Where it's comparable**:
4. **Cross-platform artifact collection** across Windows / macOS / Linux / Android / iOS — Magnet AXIOM Cyber and Oxygen Detective offer similar breadth.

**Where it's honestly behind**:
5. **No court admissibility certification, no vendor training/certification program, no 24/7 commercial support.** For legal proceedings requiring admissibility, use in parallel with NIST-tested commercial suites. unjaena-collector is appropriate for in-house incident response, authorized investigations, and academic research.

> *Trade names (Magnet AXIOM, Magnet AXIOM Cyber, Cellebrite, UFED, Inseyets, Physical Analyzer, Oxygen Forensic Detective, Autopsy, Velociraptor) are trademarks of their respective owners and are used here solely for factual identification.*
>
> *Sources: [Magnet Free Tools](https://www.magnetforensics.com/free-tools/) · [Magnet AXIOM Cyber](https://www.magnetforensics.com/products/magnet-axiom-cyber/) · [Cellebrite licensing](https://cellebrite.com/en/changes-to-cellebrite-licensing-model/) · [Oxygen Forensic Detective](https://www.oxygenforensics.com/products/oxygen-forensic-detective/) · [Autopsy GitHub](https://github.com/sleuthkit/autopsy) · [Velociraptor GitHub](https://github.com/Velocidex/velociraptor).*

## 💬 Community

- **Discord** — *[coming soon]* — Live DFIR discussion and release announcements
- **Twitter / X** — *[coming soon]* — Technical deep-dives, weekly IOC sharing
- **GitHub Discussions** — Use the [Discussions tab](https://github.com/unjaena/unjaena-collector/discussions) for Q&A
- **GitHub Issues** — [Report bugs or request artifact types](https://github.com/unjaena/unjaena-collector/issues)

## How It Works

```
┌─────────────────────┐        ┌──────────────────────────────┐
│  Intelligence        │        │  unJaena AI Platform          │
│  Collector (this)    │───────▶│                                │
│                      │ AES-256│  ✦ AI-Powered RAG Analysis    │
│  • Windows/macOS/    │ Upload │  ✦ MITRE ATT&CK Mapping       │
│    Linux/Android/iOS │        │  ✦ Timeline Reconstruction    │
│  • Memory Forensics  │        │  ✦ Multilingual Reports       │
│  • Disk Images       │        │  ✦ Evidence Chain of Custody  │
└─────────────────────┘        └──────────────────────────────┘
```

1. **Collect Evidence** — Automatically extract forensic artifacts from target devices
2. **Encrypted Transfer** — Upload with AES-256-GCM encryption
3. **AI Analysis** — Automatic parsing, vector indexing, and LLM-powered analysis
4. **Generate Reports** — Query forensic findings in natural language (Korean / English / Japanese / Chinese)

## Features

- **Windows Forensics**: MFT, registry, prefetch, event logs, browser history, USB artifacts
- **Memory Acquisition**: Raw read of pagefile and hiberfil (optional physical-memory acquisition via user-supplied WinPmem binary)
- **Android Forensics**: USB collection via ADB protocol (no external ADB binary required)
- **iOS Forensics**: USB backup and artifact extraction via pymobiledevice3
- **macOS / Linux Forensics**: System logs, user artifacts, browser data, shell history
- **Disk Image Support**: E01 (Expert Witness Format), RAW image analysis
- **BitLocker Support**: Encrypted volume access with operator-provided recovery credentials
- **Secure Upload**: AES-256-GCM encrypted transfer
- **Collection Integrity**: Per-file SHA-256 hashing with integrity verification on upload
- **Multi-language GUI**: PyQt6 interface with i18n support

## Legal Notice

This software is provided strictly for **authorized forensic activities** — including but not limited to in-house incident response, contracted penetration testing, and authorized digital investigations. You are solely responsible for ensuring that you have the legal authority to run this tool against any target system, and for complying with all applicable laws and regulations in your jurisdiction.

The maintainers disclaim any liability arising from unauthorized or unlawful use.

This tool is **not purpose-built for court-admissible evidence collection**. If you intend to use the collected data in legal proceedings, consult with qualified counsel and apply organizational chain-of-custody procedures external to this tool.

### AGPL-3.0 Network Use

This project is distributed under the GNU Affero General Public License v3.0. Because the AGPL treats network interaction as a form of distribution (§13), if you modify this collector and allow third parties to interact with your modified version — for example by operating an analysis service that receives uploads from the modified client — you must make the corresponding source of the modified client available to those users under the same license.

The AGPL obligation applies to this collector only. The separate server-side analysis platform is independently developed and is not a covered work of this repository.

## Privacy and Data Handling

When you run a collection and choose to upload to the analysis platform, the following is transmitted over the encrypted channel:

- The collected artifact archive (AES-256-GCM encrypted in transit)
- Host identifier derived from `COMPUTERNAME` / `HOSTNAME` environment variables
- Collection start/end timestamps and per-file SHA-256 hashes
- Operator consent record (the user's consent selections, timestamp, and an HMAC-SHA256 integrity tag over the record contents)

The following are **never transmitted**:

- Plaintext session tokens (only SHA-256 hashes are logged)
- Locally entered BitLocker recovery credentials (used in-memory only)
- Your API key or server URL beyond the upload handshake

The collector performs no background telemetry; network activity is limited to the explicit upload you initiate. Data retention on the analysis platform is governed by that platform's privacy policy, independent of this repository.

## Download

Pre-built binaries are available on the [Releases](https://github.com/unjaena/unjaena-collector/releases) page:

| Platform | File |
|----------|------|
| Windows (x64) | `IntelligenceCollector-*-windows-x64.exe` |
| macOS (Apple Silicon) | `IntelligenceCollector-*-macos-arm64.dmg` |
| Linux (x64) | `IntelligenceCollector-*-linux-x64.tar.gz` |

## Requirements

- Python 3.10+
- Windows 10/11 (primary platform; macOS/Linux for respective artifact collection)
- Administrator privileges (required for raw disk access and memory acquisition)

### External Dependencies (not included)

| Tool | Purpose | License | How to obtain |
|------|---------|---------|----------------|
| WinPmem | Physical memory acquisition (optional) | Apache 2.0 | Download `winpmem_mini_x64.exe` from the [WinPmem releases](https://github.com/Velocidex/WinPmem/releases) page and place it in `resources/` before building. |
| libimobiledevice | iOS device communication | LGPL 2.1 | Run `python tools/download_libimobiledevice.py` once before the first iOS collection. |
| libusb | USB device access | LGPL 2.1 | Installed via `pip install libusb1` as part of requirements. |

## Installation

```bash
# Clone the repository
git clone https://github.com/unjaena/unjaena-collector.git
cd unjaena-collector

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Copy and configure
cp config.example.json config.json
# Edit config.json with your server URL
```

### iOS Collection Setup

```bash
# Download libimobiledevice binaries (Windows only; macOS/Linux use system libimobiledevice)
python tools/download_libimobiledevice.py

# pymobiledevice3 is installed automatically via requirements
```

### Android Collection Setup

USB drivers are handled via the `adb-shell[usb]` and `libusb1` packages. On Windows you may additionally need [Zadig](https://zadig.akeo.ie/) to bind the WinUSB driver to the target device — note that Zadig changes the driver at the system level, which can affect other USB devices. See [`resources/USB_DEPENDENCIES.md`](resources/USB_DEPENDENCIES.md) for details.

### Memory Acquisition Setup (optional)

Physical memory acquisition is opt-in and requires a user-supplied WinPmem binary. Download `winpmem_mini_x64.exe` from [WinPmem releases](https://github.com/Velocidex/WinPmem/releases) and place it in `resources/` before building. Without this file, memory acquisition is skipped and only pagefile/hiberfil raw reads are attempted.

## Usage

### GUI Mode (recommended)

```bash
python src/main.py
```

### Build Standalone Executable

```bash
# Development build (uses config.json or defaults)
python build.py --development

# Production build (expects a populated config.json alongside the script)
python build.py --production

# Check bundled dependencies
python build.py --check-deps
```

The production build reads `config.json` for `server_url` / `ws_url` / `dev_mode` / `allow_insecure`. Copy `config.example.json` to `config.json` and edit before building. (The GitHub Actions release workflow generates a `config.production.json` at build time from the `PRODUCTION_SERVER_URL` secret — that file is not required for local builds.)

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FORENSIC_SERVER_URL` | Analysis server HTTPS endpoint | read from `config.json` |
| `FORENSIC_API_KEY` | API authentication key | read from `config.json` |
| `FORENSIC_DEV_MODE` | Allow plain HTTP/WS for local testing | `false` |
| `FORENSIC_VERIFY_SSL` | Verify server TLS certificate | `true` |
| `COLLECTOR_DEV_MODE` | Enable GUI development hints | `false` |

### Config File (`config.json`)

See `config.example.json` for all available options including:
- Server connection settings
- Collection parameters (hashing, file size limits)
- Upload encryption settings
- Logging configuration

## Security

- **AES-256-GCM** authenticated encryption for all file transfers, with the per-file SHA-256 hash bound as additional authenticated data
- **SHA-256** file integrity verification for every collected artifact
- **HTTPS/WSS enforced** in production (PyInstaller) builds — TLS verification cannot be disabled at runtime; the dev-mode and `FORENSIC_VERIFY_SSL` flags apply only to source builds
- **One-time session tokens** with replay prevention (used-token set with expiry)
- **Operator consent record** captured with HMAC-SHA256 integrity tag over the user's selections, timestamp, and hostname hash. Server-side verification of this record against an analysis session is planned for a future release (see CHANGELOG.md, Known Limitations).

For details, see [SECURITY.md](SECURITY.md).

## Project Structure

```
unjaena-collector/
├── src/
│   ├── main.py                  # Entry point
│   ├── collectors/              # Platform-specific collectors
│   │   ├── artifact_collector.py    # Windows artifacts
│   │   ├── android_collector.py     # Android USB collection
│   │   ├── ios_collector.py         # iOS backup & extraction
│   │   ├── linux_collector.py       # Linux artifacts
│   │   ├── macos_collector.py       # macOS artifacts
│   │   ├── memory_collector.py      # Memory acquisition
│   │   ├── mft_collector.py         # MFT parsing
│   │   └── forensic_disk/           # Disk image access layer
│   ├── core/                    # Core infrastructure
│   ├── gui/                     # PyQt6 UI
│   └── utils/                   # Utilities
├── tools/                       # External tool management
├── resources/                   # Runtime resources
├── config.example.json          # Configuration template
├── requirements.txt             # Python dependencies
├── build.py                     # PyInstaller build script
└── LICENSE                      # AGPL-3.0
```

## License

This project is licensed under the **GNU Affero General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

This project depends on [dissect.fve](https://github.com/fox-it/dissect.fve) (AGPL-3.0) for BitLocker decryption, which requires the entire work to be distributed under AGPL-3.0.

### Key Dependencies & Licenses

| Package | License | Notes |
|---------|---------|-------|
| dissect.fve | AGPL-3.0 | BitLocker decryption |
| dissect.cstruct | AGPL-3.0 | Binary structure parsing (dissect dependency) |
| pymobiledevice3 | GPL-3.0 | iOS USB communication |
| PyQt6 | GPL-3.0 / Commercial | GUI framework |
| pytsk3 | Apache 2.0 | The Sleuth Kit bindings |
| adb-shell | Apache 2.0 | Android ADB protocol |
| libusb1 | LGPL 2.1 | USB device access |
| cryptography | Apache 2.0 / BSD | Cryptographic operations |

## Contributing

This project is **source-open for transparency**, not for community-driven development.
As a forensic evidence collection tool, code integrity directly impacts legal admissibility — all changes are reviewed and authored by the internal team.

- **Bug reports & security issues**: Please open a [GitHub Issue](https://github.com/unjaena/unjaena-collector/issues) or email `contact@unjaena.com`
- **Feature requests**: Welcome via Issues — we review and prioritize internally
- **Pull requests**: Not accepted at this time
