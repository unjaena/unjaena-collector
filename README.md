# unJaena AI — Digital Intelligence Collector

> The official evidence collection tool for the **unJaena AI** forensic analysis platform.
> Collected artifacts are automatically uploaded for AI-powered analysis including MITRE ATT&CK mapping, timeline reconstruction, and multilingual investigation reports.

Cross-platform digital forensic artifact collection tool with GUI. Collects evidence from Windows, macOS, Linux, Android, and iOS devices with cryptographic integrity verification and secure upload.

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
