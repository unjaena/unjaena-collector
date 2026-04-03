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
- **Memory Forensics**: Physical memory acquisition (WinPmem), hibernation/pagefile analysis
- **Android Forensics**: USB direct collection via ADB protocol (no external ADB binary required)
- **iOS Forensics**: USB direct backup and artifact extraction via pymobiledevice3
- **macOS / Linux Forensics**: System logs, user artifacts, browser data, shell history
- **Disk Image Support**: E01 (Expert Witness Format), RAW image analysis
- **BitLocker Support**: Encrypted volume access with recovery key/password/BEK
- **Secure Upload**: AES-256-GCM encrypted transfer
- **Chain of Custody**: SHA-256 integrity verification with tamper-evident logging
- **Multi-language GUI**: PyQt6 interface with i18n support

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

| Tool | Purpose | License | Download |
|------|---------|---------|----------|
| WinPmem | Memory acquisition | Apache 2.0 | [GitHub](https://github.com/Velocidex/WinPmem/releases) |
| libimobiledevice | iOS device communication | LGPL 2.1 | Auto-downloaded via `build.py` |
| libusb | USB device access | LGPL 2.1 | Installed via `pip install libusb1` |

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
# Download libimobiledevice binaries (Windows)
python tools/download_libimobiledevice.py

# Or use pymobiledevice3 directly (cross-platform)
pip install pymobiledevice3
```

### Android Collection Setup

USB drivers are handled automatically via `adb-shell[usb]` and `libusb1` packages. No external ADB binary required.

### Memory Acquisition Setup

Download `winpmem_mini_x64.exe` from [WinPmem releases](https://github.com/Velocidex/WinPmem/releases) and place it in `resources/`.

## Usage

### GUI Mode (recommended)

```bash
python src/main.py
```

### Build Standalone Executable

```bash
# Development build
python build.py --development

# Production build (requires HTTPS server URL)
python build.py --production --server-url https://your-server.com

# Check dependencies before building
python build.py --check-deps
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `COLLECTOR_SERVER_URL` | Server endpoint | — |
| `COLLECTOR_WS_URL` | WebSocket endpoint | — |
| `COLLECTOR_DEV_MODE` | Enable development mode | `false` |

### Config File (`config.json`)

See `config.example.json` for all available options including:
- Server connection settings
- Collection parameters (hashing, file size limits)
- Upload encryption settings
- Logging configuration

## Security

- **AES-256-GCM** authenticated encryption for all file transfers
- **SHA-256** file integrity verification
- **HTTPS/WSS enforced** in production mode with TLS certificate verification
- **One-time session tokens** with replay prevention
- **Chain of custody** logging with tamper-evident audit trail

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

- **Bug reports & security issues**: Please open a [GitHub Issue](https://github.com/unjaena/unjaena-collector/issues) or email `admin@unjaena.com`
- **Feature requests**: Welcome via Issues — we review and prioritize internally
- **Pull requests**: Not accepted at this time
