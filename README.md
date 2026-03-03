# Forensic Artifact Collector

Cross-platform digital forensic artifact collection tool with GUI. Collects evidence from Windows, macOS, Linux, Android, and iOS devices with cryptographic integrity verification and secure upload capabilities.

## Features

- **Windows Forensics**: MFT, registry, prefetch, event logs, browser history, USB artifacts
- **Memory Forensics**: Physical memory acquisition (WinPmem), hibernation/pagefile analysis
- **Android Forensics**: USB direct collection via ADB protocol (no external ADB binary required)
- **iOS Forensics**: USB direct backup and artifact extraction via pymobiledevice3
- **macOS / Linux Forensics**: System logs, user artifacts, browser data, shell history
- **Disk Image Support**: E01 (Expert Witness Format), RAW image analysis
- **BitLocker Support**: Encrypted volume access with recovery key/password/BEK
- **Secure Upload**: AES-256-GCM encrypted transfer with HKDF key derivation
- **Chain of Custody**: SHA-256 integrity verification with tamper-evident logging
- **Multi-language GUI**: PyQt6 interface with i18n support

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
git clone https://github.com/YOUR-ORG/forensic-collector.git
cd forensic-collector

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
cp config.example.json config.json
# Edit .env and config.json with your server settings
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
| `COLLECTOR_SERVER_URL` | Server API endpoint | — |
| `COLLECTOR_WS_URL` | WebSocket endpoint | — |
| `COLLECTOR_DEV_MODE` | Enable development mode | `false` |
| `COLLECTOR_ALLOW_INSECURE` | Allow HTTP (dev only) | `false` |

### Config File (`config.json`)

See `config.example.json` for all available options including:
- Server connection settings
- Collection parameters (hashing, file size limits)
- Upload encryption settings
- Logging configuration

## Security

### Cryptography
- **AES-256-GCM**: Authenticated encryption for file uploads
- **HKDF-SHA256**: Key derivation from server-issued master secrets
- **SHA-256**: File integrity verification (MD5 deprecated)

### Network
- **HTTPS/WSS enforced** in production mode
- **TLS certificate verification** enabled by default
- HTTP/WS connections rejected unless explicitly allowed in development

### Authentication
- One-time session tokens with hardware binding
- Token replay prevention with expiry tracking
- Hardware ID based on multiple system identifiers

### Evidence Integrity
- Chain of custody logging with SHA-256 hash chains
- Tamper-evident audit trail
- Server-side verification of uploaded file hashes

## Project Structure

```
collector/
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
│   │   ├── encryptor.py             # Hash utilities
│   │   ├── secure_upload.py         # Encrypted file upload
│   │   ├── uploader.py              # Upload management
│   │   ├── token_validator.py       # Session authentication
│   │   └── device_manager.py        # Device enumeration
│   ├── gui/                     # PyQt6 UI
│   │   ├── app.py                   # Main application window
│   │   ├── consent_dialog.py        # Data collection consent
│   │   └── ...
│   └── utils/                   # Utilities
│       ├── bitlocker/               # BitLocker decryption (via pybde)
│       ├── hardware_id.py           # Hardware identification
│       └── error_messages.py        # User-friendly error handling
├── tests/                       # Unit & integration tests
├── tools/                       # External tool management
├── resources/                   # Runtime resources
├── config.example.json          # Configuration template
├── .env.example                 # Environment template
├── requirements.txt             # Python dependencies
├── build.py                     # PyInstaller build script
└── LICENSE                      # GPL-3.0
```

## Server API Contract

The collector communicates with a backend server via these endpoints:

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/collector/authenticate` | Device authentication |
| POST | `/api/v1/collector/validate-session` | Session validation |
| GET | `/api/v1/collector/consent` | Consent template retrieval |
| POST | `/api/v1/collector/consent/accept` | Consent acceptance |
| POST | `/api/v1/collector/raw-files/upload` | Raw file upload |
| POST | `/api/v1/upload/session` | Encrypted upload session |
| POST | `/api/v1/upload/file` | Encrypted file upload |
| POST | `/api/v1/upload/verify/{file_id}` | File integrity verification |
| WSS | `/ws/collection/{session_id}` | Real-time progress |

## Testing

```bash
# Run all tests
pytest tests/

# Run specific test suite
pytest tests/test_android_collector.py -v
pytest tests/test_ios_collector.py -v
```

## License

This project is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

### Key Dependencies & Licenses

| Package | License | Notes |
|---------|---------|-------|
| pymobiledevice3 | GPL-3.0 | iOS USB communication |
| PyQt6 | GPL-3.0 / Commercial | GUI framework |
| pytsk3 | Apache 2.0 | The Sleuth Kit bindings |
| adb-shell | Apache 2.0 | Android ADB protocol |
| libusb1 | LGPL 2.1 | USB device access |
| cryptography | Apache 2.0 / BSD | Cryptographic operations |
| pybde | LGPL 3.0 | BitLocker decryption |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

Please ensure:
- All tests pass before submitting
- No credentials or personal data in commits
- Follow existing code style and patterns
