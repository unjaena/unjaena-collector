# unJaena Intelligence Collector

The public evidence collection client for the unJaena forensic analysis
platform.

This repository contains the collector only. Server-side parsing and analysis
workflow logic are not part of this public repository.

## Latest Release

Latest release: `collector-v2.6.3`

Download pre-built binaries from:

https://github.com/unjaena/unjaena-collector/releases/latest

Typical files:

| Platform | Artifact |
| --- | --- |
| Windows x64 | `IntelligenceCollector-*-windows-x64.exe` |
| macOS Apple Silicon | `IntelligenceCollector-*-macos-arm64.dmg` |
| Linux x64 | `IntelligenceCollector-*-linux-x64.tar.gz` |

## What It Does

unJaena Intelligence Collector collects forensic artifacts from authorized
systems and uploads them to a configured analysis service with integrity
metadata.

Supported collection targets include:

- Windows endpoints
- macOS endpoints
- Linux endpoints
- Android devices
- iOS backups and supported mobile sources
- Forensic disk images and virtual disk images

Supported image/container formats depend on the installed optional libraries,
but the collector is designed to work with common formats such as:

- E01 / Expert Witness Format
- RAW / DD / IMG
- VHD / VHDX
- VMDK
- VDI
- QCOW2
- DMG

## Key Capabilities

- GUI-based collection workflow
- Local disk and image-based collection
- Artifact selection by operating system and device type
- Windows registry, event log, browser, USB, shell, application, and user
  activity artifacts
- Modern Windows artifact collection, including Windows Search index files,
  notification databases, Phone Link caches, WSL files, and related metadata
- macOS user, system, browser, shell, and application artifacts
- Linux log, shell, package, container, browser, and user activity artifacts
- Android and iOS artifact acquisition paths where supported by device state,
  backup state, and platform permissions
- BitLocker access when the operator provides valid recovery credentials
- Optional memory-related collection paths where the operator supplies required
  third-party acquisition tools
- Per-file hash calculation for chain-of-custody support
- Secure upload to a configured analysis endpoint

## Important Scope Notes

This collector is an acquisition client. It does not expose the proprietary
server-side analysis engine.

The following are intentionally not included in this repository:

- Server parser implementations
- Analysis prompts or logic
- Server-side indexing logic
- Server-side correlation logic
- Internal production deployment configuration
- Service tokens, credentials, or private endpoints

Public documentation should describe collection capability at a high level
only. Do not add implementation details that would reveal server-side analysis
logic or private operational controls.

## Quick Start From Source

```bash
git clone https://github.com/unjaena/unjaena-collector.git
cd unjaena-collector
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
# source venv/bin/activate

pip install -r requirements.txt
python src/main.py
```

You can also use:

```bash
# Windows
run.bat

# macOS / Linux
./run.sh
```

## Configuration

Copy the example configuration and set the upload endpoint for your analysis
service.

```bash
cp config.example.json config.json
```

The hosted service endpoint is:

```text
https://app.unjaena.com
```

Use only authorized session credentials issued by your analysis service.

## Requirements

- Python 3.10 or newer when running from source
- Administrator or equivalent privileges for raw disk, protected system
  locations, and some image workflows
- USB access permissions for mobile device collection
- Optional platform libraries for some disk image and mobile workflows

## External Tools

Some workflows require third-party tools that are not bundled in this
repository.

| Tool | Purpose |
| --- | --- |
| WinPmem | Optional physical memory acquisition on Windows |
| libimobiledevice | iOS device communication |
| libusb | USB device access |

Operators are responsible for obtaining third-party tools from their official
sources and complying with their licenses.

## Privacy and Data Handling

The collector uploads only when the operator starts a collection and provides
valid session information.

Uploaded data may include:

- Selected artifact files
- File names and original paths
- File hashes and size metadata
- Host and device metadata needed for evidence handling
- Collection timestamps
- Operator consent records when enabled by the configured service

The collector should be used only on systems where you have explicit legal
authority to collect evidence.

## Legal Notice

This software is provided for authorized forensic, incident response, and
research use. You are responsible for ensuring that your use complies with all
applicable laws, policies, contracts, and consent requirements.

This project is not a substitute for legal advice, organizational
chain-of-custody procedures, or certified forensic tooling required by a
specific court or regulator.

## License

This project is distributed under the GNU Affero General Public License v3.0.

The AGPL obligations apply to this public collector repository. The separate
server-side analysis platform is independently developed and is not included in
this repository.

See `LICENSE` for details.

## Security

Please do not open public issues containing:

- Real evidence files
- Session tokens
- Credentials
- Private URLs
- Personal data
- Internal case identifiers

Report sensitive security issues privately to the maintainers.

## Changelog

See `CHANGELOG.md` for release history.
