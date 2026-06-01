# unJaena Collector

unJaena Collector is the open-source acquisition client for authenticated unJaena forensic collection sessions. It provides the desktop and EnCase-side capture transport used to collect evidence from local systems, connected devices, disk images, and forensic image workflows, then upload the collected material to the unJaena service for parsing, indexing, AI-assisted analysis, timeline review, and reporting.

The public source tree intentionally excludes product-specific target catalogs, proprietary parsers, analysis rules, scoring models, and case policy. After a user validates a session token, the service returns a signed collection profile that authorizes the exact sources for that case. The collector executes local acquisition engines and upload transport only within that profile.

## What is included

- Desktop GUI for Windows, macOS, and Linux collection workflows
- Local logical-volume and live-filesystem acquisition when privileges allow access
- Physical disk, forensic image, raw image, and virtual disk workflows through local disk access backends
- Filesystem access for supported image containers and filesystems, including NTFS, FAT/exFAT, APFS, HFS+, ext, XFS, Btrfs, UFS/FFS, BitLocker, and LUKS where the required runtime dependencies are available
- Mobile device discovery and collection paths for Android and iOS when platform tooling, drivers, pairing, and user authorization are available
- Offline mobile filesystem extraction bundle ingestion for server-authorized profiles
- EnCase integration source under `tools/encase` for selected-entry upload from OpenText EnCase
- Collection consent handling, signed API requests, encrypted transport, upload manifests, hashes, and chain-of-custody metadata

## What is not included

- Proprietary parser implementations
- Proprietary AI, timeline, malware, or scoring logic
- Static application-specific collection target catalogs
- Production secrets, signing keys, notarization credentials, or service credentials
- Private case data, sample evidence, or customer-specific workflows

## Session workflow

1. Create or open a case in the unJaena web application.
2. Generate a collector session token for that case.
3. Start the collector and authenticate with the session token.
4. Review and accept the collection consent dialog.
5. Select authorized sources such as mounted volumes, disk images, mobile devices, offline bundles, or EnCase entries.
6. The collector loads the server profile, collects allowed sources, computes hashes, and uploads evidence records.
7. The service performs parsing, embedding, timeline construction, AI-assisted review, dashboard updates, and report generation.

## Releases

End users should normally download signed release artifacts from the GitHub Releases page instead of running from source:

- Windows: `.exe`
- macOS Apple Silicon: `.dmg`
- macOS Intel: `.dmg`
- Linux: `.tar.gz`

Release artifacts include `SHA256SUMS.txt` for integrity verification.

## Release validation

Before tagging a release, run the source acceptance gate:

```bash
python tools/release_gate.py --actual-local
```

The gate compiles source files, checks the public-client boundary, verifies server-profile filtering, simulates Windows logical-drive discovery, checks actual local-source discovery on the current OS, and exercises GUI artifact selection, source scoping, consent layout, duplicate-start locking, and collection-plan behavior with non-sensitive smoke targets. GitHub Actions runs the same gate before each platform build.

## Build from source

Install Python 3.11 and the platform dependency set for your host OS.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements/linux.txt
python build.py
```

On Windows, use `requirements/windows.txt`. On macOS, use `requirements/macos.txt`. Some disk-image, mobile, and filesystem backends require native libraries, OS drivers, or administrator/root privileges.

## EnCase integration

The EnCase source package is in `tools/encase`.

- `UnjaenaCollector.EnScript` is the EnScript entry point.
- `dotnet/CollectorClient.cs` is the .NET bridge used for authenticated API calls and upload transport.
- `dotnet/UnjaenaEncaseBridge.csproj` builds `UnjaenaEncaseBridge.dll`.

See `tools/encase/README.md` before publishing or operating the EnCase workflow. The bridge uses the same session token, collection profile, consent, profile identifier, and upload-ticket enforcement model as the desktop collector.

## Security model

- Remote server URLs must use TLS.
- Session tokens are exchanged for scoped collection credentials.
- Collection profiles are loaded after authentication and are enforced locally and by the backend.
- Upload requests include the server profile identifier so the backend can reject unauthorized targets.
- Consent records are submitted before collection starts.
- Sensitive target policy and parser logic remain server-side.

## License

This repository is licensed under AGPL-3.0-or-later. The license choice is intentional because the collector distributes and integrates GPL/AGPL-compatible components, including PyQt6, pymobiledevice3, and Dissect packages. See `LICENSE` and `LICENSES.md` for details.
