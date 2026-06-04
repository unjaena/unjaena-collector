# unJaena Collector

unJaena Collector is the open-source acquisition client for authenticated
unJaena forensic collection sessions. It provides desktop and EnCase-side
capture transport for evidence sources such as live systems, connected mobile
devices, disk images, virtual disks, and selected EnCase entries. Collected
records are uploaded to the unJaena service for server-side parsing, indexing,
embedding, AI-assisted review, timeline analysis, and reporting.

The public repository is intentionally limited to acquisition, local source
access, consent, transport, release tooling, and EnCase integration source.
Product-specific target catalogs, proprietary parsers, AI analysis rules,
timeline ranking, scoring models, private infrastructure, and customer case data
are not part of this repository.

## Public Client Boundary

After a session token is validated, the service returns scoped credentials and a
signed collection profile for that case. The collector uses that profile to
decide which source types and artifact classes are authorized locally. The
backend also validates profile identifiers and upload tickets so unauthorized
targets can be rejected server-side.

This design keeps the public client auditable while keeping sensitive detection
policy, parser behavior, analysis rules, and case-specific authorization outside
the public source tree.

## Capabilities

- Desktop collection workflows for Windows, macOS, and Linux
- Live local filesystem and logical volume acquisition when permissions allow
- Read-only disk image, raw image, and virtual disk acquisition through local
  backends and available native dependencies
- Filesystem access for supported containers and filesystems, including NTFS,
  FAT/exFAT, APFS, HFS+, ext, XFS, Btrfs, UFS/FFS, BitLocker, and LUKS when the
  required runtime support and credentials are available
- Android and iOS discovery and collection paths when drivers, pairing, trust,
  device authorization, and platform tooling are available
- Offline mobile filesystem extraction bundle ingestion for server-authorized
  profiles
- EnCase selected-entry upload integration under `tools/encase`
- Consent capture, signed API requests, encrypted transport, upload manifests,
  content hashes, and chain-of-custody metadata

## Not Included

- Proprietary parser implementations
- Proprietary AI, timeline, malware, or scoring logic
- Static application-specific collection target catalogs
- Production secrets, signing keys, notarization credentials, or service tokens
- Private evidence, sample case data, or customer-specific workflows
- Commercial support credentials, deployment scripts, or production
  infrastructure details

## Supported Environments

Release artifacts are built for:

- Windows x64
- macOS Apple Silicon
- macOS Intel
- Linux x64

Actual acquisition coverage depends on the operating system, privileges, native
libraries, device trust state, image condition, encryption state, and server
collection profile. Encrypted containers require the proper credentials. Mobile
collection requires lawful authority, user/device approval, and a trusted USB
connection or a supported offline extraction bundle.

## Session Workflow

1. Create or open a case in the unJaena web application.
2. Generate a collector session token for that case.
3. Start the collector and authenticate with the session token.
4. Review and accept the collection consent dialog.
5. Select authorized sources such as mounted volumes, disk images, mobile
   devices, offline bundles, or EnCase entries.
6. The collector loads the server profile, collects allowed sources, computes
   hashes, and uploads evidence records.
7. The service performs parsing, embedding, timeline construction, AI-assisted
   review, dashboard updates, and report generation.

## Operator Requirements

- Use the collector only with proper authorization, such as owner consent,
  organizational authority, or a valid legal order.
- Run with administrator/root privileges when the selected source requires raw
  disk, protected filesystem, or device access.
- Keep the device connected and powered during mobile or large image workflows.
- For stable iOS USB collection, enable encrypted backup in Apple Devices,
  Finder, or iTunes before starting collection and keep the backup password
  available for the collector prompt.
- For iOS USB collection, keep the iPhone unlocked and be ready to enter the
  physical device passcode on the iPhone screen if iOS prompts for it.
- Verify release checksums before operating in sensitive environments.
- Do not paste session tokens, credentials, private logs, or customer evidence
  into public issues or discussions.

## Releases

End users should normally download signed release artifacts from the GitHub
Releases page instead of running from source:

- Windows: `.exe`
- macOS Apple Silicon: `.dmg`
- macOS Intel: `.dmg`
- Linux: `.tar.gz`

Release artifacts include `SHA256SUMS.txt` for integrity verification. macOS
artifacts are signed and notarized when the release workflow has access to the
required Apple signing credentials.

## Release Validation

Before tagging a release, run the source acceptance gate:

```bash
python tools/release_gate.py --actual-local
```

The gate compiles source files, checks the public-client boundary, verifies
server-profile filtering, simulates Windows logical-drive discovery, checks
actual local-source discovery on the current OS, and exercises GUI artifact
selection, source scoping, consent layout, duplicate-start locking, and
collection-plan behavior with non-sensitive smoke targets. GitHub Actions runs
the same gate before platform builds.

Recommended release checks:

- `python tools/public_preflight.py`
- `python tools/release_gate.py --actual-local`
- Platform build through GitHub Actions
- Checksum publication for all release assets
- Manual smoke test with a non-sensitive token and non-sensitive sample source

## Build From Source

Install Python 3.11 and the platform dependency set for your host OS.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements/linux.txt
python build.py
```

On Windows, use `requirements/windows.txt`. On macOS, use
`requirements/macos.txt`. Some disk-image, mobile, and filesystem backends
require native libraries, OS drivers, or administrator/root privileges.

## Repository Layout

- `src/`: public collector client source
- `requirements/`: platform-specific dependency sets
- `resources/`: public runtime resources bundled with releases
- `tools/`: release, validation, smoke-test, and EnCase integration tooling
- `.github/workflows/`: CI, release, signing, and notarization workflows
- `docs/`: public images and documentation assets

## EnCase Integration

The EnCase source package is in `tools/encase`.

- `UnjaenaCollector.EnScript` is the EnScript entry point.
- `dotnet/CollectorClient.cs` is the .NET bridge used for authenticated API
  calls and upload transport.
- `dotnet/UnjaenaEncaseBridge.csproj` builds `UnjaenaEncaseBridge.dll`.

See `tools/encase/README.md` before publishing or operating the EnCase workflow.
The bridge uses the same session token, collection profile, consent, profile
identifier, and upload-ticket enforcement model as the desktop collector.

## Security Model

- Remote service URLs must use TLS.
- Session tokens are exchanged for scoped collection credentials.
- Collection profiles are loaded after authentication and enforced locally and
  by the backend.
- Upload requests include the server profile identifier so the backend can
  reject unauthorized targets.
- Consent records are submitted before collection starts.
- Sensitive target policy and parser logic remain server-side.

See `SECURITY.md` for vulnerability reporting and secret-handling guidance.

## License

This repository's source code is licensed under AGPL-3.0-or-later. Distributed
builds may include third-party components under their own license terms,
including GPL, AGPL, LGPL, MPL, BSD, MIT, Apache, PSF, and public-domain
components. See `LICENSE` and `LICENSES.md` for details.
