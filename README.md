# unJaena Collector

unJaena Collector is the open-source desktop acquisition client for authenticated unJaena forensic collection sessions.

The collector is intentionally a case-scoped acquisition client. It does not embed private product-specific target catalogs or server-side analysis logic. After a user validates a session token, the unJaena service returns a signed collection profile that authorizes the exact local sources and offline evidence formats for that case.

## What It Does

- Validates an unJaena collection session token.
- Presents a user consent workflow before collection starts.
- Discovers local evidence sources that are available on the current operating system.
- Registers forensic images and offline mobile filesystem bundles selected by the user.
- Reads supported disk image and filesystem formats locally.
- Handles BitLocker and LUKS detection; unlocked volumes are collected through the same disk access path.
- Uploads encrypted collection output to the service using scoped credentials and signed API requests.
- Checks for updates on startup so users can move to the current release.

## Supported Evidence Sources

The available sources depend on operating system permissions, installed platform tooling, and the server-issued collection profile.

- Local live filesystem collection on Windows, macOS, and Linux.
- Windows logical volumes and physical disks when the collector is run with administrator privileges.
- Forensic and virtual disk images: E01, Ex01, S01, L01, DD, RAW, IMG, BIN, split RAW `.001`, VMDK, VHD, VHDX, QCOW2, VDI, and DMG.
- Filesystems: NTFS, FAT12, FAT16, FAT32, exFAT, ext2, ext3, ext4, XFS, Btrfs, HFS, HFS+, HFSX, APFS, and UFS/FFS where the runtime parser supports the sample.
- Encrypted volumes: BitLocker detection and unlocked-reader collection, plus LUKS passphrase unlock for supported LUKS1/LUKS2 images.
- Android USB collection when Android platform tooling and device authorization are available.
- iOS USB and iOS backup collection when device trust, pairing, and platform libraries are available.
- Offline mobile filesystem bundles, including supported Cellebrite UFED FFS / CLBX zip exports, when runtime profile specifications authorize them.

## Security Model

- Collection policy is provided by the service at runtime and is scoped to the authenticated session.
- Static product-specific target catalogs are intentionally excluded from this public repository.
- Session tokens are exchanged for short-lived collection credentials.
- Upload requests include the profile identifier so the backend can enforce the same scope.
- Consent records are signed and submitted before collection starts.
- Local collection output is packaged for upload; long-term storage, parsing, embedding, AI analysis, retention, and deletion policy are enforced server-side.

## Running From Source

Python 3.11 is recommended.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements/linux.txt
python src/main.py
```

Use the platform-specific requirements file for your operating system:

- `requirements/windows.txt`
- `requirements/macos.txt`
- `requirements/linux.txt`

Some capabilities require OS privileges or external trust prompts. Physical disks and live protected paths usually require administrator/root privileges. Android and iOS collection require the device owner to authorize the workstation.

## Release Artifacts

Official releases are built by GitHub Actions from tags named `collector-v*`.

- Windows: signed or packaged `.exe`
- macOS: signed and notarized `.dmg` for Apple Silicon and Intel when Apple credentials are configured
- Linux: executable tarball

Each release includes SHA-256 checksums.

## Public Repository Boundary

This repository contains the acquisition client only. It does not contain private parser rules, server-side scoring, AI analysis prompts, retention policy implementation, billing logic, or case-management backend code.

## License

unJaena Collector is licensed under AGPL-3.0-or-later. See `LICENSE` and `LICENSES.md` for third-party license notes.
