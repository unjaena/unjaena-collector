# unjaena-collector

Open unJaena desktop client for authorized forensic collection workflows.

This repository contains the public client shell only: service authentication, signed profile validation, local file hashing, optional encrypted transport preparation, upload completion, and a desktop interface for local live collection, forensic image or bundle source upload, and server-profile driven artifact selection. The collection catalog, parsing, scoring, analysis, reporting, policy, and recovery logic are delivered or executed by the service.

## Install

Use the latest release asset for your platform when available. Windows releases publish a direct `.exe`; macOS releases publish a signed `.dmg` when signing material is configured, with archive fallbacks for diagnostics. The Python package exposes both command line and desktop entry points.

```bash
python -m pip install unjaena_collector-0.3.1-py3-none-any.whl
unjaena-collector-gui
```

The command line entry point is also available.

```bash
unjaena-collector --server https://app.unjaena.com --token CASE_SESSION_TOKEN
```

## Desktop Flow

1. Open `unjaena-collector-gui`.
2. Confirm the service address.
3. Paste the case session token issued by the service.
4. Review detected local systems, volumes, Android USB devices, iOS USB devices, and local iOS backups.
5. Add evidence images, virtual disks, filesystem images, or mobile extraction bundles when needed.
6. Use Auto detect for normal files, or pick a Source type for extensionless filesystem volume images.
7. Review the server-signed collection profile targets.
8. Start collection and keep the app open until the upload summary is complete.

The desktop app shows detected devices, source type, source file size, server profile targets, scan count, upload count, skipped files, failed files, and a short event log. It does not embed local path catalogs or product-specific collection rules; profile targets are loaded after session authentication.

## Supported Evidence Sources

The public client can upload source files only when the authenticated server profile authorizes the matching source type. Supported source families include:

- E01, Ex01, L01, Lx01, S01, and split EWF segments.
- DD, RAW, IMG, BIN, and split raw segments such as 001/002.
- AFF, AFF4, AFD, AFM, and AD1 forensic containers.
- VMDK, VDI, VHD, VHDX, QCOW2, QED, HDD, and VPC virtual disks.
- ISO, DMG, and CDR disk images.
- NTFS, FAT, FAT12, FAT16, FAT32, exFAT, ext, ext2, ext3, ext4, XFS, Btrfs, HFS, HFSX, APFS, and UFS volume images.
- Cellebrite UFDR/CLBX, ZIP, TAR, TGZ, GZ, and 7Z extraction bundles.

## Device Discovery

The desktop interface detects local live filesystems, Windows volumes and physical disks when available, Android USB devices through ADB/platform-tools, iOS USB devices through pymobiledevice3/usbmux, and local iOS backup directories. Device discovery is operator visibility and source selection; detailed target rules remain service-owned and are authorized by the signed profile.

## Security Model

- The client receives a signed collection profile at runtime.
- The client verifies the profile signature when the service provides a signing key.
- Upload requests are bound to the authenticated collection session.
- File hashes are calculated locally before upload.
- The service can require encrypted upload payloads through per-upload material.
- Uploaded artifact types must match the issued profile.
- The public client does not contain hardcoded collection targets, parser code, analysis code, scoring code, report generation code, or service policy rules.

## Public Contribution Boundary

Do not add platform artifact catalogs, product-specific target names, parser behavior, analysis prompts, report templates, account policy, billing policy, deployment paths, or operational infrastructure details to this repository.

UI improvements, packaging improvements, transport hardening, profile verification, upload reliability, and tests are appropriate here when they keep service-side policy outside the public client.
