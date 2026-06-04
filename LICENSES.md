# Third-Party License Notice

unJaena Collector is licensed under AGPL-3.0-or-later. This choice is
intentional for the distributed public client because the project integrates
GPL/AGPL-compatible forensic, GUI, disk, and mobile-device components.

This notice summarizes direct dependencies used by the public collector and the
major binary components that can be bundled in release artifacts. It is not a
complete software bill of materials. Always verify upstream package metadata,
lock files, bundled binary artifacts, and transitive dependencies before a
production release because dependency versions and license expressions can
change.

## Repository License

Unless a file states otherwise, source files in this repository are distributed
under AGPL-3.0-or-later. See `LICENSE` for the full license text.

## High-Impact Copyleft Dependencies

| Component | Purpose | Reported license |
| --- | --- | --- |
| PyQt6 | Desktop GUI framework | GPL-3.0-only in PyPI metadata; commercial licensing is available from Riverbank |
| pymobiledevice3 | iOS device communication and services | GPL-3.0-or-later |
| developer-disk-image, ipsw-parser, la-panic, opack2, parameter-decorators, pycrashreport, pygnuutils | iOS support dependencies | GPL-3.0 or GPL-3.0-or-later depending on package metadata |
| Dissect framework packages | Disk, volume, filesystem, BitLocker, LUKS, and virtual disk helpers | AGPL-3.0-or-later |

## Direct Runtime Dependency Review

The following table is based on the package metadata available from PyPI during
the 2026-06-04 public documentation review. Packages with broad version ranges
must be rechecked against the exact versions used by a release build.

| Component | Purpose | Typical license family |
| --- | --- | --- |
| adb-shell | Android ADB communication | Apache-2.0 |
| aiohappyeyeballs | Async connection support | PSF-2.0 |
| aiohttp | Async HTTP support | Apache-2.0 AND MIT |
| aiosignal | aiohttp dependency | Apache-2.0 |
| asn1crypto | ASN.1 parsing | MIT |
| attrs | Utility dependency | MIT |
| biplist | Apple binary plist support | BSD |
| bpylist2 | NSKeyedArchiver plist support | MIT |
| certifi | CA certificate bundle | MPL-2.0 |
| charset-normalizer | Text encoding detection | MIT |
| click | CLI support dependency | BSD-3-Clause |
| construct, construct-typing | Binary structure parsing | MIT |
| cryptography | Cryptographic primitives | Apache-2.0 OR BSD-3-Clause |
| developer-disk-image | iOS developer disk image support | GPL-3.0-or-later |
| dissect.apfs, dissect.btrfs, dissect.cstruct, dissect.extfs, dissect.fat, dissect.ffs, dissect.fve, dissect.hypervisor, dissect.ntfs, dissect.util, dissect.volume, dissect.xfs | Disk, filesystem, virtual disk, and encryption helpers | AGPL-3.0-or-later |
| frozenlist | aiohttp dependency | Apache-2.0 |
| hexdump | Hex dump helper | Public Domain |
| hyperframe | HTTP/2 framing dependency | MIT |
| idna | Internationalized domain names | BSD-3-Clause |
| ifaddr | Network interface discovery | MIT |
| iphone_backup_decrypt | iOS encrypted backup extraction helper | License not declared in PyPI metadata; verify upstream before release |
| ipsw-parser | iOS IPSW parsing | GPL-3.0-or-later |
| la-panic | Apple panic log parsing | GPL-3.0-or-later |
| libewf-python | EWF/E01 image bindings | LGPL-3.0-or-later |
| libfshfs-python | HFS+ bindings | LGPL-3.0-or-later |
| libusb1 | libusb wrapper | LGPL-2.1-or-later |
| lzfse | Apple LZFSE decompression | MIT |
| multidict | aiohttp dependency | Apache-2.0 |
| nest-asyncio | Nested asyncio support | BSD |
| opack2 | Apple opack serialization support | GPL-3.0-or-later |
| packaging | Packaging/version utilities | Apache-2.0 OR BSD-2-Clause |
| parameter-decorators | pymobiledevice3 dependency | GPL-3.0 |
| propcache | aiohttp dependency | Apache-2.0 |
| pycrashreport | Apple crash report parsing | GPL-3.0-or-later |
| pycryptodome | Cryptographic helpers used by mobile backup tooling | BSD/Public Domain |
| pygnuutils | GNU utility wrappers | GPL-3.0-or-later |
| pymobiledevice3 | iOS device communication and services | GPL-3.0-or-later |
| PyQt6 | Desktop GUI framework | GPL-3.0-only in PyPI metadata, unless a commercial license is used |
| python-dateutil | Date utilities | Apache-2.0 OR BSD |
| pytsk3 | Sleuth Kit bindings | Apache-2.0 in PyPI metadata; bundled native license files also apply |
| pyusb | USB support | BSD |
| pywin32 | Windows API support | PSF |
| qh3 | QUIC/HTTP3 dependency | BSD |
| requests | HTTP client | Apache-2.0 |
| rsa | RSA helper dependency | Apache-2.0 |
| srptools | SRP authentication helper | BSD-3-Clause |
| tqdm | Progress utilities | MPL-2.0 AND MIT |
| ujson | JSON support | BSD-3-Clause AND TCL |
| urllib3 | HTTP client dependency | MIT |
| websockets | WebSocket protocol support | BSD-3-Clause |
| wmi | Windows Management Instrumentation | MIT |
| wsproto | WebSocket protocol dependency | MIT |
| yarl | URL handling dependency | Apache-2.0 |

## Build and Packaging Dependencies

| Component | Purpose | License note |
| --- | --- | --- |
| PyInstaller | Application packaging | GPLv2-or-later with bootloader exception according to PyPI metadata; verify current upstream terms |
| platform-tools or ADB binaries, when bundled | Android device communication | Android SDK/platform-tools license terms apply |
| libimobiledevice Windows binaries, when downloaded | Optional Windows iOS helper binaries | LGPL-2.1 notice generated by `tools/download_libimobiledevice.py`; verify exact binary source and hash before release |
| OS signing and notarization tools | Platform release integrity | Platform vendor terms apply |

## Notable Transitive or Bundled Components

The release build can also bundle native wheels, Qt runtime files, certificate
bundles, and platform helper binaries. The exact set depends on the build
environment and PyInstaller analysis output.

| Component | Relationship | License note |
| --- | --- | --- |
| PyQt6-Qt6 | PyQt6 runtime wheel | LGPL v3 in PyPI metadata |
| PyQt6-sip | PyQt6 support dependency | BSD-2-Clause |
| six | Common Python compatibility dependency | MIT |

This list is intentionally limited to notable examples. Use the release
checklist below to produce an exact SBOM for each build.

## License Boundary

This repository contains the public acquisition client and EnCase integration
source. Proprietary server-side parsers, AI analysis services, malware scoring,
timeline ranking, production service code, and customer case data are separate
systems that communicate with the collector over authenticated HTTP APIs.

The public client source and distributed collector binaries remain under
AGPL-3.0-or-later. If a deployment uses commercial PyQt licensing or replaces
GPL/AGPL components, review the resulting license obligations before
distributing modified binaries.

## Release Manager Checklist

Before publishing a public release:

- review `requirements/` and bundled resources for license changes
- regenerate or review dependency lock files when used
- generate and archive an SBOM or equivalent dependency report for the exact
  build environment
- recheck packages whose metadata was missing or ambiguous, especially native
  bindings and mobile-device helper packages
- verify that no private evidence, secrets, certificates, or internal paths are
  included in source, logs, or release assets
- publish SHA-256 checksums for release artifacts
- retain upstream notices required by bundled dependencies

This file is a notice, not legal advice.
