# Third-Party License Notice

unJaena Collector is licensed under AGPL-3.0-or-later. This choice is
intentional for the distributed public client because the project integrates
GPL/AGPL-compatible forensic, GUI, disk, and mobile-device components.

This notice summarizes major direct dependencies used by the public collector.
It is not a complete software bill of materials. Always verify upstream package
metadata, lock files, and bundled binary artifacts before a production release
because dependency versions and license expressions can change.

## Repository License

Unless a file states otherwise, source files in this repository are distributed
under AGPL-3.0-or-later. See `LICENSE` for the full license text.

## Strong Copyleft Dependencies

| Component | Purpose | Reported license |
| --- | --- | --- |
| PyQt6 | Desktop GUI framework | GPL-3.0 or Riverbank commercial license |
| pymobiledevice3 | iOS device communication and services | GPL-3.0-or-later |
| dissect.fve | BitLocker and LUKS access | AGPL-3.0-or-later |
| Dissect framework packages | Disk, volume, filesystem, and binary parsing helpers | AGPL-3.0-or-later for Dissect framework releases |

## Common Runtime Dependencies

| Component | Purpose | Typical license family |
| --- | --- | --- |
| requests, urllib3, certifi, idna, charset-normalizer | HTTP client stack | Apache-2.0, MIT, MPL-compatible, or similar permissive licenses |
| aiohttp, websockets, and transitive async packages | Async HTTP and WebSocket support | Apache-2.0, MIT, or similar permissive licenses |
| cryptography | Cryptographic primitives | Apache-2.0 OR BSD-3-Clause |
| pycryptodome | Cryptographic helpers used by mobile backup tooling | BSD/Public Domain |
| biplist, bpylist2, construct, opack2 | Apple plist and binary protocol helpers | Permissive open-source licenses, depending on package |
| adb-shell, pyusb, libusb1 | Android USB support | Permissive open-source licenses, depending on package |
| pytsk3, libewf-python, libfshfs-python | Native forensic filesystem and image bindings | Upstream project licenses apply |
| lzfse | Apple compression support | Upstream project license applies |

## Build and Packaging Dependencies

| Component | Purpose | License note |
| --- | --- | --- |
| PyInstaller | Application packaging | GPL-compatible license with bootloader exception; verify current upstream terms |
| platform-tools or ADB binaries, when bundled | Android device communication | Android SDK/platform-tools license terms apply |
| OS signing and notarization tools | Platform release integrity | Platform vendor terms apply |

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
- verify that no private evidence, secrets, certificates, or internal paths are
  included in source, logs, or release assets
- publish SHA-256 checksums for release artifacts
- retain upstream notices required by bundled dependencies

This file is a notice, not legal advice.
