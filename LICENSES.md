# Third-Party License Notice

unJaena Collector is licensed under AGPL-3.0-or-later. This choice is intentional for the distributed public client because the project integrates GPL/AGPL-compatible forensic, GUI, and mobile-device components.

This notice summarizes major direct dependencies. Always verify upstream package metadata before a production release because dependency versions and license expressions can change.

## Strong copyleft dependencies

| Component | Purpose | Reported license |
| --- | --- | --- |
| PyQt6 | Desktop GUI framework | GPL-3.0 or Riverbank commercial license |
| pymobiledevice3 | iOS device communication and services | GPL-3.0-or-later |
| dissect.fve | BitLocker and LUKS access | AGPL-3.0-or-later |
| Dissect framework packages | Disk, volume, filesystem, and binary parsing helpers | AGPL-3.0-or-later for Dissect framework releases |

## Other common dependencies

| Component | Purpose | Typical license family |
| --- | --- | --- |
| requests, urllib3, certifi, idna, charset-normalizer | HTTP client stack | Apache-2.0, MIT, MPL-compatible, or similar permissive licenses |
| aiohttp and transitive async HTTP packages | Async HTTP/WebSocket support | Apache-2.0, MIT, or similar permissive licenses |
| cryptography | Cryptographic primitives | Apache-2.0 OR BSD-3-Clause |
| pycryptodome | Cryptographic helpers used by mobile backup tooling | BSD/Public Domain |
| adb-shell, pyusb, libusb1 | Android USB support | Permissive open-source licenses, depending on package |
| pytsk3, libewf-python, libfshfs-python | Native forensic filesystem/image bindings | Upstream project licenses apply |

## License boundary

This repository contains the public acquisition client and EnCase integration source. Proprietary server-side parsers, AI analysis services, malware scoring, timeline ranking, and production service code are separate systems that communicate with the collector over authenticated HTTP APIs.

The public client source and distributed collector binaries remain under AGPL-3.0-or-later. If a deployment uses commercial PyQt licensing or replaces GPL/AGPL components, review the resulting license obligations before distributing modified binaries.

This file is a notice, not legal advice.
