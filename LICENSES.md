# Third-Party License Notice

This project (Intelligence Collector) is licensed under AGPL-3.0.

## AGPL-3.0 Dependencies
- dissect.fve (BitLocker/LUKS support)
- dissect.cstruct (binary structure parsing)

## GPL-3.0 Dependencies
- pymobiledevice3 (iOS device communication)
- PyQt6 (GUI framework)

## Apache-2.0 Dependencies
- dissect.ntfs, dissect.extfs, dissect.fat, dissect.xfs, dissect.btrfs, dissect.ffs
- dissect.apfs, dissect.volume, dissect.util
- dissect.hypervisor (VMDK/VHD/VHDX/VDI/QCOW2)

## MIT/BSD Dependencies
- requests, aiohttp, cryptography, and other packages listed in requirements/

## License Boundary

The Intelligence Collector (this repository) is a standalone client application.
The server-side analysis platform is a separate, independently developed system
that communicates with the collector exclusively via documented HTTP/WebSocket APIs.
The AGPL-3.0 license of this collector does NOT extend to the server platform.
