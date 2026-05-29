# unJaena Collector

unJaena Collector is the open-source desktop acquisition client for authenticated unJaena forensic collection sessions.

The public client contains acquisition, packaging, consent, device discovery, disk-image access, and upload transport code. Collection target policy is not embedded in this repository. After a user validates a session token, the service sends a signed collection profile that authorizes the exact sources for that case.

## Supported acquisition surfaces

- Local logical volumes and live file systems when privileges allow access
- Physical disks and forensic disk images through the bundled disk access layer
- Raw and virtual disk container workflows supported by local runtime dependencies
- Mobile USB collection paths when platform tooling is installed
- Offline mobile filesystem extraction bundles through runtime profile specifications
- Encrypted transport and signed API requests for upload records

## Security model

- No static product-specific target catalog is shipped in the public source tree
- Session tokens are exchanged for scoped collection credentials
- Server collection profiles are verified before local target registries are populated
- Upload requests include the server profile identifier for backend enforcement
- Consent records are signed and submitted before collection starts
