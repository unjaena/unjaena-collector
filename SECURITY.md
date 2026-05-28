# Security Policy

## Reporting Vulnerabilities

Report security issues privately. Do not open public issues for vulnerabilities, exposed credentials, signing material, authentication bypasses, collection-policy bypasses, unsafe path traversal, or upload authorization flaws.

Use GitHub private security advisories when available, or contact the unJaena maintainers through the project's private support channel.

## Supported Versions

Only the latest public release and the current default branch are actively supported for security fixes. Older release artifacts should be upgraded when a security release is published.

## Public Collector Boundary

The public repository intentionally excludes case-specific and product-specific collection target catalogs. The collector receives signed runtime profiles from the service after session authentication. A vulnerability that allows local code, a modified profile, or a stale token to expand collection scope should be treated as high severity.

## Secret Handling

Never commit any of the following:

- API tokens or GitHub tokens
- Apple certificates, provisioning material, app-specific passwords, or keychain passwords
- production service URLs that are not intended to be public
- signing keys, HKDF material, session tokens, collection tokens, or consent signing keys
- real user evidence, exported forensic case data, or private test images

If a secret is exposed, rotate it immediately, invalidate affected sessions, and replace any release artifact that may have embedded it.

## Expected Security Properties

- session tokens are exchanged for scoped credentials
- upload authorization is enforced by both the collector and backend
- collection profiles are server-issued and case-scoped
- consent is recorded before collection starts
- local path handling must reject traversal and unsafe extraction paths
- release artifacts should be signed, notarized where applicable, and accompanied by checksums

## Disclosure

Please give maintainers a reasonable window to investigate and release a fix before public disclosure. Include reproduction steps, affected platform, collector version, logs with secrets removed, and any relevant sample metadata.
