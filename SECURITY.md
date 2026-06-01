# Security Policy

## Supported scope

Security issues in this repository include vulnerabilities in the public collector client, EnCase integration source, upload transport, collection profile enforcement, consent handling, local privilege checks, update checks, packaging scripts, and release workflows.

This repository does not contain the proprietary server parsers, AI analysis engine, scoring rules, production infrastructure, customer evidence, or case data. Do not include private evidence, session tokens, credentials, certificates, or personally identifiable data in public reports.

## Reporting a vulnerability

Report vulnerabilities privately to the unJaena maintainers. Do not open a public GitHub issue for:

- credential or token exposure
- collection-profile bypasses
- upload authorization bypasses
- arbitrary file read or unintended source collection
- consent bypasses
- signing, notarization, or update-channel weaknesses
- evidence tampering, hash mismatch, or chain-of-custody issues
- dependency confusion or release artifact compromise

When reporting, include the affected version or commit, platform, reproduction steps, expected impact, and any relevant logs with secrets redacted.

## Secret handling

Never commit API tokens, session tokens, GitHub tokens, Apple certificates, notarization credentials, signing material, cloud credentials, production database credentials, or customer evidence. If a secret is exposed, rotate it immediately, revoke affected sessions, invalidate release credentials if needed, and audit recent upload and release activity.

## Public-client boundary

The public collector is designed as a profile-driven acquisition client. Static product-specific target catalogs, parser logic, analysis rules, scoring models, and case policy must remain outside this repository. Public source changes must pass `tools/public_preflight.py` and the release acceptance gate in `tools/release_gate.py` before release.

## Release integrity

Release artifacts should be built by GitHub Actions from reviewed source after `tools/release_gate.py --actual-local` passes on the target runner, signed or notarized where supported, and published with SHA-256 checksums. Users should prefer release artifacts over ad-hoc builds unless they are auditing or modifying the source.

## Dependency policy

Dependencies are reviewed for license compatibility and security impact before release. The project license is AGPL-3.0-or-later because the distributed collector integrates GPL/AGPL-compatible components. See `LICENSES.md` for the current notice file.
