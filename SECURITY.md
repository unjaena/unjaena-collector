# Security Policy

## Supported Scope

Security issues in this repository include vulnerabilities in the public
collector client, EnCase integration source, upload transport, collection
profile enforcement, consent handling, local privilege checks, update checks,
packaging scripts, and release workflows.

This repository does not contain proprietary server parsers, AI analysis
engines, scoring rules, production infrastructure, customer evidence, or case
data. Do not include private evidence, session tokens, credentials,
certificates, or personally identifiable data in public reports.

## Supported Versions

| Version or branch | Security support |
| --- | --- |
| Latest GitHub release | Supported |
| `main` | Reviewed on a best-effort basis before release |
| Older releases | Supported only when still distributed through the official download channel |
| Forks or modified binaries | Maintainer support is not guaranteed |

## Reporting a Vulnerability

Report vulnerabilities privately to the unJaena maintainers through GitHub
private vulnerability reporting when available, or through the official unJaena
security/support contact. Do not open a public GitHub issue for sensitive
reports.

Use private reporting for:

- credential or token exposure
- collection-profile bypasses
- upload authorization bypasses
- arbitrary file read or unintended source collection
- consent bypasses
- signing, notarization, or update-channel weaknesses
- evidence tampering, hash mismatch, or chain-of-custody issues
- dependency confusion or release artifact compromise
- denial-of-service issues that can interrupt active collection sessions

When reporting, include the affected version or commit, platform, reproduction
steps, expected impact, and relevant logs with secrets redacted. Use synthetic
or non-sensitive evidence whenever possible.

## Out of Scope for Public Reports

The following should not be posted publicly and may require a private support or
case-specific channel instead:

- customer case data
- production session tokens or collection tokens
- proprietary parser behavior
- server-side AI, scoring, timeline, or ranking behavior
- internal infrastructure details
- legal questions about collection authority or admissibility

## Secret Handling

Never commit API tokens, session tokens, GitHub tokens, Apple certificates,
notarization credentials, signing material, cloud credentials, production
database credentials, or customer evidence. If a secret is exposed, rotate it
immediately, revoke affected sessions, invalidate release credentials if needed,
and audit recent upload and release activity.

## Public-Client Boundary

The public collector is designed as a profile-driven acquisition client. Static
product-specific target catalogs, parser logic, analysis rules, scoring models,
and case policy must remain outside this repository. Public source changes must
pass `tools/public_preflight.py` and the release acceptance gate in
`tools/release_gate.py` before release.

## Secure Development Requirements

Before merging or releasing public collector changes:

- keep public code and documentation in English
- do not include private repository paths, local operator names, internal host
  names, secrets, or customer data
- avoid printing raw server responses when they may contain operational details
- ensure collection is bounded by the authenticated server profile
- ensure consent is recorded before upload starts
- verify upload manifests, file hashes, and source metadata are preserved
- run the public preflight and release gate

## Release Integrity

Release artifacts should be built by GitHub Actions from reviewed source after
`tools/release_gate.py --actual-local` passes on the target runner. Artifacts
should be signed or notarized where supported and published with SHA-256
checksums. Users should prefer release artifacts over ad-hoc builds unless they
are auditing or modifying the source.

## Dependency Policy

Dependencies are reviewed for license compatibility and security impact before
release. The project source is AGPL-3.0-or-later, and distributed builds may
include third-party components under GPL, AGPL, LGPL, MPL, BSD, MIT, Apache,
PSF, public-domain, or other applicable terms. See `LICENSES.md` for the
current notice file.
