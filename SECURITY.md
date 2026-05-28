# Security Policy

Report security issues privately to the unJaena maintainers. Do not open public issues for vulnerabilities, exposed credentials, signing material, or collection-policy bypasses.

The public repository intentionally excludes case-specific and product-specific collection target catalogs. The collector receives signed runtime profiles from the service after session authentication.

Never commit API tokens, signing keys, Apple certificates, notarization credentials, or production service credentials. If a secret is exposed, rotate it immediately and invalidate affected sessions.
