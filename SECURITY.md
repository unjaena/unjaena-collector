# Security Policy

## Scope

This repository is the public collection client. It must stay separate from service-side collection catalogs, parsing, analysis, scoring, reporting, billing, account policy, and infrastructure details.

## Supported Versions

Only the latest public release receives fixes. Older release artifacts should be replaced by the current release when an update is published.

## Reporting

Report vulnerabilities through GitHub Security Advisories for this repository. Do not open public issues containing working exploit details, live service identifiers, session material, customer data, or operational infrastructure details.

## Rules for Changes

- Do not add hardcoded collection targets.
- Do not add parser or analysis logic.
- Do not add product-specific target names.
- Do not add deployment paths or infrastructure details.
- Do not add signing certificates or service session material.
- Keep collection profile selection on the service side.
- Keep uploads bound to the authenticated collection session.
- Keep local logs short and avoid full local path disclosure where practical.
