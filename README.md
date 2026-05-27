# unjaena-collector

Open desktop client for authorized forensic collection workflows.

This repository contains the public client shell only: service authentication, signed profile validation, local file hashing, optional encrypted transport preparation, upload completion, and a simple desktop interface. The collection catalog, parsing, scoring, analysis, reporting, policy, and recovery logic are delivered or executed by the service.

## Install

Use the latest release asset for your platform when available. The Python package exposes both command line and desktop entry points.

```bash
python -m pip install unjaena_collector-0.2.0-py3-none-any.whl
unjaena-collector-gui
```

The command line entry point is also available.

```bash
unjaena-collector --server https://app.unjaena.com --token CASE_SESSION_TOKEN
```

## Desktop Flow

1. Open `unjaena-collector-gui`.
2. Confirm the service address.
3. Paste the case session token issued by the service.
4. Start collection.
5. Keep the app open until the upload summary is complete.

The desktop app shows connection state, scan count, upload count, skipped files, failed files, and a short event log. It does not display or embed the service collection catalog.

## Security Model

- The client receives a signed collection profile at runtime.
- The client verifies the profile signature when the service provides a signing key.
- Upload requests are bound to the authenticated collection session.
- File hashes are calculated locally before upload.
- The service can require encrypted upload payloads through per-upload material.
- Uploaded artifact types must match the issued profile.
- The public client does not contain hardcoded collection targets, parser code, analysis code, scoring code, report generation code, or service policy rules.

## Public Contribution Boundary

Do not add platform artifact catalogs, product-specific target names, parser behavior, analysis prompts, report templates, account policy, billing policy, deployment paths, or operational infrastructure details to this repository.

UI improvements, packaging improvements, transport hardening, profile verification, upload reliability, and tests are appropriate here when they keep service-side policy outside the public client.
