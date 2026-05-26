# unjaena-collector

Open collection client for authorized forensic acquisition workflows.

This repository contains transport, hashing, profile execution, and upload code only. Collection targets are delivered by the service at runtime through a signed collection profile.

The client does not contain private parser logic, analysis logic, scoring logic, recovery logic, or service-side policy rules.

## Usage

```bash
unjaena-collector --server https://app.example.com --token SESSION_TOKEN
```

The session token is issued by the service for a specific case and user.
