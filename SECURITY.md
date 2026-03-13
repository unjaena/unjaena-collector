# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

1. Email: Send details to **admin@unjaena.com**
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Release**: Within 30 days for critical issues

## Security Practices

### Cryptography
- AES-256-GCM for authenticated encryption (NIST approved)
- HKDF-SHA256 for key derivation
- SHA-256 for all integrity verification
- MD5 is deprecated and not used for security purposes

### Network Security
- HTTPS/WSS enforced in production builds
- TLS certificate verification enabled by default
- HTTP/WS connections rejected in production mode

### Authentication
- One-time session tokens (replay prevention)
- Hardware-bound device identification
- Token values never logged in plaintext (SHA-256 hash used for debug)

### Data Handling
- Collected artifacts encrypted before upload
- Chain of custody with per-entry SHA-256 integrity logging
- No credentials stored in application code or config templates
- All sensitive configuration via environment variables

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| 1.x     | No        |

## Scope

The following are **in scope** for security reports:
- Authentication bypass
- Encryption weaknesses
- Data leakage in logs or error messages
- Path traversal or injection vulnerabilities
- Insecure network communication

The following are **out of scope**:
- Vulnerabilities in third-party dependencies (report to upstream)
- Social engineering attacks
- Physical access attacks on the collection device
