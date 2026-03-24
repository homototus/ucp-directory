# Security Policy

## Supported Versions

Only the `main` branch is supported. There are no versioned releases.

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

Instead, use [GitHub's private security advisory feature](../../security/advisories/new) to report the issue confidentially.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: within 48 hours
- **Assessment**: within 1 week
- **Fix**: as soon as practically possible, depending on severity

## Scope

The following are in scope for security reports:

- **SSRF bypass**: Any way to make the crawler (`scripts/verify.py`) connect to internal/private IPs
- **Registry poisoning**: Any way to inject malicious data into `registry.json` through the crawler
- **XSS**: Any way to execute scripts on `hungry-ucp.dev` via crafted registry data
- **Workflow exploitation**: Any way to abuse the GitHub Actions workflow to gain unauthorized access
- **Domain impersonation**: Registration of domains that impersonate legitimate businesses

## Security Model

The crawler fetches `/.well-known/ucp` from user-registered domains. Defenses include:

- DNS resolution with private IP rejection
- DNS pinning to prevent rebinding (TOCTOU)
- Manual redirect following with per-hop validation
- HTTPS-only with port 443 restriction
- Response streaming with 64KB size cap
- Input sanitization (control characters, bidi overrides)
- Capability and version format validation
- No proxy environment variable inheritance
