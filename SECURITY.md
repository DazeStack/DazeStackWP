# Security Policy

## Supported Versions

| Version line | Status |
| --- | --- |
| 0.0.x | Supported |
| pre-0.0.1 snapshots | Unsupported |

## Reporting a Vulnerability

Report security issues privately to:

- Email: `hello@dazestack.com`
- Fallback: `mail@ashishdungdung.com`

Please do not open public issues for vulnerabilities before a fix is available.

## What to Include

- Affected command/function/path
- Reproduction steps
- Impact assessment
- Suggested mitigation (if available)
- Whether the issue is configuration-specific or default-path

## Response Targets

- Initial acknowledgement: within 72 hours
- Triage/update: within 7 days
- Fix timeline: based on severity and reproducibility

## Security Baseline in This Project

The installer includes:

- Input validation for user-facing values (domain/email/user)
- Encrypted credentials (`AES-256-CBC` + `PBKDF2`)
- Encrypted scheduled database backups
- Atomic registry locking for state updates
- Nginx hardening and rate-limit defaults
- UFW + fail2ban baseline controls
- Cloudflare real-IP integration support

## Scope Notes

- The script performs privileged system operations and must be run with trusted inputs.
- Operational security still depends on host hardening, patching cadence, and access controls.
- Review `dazestack-wp-audit.md` for latest audit status and open risks.
