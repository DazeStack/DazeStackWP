# Security Policy

DazeStackWP aims to be safe by default, but **security is a process**.  
If you find a security issue, please report it privately so we can fix it before public disclosure.

## Supported Versions

We currently support:
- **main** branch (latest)
- Latest tagged release (once releases exist)

Older tags/releases may not receive fixes unless they are widely used.

## Reporting a Vulnerability

**Please DO NOT open a public GitHub issue for security vulnerabilities.**

Instead, report privately:
- Email: **security@dazestack.com** (recommended)
- Backup: **legal@dazestack.com**
- Subject: `SECURITY: <short summary>`
- Include:
  - Steps to reproduce
  - Impact assessment (what an attacker can do)
  - Affected versions / environments
  - Proof-of-concept (PoC) if available
  - Any suggested fix/patch

If you prefer encrypted email, include your PGP key in this repo later (e.g., `SECURITY_PGP.asc`).

## Our Disclosure Process

We follow a coordinated disclosure approach:
1. **Acknowledgement** within **3 business days**
2. **Initial triage** within **7 days**
3. **Fix / mitigation** as soon as practical (severity-based)
4. **Release notes** and credit (if desired) after a patch is available

## Scope

In scope:
- Installer scripts (Bash)
- Default configurations shipped by DazeStackWP (Nginx/PHP/DB/Redis/SSL automation)
- Privilege boundaries, credential storage, backup scripts, and health checks

Out of scope (generally):
- Issues in third-party software that DazeStackWP installs (Nginx/PHP/WordPress) **unless** caused by our configuration
- Misconfiguration by operators (e.g., exposing admin endpoints, weak passwords) unless the defaults encourage it

## Safe Harbor

We support good-faith security research. If you:
- Avoid data destruction and service disruption
- Avoid accessing private data beyond what is necessary to prove the issue
- Give us a reasonable time to patch before disclosure

…we will not pursue legal action against you for your research.

## Security Tips for Operators (Quick)

- Keep Ubuntu packages updated (`unattended-upgrades` recommended)
- Use SSH keys, disable password auth
- Restrict inbound ports with a firewall
- Keep WordPress plugins/themes updated
- Test backups and restores regularly

Last updated: 2026-02-03
