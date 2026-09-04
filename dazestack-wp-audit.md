# DazeStack WP - Current Audit Report

Audit date: February 13, 2026
Script line: `v0.1.0 (Core)` + latest maintenance patches
Scope: `dazestack-wp.sh` behavior and operational docs currently in this repository

## Executive Summary

DazeStack WP has moved significantly beyond the pre-release audit baseline.

Current posture:

- Security controls are materially improved compared to pre-`0.0.1` findings.
- The platform is certified for controlled production environments on Ubuntu 24.04 LTS and Ubuntu 26.04 LTS.
- Remaining risk is primarily operational (privileged automation, environment variance).

Recommended status: **Production-ready** for Ubuntu 24.04 / 26.04 LTS with staged rollout and observability.

## What Changed Recently (Post-0.0.1 Maintenance & LTS Hardening)

- Certified first-class support for Ubuntu 26.04 LTS ("Resolute Raccoon") alongside Ubuntu 24.04 LTS.
- Added graceful official Ubuntu repository fallback for PHP packages when `ppa:ondrej/php` is not detected or unavailable for newer releases.
- Hardened all newly added and refactored functions against `set -u` (unbound variables) via defensive parameter expansion (`${1:-}`, etc.).
- Expanded automated unit test harness to 37 test cases covering pure functions, OS release verification, and parameter expansion under `set -u`.
- Added strict cache purge module enforcement flag: `REQUIRE_CACHE_PURGE_MODULE`.
- Added cache purge fallback repo support: `NGINX_CACHE_PURGE_REPO_FALLBACK`.
- Improved `cache-purge-check` output to include build flags and module wiring state.
- Fixed `safe_apt_install()` pipeline-status handling under `set -u` (`PIPESTATUS` snapshot before index access).

## Incident-Focused Verification (Cache Purge Readiness)

Observed troubleshooting pattern:

- Build state recorded `source/success`, but cache purge module/runtime checks were false.
- Source rebuild with strict flags was required to force module build validation.

Current expected success indicators:

- module file exists: `ngx_http_cache_purge_module.so`
- loader conf exists in `/etc/nginx/modules-enabled`
- deep check reports cache purge module available
- source build exits successfully

Operational command:

```bash
sudo bash dazestack-wp.sh cache-purge-check
```

## Legacy Findings Mapping (Pre-0.0.1 -> Current)

| Legacy area | Historical status | Current status |
| --- | --- | --- |
| Domain/input validation | Critical concern | Addressed with validation/sanitization functions |
| SQL/command injection exposure | Critical concern | Reduced by strict validation + controlled variable handling |
| Credential storage | Plaintext concern | Encrypted credential workflow in place |
| Registry locking | Race-condition concern | Atomic lock strategy implemented |
| Backup encryption | Missing/weak | Encrypted DB flow present; optional encrypted file archives supported (`BACKUP_INCLUDE_FILES`) |
| MySQL socket handling | Brittle detection concern | Multi-method socket detection implemented |
| Nginx security baseline | Incomplete | Security headers/rate-limit baseline included |
| Health checks | Limited | Extended multi-service diagnostics present |
| Logging sensitivity | Redaction concern | Sanitization helpers implemented; wait-time metrics accurate |
| Cache purge module confidence | Not explicit | Dedicated readiness check + standard `fastcgi_cache_purge` syntax wired |
| Multi-tenant Redis scalability | Limited to 15 sites | Dynamically scales with `REDIS_MAX_DBS` (default 64) + DB 0 fallback |
| Headless CLI automation | Interactivity blocks | Non-interactive `--force` flag supported for `delete-site` |
| WordPress Cron privilege | Root execution hazard | Executed strictly under unprivileged `www-data` |
| SSL canonical redirect | Loop risk (`ERR_TOO_MANY_REDIRECTS`) | Automated WP `siteurl`/`home` HTTPS synchronization via WP-CLI |
| Fail2ban on Ubuntu 24.04 | Missing auth.log startup crash | `backend = systemd` configured |
| FastCGI microcache reload | Browser reload bypasses cache | `max-age=0` bypass removed; cache served reliably |
| Cloudflare Real-IP updates | Blanking risk on curl timeout | IP presence verification guard before config commit |
| Stale Certbot renewals | Orphaned renewal errors on deleted sites | `certbot delete` integrated into `delete-site` |
| Site access/error logs | Unbounded growth | Added to `/etc/logrotate.d/dazestack-wp` |

## Current Strengths

- Stronger input validation for domain/email/admin user paths
- Encrypted secrets/backups and explicit credentials directory controls
- Recovery-oriented Nginx module handling and config validation hooks
- Built-in diagnostics for caching, compression, health, and purge readiness
- Source-build aware Nginx state tracking
- Non-interactive automation support for CI/CD environments

## Open Risks and Gaps

These are not blockers for all environments, but should be managed:

1. No formal CI test suite in this repository for full install paths.
2. Script requires root and performs broad system changes.
3. Dependency and repository availability can affect deterministic builds.
4. Security posture depends on host lifecycle controls (patching, SSH policy, monitoring, incident response).

## Recommended Production Controls

1. Run initial deployment in staging first.
2. Capture and retain `/var/log/dazestack-wp/` during rollout.
3. Validate `health-check`, `cache-deep-check`, and `cache-purge-check` after each major update.
4. Maintain off-host backup copies in addition to local encrypted backups.
5. Enforce infrastructure access controls and patch cadence.

## Version Tracking Notes

Use `CHANGELOG.md` as the canonical version timeline.

- `pre-0.0.1`: legacy audit snapshot context only
- `0.0.1`: first stable documented release line
- `0.1.0 (2026-09-04)`: Ubuntu 26.04/24.04 LTS certified, multi-gigabit kernel stack, OpenSSL 3.4+, Post-Quantum TLS 1.3, Systemd overrides, MariaDB 11.4 LTS, Redis LTS with Unix socket

## Final Assessment

Compared to the legacy pre-release audit, the current codebase demonstrates clear security and operability progress.

Risk level: **Moderate (managed)** for supported Ubuntu environments with disciplined operations.

This report is a technical project audit summary, not a third-party certification.
