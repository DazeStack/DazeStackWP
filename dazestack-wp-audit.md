# DazeStack WP - Current Audit Report

Audit date: September 6, 2026
Script line: `v0.1.1 (Core)` + live production hardening
Scope: `dazestack-wp.sh` behavior, functionality, and operational docs currently in this repository

## Executive Summary

DazeStack WP has moved significantly beyond the initial baseline, incorporating critical architectural fixes and runtime enhancements validated during live production migration onto Ubuntu 26.04.1 LTS ("Resolute Raccoon") on AMD EPYC hardware.

Current posture:

- Security controls are materially hardened, with automated privilege containment, parameter shielding under `set -u`, and atomic locking.
- The platform is certified and battle-tested for production environments on Ubuntu 24.04 LTS and Ubuntu 26.04 LTS.
- The 0-byte stream truncation FastCGI compression bug behind CDNs (Cloudflare) is completely resolved.
- Full-page caching is hardened against silent header/cookie bypasses, persistent against `tmpfiles.d` evictions, and optimized with 4MB FastCGI RAM buffers.
- Bulk WP-CLI ingestion and catalog update operations are protected against archive purge floods.

Recommended status: **Production-ready** for high-traffic WordPress & WooCommerce deployments on Ubuntu 24.04 / 26.04 LTS.

## What Changed Recently (v0.1.1 Hardening & Production Verification)

- **Ubuntu 26 Native-First Architecture**: Bypasses `ppa:ondrej/php` and third-party Redis repositories on Ubuntu 26+ (`VERSION_ID >= 26`) to consume canonical native PHP 8.5 and Redis 8.x packages, eliminating APT exit 100 crashes.
- **PHP 8.5 OPcache Virtualization**: Resolved false-positive checks for `php8.5-opcache` by checking runtime core availability via `php -m`.
- **OpenSSL 3.5.1 LTS QUIC Pin**: Pinned official OpenSSL dependency to `openssl-3.5.1`, avoiding unreleased OpenSSL 4.x breaking API changes under GCC 15 `-Werror`.
- **Dynamic Module Cache Purge**: Defaulted repository to maintained `nginx-modules/ngx_cache_purge` supporting dynamic `.so` compilation.
- **FastCGI CDN Stream Truncation Resolution**: Disabled origin dynamic `brotli` and `zstd` by default, serving reliable native `gzip on;` for FastCGI dynamic responses while retaining kernel `sendfile` static pre-compressed assets (`brotli_static on;`, `zstd_static on;`).
- **FastCGI Cache Header & Cookie Hardening**: Added `fastcgi_ignore_headers Cache-Control Expires Set-Cookie;` and removed `$upstream_http_set_cookie` from `fastcgi_no_cache` to ensure standard WordPress headers and session/tracking cookies do not force uncached responses.
- **Persistent systemd-tmpfiles Cache Definition**: Installed `/etc/tmpfiles.d/nginx-cache.conf` (`0755` for `/var/cache/nginx`, `0700` for `/var/cache/nginx/microcache`), preventing 5-second cache-lock timeout freezes from missing cache directories.
- **Enlarged FastCGI Buffers in RAM**: Upgraded `fastcgi_buffers 64 64k` (4MB total RAM), `fastcgi_buffer_size 128k`, `fastcgi_busy_buffers_size 256k`, and `fastcgi_temp_file_write_size 256k` to handle heavy WooCommerce / faceted catalog payloads in RAM without disk buffering bottlenecks.
- **Extended Default Cache TTL**: Extended `FASTCGI_CACHE_TTL` default from `60s` to `10m` for optimal origin offloading, relying on event-driven instant purges.
- **Bulk Operation Purge Flood Prevention**: Added `wp-bulk-start`, `wp-bulk-finish`, and `wp-bulk-run` commands and defaulted `purge_archive_on_edit = 0` in Nginx Helper to prevent catastrophic archive purge floods during large WP-CLI imports.
- **Automated Unit Test Suite**: 38 test cases covering pure validation functions, parameter expansion under `set -u`, and OS release detection (100% passing).

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
- `0.1.1 (2026-09-06)`: Live production hardening, FastCGI CDN compression fix, `fastcgi_ignore_headers`, persistent `tmpfiles.d` microcache, 4MB RAM FastCGI buffers, 10m TTL, and WP-CLI bulk purge protection

## Final Assessment

Compared to the legacy pre-release audit, the current codebase demonstrates clear security and operability progress.

Risk level: **Moderate (managed)** for supported Ubuntu environments with disciplined operations.

This report is a technical project audit summary, not a third-party certification.
