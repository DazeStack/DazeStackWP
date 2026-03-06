# DazeStack WP — Project Index

Quick reference for navigating the codebase, commands, and documentation.  
**Script version:** `0.0.1 (Core)` · **Index date:** March 2026

---

## 1. Project overview

| Item | Description |
|------|-------------|
| **Name** | DazeStack WP |
| **Role** | One-command WordPress LEMP automation for Ubuntu 24.04+ |
| **Stack** | Nginx (source or package), PHP 8.5, MariaDB, Redis, Certbot |
| **Highlights** | Per-site isolation, FastCGI microcache, Redis object cache, encrypted creds/backups, health/tune/cache diagnostics |
| **License** | AGPLv3 + Commercial (see `COMMERCIAL_LICENSE.md`) |

---

## 2. File manifest

| File | Purpose |
|------|--------|
| **dazestack-wp.sh** | Main installer and CLI (~9.7k lines). Single entry point for install, site ops, cache, Nginx source build, backups, etc. |
| **README.md** | Product overview, features, quick start, command reference, architecture, paths, licensing. |
| **QUICK-START-GUIDE.md** | Minimal steps: install → health-check → create-site → DNS/SSL → daily ops. |
| **FAQ.md** | OS support, production readiness, PHP version, Redis DB count, credentials, backups, SSL, HTTP/3, cache-purge-check, troubleshooting. |
| **CONTRIBUTING.md** | Branch workflow, bash style, docs to update, validation commands, PR template, security contact. |
| **SECURITY.md** | Security model and disclosure (path referenced in README). |
| **CHANGELOG.md** | Version history; Unreleased + 0.0.1 + pre-0.0.1. |
| **dazestack-wp-audit.md** | Current audit: production readiness, legacy→current mapping, strengths, open risks, recommended controls. |
| **LICENSE** | Project license (AGPLv3 + commercial). |
| **LICENSES/AGPL-3.0.txt** | Full AGPLv3 text. |
| **COMMERCIAL_LICENSE.md** | Commercial licensing terms. |
| **TRADEMARK.md** | DazeStack trademark usage. |
| **.gitignore** | Logs, OS/editor, temp, `.env`. |

---

## 3. `dazestack-wp.sh` structure

The script is organized in **13 sections**. Approximate line ranges:

| Section | Lines (approx) | Responsibility |
|---------|----------------|----------------|
| **SECTION 1** | 27–256 | Core config: branding, paths, dirs, feature flags, Redis/PHP/Nginx/Cloudflare defaults, log levels. |
| **SECTION 2** | 257–399 | Security: `check_root`, credential dir setup, redaction/sanitization helpers. |
| **SECTION 3** | 400–711 | Input validation: domain, email, admin user; sanitization. |
| **SECTION 4** | 712–831 | Encryption and credentials: master/backup keys, encrypt/decrypt, credential read/write. |
| **SECTION 5** | 832–898 | Atomic locking for registry/state (e.g. domain registry). |
| **SECTION 6** | 899–977 | Rollback and error recovery; trap and cleanup. |
| **SECTION 7** | 978–1252 | Registry: domain registry (JSON), Redis DB allocator, site list/lookup. |
| **SECTION 8** | 1253–1416 | Resource calculator: RAM/CPU, PHP-FPM pool sizing, MySQL/Redis/Nginx tuning. |
| **SECTION 9** | 1417–1504 | MySQL socket detection (multi-method). |
| **SECTION 10** | 1505–4624 | Pre-flight: OS, network, dependencies; phase runner; full install flow. |
| **SECTION 11** | 4625–5652 | Installation phases (see §5 below). |
| **SECTION 12** | 5653–7309 | Site management: create/delete site, SSL, CDN, credentials, backups, cache, images, upgrade-sites. |
| **SECTION 13** | 7310–end | Main entry: `main()`, command dispatch (`case "$1"`), interactive menu. |

**Entry points:**

- **No args + TTY:** `menu_loop()` (interactive menu).
- **No args + non-TTY:** `run_full_install()`.
- **With command:** `main "$@"` dispatches to the matching `case` branch (e.g. `create-site`, `health-check`).

---

## 4. CLI commands (alphabetical)

Invocation: `sudo bash dazestack-wp.sh <command> [args]` or, after `install-cli`, `dazestack-wp <command> [args]`.

| Command | Purpose |
|---------|--------|
| **auto-tune** | Recalculate and apply tuning (PHP/MySQL/Redis/Nginx) from host resources. |
| **cache-deep-check** [domain\|--all] | Deep cache behavior probes. |
| **cache-purge-check** | Verify cache purge module build + loader + runtime. |
| **cache-status** [--all] | Per-site cache HIT/MISS/BYPASS. |
| **cdn-disable** &lt;domain&gt; | Disable CDN rewrite for site. |
| **cdn-enable** &lt;domain&gt; &lt;url&gt; [type] | Enable CDN rewrite (e.g. custom). |
| **cdn-status** [domain] | Show CDN status. |
| **compression-optimize** [auto\|balanced\|aggressive\|low-cpu] | Apply compression profile. |
| **compression-status** | Report gzip/brotli/zstd status. |
| **create-site** &lt;domain&gt; [title] [admin_email] [admin_user] [--ssl\|--no-ssl] [--admin-user=] | Create WordPress site, DB, pool, Redis DB. |
| **delete-site** &lt;domain&gt; | Remove site and related config (with confirmation). |
| **enable-http3-all** | Add HTTP/3 directives to all SSL vhosts. |
| **enable-ssl** &lt;domain&gt; | Request cert and enable HTTPS vhost. |
| **ensure-http3-curl** | Build/ensure HTTP/3-capable curl. |
| **factory-reset** [--force] | Destructive reset. |
| **flush-object-cache** | Flush Redis object cache for all sites. |
| **health-check** | Full stack diagnostics (Nginx, MariaDB, Redis, PHP-FPM, etc.). |
| **help**, **--help**, **-h** | Show help and command list. |
| **install-cli** | Install `/usr/local/sbin/dazestack-wp` wrapper. |
| **list-features** | Show feature flags / capabilities. |
| **list-phases** | List install phase names for `run-phase`. |
| **list-sites** | List sites in domain registry. |
| **menu** | Interactive TTY menu (24 actions). |
| **nginx-auto-update** --enable\|--disable\|--run\|--status | Nginx source auto-update schedule. |
| **nginx-source-build** &lt;version\|stable&gt; [--auto\|--no-auto] | Build Nginx from source (HTTP/3, Brotli, Zstd, cache purge). |
| **optimize-images** [domain\|--all] | AVIF/WebP generation. |
| **protocol-check** [domain\|--all] | HTTP/2 and HTTP/3/QUIC readiness. |
| **protocol-enforce** [domain\|--all] | Enforce protocol directives on SSL vhosts. |
| **purge-old-backups**, **remove-old-backups** [days] | Remove backups older than N days. |
| **rebalance-pools** | Recompute PHP-FPM pool sizing for all sites. |
| **rebuild-nginx** | Rebuild Nginx from saved source build state. |
| **refresh-installation** [--force] | Re-run install flow. |
| **run-phase** &lt;phase-name&gt; | Run a single installation phase. |
| **show-credentials** &lt;domain&gt; | Show decrypted credentials for site. |
| **upgrade-sites** | Apply new snippets/features to existing sites. |
| **update-cloudflare-ips** | Refresh Cloudflare real-IP config. |

*(Empty `command` with TTY = menu; without TTY = full install.)*

---

## 5. Installation phases (`list-phases` / `run-phase`)

| Phase | Function | Role |
|-------|----------|------|
| system-prerequisites | phase_system_prerequisites | Base packages, repos. |
| php | phase_php_installation | PHP + extensions. |
| certbot | phase_certbot | Certbot for TLS. |
| nginx | phase_nginx | Nginx (package or source), modules. |
| mariadb | phase_mariadb | MariaDB. |
| redis | phase_redis | Redis. |
| php-pools | phase_php_pools_base | Base PHP-FPM pool config. |
| registries | phase_registries | State/registry init. |
| idempotency | phase_idempotency_lock | Install idempotency. |
| microcache | phase_nginx_microcache | FastCGI microcache. |
| cron | phase_wordpress_cron | WP cron runner. |
| logrotate | phase_logrotate | Log rotation. |
| backups | phase_automated_backups | Encrypted backup cron. |
| security | phase_security_hardening | UFW, fail2ban, hardening. |
| cleanup | phase_system_cleanup | Post-install cleanup. |
| health-check | phase_health_check | Post-install health check. |

---

## 6. Important paths (runtime)

| Path | Purpose |
|------|--------|
| /var/lib/dazestack-wp/ | State, registries (e.g. domain-registry.json), init flag. |
| /var/log/dazestack-wp/ | installation.log, error.log, debug.log, audit.log, security.log. |
| /var/backups/dazestack-wp/ | Encrypted DB backups. |
| /root/.dazestack-wp/ | Encrypted credentials; master/backup keys. |
| /etc/dazestack-wp/ | Config (e.g. cloudflare-recommended.txt). |
| /var/www/ | Site document roots. |
| /usr/local/sbin/dazestack-wp | CLI wrapper (after install-cli). |

---

## 7. Key environment / feature flags (selection)

- **PHP:** `PHP_TARGET_VERSION` (default 8.5).
- **Nginx source:** `ENABLE_NGINX_SOURCE_BUILD`, `NGINX_SOURCE_VERSION`, `ENABLE_CACHE_PURGE_MODULE`, `REQUIRE_CACHE_PURGE_MODULE`, `NGINX_CACHE_PURGE_REPO`, `NGINX_CACHE_PURGE_REPO_FALLBACK`.
- **HTTP/3 & compression:** `ENABLE_HTTP3`, `ENABLE_BROTLI`, `ENABLE_ZSTD`, `ENABLE_HTTP3_FORCE_ALL`, `ENABLE_HTTP2_FORCE_ALL`.
- **Security:** `ENABLE_SECURITY_HEADERS`, `ENABLE_CLOUDFLARE`.
- **Tuning:** `ENABLE_AUTO_TUNE`, `AUTO_TUNE_CRON`, `ENABLE_SYSCTL_TUNING`, `ENABLE_BBR`.
- **Logging:** `LOG_LEVEL`, `LOG_FILE_OUTPUT_ENABLED`, `LOG_MAIN`, `LOG_DEBUG_FILE`.

See top of `dazestack-wp.sh` (Section 1) for full list.

---

## 8. Documentation map

| Need | Document |
|------|----------|
| First run, commands, architecture | README.md |
| Minimal deploy path | QUICK-START-GUIDE.md |
| Common questions, cache purge | FAQ.md |
| Contributing and PRs | CONTRIBUTING.md |
| Security and disclosure | SECURITY.md |
| Version history | CHANGELOG.md |
| Audit and production readiness | dazestack-wp-audit.md |
| License (AGPLv3) | LICENSE, LICENSES/AGPL-3.0.txt |
| Commercial use | COMMERCIAL_LICENSE.md |
| Brand usage | TRADEMARK.md |
| This index | INDEX.md |

---

## 9. One-line “index the project” summary

**DazeStack WP** is a single-bash WordPress LEMP automation script (`dazestack-wp.sh`) plus docs: **README** (product + commands), **QUICK-START-GUIDE** (deploy path), **FAQ** (support/cache), **CONTRIBUTING** (PRs), **SECURITY**, **CHANGELOG**, **dazestack-wp-audit** (audit), and **INDEX.md** (this file) for fast navigation of files, script sections, CLI commands, phases, paths, and docs.
