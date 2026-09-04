# Changelog

All notable changes to DazeStack WP are documented in this file.

## [0.1.1] - 2026-09-04

### Fixed
- **FastCGI 0-Byte Payload Truncation**: Resolved critical stream truncation in Nginx dynamic output filter chain behind CDNs (Cloudflare). Dynamic `brotli` and `zstd` modules are now disabled by default for FastCGI dynamic responses, while retaining standard high-performance native `gzip on;` on the origin.
- **Static Pre-Compressed Assets**: Retained direct kernel `sendfile` delivery for pre-compressed static assets (`brotli_static on;`, `zstd_static on;`) without FastCGI filter interference.
- **Ubuntu 26.04+ PPA Bypass**: Automatically skip `ppa:ondrej/php` and third-party Redis repositories on Ubuntu 26+ ("Resolute Raccoon") to consume canonical native packages (PHP 8.5, Redis 8.x), preventing APT `exit=100` errors.
- **PHP 8.5 OPcache Check**: Conditioned standalone `php-opcache` package validation to avoid false-positive failures on PHP 8.5+ where OPcache is compiled directly into PHP core.
- **OpenSSL GCC 15 Compilation**: Pinned official OpenSSL QUIC dependency to stable `openssl-3.5.1` LTS, avoiding unreleased OpenSSL 4.x breaking API changes under GCC 15 `-Werror`.
- **Nginx Cache Purge Dynamic Module**: Switched default `NGINX_CACHE_PURGE_REPO` to `nginx-modules/ngx_cache_purge.git` for native dynamic module (`auto/module`) compilation support.
- **Nginx Source Version Resolution**: Added explicit `resolve_nginx_source_version` at entry of `build_nginx_from_source()` to prevent 404s when `latest-stable` is passed.
- **Firewall & Jail Ordering**: Ensured UFW is enabled before starting Fail2ban to prevent `banaction = ufw` race conditions, and dynamically query active SSH port via `sshd -T`.

### Added
- **Origin Compression Toggles**: Added CLI commands `compression-enable-origin-brotli`, `compression-disable-origin-brotli`, `compression-enable-origin-zstd`, and `compression-disable-origin-zstd` for direct-to-origin setups without CDNs.
- **Enhanced Compression Status**: Updated `compression-status` diagnostic command to report active compression mode (`dynamic+static` vs `static-only; CDN-safe`).
- **CLI Setup Aliases**: Added `install`, `setup`, and `full-install` aliases to CLI main router for unattended deployments.

## [0.1.0] - 2026-09-04

### Added
- Official certified support for Ubuntu 26.04 LTS ("Resolute Raccoon") alongside Ubuntu 24.04 LTS in `check_os()`, runtime warnings, banner diagnostics, and documentation.
- Comprehensive native Linux kernel & multi-gigabit network stack tuning (`fs.file-max=2097152`, `vm.swappiness=10`, `vm.vfs_cache_pressure=50`, `vm.overcommit_memory=1`, 16MB dynamic TCP window scaling `net.ipv4.tcp_rmem`/`tcp_wmem`, keepalive tuning, Path MTU discovery `net.ipv4.tcp_mtu_probing=1`, and idle keepalive persistence `net.ipv4.tcp_slow_start_after_idle=0`).
- Modernized Systemd service sandboxing & high-concurrency drop-in overrides (`/etc/systemd/system/nginx.service.d/dazestack-limits.conf` and `/etc/systemd/system/php*-fpm.service.d/dazestack-limits.conf`) enforcing `LimitNOFILE=1048576`, `LimitNPROC=512000`, `TasksMax=infinity`, `PrivateTmp=true`, `ProtectSystem=full`, and `ProtectHome=read-only`.
- Support for official MariaDB 11.4 LTS repository deployment (`ENABLE_MARIADB_OFFICIAL_REPO=true`, `MARIADB_TARGET_VERSION=11.4`) with validated WordPress core compatibility through 2029.
- Support for official Redis LTS repository deployment (`ENABLE_REDIS_OFFICIAL_REPO=true`) with high-performance Unix domain socket integration (`unixsocket /run/redis/redis-server.sock`, `unixsocketperm 770`), `www-data` group membership, and kernel Transparent Huge Pages (THP) latency mitigation.
- Post-Quantum TLS 1.3 hybrid key exchange curve configuration (`X25519MLKEM768:X25519:prime256v1:secp384r1`) in Nginx TLS defaults for future-proof cryptographic handshakes.
- Optimized Nginx `ssl_buffer_size 8k` reducing Time-To-First-Byte (TTFB) latency on mobile and HTTP/2/HTTP/3 streams.
- Support for system OpenSSL vendor in Nginx HTTP/3 builds (`NGINX_QUIC_OPENSSL_VENDOR=system`) enabling native builds directly against Ubuntu 26.04's OpenSSL 3.4+ without external source fetching.
- TCP Fast Open (`net.ipv4.tcp_fastopen = 3`) in `/etc/sysctl.d/99-wp-performance.conf` saving 1 round-trip time (RTT) on client/server handshakes.
- PHP OPcache JIT tracing engine (`opcache.jit=tracing`, `opcache.jit_buffer_size=64M`) accelerating CPU-intensive WordPress and WooCommerce execution paths by 15-35%.
- Native UFW/nftables action (`banaction = ufw`) wired into Fail2ban default jail configuration for direct firewall kernel table filtering.
- Graceful official Ubuntu repository fallback for PHP packages (`ensure_ondrej_php_preferred`, `check_php_package_availability`) when `ppa:ondrej/php` is not detected or unavailable for newer Ubuntu releases.
- Production OPcache configuration and packaging (`php-opcache`) with 128MB memory allocation, accelerated file hashing, and timestamp revalidation.
- ccTLD awareness in `is_subdomain` preventing apex domains such as `.co.uk`, `.com.au`, and `.co.in` from being misclassified as subdomains.
- Automated unit test harness covering pure functions, parameter shielding under `set -u`, vendor normalization, and OS release verification logic (38 passing test cases).
- `BACKUP_INCLUDE_FILES` feature flag (defaults to `false`) enabling automated encrypted backups of `wp-content/uploads/` archives alongside database dumps.
- Dynamic Redis capacity scaling (`REDIS_MAX_DBS`, default 64) supporting 63 dedicated DBs.
- Automatic shared DB `0` fallback with isolated key prefixing (`WP_REDIS_PREFIX` and `WP_CACHE_KEY_SALT`) when dedicated Redis DBs are exhausted.
- Headless non-interactive `--force` / `-f` support for `delete-site` command.
- `REQUIRE_CACHE_PURGE_MODULE` feature flag (defaults to `ENABLE_CACHE_PURGE_MODULE`) for strict source-build enforcement.
- Cache purge source fallback support via `NGINX_CACHE_PURGE_REPO_FALLBACK`.
- `cache-purge-check` now prints build state, module file status, loader status, and build flags.
- Additional cache purge module source validation during Nginx source builds.
- `protocol-check [domain|--all]` command for deep HTTP/2/HTTP/3/QUIC readiness checks.
- `protocol-enforce [domain|--all]` command to enforce modern protocol directives across vhosts.

### Changed
- Modernized MariaDB database tuning (`write_mariadb_tuning`) for MariaDB 11.4 LTS by removing deprecated `query_cache_*` and static `innodb_log_file_size` directives in favor of native dynamic redo logging.
- Comprehensive defensive parameter expansion shielding (`${1:-}`, `${2:-}`, etc.) applied across all newly introduced and refactored functions (`run_logged_build_cmd`, `record_nginx_build_state`, `write_nginx_build_state`, `build_nginx_from_source`, `delete_site`, `menu_with_domain`, `menu_run_for_site_or_all`, `install_or_fallback_nginx_source`, `package_available`, `policy_has_ondrej_source`, `policy_has_ondrej_nginx_source`, `version_is_ge`, `openssl_tag_version`, `resolve_latest_openssl_ref`, `protocol_readiness_check`), guaranteeing complete immunity against unbound variable aborts under `set -u`.
- Refactored monolithic script architecture via in-memory deduplication: collapsed repetitive Nginx source compilation workflows (`run_logged_build_cmd`), unified pre-install APT state recovery (`sync_nginx_preinstall_state`), streamlined package policy parsing (`policy_candidate_matches_regex`), deduplicated dynamic module failure recovery (`disable_extracted_nginx_modules`), unified source rebuild and installation engines (`rebuild_nginx_core`, `install_or_fallback_nginx_source`), and consolidated CLI dispatch initialization checks (`require_initialized_and_root`), reducing redundant code by over 330 lines while maintaining 100% feature and test parity.
- Refactored `generate_secure_password` to mathematically guarantee exact requested length without truncate shortfalls.
- Added `:/tmp` to PHP-FPM pool `open_basedir` preventing plugin temporary file restriction failures.
- Corrected Nginx FastCGI cache purge directives to standard `fastcgi_cache_purge wordpress_cache <key>;` syntax in vhosts and upgrade scripts.
- Expanded `remove_old_backups` retention purging to cover `.tar.gz` and `.tar.gz.enc` uploads backups.
- Corrected atomic locking wait-time metric calculation from raw count to actual milliseconds (`$((waited * 500))ms`).
- Nginx source build now fails hard (no package fallback) when cache purge is explicitly required and not buildable.
- Documentation set refreshed for current command surface and operational checks.
- HTTP/2/HTTP/3 patching now resolves vhost files more reliably (including non-`.conf` naming patterns) and uses broader SSL listener detection.
- Licensing docs moved to an explicit dual-license open-core model with dedicated `COMMERCIAL_LICENSE.md` and `TRADEMARK.md`.
- Security reporting contact standardized to `hello@dazestack.com` (with legacy fallback retained).

### Documentation
- README restructured to a product-first flow while keeping operational and module-level references.
- Added canonical AGPLv3 text at `LICENSES/AGPL-3.0.txt` and linked from `LICENSE`.
- Updated FAQ with expanded Redis database capacity and shared key-space fallback details.

### Fixed
- Fixed WordPress system cron executing as `root` in `phase_wordpress_cron`; scheduled events now execute strictly under the unprivileged `www-data` user, eliminating privilege escalation exposure and file ownership corruption.
- Fixed infinite redirect loop (`ERR_TOO_MANY_REDIRECTS`) upon SSL certificate issuance by updating WordPress canonical `siteurl` and `home` database options to `https://$domain` via WP-CLI.
- Fixed Fail2ban daemon startup crash on Ubuntu 24.04 LTS by configuring `backend = systemd` in `jail.local`, eliminating dependence on the missing `/var/log/auth.log`.
- Fixed FastCGI microcache bypass on standard desktop browser reloads by removing `max-age=0` from `$skip_cache_cache_control`.
- Fixed Cloudflare real-IP updater blanking existing configuration during transient network/curl failures by adding a `set_real_ip_from` presence check before atomic commit.
- Fixed orphaned Certbot renewal failures following site deletion by calling `certbot delete --cert-name "$domain"` during `delete_site`.
- Fixed unbounded disk growth of WordPress site logs by adding `/var/www/*/logs/*.log` rotation rules to `phase_logrotate`.
- Fixed automated backups environment isolation by sourcing configuration files inside the cron runner so `BACKUP_INCLUDE_FILES` is honored headlessly.
- Fixed Redis performance health check in `phase_health_check` replacing non-terminating `--latency -c 10` with deterministic round-trip PING timing and timeout.
- Guarded unpassed positional parameters across entry functions to prevent `unbound variable` failures under `set -u`.
- Fixed Nginx syntax failure during purge module activation by providing correct zone name (`wordpress_cache`) and key argument to `fastcgi_cache_purge`.
- Fixed `delete-site` hanging on interactive `read` in non-interactive / headless CI environments.
- `safe_apt_install()` now snapshots `PIPESTATUS` before indexed access, preventing `set -u` failures such as `PIPESTATUS[1]: unbound variable`.
- Cache purge readiness diagnostics now expose configuration state more clearly during troubleshooting.

## [0.0.1] - 2026-02-01

### Added
- Initial DazeStack WP release.
- One-command Ubuntu 24.04+ WordPress LEMP installation.
- Per-site PHP-FPM isolation and Redis object caching.
- Encrypted credential storage and automated encrypted backups.
- Auto-tune engine, health checks, and modular phase runner.
- Cloudflare real IP integration and optional HTTP/3, Brotli, Zstd.

## [pre-0.0.1] - 2026-02-01

### Notes
- Legacy external audit (pre-release snapshot) reported severe issues.
- Many reported items were addressed before or by `0.0.1`; see `dazestack-wp-audit.md` for current status and mapping.
