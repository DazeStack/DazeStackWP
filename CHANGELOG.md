# Changelog

All notable changes to DazeStack WP are documented in this file.

## [Unreleased] - 2026-02-14

### Added
- `REQUIRE_CACHE_PURGE_MODULE` feature flag (defaults to `ENABLE_CACHE_PURGE_MODULE`) for strict source-build enforcement.
- Cache purge source fallback support via `NGINX_CACHE_PURGE_REPO_FALLBACK`.
- `cache-purge-check` now prints build state, module file status, loader status, and build flags.
- Additional cache purge module source validation during Nginx source builds.
- `protocol-check [domain|--all]` command for deep HTTP/2/HTTP/3/QUIC readiness checks.
- `protocol-enforce [domain|--all]` command to enforce modern protocol directives across vhosts.

### Changed
- Nginx source build now fails hard (no package fallback) when cache purge is explicitly required and not buildable.
- Documentation set refreshed for current command surface and operational checks.
- HTTP/2/HTTP/3 patching now resolves vhost files more reliably (including non-`.conf` naming patterns) and uses broader SSL listener detection.
- Licensing docs moved to an explicit dual-license open-core model with dedicated `COMMERCIAL_LICENSE.md` and `TRADEMARK.md`.
- Security reporting contact standardized to `hello@dazestack.com` (with legacy fallback retained).

### Documentation
- README restructured to a product-first flow while keeping operational and module-level references.
- Added canonical AGPLv3 text at `LICENSES/AGPL-3.0.txt` and linked from `LICENSE`.

### Fixed
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
