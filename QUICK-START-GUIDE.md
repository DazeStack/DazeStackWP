# DazeStack WP - Quick Start Guide

Current script version: `0.0.1 (Core)`
Documentation updated: February 13, 2026

This guide is the fastest path to deploy and validate DazeStack WP on Ubuntu 24.04+.

## 1. Prerequisites

- Ubuntu 24.04 LTS or newer
- Root/sudo access
- 512MB RAM minimum (2GB+ recommended)
- 5GB disk minimum (10GB+ recommended)
- Public DNS control for your domain

## 2. Install the Stack

```bash
chmod +x dazestack-wp.sh
sudo bash dazestack-wp.sh
```

## 3. Verify Core Health

```bash
sudo bash dazestack-wp.sh health-check
```

You should see all major services running (`nginx`, `mariadb`, `redis-server`, `php8.5-fpm`) and a healthy summary.

## 4. Create Your First Site

```bash
sudo bash dazestack-wp.sh create-site example.com admin@example.com
```

Optional variants:

```bash
sudo bash dazestack-wp.sh create-site example.com "My Site" admin@example.com
sudo bash dazestack-wp.sh create-site example.com "My Site" admin@example.com adminuser --ssl
```

## 5. Point DNS and Enable SSL

Set DNS records:

- `A` record: `example.com -> <server_ip>`
- `A` record: `www.example.com -> <server_ip>`

Then issue SSL:

```bash
sudo bash dazestack-wp.sh enable-ssl example.com
```

## 6. Check Credentials

```bash
sudo bash dazestack-wp.sh show-credentials example.com
```

## 7. Daily Operations

```bash
# List sites
sudo bash dazestack-wp.sh list-sites

# Re-apply adaptive tuning
sudo bash dazestack-wp.sh auto-tune

# Cache diagnostics
sudo bash dazestack-wp.sh cache-status --all
sudo bash dazestack-wp.sh cache-deep-check example.com

# Compression state
sudo bash dazestack-wp.sh compression-status
```

## 8. Nginx Source Build and Cache Purge (Latest)

If you need strict cache purge module availability:

```bash
sudo ENABLE_CACHE_PURGE_MODULE=true \
REQUIRE_CACHE_PURGE_MODULE=true \
NGINX_CACHE_PURGE_REPO=https://github.com/nginx-modules/ngx_cache_purge.git \
NGINX_CACHE_PURGE_REF=master \
LOG_FILE_OUTPUT_ENABLED=true \
bash dazestack-wp.sh nginx-source-build 1.28.2 --auto
```

Validate readiness:

```bash
sudo bash dazestack-wp.sh cache-purge-check
sudo bash dazestack-wp.sh protocol-check --all
```

Successful output should include:

- `build_type: source`
- `last_build_status: success`
- module file exists: `ngx_http_cache_purge_module.so`
- loader conf exists in `modules-enabled`
- deep check: `Cache purge module available: true`
- protocol status shows compliant HTTP/2 + HTTP/3/QUIC per SSL vhost

## 9. Troubleshooting Fast Paths

```bash
# Nginx config validity
sudo nginx -t

# Service state
sudo systemctl status nginx mariadb redis-server php8.5-fpm

# Installer logs
tail -f /var/log/dazestack-wp/installation.log

# Detailed debug log (includes build output)
tail -f /var/log/dazestack-wp/debug.log
```

## 10. Optional CLI Wrapper

```bash
sudo bash dazestack-wp.sh install-cli
dazestack-wp help
```

## 11. Backup Basics

Backups are encrypted DB dumps in `/var/backups/dazestack-wp/`.

Manual retention cleanup:

```bash
sudo bash dazestack-wp.sh remove-old-backups
sudo bash dazestack-wp.sh remove-old-backups 30
```

## 12. Safety Commands (Destructive)

```bash
sudo bash dazestack-wp.sh refresh-installation --force
sudo bash dazestack-wp.sh factory-reset --force
```

Use only after taking backups and confirming impact.

## Related Docs

- `README.md`
- `FAQ.md`
- `SECURITY.md`
- `CHANGELOG.md`
- `dazestack-wp-audit.md`
