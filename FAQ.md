# DazeStack WP - FAQ

## 1) Which OS versions are supported?
Ubuntu 24.04 LTS or newer.

## 2) Is this production-ready?
The project is designed for production use on supported Ubuntu versions, but you should still test in staging and follow your own rollout controls.

## 3) What PHP version is used?
Default target is `PHP 8.5` via `ppa:ondrej/php`.

Override example:
```bash
PHP_TARGET_VERSION=8.4 sudo bash dazestack-wp.sh
```

## 4) How many sites can I host by default?
Redis DB allocation uses DB `1-15` for sites (DB `0` is reserved), so default logical capacity is 15 sites, subject to hardware limits.

## 5) Where are credentials stored?
Encrypted under:

```text
/root/.dazestack-wp/
```

View with:
```bash
sudo bash dazestack-wp.sh show-credentials example.com
```

## 6) What gets backed up?
Encrypted database dumps (not full site file backups) at:

```text
/var/backups/dazestack-wp/
```

## 7) How do I enable SSL later?
After DNS is live:

```bash
sudo bash dazestack-wp.sh enable-ssl example.com
```

## 8) Does it support HTTP/3, Brotli, Zstd?
Yes, when supported by your Nginx build/module availability. The script detects support and configures fallbacks.

## 9) How do I check cache health?

```bash
sudo bash dazestack-wp.sh cache-status --all
sudo bash dazestack-wp.sh cache-deep-check example.com
```

## 10) What is `cache-purge-check` for?
It validates cache purge readiness by checking:

- build state (`source`/`success`)
- module file presence (`ngx_http_cache_purge_module.so`)
- loader conf in `/etc/nginx/modules-enabled`
- runtime deep-check availability

Run:

```bash
sudo bash dazestack-wp.sh cache-purge-check
```

## 11) I see build state success, but purge module is false. Why?
Build state can be stale from earlier builds. Use `cache-purge-check` to validate actual module + loader + runtime state, then rebuild from source with strict purge flags if needed.

## 12) How do I force cache purge module in source build?

```bash
sudo ENABLE_CACHE_PURGE_MODULE=true \
REQUIRE_CACHE_PURGE_MODULE=true \
NGINX_CACHE_PURGE_REPO=https://github.com/nginx-modules/ngx_cache_purge.git \
NGINX_CACHE_PURGE_REF=master \
LOG_FILE_OUTPUT_ENABLED=true \
bash dazestack-wp.sh nginx-source-build 1.28.2 --auto
```

## 13) I got `PIPESTATUS[1]: unbound variable`. What does it mean?
That was a known pipeline-status handling bug in earlier script revisions under `set -u`. The latest revision fixes it in `safe_apt_install()` by snapshotting `PIPESTATUS` safely.

## 14) Where are logs?

- Installer logs: `/var/log/dazestack-wp/`
- Site logs: `/var/www/<domain>/logs/`

## 15) How do I update Nginx after source build?

```bash
sudo bash dazestack-wp.sh rebuild-nginx
sudo bash dazestack-wp.sh nginx-auto-update --status
sudo bash dazestack-wp.sh nginx-auto-update --run
```

## 16) Can I integrate Cloudflare?
Yes. Refresh IP allowlists with:

```bash
sudo bash dazestack-wp.sh update-cloudflare-ips
```

Recommended settings file:

```text
/etc/dazestack-wp/cloudflare-recommended.txt
```

## 17) How do I uninstall everything?

```bash
sudo bash dazestack-wp.sh factory-reset --force
```

This is destructive and removes stack/data/config.

## 18) Where is full version history?
In `CHANGELOG.md`.

## 19) How do I deeply verify and enforce HTTP/2 + HTTP/3 for all domains?
Use the new protocol commands:

```bash
sudo bash dazestack-wp.sh protocol-check --all
sudo bash dazestack-wp.sh protocol-enforce --all
```

You can target one domain too:

```bash
sudo bash dazestack-wp.sh protocol-check example.com
sudo bash dazestack-wp.sh protocol-enforce example.com
```

`protocol-check` reports config + local origin probes (ALPN and Alt-Svc via `127.0.0.1` SNI/resolve), so Cloudflare edge behavior does not hide origin protocol gaps.

## 20) What license model does DazeStack WP use?
DazeStack WP uses a dual-license open-core model:

- AGPLv3 open-source path (see `LICENSE` and `LICENSES/AGPL-3.0.txt`)
- Commercial license path (see `COMMERCIAL_LICENSE.md`)

Trademark and branding usage rules are documented in `TRADEMARK.md`.
