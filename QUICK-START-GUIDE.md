# DazeStack WP v0.0.1 - Quick Start Guide

DazeStack WP is part of the DazeStack series - tools that let you laze while the code does the work.
Tagline: Laze while your WordPress stack builds itself.
Description: Production-ready, fully automated WordPress LEMP platform with per-site isolation, caching, SSL, backups, and maintenance tooling.

## Installation

### Prerequisites
- Ubuntu 24.04 LTS (Noble) or newer
- Root access (sudo)
- 512MB RAM minimum (2GB+ recommended)
- 5GB+ disk space
- Internet connection

### One-Command Installation
```bash
chmod +x dazestack-wp.sh
sudo bash dazestack-wp.sh
```

### Installation Time
- Expected: 30-60 minutes (network dependent)
- Phases: 17 automated phases
- Services installed: Nginx, PHP 8.5, MariaDB, Redis

---

## Post-Installation

### Verify Installation
```bash
sudo bash dazestack-wp.sh health-check
```

Expected output (example):
```
nginx is running
mariadb is running
redis-server is running
php8.5-fpm is running
MySQL connectivity verified
Redis authentication working
PHP-FPM socket exists
Nginx configuration valid
Disk space OK
Memory available

Health Check Summary: 10/10 checks passed
System health: GOOD
```

### CLI Wrapper (Optional)
```bash
sudo bash dazestack-wp.sh install-cli

# Then use:
dazestack-wp list-sites
dazestack-wp create-site example.com admin@example.com
```

---

## Site Management

### Create WordPress Site (Fully Automated)
```bash
sudo bash dazestack-wp.sh create-site example.com admin@example.com
# or with custom title
sudo bash dazestack-wp.sh create-site example.com "My Site" admin@example.com
```

What happens:
1. Domain validation (RFC 1035 compliant)
2. Redis DB allocation (DB 1-15; DB 0 reserved)
3. MySQL database and user creation
4. Isolated PHP-FPM pool creation
5. Nginx vhost configuration
6. WordPress installed and configured
7. Encrypted credential storage
8. Site registered in registry

Output (example):
```
Domain: example.com
Site Directory: /var/www/example.com/public
Database: wp_example_com
Redis DB: 1

Next Steps:
  1. Configure DNS
  2. Enable SSL
  3. View credentials
```

### Configure DNS
Point your domain to your server IP:
```
A Record: example.com -> YOUR_SERVER_IP
A Record: www.example.com -> YOUR_SERVER_IP
```

### Enable SSL Certificate
```bash
sudo bash dazestack-wp.sh enable-ssl example.com
```

Notes:
- Requires DNS to be live before issuance.
- HTTP/2 enabled automatically; HTTP/3 enabled when supported by Nginx build.
- Auto-renewal is configured by Certbot.

### View Site Credentials
```bash
sudo bash dazestack-wp.sh show-credentials example.com
```

Output (decrypted for 60 seconds):
```
WordPress Site Credentials
Domain: example.com

Database Configuration:
Database Name: wp_example_com
Database User: wp_example
Database Password: [secure password]
Database Host: localhost:/run/mysqld/mysqld.sock

Redis Configuration:
Redis DB: 1
Redis Password: [secure password]
```

### List All Sites
```bash
sudo bash dazestack-wp.sh list-sites
```

Output (example):
```
Total Sites: 3

Domain: example.com
  Redis DB: 1
  PHP Pool: example_com
  Database: wp_example_com
  Status: active
  Created: 2026-02-01 10:30:00
```

### Delete Site
```bash
sudo bash dazestack-wp.sh delete-site example.com
```

Safety features:
1. Confirmation required (type "DELETE")
2. Automatic final backup (encrypted)
3. Complete cleanup (database, files, configs)
4. Resource release (Redis DB, PHP pool)

---

## Daily Operations

### View Logs
```bash
# Installer logs
tail -f /var/log/dazestack-wp/installation.log

# Error logs
tail -f /var/log/dazestack-wp/error.log

# Security events
tail -f /var/log/dazestack-wp/security.log

# Audit trail
tail -f /var/log/dazestack-wp/audit.log

# Site-specific logs
tail -f /var/www/example.com/logs/access.log
tail -f /var/www/example.com/logs/error.log
tail -f /var/www/example.com/logs/php-error.log
```

### Check Backups
```bash
ls -lah /var/backups/dazestack-wp/

# Backups are:
# - Encrypted with AES-256
# - Compressed with gzip
# - Retention 7-15 days (based on disk size)
# - Created daily at 2:00 AM
```

### Restore Backup
```bash
# 1. Decrypt
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
    -in /var/backups/dazestack-wp/wp_example_com-20260201.sql.gz.enc \
    -out /tmp/restore.sql.gz \
    -pass file:/root/.dazestack-wp/.backup.key

# 2. Decompress
gunzip /tmp/restore.sql.gz

# 3. Import
mysql wp_example_com < /tmp/restore.sql

# 4. Clean up
shred -u /tmp/restore.sql
```

### Monitor System Health
```bash
# Quick health check
sudo bash dazestack-wp.sh health-check

# Service status
sudo systemctl status nginx
sudo systemctl status mariadb
sudo systemctl status redis-server
sudo systemctl status php8.5-fpm

# Nginx config
sudo nginx -t

# MySQL status
sudo mysqladmin status
```

### View fail2ban Status
```bash
sudo fail2ban-client status nginx-limit-req
```

### View Firewall Rules
```bash
sudo ufw status verbose
```

---

## Maintenance Tasks

### Update System
```bash
sudo apt update
sudo apt upgrade -y
sudo systemctl restart nginx
sudo systemctl restart php8.5-fpm
sudo systemctl restart mariadb
```

### Update WordPress (WP-CLI)
```bash
cd /var/www/example.com/public
sudo -u www-data wp core update
sudo -u www-data wp plugin update --all
sudo -u www-data wp theme update --all
```

### Clear Cache
```bash
# Clear Nginx cache
sudo rm -rf /var/cache/nginx/microcache/*

# Purge a single URL (run on the server)
curl -I -X PURGE https://example.com/some-page
# or using the /purge/ endpoint
curl -I https://example.com/purge/some-page

# Clear Redis cache for a site
redis-cli -a [PASSWORD] -n [DB_NUMBER] FLUSHDB

# Clear WordPress cache (if using plugin)
cd /var/www/example.com/public
sudo -u www-data wp cache flush
```

### Auto-Tune Performance
```bash
sudo bash dazestack-wp.sh auto-tune
```

---

## Troubleshooting

### Site Not Loading
```bash
sudo nginx -t
sudo systemctl status nginx
tail -f /var/www/example.com/logs/error.log
```

### PHP-FPM Issues
```bash
sudo systemctl status php8.5-fpm
ls -l /run/php/php8.5-example_com.sock
cat /etc/php/8.5/fpm/pool.d/example_com.conf
```

### Database Connection Errors
```bash
sudo systemctl status mariadb
mysql -e "SELECT 1;"
```

Check wp-config.php:
```bash
grep DB_ /var/www/example.com/public/wp-config.php
```

### Redis Not Working
```bash
sudo systemctl status redis-server
redis-cli -a [PASSWORD] PING
```

### 502 Bad Gateway
```bash
sudo systemctl restart php8.5-fpm
ls -l /run/php/php8.5-example_com.sock
```

---

## Release Checklist (Deployment Readiness)

### Pre-Flight
- Confirm OS: Ubuntu 24.04 LTS (Noble) or newer
- Confirm resources: 512MB+ RAM, 5GB+ disk
- Verify internet access (APT + PPA + Let's Encrypt)
- Confirm DNS points to server before SSL issuance

### Installation
- Run full install: `sudo bash dazestack-wp.sh`
- Confirm services: nginx, mariadb, redis-server, php8.5-fpm
- Run health check: `sudo bash dazestack-wp.sh health-check`
- Review logs: `/var/log/dazestack-wp/`

### Site Creation
- Create site: `sudo bash dazestack-wp.sh create-site example.com admin@example.com`
- Confirm admin login works
- Confirm Redis object cache is enabled
- Confirm microcache headers (X-FastCGI-Cache) appear on front-end

### SSL & Network
- Enable SSL: `sudo bash dazestack-wp.sh enable-ssl example.com`
- Confirm HTTP/2 enabled; HTTP/3 if Nginx supports QUIC
- Verify Cloudflare IP config if using Cloudflare

### Backups & Security
- Verify encrypted backups at `/var/backups/dazestack-wp/`
- Confirm fail2ban + UFW active
- Confirm credentials encrypted in `/root/.dazestack-wp/`

### Performance
- Run auto-tune: `sudo bash dazestack-wp.sh auto-tune`
- Recheck health: `sudo bash dazestack-wp.sh health-check`

---

## Release Sign-Off

Release version: 0.0.1 (Core)  
Target OS: Ubuntu 24.04 LTS (Noble) or newer  
PHP: 8.5 (Ondrej PPA)  

Sign-Off Checklist (fill in):
- [ ] Pre-flight checks completed
- [ ] Full installation successful
- [ ] Health check passed
- [ ] Site creation verified
- [ ] SSL verified
- [ ] Backups verified
- [ ] Security checks verified
- [ ] Performance auto-tune applied

Signed by: __________________________  
Date: _______________________________  
Environment: ________________________  

---

## Performance Notes

- HTTP/2 is enabled with SSL. HTTP/3 is enabled if your Nginx build supports it.
- Zstandard and Brotli are enabled when modules are available, otherwise gzip is used.
- Redis DB 0 is reserved for system use; sites use DB 1-15.
- Auto-tune is scheduled via cron after install (can be re-run any time).

---

## Cloudflare Notes

A recommended Cloudflare configuration file is created at:
```
/etc/dazestack-wp/cloudflare-recommended.txt
```

---

## Support

### Documentation
- Quick start: This file
- Audit report (legacy context): dazestack-wp-audit.md

### Getting Help
1. Check logs: /var/log/dazestack-wp/
2. Run health check: sudo bash dazestack-wp.sh health-check
3. Review documentation
4. Contact: mail@ashishdungdung.com

---

## License

This script is provided as-is. Review and test thoroughly before production use.

License: MIT (see LICENSE)

Author: Ashish Dungdung
Version: 0.0.1 (Core)
Website: https://ashishdungdung.com
Email: mail@ashishdungdung.com

---

## Changelog

### v0.0.1 (Core)
- One-command Ubuntu 24.04+ WordPress LEMP installation
- Per-site PHP-FPM isolation and Redis object caching
- Encrypted credential storage and automated backups
- Auto-tune engine, health checks, and modular phase runner
- Cloudflare real IP integration and optional HTTP/3/Brotli/Zstd
