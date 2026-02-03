# DazeStack WP

Version: 0.0.1

Tagline: Laze while your WordPress stack builds itself.

DazeStack WP is part of the DazeStack series - tools that let you laze while the code does the work.
It installs and manages a production-ready, fully automated WordPress LEMP platform with per-site
isolation, caching, SSL, backups, and maintenance tooling on Ubuntu 24.04+.

## Quick Start

### Run from GitHub (one-time)
```bash
curl -fsSL https://raw.githubusercontent.com/<YOUR_ORG>/<YOUR_REPO>/main/dazestack-wp.sh -o dazestack-wp.sh
chmod +x dazestack-wp.sh
sudo ./dazestack-wp.sh
```

### Install the CLI wrapper (optional)
```bash
sudo ./dazestack-wp.sh install-cli

# Then use:
dazestack-wp list-sites
dazestack-wp create-site example.com admin@example.com
```

## Requirements
- Ubuntu 24.04 LTS (Noble) or newer
- Root access (sudo)
- 512MB RAM minimum (2GB+ recommended)
- 5GB+ disk space
- Internet connection

## What You Get
- One-command WordPress LEMP stack installation
- Per-site PHP-FPM isolation and Redis object caching
- Encrypted credential storage and automated backups
- Auto-tune engine, health checks, and modular phase runner
- Cloudflare real IP integration and optional HTTP/3/Brotli/Zstd

## Documentation
- QUICK-START-GUIDE.md
- dazestack-wp-audit.md (legacy audit context)

## License
MIT. See LICENSE.

## DazeStack Series
DazeStack tools are designed to remove repetitive setup work so you can focus on shipping.
