# 🚀 DazeStackWP  
**Version:** 0.0.1  
**Tagline:** *Laze while your WordPress stack builds itself.*

> **DazeStackWP** is an official WordPress + LEMP automation stack under the **DazeStack™ ecosystem**.  
> It installs and manages a **production-ready, fully automated WordPress platform** with per-site isolation, caching, SSL, backups, and maintenance tooling on **Ubuntu 24.04+**.

---

## 🌟 Why DazeStackWP

Setting up WordPress properly is easy to **start** and painful to **finish**. A real “production setup” usually turns into a long checklist:

- LEMP stack + PHP tuning
- SSL automation
- Redis caching + object-cache config
- Per-site isolation (security + performance)
- Backups + restore strategy + retention
- Health checks and maintenance scripts
- Cloudflare real IP handling
- Optional modern optimizations (HTTP/3, Brotli, Zstd)

**DazeStack philosophy**:

> **Stop wasting human time on repetitive setup.**  
> Let automation stacks do the work — reliably, securely, and repeatably.

DazeStackWP is the WordPress stack in the broader DazeStack series — future stacks will cover many platforms and automation modules.

---

## 📚 Table of Contents
- [What You Get](#-what-you-get)
- [Who This Is For](#-who-this-is-for)
- [Quick Start](#-quick-start)
- [CLI Usage](#-cli-usage)
- [System Requirements](#-system-requirements)
- [What Gets Installed](#-what-gets-installed)
- [Architecture Overview](#-architecture-overview)
- [Security Model](#-security-model)
- [Performance & Caching](#-performance--caching)
- [Backups & Maintenance](#-backups--maintenance)
- [Cloud & Provider Readiness](#-cloud--provider-readiness)
- [Project Layout](#-project-layout)
- [Documentation](#-documentation)
- [Roadmap](#-roadmap)
- [Licensing (Open-Core)](#-licensing-opencore)
- [Trademark](#-trademark)
- [Contributing](#-contributing)
- [Support & Contact](#-support--contact)
- [Credits](#-credits)

---

## ✅ What You Get

DazeStackWP aims to deliver a “done right” baseline out of the box.

### Core Outcomes
- ✅ One-command WordPress LEMP stack installation
- ✅ Per-site PHP-FPM isolation (separate pools)
- ✅ Redis object caching for performance
- ✅ SSL automation (Let’s Encrypt) with security-friendly defaults
- ✅ Automated backups + maintenance tooling
- ✅ Health checks and modular phase runner architecture
- ✅ Cloudflare real IP integration support
- ✅ Optional modern optimizations: HTTP/3 / Brotli / Zstd (where supported/configured)

### Operational Outcomes
- ✅ Predictable, repeatable deployments
- ✅ Safer multi-site hosting due to isolation
- ✅ Clean foundation for integration into **DazeStack Cloud** workflows

---

## 🎯 Who This Is For

DazeStackWP is built for:

- **Agencies** deploying multiple WordPress sites
- **Developers** who want a fast + safe baseline without manual setup
- **DevOps teams** standardizing WordPress deployments
- **Hosting builders** creating managed hosting using consistent automation
- **Cloud users** who want reproducible server provisioning

---

## ⚡ Quick Start

### Run from GitHub (one-time)
```bash
curl -fsSL https://raw.githubusercontent.com/DazeStack/DazeStackWP/main/dazestack-wp.sh | tr -d '\r' | tee dazestack-wp.sh >/dev/null && chmod +x dazestack-wp.sh
sudo ./dazestack-wp.sh
```

### Install the CLI wrapper (optional)

```
dazestack-wp.sh — main installer
```

###  Then use:

```
dazestack-wp list-sites
dazestack-wp create-site example.com admin@example.
```
#### Tip: After setup, confirm DNS is pointed correctly before enabling strict SSL or caching features.

## 🧰 CLI Usage

Note: Exact commands may evolve as the project grows. This section describes the intended workflow.

### Common Actions

List sites:

dazestack-wp list-sites

Create a site:
```
dazestack-wp create-site example.com admin@example.com
```
Backup a site:
```
dazestack-wp backup-site example.com
```
Run health checks:
```
dazestack-wp health-check
```

## Automation-Friendly

#### DazeStackWP is designed to work well with:
- CI/CD
- cloud-init / user-data scripts
- server provisioning pipelines
- where repeatability and predictable output matter.

## ⚙️ System Requirements

### Minimum Supported Environment
- Ubuntu 24.04 LTS (Noble) or newer
- Root access (sudo)
- 512MB RAM minimum (2GB+ recommended)
- 5GB+ disk space
- Internet connection

### Recommended Production Baseline
2 vCPU
2–4 GB RAM
SSD storage

#Swap configured (especially on 1GB hosts)

## 📦 What Gets Installed

### DazeStackWP provisions a standard high-performance WordPress platform:
- Nginx (web server + reverse proxy)
- PHP-FPM (per-site pools for isolation)
- Database (MariaDB/MySQL depending on implementation)
- Redis (object caching / performance)
- Let’s Encrypt (Certbot) (SSL issuance and renewal)
- Supporting packages for tuning, security, and automation

🏗 Architecture Overview
Phase-Based Automation Runner

DazeStackWP is designed as a phase runner so it can grow cleanly over time:
1. System preparation
2. Package installation
3. Web server setup
4. Database provisioning
5. WordPress bootstrap
6. SSL hardening
7. Cache integration
8. Backups + maintenance hooks
9. Health checks + verification

This structure makes it easier to:
add new stacks under DazeStack
introduce provider-specific modules
maintain reliability as features expand

### Per-Site Isolation

- Each site is designed to be isolated using:
- separate PHP-FPM pools
- independent configuration boundaries
- This reduces blast radius if one site is compromised or overloaded.

## 🔒 Security Model

### Security is treated as a default — not a premium feature.

#### Intended Security Baseline
- Least-privilege service configuration
- Isolation per site via PHP-FPM pools
- Strong TLS defaults with automated renewal
- Optional Cloudflare real-IP configuration for accurate logs / rate limits
- Sensible exposure controls (ports/services) based on your environment
- Reporting Security Issues

If you discover a vulnerability:
- Do not file a public issue
- Follow SECURITY.md 

## 🚀 Performance & Caching
Redis Object Caching

Redis improves WP performance for dynamic workloads, admin responsiveness, and repeated queries.

PHP-FPM Tuning

Defaults aim to work on both small VPS instances and production servers.
Auto-tune hooks allow future smart tuning based on server resources.

## Optional Modern Optimizations

Depending on your environment:
- HTTP/3
- Brotli
- Zstd compression
- More to be added later

## 🗄 Backups & Maintenance

A WordPress stack without backups is not production-ready.

## DazeStackWP aims to provide:
- automated backups (files + database)
- retention/rotation defaults
- restore tooling (where implemented)
- maintenance hooks (updates, health checks, cleanup)

### Reminder: Always test restores on a staging server.

## ☁️ Cloud & Provider Readiness

### DazeStackWP is designed to be “cloud install script ready” and later integrate with:
- AWS
- DigitalOcean
- UpCloud
- Hetzner
- Other Linux VPS providers

## Future direction includes:
- provider templates (cloud-init / user-data)
- prebuilt images or marketplace integrations
- DazeStack Cloud workflows for one-click deployments

## 🧱 Project Layout

### Typical repo components (may expand):
dazestack-wp.sh — main installer
- docs/ — guides and architecture references
- legal/ — trademark + licensing + commercial policy
- modules/ — reusable automation modules (future)

## 📖 Documentation

Current docs:
QUICK-START-GUIDE.md
dazestack-wp-audit.md (legacy audit context)

## Planned docs:
- architecture deep dive
- module reference
- cloud provider recipes
- troubleshooting guide

## 🗺 Roadmap
### Phase 1 (Now)

- ✅ Initial installer + baseline automation
- ✅ CLI wrapper workflow
- ✅ Documentation and repository hardening

### Phase 2

- 🚀 Cloud-ready templates (cloud-init/user-data)
- 🚀 More stacks under the DazeStack org
- 🚀 Standard stack module format

### Phase 3

- 💼 DazeStack Cloud (hosted automation workflows)
- 💼 DazeStack Cloud Pro (enterprise features + managed automation)

### Phase 4

- 🌍 DazeStack Community + DazeStack Forum
- 🏬 DazeStack Marketplace (stack distribution + ecosystem)

## 🛡 Licensing (Open-Core)

### DazeStackWP is offered under a dual-license open-core model:

#### 1) Open Source — AGPLv3

You may use, modify, and distribute this project under AGPLv3.

#### See: LICENSE

#### 2) Commercial License

### Acommercial license is required if you want to:
- embed DazeStackWP into proprietary products
- offer hosted services without AGPL obligations
- deploy internally under closed enterprise conditions

#### See: COMMERCIAL_LICENSE.md

## ™ Trademark

“DazeStack” is a protected trademark owned by the project founder.

Forks may use the code under the open-source license, but must not use official branding in a confusing way.

See: TRADEMARK.md

## 🤝 Contributing

## Contributions are welcome — especially:

- new modules
- hardening improvements
- performance tuning
- docs and troubleshooting guides

## Recommended workflow:
- Fork the repo
- Create a branch
- Commit changes clearly
- Submit a PR

## 🧾 Support & Contact
* hello@dazestack.com
* legal@dazestack.com

## ❤️ Credits

## Built by Ashish Dungdung under the DazeStack™ ecosystem.
If this project saves you time, please consider starring the repo and sharing feedback via issues/discussions.

::contentReference[oaicite:0]{index=0}

