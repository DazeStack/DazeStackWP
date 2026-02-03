Install CLI Wrapper (Optional)
sudo ./dazestack-wp.sh install-cli

Then you can manage stacks using:

dazestack-wp list-sites
dazestack-wp create-site example.com admin@example.com
dazestack-wp backup-site example.com
dazestack-wp health-check
⚙️ Requirements

Minimum supported environment:

Ubuntu 24.04 LTS (Noble) or newer

Root access (sudo)

512MB RAM minimum (2GB+ recommended)

5GB+ disk space

Internet connection

🏗 Architecture Overview

DazeStackWP is designed as:

Modular Phase-Based Automation

Each deployment stage is structured in phases:

System preparation

Package installation

Web server setup

Database provisioning

WordPress bootstrap

SSL hardening

Backup + maintenance hooks

This makes future stack extensions easy.

🔒 Security & Isolation Model

DazeStackWP includes production-grade defaults:

Each site runs in its own PHP-FPM pool

Redis caching is isolated per environment

Credentials are encrypted

Firewall + Nginx hardening ready

Cloudflare real-IP support

📚 Documentation

Current docs include:

QUICK-START-GUIDE.md

dazestack-wp-audit.md (legacy audit context)

Upcoming additions:

Full stack reference guide

Cloud deployment recipes

Marketplace module format

🛡 License (Open-Core Model)

DazeStackWP is released under a dual-license open-core structure:

✅ 1. Open Source License (AGPLv3)

Free for:

Community use

Contributions

Open deployments

Forking under compliance

See: LICENSE

✅ 2. Commercial License

Required if you want to:

Embed DazeStackWP into proprietary systems

Offer SaaS hosting without publishing modifications

Use DazeStack stacks inside closed enterprise environments

See: COMMERCIAL_LICENSE.md

Commercial licensing supports:

DazeStack Cloud expansion

Enterprise roadmap funding

Official ecosystem sustainability

™ Trademark Protection

“DazeStack” is a protected trademark owned by the founder.

Forks may freely use the open-source code,
but may not use official branding such as:

DazeStack Cloud

DazeStack Community

DazeStack Forum

DazeStack Marketplace

See: TRADEMARK.md

🤝 Contributing

Contributions are welcome as DazeStack expands.

You can help by:

Improving automation modules

Adding new stack scripts

Strengthening security defaults

Writing documentation

Building future Cloud workflows

See: CONTRIBUTING.md

🗺 Roadmap
Phase 1 (2026)

✅ DazeStackWP initial release
✅ Trademark protection foundation
✅ Multi-stack automation repo expansion

Phase 2

🚀 Launch DazeStack Cloud workflows

Phase 3

💼 Cloud Pro + Enterprise licensing model

Phase 4

🌍 Community, Forum, Marketplace ecosystem

📩 Contact & Founder

Official project emails:

hello@dazestack.com

legal@dazestack.com

Built with ❤️ by Ashish Dungdung

Founder of DazeStack™

DazeStack is the brainchild of its founder, built to become a global automation ecosystem of deployable stacks, scripts, and cloud-native tooling.
