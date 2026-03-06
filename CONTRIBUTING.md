# Contributing

Thanks for contributing to DazeStack WP.

## Workflow

1. Create a focused branch.
2. Keep changes scoped and explain why they are needed.
3. Update docs when behavior, flags, or commands change.
4. Update `CHANGELOG.md` for user-visible changes.
5. Submit a PR with test evidence and rollback notes.

## Code Style (Bash)

- Keep scripts `bash`-compatible (`set -Eeuo pipefail` conventions are used).
- Prefer explicit checks over implicit behavior.
- Avoid destructive operations without strong guardrails.
- Keep log output actionable and redact secrets.

## Documentation Expectations

When you change behavior, update as needed:

- `README.md`
- `QUICK-START-GUIDE.md`
- `FAQ.md`
- `SECURITY.md`
- `CHANGELOG.md`
- `dazestack-wp-audit.md` (if risk posture changes)

## Suggested Validation Before PR

```bash
# Help and command surface
bash dazestack-wp.sh help

# Health checks (on provisioned test host)
sudo bash dazestack-wp.sh health-check

# Nginx validation after config-related changes
sudo nginx -t

# Optional: source build path
sudo bash dazestack-wp.sh nginx-source-build stable --no-auto
sudo bash dazestack-wp.sh cache-purge-check
```

## PR Template (Recommended)

- Summary
- User impact
- Flags/env vars changed
- Validation commands run
- Logs or output snippets
- Rollback plan

## Security Reports

Do not file public issues for vulnerabilities. Use `hello@dazestack.com` (fallback: `mail@ashishdungdung.com`).
