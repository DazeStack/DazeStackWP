#!/usr/bin/env bash
# Build and upload DazeStack WP source package to Launchpad PPA
# Requires: devscripts, debhelper, dput, gpg

set -euo pipefail

PPA_TARGET="${1:-ppa:dazestack/wp}"

echo "=== Building Debian Source Package for Launchpad PPA ==="

if ! command -v debuild >/dev/null 2>&1; then
    echo "Error: debuild not found. Install with: sudo apt install -y devscripts debhelper"
    exit 1
fi

if ! command -v dput >/dev/null 2>&1; then
    echo "Error: dput not found. Install with: sudo apt install -y dput"
    exit 1
fi

# Clean previous build artifacts
rm -rf debian/.debhelper/ debian/dazestack-wp/ debian/files

# Build source-only package (no binary compilation required for all-arch shell script)
debuild -S -sa

# Locate generated .changes file
CHANGES_FILE=$(ls -t ../dazestack-wp_*_source.changes 2>/dev/null | head -1)

if [[ -z "$CHANGES_FILE" || ! -f "$CHANGES_FILE" ]]; then
    echo "Error: Source changes file not generated."
    exit 1
fi

echo "Source package built: $CHANGES_FILE"
echo ""
read -p "Upload to Launchpad ($PPA_TARGET)? [y/N]: " confirm
if [[ "$confirm" =~ ^[Yy]$ ]]; then
    dput "$PPA_TARGET" "$CHANGES_FILE"
    echo "Upload complete! Check build status at: https://launchpad.net/~${PPA_TARGET#ppa:}"
else
    echo "Upload aborted. You can manually run: dput $PPA_TARGET $CHANGES_FILE"
fi
