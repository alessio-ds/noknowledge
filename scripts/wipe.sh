#!/usr/bin/env bash
# Remove all local relay and client data. Destructive.
set -euo pipefail
cd "$(dirname "$0")/.."

rm -rf relay_data dist build nk-gui.spec nk-server.spec *.spec.bak
rm -rf "${NK_DATA_DIR:-$HOME/.noknowledge}"
find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
echo "Removed relay_data/, dist/, build/ and ${NK_DATA_DIR:-$HOME/.noknowledge}"