#!/usr/bin/env bash
# Launch the desktop client.
#
#   ./scripts/run_gui.sh
#   NK_DATA_DIR=/tmp/alice ./scripts/run_gui.sh    # isolated instance
#
# Uses uv when available; `--extra gui` makes sure PyQt5 is installed.
set -euo pipefail
cd "$(dirname "$0")/.."

if command -v uv >/dev/null 2>&1; then
  exec uv run --extra gui nk-gui "$@"
fi

if [ -x .venv/bin/python ]; then
  exec .venv/bin/python -m noknowledge.gui "$@"
fi

exec python3 -m noknowledge.gui "$@"