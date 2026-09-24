#!/usr/bin/env bash
# Launch the desktop client. Set NK_DATA_DIR to run isolated instances, e.g.
#   NK_DATA_DIR=/tmp/alice ./scripts/run_gui.sh
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -x .venv/bin/python ]; then
  PY=.venv/bin/python
else
  PY=python3
fi

exec "$PY" -m noknowledge.gui "$@"