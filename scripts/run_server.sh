#!/usr/bin/env bash
# Run a local relay for development.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${NK_HOST:-127.0.0.1}"
PORT="${NK_PORT:-8000}"
DATA_DIR="${NK_DATA_DIR:-./relay_data}"

if [ -x .venv/bin/python ]; then
  PY=.venv/bin/python
else
  PY=python3
fi

exec "$PY" -m noknowledge.server --host "$HOST" --port "$PORT" --data-dir "$DATA_DIR" "$@"