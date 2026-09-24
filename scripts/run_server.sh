#!/usr/bin/env bash
# Run a local relay for development.
#
#   ./scripts/run_server.sh
#   NK_PORT=9000 ./scripts/run_server.sh --require-hashcash
#
# Uses uv when available (and syncs the environment), otherwise falls back to a
# local .venv or the system interpreter.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${NK_HOST:-127.0.0.1}"
PORT="${NK_PORT:-8000}"
DATA_DIR="${NK_DATA_DIR:-./relay_data}"

ARGS=(--host "$HOST" --port "$PORT" --data-dir "$DATA_DIR" "$@")

if command -v uv >/dev/null 2>&1; then
  exec uv run nk-server "${ARGS[@]}"
fi

if [ -x .venv/bin/python ]; then
  exec .venv/bin/python -m noknowledge.server "${ARGS[@]}"
fi

exec python3 -m noknowledge.server "${ARGS[@]}"