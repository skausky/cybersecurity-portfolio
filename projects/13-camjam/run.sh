#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
V2_DIR="$ROOT_DIR/camjam_v2"
VENV="${VIRTUAL_ENV:-"$ROOT_DIR/venv"}"
PYTHON="$VENV/bin/python3"

if [[ "${1:-}" == "--v1" ]]; then
  shift
  exec sudo -E env PATH="$PATH" "$ROOT_DIR/versions/camjam_v1/run.sh" "$@"
fi

if [[ ! -x "$PYTHON" ]]; then
  echo "venv not found at $PYTHON"
  echo "  python3 -m venv venv && source venv/bin/activate"
  echo "  pip install -r camjam_v2/requirements.txt"
  exit 1
fi

export PYTHONPATH="$V2_DIR:${PYTHONPATH:-}"
cd "$V2_DIR"

if [[ "${1:-}" == "--cli" ]]; then
  exec sudo -E env PATH="$VENV/bin:$PATH" VIRTUAL_ENV="$VENV" PYTHONPATH="$PYTHONPATH" \
    "$PYTHON" -m camjam --cli "${@:2}"
fi

exec sudo -E env PATH="$VENV/bin:$PATH" VIRTUAL_ENV="$VENV" PYTHONPATH="$PYTHONPATH" \
  "$PYTHON" -m camjam "$@"