#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${VIRTUAL_ENV:-"$ROOT_DIR/venv"}"
PYTHON="$VENV/bin/python3"

if [[ ! -x "$PYTHON" ]]; then
  echo "venv python not found at $PYTHON. Activate your venv or run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
  exit 1
fi

sudo -E env PATH="$VENV/bin:$PATH" VIRTUAL_ENV="$VENV" "$PYTHON" "$ROOT_DIR/src/main.py" "$@"
