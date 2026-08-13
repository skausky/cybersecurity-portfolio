#!/usr/bin/env bash
# run.sh — Run cam-scan.py as root using the project venv.
#
# Usage:  ./run.sh [OPTIONS]
#         ./run.sh --help
#
# The venv's Python is invoked directly with sudo so all installed
# packages are available without any environment-variable gymnastics.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_PYTHON="${SCRIPT_DIR}/venv/bin/python3"
MAIN="${SCRIPT_DIR}/cam-scan.py"

if [[ ! -x "$VENV_PYTHON" ]]; then
  echo "ERROR: venv not found. Run setup first:"
  echo "  bash setup.sh"
  exit 1
fi

exec sudo "$VENV_PYTHON" "$MAIN" "$@"
