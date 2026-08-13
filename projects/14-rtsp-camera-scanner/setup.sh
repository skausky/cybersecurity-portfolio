#!/usr/bin/env bash
# setup.sh — One-time setup: create venv and install Python dependencies.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"
REQ="${SCRIPT_DIR}/requirements.txt"

echo "==> Checking Python 3.10+..."
if ! python3 -c "import sys; assert sys.version_info >= (3,10)" 2>/dev/null; then
  echo "ERROR: Python 3.10 or newer is required."
  echo "Install with: sudo apt install python3.11"
  exit 1
fi

echo "==> Checking system tools..."
missing=()
for tool in masscan ffmpeg ffprobe; do
  command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if (( ${#missing[@]} )); then
  echo "WARNING: Missing system tools: ${missing[*]}"
  echo "         Install with: sudo apt install ${missing[*]}"
fi

echo "==> Creating virtual environment at ${VENV_DIR}..."
python3 -m venv "${VENV_DIR}"

echo "==> Installing Python dependencies..."
"${VENV_DIR}/bin/pip" install --upgrade pip --quiet
"${VENV_DIR}/bin/pip" install -r "${REQ}" --quiet

chmod +x "${SCRIPT_DIR}/run.sh"

echo
echo "Setup complete."
echo "Run the scanner with:  ./run.sh [OPTIONS]"
echo "                  or:  ./run.sh --help"
