#!/usr/bin/env bash
#
# harden-ssh.sh — Audit (and optionally apply) CIS-aligned SSH hardening.
#
# Author : Sean Spakausky
# Usage  : sudo ./harden-ssh.sh            # audit only (default, no changes)
#          sudo ./harden-ssh.sh --apply    # back up sshd_config and apply
#
# NOTE   : Test in a lab/VM snapshot first. Applying password-auth=no will
#          lock out password users — make sure key-based access works first.

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

# Control name -> desired "key value" setting
declare -A DESIRED=(
  ["PermitRootLogin"]="no"
  ["PasswordAuthentication"]="no"
  ["X11Forwarding"]="no"
  ["MaxAuthTries"]="4"
  ["ClientAliveInterval"]="300"
  ["ClientAliveCountMax"]="0"
  ["Protocol"]="2"
)

pass=0; fail=0

current_value() {
  # last non-commented occurrence wins, matching sshd behaviour
  grep -Ei "^\s*$1\b" "$SSHD_CONFIG" 2>/dev/null | tail -n1 | awk '{print $2}'
}

echo "=== SSH Hardening Audit ($(date -Is)) ==="
echo "Config: $SSHD_CONFIG"
echo

for key in "${!DESIRED[@]}"; do
  want="${DESIRED[$key]}"
  have="$(current_value "$key")"
  if [[ "${have,,}" == "${want,,}" ]]; then
    printf '[PASS] %-24s = %s\n' "$key" "$have"
    ((pass++))
  else
    printf '[FAIL] %-24s = %-8s (want: %s)\n' "$key" "${have:-<unset>}" "$want"
    ((fail++))
  fi
done

echo
echo "Score: $pass passing, $fail failing."

if ! $APPLY; then
  echo
  echo "Audit only. Re-run with --apply to remediate (a backup will be created)."
  exit 0
fi

# --- Apply mode ---
backup="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
cp -a "$SSHD_CONFIG" "$backup"
echo
echo "Backed up config to $backup"

for key in "${!DESIRED[@]}"; do
  want="${DESIRED[$key]}"
  if grep -Eqi "^\s*#?\s*$key\b" "$SSHD_CONFIG"; then
    sed -i -E "s|^\s*#?\s*$key\b.*|$key $want|I" "$SSHD_CONFIG"
  else
    echo "$key $want" >> "$SSHD_CONFIG"
  fi
done

echo "Applied hardening. Validating syntax with 'sshd -t'..."
if sshd -t; then
  echo "Config valid. Reload with: systemctl reload sshd"
else
  echo "!! sshd config test FAILED — restoring backup."
  cp -a "$backup" "$SSHD_CONFIG"
  exit 1
fi
