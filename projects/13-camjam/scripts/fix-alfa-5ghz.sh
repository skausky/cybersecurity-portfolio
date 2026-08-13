#!/usr/bin/env bash
# Fix Alfa / Realtek 0bda:0811 (8812AU/8821AU) for 5 GHz monitor scans on Linux Mint / Ubuntu.
# Replaces in-kernel rtw88_8821au with the aircrack-ng 88XXau DKMS driver from this repo.
#
# Usage:
#   sudo ./scripts/fix-alfa-5ghz.sh
#   sudo ./scripts/fix-alfa-5ghz.sh --verify-only
#   sudo ./scripts/fix-alfa-5ghz.sh --soft-only   # regdom + hints only, no DKMS
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRV_DIR="${ROOT_DIR}/rtl8812au"
MODPROBE_FILE="/etc/modprobe.d/camjam-alfa-88xxau.conf"
USB_VID="0bda"
USB_PID="0811"
VERIFY_ONLY=false
SOFT_ONLY=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[camjam]${NC} $*"; }
ok()   { echo -e "${GREEN}[ok]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
die()  { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }

for arg in "$@"; do
  case "$arg" in
    --verify-only) VERIFY_ONLY=true ;;
    --soft-only)   SOFT_ONLY=true ;;
    -h|--help)
      sed -n '2,8p' "$0"
      exit 0
      ;;
    *) die "Unknown option: $arg (try --help)" ;;
  esac
done

if [[ "${EUID:-}" -ne 0 ]]; then
  die "Run as root: sudo $0"
fi

if [[ ! -d "$DRV_DIR" ]] || [[ ! -f "$DRV_DIR/Makefile" ]]; then
  die "Driver source not found at $DRV_DIR"
fi

find_alfa_usb() {
  lsusb -d "${USB_VID}:${USB_PID}" 2>/dev/null | head -1 || true
}

find_alfa_iface() {
  local path drv
  for path in /sys/class/net/wl*; do
    [[ -e "$path" ]] || continue
    drv="$(basename "$(readlink -f "$path/device/driver" 2>/dev/null || echo "")" 2>/dev/null || true)"
    if [[ "$drv" == rtw88_* ]] || [[ "$drv" == "88XXau" ]]; then
      basename "$path"
      return 0
    fi
  done
  # fallback: any wlx* (Alfa often wlx...)
  for path in /sys/class/net/wlx*; do
    [[ -e "$path" ]] && basename "$path" && return 0
  done
  return 1
}

usb_device_path() {
  local iface="${1:-}"
  [[ -n "$iface" ]] || return 1
  readlink -f "/sys/class/net/${iface}/device" 2>/dev/null || true
}

driver_for_iface() {
  local iface="$1"
  basename "$(readlink -f "/sys/class/net/${iface}/device/driver" 2>/dev/null || echo unknown)" 2>/dev/null
}

apply_regdom() {
  local alpha="US"
  if command -v iw >/dev/null 2>&1; then
    local line
    line="$(iw reg get 2>/dev/null | grep -oP 'country \K[A-Z]{2}' | head -1 || true)"
    [[ -n "$line" ]] && alpha="$line"
    log "Setting regulatory domain to ${alpha} (iw reg set)..."
    if iw reg set "$alpha" 2>/dev/null; then
      ok "Regulatory domain: $alpha"
    else
      warn "Could not set reg domain (may still be OK)"
    fi
  fi
}

verify_5ghz() {
  local iface="$1"
  log "Verifying 5 GHz monitor on ${iface}..."

  local drv
  drv="$(driver_for_iface "$iface")"
  log "Driver: ${drv}"

  if [[ "$drv" != "88XXau" ]]; then
    warn "Expected driver 88XXau but got '${drv}'. Replug adapter or reboot."
    return 1
  fi

  ip link set "$iface" down 2>/dev/null || true
  iw dev "$iface" set type monitor 2>/dev/null || true
  ip link set "$iface" up 2>/dev/null || true

  if ! iw dev "$iface" set channel 36 HT20 2>/dev/null; then
    iw dev "$iface" set channel 36 2>/dev/null || {
      warn "Could not tune to channel 36 — 5 GHz monitor may still be blocked."
      return 1
    }
  fi

  local info
  info="$(iw dev "$iface" info 2>/dev/null || true)"
  echo "$info" | grep -q "5180 MHz" && ok "Interface on 5 GHz (ch 36 / 5180 MHz)" || {
    warn "Channel info after tune:"
    echo "$info" | grep -E 'channel|type' || true
    return 1
  }

  if command -v airodump-ng >/dev/null 2>&1; then
    log "Quick 8s airodump on 5 GHz band (channel 36)..."
    timeout 8 airodump-ng --band a --channel 36 "$iface" 2>/dev/null | head -20 || true
    ok "airodump-ng ran on 5 GHz (check above for AP list)"
  else
    warn "Install aircrack-ng for full scan test: apt install aircrack-ng"
  fi
  return 0
}

show_status() {
  echo
  log "=== Adapter status ==="
  find_alfa_usb || warn "USB ${USB_VID}:${USB_PID} not plugged in"
  local iface
  if iface="$(find_alfa_iface)"; then
    log "Interface: ${iface}"
    driver_for_iface "$iface"
    iw dev "$iface" info 2>/dev/null | grep -E 'addr|type|channel' || true
    if command -v ethtool >/dev/null 2>&1; then
      ethtool -i "$iface" 2>/dev/null | grep -E 'driver|version' || true
    fi
  else
    warn "No Alfa wireless interface found (plug in USB adapter)"
  fi
  echo
  lsmod | grep -E '88XXau|rtw88_88' || true
  echo
}

if $VERIFY_ONLY; then
  show_status
  if iface="$(find_alfa_iface)"; then
    verify_5ghz "$iface" || exit 1
  else
    die "Plug in the Alfa adapter and retry"
  fi
  exit 0
fi

show_status

if ! find_alfa_usb | grep -q .; then
  warn "Alfa USB (${USB_VID}:${USB_PID}) not detected — continue anyway if you will plug it in after reboot."
fi

apply_regdom

if $SOFT_ONLY; then
  warn "Soft-only mode: no DKMS install. If 5 GHz still fails, re-run without --soft-only."
  if iface="$(find_alfa_iface)"; then
    verify_5ghz "$iface" || exit 1
  fi
  exit 0
fi

pkg_installed() {
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

install_apt_deps() {
  local kver="$1"
  local required=(dkms build-essential bc "linux-headers-${kver}" iw aircrack-ng usbutils ethtool)
  local optional=()
  export DEBIAN_FRONTEND=noninteractive

  # libelf-dev was renamed/removed on newer Ubuntu/Mint; driver builds without it.
  for cand in libelf-dev libelf1-dev libdw-dev; do
    if apt-cache show "$cand" &>/dev/null; then
      optional+=("$cand")
      break
    fi
  done
  if [[ ${#optional[@]} -eq 0 ]]; then
    warn "No libelf *-dev package in apt (normal on Mint 22+). Skipping — not required for 88XXau."
  fi

  local missing=()
  local p
  for p in "${required[@]}"; do
    pkg_installed "$p" || missing+=("$p")
  done

  if [[ ${#missing[@]} -eq 0 ]]; then
    ok "Required build dependencies already installed"
    return 0
  fi

  log "Refreshing apt package lists (optional third-party repo errors are ignored)..."
  if apt-get update -qq 2>/dev/null; then
    : ok
  elif [[ -f /etc/apt/sources.list ]] && apt-get -o Dir::Etc::sourceparts="" -o Dir::Etc::sourceparts::commandline::ignore=true update -qq 2>/dev/null; then
    ok "Updated using main sources.list only (skipped broken PPAs)"
  else
    warn "apt-get update failed — continuing without update"
  fi

  log "Installing: ${missing[*]} ${optional[*]}"
  local to_install=("${missing[@]}" "${optional[@]}")
  if apt-get install -y --no-install-recommends "${to_install[@]}"; then
    ok "Dependencies installed"
    return 0
  fi

  # Drop optional and retry
  if apt-get install -y "${missing[@]}"; then
    ok "Required dependencies installed (without optional libelf dev)"
    return 0
  fi

  die "apt install failed for: ${missing[*]}. Try: sudo apt-get install -y dkms build-essential bc iw aircrack-ng linux-headers-${kver}"
}

KVER="$(uname -r)"
install_apt_deps "$KVER"

if [[ ! -d "/lib/modules/${KVER}/build" ]]; then
  die "Kernel headers missing for ${KVER}. Run: sudo apt install linux-headers-${KVER}"
fi

log "Writing modprobe config → ${MODPROBE_FILE}"
cat > "$MODPROBE_FILE" <<'EOF'
# CamJam: prefer aircrack-ng 88XXau for Alfa 8812AU/8821AU (0bda:0811)
# Stops rtw88 from claiming the adapter (poor 5 GHz monitor on many units).
blacklist rtw88_8812au
blacklist rtw88_8821au
install 88XXau /sbin/modprobe --ignore-install 88XXau
EOF
ok "Modprobe rules installed"

log "Removing old 88XXau / 8812au DKMS builds if present..."
dkms status 2>/dev/null | grep -E '8812au|88XXau|realtek-rtl88xxau' || true
while read -r line; do
  mod="$(echo "$line" | awk -F, '{gsub(/^ +| +$/,"",$1); print $1}')"
  ver="$(echo "$line" | awk -F, '{gsub(/^ +| +$/,"",$2); print $2}')"
  [[ -n "$mod" && -n "$ver" ]] && dkms remove "$mod/$ver" --all 2>/dev/null || true
done < <(dkms status 2>/dev/null | grep -iE '8812au|88xx' || true)

log "Building and installing 88XXau via DKMS from ${DRV_DIR}..."
log "(includes kernel 6.14+ patches: ccflags-y, timer API, cfg80211 — required on ${KVER})"
cd "$DRV_DIR"
make clean >/dev/null 2>&1 || true
if ! make dkms_install; then
  warn "DKMS install failed. Log:"
  find /var/lib/dkms/8812au -name make.log 2>/dev/null | tail -1 | xargs tail -30 2>/dev/null || true
  die "DKMS build failed. See make.log above or: cd $DRV_DIR && sudo make dkms_install"
fi

if ! modinfo 88XXau >/dev/null 2>&1; then
  die "88XXau module not found after DKMS install"
fi
ok "88XXau module installed: $(modinfo -F version 88XXau 2>/dev/null || echo unknown)"

unload_rtw88() {
  log "Unloading rtw88 drivers..."
  local mods=(
    rtw88_8821au rtw88_8812au rtw88_8812a rtw88_8821a
    rtw88_usb rtw88_88xxa rtw88_core
  )
  local m
  for m in "${mods[@]}"; do
    modprobe -r "$m" 2>/dev/null || true
  done
}

rebind_alfa() {
  local iface="${1:-}"
  local dev_path usb_if driver_path

  unload_rtw88
  modprobe 88XXau || die "modprobe 88XXau failed"

  [[ -n "$iface" ]] || return 0
  dev_path="$(usb_device_path "$iface")"
  [[ -n "$dev_path" ]] || return 0

  # e.g. .../1-2:1.0 → USB device 1-2
  usb_if="$(basename "$dev_path")"
  local bus_id="${usb_if%%:*}"

  for driver_path in /sys/bus/usb/drivers/rtw88_8821au /sys/bus/usb/drivers/rtw88_8812au; do
    if [[ -e "${driver_path}/${bus_id}" ]]; then
      log "Unbinding ${bus_id} from $(basename "$driver_path")..."
      echo "$bus_id" > "${driver_path}/unbind" 2>/dev/null || true
    fi
  done

  if [[ -d /sys/bus/usb/drivers/88XXau ]]; then
    log "Binding ${bus_id} to 88XXau..."
    echo "$bus_id" > /sys/bus/usb/drivers/88XXau/bind 2>/dev/null || warn "USB bind failed — unplug and replug the adapter"
  fi

  sleep 2
}

IFACE=""
IFACE="$(find_alfa_iface)" || true

if [[ -n "$IFACE" ]]; then
  log "Stopping NetworkManager interference on ${IFACE}..."
  nmcli dev set "$IFACE" managed no 2>/dev/null || true
  ip link set "$IFACE" down 2>/dev/null || true
fi

rebind_alfa "$IFACE"

# Refresh interface name after rebind
sleep 1
IFACE="$(find_alfa_iface)" || IFACE=""

if [[ -z "$IFACE" ]]; then
  warn "Interface not visible yet. Please:"
  echo "  1. Unplug the Alfa USB adapter"
  echo "  2. Wait 3 seconds"
  echo "  3. Plug it back in"
  echo "  4. Run: sudo $0 --verify-only"
  echo
  warn "A reboot also applies modprobe blacklists cleanly:"
  echo "  sudo reboot"
  exit 0
fi

NEW_DRV="$(driver_for_iface "$IFACE")"
if [[ "$NEW_DRV" == "88XXau" ]]; then
  ok "Adapter bound to 88XXau as ${IFACE}"
else
  warn "Driver is still '${NEW_DRV}'. Replug USB or reboot, then: sudo $0 --verify-only"
fi

verify_5ghz "$IFACE" || {
  warn "Verification incomplete — try reboot, then: sudo $0 --verify-only"
  exit 1
}

echo
ok "Done. Use CamJam with interface ${IFACE} and band '5 GHz only' or '2.4 + 5 GHz'."
echo "  cd ${ROOT_DIR} && ./run.sh"
echo "  Re-check anytime: sudo $0 --verify-only"