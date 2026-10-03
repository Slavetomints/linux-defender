#!/usr/bin/env bash
# Capabilities persistence: a binary granted cap_net_raw (on the dangerous caps list).
# getcap -r / will surface this to the defender's capabilities sweep.
# Requires libcap (pacman -S libcap — usually installed by default on Arch).
# Detected by: defender-cli anti-persistence --capabilities
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

CAPS_BIN="/usr/local/bin/defender-test-caps"

case "${1:-}" in
  deploy)
    if ! command -v setcap &>/dev/null; then
      echo "[-] 11_capabilities: setcap not found (pacman -S libcap); skipping"
      exit 0
    fi
    cp /usr/bin/id "$CAPS_BIN"
    chmod 700 "$CAPS_BIN"
    setcap cap_net_raw+eip "$CAPS_BIN"
    echo "[+] 11_capabilities: $CAPS_BIN installed with cap_net_raw+eip"
    ;;
  cleanup)
    if command -v setcap &>/dev/null && [[ -f "$CAPS_BIN" ]]; then
      setcap -r "$CAPS_BIN" 2>/dev/null || true
    fi
    rm -f "$CAPS_BIN"
    echo "[-] 11_capabilities: $CAPS_BIN removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
