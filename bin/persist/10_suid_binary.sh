#!/usr/bin/env bash
# SUID persistence: a setuid-root copy of /usr/bin/id.
# find -perm -4000 will surface this to the defender's SUID sweep.
# Detected by: defender-cli anti-persistence --suid
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

SUID_BIN="/usr/local/bin/defender-test-suid"

case "${1:-}" in
  deploy)
    cp /usr/bin/id "$SUID_BIN"
    chmod u+s "$SUID_BIN"
    echo "[+] 10_suid_binary: $SUID_BIN installed with SUID bit set"
    ;;
  cleanup)
    chmod u-s "$SUID_BIN" 2>/dev/null || true
    rm -f "$SUID_BIN"
    echo "[-] 10_suid_binary: $SUID_BIN removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
