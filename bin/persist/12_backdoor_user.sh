#!/usr/bin/env bash
# User persistence: a hidden account with a login shell.
# The defender's users check lists all accounts; this one stands out by name.
# Detected by: defender-cli anti-persistence --users
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

BACKDOOR="defender-test-backdoor"

case "${1:-}" in
  deploy)
    if id "$BACKDOOR" &>/dev/null; then
      echo "[+] 12_backdoor_user: $BACKDOOR already exists"
      exit 0
    fi
    useradd --create-home --shell /bin/bash --comment "DEFENDER-TEST" "$BACKDOOR"
    echo "[+] 12_backdoor_user: account '$BACKDOOR' created with /bin/bash shell"
    ;;
  cleanup)
    if id "$BACKDOOR" &>/dev/null; then
      userdel --remove "$BACKDOOR" 2>/dev/null
      echo "[-] 12_backdoor_user: '$BACKDOOR' removed"
    else
      echo "[-] 12_backdoor_user: '$BACKDOOR' not found"
    fi
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
