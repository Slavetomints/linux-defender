#!/usr/bin/env bash
# SSH persistence: an attacker public key in root's authorized_keys.
# Detected by: defender-cli anti-persistence --ssh-keys
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

AUTH="/root/.ssh/authorized_keys"
COMMENT="defender-test@attacker"

case "${1:-}" in
  deploy)
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    tmpkey="$(mktemp)"
    ssh-keygen -t ed25519 -f "$tmpkey" -N "" -C "$COMMENT" -q 2>/dev/null
    cat "${tmpkey}.pub" >> "$AUTH"
    chmod 600 "$AUTH"
    rm -f "$tmpkey" "${tmpkey}.pub"
    echo "[+] 02_ssh_key: test key added to $AUTH"
    ;;
  cleanup)
    [[ -f "$AUTH" ]] && sed -i "/$COMMENT/d" "$AUTH"
    echo "[-] 02_ssh_key: test key removed from $AUTH"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
