#!/usr/bin/env bash
# Systemd persistence: a masquerading service with a suspicious ExecStart.
# The ExecStart uses /bin/bash -c which triggers the scan pattern matcher.
# Detected by: defender-cli anti-persistence --systemd
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

UNIT="defender-test-beacon.service"
UNIT_FILE="/etc/systemd/system/$UNIT"

case "${1:-}" in
  deploy)
    cat > "$UNIT_FILE" << 'EOF'
[Unit]
Description=System Health Monitor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while sleep 300; do /usr/bin/logger "defender-test-beacon"; done'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    if systemctl enable --now "$UNIT" 2>/dev/null; then
      echo "[+] 03_systemd_service: $UNIT enabled and running"
    else
      echo "[+] 03_systemd_service: $UNIT unit file installed (systemctl enable failed — check journalctl -u $UNIT)"
    fi
    ;;
  cleanup)
    systemctl disable --now "$UNIT" 2>/dev/null || true
    rm -f "$UNIT_FILE"
    systemctl daemon-reload
    echo "[-] 03_systemd_service: $UNIT removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
