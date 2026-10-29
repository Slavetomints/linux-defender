#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
WEB_CONF="${SPLUNK_HOME}/etc/system/local/web.conf"
MARKER="# cfg-loopback"

case "${1:-}" in
  deploy)
    [[ -d "$SPLUNK_HOME" ]] || { echo "[!] Splunk not found at ${SPLUNK_HOME}"; exit 1; }
    # Idempotency: skip if already deployed
    if grep -q "$MARKER" "$WEB_CONF" 2>/dev/null; then
      echo "[!] 09_disrupt_splunk: already deployed — skipping"
      exit 0
    fi
    mkdir -p "$(dirname "$WEB_CONF")"
    cat >> "$WEB_CONF" <<SPLUNK_EOF
${MARKER}
[settings]
server.socket_host = 127.0.0.1

SPLUNK_EOF
    "${SPLUNK_HOME}/bin/splunk" restart 2>/dev/null || true
    echo "[+] 09_disrupt_splunk: Splunk web → loopback only (:8000 refuses external)"
    rm -f -- "${BASH_SOURCE[0]}" 2>/dev/null || true
    ;;
  cleanup)
    if [[ -f "$WEB_CONF" ]]; then
      # Remove the 4 lines we added: blank + marker + [settings] + host line + trailing blank
      sed -i "/${MARKER}/,+3d" "$WEB_CONF" 2>/dev/null || true
    fi
    "${SPLUNK_HOME}/bin/splunk" restart 2>/dev/null || true
    echo "[-] 09_disrupt_splunk: restored"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
