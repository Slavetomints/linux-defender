#!/usr/bin/env bash
# Debian Splunk scoring disruption: Splunk web binds to loopback only.
# Splunk daemon stays running — :8000 and :8089 refuse external connections.
# Visible to: defender-cli backups --compare-hashes (if baseline was taken)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
WEB_CONF="${SPLUNK_HOME}/etc/system/local/web.conf"
MARKER="# rt-override-loopback"

case "${1:-}" in
  deploy)
    [[ -d "$SPLUNK_HOME" ]] || { echo "[!] Splunk not found at ${SPLUNK_HOME}"; exit 1; }
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
      # Remove everything from the marker to end of section we added
      sed -i "/${MARKER}/,/^$/d" "$WEB_CONF" 2>/dev/null || true
    fi
    "${SPLUNK_HOME}/bin/splunk" restart 2>/dev/null || true
    echo "[-] 09_disrupt_splunk: restored"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
