#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

HTTPD_CONFS=(
    /etc/httpd/conf/httpd.conf
    /etc/apache2/apache2.conf
    /etc/nginx/nginx.conf
    /etc/nginx/conf.d/default.conf
)

corrupt_configs() {
    local TS
    TS=$(date +%s)
    for f in "${HTTPD_CONFS[@]}"; do
        [[ -f "$f" ]] || continue
        cp "$f" "${f}.orig"   # abort if backup fails — never corrupt without a backup
        # Inject a syntax error at the top so the daemon refuses to start
        sed -i "1s/^/X_SYNTAX_ERROR_${TS}\n/" "$f"
        echo "[+]   corrupted $f"
    done
}

restore_configs() {
    for f in "${HTTPD_CONFS[@]}"; do
        [[ -f "${f}.orig" ]] || continue
        mv "${f}.orig" "$f"
        echo "[+]   restored $f"
    done
}

case "${1:-}" in
  deploy)
    echo "[*] 07_disrupt_web: corrupting configs and masking service..."
    corrupt_configs
    for svc in httpd nginx apache2; do
        systemctl cat "${svc}.service" &>/dev/null || continue
        systemctl stop    "$svc" 2>/dev/null || true
        systemctl mask    "$svc" 2>/dev/null || true
        echo "[+]   stopped and masked $svc"
    done
    echo "[+] 07_disrupt_web: done"
    ;;
  cleanup)
    echo "[*] 07_disrupt_web: unmasking and restoring configs..."
    restore_configs
    for svc in httpd nginx apache2; do
        systemctl cat "${svc}.service" &>/dev/null || continue
        systemctl unmask  "$svc" 2>/dev/null || true
        systemctl enable  "$svc" 2>/dev/null || true
        systemctl start   "$svc" 2>/dev/null || true
        echo "[+]   unmasked and started $svc"
    done
    echo "[+] 07_disrupt_web: cleaned up"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
