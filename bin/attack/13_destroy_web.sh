#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

case "${1:-}" in
  deploy)
    echo "[*] 13_destroy_web: nuking web stack..."

    # Stop everything first so package removal doesn't complain
    for svc in httpd apache2 nginx php-fpm; do
        systemctl stop    "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
    done

    # Wipe web content — strip immutable bits first (06_immutable_sweep may have locked files here)
    chattr -Ri /var/www 2>/dev/null || true
    rm -rf /var/www 2>/dev/null || true
    echo "[+]   /var/www deleted"

    # Uninstall packages — distro-aware
    if command -v dnf &>/dev/null; then
        dnf remove -y httpd nginx \
            'php*' 'mod_php*' mod_ssl \
            perl-CGI 2>/dev/null || true
        dnf autoremove -y 2>/dev/null || true
    elif command -v apt-get &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y \
            apache2 apache2-utils nginx nginx-common \
            'php*' 'libapache2-mod-php*' \
            2>/dev/null || true
        apt-get autoremove --purge -y 2>/dev/null || true
    fi
    echo "[+]   packages removed"

    # Purge leftover config dirs
    rm -rf /etc/httpd /etc/apache2 /etc/nginx /etc/php* \
           /var/log/httpd /var/log/apache2 /var/log/nginx \
           /run/httpd /run/apache2 /run/nginx
    echo "[+]   config and log dirs purged"

    echo "[+] 13_destroy_web: done — web stack removed"
    ;;
  cleanup)
    echo "[*] 13_destroy_web: nothing to undo — web stack must be reinstalled manually"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
