#!/usr/bin/env bash
# Ubuntu Mail scoring disruption: postfix + dovecot bind to loopback only.
# Both daemons stay running and healthy — external connections refused.
# Visible to: defender-cli backups --compare-hashes (if baseline was taken)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

DOVECOT_CONF="/etc/dovecot/conf.d/99-rt-override.conf"

case "${1:-}" in
  deploy)
    # Postfix: loopback only (stops SMTP on :25/:587 externally)
    postconf -e "inet_interfaces = loopback-only"
    systemctl reload postfix 2>/dev/null || postfix reload 2>/dev/null || true

    # Dovecot: listen on loopback only (stops IMAP/POP3 externally)
    cat > "$DOVECOT_CONF" <<DOVE_EOF
# Override: restrict to loopback
listen = 127.0.0.1, ::1
DOVE_EOF
    chattr +i "$DOVECOT_CONF" 2>/dev/null || true
    systemctl reload dovecot 2>/dev/null || doveadm reload 2>/dev/null || true

    echo "[+] 08_disrupt_mail: postfix + dovecot → loopback only"
    echo "[+]   SMTP :25/:587 and IMAP :143/:993 and POP3 :110/:995 now refuse external connections"
    ;;
  cleanup)
    postconf -e "inet_interfaces = all"
    systemctl reload postfix 2>/dev/null || postfix reload 2>/dev/null || true

    chattr -i "$DOVECOT_CONF" 2>/dev/null || true
    rm -f "$DOVECOT_CONF"
    systemctl reload dovecot 2>/dev/null || doveadm reload 2>/dev/null || true

    echo "[-] 08_disrupt_mail: restored"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
