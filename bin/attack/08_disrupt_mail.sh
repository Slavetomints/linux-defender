#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

DOVECOT_CONF="/etc/dovecot/conf.d/99-rt-override.conf"

IFACES_SAVE="/usr/local/lib/.postfix_ifaces_orig"

case "${1:-}" in
  deploy)
    # Save original inet_interfaces so cleanup can restore it exactly
    postconf -h inet_interfaces 2>/dev/null > "$IFACES_SAVE" || echo 'all' > "$IFACES_SAVE"

    # Postfix: loopback only (stops SMTP on :25/:587 externally)
    postconf -e "inet_interfaces = loopback-only"
    systemctl reload postfix 2>/dev/null || postfix reload 2>/dev/null || true

    # Dovecot: listen on loopback only (stops IMAP/POP3 externally)
    # conf.d additions require a full restart, not reload
    cat > "$DOVECOT_CONF" <<DOVE_EOF
# Override: restrict to loopback
listen = 127.0.0.1, ::1
DOVE_EOF
    chattr +i "$DOVECOT_CONF" 2>/dev/null || true
    systemctl restart dovecot 2>/dev/null || doveadm restart 2>/dev/null || true

    echo "[+] 08_disrupt_mail: postfix + dovecot → loopback only"
    echo "[+]   SMTP :25/:587 and IMAP :143/:993 and POP3 :110/:995 now refuse external connections"
    rm -f -- "${BASH_SOURCE[0]}" 2>/dev/null || true
    ;;
  cleanup)
    orig=$(cat "$IFACES_SAVE" 2>/dev/null || echo 'all')
    postconf -e "inet_interfaces = ${orig}"
    rm -f "$IFACES_SAVE"
    systemctl reload postfix 2>/dev/null || postfix reload 2>/dev/null || true

    chattr -i "$DOVECOT_CONF" 2>/dev/null || true
    rm -f "$DOVECOT_CONF" 2>/dev/null || true
    systemctl restart dovecot 2>/dev/null || doveadm restart 2>/dev/null || true

    echo "[-] 08_disrupt_mail: restored"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
