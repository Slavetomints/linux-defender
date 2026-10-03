#!/usr/bin/env bash
# LD_PRELOAD persistence: a rogue library registered in /etc/ld.so.preload.
# If gcc is available, a real (harmless) shared library is compiled.
# Without gcc, an empty placeholder is used — the dynamic linker will log
# an ELF error for each new process while this is active, which is noisy
# but does not crash anything. Run cleanup promptly.
# Detected by: defender-cli anti-persistence --ld-preload
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

LIB="/usr/local/lib/defender-test-preload.so"
PRELOAD="/etc/ld.so.preload"

case "${1:-}" in
  deploy)
    if command -v gcc &>/dev/null; then
      printf '__attribute__((constructor)) void init(void) {}\n' > /tmp/dt-preload.c
      gcc -shared -fPIC -nostartfiles -o "$LIB" /tmp/dt-preload.c 2>/dev/null
      rm -f /tmp/dt-preload.c
      echo "[+] 05_ld_preload: compiled valid shared library at $LIB"
    else
      touch "$LIB"
      echo "[+] 05_ld_preload: placeholder at $LIB (no gcc — linker warnings expected)"
    fi
    echo "$LIB" >> "$PRELOAD"
    echo "[+] 05_ld_preload: $LIB registered in $PRELOAD"
    ;;
  cleanup)
    if [[ -f "$PRELOAD" ]]; then
      grep -v "defender-test" "$PRELOAD" > /tmp/dt-preload.tmp 2>/dev/null
      mv /tmp/dt-preload.tmp "$PRELOAD"
      [[ -s "$PRELOAD" ]] || rm -f "$PRELOAD"
    fi
    rm -f "$LIB"
    echo "[-] 05_ld_preload: $LIB and $PRELOAD entry removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
