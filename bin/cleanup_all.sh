#!/usr/bin/env bash
# Remove all persistence test artifacts deployed by deploy_all.sh.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "[!] Must run as root"; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Removing persistence test artifacts..."
echo ""

for script in "$SCRIPT_DIR"/persist/[0-9]*.sh; do
    name="$(basename "$script")"
    bash "$script" cleanup 2>/dev/null || echo "    (already clean)"
    echo ""
done

echo "[+] All artifacts removed."
