#!/usr/bin/env bash
# Deploy all persistence test artifacts, then run:
#   sudo cargo run --release -- anti-persistence --all
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "[!] Must run as root"; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Deploying persistence test artifacts..."
echo ""

failed=()
for script in "$SCRIPT_DIR"/persist/[0-9]*.sh; do
    name="$(basename "$script")"
    if bash "$script" deploy; then
        :
    else
        failed+=("$name")
    fi
    echo ""
done

if [[ ${#failed[@]} -gt 0 ]]; then
    echo "[!] Skipped/failed: ${failed[*]}"
    echo ""
fi

echo "[+] Done. Verify with:"
echo "      sudo cargo run --release -- anti-persistence --all"
echo ""
echo "[!] Clean up when finished:"
echo "      sudo ./bin/cleanup_all.sh"
