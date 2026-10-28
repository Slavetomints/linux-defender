#!/usr/bin/env bash
# Master persistence deployment script for defender-cli testing.
#
# Prompts for attacker IP/port, then deploys every available persistence
# fixture so the full anti-persistence sweep can be verified.
#
# Usage:
#   sudo ./bin/deploy_persistence.sh            # interactive prompts
#   sudo ATTACKER_IP=1.2.3.4 ./bin/deploy_persistence.sh  # skip IP prompt
#
# Cleanup:
#   sudo ./bin/cleanup_all.sh
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "[!] Must run as root"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERSIST_DIR="$SCRIPT_DIR/persist"

# ── Banner ──────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║          defender-cli persistence test fixture deployer          ║"
echo "║                                                                  ║"
echo "║  Deploys attacker-style artifacts for testing the scanner.       ║"
echo "║  Run cleanup_all.sh when done.  DO NOT run on a production box.  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# ── Gather config ────────────────────────────────────────────────────────────
if [[ -z "${ATTACKER_IP:-}" ]]; then
    read -rp "Attacker/C2 IP address   [10.0.0.1]: " ATTACKER_IP
    ATTACKER_IP="${ATTACKER_IP:-10.0.0.1}"
fi

if [[ -z "${ATTACKER_PORT:-}" ]]; then
    read -rp "Attacker/C2 port         [4444]:     " ATTACKER_PORT
    ATTACKER_PORT="${ATTACKER_PORT:-4444}"
fi

# Which fixture categories to deploy
echo ""
echo "Select which persistence categories to deploy:"
echo "  a) All (recommended for full sweep test)"
echo "  s) Select individually"
read -rp "Choice [a]: " CHOICE
CHOICE="${CHOICE:-a}"

# Build list of scripts to run
if [[ "$CHOICE" == "s" ]]; then
    declare -A ENABLED
    while IFS= read -r script; do
        name="$(basename "$script")"
        read -rp "  Deploy $name? [y/N]: " yn
        [[ "${yn,,}" == "y" ]] && ENABLED["$script"]=1
    done < <(ls "$PERSIST_DIR"/[0-9]*.sh | sort)
    SCRIPTS=()
    for s in $(ls "$PERSIST_DIR"/[0-9]*.sh | sort); do
        [[ -n "${ENABLED[$s]:-}" ]] && SCRIPTS+=("$s")
    done
else
    mapfile -t SCRIPTS < <(ls "$PERSIST_DIR"/[0-9]*.sh | sort)
fi

echo ""
echo "Configuration:"
echo "  Attacker IP   : $ATTACKER_IP"
echo "  Attacker port : $ATTACKER_PORT"
echo "  Scripts       : ${#SCRIPTS[@]}"
echo ""
read -rp "Proceed? [y/N]: " CONFIRM
[[ "${CONFIRM,,}" == "y" ]] || { echo "Aborted."; exit 0; }
echo ""

# Export for sub-scripts to pick up
export ATTACKER_IP ATTACKER_PORT

# ── Deploy ───────────────────────────────────────────────────────────────────
failed=()
deployed=()

for script in "${SCRIPTS[@]}"; do
    name="$(basename "$script")"
    echo "── $name ──"
    if bash "$script" deploy; then
        deployed+=("$name")
    else
        failed+=("$name")
        echo "    [!] $name skipped or failed"
    fi
    echo ""
done

# ── Summary ──────────────────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════════"
echo "  Deployed : ${#deployed[@]} artifact(s)"
[[ ${#failed[@]} -gt 0 ]] && echo "  Skipped  : ${failed[*]}"
echo ""
echo "  Verify with:"
echo "    sudo cargo run --release -- anti-persistence --all"
echo ""
echo "  Or run the full scanner UI:"
echo "    sudo cargo run --release"
echo ""
echo "  Cleanup when done:"
echo "    sudo ./bin/cleanup_all.sh"
echo "═══════════════════════════════════════════════════════════════════"
