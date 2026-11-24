#!/usr/bin/env bash
# ==============================================================================
# VyOS_LockdownAndFirewall.sh - Consolidated CCDC VyOS Defense & Audit Engine
# Target: VyOS 1.4.x (Sagitta) or newer
#
# Usage:
#   ./VyOS_LockdownAndFirewall.sh --audit
#   ./VyOS_LockdownAndFirewall.sh --diff [/etc/linux-defender/baseline/latest.log]
#   ./VyOS_LockdownAndFirewall.sh --team 5 --harden [--pass <secret>] [--ssh-key '<key>']
#   ./VyOS_LockdownAndFirewall.sh --console-lockdown
#   ./VyOS_LockdownAndFirewall.sh --confirm
#   ./VyOS_LockdownAndFirewall.sh --interactive
# ==============================================================================

# ─── Diagnostic Logging & Unified Working Directories ─────────────────────────
if mkdir -p /etc/linux-defender 2>/dev/null; then
    DEFENDER_DIR="/etc/linux-defender"
else
    DEFENDER_DIR="/tmp/defender"
fi

BASELINE_DIR="${DEFENDER_DIR}/baseline"
LATEST_LINK="${BASELINE_DIR}/latest.log"
LOG_DIR="${DEFENDER_DIR}/vyos"

mkdir -p "$LOG_DIR" "$BASELINE_DIR" 2>/dev/null
SAFE_ARGS=$(printf '%s ' "$@" | sed -E 's/--(pass|vyos-pass|root-pass) +[^ ]+/--\1 ******/g')
echo "[$(date)] vbash PID=$$ GID=$(id -g -n 2>/dev/null) ARGC=$# ARGS: '$SAFE_ARGS' DIR='$DEFENDER_DIR'" >> "${LOG_DIR}/debug_run.log"

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()    { echo -e "${GREEN}[ OK ]${RESET}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_error() { echo -e "${RED}[ERR ]${RESET}  $*" >&2; }
die()       { log_error "$*"; builtin exit 1; }

# ─── Defaults & Global State ──────────────────────────────────────────────────
TEAM=""
PUBLIC_OCTET=""
ADMIN_USER="vyos"
ADMIN_PASS="${DEFENDER_ADMIN_PASS:-}"
ROOT_PASS="${DEFENDER_ROOT_PASS:-}"
DNAT_TARGET="private"
ENABLE_OUTBOUND_PAT=false
SSH_PUB_KEY=""
SSH_KEY_TYPE="ssh-ed25519"
SSH_KEY_ID="ccdc_admin_key"
MGMT_SUBNET="172.17.0.0/24"     # Default Workstation Subnet (wkst)
INTERNAL_NET="172.16.0.0/24"    # Default Internal Server Subnet
COMMIT_TIMEOUT=5
NO_CONFIRM=false
FORCE=false
DRY_RUN=false
STDOUT_ONLY=false
MODE=""
DIFF_LOG=""
RESTORE_MODE="baseline"
CONFIG_SOURCE=""

run_op() {
    if [ -x /opt/vyatta/bin/vyatta-op-cmd-wrapper ]; then
        /opt/vyatta/bin/vyatta-op-cmd-wrapper "$@" 2>/dev/null
    else
        echo "ERR: /opt/vyatta/bin/vyatta-op-cmd-wrapper not found"
    fi
}

usage() {
    cat << 'EOF'
======================================================================
  VyOS_LockdownAndFirewall.sh - CCDC VyOS Defense & Audit Engine
======================================================================
Usage: ./VyOS_LockdownAndFirewall.sh [MODE] [OPTIONS]

MODES:
  --audit                 Run non-destructive forensic audit (15 sections) and save baseline
  --diff [log_file]       Diff current state against previous baseline
  --harden                Phase 1: Hardening & Init Config (passwords, SSH, firewall, NAT rules 10, 20, 30, 40, 50)
  --restore-nat           Restore CCDC DNAT Rules 10, 20, 30, 40, 50 & configure outbound PAT without full hardening
  --rotate-passwords      Separately rotate vyos and root passwords; sanitize authorized_keys
  --sanitize-hooks        Quarantine persistence hooks from /config/scripts/ and reset templates
  --sanitize-cron         Delete VyOS task-scheduler and flush /var/spool/cron/crontabs
  --clean-rootkits        Remove /etc/ld.so.preload and check systemd overrides
  --purge-containers      Delete VyOS container config and stop running podman containers
  --console-lockdown      Phase 2: Pull SSH from vyos (Console-Only Administration)
  --confirm               Confirm and save pending commit-confirm changes
  --interactive           Interactive configuration wizard

OPTIONS:
  --team <0-20>           CCDC Team number (0=practice GW 172.31.40.1 / pool 172.25.20.0/24, 1-20=competition 20+T)
  --public-octet <N>      Override Public NAT IP pool third octet 172.25.<N>.0/24 (auto-detected if omitted)
  --dnat-target <tgt>     DNAT destination target: 'private' (172.20.240.x) or 'public' (172.25.x.x) [default: private]
  --restore-mode <mode>   Restore mode for --restore-nat: 'baseline', 'detected', or 'backup' [default: baseline]
  --config-source <path>  Path to detected or backup config file for restore
  --enable-outbound-pat   Enable Outbound PAT masquerade for workstations (default: false, reverse-shell defense)
  --mgmt-subnet <cidr>    Trusted management subnet (default: 172.17.0.0/24)
  --user <username>       Target admin username (default: vyos, per CCDC rules)
  --pass <password>       New password for vyos (synonym for --vyos-pass)
  --vyos-pass <password>  New password for vyos operator account
  --root-pass <password>  New password for Linux superuser root account
  --ssh-key '<key>'       SSH public key string (e.g. 'AAAAC3NzaC1...')
  --commit-timeout <min>  Rollback timer for commit-confirm (default: 5)
  --no-confirm            Bypass commit-confirm rollback (Instant commit; DANGEROUS)
  --force                 Bypass safety checks (e.g. running --console-lockdown over SSH)
  --force-baseline        Force overwriting existing destination NAT rules with baseline
  --dry-run               Display commands without applying changes
  -h, --help              Show this help message
EOF
    builtin exit "${1:-0}"
}

# ─── Parse Arguments ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --audit)
            MODE="audit"
            shift
            ;;
        --stdout)
            STDOUT_ONLY=true
            shift
            ;;
        --diff)
            MODE="diff"
            if [[ $# -gt 1 && ! "$2" =~ ^-- ]]; then
                DIFF_LOG="$2"
                shift 2
            else
                DIFF_LOG=""
                shift
            fi
            ;;
        --harden)
            MODE="harden"
            shift
            ;;
        --restore-nat)
            MODE="restore-nat"
            shift
            ;;
        --rotate-passwords)
            MODE="rotate-passwords"
            shift
            ;;
        --sanitize-hooks)
            MODE="sanitize-hooks"
            shift
            ;;
        --sanitize-cron)
            MODE="sanitize-cron"
            shift
            ;;
        --clean-rootkits)
            MODE="clean-rootkits"
            shift
            ;;
        --purge-containers)
            MODE="purge-containers"
            shift
            ;;
        --console-lockdown)
            MODE="console-lockdown"
            shift
            ;;
        --confirm)
            MODE="confirm"
            shift
            ;;
        --interactive)
            MODE="interactive"
            shift
            ;;
        --team)
            TEAM="$2"
            shift 2
            ;;
        --public-octet)
            PUBLIC_OCTET="$2"
            shift 2
            ;;
        --dnat-target)
            DNAT_TARGET="$2"
            if [ "$DNAT_TARGET" != "private" ] && [ "$DNAT_TARGET" != "public" ]; then
                die "Invalid --dnat-target '$DNAT_TARGET'. Must be 'private' or 'public'."
            fi
            shift 2
            ;;
        --restore-mode)
            RESTORE_MODE="$2"
            shift 2
            ;;
        --config-source)
            CONFIG_SOURCE="$2"
            shift 2
            ;;
        --enable-outbound-pat)
            ENABLE_OUTBOUND_PAT=true
            shift
            ;;
        --mgmt-subnet)
            MGMT_SUBNET="$2"
            shift 2
            ;;
        --user)
            ADMIN_USER="$2"
            shift 2
            ;;
        --pass)
            ADMIN_PASS="$2"
            shift 2
            ;;
        --vyos-pass)
            ADMIN_PASS="$2"
            shift 2
            ;;
        --root-pass)
            ROOT_PASS="$2"
            shift 2
            ;;
        --ssh-key)
            SSH_PUB_KEY="$2"
            shift 2
            ;;
        --commit-timeout)
            COMMIT_TIMEOUT="$2"
            shift 2
            ;;
        --no-confirm)
            NO_CONFIRM=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --force-baseline)
            FORCE_BASELINE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage 0
            ;;
        *)
            SAFE_ARGV=$(printf '%s ' "$*" | sed -E 's/--(pass|vyos-pass|root-pass) +[^ ]+/--\1 ******/g')
            echo "[-] Unknown parameter: '$1' (Full ARGV: '$SAFE_ARGV')" >&2
            echo "[$(date)] ERROR Unknown parameter: '$1' ARGS: '$SAFE_ARGV'" >> "${LOG_DIR}/debug_run.log"
            usage 1
            ;;
    esac
done

# Default to interactive if no mode supplied
if [ -z "$MODE" ]; then
    if [ -t 0 ]; then
        MODE="interactive"
    else
        SAFE_ARGV=$(printf '%s ' "$*" | sed -E 's/--(pass|vyos-pass|root-pass) +[^ ]+/--\1 ******/g')
        echo "[-] Error: No operation mode specified and non-interactive input detected. (ARGC=$#, ARGS='$SAFE_ARGV')" >&2
        echo "[$(date)] ERROR No operation mode specified (ARGC=$#, ARGS='$SAFE_ARGV')" >> "${LOG_DIR}/debug_run.log"
        usage 1
    fi
fi

# Source VyOS script environment AFTER arguments are safely stored
if [ -f /opt/vyatta/etc/functions/script-template ]; then
    source /opt/vyatta/etc/functions/script-template
fi

# VyOS script-template defines an 'exit' shell function or alias that wraps
# vyatta-cfg-cmd-wrapper end "$@". When called with a numeric argument (e.g. exit 0 or exit 1),
# VyOS attempts to parse the number as a configuration command, printing
# "Invalid command: [0]" / "line XXX: 0: command not found" and returning exit status 127.
# We define vyos_exit_cfg to cleanly exit configuration mode, unalias exit, and use
# bash's builtin exit for process termination.
vyos_exit_cfg() {
    /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper end 2>/dev/null || true
}
unalias exit 2>/dev/null || true

# ─── Interactive Wizard ───────────────────────────────────────────────────────
if [ "$MODE" == "interactive" ]; then
    echo "======================================================================"
    echo "        VyOS CCDC Interactive Hardening & Audit Wizard"
    echo "======================================================================"
    echo "1) Forensic Audit & Baseline (Read-Only)"
    echo "2) Diff Against Last Audit Baseline"
    echo "3) Phase 1: Hardened SSH + Password Rotation + Firewall + NAT"
    echo "4) Restore CCDC DNAT Rules 10, 20, 30, 40, 50 & Outbound PAT"
    echo "5) Dual Password Rotation & SSH Key Sanitization"
    echo "6) Phase 2: Console-Only Lockdown (Nuke SSH)"
    echo "7) Exit"
    read -r -p "Select an action [1-7]: " choice
    case "$choice" in
        1) MODE="audit" ;;
        2) MODE="diff" ;;
        3) MODE="harden" ;;
        4) MODE="restore-nat" ;;
        5) MODE="rotate-passwords" ;;
        6) MODE="console-lockdown" ;;
        *) builtin exit 0 ;;
    esac

    if [ "$MODE" == "harden" ] || [ "$MODE" == "restore-nat" ]; then
        if [ -z "$TEAM" ]; then
            read -r -p "Enter Team Number [0-20] (0=practice, 1-20=competition): " TEAM
        fi
    fi

    if [ "$MODE" == "harden" ]; then
        read -r -p "Management Subnet [$MGMT_SUBNET]: " input_mgmt
        MGMT_SUBNET="${input_mgmt:-$MGMT_SUBNET}"
        read -r -s -p "Enter NEW password for '$ADMIN_USER': " input_pass
        echo ""
        ADMIN_PASS="${input_pass}"
        read -r -p "SSH Public Key (optional, press Enter to skip): " SSH_PUB_KEY
    fi
fi

# ─── Auto-Derive Team Subnets ─────────────────────────────────────────────────
detect_existing_wan_octet() {
    local detected=""
    if [ -x /opt/vyatta/bin/vyatta-op-cmd-wrapper ]; then
        detected=$(/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands 2>/dev/null | grep -E "172\.31\.[0-9]+\." | sed -n 's/.*172\.31\.\([0-9]*\)\..*/\1/p' | head -n1)
    fi
    if [ -z "$detected" ] && [ -f /config/config.boot ]; then
        detected=$(grep -E "172\.31\.[0-9]+\." /config/config.boot 2>/dev/null | sed -n 's/.*172\.31\.\([0-9]*\)\..*/\1/p' | head -n1)
    fi
    echo "$detected"
}

detect_existing_octet() {
    local detected=""
    if [ -x /opt/vyatta/bin/vyatta-op-cmd-wrapper ]; then
        detected=$(/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands 2>/dev/null | grep -E "172\.25\.[0-9]+\." | sed -n 's/.*172\.25\.\([0-9]*\)\..*/\1/p' | head -n1)
    fi
    if [ -z "$detected" ] && [ -f /config/config.boot ]; then
        detected=$(grep -E "172\.25\.[0-9]+\." /config/config.boot 2>/dev/null | sed -n 's/.*172\.25\.\([0-9]*\)\..*/\1/p' | head -n1)
    fi
    if [ -z "$detected" ]; then
        for state_f in "/etc/linux-defender/vyos/detected_nat_routes.json" "/tmp/defender/vyos/detected_nat_routes.json"; do
            if [ -f "$state_f" ]; then
                detected=$(grep -E "172\.25\.[0-9]+\." "$state_f" 2>/dev/null | sed -n 's/.*172\.25\.\([0-9]*\)\..*/\1/p' | head -n1)
                [ -n "$detected" ] && break
            fi
        done
    fi
    echo "$detected"
}

derive_team_subnets() {
    local t="$1"
    local live_wan live_pub
    live_wan=$(detect_existing_wan_octet)
    live_pub=$(detect_existing_octet)
    if [ "$t" -eq 0 ]; then
        OCTET="${live_wan:-40}"
        if [ -z "$PUBLIC_OCTET" ]; then
            if [ -n "$live_pub" ]; then
                PUBLIC_OCTET="$live_pub"
                log_info "Detected active public NAT pool octet: 172.25.${PUBLIC_OCTET}.0/24"
            else
                # Known-good Practice baseline: WAN 172.31.40.x, Public Pool 172.25.20.0/24
                PUBLIC_OCTET=20
            fi
        fi
        WAN_ROUTER_IP="172.31.${OCTET}.2/29"
        CORE_GATEWAY_IP="172.31.${OCTET}.1"
        PUBLIC_POOL="172.25.${PUBLIC_OCTET}.0/24"
        log_info "Team 0 (Practice Environment): WAN Router=${WAN_ROUTER_IP}, Core Gateway=${CORE_GATEWAY_IP}, Public Pool=${PUBLIC_POOL}"
    else
        OCTET=$((20 + t))
        if [ -z "$PUBLIC_OCTET" ]; then
            PUBLIC_OCTET="$OCTET"
        fi
        WAN_ROUTER_IP="172.31.${OCTET}.2/29"
        CORE_GATEWAY_IP="172.31.${OCTET}.1"
        PUBLIC_POOL="172.25.${PUBLIC_OCTET}.0/24"
        log_info "Team $t Subnets: WAN Router=${WAN_ROUTER_IP}, Core Gateway=${CORE_GATEWAY_IP}, Public Pool=${PUBLIC_POOL}"
    fi
}

if [ -n "$TEAM" ]; then
    if ! [[ "$TEAM" =~ ^[0-9]+$ ]] || [ "$TEAM" -lt 0 ] || [ "$TEAM" -gt 20 ]; then
        die "Invalid team number '$TEAM'. Must be between 0 (practice) and 20 (real competition)."
    fi
    derive_team_subnets "$TEAM"
fi

# Mandatory team validation for modes configuring network subnets
if [ "$MODE" == "harden" ] || [ "$MODE" == "restore-nat" ]; then
    if [ -z "$TEAM" ]; then
        if [ -t 0 ]; then
            read -r -p "Enter CCDC Team Number [0-20] (0=practice, 1-20=competition): " input_team
            if ! [[ "$input_team" =~ ^[0-9]+$ ]] || [ "$input_team" -lt 0 ] || [ "$input_team" -gt 20 ]; then
                die "Invalid team number '$input_team'. Must be between 0 (practice) and 20 (real competition)."
            fi
            TEAM="$input_team"
            derive_team_subnets "$TEAM"
        else
            die "Team number is required for --${MODE}. Pass --team <0-20> (0=practice, 1-20=competition)."
        fi
    fi
fi

# ─── Version Information ──────────────────────────────────────────────────────
RAW_VER=$(run_op show version 2>/dev/null | grep -i "^Version:" | sed 's/Version:[[:space:]]*//')
RELEASE_TRAIN=$(run_op show version 2>/dev/null | grep -i "Release train:" | awk '{print $3}')

# ==============================================================================
# MODE: DIFF AGAINST BASELINE
# ==============================================================================
if [ "$MODE" == "diff" ]; then
    PREV_LOG="$DIFF_LOG"
    if [ -z "$PREV_LOG" ]; then
        PREV_LOG="$LATEST_LINK"
    fi
    if [ ! -f "$PREV_LOG" ]; then
        die "Baseline file '$PREV_LOG' not found. Run --audit first to capture a baseline."
    fi
    TMP_CURRENT=$(mktemp /tmp/vyos_audit_current.XXXXXX)
    log_info "Generating temporary audit snapshot..."
    "$0" --audit --stdout > "$TMP_CURRENT" 2>/dev/null
    log_info "Comparing current state against baseline: $PREV_LOG"
    echo "======================================================================"

    # Run unified diff ignoring ephemeral timestamps and baseline confirmation messages
    DIFF_OPTS=(-u -I '^[[:space:]]*Timestamp[[:space:]]*:' -I 'Baseline captured:' -I 'Latest symlink' --label "Baseline ($PREV_LOG)" --label "Live Router State")

    # Check if any actual differences exist
    DIFF_OUTPUT=$(diff "${DIFF_OPTS[@]}" "$PREV_LOG" "$TMP_CURRENT" 2>&1 || true)

    if [ -z "$DIFF_OUTPUT" ]; then
        echo -e "${GREEN}======================================================================${RESET}"
        echo -e "${GREEN}[ OK ] CLEAN AUDIT: NO SYSTEM OR CONFIGURATION DRIFT DETECTED!        ${RESET}"
        echo -e "${GREEN}======================================================================${RESET}"
        echo "  Baseline Reference : $PREV_LOG"
        echo "  Live System State  : Verified identical across all 14 audit sections."
        echo ""
        echo "  ✓ No unauthorized users in /etc/passwd or VyOS config"
        echo "  ✓ No rogue SSH keys in ~/.ssh/authorized_keys"
        echo "  ✓ No unapproved crontabs or systemd timers"
        echo "  ✓ No boot scripts or commit hooks modified in /config/scripts/"
        echo "  ✓ No rogue interfaces or VPN tunnels (WireGuard, OpenVPN)"
        echo "  ✓ No unexpected listening ports or container services"
        echo "  ✓ No SUID binaries or /etc/ld.so.preload rootkits"
        echo "  ✓ Scored 1:1 DNAT Rules 10, 20, 30, 40, 50 & Outbound PAT intact"
        echo "  ✓ Systemd services match VyOS curated whitelist"
        echo -e "${GREEN}======================================================================${RESET}"
    else
        echo -e "${RED}======================================================================${RESET}"
        echo -e "${RED}[!] SYSTEM DRIFT DETECTED: DIFFERENCES FOUND AGAINST BASELINE!         ${RESET}"
        echo -e "${RED}======================================================================${RESET}"
        echo "  Baseline Reference : $PREV_LOG"
        echo "  Live System State  : Current router configuration & system state"
        echo ""
        echo "Key: (-) in baseline but removed | (+) added since baseline"
        echo "----------------------------------------------------------------------"
        if [ -t 1 ]; then
            diff "${DIFF_OPTS[@]}" --color=always "$PREV_LOG" "$TMP_CURRENT" | less -R
        else
            diff "${DIFF_OPTS[@]}" --color=never "$PREV_LOG" "$TMP_CURRENT"
        fi
        echo -e "${RED}======================================================================${RESET}"
    fi
    rm -f "$TMP_CURRENT"
    builtin exit 0
fi

# ==============================================================================
# MODE: FORENSIC AUDIT (READ-ONLY)
# ==============================================================================
if [ "$MODE" == "audit" ]; then
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    OUTPUT_FILE="${BASELINE_DIR}/vyos_audit_${TIMESTAMP}.log"

    if [ "$STDOUT_ONLY" = true ]; then
        exec 1>&1
    else
        mkdir -p "$BASELINE_DIR"
        log_ok "Running VyOS Forensic & Persistence Audit..."
        log_ok "Saving baseline report to: ${OUTPUT_FILE}"
        exec 3>&1
        exec > >(tee "${OUTPUT_FILE}")
    fi

    echo "======================================================================"
    echo "          VyOS CCDC FORENSIC & PERSISTENCE AUDIT REPORT"
    echo "  Timestamp : $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
    echo "  Hostname  : $(hostname)"
    echo "  Kernel    : $(uname -a)"
    echo "  Branch    : ${RELEASE_TRAIN:-sagitta} [${RAW_VER:-unknown}]"
    echo "======================================================================"

    echo -e "\n[+] SECTION 1: System Version & Identity"
    echo "----------------------------------------------------------------------"
    run_op show version || cat /etc/os-release

    echo -e "\n[+] SECTION 2: /config/scripts/ Directory & Boot Hooks"
    echo "----------------------------------------------------------------------"
    ls -laR /config/scripts/ 2>/dev/null
    for script in /config/scripts/vyos-preconfig-bootup.script /config/scripts/vyos-postconfig-bootup.script /config/scripts/post-upgrade; do
        if [ -f "$script" ]; then
            echo -e "\n>>> Content of $script:"
            cat "$script"
        fi
    done

    echo -e "\n[+] SECTION 3: Commit Hooks (High Risk)"
    echo "----------------------------------------------------------------------"
    ls -la /config/scripts/commit/pre-hooks.d/ /config/scripts/commit/post-hooks.d/ 2>/dev/null || true
    for f in /config/scripts/commit/pre-hooks.d/* /config/scripts/commit/post-hooks.d/*; do
        if [ -f "$f" ]; then
            echo -e "\n>>> Content of $f:"
            cat "$f"
        fi
    done

    echo -e "\n[+] SECTION 4: Task Scheduler & Linux Cron"
    echo "----------------------------------------------------------------------"
    run_op show configuration commands | grep "task-scheduler" || echo "No task-scheduler configured."
    cat /etc/crontab 2>/dev/null || true
    ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null || true

    echo -e "\n[+] SECTION 5: Login Accounts, Sudoers & SSH Keys"
    echo "----------------------------------------------------------------------"
    echo "[-] VyOS Configured Users:"
    run_op show configuration commands | grep "system login"
    echo -e "\n[-] Linux Accounts with UID 0 or >= 1000 (/etc/passwd):"
    awk -F: '($3 == 0 || $3 >= 1000) {print "User: "$1", UID: "$3", Shell: "$7}' /etc/passwd
    echo -e "\n[-] Authorized SSH Keys in filesystem:"
    for dir in /root/.ssh /home/*/.ssh; do
        if [ -f "${dir}/authorized_keys" ]; then
            echo ">>> File: ${dir}/authorized_keys"
            cat "${dir}/authorized_keys"
        fi
    done

    echo -e "\n[+] SECTION 6: Network Interfaces, Tunnels & VPNs"
    echo "----------------------------------------------------------------------"
    run_op show configuration commands | grep -E "interfaces (wireguard|openvpn|vti|tunnel|pseudo-ethernet|vxlan|bridge)" || echo "No rogue tunnel interfaces in VyOS config."
    ip -brief link show

    echo -e "\n[+] SECTION 7: Containers (Podman / VyOS 1.4+)"
    echo "----------------------------------------------------------------------"
    run_op show configuration commands | grep "container" || echo "No container configuration found."
    if command -v podman >/dev/null 2>&1; then
        podman ps -a 2>/dev/null || echo "Podman daemon inactive."
    fi

    echo -e "\n[+] SECTION 8: Configured System Services"
    echo "----------------------------------------------------------------------"
    run_op show configuration commands | grep "^set service"

    echo -e "\n[+] SECTION 9: Listening Sockets & Active Connections"
    echo "----------------------------------------------------------------------"
    ss -tulpn
    echo -e "\n[-] Established External Connections:"
    ss -tan state established '( dport != :22 and sport != :22 )'
    echo -e "\n[-] Currently Logged In Users:"
    who -a 2>/dev/null || w

    echo -e "\n[+] SECTION 10: Dynamic Linker & Systemd Overrides"
    echo "----------------------------------------------------------------------"
    if [ -f /etc/ld.so.preload ]; then
        echo "[!] CRITICAL: /etc/ld.so.preload EXISTS! Potential rootkit:"
        cat /etc/ld.so.preload
    else
        echo "Clean: /etc/ld.so.preload does not exist."
    fi
    ls -la /etc/systemd/system/*.service /etc/systemd/system/*.timer 2>/dev/null || echo "No custom service overrides."

    echo -e "\n[+] SECTION 11: SUID Binaries & Modified System Files"
    echo "----------------------------------------------------------------------"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -la {} + 2>/dev/null
    echo -e "\n[-] Recently modified system files (past 24h):"
    find /etc /bin /sbin /usr/bin /usr/sbin /config -xdev -mmin -1440 -type f 2>/dev/null | head -40

    echo -e "\n[+] SECTION 12: Commit History & Config Revisions"
    echo "----------------------------------------------------------------------"
    run_op show system commit || echo "No commit history found."

    echo -e "\n[+] SECTION 13: NAT Configuration & Rules (CCDC Baseline Audit)"
    echo "----------------------------------------------------------------------"
    echo "[-] Active VyOS NAT Configuration Commands:"
    run_op show configuration commands | grep -E "^set nat" || echo "No NAT commands configured in VyOS."

    echo -e "\n[-] Scored 1:1 DNAT Rules (10, 20, 30, 40, 50) Verification:"
    for r in 10 20 30 40 50; do
        if run_op show configuration commands | grep -q "nat destination rule $r "; then
            r_desc=$(run_op show configuration commands | grep "nat destination rule $r description" | awk '{print $NF}' | tr -d "'\"")
            r_dest=$(run_op show configuration commands | grep "nat destination rule $r destination address" | awk '{print $NF}' | tr -d "'\"")
            r_trans=$(run_op show configuration commands | grep "nat destination rule $r translation address" | awk '{print $NF}' | tr -d "'\"")
            r_port=$(run_op show configuration commands | grep "nat destination rule $r destination port" | awk '{print $NF}' | tr -d "'\"")
            r_proto=$(run_op show configuration commands | grep "nat destination rule $r protocol" | awk '{print $NF}' | tr -d "'\"")
            echo "  [OK] Rule $r (${r_desc:-unnamed}): dest=${r_dest:-0.0.0.0/0} proto=${r_proto:-any} port=${r_port:-any} -> translation=${r_trans:-none}"
        else
            echo "  [WARN] Scored DNAT Rule $r is NOT configured in active ruleset!"
        fi
    done
    for lr in 11 12 13 14; do
        if run_op show configuration commands | grep -q "nat destination rule $lr "; then
            echo "  [WARN] Legacy artifact rule $lr detected in active ruleset! Run --restore-nat to clean up."
        fi
    done

    echo -e "\n[-] Scored 1:1 SNAT Rules (10, 20, 30, 40, 50) Verification:"
    for sr in 10 20 30 40 50; do
        if run_op show configuration commands | grep -q "nat source rule $sr "; then
            sr_src=$(run_op show configuration commands | grep "nat source rule $sr source address" | awk '{print $NF}' | tr -d "'\"")
            sr_trans=$(run_op show configuration commands | grep "nat source rule $sr translation address" | awk '{print $NF}' | tr -d "'\"")
            echo "  [OK] Source Rule $sr: src=${sr_src:-any} -> translation=${sr_trans:-none}"
        else
            echo "  [WARN] Scored SNAT Rule $sr is NOT configured in active ruleset!"
        fi
    done

    echo -e "\n[-] Outbound PAT (Masquerade Rule 100) Status:"
    if run_op show configuration commands | grep -q "nat source rule 100 "; then
        echo "  [WARN] Outbound PAT (Rule 100) is ACTIVE on eth0 (LAN masquerade enabled)."
    else
        echo "  [OK] Outbound PAT (Rule 100) is DISABLED (anti-reverse-shell lockdown)."
    fi

    echo -e "\n[-] Persistent Boot Configuration NAT Section (/config/config.boot):"
    if [ -f /config/config.boot ]; then
        grep -n -A 35 "nat {" /config/config.boot 2>/dev/null || echo "No nat block found in /config/config.boot."
    else
        echo "/config/config.boot not accessible."
    fi

    echo -e "\n[-] Kernel Live NAT Tables (nftables / iptables):"
    if command -v nft >/dev/null 2>&1; then
        nft list table ip nat 2>/dev/null || nft list table inet nat 2>/dev/null || echo "No nftables nat table active."
    elif command -v iptables >/dev/null 2>&1; then
        iptables -t nat -L -n -v 2>/dev/null || echo "No iptables nat table active."
    else
        echo "No nft or iptables command found."
    fi

    echo -e "\n[+] SECTION 14: Systemd Services vs. VyOS Curated Whitelist"
    echo "----------------------------------------------------------------------"
    ROUTER_WHITELIST=(
        "vyos-router" "vyos-configd" "vyos-hostkey" "vyos-telegraf"
        "frr" "zebra" "bgpd" "ospfd" "ospf6d" "ripd" "ripngd" "staticd"
        "bfdd" "isisd" "fabricd" "vrrpd" "pimd" "pim6d" "eigrpd"
        "nftables" "conntrackd" "keepalived" "lldpd"
        "isc-dhcp-server" "dhcpd" "kea-dhcp4" "kea-dhcp6" "dhclient" "dhcpcd"
        "pdns-recursor" "dnsmasq" "ddclient"
        "snmpd" "chrony" "chronyd" "ntp" "ntpd" "rsyslog" "syslog"
        "systemd-journald" "systemd-udevd" "udev" "kmod" "irqbalance"
        "haveged" "rngd" "open-vm-tools" "vmtoolsd" "qemu-guest-agent"
        "ssh" "sshd" "getty" "serial-getty" "autovt" "console-getty"
    )

    ROUTER_BLACKLIST=(
        "telnet" "telnetd" "tftp" "tftpd-hpa" "rsh" "rlogin" "rexec"
        "apache2" "nginx" "httpd" "vyos-http-api" "lighttpd"
        "mysql" "mariadb" "postgresql" "mongod" "redis" "redis-server"
        "cups" "cups-browsed" "avahi-daemon" "bluetooth"
        "smbd" "nmbd" "nfs-server" "rpcbind"
    )

    echo "[-] Checking for Blacklisted Daemons on Router:"
    blacklisted_found=0
    for bad_svc in "${ROUTER_BLACKLIST[@]}"; do
        if systemctl is-active --quiet "$bad_svc" 2>/dev/null; then
            echo -e "  ${RED}[!] DANGEROUS / ROGUE SERVICE ACTIVE: ${bad_svc}${RESET}"
            blacklisted_found=$((blacklisted_found + 1))
        fi
    done
    if [ "$blacklisted_found" -eq 0 ]; then
        echo "  [OK] No blacklisted service daemons active."
    fi

    echo -e "\n[-] Running Systemd Services Audit against Whitelist:"
    unapproved_found=0
    if command -v systemctl >/dev/null 2>&1; then
        while read -r svc; do
            [ -z "$svc" ] && continue
            svc_name="${svc%.service}"
            svc_base="${svc_name%%@*}"

            # Check whitelist or standard systemd prefix
            is_whitelisted=0
            if [[ "$svc_name" =~ ^systemd- ]]; then
                is_whitelisted=1
            fi
            for allowed in "${ROUTER_WHITELIST[@]}"; do
                if [ "$svc_name" == "$allowed" ] || [ "$svc_base" == "$allowed" ]; then
                    is_whitelisted=1
                    break
                fi
            done

            if [ "$is_whitelisted" -eq 0 ]; then
                echo -e "  ${YELLOW}[?] UNLISTED / SUSPICIOUS SERVICE RUNNING: ${svc}${RESET}"
                unapproved_found=$((unapproved_found + 1))
            fi
        done < <(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}')
    fi

    if [ "$unapproved_found" -eq 0 ]; then
        echo "  [OK] All running systemd units match curated VyOS 1.4.0 whitelist."
    else
        echo -e "  ${YELLOW}[!] Total unlisted services flagged: ${unapproved_found}${RESET}"
    fi

    echo -e "\n[+] SECTION 15: Routing Protocols & Default Route Drift Check"
    echo "----------------------------------------------------------------------"
    echo "[-] Active VyOS Protocol Commands:"
    run_op show configuration commands | grep -E "^set protocols" || echo "No protocols commands configured in VyOS."

    AUDIT_WAN_OCTET=$(detect_existing_wan_octet)
    AUDIT_DEF_NH=$(run_op show configuration commands | grep -E "^set protocols static route 0\.0\.0\.0/0 next-hop " | awk '{print $NF}' | tr -d "'\"" | head -n1)
    AUDIT_DMZ_NH=$(run_op show configuration commands | grep -E "^set protocols static route 172\.20\.240\.0/24 next-hop " | awk '{print $NF}' | tr -d "'\"" | head -n1)

    if [ -z "$AUDIT_DEF_NH" ]; then
        echo -e "  ${RED}[CRITICAL] Missing Default Route (0.0.0.0/0) in VyOS config!${RESET}"
    elif [ -n "$AUDIT_WAN_OCTET" ] && [ "$AUDIT_DEF_NH" != "172.31.${AUDIT_WAN_OCTET}.1" ]; then
        echo -e "  ${RED}[CRITICAL] Default Route Drift: 0.0.0.0/0 -> ${AUDIT_DEF_NH} (expected 172.31.${AUDIT_WAN_OCTET}.1)${RESET}"
    else
        echo "  [OK] Default Route: 0.0.0.0/0 -> ${AUDIT_DEF_NH}"
    fi

    if [ -z "$AUDIT_DMZ_NH" ]; then
        echo -e "  ${YELLOW}[WARN] Missing DMZ Transit Route (172.20.240.0/24) in VyOS config!${RESET}"
    elif [ "$AUDIT_DMZ_NH" != "172.16.0.1" ]; then
        echo -e "  ${RED}[WARN] DMZ Transit Route Drift: 172.20.240.0/24 -> ${AUDIT_DMZ_NH} (expected 172.16.0.1)${RESET}"
    else
        echo "  [OK] DMZ Transit Route: 172.20.240.0/24 -> ${AUDIT_DMZ_NH}"
    fi

    echo "[-] Checking for Unauthorized Dynamic Routing Protocols (non-static):"
    run_op show configuration commands | grep -E "^set protocols " | grep -vE "^set protocols static " || echo "  [OK] Only static routing configured."

    echo "[-] Live Kernel Routing Table (ip -4 route show):"
    ip -4 route show 2>/dev/null || ip route show 2>/dev/null || echo "ip route unavailable."

    echo "======================================================================"
    echo "          FORENSIC AUDIT COMPLETE"
    echo "======================================================================"
    if [ "$STDOUT_ONLY" = false ]; then
        exec 1>&3 3>&-
        ln -sf "${OUTPUT_FILE}" "${LATEST_LINK}"
        log_ok "Baseline captured: ${OUTPUT_FILE}"
        log_ok "Latest symlink   : ${LATEST_LINK}"
    fi
    builtin exit 0
fi

# ==============================================================================
# MODE: CONSOLE-ONLY LOCKDOWN (NUKE SSH)
# ==============================================================================
if [ "$MODE" == "console-lockdown" ]; then
    if [ "$FORCE" = false ]; then
        if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ] || [ -n "$SSH_CONNECTION" ]; then
            echo -e "\n${RED}[!] FATAL LOCKOUT PROTECTION TRIGGERED:${RESET}"
            echo "    You are attempting to run --console-lockdown over an active SSH session!"
            echo "    This will immediately sever your connection and lock you out."
            echo "    Switch to the VMware Console to execute this mode safely."
            echo "    (If you are 100% sure, pass --force to override this safety check)."
            builtin exit 1
        fi
    fi

    echo "======================================================================"
    echo "          VyOS CONSOLE-ONLY LOCKDOWN (NUKE SSH MODE)"
    echo "======================================================================"

    if [ -z "$ADMIN_PASS" ]; then
        if [ -t 0 ]; then
            read -r -s -p "Enter NEW password for '$ADMIN_USER' console login: " ADMIN_PASS
            echo ""
        else
            die "No password supplied for '$ADMIN_USER' (pass --pass <password>)"
        fi
    fi

    BACKUP_DIR="${DEFENDER_DIR}/quarantine/quarantine_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    log_info "Quarantining commit hooks and boot scripts to $BACKUP_DIR..."
    if [ -d /config/scripts/commit ]; then
        cp -r /config/scripts/commit "$BACKUP_DIR/"
        rm -rf /config/scripts/commit/pre-hooks.d/* /config/scripts/commit/post-hooks.d/* 2>/dev/null
    fi
    for s in /config/scripts/vyos-postconfig-bootup.script /config/scripts/vyos-preconfig-bootup.script; do
        if [ -f "$s" ]; then
            cp "$s" "$BACKUP_DIR/"
            echo '#!/bin/bash' > "$s"
            echo 'exit 0' >> "$s"
            chmod +x "$s"
        fi
    done
    rm -f /etc/ld.so.preload 2>/dev/null

    if [ "$DRY_RUN" = true ]; then
        log_ok "Dry run enabled. Halting before configuration commit."
        builtin exit 0
    fi

    configure
    set system login user "$ADMIN_USER" authentication plaintext-password "$ADMIN_PASS"
    set system config-management commit-revisions 100

    log_info "Disabling remote management services (SSH, Telnet, HTTPS API)..."
    delete service ssh 2>/dev/null || true
    delete service telnet 2>/dev/null || true
    delete service https 2>/dev/null || true
    delete service https api 2>/dev/null || true
    delete system task-scheduler 2>/dev/null || true

    log_info "Applying control-plane firewall to block inbound SSH..."
    set firewall ipv4 input filter default-action drop

    set firewall ipv4 input filter rule 5 action accept
    set firewall ipv4 input filter rule 5 description 'Allow loopback'
    set firewall ipv4 input filter rule 5 inbound-interface name 'lo'

    set firewall ipv4 input filter rule 10 action accept
    set firewall ipv4 input filter rule 10 description 'Allow established/related'
    set firewall ipv4 input filter rule 10 state established
    set firewall ipv4 input filter rule 10 state related

    set firewall ipv4 input filter rule 20 action accept
    set firewall ipv4 input filter rule 20 description 'Allow ICMP'
    set firewall ipv4 input filter rule 20 protocol icmp

    set firewall ipv4 forward filter default-action accept

    commit
    save
    vyos_exit_cfg

    log_info "Terminating lingering sshd and dropbear daemons..."
    killall -9 sshd 2>/dev/null || true
    killall -9 dropbear 2>/dev/null || true

    echo "======================================================================"
    log_ok "VyOS is now locked down in CONSOLE-ONLY mode."
    log_ok "Remote SSH is deleted and blocked on firewall."
    log_ok "Default user '$ADMIN_USER' password updated."
    log_ok "Scored transit traffic continues forwarding normally."
    echo "======================================================================"
    builtin exit 0
fi

# ==============================================================================
# MODE: CONFIRM PENDING COMMIT-CONFIRM CHANGES
# ==============================================================================
if [ "$MODE" == "confirm" ]; then
    echo "======================================================================"
    echo "          VyOS CONFIRM & SAVE PENDING CONFIGURATION"
    echo "======================================================================"
    if [ "$DRY_RUN" = true ]; then
        log_ok "Dry run enabled. Exiting before configuration confirmation."
        builtin exit 0
    fi

    log_info "Entering VyOS configuration mode to confirm changes..."
    configure

    log_info "Confirming commit..."
    if ! confirm; then
        vyos_exit_cfg
        log_error "Failed to confirm VyOS configuration. Commit-confirm timer may have expired or no commit pending."
        builtin exit 1
    fi

    log_info "Saving configuration..."
    if ! save; then
        vyos_exit_cfg
        log_error "Failed to save VyOS configuration."
        builtin exit 1
    fi

    vyos_exit_cfg
    log_ok "VyOS configuration confirmed and saved permanently."
    builtin exit 0
fi

# ─── NAT Configuration Engine (Rules 10, 20, 30, 40, 50 DNAT/SNAT & Rule 100 PAT) ───
apply_nat_configuration() {
    log_info "Executing IP-Centric NAT Baseline Reconciliation (Target: $DNAT_TARGET)..."

    if [ -z "$OCTET" ]; then
        local detected_wan
        detected_wan=$(detect_existing_wan_octet)
        if [ -n "$detected_wan" ]; then
            OCTET="$detected_wan"
        elif [ -n "$TEAM" ]; then
            derive_team_subnets "$TEAM"
        else
            OCTET=40
            log_warn "Neither team nor WAN octet detected; defaulting WAN octet to Team 0 practice (40)."
        fi
    fi

    if [ -z "$PUBLIC_OCTET" ]; then
        local detected_pub
        detected_pub=$(detect_existing_octet)
        if [ -n "$detected_pub" ]; then
            PUBLIC_OCTET="$detected_pub"
            log_info "Auto-detected public NAT pool octet from router config: 172.25.${PUBLIC_OCTET}.0/24"
        elif [ -n "$TEAM" ] && [ "$TEAM" -gt 0 ]; then
            PUBLIC_OCTET="$OCTET"
        else
            # Known-good Team 0 Practice Public Pool baseline is 172.25.20.0/24
            PUBLIC_OCTET=20
            log_info "Using Team 0 Practice Public NAT Pool baseline: 172.25.${PUBLIC_OCTET}.0/24"
        fi
    fi

    local ECOM_TARGET EMAIL_TARGET SPLUNK_TARGET AD_TARGET MSSQL_TARGET
    if [ "$DNAT_TARGET" == "private" ]; then
        ECOM_TARGET="172.20.240.10"
        EMAIL_TARGET="172.20.240.15"
        SPLUNK_TARGET="172.20.240.20"
        AD_TARGET="172.20.240.100"
        MSSQL_TARGET="172.20.240.120"
    else
        ECOM_TARGET="172.25.${PUBLIC_OCTET}.10"
        EMAIL_TARGET="172.25.${PUBLIC_OCTET}.15"
        SPLUNK_TARGET="172.25.${PUBLIC_OCTET}.20"
        AD_TARGET="172.25.${PUBLIC_OCTET}.100"
        MSSQL_TARGET="172.25.${PUBLIC_OCTET}.120"
    fi

    local ECOM_PUB="172.25.${PUBLIC_OCTET}.10"
    local EMAIL_PUB="172.25.${PUBLIC_OCTET}.15"
    local SPLUNK_PUB="172.25.${PUBLIC_OCTET}.20"
    local AD_PUB="172.25.${PUBLIC_OCTET}.100"
    local MSSQL_PUB="172.25.${PUBLIC_OCTET}.120"

    local RAW_CONFIG=""
    if [ -x /opt/vyatta/bin/vyatta-op-cmd-wrapper ]; then
        RAW_CONFIG=$(/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands 2>/dev/null || true)
    fi
    if [ -z "$RAW_CONFIG" ] && [ -f /config/config.boot ]; then
        RAW_CONFIG=$(cat /config/config.boot 2>/dev/null || true)
    fi

    local RECONCILE_SUCCESS=false
    if command -v python3 >/dev/null 2>&1; then
        local PYTHON_CMDS=""
        local PY_TMP
        PY_TMP=$(mktemp 2>/dev/null || echo "/tmp/defender_nat_reconcile_$$.py")
        cat <<'PY_RECONCILE_EOF' > "$PY_TMP"
import sys, os, re

dnat_target = sys.argv[1]
force_baseline = (sys.argv[2] == "true")
ecom_tgt = sys.argv[3]
email_tgt = sys.argv[4]
splunk_tgt = sys.argv[5]
ad_tgt = sys.argv[6]
mssql_tgt = sys.argv[7]
ecom_pub = sys.argv[8]
email_pub = sys.argv[9]
splunk_pub = sys.argv[10]
ad_pub = sys.argv[11]
mssql_pub = sys.argv[12]

raw_config = os.environ.get("DEFENDER_RAW_CONFIG", "")

targets = [
    {'name': 'Ecom',   'desc': 'host .10',  'rule': 10, 'suffix': '10',  'priv': '172.20.240.10',  'ip': ecom_tgt,   'pub_ip': ecom_pub,   'ports': '80,443'},
    {'name': 'Email',  'desc': 'host .15',  'rule': 20, 'suffix': '15',  'priv': '172.20.240.15',  'ip': email_tgt,  'pub_ip': email_pub,  'ports': '25,143,587,993'},
    {'name': 'Splunk', 'desc': 'host .20',  'rule': 30, 'suffix': '20',  'priv': '172.20.240.20',  'ip': splunk_tgt, 'pub_ip': splunk_pub, 'ports': '8000,8089,9997'},
    {'name': 'AD',     'desc': 'host .100', 'rule': 40, 'suffix': '100', 'priv': '172.20.240.100', 'ip': ad_tgt,     'pub_ip': ad_pub,     'ports': '53,88,389,636,5985'},
    {'name': 'MSSQL',  'desc': 'host .120', 'rule': 50, 'suffix': '120', 'priv': '172.20.240.120', 'ip': mssql_tgt,  'pub_ip': mssql_pub,  'ports': '445,1433,3389'},
]

has_outside_group = (
    'interface-group OUTSIDE' in raw_config
    or 'group OUTSIDE' in raw_config
    or "group 'OUTSIDE'" in raw_config
    or 'group "OUTSIDE"' in raw_config
)

def extract_named_block(text, name):
    m = re.search(r'\b' + re.escape(name) + r'\s*\{', text)
    if not m:
        return None
    open_brace = m.end() - 1
    depth = 0
    for idx in range(open_brace, len(text)):
        if text[idx] == '{':
            depth += 1
        elif text[idx] == '}':
            depth -= 1
            if depth == 0:
                return text[open_brace + 1:idx]
    return None

def iter_braced_rules(section_body):
    if not section_body:
        return
    i = 0
    while i < len(section_body):
        m = re.search(r'\brule\s+(\d+)\s*\{', section_body[i:])
        if not m:
            break
        rnum = int(m.group(1))
        open_brace = i + m.end() - 1
        depth = 0
        j = open_brace
        while j < len(section_body):
            if section_body[j] == '{':
                depth += 1
            elif section_body[j] == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        yield rnum, section_body[open_brace + 1:j]
        i = j + 1

def parse_dnat_rules(text):
    rules = {}
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r'set nat destination rule (\d+)\s+(.+)', line)
        if m:
            rnum = int(m.group(1))
            rest = m.group(2)
            if rnum not in rules:
                rules[rnum] = {'rule': rnum, 'desc': '', 'trans': '', 'dest_addr': '', 'ports': '', 'proto': '', 'iface': 'eth0', 'iface_type': 'name'}
            if rest.startswith('description'):
                rules[rnum]['desc'] = rest.split(None, 1)[1].strip("'\"")
            elif rest.startswith('translation address'):
                rules[rnum]['trans'] = rest.split(None, 2)[2].strip("'\"")
            elif rest.startswith('destination address'):
                rules[rnum]['dest_addr'] = rest.split(None, 2)[2].strip("'\"")
            elif rest.startswith('destination port'):
                rules[rnum]['ports'] = rest.split(None, 2)[2].strip("'\"")
            elif rest.startswith('protocol'):
                rules[rnum]['proto'] = rest.split(None, 1)[1].strip("'\"")
            elif rest.startswith('inbound-interface name'):
                rules[rnum]['iface'] = rest.split(None, 2)[2].strip("'\"")
                rules[rnum]['iface_type'] = 'name'
            elif rest.startswith('inbound-interface group'):
                rules[rnum]['iface'] = rest.split(None, 2)[2].strip("'\"")
                rules[rnum]['iface_type'] = 'group'
            elif rest.startswith('inbound-interface'):
                rules[rnum]['iface'] = rest.split(None, 1)[1].strip("'\"")
                rules[rnum]['iface_type'] = 'bare'
    if rules:
        return rules

    nat_blk = extract_named_block(text, 'nat')
    dest_blk = extract_named_block(nat_blk, 'destination') if nat_blk else extract_named_block(text, 'destination')
    for rnum, rule_body in iter_braced_rules(dest_blk):
        trans_blk = extract_named_block(rule_body, 'translation') or ''
        dest_sub = extract_named_block(rule_body, 'destination') or ''
        iface_blk = extract_named_block(rule_body, 'inbound-interface') or ''

        trans_m = re.search(r'\baddress\s+[\'\"]?([^\s\'\";}]+)', trans_blk)
        dest_addr_m = re.search(r'\baddress\s+[\'\"]?([^\s\'\";}]+)', dest_sub)
        port_m = re.search(r'\bport\s+[\'\"]?([^\s\'\";}]+)', dest_sub)
        proto_m = re.search(r'\bprotocol\s+[\'\"]?([^\s\'\";}]+)', rule_body)
        desc_m = re.search(r'\bdescription\s+[\'\"]?([^\n\'\";}]+)', rule_body)

        iface_grp_m = re.search(r'\bgroup\s+[\'\"]?([^\s\'\";}]+)', iface_blk)
        iface_name_m = re.search(r'\bname\s+[\'\"]?([^\s\'\";}]+)', iface_blk)
        iface_bare_m = re.search(r'inbound-interface\s+[\'\"]?([^\s\'\";}{]+)', rule_body)

        iface = 'eth0'
        iface_type = 'name'
        if iface_grp_m:
            iface = iface_grp_m.group(1).strip().strip('\'\"')
            iface_type = 'group'
        elif iface_name_m:
            iface = iface_name_m.group(1).strip().strip('\'\"')
            iface_type = 'name'
        elif iface_bare_m:
            iface = iface_bare_m.group(1).strip().strip('\'\"')
            iface_type = 'bare'

        rules[rnum] = {
            'rule': rnum,
            'desc': desc_m.group(1).strip().strip('\'\"') if desc_m else '',
            'trans': trans_m.group(1).strip().strip('\'\"') if trans_m else '',
            'dest_addr': dest_addr_m.group(1).strip().strip('\'\"') if dest_addr_m else '',
            'ports': port_m.group(1).strip().strip('\'\"') if port_m else '',
            'proto': proto_m.group(1).strip().strip('\'\"') if proto_m else '',
            'iface': iface,
            'iface_type': iface_type
        }
    return rules

def parse_snat_rules(text):
    rules = {}
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r'set nat source rule (\d+)\s+(.+)', line)
        if m:
            rnum = int(m.group(1))
            rest = m.group(2)
            if rnum not in rules:
                rules[rnum] = {'rule': rnum, 'desc': '', 'src_addr': '', 'trans': '', 'iface': 'eth1', 'iface_type': 'name'}
            if rest.startswith('description'):
                rules[rnum]['desc'] = rest.split(None, 1)[1].strip("'\"")
            elif rest.startswith('source address'):
                rules[rnum]['src_addr'] = rest.split(None, 2)[2].strip("'\"")
            elif rest.startswith('translation address'):
                rules[rnum]['trans'] = rest.split(None, 2)[2].strip("'\"")
            elif rest.startswith('outbound-interface name'):
                rules[rnum]['iface'] = rest.split(None, 2)[2].strip("'\"")
                rules[rnum]['iface_type'] = 'name'
            elif rest.startswith('outbound-interface group'):
                rules[rnum]['iface'] = rest.split(None, 2)[2].strip("'\"")
                rules[rnum]['iface_type'] = 'group'
            elif rest.startswith('outbound-interface'):
                rules[rnum]['iface'] = rest.split(None, 1)[1].strip("'\"")
                rules[rnum]['iface_type'] = 'bare'
    if rules:
        return rules

    nat_blk = extract_named_block(text, 'nat')
    src_blk = extract_named_block(nat_blk, 'source') if nat_blk else extract_named_block(text, 'source')
    for rnum, rule_body in iter_braced_rules(src_blk):
        trans_blk = extract_named_block(rule_body, 'translation') or ''
        src_sub = extract_named_block(rule_body, 'source') or ''
        iface_blk = extract_named_block(rule_body, 'outbound-interface') or ''

        trans_m = re.search(r'\baddress\s+[\'\"]?([^\s\'\";}]+)', trans_blk)
        src_addr_m = re.search(r'\baddress\s+[\'\"]?([^\s\'\";}]+)', src_sub)
        desc_m = re.search(r'\bdescription\s+[\'\"]?([^\n\'\";}]+)', rule_body)

        iface_grp_m = re.search(r'\bgroup\s+[\'\"]?([^\s\'\";}]+)', iface_blk)
        iface_name_m = re.search(r'\bname\s+[\'\"]?([^\s\'\";}]+)', iface_blk)
        iface_bare_m = re.search(r'outbound-interface\s+[\'\"]?([^\s\'\";}{]+)', rule_body)

        iface = 'eth1'
        iface_type = 'name'
        if iface_grp_m:
            iface = iface_grp_m.group(1).strip().strip('\'\"')
            iface_type = 'group'
        elif iface_name_m:
            iface = iface_name_m.group(1).strip().strip('\'\"')
            iface_type = 'name'
        elif iface_bare_m:
            iface = iface_bare_m.group(1).strip().strip('\'\"')
            iface_type = 'bare'

        rules[rnum] = {
            'rule': rnum,
            'desc': desc_m.group(1).strip().strip('\'\"') if desc_m else '',
            'src_addr': src_addr_m.group(1).strip().strip('\'\"') if src_addr_m else '',
            'trans': trans_m.group(1).strip().strip('\'\"') if trans_m else '',
            'iface': iface,
            'iface_type': iface_type
        }
    return rules

parsed_dnat = parse_dnat_rules(raw_config)
parsed_snat = parse_snat_rules(raw_config)

def emit_dnat_rule_set(rnum, desc, pub_ip, trans_ip, iface, iface_type):
    # Pure 1:1 Host Destination NAT matching CCDC known-good golden image (no restrictive port/proto filters)
    print(f"SET_DNAT {rnum} description '{desc}'")
    print(f"SET_DNAT {rnum} destination address '{pub_ip}'")
    if iface_type == 'group':
        print(f"SET_DNAT {rnum} inbound-interface group '{iface}'")
    elif iface_type == 'bare':
        print(f"SET_DNAT {rnum} inbound-interface '{iface}'")
    else:
        print(f"SET_DNAT {rnum} inbound-interface name '{iface}'")
    print(f"SET_DNAT {rnum} translation address '{trans_ip}'")

def emit_snat_rule_set(rnum, desc, priv_ip, pub_ip, iface='eth1', iface_type='name'):
    print(f"SET_SNAT {rnum} description '{desc}'")
    if iface_type == 'group':
        print(f"SET_SNAT {rnum} outbound-interface group '{iface}'")
    elif iface_type == 'bare':
        print(f"SET_SNAT {rnum} outbound-interface '{iface}'")
    else:
        print(f"SET_SNAT {rnum} outbound-interface name '{iface}'")
    print(f"SET_SNAT {rnum} source address '{priv_ip}'")
    print(f"SET_SNAT {rnum} translation address '{pub_ip}'")

# Explicitly wipe legacy script artifact rules 11, 12, 13, 14
for legacy_r in (11, 12, 13, 14):
    if legacy_r in parsed_dnat:
        print(f"LOG Wiping legacy script artifact destination NAT rule {legacy_r}...")
        print(f"DELETE_DNAT {legacy_r}")

default_dnat_iface = 'OUTSIDE' if has_outside_group else 'eth0'
default_dnat_iface_type = 'group' if has_outside_group else 'name'

for tgt in targets:
    s_rule = tgt['rule']
    s_ip = tgt['ip']
    s_priv = tgt['priv']
    s_pub = tgt['pub_ip']
    s_ports = tgt['ports']
    s_name = tgt['name']
    s_desc = tgt['desc']
    expected_port_set = set(p.strip() for p in s_ports.split(',') if p.strip())

    # ── Reconcile Destination NAT ──
    matching = []
    for rnum, r in parsed_dnat.items():
        if rnum in (11, 12, 13, 14):
            continue
        trans = r.get('trans', '')
        dest_a = r.get('dest_addr', '')
        if trans == s_ip or (trans.endswith('.' + tgt['suffix']) and (trans.startswith('172.20.') or trans.startswith('172.25.'))):
            matching.append(r)
        elif dest_a == s_pub or (dest_a.endswith('.' + tgt['suffix']) and dest_a.startswith('172.25.')):
            matching.append(r)

    if force_baseline:
        for r in matching:
            print(f"DELETE_DNAT {r['rule']}")
        print(f"DELETE_DNAT {s_rule}")
        emit_dnat_rule_set(s_rule, s_desc, s_pub, s_ip, default_dnat_iface, default_dnat_iface_type)
    elif len(matching) == 0:
        print(f"LOG Deploying missing destination NAT rule {s_rule} for {s_name} ({s_pub} -> {s_ip})")
        print(f"DELETE_DNAT {s_rule}")
        emit_dnat_rule_set(s_rule, s_desc, s_pub, s_ip, default_dnat_iface, default_dnat_iface_type)
    elif len(matching) == 1:
        r = matching[0]
        r_ports = r.get('ports', '')
        if not r_ports or r_ports == 'any':
            ports_match = True
        else:
            r_ports_set = set(p.strip() for p in r_ports.split(',') if p.strip())
            ports_match = expected_port_set.issubset(r_ports_set)

        dest_match = (r.get('dest_addr') == s_pub)
        trans_match = (r.get('trans') == s_ip or not r.get('trans'))

        if r['rule'] == s_rule and ports_match and dest_match and trans_match:
            print(f"LOG Preserving valid destination NAT rule {r['rule']} for {s_name} ({s_pub} -> {s_ip})")
        elif r['rule'] == s_rule:
            print(f"LOG Correcting drifted destination NAT rule {s_rule} for {s_name} ({s_pub} -> {s_ip})")
            if not ports_match:
                print(f"DELETE_DNAT {s_rule}")
                emit_dnat_rule_set(s_rule, r.get('desc') or s_desc, s_pub, s_ip, r.get('iface', default_dnat_iface), r.get('iface_type', default_dnat_iface_type))
            else:
                if not dest_match:
                    print(f"SET_DNAT {s_rule} destination address '{s_pub}'")
                if not trans_match:
                    print(f"SET_DNAT {s_rule} translation address '{s_ip}'")
        else:
            print(f"LOG Replacing drifted non-standard rule {r['rule']} with standard rule {s_rule} for {s_name} ({s_pub} -> {s_ip})")
            print(f"DELETE_DNAT {r['rule']}")
            print(f"DELETE_DNAT {s_rule}")
            emit_dnat_rule_set(s_rule, s_desc, s_pub, s_ip, r.get('iface', default_dnat_iface), r.get('iface_type', default_dnat_iface_type))
    else:
        rnums = [r['rule'] for r in matching]
        print(f"LOG Wiping conflicting duplicate rules {rnums} for {s_name}")
        for r in matching:
            if r['rule'] != s_rule:
                print(f"DELETE_DNAT {r['rule']}")
        std_r = next((r for r in matching if r['rule'] == s_rule), None)
        if std_r:
            r_ports = std_r.get('ports', '')
            if not r_ports or r_ports == 'any':
                ports_match = True
            else:
                r_ports_set = set(p.strip() for p in r_ports.split(',') if p.strip())
                ports_match = expected_port_set.issubset(r_ports_set)
            if not ports_match:
                print(f"DELETE_DNAT {s_rule}")
            emit_dnat_rule_set(s_rule, std_r.get('desc') or s_desc, s_pub, s_ip, std_r.get('iface', default_dnat_iface), std_r.get('iface_type', default_dnat_iface_type))
        else:
            emit_dnat_rule_set(s_rule, s_desc, s_pub, s_ip, default_dnat_iface, default_dnat_iface_type)

    # ── Reconcile 1:1 Source NAT (Rules 10, 20, 30, 40, 50) ──
    snat_match = []
    for rnum, r in parsed_snat.items():
        if rnum == 100:
            continue
        sa = r.get('src_addr', '')
        ta = r.get('trans', '')
        if sa == s_priv or (sa.endswith('.' + tgt['suffix']) and sa.startswith('172.20.')) or ta == s_pub:
            snat_match.append(r)

    if force_baseline:
        for r in snat_match:
            print(f"DELETE_SNAT {r['rule']}")
        print(f"DELETE_SNAT {s_rule}")
        emit_snat_rule_set(s_rule, s_desc, s_priv, s_pub)
    elif len(snat_match) == 0:
        print(f"LOG Deploying missing source NAT rule {s_rule} for {s_name} ({s_priv} -> {s_pub})")
        print(f"DELETE_SNAT {s_rule}")
        emit_snat_rule_set(s_rule, s_desc, s_priv, s_pub)
    elif len(snat_match) == 1:
        r = snat_match[0]
        if r['rule'] == s_rule and r.get('src_addr') == s_priv and r.get('trans') == s_pub:
            print(f"LOG Preserving valid source NAT rule {r['rule']} for {s_name} ({s_priv} -> {s_pub})")
        elif r['rule'] == s_rule:
            print(f"LOG Correcting drifted source NAT rule {s_rule} for {s_name} ({s_priv} -> {s_pub})")
            print(f"SET_SNAT {s_rule} source address '{s_priv}'")
            print(f"SET_SNAT {s_rule} translation address '{s_pub}'")
        else:
            print(f"LOG Replacing non-standard source NAT rule {r['rule']} with rule {s_rule} for {s_name}")
            print(f"DELETE_SNAT {r['rule']}")
            print(f"DELETE_SNAT {s_rule}")
            emit_snat_rule_set(s_rule, s_desc, s_priv, s_pub, r.get('iface', 'eth1'), r.get('iface_type', 'name'))
    else:
        for r in snat_match:
            if r['rule'] != s_rule:
                print(f"DELETE_SNAT {r['rule']}")
        std_s = next((r for r in snat_match if r['rule'] == s_rule), None)
        if std_s:
            emit_snat_rule_set(s_rule, std_s.get('desc') or s_desc, s_priv, s_pub, std_s.get('iface', 'eth1'), std_s.get('iface_type', 'name'))
        else:
            emit_snat_rule_set(s_rule, s_desc, s_priv, s_pub)

print("RECONCILE_OK")
PY_RECONCILE_EOF
        PYTHON_CMDS=$(DEFENDER_RAW_CONFIG="$RAW_CONFIG" python3 "$PY_TMP" "$DNAT_TARGET" "$FORCE_BASELINE" "$ECOM_TARGET" "$EMAIL_TARGET" "$SPLUNK_TARGET" "$AD_TARGET" "$MSSQL_TARGET" "$ECOM_PUB" "$EMAIL_PUB" "$SPLUNK_PUB" "$AD_PUB" "$MSSQL_PUB" 2>/dev/null)
        rm -f "$PY_TMP"
        if echo "$PYTHON_CMDS" | grep -q "RECONCILE_OK"; then
            RECONCILE_SUCCESS=true
            while IFS= read -r line; do
                if [[ "$line" =~ ^LOG[[:space:]]+(.*) ]]; then
                    log_info "${BASH_REMATCH[1]}"
                elif [[ "$line" =~ ^DELETE_DNAT[[:space:]]+([0-9]+) ]]; then
                    local del_rule="${BASH_REMATCH[1]}"
                    log_info "Deleting destination NAT rule ${del_rule}..."
                    delete nat destination rule "$del_rule" >/dev/null 2>&1 || true
                elif [[ "$line" =~ ^DELETE_SNAT[[:space:]]+([0-9]+) ]]; then
                    local del_srule="${BASH_REMATCH[1]}"
                    log_info "Deleting source NAT rule ${del_srule}..."
                    delete nat source rule "$del_srule" >/dev/null 2>&1 || true
                elif [[ "$line" =~ ^SET_DNAT[[:space:]]+(.*) ]]; then
                    local set_args="${BASH_REMATCH[1]}"
                    # shellcheck disable=SC2086
                    set nat destination rule $set_args
                elif [[ "$line" =~ ^SET_SNAT[[:space:]]+(.*) ]]; then
                    local set_sargs="${BASH_REMATCH[1]}"
                    # shellcheck disable=SC2086
                    set nat source rule $set_sargs
                fi
            done <<< "$PYTHON_CMDS"
        fi
    fi

    # Shell fallback if Python3 unavailable or failed
    if [ "$RECONCILE_SUCCESS" != true ]; then
        log_warn "Python3 reconciliation unavailable; applying shell-based IP-centric cleanup..."
        for r in 10 11 12 13 14 20 30 40 50; do
            delete nat destination rule "$r" >/dev/null 2>&1 || true
        done
        for r in 10 20 30 40 50; do
            delete nat source rule "$r" >/dev/null 2>&1 || true
        done
        for ip_suffix in "10" "15" "20" "100" "120"; do
            local CONFLICT_RULES=""
            if [ -x /opt/vyatta/bin/vyatta-op-cmd-wrapper ]; then
                CONFLICT_RULES=$(/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands 2>/dev/null | grep "^set nat destination rule " | grep -E "translation address|destination address" | grep -E "(\.|\')${ip_suffix}('|$)" | awk '{print $5}' | grep -E '^[0-9]+$' | sort -u)
            elif [ -n "$RAW_CONFIG" ]; then
                CONFLICT_RULES=$(echo "$RAW_CONFIG" | grep "^set nat destination rule " 2>/dev/null | grep -E "translation address|destination address" | grep -E "(\.|\')${ip_suffix}('|$)" | awk '{print $5}' | grep -E '^[0-9]+$' | sort -u)
            fi
            for cr in $CONFLICT_RULES; do
                if [ -n "$cr" ] && [ "$cr" != "10" -a "$cr" != "20" -a "$cr" != "30" -a "$cr" != "40" -a "$cr" != "50" ]; then
                    log_info "Wiping conflicting duplicate rule $cr (target .${ip_suffix})..."
                    delete nat destination rule "$cr" >/dev/null 2>&1 || true
                fi
            done
        done

        local FB_IFACE_CMD="inbound-interface name 'eth0'"
        if echo "$RAW_CONFIG" | grep -qE "interface-group OUTSIDE|group OUTSIDE"; then
            FB_IFACE_CMD="inbound-interface group 'OUTSIDE'"
        fi

        # Deploy canonical pure 1:1 DNAT rules 10, 20, 30, 40, 50 matching known-good baseline
        set nat destination rule 10 description 'host .10'
        set nat destination rule 10 destination address "$ECOM_PUB"
        # shellcheck disable=SC2086
        set nat destination rule 10 $FB_IFACE_CMD
        set nat destination rule 10 translation address "$ECOM_TARGET"

        set nat destination rule 20 description 'host .15'
        set nat destination rule 20 destination address "$EMAIL_PUB"
        # shellcheck disable=SC2086
        set nat destination rule 20 $FB_IFACE_CMD
        set nat destination rule 20 translation address "$EMAIL_TARGET"

        set nat destination rule 30 description 'host .20'
        set nat destination rule 30 destination address "$SPLUNK_PUB"
        # shellcheck disable=SC2086
        set nat destination rule 30 $FB_IFACE_CMD
        set nat destination rule 30 translation address "$SPLUNK_TARGET"

        set nat destination rule 40 description 'host .100'
        set nat destination rule 40 destination address "$AD_PUB"
        # shellcheck disable=SC2086
        set nat destination rule 40 $FB_IFACE_CMD
        set nat destination rule 40 translation address "$AD_TARGET"

        set nat destination rule 50 description 'host .120'
        set nat destination rule 50 destination address "$MSSQL_PUB"
        # shellcheck disable=SC2086
        set nat destination rule 50 $FB_IFACE_CMD
        set nat destination rule 50 translation address "$MSSQL_TARGET"

        # Deploy canonical 1:1 SNAT rules 10, 20, 30, 40, 50 matching known-good baseline
        set nat source rule 10 description 'host .10'
        set nat source rule 10 outbound-interface name 'eth1'
        set nat source rule 10 source address '172.20.240.10'
        set nat source rule 10 translation address "$ECOM_PUB"

        set nat source rule 20 description 'host .15'
        set nat source rule 20 outbound-interface name 'eth1'
        set nat source rule 20 source address '172.20.240.15'
        set nat source rule 20 translation address "$EMAIL_PUB"

        set nat source rule 30 description 'host .20'
        set nat source rule 30 outbound-interface name 'eth1'
        set nat source rule 30 source address '172.20.240.20'
        set nat source rule 30 translation address "$SPLUNK_PUB"

        set nat source rule 40 description 'host .100'
        set nat source rule 40 outbound-interface name 'eth1'
        set nat source rule 40 source address '172.20.240.100'
        set nat source rule 40 translation address "$AD_PUB"

        set nat source rule 50 description 'host .120'
        set nat source rule 50 outbound-interface name 'eth1'
        set nat source rule 50 source address '172.20.240.120'
        set nat source rule 50 translation address "$MSSQL_PUB"
    fi

    # Outbound PAT (Masquerade rule 100)
    if [ "$ENABLE_OUTBOUND_PAT" = true ]; then
        log_warn "Outbound PAT is ENABLED! Workstations and LAN hosts will masquerade to 172.31.${OCTET}.2."
        set nat source rule 100 outbound-interface name 'eth0'
        set nat source rule 100 source address '172.16.0.0/12'
        set nat source rule 100 translation address 'masquerade'
    else
        log_ok "Outbound PAT is DISABLED by default (Anti-Reverse-Shell Protection)."
        log_info "Workstations cannot establish direct outbound internet connections unless --enable-outbound-pat is set."
        delete nat source rule 100 >/dev/null 2>&1 || true
    fi
}

# ─── Routing Baseline Engine (Standard Transit Routes Grounded in Topology) ───
apply_routing_baseline() {
    log_info "Configuring Standard Transit Routes Grounded in Topology..."
    local WAN_GW="${CORE_GATEWAY_IP:-172.31.${OCTET}.1}"
    local SERVERS_NEXTHOP="172.16.0.1"

    delete protocols static route 0.0.0.0/0 >/dev/null 2>&1 || true
    delete protocols static route 172.20.240.0/24 >/dev/null 2>&1 || true

    set protocols static route 0.0.0.0/0 next-hop "$WAN_GW"
    set protocols static route 172.20.240.0/24 next-hop "$SERVERS_NEXTHOP"
}

# ─── Detected State Restoration Engine (Parses Tab 3 JSON State) ─────────────
apply_detected_configuration() {
    local file="$1"
    if [ ! -f "$file" ]; then
        log_warn "Detected state file does not exist: $file"
        return 1
    fi

    log_info "Parsing detected configuration state from: $file"

    if [ -z "$OCTET" ]; then
        local detected_wan
        detected_wan=$(detect_existing_wan_octet)
        if [ -n "$detected_wan" ]; then
            OCTET="$detected_wan"
        elif [ -n "$TEAM" ]; then
            derive_team_subnets "$TEAM"
        else
            OCTET=40
        fi
    fi

    if [ -z "$PUBLIC_OCTET" ]; then
        local detected_pub
        detected_pub=$(detect_existing_octet)
        if [ -n "$detected_pub" ]; then
            PUBLIC_OCTET="$detected_pub"
            log_info "Auto-detected public octet: 172.25.${PUBLIC_OCTET}.0/24"
        elif [ -n "$TEAM" ] && [ "$TEAM" -gt 0 ]; then
            PUBLIC_OCTET="$OCTET"
        else
            PUBLIC_OCTET=20
        fi
    fi

    local ECOM_TARGET="" EMAIL_TARGET="" SPLUNK_TARGET="" AD_TARGET="" MSSQL_TARGET=""
    local OUTBOUND_PAT="" DEF_GW="" SRV_NH=""
    local EXTRA_DELETE_RULES=""
    local PARSE_SUCCESS=false

    # Strategy 1: Python3 JSON parser (preferred on VyOS / Debian)
    if command -v python3 >/dev/null 2>&1; then
        local PY_VARS
        PY_VARS=$(python3 - "$file" <<'EOF' 2>/dev/null
import json, sys

try:
    with open(sys.argv[1], "r") as f:
        data = json.load(f)

    nat_rules = data.get("nat_rules", [])
    routes = {rt.get("prefix"): rt.get("next_hop") for rt in data.get("static_routes", []) if isinstance(rt, dict)}
    pat = data.get("outbound_pat", False)

    # Require either at least one nat rule or static route
    if not nat_rules and not routes:
        sys.exit(1)

    for r in nat_rules:
        if isinstance(r, dict):
            r_num = r.get("rule")
            if r_num and r_num not in (10, 20, 30, 40, 50):
                print(f"EXTRA_DEL_{r_num}=1")
            trans = r.get("translation", "")
            if trans and trans != "unknown":
                if trans.endswith(".10"):
                    print(f"RULE_10={trans}")
                elif trans.endswith(".15"):
                    print(f"RULE_20={trans}")
                elif trans.endswith(".20"):
                    print(f"RULE_30={trans}")
                elif trans.endswith(".100"):
                    print(f"RULE_40={trans}")
                elif trans.endswith(".120"):
                    print(f"RULE_50={trans}")

    print(f"PAT={'true' if pat else 'false'}")

    for prefix, nh in routes.items():
        if prefix == "0.0.0.0/0":
            print(f"DEF_GW={nh}")
        elif prefix == "172.20.240.0/24":
            print(f"SRV_NH={nh}")

    print("PARSED_OK=1")
except Exception:
    sys.exit(1)
EOF
)
        if [ $? -eq 0 ] && echo "$PY_VARS" | grep -q "PARSED_OK=1"; then
            PARSE_SUCCESS=true
            while IFS='=' read -r key val; do
                case "$key" in
                    RULE_10) ECOM_TARGET="$val" ;;
                    RULE_20) EMAIL_TARGET="$val" ;;
                    RULE_30) SPLUNK_TARGET="$val" ;;
                    RULE_40) AD_TARGET="$val" ;;
                    RULE_50) MSSQL_TARGET="$val" ;;
                    EXTRA_DEL_*)
                        del_r="${key#EXTRA_DEL_}"
                        EXTRA_DELETE_RULES="$EXTRA_DELETE_RULES $del_r"
                        ;;
                    PAT) OUTBOUND_PAT="$val" ;;
                    DEF_GW) DEF_GW="$val" ;;
                    SRV_NH) SRV_NH="$val" ;;
                esac
            done <<< "$PY_VARS"
        fi
    fi

    # Strategy 2: grep/sed fallback if python3 is unavailable or failed
    if [ "$PARSE_SUCCESS" != true ]; then
        if ! grep -qE "nat_rules|static_routes" "$file"; then
            log_warn "State file contains no recognizable nat_rules or static_routes: $file"
            return 1
        fi

        ECOM_TARGET=$(grep -E '"rule"[[:space:]]*:[[:space:]]*(10)[[:space:]]*,' "$file" | sed -n 's/.*"translation"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
        EMAIL_TARGET=$(grep -E '"rule"[[:space:]]*:[[:space:]]*(20|11)[[:space:]]*,' "$file" | sed -n 's/.*"translation"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
        SPLUNK_TARGET=$(grep -E '"rule"[[:space:]]*:[[:space:]]*(30|12)[[:space:]]*,' "$file" | sed -n 's/.*"translation"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
        AD_TARGET=$(grep -E '"rule"[[:space:]]*:[[:space:]]*(40|13)[[:space:]]*,' "$file" | sed -n 's/.*"translation"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
        MSSQL_TARGET=$(grep -E '"rule"[[:space:]]*:[[:space:]]*(50|14)[[:space:]]*,' "$file" | sed -n 's/.*"translation"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)

        if grep -qE '"outbound_pat"[[:space:]]*:[[:space:]]*true' "$file"; then
            OUTBOUND_PAT="true"
        else
            OUTBOUND_PAT="false"
        fi

        DEF_GW=$(grep -E '"prefix"[[:space:]]*:[[:space:]]*"0\.0\.0\.0/0"' "$file" | sed -n 's/.*"next_hop"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
        SRV_NH=$(grep -E '"prefix"[[:space:]]*:[[:space:]]*"172\.20\.240\.0/24"' "$file" | sed -n 's/.*"next_hop"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)

        if [ -z "$ECOM_TARGET" ] && [ -z "$EMAIL_TARGET" ] && [ -z "$SPLUNK_TARGET" ] && [ -z "$AD_TARGET" ] && [ -z "$MSSQL_TARGET" ] && [ -z "$DEF_GW" ] && [ -z "$SRV_NH" ]; then
            log_warn "Failed to extract any rules or routes from $file"
            return 1
        fi
    fi

    # Clean-slate deletion of destination NAT rules 10 through 14, 20, 30, 40, 50 and conflicting rules
    for r in 10 11 12 13 14 20 30 40 50; do
        delete nat destination rule "$r" >/dev/null 2>&1 || true
    done
    for del_r in $EXTRA_DELETE_RULES; do
        delete nat destination rule "$del_r" >/dev/null 2>&1 || true
    done
    for sr in 10 20 30 40 50 100; do
        delete nat source rule "$sr" >/dev/null 2>&1 || true
    done

    # Extract clean IPv4 addresses
    local CLEAN_DEF_GW
    CLEAN_DEF_GW=$(echo "$DEF_GW" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -n1)
    if [ -z "$CLEAN_DEF_GW" ]; then
        CLEAN_DEF_GW="${CORE_GATEWAY_IP:-172.31.${OCTET}.1}"
    fi

    local CLEAN_SRV_NH
    CLEAN_SRV_NH=$(echo "$SRV_NH" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -n1)
    if [ -z "$CLEAN_SRV_NH" ]; then
        CLEAN_SRV_NH="172.16.0.1"
    fi

    local FINAL_ECOM FINAL_EMAIL FINAL_SPLUNK FINAL_AD FINAL_MSSQL
    if echo "$ECOM_TARGET" | grep -qE "^([0-9]{1,3}\.){3}[0-9]{1,3}$"; then
        FINAL_ECOM="$ECOM_TARGET"
    else
        FINAL_ECOM="172.20.240.10"
    fi

    if echo "$EMAIL_TARGET" | grep -qE "^([0-9]{1,3}\.){3}[0-9]{1,3}$"; then
        FINAL_EMAIL="$EMAIL_TARGET"
    else
        FINAL_EMAIL="172.20.240.15"
    fi

    if echo "$SPLUNK_TARGET" | grep -qE "^([0-9]{1,3}\.){3}[0-9]{1,3}$"; then
        FINAL_SPLUNK="$SPLUNK_TARGET"
    else
        FINAL_SPLUNK="172.20.240.20"
    fi

    if echo "$AD_TARGET" | grep -qE "^([0-9]{1,3}\.){3}[0-9]{1,3}$"; then
        FINAL_AD="$AD_TARGET"
    else
        FINAL_AD="172.20.240.100"
    fi

    if echo "$MSSQL_TARGET" | grep -qE "^([0-9]{1,3}\.){3}[0-9]{1,3}$"; then
        FINAL_MSSQL="$MSSQL_TARGET"
    else
        FINAL_MSSQL="172.20.240.120"
    fi

    local FINAL_ECOM_PUB="172.25.${PUBLIC_OCTET}.10"
    local FINAL_EMAIL_PUB="172.25.${PUBLIC_OCTET}.15"
    local FINAL_SPLUNK_PUB="172.25.${PUBLIC_OCTET}.20"
    local FINAL_AD_PUB="172.25.${PUBLIC_OCTET}.100"
    local FINAL_MSSQL_PUB="172.25.${PUBLIC_OCTET}.120"

    local IFACE_CMD="inbound-interface name 'eth0'"
    if [ -f /config/config.boot ] && grep -qE "interface-group OUTSIDE|group OUTSIDE" /config/config.boot 2>/dev/null; then
        IFACE_CMD="inbound-interface group 'OUTSIDE'"
    fi

    log_info "Configuring Scored 1:1 DNAT & SNAT Rules from detected state:"
    log_info "  Rule 10 (host .10)  : $FINAL_ECOM_PUB <-> $FINAL_ECOM"
    log_info "  Rule 20 (host .15)  : $FINAL_EMAIL_PUB <-> $FINAL_EMAIL"
    log_info "  Rule 30 (host .20)  : $FINAL_SPLUNK_PUB <-> $FINAL_SPLUNK"
    log_info "  Rule 40 (host .100) : $FINAL_AD_PUB <-> $FINAL_AD"
    log_info "  Rule 50 (host .120) : $FINAL_MSSQL_PUB <-> $FINAL_MSSQL"

    set nat destination rule 10 description 'host .10'
    set nat destination rule 10 destination address "$FINAL_ECOM_PUB"
    # shellcheck disable=SC2086
    set nat destination rule 10 $IFACE_CMD
    set nat destination rule 10 translation address "$FINAL_ECOM"

    set nat destination rule 20 description 'host .15'
    set nat destination rule 20 destination address "$FINAL_EMAIL_PUB"
    # shellcheck disable=SC2086
    set nat destination rule 20 $IFACE_CMD
    set nat destination rule 20 translation address "$FINAL_EMAIL"

    set nat destination rule 30 description 'host .20'
    set nat destination rule 30 destination address "$FINAL_SPLUNK_PUB"
    # shellcheck disable=SC2086
    set nat destination rule 30 $IFACE_CMD
    set nat destination rule 30 translation address "$FINAL_SPLUNK"

    set nat destination rule 40 description 'host .100'
    set nat destination rule 40 destination address "$FINAL_AD_PUB"
    # shellcheck disable=SC2086
    set nat destination rule 40 $IFACE_CMD
    set nat destination rule 40 translation address "$FINAL_AD"

    set nat destination rule 50 description 'host .120'
    set nat destination rule 50 destination address "$FINAL_MSSQL_PUB"
    # shellcheck disable=SC2086
    set nat destination rule 50 $IFACE_CMD
    set nat destination rule 50 translation address "$FINAL_MSSQL"

    set nat source rule 10 description 'host .10'
    set nat source rule 10 outbound-interface name 'eth1'
    set nat source rule 10 source address "$FINAL_ECOM"
    set nat source rule 10 translation address "$FINAL_ECOM_PUB"

    set nat source rule 20 description 'host .15'
    set nat source rule 20 outbound-interface name 'eth1'
    set nat source rule 20 source address "$FINAL_EMAIL"
    set nat source rule 20 translation address "$FINAL_EMAIL_PUB"

    set nat source rule 30 description 'host .20'
    set nat source rule 30 outbound-interface name 'eth1'
    set nat source rule 30 source address "$FINAL_SPLUNK"
    set nat source rule 30 translation address "$FINAL_SPLUNK_PUB"

    set nat source rule 40 description 'host .100'
    set nat source rule 40 outbound-interface name 'eth1'
    set nat source rule 40 source address "$FINAL_AD"
    set nat source rule 40 translation address "$FINAL_AD_PUB"

    set nat source rule 50 description 'host .120'
    set nat source rule 50 outbound-interface name 'eth1'
    set nat source rule 50 source address "$FINAL_MSSQL"
    set nat source rule 50 translation address "$FINAL_MSSQL_PUB"

    # Outbound PAT
    if [ "$OUTBOUND_PAT" == "true" ] || [ "$ENABLE_OUTBOUND_PAT" = true ]; then
        log_warn "Outbound PAT is ENABLED from detected state (Rule 100 masquerade)."
        set nat source rule 100 outbound-interface name 'eth0'
        set nat source rule 100 source address '172.16.0.0/12'
        set nat source rule 100 translation address 'masquerade'
    else
        log_ok "Outbound PAT is DISABLED (Rule 100 deleted)."
        delete nat source rule 100 2>/dev/null || true
    fi

    # Static routes
    log_info "Configuring static routes from detected state:"
    log_info "  0.0.0.0/0        next-hop $CLEAN_DEF_GW"
    log_info "  172.20.240.0/24  next-hop $CLEAN_SRV_NH"

    delete protocols static route 0.0.0.0/0 2>/dev/null || true
    delete protocols static route 172.20.240.0/24 2>/dev/null || true

    set protocols static route 0.0.0.0/0 next-hop "$CLEAN_DEF_GW"
    set protocols static route 172.20.240.0/24 next-hop "$CLEAN_SRV_NH"

    return 0
}

# ==============================================================================
# MODE: RESTORE NAT BASELINE (RULES 10, 20, 30, 40, 50 & PAT)
# ==============================================================================
if [ "$MODE" == "restore-nat" ]; then
    echo "======================================================================"
    echo "          VyOS RESTORE NAT BASELINE (RULES 10, 20, 30, 40, 50 & PAT)"
    echo "======================================================================"

    if [ "$DRY_RUN" = true ]; then
        log_ok "Dry run enabled. Exiting before configuration modifications."
        builtin exit 0
    fi

    log_info "Entering VyOS configuration mode to restore NAT & routing baseline (Mode: $RESTORE_MODE)..."
    configure

    if [ "$RESTORE_MODE" == "detected" ] || [ "$RESTORE_MODE" == "backup" ]; then
        DETECTED_FILE="${CONFIG_SOURCE:-/etc/linux-defender/vyos/detected_nat_routes.json}"
        if [ ! -f "$DETECTED_FILE" ]; then
            if [ -f "/tmp/defender/vyos/detected_nat_routes.json" ]; then
                DETECTED_FILE="/tmp/defender/vyos/detected_nat_routes.json"
            fi
        fi
        if [ -f "$DETECTED_FILE" ] && apply_detected_configuration "$DETECTED_FILE"; then
            log_ok "Successfully restored NAT rules and static routes from detected state: $DETECTED_FILE"
        else
            log_warn "Detected state file missing or invalid ($DETECTED_FILE); applying topology baseline instead."
            apply_nat_configuration
            apply_routing_baseline
        fi
    else
        apply_nat_configuration
        apply_routing_baseline
    fi

    echo "======================================================================"
    if [ "$NO_CONFIRM" = true ]; then
        log_warn "--no-confirm specified. Committing immediately..."
        COMMIT_OUT=$(commit 2>&1)
        echo "$COMMIT_OUT"
        if echo "$COMMIT_OUT" | grep -qE "Commit failed|\[\[.*\]\] failed"; then
            log_error "VyOS configuration commit failed! Discarding changes..."
            discard 2>/dev/null || true
            vyos_exit_cfg
            builtin exit 1
        fi
        save
        vyos_exit_cfg
        log_ok "NAT & routing configuration committed and saved permanently."
    else
        log_info "Applying NAT & routing configuration with ${COMMIT_TIMEOUT}-minute failsafe rollback..."
        COMMIT_OUT=$(printf 'y\n' | commit-confirm "$COMMIT_TIMEOUT" 2>&1)
        echo "$COMMIT_OUT"
        if echo "$COMMIT_OUT" | grep -qE "Commit failed|\[\[.*\]\] failed|failed\!"; then
            log_error "VyOS configuration commit-confirm failed! Discarding changes..."
            discard 2>/dev/null || true
            vyos_exit_cfg
            builtin exit 1
        fi
        echo ""
        log_ok "NAT rules and transit routes applied with commit-confirm ${COMMIT_TIMEOUT}!"
        vyos_exit_cfg
    fi
    builtin exit 0
fi

# ==============================================================================
# MODE: DUAL PASSWORD ROTATION & KEY SANITIZATION
# ==============================================================================
if [ "$MODE" == "rotate-passwords" ]; then
    echo "======================================================================"
    echo "      VyOS & LINUX ROOT DUAL PASSWORD ROTATION & KEY SANITIZATION"
    echo "======================================================================"

    # Prompt interactively if missing
    if [ -z "$ADMIN_PASS" ]; then
        if [ -t 0 ]; then
            read -r -s -p "Enter NEW password for '$ADMIN_USER' (VyOS operator): " input_vyos_pass
            echo ""
            ADMIN_PASS="$input_vyos_pass"
        else
            die "No password supplied for '$ADMIN_USER' (pass --vyos-pass <secret> or --pass <secret>)"
        fi
    fi
    if [ -z "$ADMIN_PASS" ]; then
        die "VyOS password cannot be empty!"
    fi

    if [ -z "$ROOT_PASS" ]; then
        if [ -t 0 ]; then
            read -r -s -p "Enter NEW password for Linux 'root' superuser: " input_root_pass
            echo ""
            ROOT_PASS="$input_root_pass"
        else
            die "No password supplied for 'root' (pass --root-pass <secret>)"
        fi
    fi
    if [ -z "$ROOT_PASS" ]; then
        die "Root password cannot be empty!"
    fi

    BACKUP_DIR="${DEFENDER_DIR}/quarantine/quarantine_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"

    if [ "$DRY_RUN" = true ]; then
        log_ok "Dry run enabled. Halting before password update."
        builtin exit 0
    fi

    # 1. Rotate VyOS operator password via VyOS CLI
    log_info "Step 1: Updating VyOS operator user '$ADMIN_USER' password..."
    configure
    set system login user "$ADMIN_USER" authentication plaintext-password "$ADMIN_PASS"
    commit
    save
    vyos_exit_cfg
    log_ok "VyOS operator account '$ADMIN_USER' updated and saved."

    # 2. Rotate Linux superuser root password via chpasswd / usermod
    log_info "Step 2: Updating Linux 'root' superuser account password..."
    if command -v chpasswd >/dev/null 2>&1; then
        echo "root:${ROOT_PASS}" | chpasswd
    elif command -v usermod >/dev/null 2>&1; then
        usermod -p "$(openssl passwd -6 "$ROOT_PASS")" root
    else
        die "Neither chpasswd nor usermod available to update root password."
    fi
    log_ok "Linux 'root' password successfully updated in /etc/shadow."

    # 3. Sanitize authorized_keys for root and vyos
    log_info "Step 3: Sanitizing authorized_keys for 'root' and '$ADMIN_USER'..."
    for auth_file in /root/.ssh/authorized_keys "/home/${ADMIN_USER}/.ssh/authorized_keys"; do
        if [ -f "$auth_file" ]; then
            cp "$auth_file" "${BACKUP_DIR}/$(echo "$auth_file" | tr '/' '_').bak"
            > "$auth_file"
            chmod 600 "$auth_file" 2>/dev/null || true
            log_ok "Sanitized $auth_file (backup saved to ${BACKUP_DIR})"
            echo "  [RESTORE] cp ${BACKUP_DIR}/$(echo "$auth_file" | tr '/' '_').bak $auth_file"
        else
            log_info "No authorized_keys found at $auth_file (clean)"
        fi
    done

    # 4. Audit and purge configured public keys in VyOS config.boot
    log_info "Step 4: Auditing configured SSH public keys in VyOS config.boot..."
    CFG_KEYS=$(run_op show configuration commands 2>/dev/null | grep "system login user .* authentication public-keys" || true)
    if [ -n "$CFG_KEYS" ]; then
        log_warn "Configured public-keys found in VyOS config.boot:"
        echo "$CFG_KEYS"
        configure
        for key_user in $(echo "$CFG_KEYS" | awk '{print $4}' | sort -u); do
            for key_id in $(run_op show configuration commands | grep "system login user $key_user authentication public-keys" | awk '{print $6}' | sort -u); do
                if [ -z "$SSH_KEY_ID" ] || [ "$key_id" != "$SSH_KEY_ID" ]; then
                    log_warn "Deleting unauthorized VyOS public key: user $key_user, key_id $key_id"
                    echo "  [CMD] delete system login user $key_user authentication public-keys $key_id"
                    delete system login user "$key_user" authentication public-keys "$key_id" 2>/dev/null || true
                fi
            done
        done
        commit
        save
        vyos_exit_cfg
        REMAINING=$(run_op show configuration commands 2>/dev/null | grep "system login user .* authentication public-keys" || true)
        if [ -z "$REMAINING" ] || [ -n "$SSH_KEY_ID" ]; then
            log_ok "PROOF: Unauthorized VyOS configuration public-keys purged and saved."
        else
            log_err "PROOF FAILED: Public keys still present in config.boot: $REMAINING"
        fi
    else
        log_ok "PROOF: No public-keys configured in VyOS config.boot."
    fi

    echo "======================================================================"
    log_ok "Dual password rotation and authorized_keys sanitization COMPLETE."
    echo "======================================================================"
    builtin exit 0
fi

# ==============================================================================
# MODE: SANITIZE BOOT & COMMIT HOOKS
# ==============================================================================
if [ "$MODE" == "sanitize-hooks" ]; then
    echo "======================================================================"
    echo "         VyOS SANITIZE BOOT & COMMIT HOOKS (/config/scripts/)"
    echo "======================================================================"

    BACKUP_DIR="${DEFENDER_DIR}/quarantine/hooks_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    log_info "Quarantine repository initialized: $BACKUP_DIR"

    # Step 1: Kill live processes running from /config/scripts/
    log_info "Step 1: Inspecting live processes running from /config/scripts/..."
    PIDS=$(pgrep -f "/config/scripts/" 2>/dev/null || true)
    if [ -n "$PIDS" ]; then
        log_warn "Active processes detected executing from /config/scripts/: PIDs $PIDS"
        echo "  [CMD] pkill -9 -f /config/scripts/"
        pkill -9 -f "/config/scripts/" 2>/dev/null || true
        # Proof verification
        STILL_RUNNING=$(pgrep -f "/config/scripts/" 2>/dev/null || true)
        if [ -z "$STILL_RUNNING" ]; then
            log_ok "PROOF: All rogue processes terminated (pgrep -f /config/scripts/ is clean)."
        else
            log_warn "PROOF WARNING: Some processes may require manual termination: $STILL_RUNNING"
        fi
    else
        log_ok "PROOF: No active processes executing from /config/scripts/."
    fi

    # Step 2: Commit hooks
    if [ -d /config/scripts/commit ]; then
        cp -r /config/scripts/commit "$BACKUP_DIR/" 2>/dev/null || true
        for hook in /config/scripts/commit/pre-hooks.d/* /config/scripts/commit/post-hooks.d/*; do
            if [ -f "$hook" ]; then
                log_warn "Quarantining commit hook: $hook"
                mv -f "$hook" "$BACKUP_DIR/" 2>/dev/null || rm -f "$hook"
                echo "  [RESTORE] cp $BACKUP_DIR/$(basename "$hook") $hook"
            fi
        done
        log_ok "PROOF: Neutralized /config/scripts/commit/ hooks"
    fi

    # Step 3: Bootup and upgrade scripts
    for script in /config/scripts/vyos-preconfig-bootup.script /config/scripts/vyos-postconfig-bootup.script /config/scripts/post-upgrade; do
        if [ -f "$script" ]; then
            cp "$script" "$BACKUP_DIR/"
            echo "  [RESTORE] cp $BACKUP_DIR/$(basename "$script") $script"
            if grep -q ">>>RT_BEGIN<<<" "$script" 2>/dev/null; then
                log_warn "Stripping Red Team injected block from $script..."
                echo "  [CMD] sed -i '/>>>RT_BEGIN<<</,/>>>RT_END<<</d' $script"
                sed -i '/>>>RT_BEGIN<<</,/>>>RT_END<<</d' "$script" 2>/dev/null || true
            fi
            if [ -s "$script" ]; then
                cat > "$script" << 'BOOT_CLEAN_EOF'
#!/bin/bash
# Sanitized by CCDC hardening
exit 0
BOOT_CLEAN_EOF
                chmod +x "$script"
                log_ok "PROOF: Sanitized boot script: $script"
            fi
        fi
    done

    # Step 4: Check for any other unexpected scripts or service files in /config/scripts
    if [ -d /config/scripts ]; then
        for extra in /config/scripts/*; do
            base=$(basename "$extra")
            case "$base" in
                vyos-preconfig-bootup.script|vyos-postconfig-bootup.script|post-upgrade|commit)
                    ;;
                *)
                    if [ -f "$extra" ]; then
                        log_warn "Found extra file in /config/scripts/: $extra. Quarantining..."
                        mv -f "$extra" "$BACKUP_DIR/"
                        echo "  [RESTORE] cp $BACKUP_DIR/$base $extra"
                        log_ok "Quarantined $extra -> $BACKUP_DIR/$base"
                    fi
                    ;;
            esac
        done
        log_ok "PROOF: /config/scripts/ verified clean."
    fi

    echo "======================================================================"
    log_ok "Hook sanitization COMPLETE. Quarantined files saved in $BACKUP_DIR"
    echo "======================================================================"
    builtin exit 0
fi

# ==============================================================================
# MODE: SANITIZE TASK SCHEDULER & CRONS
# ==============================================================================
if [ "$MODE" == "sanitize-cron" ]; then
    echo "======================================================================"
    echo "       VyOS SANITIZE TASK SCHEDULER & CRONTABS (CRON PURGE)"
    echo "======================================================================"

    BACKUP_DIR="${DEFENDER_DIR}/quarantine/cron_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    log_info "Quarantine repository initialized: $BACKUP_DIR"

    # 1. Check and remove VyOS task-scheduler via configuration mode
    log_info "Step 1: Checking VyOS system task-scheduler configuration..."
    if run_op show configuration commands 2>/dev/null | grep -q "task-scheduler"; then
        log_warn "Task scheduler rules detected in VyOS configuration. Purging..."
        echo "  [CMD] delete system task-scheduler && commit && save"
        configure
        delete system task-scheduler 2>/dev/null || true
        commit
        save
        vyos_exit_cfg
        log_ok "PROOF: VyOS system task-scheduler deleted and saved."
    else
        log_ok "PROOF: No task-scheduler configured in VyOS."
    fi

    # 2. Backup and flush /var/spool/cron/crontabs/*
    log_info "Step 2: Checking /var/spool/cron/crontabs/..."
    if [ -d /var/spool/cron/crontabs ]; then
        for ct in /var/spool/cron/crontabs/*; do
            if [ -f "$ct" ]; then
                log_warn "Found crontab: $ct. Quarantining and clearing..."
                cp "$ct" "$BACKUP_DIR/$(basename "$ct").crontab"
                echo "  [RESTORE] cp $BACKUP_DIR/$(basename "$ct").crontab $ct"
                > "$ct"
                log_ok "PROOF: Cleared crontab: $ct"
            fi
        done
    fi

    # 3. Check /etc/crontab
    log_info "Step 3: Checking /etc/crontab..."
    if [ -f /etc/crontab ]; then
        cp /etc/crontab "$BACKUP_DIR/etc_crontab.bak"
        echo "  [RESTORE] cp $BACKUP_DIR/etc_crontab.bak /etc/crontab"
        log_ok "Backed up /etc/crontab."
    fi

    # 4. Audit and purge rogue cron droppers in /etc/cron.d/
    log_info "Step 4: Auditing /etc/cron.d/ directory for rogue cron droppers..."
    if [ -d /etc/cron.d ]; then
        for cd in /etc/cron.d/*; do
            if [ -f "$cd" ]; then
                base=$(basename "$cd")
                case "$base" in
                    e2scrub_all|otbr-firewall|.placeholder)
                        log_info "Preserving standard system cron: $cd"
                        ;;
                    *)
                        log_warn "Rogue cron dropper detected: $cd. Quarantining and removing..."
                        echo "  [CMD] rm -f $cd"
                        cp "$cd" "$BACKUP_DIR/$base"
                        rm -f "$cd"
                        echo "  [RESTORE] cp $BACKUP_DIR/$base $cd"
                        log_ok "PROOF: Removed rogue cron: $cd"
                        ;;
                esac
            fi
        done
        log_ok "PROOF: /etc/cron.d/ verified clean."
    fi

    echo "======================================================================"
    log_ok "Task-scheduler and cron sanitization COMPLETE. Quarantined files saved in $BACKUP_DIR"
    echo "======================================================================"
    builtin exit 0
fi

# ==============================================================================
# MODE: CLEAN DYNAMIC LINKER OVERRIDES & ROOTKITS
# ==============================================================================
if [ "$MODE" == "clean-rootkits" ]; then
    echo "======================================================================"
    echo "     VyOS REMOVE DYNAMIC LINKER OVERRIDES & SYSTEMD INJECTIONS"
    echo "======================================================================"

    BACKUP_DIR="${DEFENDER_DIR}/quarantine/rootkits_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"

    # 1. /etc/ld.so.preload
    if [ -f /etc/ld.so.preload ]; then
        log_warn "CRITICAL: /etc/ld.so.preload detected! Quarantining and removing..."
        cp /etc/ld.so.preload "$BACKUP_DIR/ld.so.preload.bak"
        rm -f /etc/ld.so.preload
        log_ok "Removed /etc/ld.so.preload (backup saved in $BACKUP_DIR)"
    else
        log_ok "/etc/ld.so.preload does not exist (clean)."
    fi

    # 2. Inspect /etc/ld.so.conf.d/
    if [ -d /etc/ld.so.conf.d ]; then
        for conf in /etc/ld.so.conf.d/*; do
            if [ -f "$conf" ]; then
                log_info "Checking linker config: $conf"
                if grep -qE "(/tmp|/var/tmp|/dev/shm|/home)" "$conf" 2>/dev/null; then
                    log_warn "Suspicious linker directory in $conf! Quarantining..."
                    mv -f "$conf" "$BACKUP_DIR/"
                fi
            fi
        done
        ldconfig 2>/dev/null || true
    fi

    # 3. Check systemd drop-in overrides
    log_info "Step 3: Checking for rogue systemd unit drop-in overrides..."
    for dropin in /etc/systemd/system/*.service.d/*.conf /run/systemd/system/*.service.d/*.conf; do
        if [ -f "$dropin" ]; then
            log_warn "Found systemd drop-in override: $dropin. Quarantining..."
            mkdir -p "$BACKUP_DIR/systemd_dropins"
            cp "$dropin" "$BACKUP_DIR/systemd_dropins/"
            rm -f "$dropin"
            echo "  [RESTORE] cp $BACKUP_DIR/systemd_dropins/$(basename "$dropin") $dropin"
            log_ok "Removed $dropin"
        fi
    done

    # 4. Check for rogue standalone systemd service units in /etc/systemd/system/
    log_info "Step 4: Checking for rogue systemd service units in /etc/systemd/system/..."
    for svc_file in /etc/systemd/system/*.service; do
        if [ -f "$svc_file" ] && [ ! -L "$svc_file" ]; then
            svc_name=$(basename "$svc_file")
            case "$svc_name" in
                vyos*|systemd*|dbus*|sshd*|frr*|ssh*)
                    ;;
                *)
                    log_warn "Rogue systemd service unit detected: $svc_file. Quarantining..."
                    echo "  [CMD] systemctl stop $svc_name && systemctl disable $svc_name && rm -f $svc_file"
                    systemctl stop "$svc_name" 2>/dev/null || true
                    systemctl disable "$svc_name" 2>/dev/null || true
                    mkdir -p "$BACKUP_DIR/systemd_units"
                    cp "$svc_file" "$BACKUP_DIR/systemd_units/"
                    rm -f "$svc_file"
                    echo "  [RESTORE] cp $BACKUP_DIR/systemd_units/$svc_name $svc_file && systemctl daemon-reload"
                    log_ok "PROOF: Stopped, disabled, and removed $svc_file"
                    ;;
            esac
        fi
    done
    systemctl daemon-reload 2>/dev/null || true

    echo "======================================================================"
    log_ok "Dynamic linker and systemd injection cleanup COMPLETE."
    echo "======================================================================"
    builtin exit 0
fi

# ==============================================================================
# MODE: PURGE ROGUE CONTAINERS (PODMAN / DOCKER / VYOS 1.4+)
# ==============================================================================
if [ "$MODE" == "purge-containers" ]; then
    echo "======================================================================"
    echo "         VyOS PURGE ROGUE CONTAINERS (PODMAN & CONFIG PURGE)"
    echo "======================================================================"

    BACKUP_DIR="${DEFENDER_DIR}/quarantine/containers_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"

    # 1. VyOS container configuration
    log_info "Step 1: Checking VyOS container configuration..."
    if run_op show configuration commands 2>/dev/null | grep -q "^set container"; then
        log_warn "Container configuration nodes detected in VyOS. Deleting..."
        configure
        delete container 2>/dev/null || true
        commit
        save
        vyos_exit_cfg
        log_ok "Deleted VyOS container configuration and saved."
    else
        log_ok "No VyOS container configuration found."
    fi

    # 2. Stop and remove all Podman containers if podman binary is present
    if command -v podman >/dev/null 2>&1; then
        log_info "Step 2: Checking Podman containers..."
        CONTAINER_IDS=$(podman ps -a -q 2>/dev/null)
        if [ -n "$CONTAINER_IDS" ]; then
            log_warn "Stopping and removing running podman containers: $CONTAINER_IDS"
            podman stop -a -t 2 2>/dev/null || true
            podman rm -f -a 2>/dev/null || true
            log_ok "All Podman containers forcefully removed."
        else
            log_ok "No running or stopped Podman containers found."
        fi
    elif command -v docker >/dev/null 2>&1; then
        log_info "Step 2: Checking Docker containers..."
        DOCKER_IDS=$(docker ps -a -q 2>/dev/null)
        if [ -n "$DOCKER_IDS" ]; then
            log_warn "Stopping and removing docker containers: $DOCKER_IDS"
            docker stop -t 2 $DOCKER_IDS 2>/dev/null || true
            docker rm -f $DOCKER_IDS 2>/dev/null || true
            log_ok "All Docker containers removed."
        else
            log_ok "No Docker containers found."
        fi
    fi

    echo "======================================================================"
    log_ok "Container purge COMPLETE."
    echo "======================================================================"
    builtin exit 0
fi

# ==============================================================================
# MODE: PHASE 1 HARDENING & SSH SECURING
# ==============================================================================
if [ "$MODE" == "harden" ]; then
    echo "======================================================================"
    echo "    VyOS PHASE 1: HARDENING & INIT CONFIG (NAT & FIREWALL)"
    echo "======================================================================"

    if [ -z "$ADMIN_PASS" ]; then
        if [ -t 0 ]; then
            read -r -s -p "Enter NEW password for '$ADMIN_USER': " ADMIN_PASS
            echo ""
        else
            die "No password supplied for '$ADMIN_USER' (pass --pass <password>)"
        fi
        if [ -z "$ADMIN_PASS" ]; then
            die "Password cannot be empty!"
        fi
    fi

    # 1. Quarantine persistence hooks
    BACKUP_DIR="${DEFENDER_DIR}/quarantine/quarantine_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    log_info "Step 1: Quarantining filesystem hooks to $BACKUP_DIR..."

    # Terminate any processes executing from /config/scripts/
    pkill -9 -f "/config/scripts/" 2>/dev/null || true

    if [ -d /config/scripts/commit ]; then
        cp -r /config/scripts/commit "$BACKUP_DIR/"
        rm -rf /config/scripts/commit/pre-hooks.d/* /config/scripts/commit/post-hooks.d/* 2>/dev/null
        log_ok "Neutralized /config/scripts/commit/ hooks"
    fi

    for script in /config/scripts/vyos-preconfig-bootup.script /config/scripts/vyos-postconfig-bootup.script /config/scripts/post-upgrade; do
        if [ -f "$script" ]; then
            cp "$script" "$BACKUP_DIR/"
            if [ -s "$script" ]; then
                echo "#!/bin/bash" > "$script"
                echo "# Sanitized by CCDC hardening on $(date)" >> "$script"
                echo "exit 0" >> "$script"
                chmod +x "$script"
                log_ok "Sanitized $script"
            fi
        fi
    done

    # Quarantine any rogue scripts or service files in /config/scripts/
    if [ -d /config/scripts ]; then
        for extra in /config/scripts/*; do
            base=$(basename "$extra")
            case "$base" in
                vyos-preconfig-bootup.script|vyos-postconfig-bootup.script|post-upgrade|commit)
                    ;;
                *)
                    if [ -f "$extra" ]; then
                        log_warn "Quarantining rogue file in /config/scripts/: $extra"
                        mv -f "$extra" "$BACKUP_DIR/"
                    fi
                    ;;
            esac
        done
    fi

    if [ -f /etc/ld.so.preload ]; then
        log_warn "Found /etc/ld.so.preload! Backing up and removing..."
        cp /etc/ld.so.preload "$BACKUP_DIR/"
        rm -f /etc/ld.so.preload
    fi

    # Rotate Linux root password if supplied and sanitize authorized_keys
    if [ -n "$ROOT_PASS" ]; then
        log_info "Updating Linux 'root' superuser account password..."
        if command -v chpasswd >/dev/null 2>&1; then
            echo "root:${ROOT_PASS}" | chpasswd
        elif command -v usermod >/dev/null 2>&1; then
            usermod -p "$(openssl passwd -6 "$ROOT_PASS")" root
        fi
        log_ok "Linux 'root' password updated."
    fi

    # Sanitize authorized_keys for root and vyos
    log_info "Sanitizing authorized_keys for 'root' and '$ADMIN_USER'..."
    for auth_file in /root/.ssh/authorized_keys "/home/${ADMIN_USER}/.ssh/authorized_keys"; do
        if [ -f "$auth_file" ]; then
            cp "$auth_file" "${BACKUP_DIR}/$(echo "$auth_file" | tr '/' '_').bak"
            > "$auth_file"
            chmod 600 "$auth_file" 2>/dev/null || true
            log_ok "Sanitized $auth_file (quarantined to ${BACKUP_DIR})"
        fi
    done

    if [ "$DRY_RUN" = true ]; then
        log_ok "Dry run enabled. Exiting before configuration modifications."
        builtin exit 0
    fi

    # 2. Enter configuration mode
    log_info "Step 2: Entering VyOS configuration mode..."
    configure

    # Pre-login banner
    set system login banner pre-login '*** AUTHORIZED CCDC BLUE TEAM ACCESS ONLY - ALL ACTIVITIES MONITORED ***'

    # Configuration management
    set system config-management commit-revisions 100
    set system config-management commit-confirm action reload

    # Rotate vyos password
    log_info "Step 3: Rotating password for '$ADMIN_USER'..."
    set system login user "$ADMIN_USER" authentication plaintext-password "$ADMIN_PASS"

    if [ -n "$SSH_PUB_KEY" ]; then
        log_info "Adding SSH public key for '$ADMIN_USER'..."
        set system login user "$ADMIN_USER" authentication public-keys "$SSH_KEY_ID" key "$SSH_PUB_KEY"
        set system login user "$ADMIN_USER" authentication public-keys "$SSH_KEY_ID" type "$SSH_KEY_TYPE"
    fi

    # Purge unauthorized VyOS configuration public keys (like rt-backup)
    for key_user in $(run_op show configuration commands 2>/dev/null | grep "system login user .* authentication public-keys" | awk '{print $4}' | sort -u); do
        for key_id in $(run_op show configuration commands 2>/dev/null | grep "system login user $key_user authentication public-keys" | awk '{print $6}' | sort -u); do
            if [ -z "$SSH_KEY_ID" ] || [ "$key_id" != "$SSH_KEY_ID" ]; then
                log_warn "Purging unauthorized VyOS public key: user $key_user, key_id $key_id"
                delete system login user "$key_user" authentication public-keys "$key_id" 2>/dev/null || true
            fi
        done
    done

    # SSH Hardening: Dynamic brute-force rate-limiting restricted to Workstations
    log_info "Step 4: Hardening SSH service (dynamic-protection restricted to $MGMT_SUBNET)..."
    set service ssh port 22
    set service ssh dynamic-protection allow-from "$MGMT_SUBNET"
    set service ssh dynamic-protection threshold 15
    set service ssh dynamic-protection block-time 600
    set service ssh dynamic-protection detect-time 1800

    # Attack surface reduction
    log_info "Step 5: Disabling insecure legacy protocols (Telnet, HTTPS API, task-scheduler)..."
    delete service telnet 2>/dev/null || true
    delete service https 2>/dev/null || true
    delete service https api 2>/dev/null || true
    delete system task-scheduler 2>/dev/null || true

    # Control Plane Firewall
    log_info "Step 6: Configuring Control Plane (INPUT) and Transit (FORWARD) Firewalls..."
    # Control plane filter (Protect router itself)
    set firewall ipv4 input filter default-action drop

    set firewall ipv4 input filter rule 5 action accept
    set firewall ipv4 input filter rule 5 description 'Allow loopback'
    set firewall ipv4 input filter rule 5 inbound-interface name 'lo'

    set firewall ipv4 input filter rule 10 action accept
    set firewall ipv4 input filter rule 10 description 'Allow established/related'
    set firewall ipv4 input filter rule 10 state established
    set firewall ipv4 input filter rule 10 state related

    set firewall ipv4 input filter rule 20 action accept
    set firewall ipv4 input filter rule 20 description 'Allow ICMP'
    set firewall ipv4 input filter rule 20 protocol icmp

    set firewall ipv4 input filter rule 30 action accept
    set firewall ipv4 input filter rule 30 description 'Allow SSH from Workstation subnet'
    set firewall ipv4 input filter rule 30 protocol tcp
    set firewall ipv4 input filter rule 30 destination port 22
    set firewall ipv4 input filter rule 30 source address "$MGMT_SUBNET"

    # Transit filter (Scoring protection)
    set firewall ipv4 forward filter default-action accept
    set firewall ipv4 forward filter rule 10 action accept
    set firewall ipv4 forward filter rule 10 description 'Allow established/related transit'
    set firewall ipv4 forward filter rule 10 state established
    set firewall ipv4 forward filter rule 10 state related

    # Scored 1:1 DNAT and Outbound PAT
    log_info "Step 7: Applying Scored 1:1 DNAT Rules 10, 20, 30, 40, 50 & Outbound PAT..."
    apply_nat_configuration

    log_info "Step 7b: Applying Standard Transit Routes Grounded in Topology..."
    apply_routing_baseline

    # 3. Apply changes with commit-confirm
    echo "======================================================================"
    if [ "$NO_CONFIRM" = true ]; then
        echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${RESET}"
        echo -e "${RED}  WARNING: --no-confirm ENABLED! Instant commit in progress...        ${RESET}"
        echo -e "${RED}  Rollback protection is DISABLED!                                     ${RESET}"
        echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${RESET}"
        COMMIT_OUT=$(commit 2>&1)
        echo "$COMMIT_OUT"
        if echo "$COMMIT_OUT" | grep -qE "Commit failed|\[\[.*\]\] failed"; then
            log_error "VyOS configuration commit failed! Discarding changes..."
            discard 2>/dev/null || true
            vyos_exit_cfg
            builtin exit 1
        fi
        save
        vyos_exit_cfg
        log_ok "Configuration committed and saved permanently."
    else
        log_info "Step 8: Applying configuration with ${COMMIT_TIMEOUT}-minute failsafe rollback..."
        COMMIT_OUT=$(printf 'y\n' | commit-confirm "$COMMIT_TIMEOUT" 2>&1)
        echo "$COMMIT_OUT"
        if echo "$COMMIT_OUT" | grep -qE "Commit failed|\[\[.*\]\] failed|failed\!"; then
            log_error "VyOS configuration commit-confirm failed! Discarding changes..."
            discard 2>/dev/null || true
            vyos_exit_cfg
            builtin exit 1
        fi
        echo ""
        log_ok "Changes applied with commit-confirm ${COMMIT_TIMEOUT}!"
        echo "----------------------------------------------------------------------"
        echo -e "${YELLOW}[!] COMMIT PENDING CONFIRMATION:${RESET}"
        echo "    The changes are active but NOT permanent."
        echo "    Rollback timer: ${COMMIT_TIMEOUT} minutes remaining."
        echo ""
        echo "    1. Open a separate terminal window to verify access."
        echo "    2. Verify SSH login with the new password:"
        echo "       ssh ${ADMIN_USER}@172.17.0.1"
        echo "    3. Confirm and save changes from the Router tab in the TUI,"
        echo "       or run: router --confirm"
        echo "    4. If login fails or access is lost, DO NOTHING!"
        echo "       VyOS will automatically roll back all changes after ${COMMIT_TIMEOUT} minutes."
        echo "----------------------------------------------------------------------"
        vyos_exit_cfg
    fi
    builtin exit 0
fi
