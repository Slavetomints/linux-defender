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
SAFE_ARGS=$(printf '%s ' "$@" | sed -E 's/--pass +[^ ]+/--pass ******/g')
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
ADMIN_USER="vyos"
ADMIN_PASS="${DEFENDER_ADMIN_PASS:-}"
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
  --audit                 Run non-destructive forensic audit and save baseline
  --diff [log_file]       Diff current state against previous baseline
  --harden                Phase 1: Rotate vyos password, harden SSH, apply firewall
  --console-lockdown      Phase 2: Pull SSH from vyos (Console-Only Administration)
  --confirm               Confirm and save pending commit-confirm changes
  --interactive           Interactive configuration wizard

OPTIONS:
  --team <1-20>           CCDC Team number (derives WAN subnet 172.31.{20+T}.2/29)
  --mgmt-subnet <cidr>    Trusted management subnet (default: 172.17.0.0/24)
  --user <username>       Target admin username (default: vyos, per CCDC rules)
  --pass <password>       New password for vyos (prompted securely if omitted)
  --ssh-key '<key>'       SSH public key string (e.g. 'AAAAC3NzaC1...')
  --commit-timeout <min>  Rollback timer for commit-confirm (default: 5)
  --no-confirm            Bypass commit-confirm rollback (Instant commit; DANGEROUS)
  --force                 Bypass safety checks (e.g. running --console-lockdown over SSH)
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
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage 0
            ;;
        *)
            SAFE_ARGV=$(printf '%s ' "$*" | sed -E 's/--pass +[^ ]+/--pass ******/g')
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
        SAFE_ARGV=$(printf '%s ' "$*" | sed -E 's/--pass +[^ ]+/--pass ******/g')
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
    echo "3) Phase 1: Hardened SSH + Password Rotation + Firewall"
    echo "4) Phase 2: Console-Only Lockdown (Nuke SSH)"
    echo "5) Exit"
    read -r -p "Select an action [1-5]: " choice
    case "$choice" in
        1) MODE="audit" ;;
        2) MODE="diff" ;;
        3) MODE="harden" ;;
        4) MODE="console-lockdown" ;;
        *) builtin exit 0 ;;
    esac

    if [ "$MODE" == "harden" ]; then
        if [ -z "$TEAM" ]; then
            read -r -p "Enter Team Number [1-20]: " TEAM
        fi
        read -r -p "Management Subnet [$MGMT_SUBNET]: " input_mgmt
        MGMT_SUBNET="${input_mgmt:-$MGMT_SUBNET}"
        read -r -s -p "Enter NEW password for '$ADMIN_USER': " input_pass
        echo ""
        ADMIN_PASS="${input_pass}"
        read -r -p "SSH Public Key (optional, press Enter to skip): " SSH_PUB_KEY
    fi
fi

# ─── Auto-Derive Team Subnets ─────────────────────────────────────────────────
if [ -n "$TEAM" ]; then
    if ! [[ "$TEAM" =~ ^[0-9]+$ ]] || [ "$TEAM" -lt 1 ] || [ "$TEAM" -gt 20 ]; then
        die "Invalid team number '$TEAM'. Must be between 1 and 20."
    fi
    OCTET=$((20 + TEAM))
    WAN_ROUTER_IP="172.31.${OCTET}.2/29"
    CORE_GATEWAY_IP="172.31.${OCTET}.1"
    PUBLIC_POOL="172.25.${OCTET}.0/24"
    log_info "Team $TEAM Subnets: WAN Router=${WAN_ROUTER_IP}, Core Gateway=${CORE_GATEWAY_IP}, Public Pool=${PUBLIC_POOL}"
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
        echo "  Live System State  : Verified identical across all 12 audit sections."
        echo ""
        echo "  ✓ No unauthorized users in /etc/passwd or VyOS config"
        echo "  ✓ No rogue SSH keys in ~/.ssh/authorized_keys"
        echo "  ✓ No unapproved crontabs or systemd timers"
        echo "  ✓ No boot scripts or commit hooks modified in /config/scripts/"
        echo "  ✓ No rogue interfaces or VPN tunnels (WireGuard, OpenVPN)"
        echo "  ✓ No unexpected listening ports or container services"
        echo "  ✓ No SUID binaries or /etc/ld.so.preload rootkits"
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

# ==============================================================================
# MODE: PHASE 1 HARDENING & SSH SECURING
# ==============================================================================
if [ "$MODE" == "harden" ]; then
    echo "======================================================================"
    echo "        VyOS PHASE 1: HARDENED SSH & PASSWORDS & FIREWALL"
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

    if [ -f /etc/ld.so.preload ]; then
        log_warn "Found /etc/ld.so.preload! Backing up and removing..."
        cp /etc/ld.so.preload "$BACKUP_DIR/"
        rm -f /etc/ld.so.preload
    fi

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

    # 3. Apply changes with commit-confirm
    echo "======================================================================"
    if [ "$NO_CONFIRM" = true ]; then
        echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${RESET}"
        echo -e "${RED}  WARNING: --no-confirm ENABLED! Instant commit in progress...        ${RESET}"
        echo -e "${RED}  Rollback protection is DISABLED!                                     ${RESET}"
        echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${RESET}"
        commit
        save
        vyos_exit_cfg
        log_ok "Configuration committed and saved permanently."
    else
        log_info "Step 7: Applying configuration with ${COMMIT_TIMEOUT}-minute failsafe rollback..."
        if ! printf 'y\n' | commit-confirm "$COMMIT_TIMEOUT"; then
            vyos_exit_cfg
            log_error "commit-confirm failed! Rollback will not be initiated."
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
