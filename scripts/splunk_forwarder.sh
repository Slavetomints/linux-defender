#!/usr/bin/env bash
# splunk_forwarder.sh — Install and configure Splunk Universal Forwarder
# Run as root: sudo bash splunk_forwarder.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()    { echo -e "${GREEN}[ OK ]${RESET}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_error() { echo -e "${RED}[ERR ]${RESET}  $*" >&2; }
die()       { log_error "$*"; exit 1; }

[[ $EUID -eq 0 ]] || die "Must run as root (use: sudo bash $0)"

SPLUNK_BIN="/opt/splunkforwarder/bin/splunk"
SPLUNK_LOCAL="/opt/splunkforwarder/etc/system/local"
INDEXER_IP=""
INDEXER_PORT="9997"
BOX_TYPE=""

# ─── 1. Check if already installed ───────────────────────────────────────────
echo
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║   Splunk Universal Forwarder — CCDC Team                 ║${RESET}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}"
echo

echo -e "${BOLD}━━━ Step 1: Check Installation Status ━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo

if [[ -x "$SPLUNK_BIN" ]]; then
    log_ok "Splunk Universal Forwarder is already installed."
    if "$SPLUNK_BIN" status --accept-license --answer-yes --no-prompt 2>/dev/null | grep -q "running"; then
        log_ok "Service is running."
    else
        log_warn "Service is installed but not running."
    fi
    echo
    read -rp "$(echo -e "${BOLD}Reconfigure existing installation? [y/n]:${RESET} ")" reconfigure
    [[ "${reconfigure,,}" =~ ^y ]] || { echo "Aborted."; exit 0; }
else
    log_warn "Splunk Universal Forwarder not found at /opt/splunkforwarder"
    echo
    echo -e "${BOLD}━━━ Step 2: Locate Installation Package ━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo
    echo -e "  Splunk requires authentication to download. Get the package from:"
    echo -e "  ${CYAN}https://www.splunk.com/en_us/download/universal-forwarder.html${RESET}"
    echo -e "  Download the .deb (Ubuntu/Debian) or .rpm (RHEL/Fedora/CentOS) package"
    echo -e "  and place it in /tmp/ or another accessible location."
    echo

    # Look for a package in common locations
    PACKAGE=""
    for candidate in \
        /tmp/splunk*.deb /tmp/splunkforwarder*.deb \
        /tmp/splunk*.rpm /tmp/splunkforwarder*.rpm \
        /var/cache/apt/archives/splunk*.deb \
        /root/splunk*.deb /root/splunk*.rpm \
        /home/*/splunk*.deb /home/*/splunk*.rpm; do
        # glob may not expand — use find
        true
    done

    mapfile -t found < <(find /tmp /root /var/cache/apt/archives -maxdepth 1 \
        \( -name "splunk*.deb" -o -name "splunkforwarder*.deb" \
           -o -name "splunk*.rpm" -o -name "splunkforwarder*.rpm" \) 2>/dev/null | sort)

    if [[ ${#found[@]} -gt 0 ]]; then
        log_info "Found package(s):"
        for i in "${!found[@]}"; do
            printf "    %d) %s\n" "$((i+1))" "${found[$i]}"
        done
        echo
        read -rp "$(echo -e "${BOLD}Select package number, or enter a custom path:${RESET} ")" selection

        if [[ "$selection" =~ ^[0-9]+$ ]] && [[ "$selection" -ge 1 ]] && [[ "$selection" -le "${#found[@]}" ]]; then
            PACKAGE="${found[$((selection-1))]}"
        else
            PACKAGE="$selection"
        fi
    else
        log_warn "No package found automatically."
        read -rp "$(echo -e "${BOLD}Enter full path to the Splunk forwarder package:${RESET} ")" PACKAGE
    fi

    [[ -f "$PACKAGE" ]] || die "Package not found: $PACKAGE"
    log_ok "Using package: $PACKAGE"

    echo
    echo -e "${BOLD}━━━ Step 3: Installing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo

    case "$PACKAGE" in
        *.deb)
            log_info "Installing with dpkg…"
            dpkg -i "$PACKAGE" || {
                log_warn "dpkg reported errors — attempting apt-get -f install to fix dependencies"
                apt-get -f install -y
            }
            ;;
        *.rpm)
            if command -v dnf &>/dev/null; then
                log_info "Installing with dnf…"
                dnf install -y "$PACKAGE"
            elif command -v yum &>/dev/null; then
                log_info "Installing with yum…"
                yum install -y "$PACKAGE"
            else
                log_info "Installing with rpm…"
                rpm -ivh "$PACKAGE"
            fi
            ;;
        *)
            die "Unknown package format: $PACKAGE (expected .deb or .rpm)"
            ;;
    esac

    [[ -x "$SPLUNK_BIN" ]] || die "Installation failed — $SPLUNK_BIN not found after install"
    log_ok "Splunk Universal Forwarder installed."
fi

# ─── 4. Prompt for indexer ────────────────────────────────────────────────────
echo
echo -e "${BOLD}━━━ Step 4: Indexer Configuration ━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo

while true; do
    read -rp "$(echo -e "${BOLD}Splunk indexer IP address:${RESET} ")" INDEXER_IP
    [[ -n "$INDEXER_IP" ]] && break
    echo "IP cannot be empty."
done

read -rp "$(echo -e "${BOLD}Indexer port [${INDEXER_PORT}]:${RESET} ")" port_input
[[ -n "$port_input" ]] && INDEXER_PORT="$port_input"

log_ok "Indexer: ${INDEXER_IP}:${INDEXER_PORT}"

# ─── 5. Box type detection ────────────────────────────────────────────────────
echo
echo -e "${BOLD}━━━ Step 5: Box Type ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo

detect_box_type() {
    if [[ -d /opt/splunk ]]; then
        echo "splunk"; return
    fi
    if [[ -f /etc/postfix/main.cf ]] || command -v postfix &>/dev/null; then
        echo "mail"; return
    fi
    if [[ -d /etc/nginx ]] || [[ -d /etc/apache2 ]] || [[ -d /etc/httpd ]]; then
        echo "web"; return
    fi
    echo "general"
}

DETECTED_TYPE="$(detect_box_type)"
log_info "Auto-detected box type: ${BOLD}${DETECTED_TYPE}${RESET}"
echo
echo -e "  1) web      — Apache/nginx access+error logs, auth, syslog"
echo -e "  2) mail     — mail.log, auth, syslog, roundcube"
echo -e "  3) splunk   — splunkd.log, metrics, web_access, auth"
echo -e "  4) general  — auth, syslog, kern.log"
echo

read -rp "$(echo -e "${BOLD}Box type [detected=${DETECTED_TYPE}, Enter to accept]:${RESET} ")" bt_choice

case "${bt_choice,,}" in
    1|web)      BOX_TYPE="web" ;;
    2|mail)     BOX_TYPE="mail" ;;
    3|splunk)   BOX_TYPE="splunk" ;;
    4|general)  BOX_TYPE="general" ;;
    "")         BOX_TYPE="$DETECTED_TYPE" ;;
    *)          BOX_TYPE="general"; log_warn "Unrecognized input — defaulting to general" ;;
esac

log_ok "Box type: ${BOLD}${BOX_TYPE}${RESET}"

# ─── 6. Write outputs.conf ────────────────────────────────────────────────────
echo
echo -e "${BOLD}━━━ Step 6: Writing outputs.conf ━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo

mkdir -p "$SPLUNK_LOCAL"

cat > "${SPLUNK_LOCAL}/outputs.conf" <<OUTPUTS
[tcpout]
defaultGroup = indexers

[tcpout:indexers]
server = ${INDEXER_IP}:${INDEXER_PORT}
OUTPUTS

log_ok "Wrote ${SPLUNK_LOCAL}/outputs.conf"

# ─── 7. Write inputs.conf ─────────────────────────────────────────────────────
echo
echo -e "${BOLD}━━━ Step 7: Writing inputs.conf (${BOX_TYPE}) ━━━━━━━━━━━━━━━━━${RESET}"
echo

write_monitor() {
    local path="$1" sourcetype="$2"
    printf "[monitor://%s]\nindex = main\nsourcetype = %s\n\n" "$path" "$sourcetype"
}

{
    printf "# inputs.conf — generated by splunk_forwarder.sh (%s)\n\n" "$(date)"

    case "$BOX_TYPE" in
        web)
            # Apache
            if [[ -d /var/log/apache2 ]]; then
                write_monitor "/var/log/apache2/access.log"  "access_combined"
                write_monitor "/var/log/apache2/error.log"   "apache_error"
            fi
            if [[ -d /var/log/httpd ]]; then
                write_monitor "/var/log/httpd/access_log"    "access_combined"
                write_monitor "/var/log/httpd/error_log"     "apache_error"
            fi
            # nginx
            if [[ -d /var/log/nginx ]]; then
                write_monitor "/var/log/nginx/access.log"    "nginx_access"
                write_monitor "/var/log/nginx/error.log"     "nginx_error"
            fi
            write_monitor "/var/log/auth.log"                "linux_secure"
            write_monitor "/var/log/syslog"                  "syslog"
            ;;

        mail)
            write_monitor "/var/log/mail.log"                "syslog"
            write_monitor "/var/log/auth.log"                "linux_secure"
            write_monitor "/var/log/syslog"                  "syslog"
            # Postfix logs (RHEL)
            if [[ -f /var/log/maillog ]]; then
                write_monitor "/var/log/maillog"             "syslog"
            fi
            # Roundcube
            for rc_log in /var/log/roundcube/errors.log /var/log/roundcubemail/errors.log; do
                if [[ -f "$rc_log" ]]; then
                    write_monitor "$rc_log"                  "php"
                fi
            done
            ;;

        splunk)
            SPLUNK_LOG_DIR="/opt/splunk/var/log/splunk"
            write_monitor "${SPLUNK_LOG_DIR}/splunkd.log"    "splunk_splunkd"
            write_monitor "${SPLUNK_LOG_DIR}/web_access.log" "splunk_web_access"
            write_monitor "${SPLUNK_LOG_DIR}/metrics.log"    "splunk_metrics"
            write_monitor "/var/log/auth.log"                "linux_secure"
            ;;

        general|*)
            write_monitor "/var/log/auth.log"                "linux_secure"
            write_monitor "/var/log/syslog"                  "syslog"
            write_monitor "/var/log/kern.log"                "syslog"
            # RHEL equivalents
            if [[ -f /var/log/secure ]]; then
                write_monitor "/var/log/secure"              "linux_secure"
            fi
            if [[ -f /var/log/messages ]]; then
                write_monitor "/var/log/messages"            "syslog"
            fi
            ;;
    esac

} > "${SPLUNK_LOCAL}/inputs.conf"

log_ok "Wrote ${SPLUNK_LOCAL}/inputs.conf"

# ─── 8. Enable boot-start and restart ────────────────────────────────────────
echo
echo -e "${BOLD}━━━ Step 8: Enable Boot-Start and Restart ━━━━━━━━━━━━━━━━━━━${RESET}"
echo

log_info "Enabling boot-start…"
"$SPLUNK_BIN" enable boot-start --accept-license --answer-yes --no-prompt 2>/dev/null || \
    log_warn "boot-start enable returned non-zero (may already be set)"

log_info "Restarting Splunk forwarder…"
"$SPLUNK_BIN" restart --accept-license --answer-yes --no-prompt

# ─── 9. Status check ─────────────────────────────────────────────────────────
echo
echo -e "${BOLD}━━━ Step 9: Status Check ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo

sleep 3

pass=0; fail=0

_chk() {
    local label="$1" ok="$2"
    if [[ "$ok" == "1" ]]; then
        printf "  ${GREEN}✓${RESET}  %-48s ${GREEN}PASS${RESET}\n" "$label"
        pass=$((pass+1))
    else
        printf "  ${RED}✗${RESET}  %-48s ${RED}FAIL${RESET}\n" "$label"
        fail=$((fail+1))
    fi
}

if [[ -x "$SPLUNK_BIN" ]]; then
    _chk "Binary present ($SPLUNK_BIN)" 1
else
    _chk "Binary present ($SPLUNK_BIN)" 0
fi

if "$SPLUNK_BIN" status --accept-license --answer-yes --no-prompt 2>/dev/null | grep -qi "running"; then
    _chk "Splunkd is running" 1
else
    _chk "Splunkd is running" 0
fi

if [[ -f "${SPLUNK_LOCAL}/outputs.conf" ]]; then
    _chk "outputs.conf present" 1
else
    _chk "outputs.conf present" 0
fi

if [[ -f "${SPLUNK_LOCAL}/inputs.conf" ]]; then
    _chk "inputs.conf present" 1
else
    _chk "inputs.conf present" 0
fi

echo
echo -e "  ─────────────────────────────────────────────────────────"
echo -e "  ${BOLD}Summary${RESET}"
echo -e "    Indexer  : ${INDEXER_IP}:${INDEXER_PORT}"
echo -e "    Box type : ${BOX_TYPE}"
echo -e "    Passed   : $pass"
echo -e "    Failed   : $fail"
echo

if [[ $fail -eq 0 ]]; then
    echo -e "  ${BOLD}${GREEN}Splunk forwarder deployment SUCCESSFUL${RESET}"
else
    echo -e "  ${BOLD}${RED}Splunk forwarder deployment FAILED${RESET} — see above"
    echo
    echo -e "  ${YELLOW}Troubleshooting tips:${RESET}"
    echo -e "    • Check $SPLUNK_BIN status"
    echo -e "    • Review /opt/splunkforwarder/var/log/splunk/splunkd.log"
    echo -e "    • Verify indexer is reachable: nc -zv ${INDEXER_IP} ${INDEXER_PORT}"
fi
echo
