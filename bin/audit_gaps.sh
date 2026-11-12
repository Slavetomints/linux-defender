#!/usr/bin/env bash
# Defender gap audit: check what the attack + persist scripts left behind.
# Run as root AFTER defender scan. Reports every artifact still present.
# Checks bypass bash-function overrides from 14_shell_poison via 'command'.

[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

RED='\033[1;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
CYN='\033[0;36m'
RST='\033[0m'

FOUND=0
CLEAN=0

hit() {
    echo -e "  ${RED}[FOUND]${RST} $1${2:+  ${CYN}($2)${RST}}"
    (( FOUND++ )) || true
}
miss() {
    echo -e "  ${GRN}[CLEAN]${RST} $1"
    (( CLEAN++ )) || true
}
hdr() {
    echo
    echo -e "${YEL}=== $* ===${RST}"
}

file_check() {
    local label="$1" path="$2"
    if [[ -e "$path" ]]; then
        local attrs=""
        attrs=$(command lsattr "$path" 2>/dev/null | awk '{print $1}' || true)
        [[ "$attrs" == *i* ]] && attrs=" immutable" || attrs=""
        hit "$label" "${path}${attrs}"
    else
        miss "$label"
    fi
}

imm_check() {
    local path="$1"
    local attrs
    attrs=$(command lsattr "$path" 2>/dev/null | awk '{print $1}' || true)
    [[ "$attrs" == *i* ]] && echo "immutable" || echo "mutable"
}


# ── LKM ROOTKIT ──────────────────────────────────────────────────────────────
hdr "LKM ROOTKIT (nic_fw)"

if [[ -d /sys/module/nic_fw ]]; then
    hit "nic_fw kernel module loaded" "/sys/module/nic_fw (hidden from lsmod)"
else
    miss "nic_fw kernel module"
fi

# test with a hidden-prefix file — LKM hides names matching _PROTECTED_FILES
# but stat() bypasses getdents64, so -e works; ls won't show it
if command touch /tmp/.nic_fw_test 2>/dev/null && command ls -a /tmp/ | command grep -q nic_fw_test; then
    miss "LKM getdents64 hook (file visible in ls — hook not intercepting)"
    command rm -f /tmp/.nic_fw_test
else
    hit "LKM getdents64 hook active" "files matching protected patterns hidden from ls"
    command rm -f /tmp/.nic_fw_test 2>/dev/null || true
fi


# ── USERS & SUDOERS ──────────────────────────────────────────────────────────
hdr "USERS & SUDOERS"

for user in sys.sync netadmin svc.monitor; do
    if getent passwd "$user" &>/dev/null; then
        uid=$(getent passwd "$user" | cut -d: -f3)
        hit "user: $user" "uid=$uid"
    else
        miss "user: $user"
    fi
done

if getent passwd defender-test-backdoor &>/dev/null; then
    hit "user: defender-test-backdoor"
else
    miss "user: defender-test-backdoor"
fi

for f in /etc/sudoers.d/.sys_sync \
          /etc/sudoers.d/.netadmin \
          /etc/sudoers.d/.svc_monitor \
          /etc/sudoers.d/defender-test-nopasswd; do
    file_check "sudoers drop-in: $f" "$f"
done

# Any dot-prefixed sudoers files (generic catch)
while IFS= read -r -d '' f; do
    fname=$(command basename "$f")
    # skip the ones we already checked
    [[ "$fname" == .sys_sync || "$fname" == .netadmin || "$fname" == .svc_monitor ]] && continue
    hit "unexpected dot-file in sudoers.d" "$f"
done < <(command find /etc/sudoers.d -maxdepth 1 -name '.*' -print0 2>/dev/null)


# ── SSH BACKDOORS ─────────────────────────────────────────────────────────────
hdr "SSH BACKDOORS"

auth="/root/.ssh/authorized_keys"
if [[ -f "$auth" ]]; then
    imm=$(imm_check "$auth")
    if command grep -qF '# svc-monitoring' "$auth" 2>/dev/null; then
        hit "SSH key (attack): # svc-monitoring marker" "$auth  $imm"
    else
        miss "SSH key (attack): # svc-monitoring marker"
    fi
    if command grep -qF 'defender-test@attacker' "$auth" 2>/dev/null; then
        hit "SSH key (persist 02): defender-test@attacker" "$auth"
    else
        miss "SSH key (persist 02): defender-test@attacker"
    fi
    if command grep -qF 'rt-backdoor' "$auth" 2>/dev/null; then
        hit "SSH key (attack 02): rt-backdoor comment" "$auth"
    else
        miss "SSH key (attack 02): rt-backdoor comment"
    fi
    [[ "$imm" == "immutable" ]] && hit "authorized_keys is immutable" "$auth" || miss "authorized_keys mutable (OK)"
else
    miss "SSH authorized_keys file absent (OK)"
fi


# ── PAM BACKDOOR ─────────────────────────────────────────────────────────────
hdr "PAM BACKDOOR"

file_check "PAM helper: /usr/lib/.pam_auth" "/usr/lib/.pam_auth"

if [[ -f /etc/pam.d/sshd ]]; then
    if command grep -qF 'pam_exec.so' /etc/pam.d/sshd 2>/dev/null && \
       command grep -qF 'pam_auth' /etc/pam.d/sshd 2>/dev/null; then
        hit "PAM sshd injection: pam_exec pam_auth line present"
    else
        miss "PAM sshd injection"
    fi
else
    miss "PAM sshd injection (/etc/pam.d/sshd absent)"
fi


# ── SYSTEMD PERSISTENCE ───────────────────────────────────────────────────────
hdr "SYSTEMD SERVICES / TIMERS"

for unit in systemd-network-helper.service \
            systemd-network-helper.timer \
            defender-test-beacon.service \
            defender-test-timer.service \
            defender-test-timer.timer; do
    f="/etc/systemd/system/$unit"
    if [[ -f "$f" ]]; then
        imm=$(imm_check "$f")
        hit "unit file: $unit" "$f  $imm"
    else
        miss "unit file: $unit"
    fi
done

file_check "net-helper binary: /usr/lib/systemd/.net-helper" "/usr/lib/systemd/.net-helper"

for unit in systemd-network-helper.timer defender-test-timer.timer; do
    state=$(command systemctl is-active "$unit" 2>/dev/null || echo "inactive")
    [[ "$state" == "active" ]] && hit "unit active: $unit" || miss "unit inactive: $unit"
done


# ── CRON PERSISTENCE ─────────────────────────────────────────────────────────
hdr "CRON PERSISTENCE"

file_check "cron: /etc/cron.d/sysaudit (reverse shell)" "/etc/cron.d/sysaudit"
file_check "cron: /etc/cron.d/pkg_audit (logic bomb)" "/etc/cron.d/pkg_audit"
file_check "cron: /etc/cron.d/defender-test-system" "/etc/cron.d/defender-test-system"

if crontab -l 2>/dev/null | command grep -qF 'DEFENDER-TEST-cron'; then
    hit "root crontab: DEFENDER-TEST-cron entry"
else
    miss "root crontab: DEFENDER-TEST-cron entry"
fi


# ── AT JOBS ───────────────────────────────────────────────────────────────────
hdr "AT JOBS"

if command -v at &>/dev/null; then
    at_jobs=$(atq 2>/dev/null | wc -l || echo 0)
    if [[ "$at_jobs" -gt 0 ]]; then
        # Check for logic bomb payload
        while IFS= read -r line; do
            jid=$(echo "$line" | awk '{print $1}')
            if at -c "$jid" 2>/dev/null | command grep -qF '.sys_cleanup'; then
                hit "at job: logic bomb" "job $jid references /usr/local/lib/.sys_cleanup"
            fi
            if at -c "$jid" 2>/dev/null | command grep -qF 'DEFENDER_TEST_AT'; then
                hit "at job: DEFENDER_TEST_AT persist job" "job $jid"
            fi
        done < <(atq 2>/dev/null || true)
    else
        miss "no at jobs queued"
    fi
else
    miss "at not installed"
fi


# ── STARTUP SCRIPTS & DOTFILE POISON ─────────────────────────────────────────
hdr "STARTUP SCRIPTS & SHELL POISON"

file_check "profile.d: /etc/profile.d/.sys_cleanup.sh (shell poison)" "/etc/profile.d/.sys_cleanup.sh"
file_check "profile.d: /etc/profile.d/defender-test-update.sh" "/etc/profile.d/defender-test-update.sh"
file_check "profile.d: /etc/profile.d/defender-test-aliases.sh" "/etc/profile.d/defender-test-aliases.sh"

if [[ -f /etc/rc.local ]]; then
    if command grep -qF 'DEFENDER-TEST' /etc/rc.local 2>/dev/null; then
        hit "rc.local: DEFENDER-TEST marker present" "/etc/rc.local"
    else
        miss "rc.local: DEFENDER-TEST marker"
    fi
else
    miss "rc.local: not present"
fi

if [[ -f /etc/bash.bashrc ]]; then
    imm=$(imm_check /etc/bash.bashrc)
    if command grep -qF 'SC_BEGIN' /etc/bash.bashrc 2>/dev/null; then
        hit "bash.bashrc: SC_BEGIN shell poison block" "$imm"
    else
        miss "bash.bashrc: SC_BEGIN block"
    fi
    if command grep -qF 'DEFENDER-TEST-prompt-command' /etc/bash.bashrc 2>/dev/null; then
        hit "bash.bashrc: PROMPT_COMMAND injection"
    else
        miss "bash.bashrc: PROMPT_COMMAND injection"
    fi
    [[ "$imm" == "immutable" ]] && hit "bash.bashrc is immutable" || miss "bash.bashrc mutable (OK)"
fi

for home in /root /home/*/; do
    [[ -d "$home" ]] || continue
    for rc in .bashrc .bash_profile .profile .bash_login; do
        f="${home%/}/$rc"
        [[ -f "$f" ]] || continue
        if command grep -qF 'SC_BEGIN' "$f" 2>/dev/null; then
            imm=$(imm_check "$f")
            hit "dotfile poison: $f" "$imm"
        fi
    done
done


# ── XDG AUTOSTART ─────────────────────────────────────────────────────────────
hdr "XDG AUTOSTART"

file_check "XDG: /etc/xdg/autostart/defender-test-updater.desktop" \
           "/etc/xdg/autostart/defender-test-updater.desktop"


# ── PHP WEBSHELLS ─────────────────────────────────────────────────────────────
hdr "PHP WEBSHELLS"

for root in /var/www/html /var/www/opencart /var/www/prestashop \
            /var/www/roundcubemail /var/www/html/roundcubemail \
            /usr/share/roundcubemail /srv/http /srv/www/htdocs; do
    [[ -d "$root" ]] || continue
    # p0wny shell
    f="$root/health.php"
    if [[ -f "$f" ]]; then
        imm=$(imm_check "$f")
        hit "p0wny shell: $f" "$imm"
    fi
    # persist script shell
    f="$root/wp-theme-update.php"
    [[ -f "$f" ]] && hit "eval shell: $f" || true
done

# generic sweep for eval+base64 shells
while IFS= read -r -d '' f; do
    # skip ones we already flagged
    [[ "$(command basename "$f")" == "health.php" ]] && continue
    [[ "$(command basename "$f")" == "wp-theme-update.php" ]] && continue
    hit "suspicious PHP file (eval+base64): $f"
done < <(command grep -rlZ 'base64_decode' /var/www 2>/dev/null || true)


# ── LD_PRELOAD ────────────────────────────────────────────────────────────────
hdr "LD_PRELOAD"

if [[ -f /etc/ld.so.preload ]]; then
    if command grep -qF 'defender-test' /etc/ld.so.preload 2>/dev/null; then
        hit "ld.so.preload: defender-test entry"
    else
        miss "ld.so.preload: no defender-test entry"
    fi
    file_check "ld.so.preload rogue library: /usr/local/lib/defender-test-preload.so" \
               "/usr/local/lib/defender-test-preload.so"
else
    miss "ld.so.preload: file absent (OK)"
fi


# ── SUID & CAPABILITIES ───────────────────────────────────────────────────────
hdr "SUID BINARIES & CAPABILITIES"

file_check "SUID binary: /usr/local/bin/defender-test-suid" "/usr/local/bin/defender-test-suid"
if [[ -f /usr/local/bin/defender-test-suid ]]; then
    perm=$(command stat -c '%a' /usr/local/bin/defender-test-suid 2>/dev/null || true)
    [[ "$perm" == *4* ]] || true  # already flagged above
fi

file_check "caps binary: /usr/local/bin/defender-test-caps" "/usr/local/bin/defender-test-caps"
if [[ -f /usr/local/bin/defender-test-caps ]] && command -v getcap &>/dev/null; then
    caps=$(command getcap /usr/local/bin/defender-test-caps 2>/dev/null || true)
    [[ -n "$caps" ]] && hit "capability set on defender-test-caps" "$caps" || true
fi


# ── GIT HOOKS ─────────────────────────────────────────────────────────────────
hdr "GIT HOOKS"

for candidate in /root /home/*/; do
    hook="${candidate%/}/.git/hooks/post-commit"
    [[ -f "$hook" ]] || continue
    if command grep -qF 'DEFENDER-TEST-git-hook' "$hook" 2>/dev/null; then
        hit "git hook: $hook"
    fi
done


# ── POLKIT RULES ──────────────────────────────────────────────────────────────
hdr "POLKIT RULES"

file_check "polkit rule: /etc/polkit-1/rules.d/00-defender-test.rules" \
           "/etc/polkit-1/rules.d/00-defender-test.rules"


# ── LOGIC BOMB ARTIFACTS ─────────────────────────────────────────────────────
hdr "LOGIC BOMB ARTIFACTS"

file_check "logic bomb payload: /usr/local/lib/.sys_cleanup" "/usr/local/lib/.sys_cleanup"
file_check "logic bomb user registry: /usr/local/lib/.user_registry" "/usr/local/lib/.user_registry"

if [[ -f /usr/local/lib/.user_registry ]]; then
    count=$(command wc -l < /usr/local/lib/.user_registry 2>/dev/null || echo 0)
    [[ "$count" -gt 0 ]] && hit "bomb already fired: $count extra users in /etc/passwd" "check /var/log/.pkg_audit.log"
fi


# ── MAIL INTERCEPT ────────────────────────────────────────────────────────────
hdr "MAIL INTERCEPT"

file_check "mail filter script: /usr/local/lib/.locale_helper" "/usr/local/lib/.locale_helper"

if [[ -d /usr/local/lib/.locale_cache ]]; then
    count=$(command ls /usr/local/lib/.locale_cache 2>/dev/null | wc -l || echo 0)
    hit "mail archive dir: /usr/local/lib/.locale_cache" "$count message(s) stored"
else
    miss "mail archive dir: /usr/local/lib/.locale_cache"
fi

if [[ -f /etc/postfix/main.cf ]]; then
    cf=$(command postconf -h content_filter 2>/dev/null || command grep '^content_filter' /etc/postfix/main.cf 2>/dev/null || echo "")
    if [[ -n "$cf" && "$cf" != "(empty)" ]]; then
        hit "postfix content_filter set" "$cf"
    else
        miss "postfix content_filter"
    fi

    if command grep -qF '# svc-mailroute' /etc/postfix/master.cf 2>/dev/null; then
        hit "postfix master.cf: mailarchive transport present"
    else
        miss "postfix master.cf: mailarchive transport"
    fi

    for f in /etc/postfix/main.cf /etc/postfix/master.cf; do
        imm=$(imm_check "$f")
        [[ "$imm" == "immutable" ]] && hit "postfix config immutable: $f"
    done
fi


# ── SERVICE DISRUPTION ────────────────────────────────────────────────────────
hdr "SERVICE DISRUPTION"

for svc in httpd nginx apache2; do
    state=$(command systemctl is-enabled "$svc" 2>/dev/null || echo "not-found")
    [[ "$state" == "masked" ]] && hit "service masked: $svc" || miss "service not masked: $svc ($state)"
done

file_check "dovecot loopback override: /etc/dovecot/conf.d/99-rt-override.conf" \
           "/etc/dovecot/conf.d/99-rt-override.conf"

if [[ -f /etc/postfix/main.cf ]]; then
    ifaces=$(command postconf -h inet_interfaces 2>/dev/null || true)
    if [[ "$ifaces" == *loopback* ]]; then
        hit "postfix inet_interfaces restricted" "$ifaces"
    else
        miss "postfix inet_interfaces: $ifaces"
    fi
fi

if [[ -d /opt/splunk ]]; then
    wcf="/opt/splunk/etc/system/local/web.conf"
    if [[ -f "$wcf" ]] && command grep -qF 'cfg-loopback' "$wcf" 2>/dev/null; then
        hit "Splunk web.conf: loopback restriction active" "$wcf"
    else
        miss "Splunk web.conf: no loopback restriction"
    fi
fi

# Web stack check (13_destroy_web nukes /var/www and packages)
[[ -d /var/www ]] && miss "web root /var/www exists (OK)" || hit "web root /var/www deleted" "13_destroy_web may have fired"


# ── IMMUTABLE FILE SWEEP ──────────────────────────────────────────────────────
hdr "UNEXPECTED IMMUTABLE FILES"

for f in /root/.ssh/authorized_keys \
          /etc/pam.d/sshd \
          /usr/lib/.pam_auth \
          /usr/lib/systemd/.net-helper \
          /etc/systemd/system/systemd-network-helper.service \
          /etc/systemd/system/systemd-network-helper.timer \
          /etc/cron.d/sysaudit \
          /etc/cron.d/pkg_audit \
          /etc/bash.bashrc \
          /etc/profile.d/.sys_cleanup.sh \
          /usr/local/lib/.sys_cleanup \
          /usr/local/lib/.locale_helper; do
    [[ -e "$f" ]] || continue
    imm=$(imm_check "$f")
    [[ "$imm" == "immutable" ]] && hit "immutable: $f"
done

# Sweep sudoers for immutable drop-ins
while IFS= read -r -d '' f; do
    imm=$(imm_check "$f")
    [[ "$imm" == "immutable" ]] && hit "immutable sudoers drop-in: $f"
done < <(command find /etc/sudoers.d -maxdepth 1 -type f -print0 2>/dev/null)


# ── SUMMARY ───────────────────────────────────────────────────────────────────
echo
echo -e "${YEL}════════════════════════════════════════${RST}"
echo -e "  ${RED}FOUND (not caught):  $FOUND${RST}"
echo -e "  ${GRN}CLEAN (removed/OK):  $CLEAN${RST}"
total=$(( FOUND + CLEAN ))
if [[ "$total" -gt 0 ]]; then
    pct=$(( FOUND * 100 / total ))
    echo -e "  Detection gap: ${RED}${pct}%${RST} of artifacts still present"
fi
echo -e "${YEL}════════════════════════════════════════${RST}"
echo
