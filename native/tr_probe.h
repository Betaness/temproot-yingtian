/*
 * tr_probe.h - runtime environment probe.
 *
 * Purpose: answer the two questions the handoff document left open, with
 * evidence collected on the device instead of assumptions:
 *   1. What is this build, exactly (identity + mitigation configuration)?
 *   2. Which syscalls / primitives does an ordinary app process actually have?
 * Every field is filled from a real read or a real syscall attempt.
 */
#ifndef TR_PROBE_H
#define TR_PROBE_H

#include "tr_common.h"

typedef struct {
    /* ---- device identity (Android Build fields, passed in from Java) ---- */
    char manufacturer[64];
    char model[64];
    char device[64];
    char fingerprint[320];
    char incremental[160];
    char android_release[32];
    int sdk_int;
    char security_patch[48];

    /* ---- kernel identity (read from uname) ---- */
    char kernel_release[256];
    char kernel_version[512];
    char machine[32];
    int page_size;

    /* ---- this process ---- */
    int pid;
    int uid;
    int euid;
    int egid;
    int is64;
    char cap_eff[32];
    char cap_bnd[32];
    char cap_prm[32];
    char no_new_privs[8];
    char seccomp[8];
    char selinux[160];

    /* ---- kernel command line and hardware capabilities ---- */
    char cmdline[1024];
    int hwcap2_mte;
    int cmdline_kasan_off;
    int cmdline_kfence_off;

    /* ---- bootloader / verified boot state (decides which root path exists) -- */
    char verified_boot_state[16];   /* green | yellow | orange | red | unknown */
    char flash_locked[16];          /* 1 | 0 */
    char verity_mode[16];           /* enforcing | logging | unknown */
    int boot_unlocked;              /* 1 when verifiedbootstate == orange */
    char boot_state_source[32];     /* /proc/cmdline | /proc/bootconfig | none */

    /* ---- mitigation configuration (from /proc/config.gz when available) -- */
    char config_state[24]; /* "parsed" | "absent" | "unreadable" */
    int cfg_kasan;
    int cfg_kasan_hw_tags;
    int cfg_kfence;
    int cfg_panic_on_oops;
    int cfg_init_on_alloc;
    int cfg_init_on_free;
    int cfg_sysvipc;
    int cfg_user_ns;
    int cfg_static_usermodehelper;
    int cfg_shadow_call_stack;
    int cfg_cfi;
    int cfg_randomize_base;
    int cfg_slab_freelist_hardened;
    int cfg_slab_freelist_random;
    int cfg_slab_merge_default;
    int cfg_unprivileged_bpf_disabled;
    int cfg_seccomp;
    int cfg_seccomp_filter;
    int cfg_posix_timers;
    int cfg_userfaultfd;
    int cfg_io_uring;
    long btf_size;

    /* ---- syscall reachability: 1 = permitted, 0 = denied, -1 = error ---- */
    int sc_timer_create;
    int sc_timer_delete;
    int sc_unshare_files;
    int sc_memfd_create;
    int sc_io_uring_setup;
    int sc_pipe2;
    int sc_setpipe_sz;
    int sc_fork_exec;
    int sc_userfaultfd;
    int sc_errno_timer;
    int sc_errno_unshare;
    int sc_errno_uring;
    int sc_errno_userfaultfd;
    int sc_errno_exec;
    char sc_notes[256];   /* e.g. "io_uring_setup=seccomp_kill" */

    /* ---- pre-existing root infrastructure ---- */
    int su_present;
    char su_path[128];
    int ksu_present;
    int magisk_present;

    /* ---- read-only kernel interfaces available to this process ---- */
    int btf_readable;
    int kallsyms_readable;
    int proc_timers_readable;
    int proc_pagemap_readable;

    /* ---- derived ---- */
    double probe_ms;
} tr_env;

/* Fill env->device..security_patch from Java-side Build fields (may be empty). */
void tr_probe_set_build(tr_env *env, const char *manufacturer, const char *model,
                        const char *device, const char *fingerprint,
                        const char *incremental, const char *android_release,
                        int sdk_int, const char *security_patch);

/* Collect everything. Returns TR_OK when the mandatory fields were read. */
int tr_probe_env(tr_env *env);

/* Serialize to JSON (no escapes broken, safe for org.json parsing). */
void tr_probe_json(const tr_env *env, tr_buf *out);

/* Parse /proc/config.gz into the cfg_* fields. */
int tr_probe_config_gz(tr_env *env);

/* Parse androidboot.verifiedbootstate / flash.locked / veritymode. */
void tr_probe_boot_state(tr_env *env);

/* Merge evidence collected by a more privileged companion (adb/Shizuku/rootd):
 * the app itself cannot read /proc/cmdline or /sys/kernel/btf on this device.
 * Negative values mean "unknown, keep what the probe found". */
void tr_probe_apply_evidence(tr_env *env, int kasan_off, int mte_hw,
                             const char *verified_boot_state,
                             const char *flash_locked,
                             const char *verity_mode);

#endif /* TR_PROBE_H */
