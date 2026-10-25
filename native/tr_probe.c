#define _GNU_SOURCE 1

#include "tr_probe.h"

#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <zlib.h>

#ifndef HWCAP2_MTE
#define HWCAP2_MTE (1UL << 18)
#endif

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif

#ifndef __NR_userfaultfd
#define __NR_userfaultfd 282
#endif

#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif

void tr_probe_set_build(tr_env *env, const char *manufacturer, const char *model,
                        const char *device, const char *fingerprint,
                        const char *incremental, const char *android_release,
                        int sdk_int, const char *security_patch)
{
#define COPY_FIELD(field, value)                                          \
    do {                                                                  \
        const char *v_ = (value);                                         \
        if (v_ != NULL) {                                                 \
            snprintf(env->field, sizeof(env->field), "%s", v_);           \
        }                                                                 \
    } while (0)

    COPY_FIELD(manufacturer, manufacturer);
    COPY_FIELD(model, model);
    COPY_FIELD(device, device);
    COPY_FIELD(fingerprint, fingerprint);
    COPY_FIELD(incremental, incremental);
    COPY_FIELD(android_release, android_release);
    COPY_FIELD(security_patch, security_patch);
#undef COPY_FIELD
    env->sdk_int = sdk_int;
}

/* Read one "Key:\tvalue" field out of a /proc/self style text blob. */
static int status_field(const char *blob, const char *key, char *out, size_t cap)
{
    const char *line = blob;
    size_t key_len = strlen(key);

    out[0] = '\0';
    while (line != NULL && *line != '\0') {
        if (strncmp(line, key, key_len) == 0 && line[key_len] == ':') {
            const char *v = line + key_len + 1;
            const char *end;
            size_t n;
            while (*v == ' ' || *v == '\t') {
                v++;
            }
            end = strchr(v, '\n');
            n = end != NULL ? (size_t)(end - v) : strlen(v);
            if (n >= cap) {
                n = cap - 1;
            }
            memcpy(out, v, n);
            out[n] = '\0';
            return 0;
        }
        line = strchr(line, '\n');
        if (line != NULL) {
            line++;
        }
    }
    return -1;
}

/* ---- /proc/config.gz: decompress into memory and scan for CONFIG_ lines ---- */
static int config_lookup(const char *text, const char *key)
{
    char needle[128];
    const char *p;

    snprintf(needle, sizeof(needle), "%s=y", key);
    p = text;
    while (p != NULL && *p != '\0') {
        if (strncmp(p, needle, strlen(needle)) == 0 &&
            (p[strlen(needle)] == '\n' || p[strlen(needle)] == '\0')) {
            return 1;
        }
        p = strchr(p, '\n');
        if (p != NULL) {
            p++;
        }
    }
    return 0;
}

int tr_probe_config_gz(tr_env *env)
{
    unsigned char *raw = NULL, *plain = NULL;
    size_t raw_len = 0;
    z_stream zs;
    size_t cap = 1u << 20;
    size_t out_len = 0;
    int rc;

    snprintf(env->config_state, sizeof(env->config_state), "absent");
    if (tr_read_file_alloc("/proc/config.gz", &raw, &raw_len) != 0) {
        /* Android user builds usually drop IKCONFIG_PROC. The offline
         * stock/kernel.config remains authoritative evidence in that case. */
        return TR_EUNSUPPORTED;
    }
    plain = (unsigned char *)malloc(cap);
    if (plain == NULL) {
        free(raw);
        return TR_ENOMEM;
    }
    memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) {
        free(raw);
        free(plain);
        return TR_EIO;
    }
    zs.next_in = raw;
    zs.avail_in = (uInt)raw_len;
    zs.next_out = plain;
    zs.avail_out = (uInt)(cap - 1);
    rc = inflate(&zs, Z_FINISH);
    inflateEnd(&zs);
    free(raw);
    if (rc != Z_STREAM_END && rc != Z_OK && rc != Z_BUF_ERROR) {
        free(plain);
        snprintf(env->config_state, sizeof(env->config_state), "unreadable");
        return TR_EIO;
    }
    out_len = zs.total_out < cap ? zs.total_out : cap - 1;
    plain[out_len] = '\0';
    snprintf(env->config_state, sizeof(env->config_state), "parsed");

    env->cfg_kasan = config_lookup((const char *)plain, "CONFIG_KASAN");
    env->cfg_kasan_hw_tags = config_lookup((const char *)plain, "CONFIG_KASAN_HW_TAGS");
    env->cfg_kfence = config_lookup((const char *)plain, "CONFIG_KFENCE");
    env->cfg_panic_on_oops = config_lookup((const char *)plain, "CONFIG_PANIC_ON_OOPS");
    env->cfg_init_on_alloc = config_lookup((const char *)plain, "CONFIG_INIT_ON_ALLOC_DEFAULT_ON");
    env->cfg_init_on_free = config_lookup((const char *)plain, "CONFIG_INIT_ON_FREE_DEFAULT_ON");
    env->cfg_sysvipc = config_lookup((const char *)plain, "CONFIG_SYSVIPC");
    env->cfg_user_ns = config_lookup((const char *)plain, "CONFIG_USER_NS");
    env->cfg_static_usermodehelper = config_lookup((const char *)plain, "CONFIG_STATIC_USERMODEHELPER");
    env->cfg_shadow_call_stack = config_lookup((const char *)plain, "CONFIG_SHADOW_CALL_STACK");
    env->cfg_cfi = config_lookup((const char *)plain, "CONFIG_CFI_CLANG");
    env->cfg_randomize_base = config_lookup((const char *)plain, "CONFIG_RANDOMIZE_BASE");
    env->cfg_slab_freelist_hardened = config_lookup((const char *)plain, "CONFIG_SLAB_FREELIST_HARDENED");
    env->cfg_slab_freelist_random = config_lookup((const char *)plain, "CONFIG_SLAB_FREELIST_RANDOM");
    env->cfg_slab_merge_default = config_lookup((const char *)plain, "CONFIG_SLAB_MERGE_DEFAULT");
    env->cfg_unprivileged_bpf_disabled = config_lookup((const char *)plain, "CONFIG_BPF_UNPRIV_DEFAULT_OFF");
    env->cfg_seccomp = config_lookup((const char *)plain, "CONFIG_SECCOMP");
    env->cfg_seccomp_filter = config_lookup((const char *)plain, "CONFIG_SECCOMP_FILTER");
    env->cfg_posix_timers = config_lookup((const char *)plain, "CONFIG_POSIX_TIMERS");
    env->cfg_userfaultfd = config_lookup((const char *)plain, "CONFIG_USERFAULTFD");
    env->cfg_io_uring = config_lookup((const char *)plain, "CONFIG_IO_URING");
    free(plain);
    return TR_OK;
}

/* ---- bootloader / verified boot state ---------------------------------- */
/* Decides which temporary-root path exists at all: with a locked bootloader a
 * one-shot `fastboot boot` is refused, and the kernel bug path costs a reboot. */
static int boot_kv(const char *blob, const char *key, char *out, size_t cap)
{
    const char *p = strstr(blob, key);
    size_t n = 0;

    out[0] = '\0';
    if (p == NULL) {
        return -1;
    }
    p += strlen(key);
    while (*p == '=' || *p == ' ' || *p == '\t' || *p == '"' || *p == ':') {
        p++;
    }
    while (p[n] != '\0' && p[n] != ' ' && p[n] != '\n' && p[n] != '\t' &&
           p[n] != '"' && p[n] != ',' && n + 1 < cap) {
        out[n] = p[n];
        n++;
    }
    out[n] = '\0';
    return n > 0 ? 0 : -1;
}

void tr_probe_boot_state(tr_env *env)
{
    char blob[8192];
    const char *src = NULL;

    snprintf(env->verified_boot_state, sizeof(env->verified_boot_state), "unknown");
    snprintf(env->flash_locked, sizeof(env->flash_locked), "unknown");
    snprintf(env->verity_mode, sizeof(env->verity_mode), "unknown");
    snprintf(env->boot_state_source, sizeof(env->boot_state_source), "none");
    env->boot_unlocked = 0;

    if (boot_kv(env->cmdline, "androidboot.verifiedbootstate",
                env->verified_boot_state, sizeof(env->verified_boot_state)) == 0) {
        src = "/proc/cmdline";
    }
    if (src == NULL && tr_read_file("/proc/bootconfig", blob, sizeof(blob)) > 0) {
        if (boot_kv(blob, "androidboot.verifiedbootstate",
                    env->verified_boot_state, sizeof(env->verified_boot_state)) == 0) {
            src = "/proc/bootconfig";
        }
    }
    if (src == NULL) {
        /* The device may still expose the value through the vendor property
         * channel; nothing else is assumed. */
        snprintf(env->verified_boot_state, sizeof(env->verified_boot_state), "unknown");
        return;
    }
    snprintf(env->boot_state_source, sizeof(env->boot_state_source), "%s", src);
    if (strcmp(src, "/proc/cmdline") == 0) {
        boot_kv(env->cmdline, "androidboot.flash.locked", env->flash_locked,
                sizeof(env->flash_locked));
        boot_kv(env->cmdline, "androidboot.veritymode", env->verity_mode,
                sizeof(env->verity_mode));
    } else {
        boot_kv(blob, "androidboot.flash.locked", env->flash_locked, sizeof(env->flash_locked));
        boot_kv(blob, "androidboot.veritymode", env->verity_mode, sizeof(env->verity_mode));
    }
    env->boot_unlocked = strcmp(env->verified_boot_state, "orange") == 0;
    tr_logf(TR_LOG_INFO, "boot: verifiedbootstate=%s locked=%s source=%s",
            env->verified_boot_state, env->flash_locked, env->boot_state_source);
}

void tr_probe_apply_evidence(tr_env *env, int kasan_off, int mte_hw,
                             const char *verified_boot_state,
                             const char *flash_locked,
                             const char *verity_mode)
{
    if (kasan_off > 0) {
        /* A companion with shell rights read the real command line. */
        env->cmdline_kasan_off = 1;
    } else if (kasan_off == 0) {
        env->cmdline_kasan_off = 0;
    }
    if (mte_hw >= 0) {
        env->hwcap2_mte = mte_hw;
    }
    if (verified_boot_state != NULL && verified_boot_state[0] != '\0') {
        snprintf(env->verified_boot_state, sizeof(env->verified_boot_state), "%s",
                 verified_boot_state);
        snprintf(env->boot_state_source, sizeof(env->boot_state_source),
                 "external:companion");
        env->boot_unlocked = strcmp(env->verified_boot_state, "orange") == 0;
    }
    if (flash_locked != NULL && flash_locked[0] != '\0') {
        snprintf(env->flash_locked, sizeof(env->flash_locked), "%s", flash_locked);
    }
    if (verity_mode != NULL && verity_mode[0] != '\0') {
        snprintf(env->verity_mode, sizeof(env->verity_mode), "%s", verity_mode);
    }
    tr_logf(TR_LOG_INFO, "evidence: kasan_off=%d mte=%d boot=%s locked=%s verity=%s",
            env->cmdline_kasan_off, env->hwcap2_mte, env->verified_boot_state,
            env->flash_locked, env->verity_mode);
}

/* ---- syscall reachability probes -------------------------------------- */
/* Each probe runs in a throwaway child so a denial cannot poison our state.
 * Android's app seccomp policy kills the process on some syscalls (SIGSYS)
 * instead of returning EPERM, so isolation here is mandatory, not cosmetic. */

static void note_sc(tr_env *env, const char *text)
{
    size_t used = strlen(env->sc_notes);

    if (used + strlen(text) + 2 < sizeof(env->sc_notes)) {
        snprintf(env->sc_notes + used, sizeof(env->sc_notes) - used, "%s%s",
                 used ? " " : "", text);
    }
}

/* 1 = permitted, 0 = refused with errno, -2 = killed by seccomp, -3 = other */
static int run_isolated(int (*fn)(void), int *err_out)
{
    pid_t pid;
    int status = 0;

    *err_out = 0;
    pid = fork();
    if (pid < 0) {
        return -3;
    }
    if (pid == 0) {
        int rc = fn();
        if (rc == 0) {
            _exit(0);
        }
        _exit(errno & 0x7f);
    }
    if (waitpid(pid, &status, 0) < 0) {
        return -3;
    }
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        *err_out = sig;
        return sig == SIGSYS ? -2 : -3;
    }
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 0) {
            return 1;
        }
        *err_out = code;
        return 0;
    }
    return -3;
}

static int fn_memfd(void)
{
    int fd = (int)syscall(__NR_memfd_create, "trprobe", 0);
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

static int fn_io_uring(void)
{
    struct {
        uint32_t sq_entries;
        uint32_t cq_entries;
        uint32_t flags;
        uint32_t sq_thread_cpu;
        uint32_t sq_thread_idle;
        uint32_t features;
        uint32_t wq_fd;
        uint32_t resv[3];
    } p;
    int fd;

    memset(&p, 0, sizeof(p));
    p.sq_entries = 2;
    p.cq_entries = 4;
    fd = (int)syscall(__NR_io_uring_setup, 2, &p);
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

static int fn_userfaultfd(void)
{
    int fd = (int)syscall(__NR_userfaultfd, 0);
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

static int fn_pipe(void)
{
    int fds[2];

    if (pipe(fds) != 0) {
        return -1;
    }
    /* A tiny F_SETPIPE_SZ is enough: we only need to know it is reachable. */
    if (fcntl(fds[1], F_SETPIPE_SZ, 4096 * 8) <= 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    close(fds[0]);
    close(fds[1]);
    return 0;
}
static void probe_timer_create(tr_env *env)
{
    struct sigevent sev;
    timer_t tid = (timer_t)0;
    int i, rc, err = 0;

    env->sc_timer_create = 0;
    for (i = 0; i < 4; i++) {
        memset(&sev, 0, sizeof(sev));
        sev.sigev_notify = SIGEV_NONE;
        tid = (timer_t)0;
        rc = timer_create(CLOCK_PROCESS_CPUTIME_ID, &sev, &tid);
        if (rc == 0) {
            env->sc_timer_create = 1;
            env->sc_timer_delete = 1;
            if (timer_delete(tid) != 0) {
                env->sc_timer_delete = 0;
            }
            break;
        }
        err = errno;
        if (err == EAGAIN) {
            /* Timer id space temporarily exhausted inside the child: retry. */
            tr_sleep_ms(2);
            continue;
        }
        break;
    }
    env->sc_errno_timer = err;
}

static void probe_misc_syscalls(tr_env *env)
{
    int fd, rc;

    /* Every syscall below may be in Android's seccomp KILL list, which raises
     * SIGSYS instead of returning an error. Each one therefore runs in a
     * throwaway child: the probe records "killed" and the app survives. */
    rc = run_isolated(fn_memfd, &fd);
    if (rc == 1) {
        env->sc_memfd_create = 1;
    } else if (rc == -2) {
        note_sc(env, "memfd=seccomp_kill");
    }

    rc = run_isolated(fn_io_uring, &fd);
    if (rc == 1) {
        env->sc_io_uring_setup = 1;
    } else if (rc == -2) {
        env->sc_errno_uring = SIGSYS;
        note_sc(env, "io_uring_setup=seccomp_kill");
    } else {
        env->sc_errno_uring = fd;
    }

    rc = run_isolated(fn_userfaultfd, &fd);
    if (rc == 1) {
        env->sc_userfaultfd = 1;
    } else if (rc == -2) {
        env->sc_errno_userfaultfd = SIGSYS;
        note_sc(env, "userfaultfd=seccomp_kill");
    } else {
        env->sc_errno_userfaultfd = fd;
    }

    rc = run_isolated(fn_pipe, &fd);
    if (rc == 1) {
        env->sc_pipe2 = 1;
        env->sc_setpipe_sz = 1;
    } else if (rc == -2) {
        note_sc(env, "pipe=seccomp_kill");
    }
}

static void probe_unshare_files(tr_env *env)
{
    pid_t pid = fork();
    int status = 0;

    if (pid < 0) {
        return;
    }
    if (pid == 0) {
        /* Single threaded in the child, so CLONE_FILES is the only request. */
        int rc = unshare(CLONE_FILES);
        _exit(rc == 0 ? 10 : (errno & 0x7f));
    }
    if (waitpid(pid, &status, 0) < 0) {
        return;
    }
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        env->sc_unshare_files = (code == 10);
        env->sc_errno_unshare = (code == 10) ? 0 : code;
    }
}

static void probe_fork_exec(tr_env *env)
{
    static const char *candidates[] = {
        "/system/bin/sh", "/system/bin/toybox", "/system/bin/true", NULL
    };
    int i;

    for (i = 0; candidates[i] != NULL; i++) {
        pid_t pid = fork();
        int status = 0;

        if (pid < 0) {
            return;
        }
        if (pid == 0) {
            char *argv[2];
            argv[0] = (char *)candidates[i];
            argv[1] = NULL;
            execve(candidates[i], argv, (char *const *)NULL);
            _exit(errno & 0x7f);
        }
        if (waitpid(pid, &status, 0) < 0) {
            return;
        }
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            env->sc_fork_exec = 1;
            env->sc_errno_exec = 0;
            return;
        }
        if (WIFEXITED(status)) {
            env->sc_errno_exec = WEXITSTATUS(status);
        }
    }
}

static void probe_root_infrastructure(tr_env *env)
{
    static const char *su_paths[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/debug_ramdisk/su", "/data/adb/ksu/bin/su", "/data/adb/magisk/su", NULL
    };
    int i;

    for (i = 0; su_paths[i] != NULL; i++) {
        if (access(su_paths[i], X_OK) == 0) {
            env->su_present = 1;
            snprintf(env->su_path, sizeof(env->su_path), "%s", su_paths[i]);
            break;
        }
    }
    env->ksu_present = tr_file_exists("/data/adb/ksu")
        || tr_file_exists("/sys/module/kernelsu");
    env->magisk_present = tr_file_exists("/data/adb/magisk")
        || tr_file_exists("/sbin/magisk");
}

int tr_probe_env(tr_env *env)
{
    struct utsname u;
    char blob[8192];
    char line[256];
    unsigned char *btf = NULL;
    size_t btf_len = 0;
    double started = tr_now_ms();

    memset(env, 0, sizeof(*env));
    env->btf_size = -1;

    if (uname(&u) == 0) {
        snprintf(env->kernel_release, sizeof(env->kernel_release), "%s", u.release);
        snprintf(env->kernel_version, sizeof(env->kernel_version), "%s", u.version);
        snprintf(env->machine, sizeof(env->machine), "%s", u.machine);
    }

    env->pid = (int)getpid();
    env->uid = (int)getuid();
    env->euid = (int)geteuid();
    env->egid = (int)getegid();
    env->is64 = sizeof(void *) == 8;
    env->page_size = (int)sysconf(_SC_PAGESIZE);
    env->hwcap2_mte = (getauxval(AT_HWCAP2) & HWCAP2_MTE) != 0;

    if (tr_read_file("/proc/self/status", blob, sizeof(blob)) > 0) {
        status_field(blob, "CapEff", env->cap_eff, sizeof(env->cap_eff));
        status_field(blob, "CapBnd", env->cap_bnd, sizeof(env->cap_bnd));
        status_field(blob, "CapPrm", env->cap_prm, sizeof(env->cap_prm));
        status_field(blob, "NoNewPrivs", env->no_new_privs, sizeof(env->no_new_privs));
        status_field(blob, "Seccomp", env->seccomp, sizeof(env->seccomp));
    }
    if (tr_read_line("/proc/self/attr/current", line, sizeof(line)) > 0) {
        snprintf(env->selinux, sizeof(env->selinux), "%s", line);
    }
    if (tr_read_file("/proc/cmdline", env->cmdline, sizeof(env->cmdline)) < 0) {
        env->cmdline[0] = '\0';
    }
    env->cmdline_kasan_off = strstr(env->cmdline, "kasan=off") != NULL;
    env->cmdline_kfence_off = strstr(env->cmdline, "kfence.sample_interval=0") != NULL
        || strstr(env->cmdline, "kfence=off") != NULL;
    tr_probe_boot_state(env);

    /* /sys/kernel/btf/vmlinux gives us struct layouts at runtime: this is how
     * the project avoids every hardcoded offset the handoff forbade. */
    if (tr_read_file_alloc("/sys/kernel/btf/vmlinux", &btf, &btf_len) == 0) {
        env->btf_readable = 1;
        env->btf_size = (long)btf_len;
        free(btf);
    }
    env->kallsyms_readable = tr_read_line("/proc/kallsyms", line, sizeof(line)) > 0
        && strstr(line, "0000000000000000") == NULL;
    env->proc_timers_readable = tr_read_file("/proc/self/timers", line, sizeof(line)) >= 0;
    env->proc_pagemap_readable = access("/proc/self/pagemap", R_OK) == 0;

    tr_probe_config_gz(env);

    probe_timer_create(env);
    probe_misc_syscalls(env);
    probe_unshare_files(env);
    probe_fork_exec(env);
    probe_root_infrastructure(env);

    env->probe_ms = tr_now_ms() - started;
    return TR_OK;
}

void tr_probe_json(const tr_env *env, tr_buf *out)
{
    tr_buf_add(out, "{");
    tr_buf_add(out, "\"schema_version\":1,");
    tr_buf_addf(out, "\"app_version\":\"%s\",", TR_VERSION);

    tr_buf_add(out, "\"device\":{");
    tr_buf_add(out, "\"manufacturer\":"); tr_buf_add_json_string(out, env->manufacturer);
    tr_buf_add(out, ",\"model\":"); tr_buf_add_json_string(out, env->model);
    tr_buf_add(out, ",\"device\":"); tr_buf_add_json_string(out, env->device);
    tr_buf_add(out, ",\"fingerprint\":"); tr_buf_add_json_string(out, env->fingerprint);
    tr_buf_add(out, ",\"incremental\":"); tr_buf_add_json_string(out, env->incremental);
    tr_buf_add(out, ",\"android_release\":"); tr_buf_add_json_string(out, env->android_release);
    tr_buf_addf(out, ",\"sdk_int\":%d,", env->sdk_int);
    tr_buf_add(out, "\"security_patch\":"); tr_buf_add_json_string(out, env->security_patch);
    tr_buf_add(out, ",\"kernel_release\":"); tr_buf_add_json_string(out, env->kernel_release);
    tr_buf_add(out, ",\"machine\":"); tr_buf_add_json_string(out, env->machine);
    tr_buf_addf(out, ",\"page_size\":%d", env->page_size);
    tr_buf_addf(out, ",\"hwcap2_mte\":%s", env->hwcap2_mte ? "true" : "false");
    tr_buf_add(out, ",\"verified_boot_state\":"); tr_buf_add_json_string(out, env->verified_boot_state);
    tr_buf_add(out, ",\"flash_locked\":"); tr_buf_add_json_string(out, env->flash_locked);
    tr_buf_add(out, ",\"verity_mode\":"); tr_buf_add_json_string(out, env->verity_mode);
    tr_buf_addf(out, ",\"boot_unlocked\":%s", env->boot_unlocked ? "true" : "false");
    tr_buf_add(out, ",\"boot_state_source\":"); tr_buf_add_json_string(out, env->boot_state_source);
    tr_buf_add(out, "},");

    tr_buf_add(out, "\"process\":{");
    tr_buf_addf(out, "\"pid\":%d,\"uid\":%d,\"euid\":%d,\"egid\":%d,", env->pid, env->uid, env->euid, env->egid);
    tr_buf_addf(out, "\"is64\":%s,", env->is64 ? "true" : "false");
    tr_buf_add(out, "\"cap_eff\":"); tr_buf_add_json_string(out, env->cap_eff);
    tr_buf_add(out, ",\"cap_bnd\":"); tr_buf_add_json_string(out, env->cap_bnd);
    tr_buf_add(out, ",\"no_new_privs\":"); tr_buf_add_json_string(out, env->no_new_privs);
    tr_buf_add(out, ",\"seccomp\":"); tr_buf_add_json_string(out, env->seccomp);
    tr_buf_add(out, ",\"selinux\":"); tr_buf_add_json_string(out, env->selinux);
    tr_buf_add(out, "},");

    tr_buf_add(out, "\"mitigations\":{");
    tr_buf_add(out, "\"config_state\":"); tr_buf_add_json_string(out, env->config_state);
    tr_buf_addf(out, ",\"kasan\":%s", env->cfg_kasan ? "true" : "false");
    tr_buf_addf(out, ",\"kasan_hw_tags\":%s", env->cfg_kasan_hw_tags ? "true" : "false");
    tr_buf_addf(out, ",\"kfence\":%s", env->cfg_kfence ? "true" : "false");
    tr_buf_addf(out, ",\"panic_on_oops\":%s", env->cfg_panic_on_oops ? "true" : "false");
    tr_buf_addf(out, ",\"init_on_alloc\":%s", env->cfg_init_on_alloc ? "true" : "false");
    tr_buf_addf(out, ",\"init_on_free\":%s", env->cfg_init_on_free ? "true" : "false");
    tr_buf_addf(out, ",\"sysvipc\":%s", env->cfg_sysvipc ? "true" : "false");
    tr_buf_addf(out, ",\"user_ns\":%s", env->cfg_user_ns ? "true" : "false");
    tr_buf_addf(out, ",\"static_usermodehelper\":%s", env->cfg_static_usermodehelper ? "true" : "false");
    tr_buf_addf(out, ",\"shadow_call_stack\":%s", env->cfg_shadow_call_stack ? "true" : "false");
    tr_buf_addf(out, ",\"cfi\":%s", env->cfg_cfi ? "true" : "false");
    tr_buf_addf(out, ",\"randomize_base\":%s", env->cfg_randomize_base ? "true" : "false");
    tr_buf_addf(out, ",\"slab_freelist_hardened\":%s", env->cfg_slab_freelist_hardened ? "true" : "false");
    tr_buf_addf(out, ",\"slab_freelist_random\":%s", env->cfg_slab_freelist_random ? "true" : "false");
    tr_buf_addf(out, ",\"slab_merge_default\":%s", env->cfg_slab_merge_default ? "true" : "false");
    tr_buf_addf(out, ",\"unprivileged_bpf_disabled\":%s", env->cfg_unprivileged_bpf_disabled ? "true" : "false");
    tr_buf_addf(out, ",\"io_uring\":%s", env->cfg_io_uring ? "true" : "false");
    tr_buf_addf(out, ",\"userfaultfd\":%s", env->cfg_userfaultfd ? "true" : "false");
    tr_buf_addf(out, ",\"cmdline_kasan_off\":%s", env->cmdline_kasan_off ? "true" : "false");
    tr_buf_addf(out, ",\"cmdline_kfence_off\":%s", env->cmdline_kfence_off ? "true" : "false");
    tr_buf_add(out, "},");

    tr_buf_add(out, "\"kernel_interfaces\":{");
    tr_buf_addf(out, "\"btf_readable\":%s,\"btf_size\":%ld,", env->btf_readable ? "true" : "false", env->btf_size);
    tr_buf_addf(out, "\"kallsyms_readable\":%s,", env->kallsyms_readable ? "true" : "false");
    tr_buf_addf(out, "\"proc_timers_readable\":%s,", env->proc_timers_readable ? "true" : "false");
    tr_buf_addf(out, "\"proc_pagemap_readable\":%s", env->proc_pagemap_readable ? "true" : "false");
    tr_buf_add(out, "},");

    tr_buf_add(out, "\"syscall_reachability\":{");
    tr_buf_addf(out, "\"timer_create\":%s,", env->sc_timer_create ? "true" : "false");
    tr_buf_addf(out, "\"timer_delete\":%s,", env->sc_timer_delete ? "true" : "false");
    tr_buf_addf(out, "\"timer_errno\":%d,", env->sc_errno_timer);
    tr_buf_addf(out, "\"unshare_files\":%s,", env->sc_unshare_files ? "true" : "false");
    tr_buf_addf(out, "\"unshare_errno\":%d,", env->sc_errno_unshare);
    tr_buf_addf(out, "\"memfd_create\":%s,", env->sc_memfd_create ? "true" : "false");
    tr_buf_addf(out, "\"io_uring_setup\":%s,", env->sc_io_uring_setup ? "true" : "false");
    tr_buf_addf(out, "\"io_uring_errno\":%d,", env->sc_errno_uring);
    tr_buf_addf(out, "\"userfaultfd\":%s,", env->sc_userfaultfd ? "true" : "false");
    tr_buf_addf(out, "\"userfaultfd_errno\":%d,", env->sc_errno_userfaultfd);
    tr_buf_addf(out, "\"pipe2\":%s,", env->sc_pipe2 ? "true" : "false");
    tr_buf_addf(out, "\"setpipe_sz\":%s,", env->sc_setpipe_sz ? "true" : "false");
    tr_buf_addf(out, "\"fork_exec\":%s,", env->sc_fork_exec ? "true" : "false");
    tr_buf_addf(out, "\"exec_errno\":%d,", env->sc_errno_exec);
    tr_buf_add(out, "\"notes\":"); tr_buf_add_json_string(out, env->sc_notes);
    tr_buf_add(out, "},");

    tr_buf_add(out, "\"existing_root\":{");
    tr_buf_addf(out, "\"su_present\":%s,", env->su_present ? "true" : "false");
    tr_buf_add(out, "\"su_path\":"); tr_buf_add_json_string(out, env->su_path);
    tr_buf_addf(out, ",\"kernelsu\":%s,", env->ksu_present ? "true" : "false");
    tr_buf_addf(out, "\"magisk\":%s", env->magisk_present ? "true" : "false");
    tr_buf_add(out, "},");

    tr_buf_addf(out, "\"probe_ms\":%.1f", env->probe_ms);
    tr_buf_add(out, "}");
}
