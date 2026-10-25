#include "tr_verify.h"

/* CAP_SYS_ADMIN is bit 21 in the capability sets since Linux 2.2. */
#define CAP_SYS_ADMIN_BIT 21

static int cap_bit_set(const char *hex, int bit)
{
    uint64_t value = 0;

    if (hex == NULL) {
        return 0;
    }
    if (tr_parse_hex_u64(hex, &value) != 0) {
        return 0;
    }
    return (value >> bit) & 1ULL;
}

static int read_status_field(const char *key, char *out, size_t cap)
{
    char blob[8192];
    const char *line;
    size_t key_len = strlen(key);

    out[0] = '\0';
    if (tr_read_file("/proc/self/status", blob, sizeof(blob)) <= 0) {
        return -1;
    }
    line = blob;
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

/* A privileged operation that an untrusted app cannot perform:
 * reading the init process memory image requires CAP_SYS_PTRACE and a domain
 * transition, so success here is real evidence, not a label. */
static void probe_privileged_open(tr_verify *v)
{
    static const char *paths[] = {
        "/proc/1/mem",
        "/data/system/packages.xml",
        "/proc/1/environ",
        NULL
    };
    int i;

    v->privileged_open_ok = 0;
    v->privileged_open_errno = 0;
    for (i = 0; paths[i] != NULL; i++) {
        int fd = open(paths[i], O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            char tmp[16];
            ssize_t n = read(fd, tmp, sizeof(tmp));
            close(fd);
            if (n >= 0) {
                v->privileged_open_ok = 1;
                snprintf(v->privileged_path, sizeof(v->privileged_path), "%s", paths[i]);
                return;
            }
            v->privileged_open_errno = errno;
        } else {
            v->privileged_open_errno = errno;
        }
    }
}

static void probe_setuid_roundtrip(tr_verify *v)
{
    v->setuid_roundtrip_ok = 0;
    if (geteuid() != 0) {
        return;
    }
    /* Drop to an unprivileged id and come back: only a process holding
     * CAP_SETUID can do this. */
    if (seteuid(2000) != 0) {
        return;
    }
    if (seteuid(0) == 0 && geteuid() == 0) {
        v->setuid_roundtrip_ok = 1;
    }
}

int tr_verify_run(tr_verify *v)
{
    char selinux[192];
    char enforce[32];

    memset(v, 0, sizeof(*v));
    v->uid = (int)getuid();
    v->euid = (int)geteuid();
    v->egid = (int)getegid();
    read_status_field("CapEff", v->cap_eff, sizeof(v->cap_eff));
    read_status_field("CapPrm", v->cap_prm, sizeof(v->cap_prm));
    read_status_field("CapBnd", v->cap_bnd, sizeof(v->cap_bnd));
    read_status_field("Seccomp", v->seccomp, sizeof(v->seccomp));
    read_status_field("NoNewPrivs", v->no_new_privs, sizeof(v->no_new_privs));
    if (tr_read_line("/proc/self/attr/current", selinux, sizeof(selinux)) > 0) {
        snprintf(v->selinux, sizeof(v->selinux), "%s", selinux);
    }
    v->selinux_enforce = -1;
    if (tr_read_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce)) > 0) {
        v->selinux_enforce = atoi(enforce) ? 1 : 0;
    }

    v->cap_sys_admin = cap_bit_set(v->cap_eff, CAP_SYS_ADMIN_BIT);
    v->uid_is_root = v->uid == 0 && v->euid == 0;
    v->context_is_root_like = strstr(v->selinux, ":su:") != NULL
        || strstr(v->selinux, "magisk") != NULL
        || strstr(v->selinux, "u:r:kernel:s0") != NULL;

    probe_privileged_open(v);
    probe_setuid_roundtrip(v);

    /* Strict conjunction. A permissive SELinux state alone never qualifies. */
    v->verified = v->uid_is_root && v->cap_sys_admin &&
                  (v->privileged_open_ok || v->setuid_roundtrip_ok);
    if (v->verified) {
        snprintf(v->summary, sizeof(v->summary),
                 "已验证：uid=0、CapEff 含 CAP_SYS_ADMIN、特权访问成功（%s）",
                 v->privileged_open_ok ? v->privileged_path : "setuid 往返");
    } else if (v->uid_is_root && !v->cap_sys_admin) {
        snprintf(v->summary, sizeof(v->summary),
                 "未通过：uid=0 但 capability 集不含 CAP_SYS_ADMIN（CapEff=%s）",
                 v->cap_eff);
    } else if (!v->uid_is_root) {
        snprintf(v->summary, sizeof(v->summary),
                 "未通过：uid=%d euid=%d，尚未取得特权身份", v->uid, v->euid);
    } else {
        snprintf(v->summary, sizeof(v->summary),
                 "未通过：uid=0 且具备 capability，但特权操作失败（errno=%d）",
                 v->privileged_open_errno);
    }
    return v->verified ? TR_OK : TR_EPERM;
}

void tr_verify_json(const tr_verify *v, tr_buf *out)
{
    tr_buf_add(out, "{");
    tr_buf_addf(out, "\"uid\":%d,\"euid\":%d,\"egid\":%d,", v->uid, v->euid, v->egid);
    tr_buf_add(out, "\"cap_eff\":"); tr_buf_add_json_string(out, v->cap_eff);
    tr_buf_add(out, ",\"cap_prm\":"); tr_buf_add_json_string(out, v->cap_prm);
    tr_buf_add(out, ",\"cap_bnd\":"); tr_buf_add_json_string(out, v->cap_bnd);
    tr_buf_add(out, ",\"selinux\":"); tr_buf_add_json_string(out, v->selinux);
    tr_buf_addf(out, ",\"selinux_enforce\":%d", v->selinux_enforce);
    tr_buf_add(out, ",\"seccomp\":"); tr_buf_add_json_string(out, v->seccomp);
    tr_buf_add(out, ",\"no_new_privs\":"); tr_buf_add_json_string(out, v->no_new_privs);
    tr_buf_addf(out, ",\"cap_sys_admin\":%s", v->cap_sys_admin ? "true" : "false");
    tr_buf_addf(out, ",\"uid_is_root\":%s", v->uid_is_root ? "true" : "false");
    tr_buf_addf(out, ",\"context_is_root_like\":%s", v->context_is_root_like ? "true" : "false");
    tr_buf_addf(out, ",\"privileged_open_ok\":%s", v->privileged_open_ok ? "true" : "false");
    tr_buf_add(out, ",\"privileged_path\":"); tr_buf_add_json_string(out, v->privileged_path);
    tr_buf_addf(out, ",\"privileged_open_errno\":%d", v->privileged_open_errno);
    tr_buf_addf(out, ",\"setuid_roundtrip_ok\":%s", v->setuid_roundtrip_ok ? "true" : "false");
    tr_buf_addf(out, ",\"verified\":%s", v->verified ? "true" : "false");
    tr_buf_add(out, ",\"summary\":"); tr_buf_add_json_string(out, v->summary);
    tr_buf_add(out, "}");
}

const char *tr_verify_summary_zh(const tr_verify *v)
{
    return v->summary;
}
