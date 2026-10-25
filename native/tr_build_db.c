#include "tr_build_db.h"

/*
 * Rows come from offline analysis of the stock OTA extracted in
 * D:\Codex\android-kernel (stock/kernel.config, stock/verification.json).
 * The yingtian row below is the one that was actually analysed; its mitigation
 * flags are copied from that extracted .config, not guessed.
 */
static const tr_build_row g_builds[] = {
    {
        .device = "yingtian",
        .kernel_release = "6.18.21-android17-5-g805aa6adea19-abogki565292102-4k",
        .fingerprint_prefix = "Xiaomi/yingtian/yingtian:17/",
        .kasan = 1,
        .panic_on_oops = 1,
        .kfence = 1,
        .init_on_alloc = 1,
        .sysvipc = 0,
        .user_ns = 0,
        .static_usermodehelper = 1,
        .mte = 1,
        .evidence = "android-kernel/stock/kernel.config (IKCONFIG of the "
                    "OS4.0.16.0.XBMCNXM boot.img, kernel sha256 "
                    "cde87cd70206f21db4359aa1148f5f68e693ffefb11108dffde99c07c8c5ad88)",
        .note_zh = "该内核启用 KASAN_HW_TAGS + KFENCE + PANIC_ON_OOPS："
                   "任何 UAF 都会立即被标签校验捕获并 panic 重启，"
                   "同时 SYSVIPC/USER_NS 未启用、STATIC_USERMODEHELPER 已开启，"
                   "常规利用原语不可用。此构建上只做非破坏性探测。"
    }
};

static const size_t g_build_count = sizeof(g_builds) / sizeof(g_builds[0]);

const tr_build_row *tr_build_lookup(const char *device, const char *kernel_release)
{
    size_t i;

    if (kernel_release == NULL) {
        return NULL;
    }
    for (i = 0; i < g_build_count; i++) {
        if (strcmp(g_builds[i].kernel_release, kernel_release) != 0) {
            continue;
        }
        if (device != NULL && device[0] != '\0' &&
            strcmp(g_builds[i].device, device) != 0) {
            continue;
        }
        return &g_builds[i];
    }
    return NULL;
}

int tr_build_evaluate(const tr_build_row *row)
{
    if (row == NULL) {
        return TR_BUILD_UNKNOWN;
    }
    if (row->kasan || row->panic_on_oops) {
        return TR_BUILD_BLOCK;
    }
    /* Identity confirmed but no execution evidence exists for any row yet. */
    return TR_BUILD_EXPERIMENT;
}

const char *tr_build_gate_json(const tr_env *env, tr_buf *out)
{
    const tr_build_row *row = tr_build_lookup(env->device, env->kernel_release);
    int verdict = tr_build_evaluate(row);

    tr_buf_add(out, "{");
    tr_buf_add(out, "\"verdict\":");
    switch (verdict) {
    case TR_BUILD_ALLOW: tr_buf_add_json_string(out, "ALLOW"); break;
    case TR_BUILD_EXPERIMENT: tr_buf_add_json_string(out, "EXPERIMENT"); break;
    case TR_BUILD_BLOCK: tr_buf_add_json_string(out, "BLOCK"); break;
    default: tr_buf_add_json_string(out, "UNKNOWN"); break;
    }
    tr_buf_addf(out, ",\"row_matched\":%s", row != NULL ? "true" : "false");
    if (row != NULL) {
        tr_buf_add(out, ",\"evidence\":"); tr_buf_add_json_string(out, row->evidence);
        tr_buf_add(out, ",\"note_zh\":"); tr_buf_add_json_string(out, row->note_zh);
        tr_buf_add(out, ",\"device\":"); tr_buf_add_json_string(out, row->device);
        tr_buf_add(out, ",\"kernel_release\":"); tr_buf_add_json_string(out, row->kernel_release);
        tr_buf_add(out, ",\"fingerprint_prefix\":"); tr_buf_add_json_string(out, row->fingerprint_prefix);
        tr_buf_addf(out, ",\"declared_kasan\":%s", row->kasan ? "true" : "false");
        tr_buf_addf(out, ",\"declared_panic_on_oops\":%s", row->panic_on_oops ? "true" : "false");
        tr_buf_addf(out, ",\"declared_sysvipc\":%s", row->sysvipc ? "true" : "false");
        tr_buf_addf(out, ",\"declared_user_ns\":%s", row->user_ns ? "true" : "false");
    }
    tr_buf_addf(out, ",\"exploit_allowed\":%s", verdict == TR_BUILD_ALLOW ? "true" : "false");
    tr_buf_add(out, "}");
    return tr_buf_cstr(out);
}
