#include "tr_guard.h"

static void guard_reason(tr_guard *g, const char *fmt, ...)
{
    va_list ap;

    if (g->reason_count >= TR_GUARD_MAX_REASONS) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(g->reason[g->reason_count], sizeof(g->reason[0]), fmt, ap);
    va_end(ap);
    g->reason_count++;
}

static void guard_block(tr_guard *g, const char *code, const char *fmt, ...)
{
    va_list ap;

    g->exploit_allowed = 0;
    snprintf(g->block_code, sizeof(g->block_code), "%s", code);
    if (g->reason_count < TR_GUARD_MAX_REASONS) {
        va_start(ap, fmt);
        vsnprintf(g->reason[g->reason_count], sizeof(g->reason[0]), fmt, ap);
        va_end(ap);
        g->reason_count++;
    }
}

int tr_guard_evaluate(const tr_env *env, tr_guard *g)
{
    const tr_build_row *row = NULL;

    memset(g, 0, sizeof(*g));
    g->verdict = TR_BUILD_UNKNOWN;
    g->runtime_config_known = strcmp(env->config_state, "parsed") == 0;
    g->mte_hw = env->hwcap2_mte;
    g->identity_complete = env->device[0] != '\0' && env->kernel_release[0] != '\0';

    if (!g->identity_complete) {
        guard_block(g, "IDENTITY_MISSING",
                    "未能完整读取设备代号或内核标识，按证据不足停止执行");
        return TR_OK;
    }

    if (g->runtime_config_known) {
        /* Runtime evidence wins over the offline table. */
        g->kasan_active = env->cfg_kasan && !env->cmdline_kasan_off;
        g->kfence_active = env->cfg_kfence && !env->cmdline_kfence_off;
        g->panic_on_oops = env->cfg_panic_on_oops;
        guard_reason(g, "/proc/config.gz 已解析：以内核自报配置为准");
        if (env->cfg_kasan_hw_tags) {
            guard_reason(g, "内核启用 KASAN_HW_TAGS（硬件标签），启用 MTE 时越界/悬垂访问同步报错");
        }
        if (!env->cfg_sysvipc) {
            guard_reason(g, "未启用 CONFIG_SYSVIPC：msg_msg 类堆喷原语在本内核不存在");
        }
        if (!env->cfg_user_ns) {
            guard_reason(g, "未启用 CONFIG_USER_NS：无法用用户命名空间扩大可利用面");
        }
        if (env->cfg_static_usermodehelper) {
            guard_reason(g, "启用 CONFIG_STATIC_USERMODEHELPER：modprobe_path 覆盖技巧失效");
        }
        if (env->cfg_shadow_call_stack) {
            guard_reason(g, "启用 CONFIG_SHADOW_CALL_STACK：栈上返回地址劫持失效");
        }
        if (env->cfg_init_on_alloc) {
            guard_reason(g, "启用 CONFIG_INIT_ON_ALLOC_DEFAULT_ON：新分配对象清零，未初始化读泄漏失效");
        }
        if (env->cfg_slab_freelist_hardened || env->cfg_slab_freelist_random) {
            guard_reason(g, "SLUB freelist 加固/随机化开启：堆喷布局不可预测");
        }
    } else {
        /* No runtime config: fall back to the offline-verified table. */
        row = tr_build_lookup(env->device, env->kernel_release);
        if (row == NULL) {
            guard_block(g, "NO_EVIDENCE",
                        "本机无 /proc/config.gz，且内核标识 %s 不在离线验证表中："
                        "缺少基线证据，按失败关闭处理",
                        env->kernel_release);
            return TR_OK;
        }
        g->verdict = (row->kasan && !env->cmdline_kasan_off) ? TR_BUILD_BLOCK
                                                             : TR_BUILD_EXPERIMENT;
        g->kasan_active = row->kasan && !env->cmdline_kasan_off;
        g->kfence_active = row->kfence && !env->cmdline_kfence_off;
        g->panic_on_oops = row->panic_on_oops;
        guard_reason(g, "内核标识与离线验证表精确匹配，配置取自 %s", row->evidence);
        if (row->kasan) {
            guard_reason(g, "离线配置显示 CONFIG_KASAN=y + CONFIG_KASAN_HW_TAGS=y");
        }
        if (row->panic_on_oops) {
            guard_reason(g, "离线配置显示 CONFIG_PANIC_ON_OOPS=y：一次 KASAN 命中即整机重启");
        }
        if (!row->sysvipc) {
            guard_reason(g, "离线配置显示 CONFIG_SYSVIPC 未启用");
        }
        if (!row->user_ns) {
            guard_reason(g, "离线配置显示 CONFIG_USER_NS 未启用");
        }
        if (row->static_usermodehelper) {
            guard_reason(g, "离线配置显示 CONFIG_STATIC_USERMODEHELPER=y");
        }
        if (row->mte) {
            guard_reason(g, "离线配置显示 CONFIG_ARM64_MTE=y");
        }
    }

    if (g->kasan_active) {
        guard_block(g, "KASAN_ACTIVE",
                    "KASAN 处于启用状态：悬垂指针一经解引用即触发标签/影子校验，"
                    "配合 PANIC_ON_OOPS 会立即重启设备。本工具在内核内存上不执行写入");
    } else if (!env->cmdline_kasan_off) {
        guard_block(g, "KASAN_STATE_UNKNOWN",
                    "编译配置含 KASAN，但本进程读不到内核命令行里的 kasan=off，"
                    "证据不足，按检测仍开启处理（可由伴侣进程经 adb 导入证据）");
    } else {
        guard_reason(g, "内核命令行含 kasan=off：本构建的 KASAN 检测在本次启动未生效");
    }
    if (g->panic_on_oops) {
        guard_reason(g, "CONFIG_PANIC_ON_OOPS=y：真实 oops 仍会重启（生产内核常态，按风险保留）");
    }
    if (g->kfence_active) {
        guard_reason(g, "KFENCE 抽样开启：随机隔离对象，复用命中概率低但非零");
    }
    if (row == NULL && g->runtime_config_known && g->exploit_allowed) {
        /* Runtime config parsed, mitigations absent: require the offline table
         * to confirm this is a known build before touching kernel memory. */
        const tr_build_row *known = tr_build_lookup(env->device, env->kernel_release);
        if (known == NULL) {
            guard_block(g, "UNVERIFIED_BUILD",
                        "运行时未报告 KASAN，但 %s 不在离线验证表中；"
                        "缺少该构建的配置基线，不做未经验证的适配",
                        env->kernel_release);
        } else {
            g->verdict = TR_BUILD_EXPERIMENT;
            guard_reason(g, "该构建已知但从未实机验证执行链：仅允许实验性流程");
        }
    }

    if (g->exploit_allowed && g->verdict == TR_BUILD_UNKNOWN) {
        g->verdict = TR_BUILD_EXPERIMENT;
    }
    if (!g->exploit_allowed && g->verdict == TR_BUILD_UNKNOWN) {
        g->verdict = TR_BUILD_BLOCK;
    }

    /* Secondary consistency check: MTE hardware plus a debug-style build is a
     * strong hint that HW tags are live even when /proc/config.gz is absent. */
    if (g->exploit_allowed && g->mte_hw && env->cfg_kasan_hw_tags && !env->cmdline_kasan_off) {
        guard_block(g, "MTE_HW_KASAN",
                    "硬件支持 MTE 且内核编译了 HW_TAGS：标签故障会同步触发");
    }
    return TR_OK;
}

void tr_guard_json(const tr_guard *g, tr_buf *out)
{
    int i;

    tr_buf_add(out, "{");
    tr_buf_add(out, "\"verdict\":");
    switch (g->verdict) {
    case TR_BUILD_ALLOW: tr_buf_add_json_string(out, "ALLOW"); break;
    case TR_BUILD_EXPERIMENT: tr_buf_add_json_string(out, "EXPERIMENT"); break;
    case TR_BUILD_BLOCK: tr_buf_add_json_string(out, "BLOCK"); break;
    default: tr_buf_add_json_string(out, "UNKNOWN"); break;
    }
    tr_buf_addf(out, ",\"exploit_allowed\":%s", g->exploit_allowed ? "true" : "false");
    tr_buf_addf(out, ",\"runtime_config_known\":%s", g->runtime_config_known ? "true" : "false");
    tr_buf_addf(out, ",\"kasan_active\":%s", g->kasan_active ? "true" : "false");
    tr_buf_addf(out, ",\"kfence_active\":%s", g->kfence_active ? "true" : "false");
    tr_buf_addf(out, ",\"panic_on_oops\":%s", g->panic_on_oops ? "true" : "false");
    tr_buf_addf(out, ",\"mte_hw\":%s", g->mte_hw ? "true" : "false");
    tr_buf_add(out, ",\"block_code\":"); tr_buf_add_json_string(out, g->block_code);
    tr_buf_add(out, ",\"reasons\":[");
    for (i = 0; i < g->reason_count; i++) {
        if (i > 0) {
            tr_buf_add(out, ",");
        }
        tr_buf_add_json_string(out, g->reason[i]);
    }
    tr_buf_add(out, "]}");
}

const char *tr_guard_summary_zh(const tr_guard *g)
{
    if (g->exploit_allowed) {
        return "闸门放行：未检测到会阻断利用的缓解措施（仅实验性流程）";
    }
    if (strcmp(g->block_code, "KASAN_ACTIVE") == 0) {
        return "闸门阻断：内核启用 KASAN/MTE，利用会直接 panic 重启";
    }
    if (strcmp(g->block_code, "NO_EVIDENCE") == 0) {
        return "闸门阻断：缺少该内核的配置基线，无法证明缓解措施状态";
    }
    if (strcmp(g->block_code, "IDENTITY_MISSING") == 0) {
        return "闸门阻断：设备或内核标识读取不完整";
    }
    return "闸门阻断：当前构建不满足执行条件";
}
