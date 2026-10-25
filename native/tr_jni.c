/*
 * tr_jni.c - JNI surface consumed by org.fujiang.temproot.NativeBridge.
 *
 * Every entry point returns a JSON string and never throws across the JNI
 * boundary; failures are reported as {"error": ...} so the Java state machine
 * can show a real reason instead of a generic exception.
 */
#include <jni.h>

#include "tr_common.h"
#include "tr_probe.h"
#include "tr_guard.h"
#include "tr_layout.h"
#include "tr_btf.h"
#include "tr_timer_exec.h"
#include "tr_verify.h"
#include "tr_rootd.h"
#include "tr_exploit.h"
#include "tr_leak.h"

#define TR_LAYOUT_PATH "/sys/kernel/btf/vmlinux"

static tr_env g_env;
static tr_guard g_guard;
static tr_layout g_layout;
static int g_probed = 0;
static tr_buf g_log;
static int g_log_ready = 0;

static void log_sink(int level, const char *line)
{
    static const char *tags[] = { "D", "I", "W", "E" };
    const char *tag = (level >= 0 && level <= 3) ? tags[level] : "I";
    if (!g_log_ready) {
        tr_buf_init(&g_log);
        g_log_ready = 1;
    }
    if (g_log.len > 200 * 1024) {
        return;
    }
    tr_buf_addf(&g_log, "[%s] %s\n", tag, line);
}

static jstring new_string(JNIEnv *env, const char *s)
{
    return (*env)->NewStringUTF(env, s != NULL ? s : "");
}

static void json_error(tr_buf *b, int status)
{
    tr_buf_add(b, "{\"error\":");
    tr_buf_add_json_string(b, tr_strerror(status));
    tr_buf_addf(b, ",\"status\":%d}", status);
}

JNIEXPORT jstring JNICALL
Java_org_fujiang_temproot_NativeBridge_nativeVersion(JNIEnv *env, jclass cls)
{
    (void)cls;
    return new_string(env, TR_VERSION);
}

/* Entry point: installed the log sink and announces the build so a partial
 * library load is visible in the exported diagnostics. */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)vm;
    (void)reserved;
    if (!g_log_ready) {
        tr_buf_init(&g_log);
        g_log_ready = 1;
    }
    tr_set_log_sink(log_sink);
    tr_logf(TR_LOG_INFO, "libtemproot %s 已加载（JNI_OnLoad）", TR_VERSION);
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL
Java_org_fujiang_temproot_NativeBridge_nativeInit(JNIEnv *env, jclass cls)
{
    (void)cls;
    if (!g_log_ready) {
        tr_buf_init(&g_log);
        g_log_ready = 1;
    }
    tr_set_log_sink(log_sink);
    (void)env;
}

JNIEXPORT jstring JNICALL
Java_org_fujiang_temproot_NativeBridge_nativeProbe(JNIEnv *env, jclass cls,
                                                   jstring manufacturer, jstring model,
                                                   jstring device, jstring fingerprint,
                                                   jstring incremental, jstring release,
                                                   jint sdk, jstring patch)
{
    tr_buf out;
    const char *c_mfr, *c_model, *c_device, *c_fp, *c_inc, *c_rel, *c_patch;

    (void)cls;
    tr_set_log_sink(log_sink);
    tr_buf_init(&out);

    c_mfr = manufacturer ? (*env)->GetStringUTFChars(env, manufacturer, NULL) : "";
    c_model = model ? (*env)->GetStringUTFChars(env, model, NULL) : "";
    c_device = device ? (*env)->GetStringUTFChars(env, device, NULL) : "";
    c_fp = fingerprint ? (*env)->GetStringUTFChars(env, fingerprint, NULL) : "";
    c_inc = incremental ? (*env)->GetStringUTFChars(env, incremental, NULL) : "";
    c_rel = release ? (*env)->GetStringUTFChars(env, release, NULL) : "";
    c_patch = patch ? (*env)->GetStringUTFChars(env, patch, NULL) : "";

    tr_probe_env(&g_env);
    tr_probe_set_build(&g_env, c_mfr, c_model, c_device, c_fp, c_inc, c_rel,
                       (int)sdk, c_patch);
    tr_guard_evaluate(&g_env, &g_guard);
    tr_layout_build(&g_layout, TR_LAYOUT_PATH, g_env.kernel_release);
    g_probed = 1;

    tr_buf_add(&out, "{\"env\":");
    tr_probe_json(&g_env, &out);
    tr_buf_add(&out, ",\"guard\":");
    tr_guard_json(&g_guard, &out);
    tr_buf_add(&out, ",\"layout\":");
    tr_layout_json(&g_layout, &out);
    tr_buf_add(&out, ",\"guard_summary\":");
    tr_buf_add_json_string(&out, tr_guard_summary_zh(&g_guard));
    tr_buf_add(&out, "}");

    if (manufacturer) (*env)->ReleaseStringUTFChars(env, manufacturer, c_mfr);
    if (model) (*env)->ReleaseStringUTFChars(env, model, c_model);
    if (device) (*env)->ReleaseStringUTFChars(env, device, c_device);
    if (fingerprint) (*env)->ReleaseStringUTFChars(env, fingerprint, c_fp);
    if (incremental) (*env)->ReleaseStringUTFChars(env, incremental, c_inc);
    if (release) (*env)->ReleaseStringUTFChars(env, release, c_rel);
    if (patch) (*env)->ReleaseStringUTFChars(env, patch, c_patch);

    {
        jstring result = new_string(env, tr_buf_cstr(&out));
        tr_buf_free(&out);
        return result;
    }
}

JNIEXPORT jstring JNICALL
Java_org_fujiang_temproot_NativeBridge_nativeLayoutReport(JNIEnv *env, jclass cls)
{
    tr_buf out;

    (void)cls;
    tr_buf_init(&out);
    if (!g_probed) {
        tr_layout_build(&g_layout, TR_LAYOUT_PATH, g_env.kernel_release);
    }
    tr_layout_text(&g_layout, &out);
    {
        jstring result = new_string(env, tr_buf_cstr(&out));
        tr_buf_free(&out);
        return result;
    }
}

JNIEXPORT jstring JNICALL
Java_org_fujiang_temproot_NativeBridge_nativeTimerProbe(JNIEnv *env, jclass cls, jint rounds)
{
    tr_timer_probe probe;
    tr_buf out;

    (void)cls;
    tr_buf_init(&out);
    tr_timer_probe_run(&probe, (int)rounds);
    tr_timer_probe_json(&probe, &out);
    {
        jstring result = new_string(env, tr_buf_cstr(&out));
        tr_buf_free(&out);
        return result;
    }
}

JNIEXPORT jstring JNICALL
Java_org_fujiang_temproot_NativeBridge_nativeTrigger(JNIEnv *env, jclass cls)
{
    tr_buf out, report;
    int rc;

    (void)cls;
    tr_buf_init(&out);
    tr_buf_init(&report);
    if (!g_probed) {
        json_error(&out, TR_ECOMPAT);
        tr_buf_free(&report);
        {
            jstring result = new_string(env, tr_buf_cstr(&out));
            tr_buf_free(&out);
            return result;
        }
    }
    rc = tr_timer_trigger_run(&g_env, &g_guard, &report);
    tr_buf_add(&out, "{\"status\":");
    tr_buf_addf(&out, "%d,\"message\":", rc);
    tr_buf_add_json_string(&out, tr_strerror(rc));
    tr_buf_add(&out, ",\"detail\":");
    tr_buf_add_json_string(&out, tr_buf_cstr(&report));
    tr_buf_add(&out, ",\"guard\":");
    tr_guard_json(&g_guard, &out);
    tr_buf_add(&out, "}");
    tr_buf_free(&report);
    {
        jstring result = new_string(env, tr_buf_cstr(&out));
        tr_buf_free(&out);
        return result;
    }
}

JNIEXPORT jstring JNICALL
Java_org_fujiang_temproot_NativeBridge_nativeApplyEvidence(JNIEnv *env, jclass cls,
                                                          jint kasan_off, jint mte,
                                                          jstring vbs, jstring locked,
                                                          jstring verity)
{
    const char *c_vbs = NULL, *c_locked = NULL, *c_verity = NULL;
    tr_buf out;

    (void)cls;
    if (vbs) c_vbs = (*env)->GetStringUTFChars(env, vbs, NULL);
    if (locked) c_locked = (*env)->GetStringUTFChars(env, locked, NULL);
    if (verity) c_verity = (*env)->GetStringUTFChars(env, verity, NULL);

    tr_probe_apply_evidence(&g_env, (int)kasan_off, (int)mte, c_vbs, c_locked, c_verity);
    tr_guard_evaluate(&g_env, &g_guard);
    tr_layout_build(&g_layout, TR_LAYOUT_PATH, g_env.kernel_release);

    tr_buf_init(&out);
    tr_buf_add(&out, "{\"guard\":");
    tr_guard_json(&g_guard, &out);
    tr_buf_add(&out, ",\"guard_summary\":");
    tr_buf_add_json_string(&out, tr_guard_summary_zh(&g_guard));
    tr_buf_addf(&out, ",\"layout_complete\":%s,\"layout_offline\":%s",
                g_layout.complete ? "true" : "false",
                g_layout.offline_used ? "true" : "false");
    tr_buf_add(&out, ",\"boot\":{");
    tr_buf_add(&out, "\"verified_boot_state\":"); tr_buf_add_json_string(&out, g_env.verified_boot_state);
    tr_buf_add(&out, ",\"flash_locked\":"); tr_buf_add_json_string(&out, g_env.flash_locked);
    tr_buf_add(&out, ",\"verity_mode\":"); tr_buf_add_json_string(&out, g_env.verity_mode);
    tr_buf_addf(&out, ",\"boot_unlocked\":%s", g_env.boot_unlocked ? "true" : "false");
    tr_buf_add(&out, ",\"source\":"); tr_buf_add_json_string(&out, g_env.boot_state_source);
    tr_buf_add(&out, "}");
    tr_buf_addf(&out, ",\"kasan_off\":%s", g_env.cmdline_kasan_off ? "true" : "false");
    tr_buf_addf(&out, ",\"mte_hw\":%s", g_env.hwcap2_mte ? "true" : "false");
    tr_buf_add(&out, "}");

    if (vbs) (*env)->ReleaseStringUTFChars(env, vbs, c_vbs);
    if (locked) (*env)->ReleaseStringUTFChars(env, locked, c_locked);
    if (verity) (*env)->ReleaseStringUTFChars(env, verity, c_verity);

    {
        jstring result = new_string(env, tr_buf_cstr(&out));
        tr_buf_free(&out);
        return result;
    }
}

JNIEXPORT jstring JNICALL
Java_org_fujiang_temproot_NativeBridge_nativeExploitPlan(JNIEnv *env, jclass cls, jint do_groom)
{
    tr_exploit e;
    tr_buf out;

    (void)cls;
    tr_buf_init(&out);
    if (!g_probed) {
        json_error(&out, TR_ECOMPAT);
        {
            jstring result = new_string(env, tr_buf_cstr(&out));
            tr_buf_free(&out);
            return result;
        }
    }
    tr_exploit_plan(&e, &g_env, &g_guard, &g_layout);
    if (do_groom) {
        (void)tr_exploit_groom(&e);
    }
    tr_buf_add(&out, "{\"plan\":");
    tr_exploit_json(&e, &out);
    tr_buf_add(&out, ",\"guard\":");
    tr_guard_json(&g_guard, &out);
    tr_buf_add(&out, "}");
    if (do_groom) {
        /* Never leave groomed objects resident inside the app process. */
        tr_exploit_ungroom(&e);
    }
    {
        jstring result = new_string(env, tr_buf_cstr(&out));
        tr_buf_free(&out);
        return result;
    }
}

JNIEXPORT jstring JNICALL
Java_org_fujiang_temproot_NativeBridge_nativeLeakProbe(JNIEnv *env, jclass cls)
{
    tr_leak leak;
    tr_buf out, text;

    (void)cls;
    tr_buf_init(&out);
    tr_buf_init(&text);
    tr_leak_probe(&leak);
    tr_leak_json(&leak, &out);
    tr_leak_text(&leak, &text);
    tr_buf_add(&out, ",\"report\":");
    tr_buf_add_json_string(&out, tr_buf_cstr(&text));
    tr_buf_add(&out, "}");
    {
        jstring result = new_string(env, tr_buf_cstr(&out));
        tr_buf_free(&out);
        tr_buf_free(&text);
        return result;
    }
}

JNIEXPORT jstring JNICALL
Java_org_fujiang_temproot_NativeBridge_nativeVerify(JNIEnv *env, jclass cls)
{
    tr_verify v;
    tr_buf out;

    (void)cls;
    tr_buf_init(&out);
    tr_verify_run(&v);
    tr_verify_json(&v, &out);
    {
        jstring result = new_string(env, tr_buf_cstr(&out));
        tr_buf_free(&out);
        return result;
    }
}

JNIEXPORT jint JNICALL
Java_org_fujiang_temproot_NativeBridge_nativeRootdStart(JNIEnv *env, jclass cls,
                                                        jstring allow_file, jint ttl)
{
    const char *path = allow_file ? (*env)->GetStringUTFChars(env, allow_file, NULL) : NULL;
    int rc = tr_rootd_start(path, (int)ttl);

    (void)cls;
    if (allow_file) (*env)->ReleaseStringUTFChars(env, allow_file, path);
    return rc;
}

JNIEXPORT jint JNICALL
Java_org_fujiang_temproot_NativeBridge_nativeRootdPing(JNIEnv *env, jclass cls)
{
    (void)env;
    (void)cls;
    return tr_rootd_ping();
}

JNIEXPORT jint JNICALL
Java_org_fujiang_temproot_NativeBridge_nativeRootdStop(JNIEnv *env, jclass cls)
{
    (void)env;
    (void)cls;
    return tr_rootd_stop();
}

JNIEXPORT jstring JNICALL
Java_org_fujiang_temproot_NativeBridge_nativeSu(JNIEnv *env, jclass cls,
                                                jobjectArray argv, jint timeout_ms)
{
    tr_buf out, captured;
    char *cargv[TR_SU_MAX_ARGC + 1];
    const char *utf[TR_SU_MAX_ARGC + 1];
    jsize count, i;
    int pty_fd = -1, child = -1, exit_code = -1, rc;

    (void)cls;
    tr_buf_init(&out);
    tr_buf_init(&captured);

    count = argv ? (*env)->GetArrayLength(env, argv) : 0;
    if (count <= 0 || count > TR_SU_MAX_ARGC) {
        json_error(&out, TR_EINVAL);
        tr_buf_free(&captured);
        {
            jstring result = new_string(env, tr_buf_cstr(&out));
            tr_buf_free(&out);
            return result;
        }
    }
    for (i = 0; i < count; i++) {
        jstring item = (jstring)(*env)->GetObjectArrayElement(env, argv, i);
        utf[i] = item ? (*env)->GetStringUTFChars(env, item, NULL) : "";
        cargv[i] = (char *)utf[i];
    }
    cargv[count] = NULL;

    rc = tr_su_capture(cargv, &captured, &exit_code, (int)timeout_ms);
    tr_buf_add(&out, "{\"status\":");
    tr_buf_addf(&out, "%d,\"message\":", rc);
    tr_buf_add_json_string(&out, tr_strerror(rc));
    tr_buf_addf(&out, ",\"exit_code\":%d,\"output\":", exit_code);
    tr_buf_add_json_string(&out, tr_buf_cstr(&captured));
    tr_buf_add(&out, "}");

    for (i = 0; i < count; i++) {
        jstring item = (jstring)(*env)->GetObjectArrayElement(env, argv, i);
        if (item) {
            (*env)->ReleaseStringUTFChars(env, item, utf[i]);
            (*env)->DeleteLocalRef(env, item);
        }
    }
    (void)pty_fd;
    (void)child;
    tr_buf_free(&captured);
    {
        jstring result = new_string(env, tr_buf_cstr(&out));
        tr_buf_free(&out);
        return result;
    }
}

JNIEXPORT jstring JNICALL
Java_org_fujiang_temproot_NativeBridge_nativeLogDrain(JNIEnv *env, jclass cls)
{
    jstring result;

    (void)cls;
    if (!g_log_ready) {
        return new_string(env, "");
    }
    result = new_string(env, tr_buf_cstr(&g_log));
    g_log.len = 0;
    if (g_log.data != NULL) {
        g_log.data[0] = '\0';
    }
    return result;
}
