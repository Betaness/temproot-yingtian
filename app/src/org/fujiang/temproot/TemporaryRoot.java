package org.fujiang.temproot;

import android.os.Build;
import org.json.JSONObject;

/**
 * Integration surface for host applications (DroidDesk and others).
 *
 * Contract:
 *   - every method is blocking and must be called off the main thread
 *   - every method returns a JSONObject and never throws for an expected failure;
 *     unexpected failures surface as {"error": "..."} plus a stack-free reason
 *   - escalate() refuses to touch kernel memory when the mitigation guard blocks
 *   - verify() is the only source of truth for "root works"
 */
public final class TemporaryRoot {

    /** Independent progress markers. They are never merged into one "success". */
    public enum Stage {
        LIBRARY_LOADED,
        ENVIRONMENT_PROBED,
        GUARD_EVALUATED,
        LAYOUT_RESOLVED,
        REACHABILITY_MEASURED,
        ESCALATION_EXECUTED,
        PRIVILEGE_VERIFIED,
        DAEMON_RUNNING
    }

    public static final String PACKAGE = "org.fujiang.temproot";

    private TemporaryRoot() { }

    public static boolean isNativeLoaded() { return NativeBridge.load(); }

    public static String nativeLoadError() { return NativeBridge.loadError(); }

    public static String version() {
        if (!NativeBridge.load()) return "unavailable (" + NativeBridge.loadError() + ")";
        return NativeBridge.nativeVersion();
    }

    /** Full environment + guard + layout snapshot. */
    public static JSONObject probe() {
        if (!NativeBridge.load()) return error("native library not loaded: " + NativeBridge.loadError());
        NativeBridge.nativeInit();
        String json = NativeBridge.nativeProbe(
                safe(Build.MANUFACTURER), safe(Build.MODEL), safe(Build.DEVICE),
                safe(Build.FINGERPRINT), safe(Build.VERSION.INCREMENTAL),
                safe(Build.VERSION.RELEASE),
                Build.VERSION.SDK_INT, safe(Build.VERSION.SECURITY_PATCH));
        return parse(json);
    }

    /** Non-destructive reachability measurement of the timer/exec cleanup order. */
    public static JSONObject measureReachability(int rounds) {
        if (!NativeBridge.load()) return error("native library not loaded");
        return parse(NativeBridge.nativeTimerProbe(rounds));
    }

    /** Destructive stage. Blocked by the guard on every known KASAN build. */
    public static JSONObject escalate() {
        if (!NativeBridge.load()) return error("native library not loaded");
        return parse(NativeBridge.nativeTrigger());
    }

    /** Strict verification: uid + capability + a privileged operation. */
    public static JSONObject verify() {
        if (!NativeBridge.load()) return error("native library not loaded");
        return parse(NativeBridge.nativeVerify());
    }

    /** Human readable BTF layout table for the running kernel. */
    public static String layoutReport() {
        if (!NativeBridge.load()) return "native library not loaded";
        return NativeBridge.nativeLayoutReport();
    }

    public static int rootDaemonStart(String allowFile, int ttlSeconds) {
        if (!NativeBridge.load()) return -5;
        return NativeBridge.nativeRootdStart(allowFile, ttlSeconds);
    }

    public static int rootDaemonPing() {
        if (!NativeBridge.load()) return 0;
        return NativeBridge.nativeRootdPing();
    }

    public static int rootDaemonStop() {
        if (!NativeBridge.load()) return 0;
        return NativeBridge.nativeRootdStop();
    }

    /** Run a command through the temporary root daemon. */
    public static JSONObject su(String[] argv, int timeoutMs) {
        if (!NativeBridge.load()) return error("native library not loaded");
        if (argv == null || argv.length == 0) return error("empty command");
        return parse(NativeBridge.nativeSu(argv, timeoutMs));
    }

    /** Drain buffered native log lines for the exported diagnostics file. */
    public static String drainNativeLog() {
        if (!NativeBridge.load()) return "";
        return NativeBridge.nativeLogDrain();
    }

    private static String kernelRelease() {
        try {
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.FileReader("/proc/sys/kernel/osrelease"));
            String line = reader.readLine();
            reader.close();
            return line == null ? "" : line.trim();
        } catch (Exception e) {
            return "";
        }
    }

    private static String safe(String value) { return value == null ? "" : value; }

    private static JSONObject parse(String json) {
        try {
            return new JSONObject(json == null ? "{}" : json);
        } catch (Exception e) {
            return error("native returned unparsable JSON");
        }
    }

    private static JSONObject error(String message) {
        try {
            JSONObject o = new JSONObject();
            o.put("error", message);
            return o;
        } catch (Exception e) {
            return new JSONObject();
        }
    }
}
