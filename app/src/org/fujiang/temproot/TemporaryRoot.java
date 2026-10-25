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

    /**
     * Merge evidence gathered by a companion process that has shell rights
     * (adb, Shizuku or a running rootd). The app itself cannot read
     * /proc/cmdline or /sys/kernel/btf on this device, so without this input the
     * guard must stay conservative.
     *
     * Negative values mean "unknown, keep whatever the probe found".
     */
    public static JSONObject applyEvidence(int kasanOff, int mteHw, String verifiedBootState,
                                          String flashLocked, String verityMode) {
        if (!NativeBridge.load()) return error("native library not loaded");
        return parse(NativeBridge.nativeApplyEvidence(kasanOff, mteHw, verifiedBootState,
                flashLocked, verityMode));
    }

    /**
     * Parse a companion-written evidence file:
     * <pre>
     * kasan_off=1
     * mte=0
     * verifiedbootstate=green
     * flash_locked=1
     * veritymode=enforcing
     * </pre>
     */
    public static JSONObject applyEvidenceFromFile(java.io.File file) {
        if (file == null || !file.isFile()) return error("evidence file not found");
        int kasanOff = -1, mte = -1;
        String vbs = "", locked = "", verity = "";
        try (java.io.BufferedReader reader =
                     new java.io.BufferedReader(new java.io.FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int eq = line.indexOf('=');
                if (eq <= 0) continue;
                String key = line.substring(0, eq).trim().toLowerCase(java.util.Locale.ROOT);
                String value = line.substring(eq + 1).trim();
                switch (key) {
                    case "kasan_off":
                        kasanOff = truthy(value) ? 1 : 0;
                        break;
                    case "mte":
                    case "mte_hw":
                        mte = truthy(value) ? 1 : 0;
                        break;
                    case "verifiedbootstate":
                    case "verified_boot_state":
                        vbs = value;
                        break;
                    case "flash_locked":
                    case "flash.locked":
                        locked = value;
                        break;
                    case "veritymode":
                    case "verity_mode":
                        verity = value;
                        break;
                    default:
                        break;
                }
            }
        } catch (Exception e) {
            return error("evidence read failed: " + e.getClass().getSimpleName());
        }
        JSONObject result = applyEvidence(kasanOff, mte, vbs, locked, verity);
        try {
            result.put("evidence_file", file.getName());
            result.put("evidence_parsed", "kasan_off=" + kasanOff + " mte=" + mte
                    + " boot=" + vbs + " locked=" + locked + " verity=" + verity);
        } catch (Exception ignored) {
            /* JSONObject.put on a valid map cannot fail here. */
        }
        return result;
    }

    private static boolean truthy(String value) {
        return "1".equals(value) || "true".equalsIgnoreCase(value)
                || "yes".equalsIgnoreCase(value) || "on".equalsIgnoreCase(value);
    }

    /**
     * Report the exploitation stage table. Never writes kernel memory: the
     * destructive stages refuse unless an operator exported
     * TR_DESTRUCTIVE_ALLOW=1 in the process environment, which the app itself
     * never sets.
     *
     * @param groom when true, also performs the user-space pipe pre-spray and
     *              releases it again before returning
     */
    public static JSONObject exploitPlan(boolean groom) {
        if (!NativeBridge.load()) return error("native library not loaded");
        return parse(NativeBridge.nativeExploitPlan(groom ? 1 : 0));
    }

    /**
     * Enumerate every readable kernel interface that could disclose an address.
     * Read-only: it opens files, reads a bounded amount and closes them.
     * A negative result defines whether the primitive stage is blocked by the
     * platform or merely by missing code.
     */
    public static JSONObject leakProbe() {
        if (!NativeBridge.load()) return error("native library not loaded");
        return parse(NativeBridge.nativeLeakProbe());
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
