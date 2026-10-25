package org.fujiang.temproot;

/**
 * Thin JNI binding. Load failures are recorded instead of thrown so the UI can
 * explain exactly why the native core is missing (for example a mismatched ABI).
 */
public final class NativeBridge {
    private static volatile boolean loaded;
    private static volatile String loadError = "";

    private NativeBridge() { }

    public static synchronized boolean load() {
        if (loaded) return true;
        try {
            System.loadLibrary("temproot");
            loaded = true;
            loadError = "";
        } catch (Throwable t) {
            loadError = t.getClass().getSimpleName() + ": " + t.getMessage();
        }
        return loaded;
    }

    public static String loadError() { return loadError; }
    public static boolean isLoaded() { return loaded; }

    public static native void nativeInit();
    public static native String nativeVersion();
    public static native String nativeProbe(String manufacturer, String model, String device,
                                            String fingerprint, String incremental, String release,
                                            int sdk, String securityPatch);
    public static native String nativeLayoutReport();
    public static native String nativeTimerProbe(int rounds);
    public static native String nativeTrigger();
    public static native String nativeVerify();
    public static native int nativeRootdStart(String allowFile, int ttlSeconds);
    public static native int nativeRootdPing();
    public static native int nativeRootdStop();
    public static native String nativeSu(String[] argv, int timeoutMs);
    public static native String nativeLogDrain();
}
