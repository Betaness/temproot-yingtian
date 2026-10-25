package org.fujiang.temproot;

import android.app.Application;

import java.io.File;

/** Owns the single session log for the process. */
public final class RootApp extends Application {
    private SessionLog log;

    @Override public void onCreate() {
        super.onCreate();
        log = new SessionLog(new File(getFilesDir(), "logs"));
        boolean ok = TemporaryRoot.isNativeLoaded();
        log.event("native_library", ok ? "libtemproot 已加载 " + TemporaryRoot.version()
                : "加载失败：" + TemporaryRoot.nativeLoadError());
        if (ok) TemporaryRoot.drainNativeLog();
    }

    public SessionLog logs() { return log; }
}
