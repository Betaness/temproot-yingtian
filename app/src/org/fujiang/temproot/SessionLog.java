package org.fujiang.temproot;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;

/**
 * Bounded, app-private session log. Events, the newest native snapshot and the
 * native log drain are stored in one rotating text file per run (max 10).
 * No exception messages, no arbitrary paths, no logcat.
 */
public final class SessionLog {
    public static final String VERSION = "0.3.0-experimental";
    private static final int MAX_EVENTS = 160, MAX_LOGS = 10, MAX_REPORT = 65536;
    private static final String PREFIX = "temproot-";
    private final File directory;
    private final File current;
    private final List<String> events = new ArrayList<>();
    private String report = "尚未采集；请先在界面上运行环境探测。";
    private String persistenceError = "";

    public SessionLog(File directory) {
        this.directory = directory;
        this.current = new File(directory, PREFIX + System.currentTimeMillis() + "-" + UUID.randomUUID() + ".txt");
        event("session_started", "版本 " + VERSION + "；提权入口受缓解措施闸门控制");
        try {
            File[] files = history();
            for (int i = MAX_LOGS; i < files.length; i++) Files.deleteIfExists(files[i].toPath());
        } catch (Exception e) {
            persistenceError = e.getClass().getSimpleName();
        }
    }

    private static String now() {
        SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.ROOT);
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        return f.format(new Date());
    }

    public synchronized void event(String stage, String detail) {
        events.add(now() + "  " + stage + "  " + detail);
        while (events.size() > MAX_EVENTS) events.remove(0);
        persist();
    }

    public synchronized void setReport(String json) {
        report = json == null ? "{}" : json.length() <= MAX_REPORT ? json
                : json.substring(0, MAX_REPORT) + "\n[报告过长，已截断]";
        persist();
    }

    public synchronized void failure(String stage, Throwable error) {
        event(stage, describe(error));
    }

    public static String describe(Throwable error) {
        StringBuilder text = new StringBuilder();
        for (int cause = 0; error != null && cause < 4; cause++, error = error.getCause()) {
            if (cause > 0) text.append("\ncaused_by: ");
            text.append(error.getClass().getName());
            int count = 0;
            for (StackTraceElement frame : error.getStackTrace()) {
                if (frame.getClassName().startsWith("org.fujiang.temproot.") && count++ < 16)
                    text.append("\n  at ").append(frame.getClassName()).append('.')
                        .append(frame.getMethodName()).append(':').append(frame.getLineNumber());
            }
        }
        return text.toString();
    }

    public synchronized String snapshot() {
        return "临时 root 研究工具 · 日志\n版本：" + VERSION + "\n"
                + "用途：设备与内核环境核验、可达性测量；不是提权成功证明。\n"
                + "隐私：不采集序列号、账号、网络地址、其他应用日志；异常省略消息与路径。\n"
                + "时间使用 UTC。仅在你主动分享或导出时才离开应用。\n"
                + (persistenceError.isEmpty() ? "" : "本地保存错误：" + persistenceError + "\n")
                + "\n=== 事件（最多 " + MAX_EVENTS + " 条） ===\n" + String.join("\n", events)
                + "\n\n=== 最近一次探测 JSON ===\n" + report + "\n"
                + "\n=== 原生层日志 ===\n" + TemporaryRoot.drainNativeLog() + "\n";
    }

    private void persist() {
        File temp = new File(directory, current.getName() + ".tmp");
        try {
            Files.createDirectories(directory.toPath());
            Files.write(temp.toPath(), snapshot().getBytes(StandardCharsets.UTF_8));
            Files.move(temp.toPath(), current.toPath(),
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            persistenceError = "";
        } catch (Exception e) {
            persistenceError = e.getClass().getSimpleName();
        }
    }

    public synchronized String persistenceError() { return persistenceError; }

    public synchronized File currentFile() { return current; }

    public synchronized File[] history() {
        File[] files = directory.listFiles((dir, name) -> name.matches("temproot-[0-9]+-[a-f0-9-]+\\.txt"));
        if (files == null) return new File[0];
        Arrays.sort(files, Comparator.comparing((File f) -> !f.equals(current))
                .thenComparing(Comparator.comparingLong(File::lastModified).reversed())
                .thenComparing(File::getName));
        return files;
    }

    public synchronized String read(File file) throws IOException {
        File safe = safeFile(directory, file.getName());
        if (Arrays.stream(history()).noneMatch(f -> f.getName().equals(safe.getName())))
            throw new IOException("Not a log file");
        if (safe.length() > 262144) throw new IOException("Log too large");
        return new String(Files.readAllBytes(safe.toPath()), StandardCharsets.UTF_8);
    }

    public static File safeFile(File directory, String name) throws IOException {
        if (name == null || !name.matches("temproot-[a-zA-Z0-9-]+\\.txt"))
            throw new IOException("Invalid log name");
        File candidate = new File(directory, name).getCanonicalFile();
        if (!directory.getCanonicalFile().equals(candidate.getParentFile()))
            throw new IOException("Invalid log path");
        return candidate;
    }
}
