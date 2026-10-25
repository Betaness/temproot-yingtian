package org.fujiang.temproot;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Comparator;
import java.util.UUID;

/**
 * Control surface. Every card reports measured evidence; nothing here can turn a
 * blocked build into an allowed one, and the escalation button stays disabled
 * unless the native guard explicitly allows execution.
 */
public final class MainActivity extends Activity {
    private static final int EXPORT_REQUEST = 51;
    private static final int BG = Color.rgb(9, 15, 21), CARD = Color.rgb(21, 33, 44);
    private static final int INK = Color.rgb(234, 242, 247), MUTED = Color.rgb(158, 178, 192);
    private static final int ACCENT = Color.rgb(103, 220, 190), AMBER = Color.rgb(255, 199, 109);
    private static final int DANGER = Color.rgb(255, 122, 122);

    private LinearLayout body;
    private SessionLog sessionLog;
    private JSONObject probe, reachability, escalation, verification;
    private String banner = "尚未探测";
    private String pendingExport;
    private boolean busy;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        sessionLog = ((RootApp) getApplication()).logs();
        sessionLog.event("activity_created", saved == null ? "打开控制页面" : "恢复控制页面");
        Window w = getWindow();
        w.setStatusBarColor(BG);
        w.setNavigationBarColor(BG);
        render();
        if (saved == null) probeNow();
    }

    @Override public void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
        if (pendingExport != null) state.putString("pending_export", pendingExport);
    }

    private int dp(int n) { return (int) (n * getResources().getDisplayMetrics().density + 0.5f); }

    private TextView text(String value, int size, int color) {
        TextView t = new TextView(this);
        t.setText(value);
        t.setTextSize(size);
        t.setTextColor(color);
        t.setLineSpacing(dp(3), 1f);
        t.setPadding(0, dp(3), 0, dp(3));
        t.setTextIsSelectable(true);
        return t;
    }

    private LinearLayout card(String title) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(18), dp(16), dp(18), dp(16));
        GradientDrawable shape = new GradientDrawable();
        shape.setColor(CARD);
        shape.setCornerRadius(dp(18));
        box.setBackground(shape);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.bottomMargin = dp(12);
        body.addView(box, lp);
        TextView heading = text(title, 17, INK);
        heading.setTypeface(null, Typeface.BOLD);
        box.addView(heading);
        return box;
    }

    private void row(LinearLayout box, String label, String value) {
        box.addView(text(label, 12, MUTED));
        box.addView(text(value, 14, INK));
    }

    private void stage(LinearLayout box, String name, int state, String note) {
        String mark = state == 1 ? "✓  " : state == 0 ? "—  " : "×  ";
        int color = state == 1 ? ACCENT : state == -1 ? DANGER : AMBER;
        box.addView(text(mark + name + "：" + note, 14, color));
    }

    private void render() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BG);
        body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(20), dp(26), dp(20), dp(24));
        scroll.addView(body);
        scroll.setOnApplyWindowInsetsListener((v, insets) -> {
            v.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                    insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            return insets.consumeSystemWindowInsets();
        });
        setContentView(scroll);

        body.addView(text("ANDROID · 内核提权研究", 12, ACCENT));
        TextView title = text("临时 root", 32, INK);
        title.setTypeface(null, Typeface.BOLD);
        body.addView(title);
        body.addView(text(SessionLog.VERSION + "  /  arm64 原生核心  /  " + TemporaryRoot.version(), 13, MUTED));

        LinearLayout status = card("当前结论");
        status.addView(text(banner, 19, AMBER));
        if (probe != null) {
            JSONObject guard = probe.optJSONObject("guard");
            if (guard != null) {
                status.addView(text(probe.optString("guard_summary", ""), 14, INK));
                String code = guard.optString("block_code", "");
                if (!code.isEmpty()) status.addView(text("阻断码：" + code, 13, DANGER));
            }
        }

        boolean libOk = TemporaryRoot.isNativeLoaded();
        boolean guardOk = probe != null && probe.optJSONObject("guard") != null
                && probe.optJSONObject("guard").optBoolean("exploit_allowed");
        JSONObject layout = probe == null ? null : probe.optJSONObject("layout");

        LinearLayout stages = card("阶段状态");
        stage(stages, "原生库加载", libOk ? 1 : -1,
                libOk ? "libtemproot 已加载" : "失败：" + TemporaryRoot.nativeLoadError());
        stage(stages, "环境探测", probe != null ? 1 : 0, probe != null ? "已完成" : "未执行");
        stage(stages, "缓解措施闸门", probe == null ? 0 : guardOk ? 1 : -1,
                probe == null ? "未评估" : guardOk ? "放行（实验性）" : "阻断");
        stage(stages, "运行时布局", layout == null ? 0 : layout.optBoolean("complete") ? 1 : -1,
                layout == null ? "未解析" : layout.optBoolean("complete")
                        ? "BTF 字段齐全" : "缺失 " + layout.optInt("missing_count") + " 项");
        stage(stages, "可达性测量", reachability != null ? 1 : 0,
                reachability == null ? "未执行" : reachability.optString("conclusion", "?"));
        stage(stages, "提权执行", escalation != null && escalation.optInt("status", -1) == 0 ? 1
                : escalation != null ? -1 : 0,
                escalation == null ? "未执行" : escalation.optString("message", "?"));
        stage(stages, "权限验证", verification == null ? 0
                : verification.optBoolean("verified") ? 1 : -1,
                verification == null ? "未执行" : verification.optString("summary", "?"));
        stages.addView(text("以上状态彼此独立：构建成功 ≠ 安装成功 ≠ 权限验证成功。", 12, MUTED));

        if (probe != null) buildDeviceCard(probe.optJSONObject("env"));
        if (probe != null) buildGuardCard(probe.optJSONObject("guard"));
        buildReachabilityCard();
        buildEscalationCard(guardOk);
        buildDaemonCard();
        buildVerifyCard();
        buildLogCard();

        LinearLayout actions = card("操作");
        Button redo = new Button(this);
        redo.setText(busy ? "处理中…" : "重新探测环境");
        redo.setEnabled(!busy);
        redo.setOnClickListener(v -> probeNow());
        actions.addView(redo);

        Button layoutBtn = new Button(this);
        layoutBtn.setText("查看运行时布局明细（BTF）");
        layoutBtn.setOnClickListener(v -> showText("运行时布局", TemporaryRoot.layoutReport()));
        actions.addView(layoutBtn);

        Button help = new Button(this);
        help.setText("使用说明与限制");
        help.setOnClickListener(v -> showText("使用说明",
                "1. 首次打开自动执行环境探测：设备标识、内核配置、seccomp 可达性、BTF 可读性。\n\n"
                + "2. 闸门（guard）是硬性的：内核启用 KASAN / PANIC_ON_OOPS / KFENCE 时，"
                + "任何内核内存写入都会导致崩溃或重启，因此提权入口保持禁用。\n\n"
                + "3. 「可达性测量」是非破坏性实验：它只创建并删除本进程的 CPU 定时器，"
                + "观察 exec 失败后的清理顺序，不解引用任何已释放对象。\n\n"
                + "4. 临时 root 守护（rootd）只在当前进程已有 root 凭据时才可启动；"
                + "重启即失效，不写分区、不加开机自启。\n\n"
                + "5. 「权限验证」只有在 uid=0、CapEff 含 CAP_SYS_ADMIN、且一个特权操作真正成功时才判定通过。\n\n"
                + "6. 日志仅保存在应用私有目录，只有你主动分享或导出才会离开设备。"));
        actions.addView(help);
    }

    private void buildDeviceCard(JSONObject env) {
        if (env == null) return;
        JSONObject device = env.optJSONObject("device");
        JSONObject proc = env.optJSONObject("process");
        JSONObject sc = env.optJSONObject("syscall_reachability");
        JSONObject ki = env.optJSONObject("kernel_interfaces");
        JSONObject root = env.optJSONObject("existing_root");
        LinearLayout box = card("设备与内核");
        if (device != null) {
            row(box, "型号 / 代号", device.optString("model") + " / " + device.optString("device"));
            row(box, "Android / SDK / 补丁", device.optString("android_release") + " / "
                    + device.optInt("sdk_int") + " / " + device.optString("security_patch"));
            row(box, "内核标识", device.optString("kernel_release"));
            row(box, "页大小 / MTE 硬件", device.optInt("page_size") + " / "
                    + (device.optBoolean("hwcap2_mte") ? "支持" : "不支持"));
            row(box, "引导程序 / 验证启动",
                    device.optString("verified_boot_state") + " · flash.locked="
                            + device.optString("flash_locked") + " · veritymode="
                            + device.optString("verity_mode") + "（来源 "
                            + device.optString("boot_state_source") + "）");
            box.addView(text(device.optBoolean("boot_unlocked")
                            ? "引导程序已解锁：可以走 fastboot boot 一次性内核拿到真正的临时 root（不写分区）。"
                            : "引导程序锁定或状态未知：fastboot boot 会被拒绝，此状态下本固件没有可用的临时 root 路径。",
                    12, device.optBoolean("boot_unlocked") ? ACCENT : AMBER));
            row(box, "构建增量", device.optString("incremental"));
        }
        if (proc != null) {
            row(box, "本进程", "uid " + proc.optInt("uid") + " · euid " + proc.optInt("euid")
                    + " · pid " + proc.optInt("pid") + " · " + (proc.optInt("is64") == 1 ? "64 位" : "32 位"));
            row(box, "CapEff / Seccomp", proc.optString("cap_eff") + " / " + proc.optString("seccomp"));
            row(box, "SELinux 上下文", proc.optString("selinux"));
        }
        if (sc != null) {
            row(box, "系统调用可达性",
                    "timer_create=" + yesNo(sc.optBoolean("timer_create"))
                            + " · unshare(CLONE_FILES)=" + yesNo(sc.optBoolean("unshare_files"))
                            + " · memfd=" + yesNo(sc.optBoolean("memfd_create"))
                            + " · io_uring=" + yesNo(sc.optBoolean("io_uring_setup"))
                            + " · userfaultfd=" + yesNo(sc.optBoolean("userfaultfd"))
                            + " · fork+exec=" + yesNo(sc.optBoolean("fork_exec")));
            box.addView(text("这些是本应用进程内真实发起过系统调用的结果，不是推断值。", 12, MUTED));
        }
        if (ki != null) {
            row(box, "内核只读接口", "BTF=" + (ki.optBoolean("btf_readable")
                    ? ki.optLong("btf_size") + " 字节" : "不可读")
                    + " · kallsyms=" + yesNo(ki.optBoolean("kallsyms_readable"))
                    + " · /proc/self/timers=" + yesNo(ki.optBoolean("proc_timers_readable")));
        }
        if (root != null) {
            row(box, "既有 root 组件", "su=" + (root.optBoolean("su_present")
                    ? root.optString("su_path") : "无")
                    + " · KernelSU=" + yesNo(root.optBoolean("kernelsu"))
                    + " · Magisk=" + yesNo(root.optBoolean("magisk")));
        }
    }

    private void buildGuardCard(JSONObject guard) {
        if (guard == null) return;
        LinearLayout box = card("缓解措施闸门");
        box.addView(text(guard.optBoolean("exploit_allowed")
                        ? "判定：允许实验性执行" : "判定：禁止内核内存写入",
                16, guard.optBoolean("exploit_allowed") ? ACCENT : DANGER));
        JSONArray reasons = guard.optJSONArray("reasons");
        if (reasons != null) {
            for (int i = 0; i < reasons.length(); i++) {
                box.addView(text("· " + reasons.optString(i), 13, INK));
            }
        }
        box.addView(text("配置来源：" + (guard.optBoolean("runtime_config_known")
                ? "本机 /proc/config.gz（运行时读取）"
                : "离线提取的内核配置（按内核标识精确匹配）"), 12, MUTED));
    }

    private void buildReachabilityCard() {
        LinearLayout box = card("可达性测量 · 非破坏性");
        box.addView(text("测量 exec 失败后 POSIX CPU 定时器的清理顺序，"
                + "用于判断该内核是否存在修复前的顺序。全程不解引用已释放对象。", 13, MUTED));
        Button run = new Button(this);
        run.setText(reachability == null ? "运行测量（8 轮）" : "重新运行测量（8 轮）");
        run.setEnabled(!busy);
        run.setOnClickListener(v -> measureNow());
        box.addView(run);
        if (reachability == null) {
            box.addView(text("尚未测量。", 13, AMBER));
            return;
        }
        box.addView(text("结论：" + reachability.optString("conclusion"), 16,
                "PRE_FIX_ORDER".equals(reachability.optString("conclusion")) ? AMBER : ACCENT));
        box.addView(text(reachability.optString("detail"), 13, INK));
        JSONArray rows = reachability.optJSONArray("rows");
        if (rows != null) {
            for (int i = 0; i < rows.length(); i++) {
                JSONObject r = rows.optJSONObject(i);
                if (r == null) continue;
                box.addView(text("策略 " + r.optInt("strategy") + "：errno=" + r.optInt("exec_errno")
                        + " · 装载 " + r.optInt("timers_armed")
                        + " · 删除成功 " + r.optInt("delete_ok")
                        + " · 已清理 " + r.optInt("delete_einval")
                        + " · 残留列表 " + r.optInt("listed_after")
                        + (r.optBoolean("signaled") ? " · 子进程被信号 " + r.optInt("signal") + " 终止" : ""),
                        12, MUTED));
            }
        }
    }

    private void buildEscalationCard(boolean guardOk) {
        LinearLayout box = card("提权执行");
        Button run = new Button(this);
        run.setText(guardOk ? "执行提权流程" : "提权流程已禁用（闸门阻断）");
        run.setEnabled(guardOk && !busy);
        run.setOnClickListener(v -> escalateNow());
        box.addView(run);
        if (escalation == null) {
            box.addView(text(guardOk ? "闸门已放行：可进入实验性流程。" : "当前构建不满足执行条件，入口保持禁用。",
                    13, guardOk ? AMBER : MUTED));
        } else {
            box.addView(text("状态：" + escalation.optString("message"), 15, AMBER));
            String detail = escalation.optString("detail", "");
            if (!detail.isEmpty()) box.addView(text(detail, 13, INK));
        }
    }

    private void buildDaemonCard() {
        LinearLayout box = card("临时 root 守护 · 授权层");
        boolean alive = TemporaryRoot.isNativeLoaded() && TemporaryRoot.rootDaemonPing() == 1;
        box.addView(text(alive ? "rootd 在线（抽象 socket @fujiang.temproot.su）" : "rootd 未运行", 15,
                alive ? ACCENT : MUTED));
        Button start = new Button(this);
        start.setText("启动守护（TTL 900 秒）");
        start.setEnabled(!busy);
        start.setOnClickListener(v -> runTask("daemon_start", () -> {
            File allowFile = new File(getFilesDir(), "allowed_uids");
            int rc = TemporaryRoot.rootDaemonStart(allowFile.getAbsolutePath(), 900);
            return rc >= 0 ? "守护启动返回 " + rc : "启动失败，原因：" + reasonOf(rc);
        }));
        box.addView(start);
        Button stop = new Button(this);
        stop.setText("停止守护");
        stop.setOnClickListener(v -> runTask("daemon_stop", () -> {
            TemporaryRoot.rootDaemonStop();
            return "已请求停止（幂等）";
        }));
        box.addView(stop);
        Button probeCmd = new Button(this);
        probeCmd.setText("通过守护执行 id");
        probeCmd.setOnClickListener(v -> runTask("su_id", () -> {
            JSONObject r = TemporaryRoot.su(new String[]{"id"}, 4000);
            int status = r.optInt("status", -999);
            if (status != 0) return "调用失败：" + r.optString("message", "?");
            return "exit=" + r.optInt("exit_code") + "\n" + r.optString("output");
        }));
        box.addView(probeCmd);
        box.addView(text("授权按连接进程的 SO_PEERCRED uid 判定；默认只允许本应用与自己。"
                + "守护随进程/TTL 结束，重启后不存在。", 12, MUTED));
    }

    private void buildVerifyCard() {
        LinearLayout box = card("权限验证");
        Button run = new Button(this);
        run.setText("运行权限验证");
        run.setEnabled(!busy);
        run.setOnClickListener(v -> verifyNow());
        box.addView(run);
        if (verification == null) {
            box.addView(text("尚未验证。判定条件：uid=0 且 CapEff 含 CAP_SYS_ADMIN 且至少一个特权操作成功。",
                    12, MUTED));
            return;
        }
        box.addView(text(verification.optString("summary"), 15,
                verification.optBoolean("verified") ? ACCENT : AMBER));
        box.addView(text("uid=" + verification.optInt("uid")
                + " euid=" + verification.optInt("euid")
                + " CapEff=" + verification.optString("cap_eff")
                + "\nSELinux=" + verification.optString("selinux")
                + "（enforce=" + verification.optInt("selinux_enforce") + "）"
                + "\n特权访问=" + verification.optString("privileged_path")
                + " errno=" + verification.optInt("privileged_open_errno")
                + " · setuid 往返=" + yesNo(verification.optBoolean("setuid_roundtrip_ok")), 12, MUTED));
    }

    private void buildLogCard() {
        LinearLayout box = card("诊断日志");
        box.addView(text("事件、探测 JSON 与原生日志自动保存，最多保留 10 次。", 13, INK));
        if (!sessionLog.persistenceError().isEmpty()) {
            box.addView(text("自动保存失败：" + sessionLog.persistenceError(), 13, AMBER));
        }
        Button share = new Button(this);
        share.setText("分享本次日志");
        share.setOnClickListener(v -> shareLog(sessionLog.snapshot()));
        box.addView(share);
        Button export = new Button(this);
        export.setText("保存到文件");
        export.setOnClickListener(v -> saveLog(sessionLog.snapshot()));
        box.addView(export);
        Button history = new Button(this);
        history.setText("历史日志");
        history.setOnClickListener(v -> history());
        box.addView(history);
    }

    private String reasonOf(int rc) {
        switch (rc) {
            case -7: return "当前进程没有 root 权限（euid≠0）";
            case -5: return "被缓解措施闸门阻断";
            case -8: return "调用方 uid 未获授权";
            case -4: return "守护未运行或 socket 不可达";
            case -3: return "I/O 失败";
            default: return "错误码 " + rc;
        }
    }

    private static String yesNo(boolean v) { return v ? "可用" : "不可用"; }

    private interface Task { String run() throws Exception; }

    private void runTask(String name, Task task) {
        if (busy) return;
        busy = true;
        render();
        new Thread(() -> {
            String result;
            try {
                result = task.run();
                sessionLog.event(name, "完成");
            } catch (Exception e) {
                sessionLog.failure(name + "_exception", e);
                result = "异常：" + e.getClass().getSimpleName();
            }
            final String message = result;
            runOnUiThread(() -> {
                busy = false;
                if (isDestroyed()) return;
                render();
                Toast.makeText(this, message, Toast.LENGTH_LONG).show();
            });
        }, "temproot-" + name).start();
    }

    private void probeNow() {
        if (busy) return;
        busy = true;
        banner = "正在探测…";
        render();
        new Thread(() -> {
            JSONObject result = null;
            try {
                result = TemporaryRoot.probe();
                sessionLog.setReport(result.toString(2));
                sessionLog.event("probe", "环境与闸门评估完成");
            } catch (Exception e) {
                sessionLog.failure("probe_exception", e);
            }
            final JSONObject done = result;
            runOnUiThread(() -> {
                busy = false;
                if (isDestroyed()) return;
                probe = done;
                JSONObject guard = done == null ? null : done.optJSONObject("guard");
                if (done == null) banner = "探测失败，详见日志";
                else if (guard != null && guard.optBoolean("exploit_allowed")) banner = "闸门放行 · 仅实验性";
                else banner = "闸门阻断 · 仅只读探测";
                if (done != null) {
                    JSONObject env = done.optJSONObject("env");
                    if (env != null && env.optJSONObject("syscall_reachability") != null
                            && !env.optJSONObject("syscall_reachability").optBoolean("timer_create")) {
                        banner = banner + "（timer_create 不可用）";
                    }
                }
                render();
            });
        }, "temproot-probe").start();
    }

    private void measureNow() {
        if (busy) return;
        busy = true;
        render();
        new Thread(() -> {
            JSONObject result = null;
            try {
                result = TemporaryRoot.measureReachability(8);
                sessionLog.event("reachability", result.optString("conclusion", "?"));
                sessionLog.setReport(result.toString(2));
            } catch (Exception e) {
                sessionLog.failure("reachability_exception", e);
            }
            final JSONObject done = result;
            runOnUiThread(() -> {
                busy = false;
                if (isDestroyed()) return;
                reachability = done;
                render();
            });
        }, "temproot-reach").start();
    }

    private void escalateNow() {
        if (busy) return;
        busy = true;
        render();
        new Thread(() -> {
            JSONObject result = null;
            try {
                result = TemporaryRoot.escalate();
                sessionLog.event("escalate", result.optString("message", "?"));
                sessionLog.setReport(result.toString(2));
            } catch (Exception e) {
                sessionLog.failure("escalate_exception", e);
            }
            final JSONObject done = result;
            runOnUiThread(() -> {
                busy = false;
                if (isDestroyed()) return;
                escalation = done;
                render();
            });
        }, "temproot-escalate").start();
    }

    private void verifyNow() {
        if (busy) return;
        busy = true;
        render();
        new Thread(() -> {
            JSONObject result = null;
            try {
                result = TemporaryRoot.verify();
                sessionLog.event("verify", result.optString("summary", "?"));
            } catch (Exception e) {
                sessionLog.failure("verify_exception", e);
            }
            final JSONObject done = result;
            runOnUiThread(() -> {
                busy = false;
                if (isDestroyed()) return;
                verification = done;
                render();
            });
        }, "temproot-verify").start();
    }

    private void showText(String title, String content) {
        ScrollView scroll = new ScrollView(this);
        TextView view = text(content, 12, Color.DKGRAY);
        view.setPadding(dp(16), dp(12), dp(16), dp(12));
        scroll.addView(view);
        new AlertDialog.Builder(this).setTitle(title).setView(scroll)
                .setPositiveButton("关闭", null).show();
    }

    private void shareLog(String snapshot) {
        try {
            File folder = new File(getCacheDir(), "shared-logs");
            Files.createDirectories(folder.toPath());
            File file = SessionLog.safeFile(folder, "temproot-" + System.currentTimeMillis()
                    + "-" + UUID.randomUUID() + ".txt");
            Files.write(file.toPath(), snapshot.getBytes(StandardCharsets.UTF_8));
            File[] old = folder.listFiles((dir, name) -> name.matches("temproot-[a-zA-Z0-9-]+\\.txt"));
            if (old != null) {
                Arrays.sort(old, Comparator.comparingLong(File::lastModified).reversed());
                for (int i = 20; i < old.length; i++) if (!old[i].equals(file)) Files.deleteIfExists(old[i].toPath());
            }
            Uri uri = new Uri.Builder().scheme("content").authority(LogProvider.AUTHORITY)
                    .appendPath(file.getName()).build();
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_STREAM, uri);
            intent.putExtra(Intent.EXTRA_SUBJECT, "临时 root 研究日志");
            intent.setClipData(ClipData.newRawUri("日志", uri));
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(intent, "选择接收日志的应用"));
            sessionLog.event("share_chooser", "已打开分享界面");
        } catch (Exception e) {
            sessionLog.failure("share_failed", e);
            Toast.makeText(this, "分享失败，请改用保存到文件", Toast.LENGTH_LONG).show();
        }
    }

    private void saveLog(String snapshot) {
        try {
            pendingExport = snapshot;
            Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_TITLE, "temproot-" + System.currentTimeMillis() + ".txt");
            startActivityForResult(intent, EXPORT_REQUEST);
        } catch (Exception e) {
            pendingExport = null;
            sessionLog.failure("export_picker_failed", e);
            Toast.makeText(this, "无法打开保存界面", Toast.LENGTH_LONG).show();
        }
    }

    private void history() {
        File[] files = sessionLog.history();
        if (files.length == 0) {
            showText("日志", sessionLog.snapshot());
            return;
        }
        String[] labels = new String[files.length];
        for (int i = 0; i < files.length; i++) {
            labels[i] = (files[i].equals(sessionLog.currentFile()) ? "本次 · " : "历史 · ")
                    + new java.text.SimpleDateFormat("MM-dd HH:mm:ss", java.util.Locale.getDefault())
                    .format(new java.util.Date(files[i].lastModified()));
        }
        new AlertDialog.Builder(this).setTitle("选择日志").setItems(labels, (d, index) -> {
            try {
                final String snapshot = sessionLog.read(files[index]);
                new AlertDialog.Builder(this).setTitle(labels[index])
                        .setItems(new String[]{"查看", "分享", "保存到文件"}, (dialog, action) -> {
                            if (action == 0) showText("日志预览", snapshot);
                            else if (action == 1) shareLog(snapshot);
                            else saveLog(snapshot);
                        }).show();
            } catch (Exception e) {
                sessionLog.failure("history_read_failed", e);
                Toast.makeText(this, "读取失败", Toast.LENGTH_LONG).show();
            }
        }).show();
    }

    @Override public void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != EXPORT_REQUEST) return;
        if (result != RESULT_OK || data == null || data.getData() == null || pendingExport == null) {
            pendingExport = null;
            sessionLog.event("export_cancelled", "取消或无有效目标");
            return;
        }
        final Uri uri = data.getData();
        final String snapshot = pendingExport;
        pendingExport = null;
        new Thread(() -> {
            try {
                OutputStream out = getContentResolver().openOutputStream(uri, "wt");
                if (out == null) throw new IllegalStateException("no output stream");
                out.write(snapshot.getBytes(StandardCharsets.UTF_8));
                out.close();
                sessionLog.event("export_completed", "写入并关闭成功");
                runOnUiThread(() -> Toast.makeText(this, "日志已保存", Toast.LENGTH_LONG).show());
            } catch (Exception e) {
                sessionLog.failure("export_exception", e);
                runOnUiThread(() -> Toast.makeText(this, "保存失败，可重试", Toast.LENGTH_LONG).show());
            }
        }, "temproot-export").start();
    }
}
