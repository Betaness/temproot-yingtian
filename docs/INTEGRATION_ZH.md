# 集成到宿主应用（DroidDesk）

## 1. 需要搬走的东西

| 类型 | 路径 | 说明 |
| --- | --- | --- |
| 原生库 | `dist/lib/arm64-v8a/libtemproot.so` | 放 `src/main/jniLibs/arm64-v8a/` |
| 原生库 | `dist/lib/x86_64/libtemproot.so` | 仅模拟器需要，可删 |
| 原生源码 | `native/*.c, *.h` | 想自己编就整份带走（10 个 .c） |
| Java API | `app/src/org/fujiang/temproot/TemporaryRoot.java` | 唯一对外入口 |
| Java API | `app/src/org/fujiang/temproot/NativeBridge.java` | JNI 声明，必须与包名一致 |
| 可选 | `SessionLog.java` / `LogProvider.java` | 宿主已有日志体系就用自己的 |

**包名约束**：`NativeBridge` 的包名必须保持 `org.fujiang.temproot`，
因为 JNI 符号名是 `Java_org_fujiang_temproot_NativeBridge_*`。
想改包名，就同步改 `native/tr_jni.c` 的函数名（或加 `JNI_OnLoad` 里的
`RegisterNatives`，本工程用的是静态命名法，更省事）。

## 2. 权限与清单

APK 侧**不需要任何 Android 权限**：全部动作要么是读 `/proc`、`/sys/kernel/btf`，
要么是本地 unix socket。因此清单里不要加 `uses-permission`，
`extractNativeLibs` 必须是 `true`（`.so` 要被解压到 `lib/` 才能 `dlopen`）。

宿主如果要把 root 传给别的应用，那属于 **rootd 的授权表**，不是 Android 权限：

```
# 文件：<app files dir>/allowed_uids   （每行一个 uid，"all" 表示全部放行）
2000
10123
```

## 3. 调用方式

全部方法**阻塞**，必须在工作线程调用；都返回 `org.json.JSONObject`，
预期失败不抛异常（返回 `{"error": "..."}`）。

```java
import org.fujiang.temproot.TemporaryRoot;
import org.json.JSONObject;

// 1) 原生库加载（可重复调用，失败原因可查）
if (!TemporaryRoot.isNativeLoaded()) {
    Log.w("DroidDesk", "native load failed: " + TemporaryRoot.nativeLoadError());
}

// 2) 环境探测 + 闸门 + 布局（约 100~300 ms）
JSONObject probe = TemporaryRoot.probe();
JSONObject env   = probe.optJSONObject("env");
JSONObject guard = probe.optJSONObject("guard");
JSONObject layout= probe.optJSONObject("layout");

boolean allowed = guard != null && guard.optBoolean("exploit_allowed");
String  reason  = guard == null ? "no data" : guard.optString("block_code");
String  humanZh = probe.optString("guard_summary");

// 3) 非破坏性可达性测量（安全，可以在任何设备上跑）
JSONObject reach = TemporaryRoot.measureReachability(8);
// reach.optString("conclusion") -> PRE_FIX_ORDER / POST_FIX_ORDER / INCONCLUSIVE

// 4) 提权（闸门阻断时立即返回，不会碰内核内存）
JSONObject esc = TemporaryRoot.escalate();
// esc.optInt("status") == 0 才代表"执行完成"，仍不代表成功，必须再 verify

// 5) 严格验证（唯一的"能用"判据）
JSONObject v = TemporaryRoot.verify();
boolean rooted = v.optBoolean("verified");   // uid=0 且 CAP_SYS_ADMIN 且特权操作成功

// 6) 授权层：把 root 分发给宿主或其他应用
int rc = TemporaryRoot.rootDaemonStart("/data/data/<宿主包名>/files/allowed_uids", 900);
JSONObject r = TemporaryRoot.su(new String[]{"id"}, 4000);
if (r.optInt("status") == 0) {
    Log.i("DroidDesk", "exit=" + r.optInt("exit_code") + " out=" + r.optString("output"));
}
TemporaryRoot.rootDaemonStop();
```

## 4. 状态机建议

宿主不要把上面的步骤压成一个布尔值。推荐按 `TemporaryRoot.Stage` 逐项点亮：

```
LIBRARY_LOADED -> ENVIRONMENT_PROBED -> GUARD_EVALUATED -> LAYOUT_RESOLVED
   -> REACHABILITY_MEASURED -> ESCALATION_EXECUTED -> PRIVILEGE_VERIFIED
   -> DAEMON_RUNNING
```

UI 文案建议：

| 状态 | 文案 |
| --- | --- |
| 闸门阻断 | 当前内核启用了 KASAN/MTE 类检测，提权会重启设备，已停止 |
| 闸门放行但未执行 | 可进入实验性流程（未实机验证） |
| 执行完成但验证失败 | 提权流程已运行，但权限验证未通过 |
| 验证通过 | 已取得临时 root（重启后失效） |

## 5. rootd 协议（非 Java 调用方）

如果宿主有自己的 native 进程，可以直接实现客户端：

```
AF_UNIX SOCK_STREAM @fujiang.temproot.su
请求： struct tr_su_hdr { uint32 magic=0x54525331; uint32 version=1;
                          int32 uid; int32 pid; int32 argc; int32 reserved; }
      + argc 个以 '\0' 结尾的参数（第一个是命令绝对路径）
应答： struct tr_su_reply { int32 status; int32 child_pid; int32 reserved[2]; }
      并附带 1 个文件描述符（SCM_RIGHTS）= 命令的 pty master
退出： 控制 socket 上再收 8 字节 { uint32 "TREX"; int32 exit_code; }
```

`status != 0` 时不会附带 fd。授权判定一律以 `SO_PEERCRED` 为准。

## 6. 不要做的事

- 不要把 `libtemproot.so` 当命令行程序 exec（它没有 `main`，也没有独立进程入口）。
- 不要在 `ro.boot.verifiedbootstate != orange` 的设备上尝试 `fastboot boot`。
- 不要把 `escalate()` 返回的 `status == 0` 当作 root 成功，必须 `verify()`。
- 不要把闸门结论缓存到下次开机（内核可能被 OTA 换掉）。
