# 临时 root 研究工具（TemporaryRoot）

面向 **Xiaomi Pad 9 Pro Max（代号 `yingtian`，Android 17 / SDK 37，
内核 `6.18.21-android17-5-g805aa6adea19-abogki565292102-4k`）** 的内核提权研究工程。
目标是给宿主应用（DroidDesk）提供一个可集成的「临时 root」能力模块。

当前版本：`0.3.0-experimental`，APK SHA-256 见 `dist/temproot-0.3.0-experimental.apk.sha256`。

## 结论先行（2026-10-25 修订）

从 `stock/kernel.config`（该固件 boot.img 的 IKCONFIG）读出的缓解措施：

| 配置 | 值 | 对提权的影响 |
| --- | --- | --- |
| `CONFIG_KASAN=y` + `CONFIG_KASAN_HW_TAGS=y` | 开 | 悬垂指针一经解引用即同步报错 |
| `CONFIG_PANIC_ON_OOPS=y` | 开 | 一次报错 = 整机重启 |
| `CONFIG_KFENCE=y`（sample 500ms） | 开 | 随机抽样隔离对象，跨缓存复用会被捕获 |
| `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` | 开 | 新分配清零，未初始化读泄漏失效 |
| `CONFIG_SYSVIPC` | **未启用** | `msg_msg` 类堆喷原语不存在 |
| `CONFIG_USER_NS` | **未启用** | 无法用用户命名空间扩大面 |
| `CONFIG_STATIC_USERMODEHELPER=y` | 开 | `modprobe_path` 覆盖失效 |
| `CONFIG_SHADOW_CALL_STACK=y` | 开 | 栈上返回地址劫持失效 |
| `CONFIG_SLAB_FREELIST_HARDENED/RANDOM=y` | 开 | 堆喷布局不可预测 |
| `CONFIG_ARM64_MTE=y` | 开 | 硬件内存标签可用 |

**因此：CVE-2026-98260 这条 UAF 在本固件上无法变成 root ——**
它会在第一次解引用悬垂对象时被 MTE/KASAN 捕获并触发 `PANIC_ON_OOPS`，
换来的是一次自动重启，不是提权。工具据此把提权入口做成**硬闸门**：
检测到上述组合就拒绝执行内核内存写入，只允许只读探测与非破坏性测量。

能真正拿到「临时 root」的路径见 [`docs/FINDINGS_ZH.md`](docs/FINDINGS_ZH.md) 第 4 节
（解锁引导程序后的 `fastboot boot` 一次性内核，不写任何分区）。

## 这个版本已经实现了什么

| 能力 | 状态 |
| --- | --- |
| 环境探测（设备/内核/进程/seccomp 真实可达性） | 已实现并编译进 APK |
| 缓解措施闸门（fail-closed，含离线构建表） | 已实现 |
| 运行时结构布局解析（读 `/sys/kernel/btf/vmlinux`，零硬编码偏移） | 已实现；本机 31/31 字段全部解析成功 |
| 非破坏性可达性测量（exec 失败后的定时器清理顺序） | 已实现 |
| 临时 root 守护 rootd + su 协议（`SO_PEERCRED` 授权、pty 传递、TTL） | 已实现 |
| 严格权限验证（uid + CAP_SYS_ADMIN + 特权操作） | 已实现 |
| 中文控制界面、日志持久化与导出 | 已实现 |
| 内核内存写入 / 凭据改写 | **未实现**（被闸门阻断，本固件上不可行） |
| 实机验证 | **未执行**（本机无可用 Android 运行环境） |

## 构建

```powershell
$py = 'C:\Users\Administrator\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $py scripts\build_native.py --abis arm64-v8a x86_64   # 需要 NDK r27c
& $py scripts\check_jni.py                              # JNI 符号与 Java 声明逐一对齐
& $py scripts\build_apk.py                              # 输出 dist\temproot-0.3.0-experimental.apk
```

工具链：NDK r27c（clang 18.0.3）、JDK（`--release 8`）、Android Platform 35、
Build Tools 35.0.0、aapt2 / d8 / zipalign / apksigner。不使用 Gradle。

## 安装

```powershell
adb install -r dist\temproot-0.3.0-experimental.apk
```

应用零权限、非 debuggable、`extractNativeLibs=true`（`.so` 需要被解压才能 `dlopen`）。

## 给宿主应用集成

见 [`docs/INTEGRATION_ZH.md`](docs/INTEGRATION_ZH.md)：`TemporaryRoot` 是唯一入口，
全部方法阻塞式、返回 `JSONObject`，不会为预期失败抛异常。

## 目录

```
native/      arm64 C 核心（探测 / 闸门 / BTF / 布局 / 定时器测量 / rootd / 验证 / JNI）
app/         Java 界面与对外 API
scripts/     构建、JNI 自检、BTF 转储、一次性临时 root 脚本
docs/        设计、发现、集成说明
dist/        构建产物与哈希
```

## 许可

见 `LICENSES.md`。
