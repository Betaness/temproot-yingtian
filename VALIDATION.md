# 验证记录

本文件只记录**真实执行过**的命令与输出摘要。未执行的项一律写 `NOT RUN` 并给出可复现命令。

环境：Windows `10.0.26200`，PowerShell 5.1，用户 `D460FAC62907FDA\Administrator`，
工作目录 `D:\Codex\temproot`。

## 1. 工具链

| 项目 | 实测 |
| --- | --- |
| NDK | `android-ndk-r27c`（`Pkg.Revision = 27.2.12479018`） |
| NDK 归档校验 | 官方 `repository2-3.xml`：size `781511249`、SHA-1 `ac5f7762764b1f15341094e148ad4f847d050c38`；实测一致 |
| clang | `Android (12470979, based on r522817c) clang version 18.0.3` |
| JDK | `javac 26-ea`（`C:\Program Files (x86)\jdk-26`），`--release 8` 可用 |
| Android Platform | `35_r02`（沿用 `android-kernel/.tools/android`） |
| Build Tools | `35.0.0`（aapt2 / d8 / zipalign / apksigner） |
| Gradle | 未使用 |

## 2. 构建

```powershell
& $py scripts\build_native.py --abis arm64-v8a x86_64
& $py scripts\check_jni.py --abi arm64-v8a
& $py scripts\build_apk.py
```

结果：

```
arm64-v8a: dist\lib\arm64-v8a\libtemproot.so  55272 bytes
x86_64   : dist\lib\x86_64\libtemproot.so     56872 bytes
native declarations: 12 / exported JNI symbols: 12 / JNI_OnLoad: True
NEEDED: libz.so, libdl.so, libc.so
APK: 86638 bytes  sha256=40d33aa99392b214342dee4ad85027d298086124941be3ffa55cd65b909a4338
```

首次编译失败并已修复的真实错误（保留以说明不是一次成功）：

| 错误 | 原因 | 修复 |
| --- | --- | --- |
| `call to undeclared function 'unshare'` | 缺 `_GNU_SOURCE` | `tr_probe.c` 顶部加 `#define _GNU_SOURCE 1` |
| `argument unused during compilation: '-shared'` | `-shared` 混进编译参数 | 拆成编译/链接两组 |
| `version script assignment of 'global' to symbol 'JNI_OnLoad' failed` | 未定义 `JNI_OnLoad` | `tr_jni.c` 补 `JNI_OnLoad` |

## 3. Android 运行测试 — NOT RUN

```powershell
# 曾尝试并可复现失败原因：
$env:ANDROID_AVD_HOME='D:\Codex\android-kernel\.tools\android\avd'
& 'D:\Codex\android-kernel\.tools\android\emulator\emulator\emulator.exe' `
    -avd kernelcheck35 -no-audio -no-window -port 5580 -gpu swiftshader_indirect
```

实测输出（决定性地说明问题不在脚本）：

```
ERROR | x86_64 emulation currently requires hardware acceleration!
CPU acceleration status: Android Emulator hypervisor driver is not installed on this machine
```

本机未安装 AEHD/WHPX，x86_64 模拟器无法启动；`adb devices` 始终为空。
上一轮 `android-kernel` 记录的「模拟器 ADB offline / 启动超时」同一根因。

因此以下项目全部 `NOT RUN`：

| 项目 | 复现命令 |
| --- | --- |
| APK 安装 | `adb install -r dist\temproot-0.3.0-experimental.apk` |
| 启动与 UI | `adb shell am start -n org.fujiang.temproot/.MainActivity` |
| 原生库加载 | `adb logcat -s temproot` 或界面「阶段状态」卡片 |
| 可达性测量 | 界面「运行测量（8 轮）」 |
| rootd 启动与 su | 界面「启动守护」→「通过守护执行 id」 |
| 权限验证 | 界面「运行权限验证」 |

## 4. 静态验证（已通过）

| 检查 | 命令 | 结果 |
| --- | --- | --- |
| 布局解析（独立实现交叉校验） | `scripts\btf_dump.py D:\Codex\android-kernel\stock\kernel-0.btf` | 170,569 类型，31/31 字段命中，`missing: 0` |
| ELF 段对齐 | `llvm-readelf -l libtemproot.so` | `LOAD ... 0x4000`（16 KiB 兼容） |
| JNI 一致性 | `scripts\check_jni.py` | 12/12 |
| 签名 | `apksigner verify --print-certs` | v2 true / v3 true，RSA 3072 |
| 对齐 | `zipalign -c 4` | 通过 |
| 资源表 | `build_apk.py` 内置检查 | `stored`、`aligned_4_bytes: true` |
| 清单 | `aapt2 dump badging` | 无 `uses-permission`、无 `application-debuggable`、`native-code: 'arm64-v8a' 'x86_64'` |

## 5. 布局交叉校验的两次修正

用真 BTF 才发现的三处错误假设（修正前 3 个字段缺失）：

```
MISSING  signal_struct.nr_timers      -> 该成员不存在，改用 posix_cputimers (+0x118)
MISSING  pipe_inode_info.head         -> 在 +0x058 匿名 union 内，解析器需下钻
MISSING  k_itimer.it_clockid          -> 真实名为 it_clock (+0x024)
```

修正后 `missing: 0`。这三处如果靠猜，会在真机上表现为静默的偏移错误。
