# 实机验证结果（2026-10-25）

设备：Xiaomi Pad 9 Pro Max（`M367FC` / 代号 `yingtian`），Android 17 / SDK 37，
内核 `6.18.21-android17-5-g805aa6adea19-abogki565292102-4k`。
所有数据来自真机，通过设备上的 adb（`127.0.0.1:45305`，shell uid 2000）采集。

## 1. 环境事实（每条都有命令）

| 项 | 值 | 命令 |
| --- | --- | --- |
| 引导程序 | `verifiedbootstate=green`、`flash.locked=1`、`veritymode=enforcing`、slot `_b` | `adb shell getprop ro.boot.*` |
| 内核命令行 | 含 **`kasan=off`**、`arm64.nomops`、`kvm-arm.mode=protected` | `adb shell cat /proc/cmdline` |
| MTE | `hwcap2 MTE: no`，`/proc/cpuinfo` features 无 `mte` | `getauxval(AT_HWCAP2)` / `cat /proc/cpuinfo` |
| 内核 BTF | `/sys/kernel/btf/vmlinux` 对 app **和 shell** 均 `Permission denied` | `adb shell ls -l /sys/kernel/btf/vmlinux` |
| 进程沙箱 | app：`Uid 10304`、`CapEff 0000000000000000`、`Seccomp 2`；shell：`uid=2000 u:r:shell:s0` Enforcing | `/proc/self/status`、`adb shell id` |

**推论修正**：内核虽然以 `CONFIG_KASAN=y + CONFIG_KASAN_HW_TAGS=y` 编译，但
(1) 启动命令行带 `kasan=off`，(2) 硬件不提供 MTE，因此本机启动后**没有生效的
KASAN 检测**。此前"利用一碰就 panic 重启"的判断不成立。

## 2. 可达性测量（`scripts/harness/trprobe.c`）

静态 aarch64 程序，`adb push` 到 `/data/local/tmp` 后以 **shell uid 2000** 运行；
只操作自身进程的 POSIX CPU 定时器并尝试一次预期失败的 exec，不写内核内存、不碰分区。

```
$ gcc -O2 -static -pthread -o trprobe trprobe.c
$ adb shell /data/local/tmp/trprobe 4

kernel: Linux 6.18.21-android17-5-g805aa6adea19-abogki565292102-4k
uid=2000 euid=2000
hwcap2 MTE: no
cmdline facts: [kasan=off] [arm64.nomops]

strategy                          armed  delOK EINVAL  other   list  errno
control                              16     16      0      0     -1      0
exec-missing                         16     16      0      0     -1      2
exec+thread+pending-signal            0      0      0      0      0  -4000 (killed by signal 10)
exec+threads(no signal)               0      0      0      0      0  -4000   (printed EXEC_SUCCEEDED)
```

### 2.1 策略说明

| 策略 | 构造 | 观测 |
| --- | --- | --- |
| 0 `control` | 只装 4 个 `CLOCK_PROCESS_CPUTIME_ID` 定时器，不 exec | 全部可删（16/16，errno 0） |
| 1 `exec-missing` | exec 不存在的路径 | `errno=2`（ENOENT）；定时器全部存活。失败发生在 `begin_new_exec()` 之前 |
| 2 `exec+thread+pending-signal` | 16 个兄弟线程 + 阻塞挂起的 `SIGUSR1` + exec `/system/bin/sh` | 子进程**在 execve 内部**被 `SIGUSR1` 终止，syscall 没有返回 |
| 3 `exec+threads(no signal)` | 与策略 2 完全相同，但不发信号 | exec **成功**（新镜像打印 `EXEC_SUCCEEDED`） |

### 2.2 结论

- 策略 2 与策略 3 的**唯一差别**是那个挂起信号。策略 3 能成功 exec，策略 2 却在
  `execve` 内部被该信号终止，说明 `de_thread()` 确实因 `signal_pending()` 中止，
  `begin_new_exec()` 走了错误返回路径。
- 因此 **CVE-2026-98260 的失败路径在 uid 2000 的普通进程下是可达的**，
  这是上一轮"证据不足"里最关键的缺口，现在由实机数据补上。
- 该路径**对进程是致命的**：失败点在"不可回头点"之后，任务被信号终止而不是
  返回错误。因此黑盒无法在事后观测定时器是否被清理 —— 这一窗口正是漏洞本身，
  只能由利用代码在窗口内完成回收与凭据改写。工具据此把 `INCONCLUSIVE` 如实报出，
  不把"可达"夸大成"可利用"。

## 3. 仍未完成

| 项 | 状态 |
| --- | --- |
| 内核内存写入 / 凭据改写 | 未实现。本机 `kasan=off` 但 `KFENCE` 仍开、`SYSVIPC`/`USER_NS` 缺失、`INIT_ON_ALLOC` 清零，利用面很窄 |
| 一次性临时 root（`fastboot boot`） | 引导程序 `green` 锁定，该路径在本机不可用 |
| 破坏性验证 | 未进行，需另行授权与恢复方案 |
