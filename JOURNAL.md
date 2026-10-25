# 工作日志 / 续做入口

> **重启后先读这个文件。** 它记录到哪一步、下一步是什么、以及怎么确认设备没坏。

## 0. 重启后 60 秒恢复流程

```bash
cd /root/workspace/repo 2>/dev/null || cd <repo 路径>
bash scripts/journal.sh state          # 看主机 + 设备 + 仓库状态 + 最近日志
bash scripts/safety_preflight.sh verify /tmp/tp-base.txt   # 对比基线，确认设备没变
bash scripts/journal.sh show 60        # 读最近 60 条工作记录
```

若 `/tmp/tp-base.txt` 丢了（重启会清 `/tmp`），用这份基线：

```
Xiaomi/yingtian/yingtian:17/CP2A.260605.016/OS4.0.16.0.XBMCNXM:user/release-keys
green
_b
1
Enforcing
6.18.21-android17-5-g805aa6adea19-abogki565292102-4k
```

adb 断了的话：设备上打开「开发者选项 → 无线调试」，重新配对后
`adb connect 127.0.0.1:<端口>`；journal 的 `/sdcard/temproot-journal/SESSION.log`
不依赖 proot 环境，随时可读。

## 1. 当前状态（2026-10-25，SESSION A）

| 项 | 状态 |
| --- | --- |
| 仓库 | `https://github.com/Betaness/temproot-yingtian`，`main` 分支 |
| APK | `dist/temproot-0.3.0-experimental.apk`，已装到设备，启动正常 |
| 闸门 | 放行（实验性）；证据来自伴侣进程自动导入 |
| 布局 | 离线 BTF 表 38/38 字段（设备拒绝读 `/sys/kernel/btf/vmlinux`） |
| 可达性 | `de_thread` 中止路径在 uid 2000 下**实测可达** |
| 内核写入阶段 | 未实现（`native/tr_exploit.c` 骨架，默认拒绝执行） |

## 2. 设备事实（全部实测，别再猜）

```
verifiedbootstate = green          → 引导程序锁定，fastboot boot 不可用
flash.locked = 1, veritymode = enforcing
slot = _b                          → boot_a=sdc22, boot_b=sdc57
kernel cmdline 含 kasan=off        → 编译有 KASAN，启动时关闭
hwcap2 MTE = no                    → KASAN_HW_TAGS 在本机不生效
/sys/kernel/btf/vmlinux            → app 与 shell 均 Permission denied
mi_mtdoops.devname=/dev/block/by-name/oops  → 崩溃有专用分区
/data 228G，已用 77%
```

## 3. 已经验证过的结论

1. `CVE-2026-98260` 的失败路径（`begin_new_exec` → `de_thread` 中止）在普通
   `uid=2000` 进程下可达。证据：`trprobe` 策略 3（16 线程、不发信号）exec 成功并打印
   `EXEC_SUCCEEDED`；策略 2（同样 16 线程 + 挂起 `SIGUSR1`）在 `execve` 内部被
   `SIGUSR1` 终止。唯一差别是那个信号。
2. 该失败点**对进程致命**：syscall 不返回，因此黑盒无法事后观测定时器状态。
   那个窗口就是漏洞本体，只能由利用代码在窗口内完成回收。
3. Android 应用 seccomp 对 `io_uring_setup(425)` / `userfaultfd(282)` 是 SIGSYS
   杀进程；已改为按策略记录，不再每次启动留墓碑（否则 MIUI 报 `NE_AppException`）。

## 4. 下一步（按顺序）

1. 在 `exploit/window-keepalive` 分支上补完 `native/tr_exploit.c` 的
   跨进程回收（worker 预喷 + 触发后重喷），先在**非破坏**模式验证计数与存活。
2. 只有 `tr_exploit_plan()` 报告全部前置条件满足、且显式设置
   `TR_DESTRUCTIVE_ALLOW=1` 时才允许进入内核写入；默认永远拒绝。
3. 任何一次 panic 后：先 `state`，再 `verify`，确认 `verifiedbootstate` 仍为
   `green`、`sys.boot_completed=1`、SELinux `Enforcing`，才继续。

## 5. 恢复阶梯

```
① 自动重启          → 等 30 秒
② 长按电源 10~15 秒  → panic 卡死时强制重启
③ 恢复模式           → 音量上 + 电源 → 清除数据（救 bootloop，会丢数据）
④ MiAssistant / 线刷 → BL 锁定只收官方包
```

## 6. 日志位置

| 层 | 路径 | 存活范围 |
| --- | --- | --- |
| 1 | `journal/SESSION.log`（repo 内，git 跟踪） | 随仓库 |
| 2 | `/sdcard/temproot-journal/SESSION.log` | 不依赖 proot，重启可见 |
| 3 | GitHub `main` 分支 | 抗清数据 |

写日志：`bash scripts/journal.sh add "内容"`；
同步上云：`bash scripts/journal.sh push`。
