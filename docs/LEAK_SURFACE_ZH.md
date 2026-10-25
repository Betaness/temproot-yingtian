# 内核地址泄漏面枚举（2026-10-25 实机）

目的：primitive 阶段需要**一个**内核地址（vmemmap 基址 / 内核 text 指针 / `task_struct`）。
本文件记录在真机上挨个试探的结果。**负面结果同样重要**：它区分了"卡在平台"和"卡在代码"。

## 1. 结论

**两种身份下都没有可用泄漏面。** 也就是说 stage 5（任意写）在本机不是缺代码，
而是缺一个前提条件：一个能吐出内核地址的原语。

| 身份 | 结果 |
| --- | --- |
| 普通 app（uid 10304，`u:r:untrusted_app_34:s0`） | 几乎所有 `/proc` 内核接口 `Permission denied` |
| shell（uid 2000，`u:r:shell:s0`） | 能读一部分，但**地址全部被 `kptr_restrict` 零化** |

## 2. app 身份（`native/tr_leak.c` 扫描器输出）

```
kptr_restrict=-1  dmesg_restrict=-1  perf_event_paranoid=-1   ← 连 sysctl 都读不到
/proc/kallsyms           拒绝   denied: Permission denied
/proc/modules            拒绝   denied: Permission denied
/proc/net/unix           拒绝   denied: Permission denied
/proc/net/tcp            拒绝   denied: Permission denied
```

## 3. shell 身份（`adb shell` 逐项实测）

| 接口 | 可用性 | 内容 |
| --- | --- | --- |
| `/proc/kallsyms` | **拒绝** | Permission denied |
| `/proc/modules` | 可读 | 60 处 `0000000000000000`（地址被零化） |
| `/proc/net/unix` | 可读 | 65 处零化 |
| `/proc/net/tcp` | 可读 | 20 处零化 |
| `/proc/net/packet` | 可读 | 10 处零化 |
| `/proc/net/netlink` | 可读 | 44 处零化 |
| `/proc/net/protocols` | 可读 | 无地址字段 |
| `/proc/slabinfo` | 可读 | 无地址字段 |
| `/proc/self/stack`、`/proc/1/stack` | 拒绝 | Permission denied |
| `/proc/vmallocinfo`、`/proc/iomem` | 拒绝 | Permission denied |
| `/proc/kmsg`、`/dev/kmsg` | 拒绝 | Permission denied |
| `/sys/kernel/btf/vmlinux` | 拒绝 | Permission denied |
| `/sys/fs/pstore` | 拒绝 | Permission denied |

## 4. perf 路线：看起来有戏，实际被更下层拦住

`/proc/sys/kernel/perf_event_paranoid` 在 shell 下可读，值是 **`-1`**（理论上允许
非特权 perf）。`PERF_SAMPLE_IP` 能采到内核态指令指针，是打 KASLR 的经典路子。

实测（`scripts/harness/perfleak.c`，静态 aarch64，`adb shell` 运行）：

```
uid=2000 perf_event_paranoid test
  [sw-cpu-clock]        perf_event_open denied: Permission denied (errno=13)
  [sw-task-clock]       perf_event_open denied: Permission denied (errno=13)
  [hw-cycles]           perf_event_open denied: Permission denied (errno=13)
  [sw-context-switches] perf_event_open denied: Permission denied (errno=13)
```

结论：`perf_event_paranoid=-1` 只是那个 sysctl 的值，实际调用在 SELinux/seccomp
层就被 `EPERM` 拦住。**这条路不通。**

## 5. 对整体路线的影响

```
漏洞结构        ✅ 静态确认（修复前清理顺序）
失败路径可达性  ✅ 实机确认（de_thread 中止，uid 2000）
触发入口        ✅ 可用（trprobe 策略 2）
回收              ❌ 需要跨缓存对齐（KFENCE 抽样干扰）
写原语            ❌ 需要一个内核地址 —— 本文件证明：拿不到
凭据改写          ❌ 依赖写原语
```

**因此在保持"不改分区、不解锁引导程序"的前提下，本机不存在能自动完成提权的路径。**
要打破这个局面只有三条：

1. 引导程序解锁 → `fastboot boot` 一次性内核（真正临时，但我们不能自己解锁）；
2. 发现一个**泄漏类**漏洞（不是 UAF），单独拿到地址；
3. 放弃内核路线，接受 shell 级（uid 2000）能力——这台设备现在就有 adb shell。

## 6. tracefs 路线：可写但不可启用（2026-10-25 追加）

`/sys/kernel` 下对 shell 可读的文件只有 11 个，全部属于 tracefs。实测权限：

| 文件 | 权限 | 结果 |
| --- | --- | --- |
| `kprobe_events` | `-rwxrwxrwx` | **可写**：`p:trp_probe vfs_read` 返回 rc=0，探针注册成功 |
| `tracing_on` | `-rw-rw-rw-` | 可写（echo 0/1 都成功） |
| `events/kprobes/<name>/enable` | — | **Permission denied**（SELinux 拒绝） |
| `current_tracer` / `trace_options` / `kprobe_profile` | — | Permission denied |
| `trace` / `trace_pipe` | 可读 | 但事件没有 enable，采样为空，0 个内核地址 |

结论：**能在任意内核符号上注册 kprobe，但无法启用它，因此拿不到 `$stack` / `$argN`
的运行时内容。** 这条路不通。

顺带发现两个平台事实，值得单独反馈给厂商：

1. `kprobe_events` 对 `shell` 域是 `0777`——比 `enable` 宽松得多，权限设计不一致；
2. 设备上常驻两个小米自己的探针（`vfs_unlink_miuibpf_bcc_*`、`enter_fd_install_miuibpf_bcc_*`），
   即 MIUI 自带 bcc/BCC 埋点。这两个探针不可删除（rc=1），也未被我触碰。

清理：本次试验创建的 `trp_probe` / `trp_stk` / `trp3` 已全部移除，
`tracing_on` 已恢复为 0，设备上只剩厂商自己的两个探针。
