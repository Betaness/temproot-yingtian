# 设计说明

## 0. 原则

1. **不猜任何构建相关常量**：结构偏移现场读 BTF；备份路径、socket 名、TTL 等全部常量集中定义。
2. **失败关闭**：证据不足时拒绝执行危险动作，而不是「先试试」。
3. **状态不合并**：构建成功、安装成功、兼容、可达、执行、验证是六个独立结论。
4. **临时的含义**：不写分区、不加开机自启、不进 `/data/adb`；进程退出 / TTL 到期 / 重启即消失。

## 1. 原理：为什么闸门必须先于利用

UAF 利用的本质是「让内核把一个已释放对象当成新对象用」。现代内核的检测手段分两类：

- **影子内存 / 硬件标签**（KASAN、MTE）：在**访问时**判定对象是否有效，同步报错。
- **卫生化**（INIT_ON_ALLOC/FREE、freelist 加固）：让「受控内容」无法注入。

本目标固件同时具备两类（见 `FINDINGS_ZH.md` §2），且 `PANIC_ON_OOPS=y`。
于是「先跑一遍看看」的代价是**整机重启**，而且每次尝试都重启一次。
所以 `tr_guard_evaluate()` 必须在任何危险动作之前给出结论，且结论来自
两个独立证据源：

1. 运行时：`/proc/config.gz`（若可读）——内核自报配置，优先级最高。
2. 离线：`tr_build_db.c` 里按 **内核 release 字符串精确匹配** 的配置基线，
   每条都带证据路径与内核镜像哈希。

两者都没有 → `NO_EVIDENCE` → 阻断。这条规则直接对应交接文档
「不得猜测…证据不足时停止宣称适配完成」。

## 2. 步骤：一次完整流程

```
probe()            读设备/内核/进程/seccomp 真实可达性     -> tr_probe.c
  |
guard()           运行时配置 or 离线基线 -> 允许/阻断      -> tr_guard.c
  |
layout()          /sys/kernel/btf/vmlinux -> 31 个字段     -> tr_btf.c + tr_layout.c
  |
measure()         非破坏性：exec 失败后的定时器清理顺序    -> tr_timer_exec.c
  |
escalate()        闸门放行才执行；本版本对 KASAN 构建恒阻断 -> tr_timer_exec.c
  |
rootd_start()     已有 root 凭据时启动授权层               -> tr_rootd.c
  |
verify()          uid + CAP_SYS_ADMIN + 特权操作            -> tr_verify.c
```

## 3. 实现要点

### 3.1 环境探测（`tr_probe.c`）

不止读字段，还**真实发起系统调用**并记录 errno：`timer_create`、
`unshare(CLONE_FILES)`、`memfd_create`、`io_uring_setup`、`userfaultfd`、`pipe2`、
`F_SETPIPE_SZ`、`fork+execve`。每个探测都在可抛弃的子进程里做，避免污染本进程状态。
这是交接文档里从未完成的那一项（「普通 APK 权限可行性」）。

### 3.2 BTF 布局（`tr_btf.c` / `tr_layout.c`）

自实现的最小 BTF 读取器：解析 header、按 `kind` 计算每条记录的额外长度、
建立类型索引、支持 `TYPEDEF/CONST/VOLATILE/RESTRICT/TYPE_TAG` 穿透、
支持**匿名 struct/union 递归下钻**（`pipe_inode_info.head` 就藏在匿名 union 里）。
`tr_layout.c` 声明 31 个必需字段，任一缺失即 `complete=false`，后续阶段拒绝运行。

### 3.3 非破坏性可达性测量（`tr_timer_exec.c`）

三种策略，全部只操作本进程的定时器，不解引用任何已释放对象：

| 策略 | 构造 | 预期 |
| --- | --- | --- |
| 0 | 只装定时器，不 exec | 基线：定时器应全部可删 |
| 1 | exec 一个不存在的路径 | 在 `begin_new_exec` 之前失败 |
| 2 | 装定时器 + 阻塞挂起 SIGUSR1 + 保留一个活着的兄弟线程，再 exec | 让 `de_thread()` 在检查块之后失败 |

exec 返回后用 `timer_delete()` 的返回值判定内核是否已经清理过定时器：
`EINVAL` = 已被内核移除（修复前顺序）；`0` = 仍存在（修复后顺序）。
结论写成 `PRE_FIX_ORDER` / `POST_FIX_ORDER` / `INCONCLUSIVE`，
原始矩阵一并导出，由分析者判断，不由程序夸大。

### 3.4 临时 root 守护（`tr_rootd.c`）

- 抽象 unix socket `@fujiang.temproot.su`（不落文件系统，重启即无）。
- 授权用 **`SO_PEERCRED`** 取真实 uid/pid，客户端自称的 uid 只作参考。
- 每个请求 fork 一个 handler，命令跑在**独立 session + 独立 pty**。
- pty master 通过 `SCM_RIGHTS` 传给调用方；退出码走控制 socket 的 `TREX` 消息。
- TTL（默认 900 秒）到期自动退出；`rootd.pid` 写在 `/data/local/tmp/temproot/`。
- 没有开机自启、没有 `/data/adb`、不写分区。

### 3.5 严格验证（`tr_verify.c`）

判定条件（必须全部成立）：

1. `uid == 0 && euid == 0`
2. `CapEff` 含 `CAP_SYS_ADMIN`（bit 21，从 `/proc/self/status` 解析真值）
3. 至少一个特权操作成功：`open("/proc/1/mem")` / `open("/data/system/packages.xml")`
   或 `seteuid(2000)` 后再 `seteuid(0)` 的往返成功

SELinux permissive **不计入**成功条件（交接文档明确禁止）。

## 4. 验证：怎么证明它是对的

| 层 | 手段 | 状态 |
| --- | --- | --- |
| 编译 | NDK clang 18.0.3，`-Wall -Wextra` 零警告 | 通过 |
| 链接 | `llvm-readelf --dyn-syms` 12/12 JNI 符号导出，`JNI_OnLoad` 存在 | 通过 |
| 依赖 | `NEEDED` 仅 `libc.so/libdl.so/libz.so`，无 `TEXTREL` | 通过 |
| 对齐 | `LOAD` 段对齐 `0x4000`（16 KiB 页兼容） | 通过 |
| 布局算法 | Python 独立实现解析同一份 BTF，31/31 字段命中 | 通过 |
| 打包 | `apksigner verify` v2/v3 通过、`zipalign -c 4` 通过、`resources.arsc` STORED 且 4 字节对齐 | 通过 |
| 清单 | 零权限、非 debuggable、`native-code: arm64-v8a x86_64` | 通过 |
| 实机 | 安装 / 启动 / 探测 / 测量 / 验证 | **未执行** |
