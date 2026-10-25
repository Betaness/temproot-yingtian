# 关键发现（2026-10-25）

本轮在 `D:\Codex\android-kernel` 的既有产物上继续，全部证据可复现。
本文件只记录**实测/实读**得到的结论，推断一律标注。

## 1. 目标固件身份

| 项目 | 值 | 来源 |
| --- | --- | --- |
| 设备代号 | `yingtian` | OTA 元数据 `pre-device` |
| 内核 release | `6.18.21-android17-5-g805aa6adea19-abogki565292102-4k` | `stock/verification.json` 的 `linux_banners` |
| kernel SHA-256 | `cde87cd70206f21db4359aa1148f5f68e693ffefb11108dffde99c07c8c5ad88` | 同一文件 |
| boot SHA-256 | `1e3a1111aaf7e17f843dd541ef663a46b3b1891d25568f905cbcb364cc911ce4` | 同一文件 |
| 内核编译 | clang 22.0.1（Android 15323222），2026-09-23 09:23:45 UTC | banner |
| 配置来源 | `stock/kernel.config`（IKCONFIG，8465 行） | 从 `stock/kernel.bin` 提取 |

用户回传的实机日志（`reports/DEVICE_LOG_REVIEW_20261025.md`）里 uname 与本表逐字一致，
但 incremental / fingerprint 与 OTA 元数据不同，`.D00` 仍未核实。本项目的闸门按
**内核 release 精确匹配**，因此这条差异不影响保护行为。

## 2. 决定性发现：这是一枚 KASAN + MTE 内核

上一轮的 `reports/SECURITY_REPORT_ZH.md` 只列了 SELINUX / CFI / RANDOMIZE_BASE 等配置，
**漏掉了整段 KASAN/KFENCE 配置**，这也是它一直停在「证据不足」的原因。实际读到的内容：

```
CONFIG_KASAN=y
CONFIG_KASAN_HW_TAGS=y          # 硬件标签版 KASAN（靠 MTE 实现）
CONFIG_KASAN_VMALLOC=y
CONFIG_KFENCE=y
CONFIG_KFENCE_SAMPLE_INTERVAL=500
CONFIG_PANIC_ON_OOPS=y
CONFIG_BUG_ON_DATA_CORRUPTION=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set
# CONFIG_SYSVIPC is not set
# CONFIG_USER_NS is not set
# CONFIG_CHECKPOINT_RESTORE is not set
CONFIG_STATIC_USERMODEHELPER=y
CONFIG_SHADOW_CALL_STACK=y
CONFIG_ARM64_MTE=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SLAB_FREELIST_RANDOM=y
# CONFIG_SLAB_MERGE_DEFAULT is not set
CONFIG_DEBUG_INFO_BTF=y
CONFIG_KALLSYMS=y
CONFIG_CFI=y
CONFIG_RANDOMIZE_BASE=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_USERFAULTFD=y
CONFIG_IO_URING=y
```

复现命令：

```powershell
Select-String -Path D:\Codex\android-kernel\stock\kernel.config -Pattern 'KASAN|KFENCE|PANIC_ON_OOPS|SYSVIPC|USER_NS|STATIC_USERMODEHELPER'
```

### 2.1 这对 CVE-2026-98260 意味着什么

UAF 类漏洞的利用前提是「释放后仍能安全地读到受控内容」。本内核一次性否掉了这个前提：

1. `KASAN_HW_TAGS` + `ARM64_MTE`：slab 对象带硬件标签，访问已释放对象是**同步**故障，不是延迟崩溃。
2. `PANIC_ON_OOPS=y`：该故障直接 panic，设备重启。没有「试第二次」的机会。
3. `INIT_ON_ALLOC_DEFAULT_ON=y`：即便绕过标签，新分配对象被清零，未初始化读泄漏拿不到内容。
4. 没有 `SYSVIPC`：`msg_msg` / `msg_msgseg` 这一整类堆喷与任意读原语在本内核不存在。
5. 没有 `USER_NS`、没有 `CHECKPOINT_RESTORE`：无法扩大可利用面。
6. `STATIC_USERMODEHELPER=y`：`modprobe_path` / `core_pattern` 覆盖失效。
7. `SHADOW_CALL_STACK=y` + `CFI=y`：返回地址与控制流劫持基本被堵死。

**结论：在本固件上，这条 UAF 只能得到一次 KASAN 报告 + 重启，得不到 root。**
这不是「还没调通」，而是内核配置层面的否定。工具因此对该组合做了 fail-closed 处理。

## 3. 运行时布局（真实数据，不是猜的）

`CONFIG_DEBUG_INFO_BTF=y` 且 `/sys/kernel/btf/vmlinux` 对普通应用可读，
于是所有偏移都可以在设备上现读。用 `scripts/btf_dump.py` 解析固件内嵌的
`stock/kernel-0.btf`（170,569 个类型，字符串表 2,765,823 字节）得到：

| 字段 | 偏移 | 字段 | 偏移 |
| --- | --- | --- | --- |
| `task_struct.pid` | `+0x718` | `cred.uid` | `+0x008` |
| `task_struct.tgid` | `+0x71c` | `cred.euid` | `+0x018` |
| `task_struct.comm` | `+0x918` | `cred.fsuid` | `+0x020` |
| `task_struct.tasks` | `+0x648` | `cred.cap_permitted` | `+0x038` |
| `task_struct.cred` | `+0x908` | `cred.cap_effective` | `+0x040` |
| `task_struct.real_cred` | `+0x900` | `cred.security` | `+0x080` |
| `task_struct.signal` | `+0x960` | `cred.user_ns` | `+0x090` |
| `task_struct.mm` | `+0x698` | `pipe_buffer.page` | `+0x000` |
| `task_struct.files` | `+0x948` | `pipe_buffer.len` | `+0x00c` |
| `signal_struct.posix_timers` | `+0x088` | `pipe_buffer.ops` | `+0x010` |
| `signal_struct.posix_cputimers` | `+0x118` | `pipe_buffer.flags` | `+0x018` |
| `pipe_inode_info.bufs` | `+0x0a8` | `k_itimer.it_clock` | `+0x024` |
| `pipe_inode_info.head` | `+0x058` | `k_itimer.it_signal` | `+0x030` |
| `pipe_inode_info.tail` | `+0x05c` | `k_itimer.it` | `+0x0e0` |
| `pipe_inode_info.ring_size` | `+0x064` | | |

结构体大小：`task_struct` 4736、`cred` 184、`pipe_buffer` 40、`k_itimer` 384、`signal_struct` 1176。

复现：

```powershell
& $py scripts\btf_dump.py D:\Codex\android-kernel\stock\kernel-0.btf --json dist\layout-stock-kernel.json
```

**注意**：这张表是给报告和交叉校验用的。设备上不读这张表，而是由
`native/tr_btf.c` + `native/tr_layout.c` 现场解析同一份 BTF，
所以换内核构建不需要重新编译，也不会出现「偏移猜错」导致的静默失败。

解析过程中修正了三处错误假设（这就是必须用真数据的原因）：

| 原假设 | 实际成员名 | 说明 |
| --- | --- | --- |
| `k_itimer.it_clockid` | `k_itimer.it_clock` | 该字段不在匿名 union 内 |
| `signal_struct.nr_timers` | 不存在；用 `posix_cputimers` | 6.18 的每 CPU 时钟队列结构 |
| `pipe_inode_info.head/tail` | 在 `+0x058` 的匿名 union 内 | 解析器必须能下钻匿名成员 |

## 4. 能真正拿到「临时 root」的路径

按可行性排序，全部不需要内核漏洞：

### 4.1 引导程序已解锁：`fastboot boot` 一次性内核（推荐，真正的「临时」）

```powershell
& $py scripts\temp_boot_root.py check      # 读 verifiedbootstate / slot / 内核 / 当前 uid
& $py scripts\temp_boot_root.py pull       # 拉取当前 slot 的 boot.img 作为证据并记哈希
# 在设备上用 Magisk / KernelSU 管理器 patch 这个 boot.img（选择并修补文件）
& $py scripts\temp_boot_root.py boot --image magisk_patched.img --expected-sha256 <哈希>
& $py scripts\temp_boot_root.py verify     # adb shell id 应为 uid=0
```

- **不写任何分区**：`fastboot boot` 只把镜像加载进内存运行一次，slot 内容不变。
- **临时性由硬件保证**：正常重启即回到原厂内核。
- 拿到 root 后，本 APK 的 `rootd` 接管授权层，把 root 按 uid 分发给 DroidDesk。

### 4.2 引导程序已锁定

这种情况下 `fastboot boot` 会被拒绝，而未签名镜像也无法加载。
剩下的只有内核漏洞路径，而在 §2 的配置下那条路会把设备重启。
**结论：该状态下本固件不存在可用的临时 root 路径**，工具会如实报告 `LOCKED_BOOTLOADER`
而不是伪装成功。

### 4.3 设备已有 root（Magisk / KernelSU）

APK 的探测会读到 `/system/bin/su`、`/data/adb/ksu` 等路径，此时可直接用
`TemporaryRoot.rootDaemonStart()` + `su()` 做授权层，无需任何提权动作。

## 5. 仍未完成 / 证据不足

| 项目 | 状态 |
| --- | --- |
| 目标设备实机运行本 APK | **未执行**（本机无可用 Android 运行环境，见 `VALIDATION.md`） |
| CVE 在普通应用进程中的动态可达性 | 未测量（测量器已实现，需在真机点一下） |
| 内核内存写入 / 凭据改写 | 未实现（被闸门阻断，本固件不可行） |
| `.D00` 与 OTA 元数据版本的差异 | 未核实 |
| 第三方应用 root 授权 | 已实现 rootd 授权层，但仅在已有 root 凭据时可用 |
