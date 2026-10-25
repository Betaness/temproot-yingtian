# 使用说明（中文）

## 一、先看结论，再动手

这个工具在**当前固件**（`yingtian` / `4.0.16.0.XBMCNXM.D00` / 内核
`6.18.21-android17-5-g805aa6adea19-abogki565292102-4k`）上**不会**给你 root，
因为它读到的内核配置里 `KASAN + KASAN_HW_TAGS + PANIC_ON_OOPS` 全开：

- 走内核漏洞（UAF）＝ 一次 KASAN 报告 + 设备自动重启，不是提权。
- 所以提权按钮是**灰色**的，这是设计行为，不是坏了。

它能给你的是：**把「为什么不行」变成可导出的证据**，以及在
**引导程序解锁**的设备上用 `fastboot boot` 拿到真正意义上的临时 root，
再由本应用的授权层把 root 分发给宿主应用。

## 二、装到平板上

```powershell
adb install -r D:\Codex\temproot\dist\temproot-0.3.0-experimental.apk
adb shell am start -n org.fujiang.temproot/.MainActivity
```

打开后自动跑一次探测，界面上会依次出现这些卡片：

1. **当前结论**：闸门判定 + 阻断码（例如 `KASAN_ACTIVE`）
2. **阶段状态**：8 个阶段各自独立的状态（不会合并成一个“成功”）
3. **设备与内核**：型号、代号、内核 release、页大小、MTE 支持、本进程 uid/caps/SELinux
4. **系统调用可达性**：`timer_create` / `unshare` / `memfd` / `io_uring` / `userfaultfd` /
   `pipe2` / `fork+exec` 的真实结果
5. **缓解措施闸门**：逐条列出为什么阻断
6. **可达性测量**：点「运行测量（8 轮）」
7. **提权执行**：闸门放行才可点
8. **临时 root 守护**：启动 / 停止 / 试跑 `id`
9. **权限验证**
10. **诊断日志**：分享 / 保存 / 历史

## 三、第一件该做的事：跑可达性测量

点「运行测量（8 轮）」，几秒出结果。它会给出三种结论之一：

| 结论 | 含义 |
| --- | --- |
| `PRE_FIX_ORDER` | 这个内核的定时器清理顺序与修复前一致（说明 bug 结构在，但本机 KASAN 让利用不可行） |
| `POST_FIX_ORDER` | 该内核已包含修复，不用继续 |
| `INCONCLUSIVE` | 构造的失败路径没命中，需要更多轮次 |

整个过程只创建/删除**本进程**的 CPU 定时器，不解引用任何已释放对象，
所以**不会重启设备**。跑完点「保存到文件」，把 TXT 发回来。

## 四、想要真的临时 root：看引导程序状态

```powershell
$py = 'C:\Users\Administrator\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $py D:\Codex\temproot\scripts\temp_boot_root.py check
```

- 输出 `"state": "READY"`（`ro.boot.verifiedbootstate == orange`）→ 可以继续：

```powershell
& $py scripts\temp_boot_root.py pull          # 拉当前 slot 的 boot.img，附 SHA-256
# 在平板上用 Magisk / KernelSU 管理器「选择并修补一个文件」，选刚拉出来的 boot.img
& $py scripts\temp_boot_root.py boot --image magisk_patched.img --expected-sha256 <哈希>
& $py scripts\temp_boot_root.py verify        # adb shell id 应为 uid=0
```

`fastboot boot` **不写任何分区**，只把镜像加载进内存跑一次；正常重启即回原厂内核。
这就是硬件保证的「临时」。

- 输出 `"state": "LOCKED_BOOTLOADER"` → `fastboot boot` 会被拒绝，
  未签名镜像也加载不了。此状态下本固件**没有**可用的临时 root 路径，
  唯一的出路是解锁（会清数据）或等一个没开 KASAN 的构建。

## 五、拿到 root 之后：用 rootd 分发

界面「临时 root 守护」→「启动守护（TTL 900 秒）」→「通过守护执行 id」。
看到 `uid=0(root)` 就说明授权层通了。宿主应用（DroidDesk）通过
`TemporaryRoot.su(new String[]{"..."}, timeout)` 调用。

授权表（默认只允许本应用）：

```
# /data/data/org.fujiang.temproot/files/allowed_uids
2000          # shell
10123         # 某个具体应用的 uid
# all         # 放开给所有应用（慎用）
```

守护 **900 秒无操作自动退出**，重启后不存在，不写分区、不加自启。

## 六、验证是不是真的 root

点「运行权限验证」。只有三条**同时**成立才算通过：

1. `uid == 0` 且 `euid == 0`
2. `/proc/self/status` 的 `CapEff` 含 `CAP_SYS_ADMIN`（bit 21）
3. 一个特权操作真的成功（读 `/proc/1/mem` 或 `/data/system/packages.xml`，
   或 `seteuid(2000)` → `seteuid(0)` 往返成功）

**SELinux 变成 permissive 不算成功。** 界面显示「已验证：…」才算。

## 七、出问题怎么回传

任何一步失败，点「保存到文件」导出 TXT。日志里有：事件时间线、每次探测的完整 JSON、
原生层日志。不含序列号、账号、网络地址。

## 八、恢复

- 本应用不做任何持久化修改：卸载即清除。
- 若用过 `fastboot boot`：重启一次即回原厂内核（没有分区被写过，无需恢复）。
- 若守护还在跑：界面点「停止守护」，或重启设备。
