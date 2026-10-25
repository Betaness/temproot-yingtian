# 第三方组件与许可

## 本项目

源码以 MIT 许可发布（见 `LICENSE`）。仅用于自有设备的授权研究。

## 构建期依赖（不随 APK 分发）

| 组件 | 版本 | 许可 | 用途 |
| --- | --- | --- | --- |
| Android NDK | r27c (27.2.12479018) | Android NDK License（含 LLVM Apache-2.0 with LLVM exceptions） | 交叉编译 `libtemproot.so` |
| LLVM / clang | 18.0.3（NDK 内置） | Apache-2.0 WITH LLVM-exception | 编译器、`llvm-strip`、`llvm-readelf` |
| zlib | NDK sysroot | zlib License | 解压 `/proc/config.gz` |
| Android SDK Platform | 35_r02 | Android SDK License | `android.jar` |
| Android Build Tools | 35.0.0 | Android SDK License | aapt2 / d8 / zipalign / apksigner |
| JDK | 26-ea（本机） | GPLv2 with Classpath Exception | javac / keytool / apksigner 运行 |

## 运行期依赖（APK 内）

`libtemproot.so` 的 `DT_NEEDED` 只有 `libc.so`、`libdl.so`、`libz.so`，
全部是 Android 平台库。APK 内**没有**第三方 Java 库、没有 Gradle 依赖、没有网络库。

## 参考的公开资料（未复制代码）

| 主题 | 来源 |
| --- | --- |
| CVE-2026-98260 记录 | <https://www.cve.org/CVERecord?id=CVE-2026-98260> |
| 上游修复提交 | <https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux/+/75aa08b93c65766040f9ca99f41ac85ad22596b6> |
| BTF 格式 | Linux 内核 `Documentation/bpf/btf.rst`（仅按格式实现，未复制代码） |

## 不含分发的内容

- 原厂固件（`boot.img` / `payload.bin` / OTA 片段）不在本工程内，也不随任何包分发。
- 签名私钥 `private/temproot-signing.jks` 与密码文件不进版本库、不进任何包。
- 上一轮 `android-kernel/` 的私有证据与固件同样不进本工程。

## 商标

Xiaomi、HyperOS、Magisk、KernelSU、Android 均为其各自权利人的商标，
本项目与上述权利人无关联，也未获得其背书。
