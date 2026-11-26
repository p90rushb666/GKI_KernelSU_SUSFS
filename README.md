# 红米 K80 Pro（miro）自编译内核 · SukiSU-Nova Built-in

[![Build](https://github.com/p90rushb666/GKI_KernelSU_SUSFS/actions/workflows/main.yml/badge.svg)](https://github.com/p90rushb666/GKI_KernelSU_SUSFS/actions/workflows/main.yml)

> 基于 [WildKernels/GKI_KernelSU_SUSFS](https://github.com/WildKernels/GKI_KernelSU_SUSFS) 构建链，
> 为 **红米 K80 Pro（`miro` / `24122RKC7C`）** 定制的 GKI 6.6 内核。
> 根方案为 **SukiSU-Nova 内核内建（built-in）**，不是 LKM 模块。

---

> [!CAUTION]
> **刷机有风险，风险自负。** 仅适配 `miro`，其它机型刷入可能直接变砖。
> 刷前务必备份原厂 `boot`，并确认已解锁 BL。

---

## 一、适配范围

| 项 | 值 |
|---|---|
| 机型 | 红米 K80 Pro / `miro` / `24122RKC7C` |
| 系统 | HyperOS `4.0.3.0.XOMCNXM`（Android 17 / API 37） |
| 内核 | `6.6.118-android15-8` |
| 内核版本串 | `6.6.118-android15-8-gf72a02f47f4b-abogki551678766-4k`（与原厂**一字不差**） |
| 根方案 | SukiSU-Nova，内核内建（`CONFIG_KSU=y`，非 LKM） |
| 管理器包名 | `com.sukisu.nova` |

> 说明：`android15` 是 GKI KMI 分支名，**不是**系统版本。本机系统实际是 Android 17。

---

## 二、特性

| 功能 | 状态 | 说明 |
|---|---|---|
| SUSFS | ✅ v2.4.0 | builtin / GKI，路径、挂载、kstat、uname、cmdline 全量 |
| BBG（Baseband Guard） | ✅ | 关键分区写入保护，**已修 su / ksu 域识别**（原版对 SukiSU 形同虚设） |
| KPM | ✅ kpimg 0.14.0 | 静态注入 KernelPatch，管理器可加载 `.kpm` |
| NoMount | ✅ | 同步上游 `dev` 最新提交 |
| DroidSpaces | ✅ | 完整支持 |
| USB Arsenal | ✅ | |
| NTSync | ✅ | |
| Ptrace 补丁 | ✅ | |
| Unicode 修复 | ✅ | 不可见字符绕过修复 |
| 网络补丁 | ✅ | |
| 杂项优化 | ✅ | |

额外处理过的两处（这版的重点）：

1. **SELinux 隐藏逻辑与原生解析器行为对齐**
   - `selinuxfs` 事务状态：拒绝请求时先推进真实事务，再返回 `EINVAL`（原实现会让同一 fd 可二次写入）
   - `/access` 只扫描源、目标两个字段；`/context` 只扫描首个 NUL 之前
   - 拒绝时保留"类型不存在"的语义，不再暴露实现差异

2. **BBG 的 `su` / `ksu` 域识别**
   - 原版把解析失败缓存成 `-EINVAL`，与守卫 `if (sid == -1)` 冲突，导致开机后永不重试，
     `u:r:ksu:s0` 永远识别不到 → 防格机对 SukiSU 无效
   - 改为缓存 `-1`，恢复"下次再试"

---

## 三、下载

- **GitHub Actions 产物**：进入 [Actions](https://github.com/p90rushb666/GKI_KernelSU_SUSFS/actions/workflows/main.yml)，
  选最新一次成功的 run，在 Artifacts 里下载 `*-AnyKernel3.zip`
- **酷安发布帖**：见帖子内链接
- 管理器需单独安装：`com.sukisu.nova`，版本与内核自报版本对应

> ⚠️ Actions 里的 `SukiSU_v4.x_...-release.apk` 包名是 `com.sukisu.ultra`，
> **不是**本内核预期的那条线，装了会并存且拿不到授权，请勿使用。

---

## 四、刷入

### 刷前自检（重要）

如果你之前用的是 **LKM 模式**，必须先还原 `init_boot` 为原厂，否则会两套 root 打架：

```bash
lsmod | grep kernelsu      # 有输出 = 模块在跑（LKM）
ls -l /init.real           # 存在 = init_boot 被 LKM 改过
```

两条任意命中，就先在管理器里「卸载 KernelSU」（会自动还原 `init_boot`），或直接刷原厂 `init_boot`，
重启确认上面两条都"干净"后再继续。

### 方式一：fastboot（推荐）

```bash
adb reboot bootloader
fastboot flash boot boot.img
fastboot reboot
```

只刷 `boot` 分区，`init_boot` 不要动。

### 方式二：AnyKernel3

用 SukiSU 管理器、KernelFlasher、爱玩机工具箱等直接刷 AK3 压缩包，
会自动 split / repack 当前 boot 并保留原 ramdisk。

### 回滚

```bash
fastboot flash boot boot_stock.img
```

### 升级

从上一版升级直接重刷 `boot` 或 AK3 即可，**不需要清数据、不需要重装模块**。

---

## 五、自行构建

### 触发构建

`Actions` → `Build Kernel` → `Run workflow`，参数：

| 参数 | 值 |
|---|---|
| `release_type` | `CI` |
| `kernel_build_version` | `6.6.x-android15` |
| `os_patch_level` | `118` |
| `page_size` | `4k` |
| `brand_name` | `gf72a02f47f4b-abogki551678766-4k` |
| `keep_kmi` | `true` |
| `root_flavor` | `SukiSU-Ultra` |
| `use_susfs` / `use_nomount` / `use_bbg` | `true` |
| `use_net` / `use_ds` / `use_usba` / `use_ntsync` / `use_ptrace` / `use_unicode` / `use_misc` | `true` |
| `use_perf` | `false` |

> `brand_name` 不能留空：留空会被 GitHub 当成"未填"，回退成默认值 `Wild`，
> 编出 `...-android15-8-Wild`，自带指纹。必须是原厂后半段。

构建约 20–25 分钟，只有 `android15-6.6` 这个矩阵会真跑，其余全部 skip。

### 本仓库相对上游改了什么

| 文件 | 改动 | 目的 |
|---|---|---|
| `.github/actions/root-setup/action.yml` | 上游改为自建 Forgejo、分支 `builtin-new` | GitHub 镜像滞后一周，真实上游在 Forgejo |
| 同上 | 在 `ksu_init_slow_avc_audit_hook()` 前插入 `ksu_init_hook_transaction_ops_write()` | SUSFS 分支默认不装 access 钩子，会导致 `status 0/0` 与 `access.seqno=5` 矛盾 |
| `.github/scripts/selinux_hook_stock_fidelity.py` | 新增，构建时改 3 处源码 | 让隐藏钩子与原生 `selinuxfs` 行为一致（NUL 边界、字段边界、事务消耗） |
| `.github/workflows/build.yml` | 新增「BBG retry su/ksu sid resolution」 | `-EINVAL` 缓存改 `-1`，修复 ksu 域识别 |
| `.github/workflows/build.yml` | 新增「Enable KPM」+ fragment | `CONFIG_KPM=y` |
| `.github/workflows/build.yml` | 新增「Inject KernelPatch for KPM」 | kpimg 静态注入，KPM 才能真正工作 |
| `.github/scripts/trim_sukisu_managers.py` | 无 `apk_sign_keys[]` 时跳过 | `builtin-new` 改成动态管理器证书，老逻辑会报错 |

> `PIN_SUKISU_ULTRA` 锁定了上游提交，升级上游时改这里即可。

---

## 六、常见问题

**Q：管理器显示 KPM 不支持？**
内核只开了 `CONFIG_KPM=y` 还不够，KPM 引擎在 KernelPatch（kpimg）里。本仓库会在打包前自动注入，
如果显示不支持，说明构建时注入步骤失败了，看构建日志的 `Inject KernelPatch` 步骤。

**Q：内核版本 35100 和管理器版本对不上？**
两套计数体系。`35100` 是内核自报的 KSU 版本（`30000 + 提交数 - 4001`），
管理器显示的是它自己的 `versionName`（如 `v3.0.0-r1`），不必相等，包名对就行。

**Q：能不能装 `com.sukisu.ultra` 那个管理器？**
不建议。内核里写死的预期包名是 `com.sukisu.nova`，装另一个包会并存，且可能拿不到授权。

**Q：系统更新后 root 没了？**
OTA 会覆盖 `boot` 分区，重刷本内核即可，数据不受影响。

**Q：能和 LKM 版共存吗？**
不能。两套 root 会抢同一份 `/data/adb/ksu` 状态和 SELinux 策略，轻则授权异常，重则开机异常。

**Q：为什么 `uname -r` 跟原厂一样？**
故意的。版本串对齐原厂是为了不暴露自编译指纹；KMI 保留，厂商模块（WiFi / 相机 / 基带）正常加载。

---

## 七、致谢

- [WildKernels/GKI_KernelSU_SUSFS](https://github.com/WildKernels/GKI_KernelSU_SUSFS) —— 构建链
- [SukiSU-Nova](https://git.zako.shirkneko.top:20004/shirkneko/SukiSU) —— 根方案（真实上游在自建 Forgejo）
- [simonpunk/susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu) —— SUSFS
- [vc-teahouse/Baseband-guard](https://github.com/vc-teahouse/Baseband-guard) —— BBG
- [bmax121/KernelPatch](https://github.com/bmax121/KernelPatch) 与 [SukiSU_KernelPatch_patch](https://git.zako.shirkneko.top:20004/shirkneko/SukiSU_KernelPatch_patch) —— KPM
- [maxsteeel/nomount](https://github.com/maxsteeel/nomount) —— NoMount

---

## 八、免责声明

- 本仓库仅供个人学习与自用，不提供任何形式的售后与担保。
- 刷机、解锁、回锁均可能导致数据丢失或设备损坏，风险自负。
- 请勿用于商业用途或二次倒卖。
- 原上游英文 README 保留在 [`README.upstream.md`](README.upstream.md)，便于与上游同步时对照。
