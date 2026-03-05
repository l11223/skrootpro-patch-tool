# SKRoot(Pro) — ARM64 Linux 内核 ROOT 修补工具

<p align="center">
  <img src="https://img.shields.io/badge/arch-AArch64-blue" />
  <img src="https://img.shields.io/badge/kernel-6.1%20%7C%206.6%20%7C%206.12-green" />
  <img src="https://img.shields.io/badge/lang-C%2B%2B20-orange" />
  <img src="https://img.shields.io/badge/license-GPL--3.0-red" />
</p>

新一代 Android 内核级 ROOT 方案的核心修补工具。直接修补内核二进制，注入轻量 shellcode，实现**无模块残留、无文件系统痕迹**的完美隐藏 ROOT。

与 Magisk 完全不同的技术路线 —— 不修改 system 分区、不挂载 overlay、不依赖 Zygisk，从内核层面原生提供 ROOT 能力，让所有用户态检测手段失效。

---

## 工作原理

```
┌─────────────────────────────────────────────────────────┐
│                    内核二进制 (Image)                      │
│                                                         │
│  ┌─────────────────┐    ┌──────────────────────────┐    │
│  │ do_execveat_     │───▶│ die 区域 (shellcode)      │    │
│  │ common (入口)    │ B  │                          │    │
│  └─────────────────┘    │ [init_flag 4B]            │    │
│                         │ [root_key  48B]           │    │
│                         │ [提权 shellcode]           │    │
│                         │ [filldir64 引导]           │    │
│                         │         │ B               │    │
│                         └─────────┼─────────────────┘    │
│                                   ▼                      │
│  ┌─────────────────┐    ┌──────────────────────────┐    │
│  │ filldir64 (入口) │───▶│ arm64_notify_die 区域     │    │
│  └─────────────────┘ B  │ [目录隐藏 shellcode]       │    │
│                         └──────────────────────────┘    │
│                                                         │
│  ┌─────────────────┐    ┌──────────────────────────┐    │
│  │ avc_denied       │───▶│ __drm_printfn_coredump   │    │
│  │ audit_log_start  │ B  │ [SELinux 绕过 shellcode]  │    │
│  └─────────────────┘    └──────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

### 五大 Hook 点

| Hook 目标 | 功能 | 实现方式 |
|---|---|---|
| `do_execveat_common` | ROOT 提权 | execve 时匹配 root_key，命中则清零 uid/gid、填满 capabilities、关闭 seccomp |
| `filldir64` | 目录隐藏 | 拦截目录遍历，隐藏以 root_key 前 16 字符命名的条目 |
| `avc_denied` | SELinux 绕过 | 对已提权进程返回"允许"，跳过 SELinux 拒绝 |
| `audit_log_start` | 审计静默 | 对已提权进程返回 NULL，不产生审计日志 |
| `__cfi_check` 等 | CFI 绕过 | 直接 RET，防止 Control Flow Integrity 阻断 hook 跳转 |

### Pro 独有：模块加载器跳板

在 `die` 区域头部预留 4 字节 `init_flag`（初始值 0）。首次 root_key 匹配成功时置 1，标记内核 patch 已激活。用户态 SDK 检测此标志后部署 autorun bootstrap，后续开机自动加载 SKRoot 模块。

```asm
ADR  X13, init_flag        ; 计算 init_flag 地址
LDR  W14, [X13]            ; 读取当前值
CBNZ W14, skip             ; 非零则跳过（已初始化）
MOV  W14, #1               ; 首次：置 1
STR  W14, [X13]            ; 写回
skip:
```

---

## 支持的内核版本

| 内核版本 | 状态 | 说明 |
|---|---|---|
| 6.1.x | ✅ 已验证 | 主流安卓 14 内核 |
| 6.6.x | ✅ 已验证 | 主流安卓 15 内核 |
| 6.12.x | ✅ 已验证 | 最新安卓内核（如一加 15） |

---

## 编译

环境要求：Linux / macOS，g++ 支持 C++20。

```bash
cd patch_kernel_sk
make -j$(nproc)
```

编译产物：`patch_kernel_sk` 可执行文件。

清理：

```bash
make clean
```

---

## 使用

```bash
# 1. 从 boot.img 中提取内核二进制（需要先用 magiskboot 或 unpackbootimg 解包）
#    得到的是裸内核文件，不是 boot.img 本身

# 2. 运行修补工具
./patch_kernel_sk <kernel_binary_file>

# 3. 工具会自动：
#    - 解析内核版本
#    - 定位所有需要的符号（kallsyms）
#    - 计算 cred/seccomp 结构体偏移
#    - 生成并注入 shellcode
#    - 提示输入或自动生成 48 字符 ROOT 密钥
#    - 写入修补后的内核文件

# 4. 将修补后的内核重新打包回 boot.img 并刷入
```

### 输出示例

```
SKRoot(Pro) ARM64 Linux内核ROOT提权工具 V1.0
仅支持 Linux 内核 6.1.x、6.6.x 和 6.12.x

内核版本: 6.12.23
符号定位结果:
所有必需符号已定位
结构体偏移解析完成
正在 hook do_execveat_common...
正在 hook filldir64 (guide)...
正在 hook filldir64 (core)...
...
Done.

#获取ROOT权限的密匙(Key): aB3dEf...（48字符）
```

---

## 项目结构

```
patch_kernel_sk/
├── patch_kernel_sk.cpp          # 主程序入口
├── patch_kernel_sk.h            # 全局常量与宏
├── patch_base.cpp/h             # 基础 patch 工具（跳转指令、寄存器操作）
├── patch_do_execve.cpp/h        # do_execve hook（ROOT 提权 + Pro 跳板）
├── patch_filldir64.cpp/h        # filldir64 hook（目录隐藏）
├── patch_current_avc_check.cpp/h # current_avc_check（SELinux 当前进程检查）
├── patch_avc_denied.cpp/h       # avc_denied hook（SELinux 拒绝绕过）
├── patch_audit_log_start.cpp/h  # audit_log_start hook（审计日志静默）
├── analyze/
│   ├── symbol_analyze.cpp/h     # 符号分析主逻辑
│   ├── kernel_symbol_parser.cpp/h # kallsyms 符号表解析
│   ├── kernel_version_parser.cpp/h # 内核版本解析
│   ├── kallsyms_lookup_name_*.cpp/h # 各版本 kallsyms 算法
│   ├── base_func.h              # 文件读写、hex 转换等基础函数
│   └── aarch64_insn.h           # AArch64 指令编解码
├── 3rdparty/
│   ├── asmjit2-src/             # AsmJit — AArch64 汇编器（运行时生成 shellcode）
│   ├── capstone-4.0.2/          # Capstone — AArch64 反汇编器（指令分析）
│   ├── aarch64_asm_helper.h     # AsmJit 封装（ADR/B/BL 长跳转）
│   ├── aarch64_reg_protect_guard.h # 寄存器保护 RAII
│   ├── find_mrs_register.h      # MRS 指令分析（定位 task_struct 偏移）
│   └── find_imm_register_offset.h # 立即数偏移分析
└── Makefile
```

---

## 技术细节

### 符号定位

不依赖任何外部符号表文件。直接解析内核二进制中的 `kallsyms` 压缩符号表，支持 5 种不同版本的 kallsyms 格式（4.6.0 / 6.1.42 / 6.1.60 / 6.4.0 / 6.12.0），自动适配。

### Shellcode 生成

使用 AsmJit 在宿主机上动态生成 AArch64 机器码，而非硬编码字节序列。所有跳转偏移、内存地址引用都在编译时精确计算，确保 position-dependent 代码的正确性。

### 结构体偏移自动推断

通过分析 `sys_getuid` 和 `prctl_get_seccomp` 的反汇编代码，自动推断 `task_struct->cred`、`cred->uid`、`task_struct->seccomp` 的偏移量，无需针对不同内核版本硬编码。

### root_key 存储混淆

内核二进制中不存储明文 root_key。写入时每字节与 `0xA5` 异或，shellcode 读取时实时解密比较：

```
存储: key[i] ^ 0xA5  →  内核二进制
读取: ldrb → eor #0xA5 → cmp（与明文 filename 比较）
```

### 提权过程（shellcode 伪代码）

```c
// 1. 验证 filename 指针合法性
if (filename_ptr >= -MAX_ERRNO) goto end;

// 2. 逐字节比较 filename->name 与 XOR 解密后的 root_key
for (i = 0; ; i++) {
    plain = filename->name[i];
    decrypted = stored_key[i] ^ 0xA5;
    if (plain != decrypted) goto end;
    if (plain == 0) break;  // 匹配完成
}

// 3. 获取当前 task_struct
current = mrs(SP_EL0);

// 4. 提权
cred = current->cred;
memset(&cred->uid, 0, 32);       // 清零 8 个 id 字段
cred->securebits = 0;
cred->cap_inheritable = FULL;     // 0x1FFFFFFFFFF
cred->cap_permitted   = FULL;
cred->cap_effective   = FULL;
cred->cap_bounding    = FULL;
cred->cap_ambient     = FULL;

// 5. 关闭 seccomp
clear_bit(TIF_SECCOMP, &current->thread_info.flags);
current->seccomp.mode = 0;

// 6. Pro 跳板：首次激活标记
if (init_flag == 0) init_flag = 1;
```

---

## 与 SKRoot Lite 的区别

### Patcher 层面（本工具）

| 特性 | Lite Patcher | Pro Patcher |
|---|---|---|
| 内核版本 | 4.4 ~ 6.6 | 6.1 / 6.6 / 6.12 |
| 模块加载器跳板 | ❌ | ✅ init_flag 机制 |
| root_key 存储 | 明文 | XOR 0xA5 混淆 |
| 调试输出 | 泄露地址和 shellcode | 精简到最少 |
| 华为绕过 | ✅ hkip_check | ❌ 已移除 |
| 旧版本兼容 | ✅ 3.x / 4.x / 5.x | ❌ 仅 6.x |

Pro patcher 相对 Lite 的改动很小——核心提权 shellcode 完全一致，只是加了 init_flag 跳板、XOR 混淆、精简输出，去掉了旧版本和华为的兼容代码。

### 完整生态层面

Pro 的真正价值不在 patcher，而在用户态的完整生态系统：

```
┌─────────────────────────────────────────────────┐
│  SKRoot Pro 完整架构                              │
│                                                 │
│  ┌───────────────┐                              │
│  │ Patcher (本工具)│ ← 修补内核，注入 shellcode    │
│  └───────┬───────┘                              │
│          │ 刷入 boot.img                         │
│          ▼                                      │
│  ┌───────────────┐                              │
│  │ 内核 Shellcode  │ ← 提权 + init_flag 激活      │
│  └───────┬───────┘                              │
│          │ execve(root_key)                      │
│          ▼                                      │
│  ┌───────────────┐                              │
│  │ kernel_module_ │ ← 用户态 SDK 静态库           │
│  │ kit SDK        │   get_root / install_env     │
│  └───────┬───────┘                              │
│          │                                      │
│          ▼                                      │
│  ┌───────────────┐  ┌───────────────┐           │
│  │ testInstall    │  │ PermissionMgr │           │
│  │ (环境部署)      │  │ (Android App) │           │
│  └───────────────┘  └───────────────┘           │
│                                                 │
│  用户态提供：                                     │
│  • 模块安装/卸载/管理                              │
│  • SU 授权白名单                                  │
│  • 开机自动加载 (autorun bootstrap)               │
│  • 开机失败保护 (自动禁用防死机)                    │
│  • WebUI 管理界面                                │
└─────────────────────────────────────────────────┘
```

本仓库只包含 Patcher 工具。SDK、testInstall、PermissionManager 等用户态组件不在此仓库中。

---

## 致谢

- [AsmJit](https://github.com/asmjit/asmjit) — 运行时汇编器
- [Capstone](https://github.com/capstone-engine/capstone) — 反汇编框架
- [SKRoot-linuxKernelRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot) — Lite 版本开源基础

---

## 免责声明

本工具仅供安全研究和学习用途。使用者应遵守所在地区法律法规，对使用本工具造成的任何后果自行承担责任。修改内核可能导致设备无法启动，请确保了解相关风险并做好备份。

---

## License

GPL-3.0
