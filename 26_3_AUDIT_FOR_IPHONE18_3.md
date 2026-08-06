# FilzaJailedDS 26.3 适配审计报告

**目标设备:** iPhone 17 Pro (iPhone18,3) | **CPU:** A19 Pro | **iOS:** 26.3 (23D127)
**内核:** xnu-12377.82.2

---

## 1. 已完成的修改

### 1.1 offsets.m
- ✅ `gCPUFamily` 声明并赋值 (新增变量)
- ✅ 26.0+ 版本检查放宽到 26.6
- ✅ A17 t_tro 修复 (BUG FIX 注释)
- ✅ `gIsA18Above` 已包含 A19/TILOS + A19 Pro/THERA

### 1.2 kexploit_opa334.h
- ✅ `CPUFamily` enum 定义 (A17/A17Pro/A18/A18Pro/A18X/A19/A19Pro)
- ✅ `gCPUFamily` extern 声明

### 1.3 kexploit_opa334.m
- ✅ `mach_vm_map_overwrite_fixed()` 替代 `VM_FLAGS_OVERWRITE`

### 1.4 kutils.m
- ✅ `proc_self()` 链每步验证 + 诊断日志

### 1.5 sandbox_escape.m
- ✅ `dump_proc_ro()` 在 `sandbox_escape()` 入口处调用
- ✅ `sbx_find_ucred_slot()` 扫描范围 0x10~0x60

---

## 2. 已知风险

### 2.1 t_tro 偏移未验证 (中风险)
A19 Pro 的 `thread.t_tro` 偏移未知。代码中使用的值来自 A18，未经 A19 Pro 验证。
可能值: 0x3c0 / 0x3e8 / 0x3f0
**影响:** proc_self 链在第一跳就断裂。
**诊断:** 日志会打印 `proc_self: invalid thread_ro addr from thread+0x...`

### 2.2 so_background_thread 偏移未验证 (中风险)
同理，`socket.so_background_thread` 偏移来自 A18，A19 Pro 未验证。
**影响:** proc_self 链第二跳断裂。
**诊断:** 日志打印 `proc_self: invalid thread addr from socket+0x...`

### 2.3 is_kaddr_valid 掩码 (低风险)
当前掩码 `0xFFFFF00000000000` 对所有 iOS 26.x 都适用，内核地址在 `0xfffff...` 范围内。

---

## 3. 测试流程

1. 替换 5 个文件到 FilzaJailedDS 项目
2. `make` 编译
3. 企业证书签名打包
4. 安装到 iPhone 17 Pro (26.3)
5. 启动 Filza
6. 查看日志（详见 README.md）

---

## 4. 日志预期输出

| 日志内容 | 含义 |
|----------|------|
| `[CPU] gCPUFamily=6 (A19Pro)` | CPU 检测正确 |
| `[i] proc_self: socket addr = 0xfffff...` | 第一跳成功 |
| `[i] proc_self: thread addr = 0xfffff...` | 第二跳成功 |
| `[i] proc_self: thread_ro addr = 0xfffff...` | 第三跳成功 |
| `[i] proc_self: proc addr = 0xfffff...` | proc_self 链完整 |
| `[SBX] proc_ro=0x...` | proc_ro 地址正确 |
| `[DUMP] proc_ro structure` | 内存转储 (逐字段打印) |
| `[SBX] Found ucred at proc_ro+0x...` | ucred 找到 |
| `[SBX] Found dynamic cr_label offset 0x...` | cr_label 偏移确认 |

如果任何一步失败，日志会精确打印失败的位置和原因。
