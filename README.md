# FilzaJailedDS 26.3 适配包 — iPhone 17 Pro (iPhone18,3) / A19 Pro / iOS 26.3

## 文件清单

| 文件 | 替换位置 | 说明 |
|------|----------|------|
| kexploit_opa334.h | FilzaJailedDS/kexploit/ | 新增 CPUFamily enum + gCPUFamily extern |
| kexploit_opa334.m | FilzaJailedDS/kexploit/ | mach_vm_map_overwrite_fixed 修复 |
| offsets.m | FilzaJailedDS/kexploit/ | gCPUFamily 赋值、A17 t_tro 修复、版本放宽 |
| kutils.m | FilzaJailedDS/kexploit/ | proc_self 链每步验证 |
| sandbox_escape.m | FilzaJailedDS/ | dump_proc_ro + 扩展扫描 + 动态偏移 |

## 替换步骤

1. 在 macOS 上打开 FilzaJailedDS 项目
2. 将以上 5 个文件替换到对应位置
3. 编译：`make`
4. 用企业证书签名打包
5. 安装到 iPhone 17 Pro (26.3) 上

## 日志查看

启动 Filza 后，在手机上查看日志：

1. 设置 → 隐私与安全性 → 分析与改进 → 分析数据
2. 搜索包含 "Filza" 或 "sandbox" 的日志文件
3. 或者用 Mac 连接手机运行：`idevicesyslog | grep -E "SBX|Tweak|DUMP|proc_self|kexploit"`

## 关键日志标识

- `[CPU]` — CPU 检测结果（应显示 A19Pro）
- `[SBX]` — 沙盒逃逸相关
- `[DUMP]` — proc_ro 内存转储
- `[Tweak]` — Tweak 注入日志
- `proc_self: chain failed` — proc_self 链断裂（偏移错误）

## 已知风险

- A19 Pro 的 t_tro 偏移未经验证，可能有偏移不匹配
- 建议首次测试只看日志，不实际触发 exploit
