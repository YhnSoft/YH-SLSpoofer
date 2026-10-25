# YH-SLSpoofer

在 **SCP: Secret Laboratory** 启动的瞬间，把游戏读到的 SMBIOS 机器标识替换成另一组
看起来完全正常的硬件信息。

- 不修改游戏目录里的任何文件
- 不安装驱动，不需要测试签名
- 不碰注册表、磁盘序列号、网卡 MAC
- 每一次启动都只需要一次注入

> 用于本机环境研究与自测。请在你自己拥有或明确授权的机器上使用。

---

## 目录

- [它解决什么问题](#它解决什么问题)
- [原理速览](#原理速览)
- [为什么这样能成](#为什么这样能成)
- [目录结构](#目录结构)
- [环境要求](#环境要求)
- [安装](#安装)
- [配置](#配置)
- [使用](#使用)
- [日志怎么读](#日志怎么读)
- [侦察模式](#侦察模式)
- [故障排查](#故障排查)
- [已知限制](#已知限制)
- [还原 / 卸载](#还原--卸载)
- [进一步阅读](#进一步阅读)

---

## 它解决什么问题

目标反作弊把「机器唯一标识」当成账号之外的第二把锁：它从系统里读出主板/整机的
序列号和 UUID，算出一个指纹上报给服务器。服务器按这个指纹记录封禁。

要绕开它，有两条路：

1. 让反作弊算不出指纹 —— 需要拆掉商业壳，成本极高，而且服务器端已经存了旧指纹；
2. 让它算出**另一台机器**的指纹 —— 只需要改它读到的输入。

这个项目走第二条。因为实测发现：反作弊读的输入非常单一，就是**一张原始 SMBIOS 表**。

## 原理速览

```
双击快捷方式 / scripts\start_scpsl.bat
  │
  └─ pythonw src\spawn_patch.py
       │
       ├─ 查重：SCPSL.exe 已在运行就不重复拉起
       │
       ├─ frida.spawn(SCPSL.exe)          ← 进程已创建，但一条指令都没执行
       │
       ├─ attach + 执行 src\hwid_patch.js ← 此刻钩子已经装在
       │                                     kernel32!GetSystemFirmwareTable 上
       │
       └─ frida.resume()                  ← 游戏开始启动
              │
              └─ 约 0.7 秒：反作弊调用 GetSystemFirmwareTable('RSMB')
                     │
                     └─ 钩子的 onLeave 把缓冲区里的序列号 / UUID 换成假值
                            │
                            └─ 反作弊拿到的就是另一台机器的指纹
```

关键点是 **spawn（挂起）而不是事后 attach**：采集发生在 0.7 秒左右，普通注入
来不及。挂起态启动可以保证钩子一定早于第一次读取。

## 为什么这样能成

三条实测结论（证据见 [docs/REVERSE-NOTES.md](docs/REVERSE-NOTES.md)）：

1. **反作弊只读 SMBIOS 一张表。**
   整场会话里，来自反作弊模块的系统调用只有 `GetSystemFirmwareTable('RSMB')` 一次，
   以及若干次本机端口探活。磁盘序列号、卷序列号、网卡 MAC、`MachineGuid`、WMI
   全部零调用。

2. **只读一次，不重读。**
   0.72 秒读完之后，无论切菜单、进服务器还是长时间挂机，都没有第二次采集。
   所以每次启动改一次就够，不需要常驻。

3. **没有触发它的防护。**
   钩子挂的是系统 DLL 的导出函数，不在商业壳的自我校验范围内；实测长时间运行
   没有被踢、没有弹框。

## 目录结构

```
YH-SLSpoofer/
├── README.md                    本文件
├── docs/
│   └── REVERSE-NOTES.md         逆向实测记录（样本结构、调用点、被否决的方案）
├── scripts/
│   ├── start_scpsl.bat          日常入口（给快捷方式用）
│   └── repair-environment.ps1   修复启动闸门（测试签名 / Defender 排除项）
├── src/
│   ├── sl_common.py             公共工具：路径、日志、进程查重、会话装配
│   ├── spawn_patch.py           正常启动：spawn → 改装写器 → resume
│   ├── spawn_probe.py           侦察启动：额外挂侦察器并记录全部采集行为
│   ├── hwid_patch.js            ★ 核心：SMBIOS 解析与等长改写
│   └── hwid_probe.js            侦察器：记录所有能读到机器标识的系统调用
└── logs/                        运行日志（自动创建，不进版本库）
```

## 环境要求

| 项 | 要求 |
| --- | --- |
| 系统 | Windows 10 / 11 x64 |
| 游戏 | SCP: Secret Laboratory（Steam 版），且 Steam 客户端已登录 |
| Python | 3.9 以上（建议 3.11+） |
| 依赖 | `pip install frida`（实测 frida 17.x） |
| 权限 | 普通用户即可，不需要管理员 |

## 安装

```powershell
py -m pip install frida

# 确认装配成功
python -c "import frida; print(frida.__version__)"
```

把整个仓库放到任意位置即可，脚本里的路径都从文件位置推导，不依赖盘符。

## 配置

### 游戏目录

默认值写在 [src/sl_common.py](src/sl_common.py) 的 `DEFAULT_GAME_DIR`。装的不是默认
路径时，用环境变量覆盖：

```powershell
setx SL_GAME_DIR "D:\Games\SCP Secret Laboratory"
```

### 机器身份

在 [src/hwid_patch.js](src/hwid_patch.js) 顶部的 `CONFIG.identity` 里（下面是**占位示例**，
用之前换成自己的值）：

```javascript
identity: {
  systemSerial: 'EXAMPLE000000001',  // 系统序列号（Type 1）
  boardSerial: 'EXAMPLE0001',        // 主板序列号（Type 2）
  chassisSerial: 'EXAMPLE000000001', // 机箱序列号（Type 3）
  systemUuid: [...16 个字节...],      // 系统 UUID（Type 1 偏移 0x08）
},
```

规则：

- 长度**不必**和真值一致 —— 代码会按原字符串长度截断或用空格补齐，保证表结构不变。
- 换一组身份只需改这几个值，然后重新启动一次。
- 建议改一次之后长期固定。频繁换身份会让服务器看到一堆不同机器在短时间内交替上线。
- **不要把真实机器码写进仓库再公开**：`systemSerial` 这类值一旦推到公开仓库，
  等于把指纹一起发布了。

## 使用

双击 `scripts\start_scpsl.bat`（或给它建个快捷方式）。

**不要用 Steam 的「开始游戏」按钮**：那条路直接运行原版 exe，不经过本项目的注入，
反作弊会读到真实机器标识。

启动成功的标志：`logs/patch_runtime.log` 里出现 `[PATCH]` 行。

## 日志怎么读

`logs/patch_runtime.log` 每次启动追加一段（下面的机器标识已打码）：

```
=== start 2026-10-25 10:30:00 ===
[   0.00s][READY] 改写器已安装：serial=XYZ***********01 board=DEF******VW
[*] pid=12345 已放行，等待游戏退出
[   0.72s][PATCH] 表已改写：长度=4703 字段=4 调用者=SL-AC.dll+0xe630c5
[   0.72s][FIELD] T1 System Serial: "ABC***********89" -> "XYZ***********01"
[   0.72s][FIELD] T2 Board Serial:  "DEF******UV"      -> "DEF******VW"
[   0.72s][FIELD] T3 Chassis Serial:"ABC***********89" -> "XYZ***********01"
[   0.72s][FIELD] T1 System UUID:   1122…99aa -> 3344…ccdd
```

- 有 `[PATCH]` → 改写生效
- 只有 `[READY]` 没有 `[PATCH]` → 钩子装上了但没命中，看[故障排查](#故障排查)
- `[FIELD]` 每行就是一个被替换的字段
- 机器标识默认只保留首尾各几位（`CONFIG.mask`），要完整值排错就把 `mask.enabled` 临时设为 `false`

## 侦察模式

需要重新确认反作弊读了什么（换了版本、换了机器、怀疑采集面变宽）时：

```powershell
set SL_PROBE_SECONDS=600
pythonw src\spawn_probe.py
```

它会同时装载改写器和侦察器，把每一次相关系统调用连同**调用者模块+偏移**
记录到 `logs/probe_runtime.log`，观察窗口结束后仍保持挂载。

日志标签含义：

| 标签 | 含义 |
| --- | --- |
| `SMBIOS` | 固件表读取（最重要） |
| `REG` / `REGKEY` / `NTREG` | 注册表查询（Win32 与原生两条通道） |
| `VOLUME` | 卷序列号 |
| `IOCTL` / `NTIOCTL` | 磁盘序列号、SMART |
| `NIC` | 网卡 MAC |
| `HOST` / `USER` | 计算机名 / 用户名 |
| `WMI` | COM/WMI 实例化 |
| `CONN` | 出站 TCP 连接 |
| `MOD` | 关键模块基址快照 |

所有标签的日志都带 `<- 模块名+偏移`，那是调用者。只关心带目标模块名的行。

## 故障排查

| 现象 | 原因 / 处理 |
| --- | --- |
| 双击后毫无反应 | 看 `logs/patch_runtime.log`；多半是 `pythonw` 不在 PATH 或没装 frida |
| 日志只有 `[READY]`，没有 `[PATCH]` | 说明钩子没命中。确认是从本入口启动；确认反作弊还是同一个模块名（见配置里的 `onlyFromModule`）；必要时用侦察模式看实际调用者 |
| 启动后弹出 *Please disable kernel debugging...* | 机器环境不合规，跑 `scripts\repair-environment.ps1`（管理员）后**重启** |
| 启动后弹出 *Unexpected game file found* | 游戏目录里有清单外的文件（额外的 exe / DLL / IDA 数据库等），清掉 |
| 提示「已在运行，跳过」 | 防双开保护，关掉现有游戏再启动 |
| 游戏启动后立刻自己退出 | 检查 Steam 是否已登录；检查 `SL_GAME_DIR` 是否指向正确目录 |
| `ModuleNotFoundError: No module named 'frida'` | `pip install frida`，注意装到正在使用的那个 Python |
| 游戏能进但服务器列表加载失败 | 与本项目无关，通常是网络/DNS |
| 用 `Get-Content` 看日志是乱码 | 日志是 UTF-8，Windows PowerShell 5.1 默认按 GBK 显示。用 `Get-Content -Encoding UTF8`，或直接用编辑器打开 |

## 已知限制

- **仅 Windows x64。** 用的是 `GetSystemFirmwareTable` 的 Windows 语义。
- **依赖注入。** 反作弊若将来加入对注入的检测，方案需要在注入方式上做对抗。
- **只在 spawn 路径生效。** 从 Steam 直接启动不会带钩子。
- **采集面可能变化。** 反作弊更新后调用点可能变化，届时用侦察模式重新确认，必要时更新 `hwid_patch.js` 的过滤条件。
- **只改 SMBIOS。** 如果目标将来开始读磁盘序列号或 MAC，需要扩展改写范围（侦察器已经能记录这些调用）。
- **账号层面的封禁与本项目无关。** 本项目只改变机器标识。

## 还原 / 卸载

本项目不改动系统与游戏文件，卸载就是删掉仓库目录：

```powershell
Remove-Item -Recurse -Force D:\YH-SLSpoofer
```

如果之前跑过 `scripts\repair-environment.ps1`，它改的是系统引导项（关闭测试签名、
关闭内核调试、清 Defender 排除项），需要恢复的话自行用 `bcdedit` 改回去。

## 进一步阅读

- [docs/REVERSE-NOTES.md](docs/REVERSE-NOTES.md) —— 完整逆向实测记录：
  样本结构与保护壳判定、启动闸门、采集面证据、SMBIOS 字段表、已排除的方案、遗留未知
