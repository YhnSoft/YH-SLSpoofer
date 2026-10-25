# 工作原理

这份文档讲三件事：它**怎么**工作、**为什么**能成、以及它读写的那些系统接口长什么样。
逆向实测的原始证据（样本结构、保护壳、调用点、被否决的方案）在
[REVERSE-NOTES.md](REVERSE-NOTES.md)。

---

## 1. 一次启动的完整时序

```
双击快捷方式 / src\start_scpsl.bat
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

## 2. 为什么这样能成

三条实测结论（原始日志见 [REVERSE-NOTES.md](REVERSE-NOTES.md) 第 5 节）：

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

## 3. 三个设计取舍

### 3.1 为什么必须改写而不是拦截

SMBIOS 表由内核缓存，用户态没有任何接口可以修改它；要改只能进 ring0，而目标
反作弊在启动时会强制关闭测试签名。因此唯一不需要签名驱动的路径是：**在用户态
进程内，改它拿到的那份副本**。

### 3.2 为什么必须等长改写

SMBIOS 不是定长结构体数组，而是一条变长记录流：

```
[8 字节表头: 'RSMB' + 表长度 + 校验和 + 版本]
[结构: type(1) + 格式化长度(1) + 格式化区 + 字符串集]
[结构: ...]
[type=127 结束]
```

字符串集格式是 `"str1\0str2\0\0"`。字符串长度一变，后面所有记录的起始偏移都会
错位，整张表无法解析。所以 [hwid_patch.js](../src/hwid_patch.js) 只做等长覆盖：
短了用空格补，长了截断，表总长保持不变。

### 3.3 为什么只改"目标模块发起的调用"

同一个进程里，Steam / Unity / 显卡驱动都会读 SMBIOS 判断硬件型号。全都改会干扰
它们（可能导致渲染或硬件识别异常），日志也会被淹没。所以只在调用者属于目标模块
时才动手，其它调用原样放行。判断依据是 `returnAddress` 落在哪个模块里。

> 注意：Windows 上 Frida 的 `onEnter` 上下文里 `returnAddress` 为空，必须在
> `onLeave` 才能反查。这就是所有 hook 都采用「`onEnter` 存参数、`onLeave` 判归属」
> 结构的原因。

## 4. 日志怎么读

`logs/patch_runtime.log` 每次启动追加一段（下面机器标识已打码）：

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
- 只有 `[READY]` 没有 `[PATCH]` → 钩子装上了但没命中，见
  [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- `[FIELD]` 每行就是一个被替换的字段，`"改前" -> "改后"`
- 机器标识默认只保留首尾各几位（`src/config.json` 里 `js."hwid_patch.js".mask`）。
  要完整值排错，把 `enabled` 临时设成 `false`

日志是 UTF-8。Windows PowerShell 5.1 默认按 GBK 显示会乱码，用
`Get-Content -Encoding UTF8` 或直接用编辑器打开。

## 5. 侦察模式

需要重新确认反作弊读了什么（换了版本、换了机器、怀疑采集面变宽）时：

```powershell
pythonw src\spawn_probe.py
```

观察窗口在 `src/config.json` 的 `probe_seconds` 里配（默认 300 秒）。临时改一次，
也可以用环境变量覆盖（优先级高于配置文件）：

```powershell
set SL_PROBE_SECONDS=600
pythonw src\spawn_probe.py
```

它会同时装载改写器和侦察器，把每一次相关系统调用连同**调用者模块+偏移**记录到
`logs/probe_runtime.log`。观察窗口结束后不卸载，继续挂到游戏退出——中途卸载会让
后续读取恢复真值，反而制造不一致。

标签含义：

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

所有标签都带 `<- 模块名+偏移`，那是调用者。只关心带目标模块名的行。

侦察器默认**不打印** SMBIOS 表内容（`src/config.json` 里 `js."hwid_probe.js".dumpTable`），
因为那张表里就是完整机器码。需要时临时打开。

## 6. 被读写的系统接口

| 接口 | 用途 | 本项目动作 |
| --- | --- | --- |
| `GetSystemFirmwareTable('RSMB')` | 取原始 SMBIOS 表 | **改写**（核心） |
| `GetSystemFirmwareTable` 其它签名 | ACPI 等固件表 | 放行 |
| `DeviceIoControl` / `NtDeviceIoControlFile` | 磁盘序列号、SMART | 只观测 |
| `GetVolumeInformationW` | 卷序列号 | 只观测 |
| `GetAdaptersInfo` / `GetAdaptersAddresses` | 网卡 MAC | 只观测 |
| `RegQueryValueExW` / `NtQueryValueKey` | `MachineGuid` 等 | 只观测 |
| `CoCreateInstance` | WMI 查询 | 只观测 |
| `GetComputerNameW` / `GetUserNameW` | 主机名 / 用户名 | 只观测 |

「只观测」的部分是 `hwid_probe.js` 的职责：用来证明目标到底读不读它们。
当前实测结论是**不读**，所以改写器也不需要碰这些。

SMBIOS 表里被具体使用的字段（Type 0/1/2/3 的厂商、型号、序列号、UUID）见
[REVERSE-NOTES.md](REVERSE-NOTES.md) 第 6 节。
