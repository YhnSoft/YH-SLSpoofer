# 逆向实测记录

这份文档只记录**实际测量到的证据**，不写推测。所有行号、偏移、返回值都来自
本机复现时的日志。

测试对象：`SL-AC.dll`（SCP: Secret Laboratory 客户端反作弊模块）

| 项 | 值 |
| --- | --- |
| 文件大小 | 10,328,416 字节 |
| 格式 | PE32+ / x86_64 / 12 个节 |
| SHA-256 | `2018f32ff73df4036016713db1d975b06f2419576064bfebb69ed5c54e94682c` |
| 托管代码 | 否（无 CLI 目录） |
| 保护 | Themida |

---

## 1. 保护壳判定

三个特征同时出现，可以确定是 Themida 的 Win64 变体：

- `.themida` 段，VirtualSize `0x992000`，特性 `0x60000000`（可读写、不可执行）
- `.boot` 段，`0x617800`，同样可读写不可执行；`DllMain` 入口 `entry` 落在里面
- 独立地址空间 `tdb`，位于 `0xff00000000`–`0xff00001850`（VM 描述块）

壳在运行时会解密主代码段并临时改页属性，所以磁盘上看到的永远是不可用状态。

## 2. 静态分析的边界

用 Ghidra 12.1.4 跑完默认全量分析后：

- 只识别出 **14 个过程、37 个字符串**（对 10 MB 的二进制来说等于零）
- 导出函数 `PollAsync`（`0x180128c60`）反汇编出来是：

  ```
  OUTSB DX, RSI
  PUSH RBP
  OR dword ptr [RBX + 0x50], ESI
  XCHG EAX, EDX
  IRETD
  ```

  这串指令在该上下文中不可能成立，说明函数体是密文，函数边界也是假的。

**结论**：任何"反编译出来的机器码函数"都不可信，静态路线到此为止。

## 3. 能静态读到的接口面

导出表（`.edata`）：

```
GetConfig
PollAsync
SendRequest
SendRequestAsync
FreeLpString
```

导入表（壳未加密的外层部分，只有 10 个）：

```
KERNEL32   GetModuleHandleA
NTDLL      RtlVirtualUnwind
OLE32      CoCreateInstance        <- WMI 入口
ADVAPI32   CryptDecrypt
CRYPT32    CertDuplicateCertificateContext
SHLWAPI    PathFileExistsW
USER32     GetWindowTextW
WS2_32     getpeername
IPHLPAPI   if_nametoindex
NORMALIZ   IdnToUnicode
```

另有字符串：`WINHTTP.dll`、`WinHttpGetIEProxyConfigForCurrentUser`、
`Secur32.dll`、`InitSecurityInterfaceW`、`WakeByAddressSingle`、`SHGetFolderPathW`。

据此判断它是「HTTP(S) 客户端 + TLS(Schannel) + WMI 采集」的组合。

## 4. 启动闸门（实测弹框与触发条件）

启动时依次通过三道检查，任何一道不过就直接终止进程：

### 4.1 环境检查

弹框原文：

> Please disable kernel debugging, exclusion paths and test signing in your system before playing SCP:SL.

实测触发项：

| 检查 | 本机状态 | 结果 |
| --- | --- | --- |
| `TESTSIGNING` | 开启（`SystemStartOptions` 里有） | 触发 |
| 内核调试 `Debug` | False | 通过 |
| Defender `WinDefend` | Stopped / Manual | 触发（查不到排除项，按不合规处理） |
| Defender 排除项 | 键被 ACL 锁住（TamperProtection=1） | 可能触发 |

`SystemStartOptions` 这一条是从 `NtQueryValueKey` 抓到的，调用者就是 SL-AC：

```
[NTREG] SystemStartOptions = TESTSIGNING NOEXECUTE=OPTIN ...
```

处理方式：按提示把测试签名 / 内核调试关掉、清空 Defender 排除项，然后重启。
本项目不附带这类环境修复脚本——具体怎么关取决于这台机器被什么改动过。

### 4.2 游戏目录文件白名单

把所有游戏文件与 Steam 清单比对，发现清单外的文件就弹框：

> Unexpected game file found (SCPSL_real.exe). Press Yes if you want to remove it or No to cancel game startup.

这意味着**任何往游戏目录里放 exe / DLL 的做法都会被发现**。
本项目的方案因此完全不改游戏目录。

### 4.3 采集（闸门之后）

见下一节。

## 5. 机器标识采集面（核心证据）

在进程挂起阶段装好钩子后启动，完整日志（机器标识已打码，只保留首尾几位）：

```
[0.71s][SMBIOS] 签名=RSMB 表ID=0x0 返回=4703 (仅询问长度)   <- SL-AC.dll+0xe30fd8
[0.72s][PATCH]  表已改写：长度=4703 字段=4 调用者=SL-AC.dll+0xe630c5
[0.71s][SMBIOS] 签名=RSMB 表ID=0x0 返回=4703 (内容已省略)    <- SL-AC.dll+0xe630c5
[0.72s][FIELD]  T1 System Serial: "ABC***********89" -> "XYZ***********01"
[0.72s][FIELD]  T2 Board Serial:  "DEF******UV"      -> "DEF******VW"
[0.72s][FIELD]  T1 System UUID:   1122…99aa -> 3344…ccdd
```

> 表内容默认不打印：那张表里就是完整机器码，日志一旦被截图或上传等于公开指纹。

解读：

1. **两次调用**：第一次 `BufferSize=0` 只问长度（返回 4703），第二次真正取数据。
   这是 Windows 固件表 API 的标准用法。
2. **调用点**：`+0xe30fd8` 问大小、`+0xe630c5` 取数据，两个都在 SL-AC 模块内。
3. **只读一次**：整场会话（累计两小时以上、多局游戏）没有第二次读取。

同一批日志里，`caller=SL-AC.dll` 的记录**只有**：

- `GetSystemFirmwareTable('RSMB')` × 1
- `connect()` 到 `127.0.0.1:<随机端口>` × 7

以下 API **一次都没有**被 SL-AC 调用：

```
GetVolumeInformationW          卷序列号
DeviceIoControl                磁盘序列号 / SMART
NtDeviceIoControlFile          同上（原生通道）
GetAdaptersInfo                网卡 MAC
CoCreateInstance               WMI
RegQueryValueExW               MachineGuid 等注册表值
GetComputerNameW / GetUserNameW
```

**结论**：机器码 = `f(原始 SMBIOS 表)`，且启动时只算一次。

## 6. SMBIOS 表里被使用的字段

实测表长 4703 字节，被引用的字段如下。

> 具体值一律替换为占位符：这些字符串就是本机的唯一指纹，公开仓库里不留原件。

```
Type 0  BIOS        <BIOS 厂商> / <BIOS 版本> / <发布日期>
Type 1  System      <整机厂商> / <机型> / <机型版本>
        Serial      <整机序列号>            <- 机器唯一标识的主要来源
        UUID        16 字节二进制（偏移 0x08）
Type 2  Baseboard   <主板厂商> / <主板型号> / <版本> / <主板序列号>
Type 3  Chassis     <机箱厂商> / <版本> / <机箱序列号> / <资产标签>
```

注意 Type 1 与 Type 3 的序列号经常是同一串内容（各自字符串集里有一份），
所以改写时要按「内容相同」把它们一起处理，否则会出现系统序列号变了、
机箱序列号还是老值的半改状态。

## 7. 表结构约束（为什么必须等长改写）

```
[8 字节表头: 'RSMB' + 长度 + 校验和 + 版本]
[结构: type(1) + 格式化长度(1) + 格式化区 + 字符串集]
[结构: ...]
[type=127 结束]
```

字符串集格式：`"str1\0str2\0\0"`。字符串长度变化会让后续所有结构的起始偏移错位，
整张表不可解析。所以改写必须等长（短了补空格、长了截断），表总长保持 4703。

## 8. 上报通道

- `WinHttpOpen` 全程只被 `steamclient64.dll` 调用，**SL-AC 从未使用 WinHTTP**
- SL-AC 出站连接 7 次，全部指向 `127.0.0.1`，端口每次不同
  （`57696 / 57985 / 53189 / 61407 / 56236 / 56238 / 52044`），调用点固定为 `SL-AC.dll+0x52d886`

目标端口每次都变，不符合"连固定本地服务"的特征，更像**本机端口探活**（扫描常见
作弊工具的本地监听端口）。因此上报数据实际走的是游戏自身的网络栈（Unity 层），
这也是从 WinHTTP 抓不到 payload 的原因。

## 9. 已排除的方案（都试过，各自失败在明确的位置）

| 方案 | 失败原因 |
| --- | --- |
| 改 DLL 代码绕过 | Themida 虚拟化 + 自校验，启动即崩 |
| 替换游戏 exe 为启动桩 | 被 4.2 的文件白名单拦截 |
| 内核驱动改 SMBIOS/磁盘序列号 | 需要测试签名，而 4.1 强制关闭测试签名 |
| 改 MachineGuid / 卷序列号 / 网卡 MAC | 4.5 证明 SL-AC 根本不读这些 |
| 用 Steam "开始游戏" 启动 | 走原版路径，钩子不生效 |
| Frida 挂载后再 attach（非 spawn） | 0.7 秒的采集窗太早，注入来不及 |

## 10. 遗留未知

1. `127.0.0.1` 探活端口的具体用途（是否在检测本机作弊工具）。
2. 连服阶段是否存在二次采集 —— 现有日志显示没有，但样本有限。
3. 封禁判定的时间窗口（观察结果是 1~2 局，说明是服务端批处理，不是即时踢）。
4. Themida 版本号（段特征能确定产品，不能确定具体版本）。
