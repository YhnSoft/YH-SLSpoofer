[![](https://img.shields.io/badge/powered_by-dsh-4D6BFE?style=flat-square&logo=deepseek&logoColor=white)](https://github.com/deepseek-ai/deepseek-harness)

# YH-SLSpoofer

在 **SCP: Secret Laboratory** 启动的瞬间，把它读到的 SMBIOS 机器标识换成另一组
看起来完全正常的硬件信息。

- 不改游戏目录里的任何文件
- 不安装驱动，不需要测试签名
- 不碰注册表、磁盘序列号、网卡 MAC
- 每次启动只需一次注入

<h1 align="center">🤖 本仓库由 AI 编写 · AI-WRITTEN</h1>

<p align="center">
  <b>代码、文档、逆向笔记全部由 AI（DeepSeek Harness，powered by dsh）生成并整理。</b><br>
  <b>每条结论都在 <code>docs/REVERSE-NOTES.md</code> 里有对应的实测日志，但命令、偏移和判断请你自己复核后再用。</b><br>
  <b>仅用于本机环境研究与自测；请在你拥有或明确获授权的机器上使用。</b>
</p>

---

<h2 align="center">⚠️ 仅针对 SCP:SL 14.2.8 实测</h2>

<p align="center">
  <b>本项目的调用点、采集时机、模块名、字段布局全部来自 <code>SCP: Secret Laboratory 14.2.8</code>。</b><br>
  <b>游戏或反作弊一旦更新：调用点可能移位、模块名可能变化、采集面可能扩大，脚本会直接失效。</b><br>
  <b>更糟的情况是改到了不该改的字段——先跑侦察模式确认，再决定要不要继续用。</b>
</p>

---

## 快速开始

### 1. 安装依赖

```powershell
py -m pip install frida
```

需要 Windows 10/11 x64、Python 3.9+、已登录的 Steam 客户端，普通用户权限即可。

### 2. 配置

所有可调项集中在一个文件里：

```powershell
Copy-Item src\config.example.json src\config.json
```

`src\config.json`（不进版本库，随便写本机路径）：

```jsonc
{
  "game_dir": "",              // 留空则自动探测 Steam 库；也可写绝对路径
  "probe_seconds": 300,        // 侦察模式观察窗口

  "js": {
    "hwid_patch.js": {
      "onlyFromModule": "SL-AC\\.dll",   // 只处理这个模块发起的调用
      "logBudget": 80,
      "mask": { "enabled": true, "keepStart": 3, "keepEnd": 2 },
      "identity": {
        "systemSerial":  "EXAMPLE000000001",   // Type 1 系统序列号
        "boardSerial":   "EXAMPLE0001",        // Type 2 主板序列号
        "chassisSerial": "EXAMPLE000000001",   // Type 3 机箱序列号
        "systemUuid": [0, 17, 34, 51, 68, 85, 102, 119,
                       136, 153, 170, 187, 204, 221, 238, 255]
      }
    },
    "hwid_probe.js": {
      "targetModule": "SL-AC\\.dll",
      "logBudget": 1200,
      "dumpTable": false,      // 是否把 SMBIOS 表内容打进日志
      "maskSecrets": true
    }
  }
}
```

要点：

- **只改 `src\config.json` 即可**，不用碰任何 `.js` / `.py`。
- `game_dir` 留空时，顺序是「`SL_GAME_DIR` 环境变量 → Steam 注册表 → 各库目录」。
- `identity` 三个串长度不必和真值一致，写入时按目标字符串长度截断或补齐。
- `src\config.json` 已在 `.gitignore` 里；**不要把真实机器码提交进仓库**。
- 改完不需要重新安装，下次启动生效。

#### 每个参数怎么填

| 参数 | 类型 | 示例 | 说明 |
| --- | --- | --- | --- |
| `game_dir` | 字符串 | `"D:\\SteamLibrary\\steamapps\\common\\SCP Secret Laboratory"` | 留空则自动探测。支持 `%USERPROFILE%` 之类环境变量 |
| `probe_seconds` | 数字 | `300` | 侦察模式观察窗口，单位秒 |
| `js."hwid_patch.js".onlyFromModule` | 正则字符串 | `"SL-AC\\.dll"` | 只处理该模块发起的调用。JSON 里反斜杠要双写 |
| `js."hwid_patch.js".logBudget` | 数字 | `80` | 改写器日志条数上限，防止刷屏 |
| `js."hwid_patch.js".mask.enabled` | 布尔 | `true` | 日志里的机器码是否打码 |
| `js."hwid_patch.js".mask.keepStart` | 数字 | `3` | 打码时保留开头几位 |
| `js."hwid_patch.js".mask.keepEnd` | 数字 | `2` | 打码时保留结尾几位 |
| `js."hwid_patch.js".identity.systemSerial` | 字符串 | `"EXAMPLE000000001"` | Type 1 系统序列号 |
| `js."hwid_patch.js".identity.boardSerial` | 字符串 | `"EXAMPLE0001"` | Type 2 主板序列号 |
| `js."hwid_patch.js".identity.chassisSerial` | 字符串 | `"EXAMPLE000000001"` | Type 3 机箱序列号 |
| `js."hwid_patch.js".identity.systemUuid` | 16 个整数 | `[74, 44, 174, 228, 230, 35, 243, 75, 190, 122, 18, 190, 14, 162, 72, 156]` | Type 1 系统 UUID，见下 |
| `js."hwid_probe.js".targetModule` | 正则字符串 | `"SL-AC\\.dll"` | 侦察器只关注该模块的调用 |
| `js."hwid_probe.js".logBudget` | 数字 | `1200` | 侦察日志条数上限 |
| `js."hwid_probe.js".dumpTable` | 布尔 | `false` | 是否把 SMBIOS 表内容打进日志（含完整机器码，默认关） |
| `js."hwid_probe.js".maskSecrets` | 布尔 | `true` | 是否给读到的长文本（`MachineGuid` 等）打码 |

三个串号的长度不必和真值一致：短了补空格、长了截断，SMBIOS 表结构不受影响。
`onlyFromModule` / `targetModule` 是**正则字符串**而不是通配符，`\\.` 表示字面量点号。

#### `systemUuid` 怎么填

唯一不是字符串的字段，要求 **恰好 16 个 0–255 的整数**，顺序是内存字节序。
生成一组新的：

```powershell
[guid]::NewGuid().ToByteArray() -join ', '
```

输出形如 `74, 44, 174, 228, 230, 35, 243, 75, 190, 122, 18, 190, 14, 162, 72, 156`，
整行粘进数组即可。`.NET` 的 `Guid.ToByteArray()` 前 3 段本身就是小端存放，
和 SMBIOS 的约定一致，不用手动翻字节。

想基于本机真实 UUID 改（先看值，再转数组）：

```powershell
(Get-CimInstance Win32_ComputerSystemProduct).UUID
[byte[]]([guid](Get-CimInstance Win32_ComputerSystemProduct).UUID).ToByteArray() -join ', '
```

填错不会崩：数量不是 16、元素不是整数或越界时，改写器会跳过 UUID 并写一条
`[WARN] systemUuid 必须是 16 个 0-255 的整数`，其余字段照常改写。

### 3. 启动

双击 `src\start_scpsl.bat`，或给它建一个快捷方式。

启动成功的标志：`logs/patch_runtime.log` 里出现 `[PATCH]` 行。

> **不要用 Steam 的「开始游戏」按钮。** 那条路直接运行原版 exe，不经过本项目注入，
> 反作弊会读到真实机器标识。

---

## 目录结构

```
YH-SLSpoofer/
├── src/
│   ├── config.example.json     配置模板（复制成 config.json 后修改）
│   ├── config.json             本地配置（不进版本库）
│   ├── hwid_patch.js           核心：SMBIOS 解析与改写
│   ├── hwid_probe.js           侦察器
│   ├── sl_common.py            公共工具：路径、配置、日志、会话装配
│   ├── spawn_patch.py          正常启动入口
│   ├── spawn_probe.py          侦察启动入口
│   └── start_scpsl.bat         双击入口
├── docs/                       原理、排错、逆向实测记录
└── logs/                       运行日志（自动创建，不进版本库）
```

## 常见问题

| 现象 | 处理 |
| --- | --- |
| 双击没反应 | 看 `logs/patch_runtime.log`，通常是没有 `pip install frida` |
| 日志只有 `[READY]` 没有 `[PATCH]` | 不是从本入口启动，或反作弊模块名变了 |
| 弹框要求关闭测试签名 / 内核调试 | 这是机器环境问题，与本项目无关。按弹框提示自行关闭对应开关后重启即可 |

完整列表见 [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)。

## 已知限制

- **只针对 SCP:SL `14.2.8`**。版本一变就重新验证，别想当然。
- **仅 Windows x64**，只改写 SMBIOS 相关的机器标识。
- **只在 spawn 路径生效**，从 Steam 直接启动不带钩子。
- **依赖注入**，若目标将来加入注入检测，需要调整注入方式。
- **采集面可能变化**，反作弊更新后用侦察模式重新确认。
- 账号层面的封禁与本项目无关。

## 卸载

不改动系统与游戏文件，删掉仓库目录即可（在仓库根目录执行）：

```powershell
Remove-Item -Recurse -Force .
```

## 文档

| 文档 | 内容 |
| --- | --- |
| [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md) | 工作原理、时序、三个设计取舍、日志格式、侦察模式 |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | 完整故障排查 |
| [docs/REVERSE-NOTES.md](docs/REVERSE-NOTES.md) | 逆向实测证据：样本结构、启动闸门、采集面、被否决的方案 |
