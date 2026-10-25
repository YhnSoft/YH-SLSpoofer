# 故障排查

按现象查表。日志路径统一是 `logs/`（相对于仓库根目录）。

## 启动相关

| 现象 | 原因 / 处理 |
| --- | --- |
| 双击后毫无反应 | 看 `logs/patch_runtime.log`。多半是 `pythonw` 不在 PATH，或没有 `pip install frida`。也可以直接 `python src\spawn_patch.py` 看控制台报错 |
| `ModuleNotFoundError: No module named 'frida'` | `pip install frida`，注意装到正在使用的那个 Python（`python -c "import sys; print(sys.executable)"`） |
| 提示「SCPSL.exe 已在运行，跳过」 | 防双开保护。关掉现有游戏再启动；两个实例抢同一 Steam 会话会让反作弊读到真值 |
| 游戏启动后立刻自己退出 | 检查 Steam 客户端是否已登录；检查 `SL_GAME_DIR`（或 `sl_common.py` 里的默认值）是否指向正确目录 |

## 改写没生效

| 现象 | 原因 / 处理 |
| --- | --- |
| 日志只有 `[READY]`，没有 `[PATCH]` | 钩子装上了但没命中。① 确认是从本项目入口启动，而不是 Steam「开始游戏」；② 确认反作弊模块名没变（`hwid_patch.js` 的 `onlyFromModule`）；③ 用侦察模式看实际调用者是谁 |
| 日志里出现 `[SKIP]` | 某个导出函数没找到。系统不是常规 Windows，或该 API 已被替换 |
| `[PATCH]` 有，但只有 1~2 个 `[FIELD]` | 目标机器 SMBIOS 字段布局不同。看 `[FIELD]` 少了哪一项，对照 `REVERSE-NOTES.md` 第 6 节的字段表调整 |

## 反作弊弹框

| 弹框原文 | 含义 | 处理 |
| --- | --- | --- |
| *Please disable kernel debugging, exclusion paths and test signing in your system before playing* | 机器环境不合规：开了测试签名 / 内核调试，或 Defender 排除项非空、服务查不到 | 管理员运行 `scripts\repair-environment.ps1`，然后**必须重启**（测试签名是引导期设置） |
| *Unexpected game file found (…)* | 游戏目录里有 Steam 清单外的文件 | 把多余文件移出游戏目录（额外的 exe、DLL、IDA 数据库 `.id0/.id1/.i64` 等） |

## 日志本身

| 现象 | 原因 / 处理 |
| --- | --- |
| 用 `Get-Content` 看日志是乱码 | 日志是 UTF-8，Windows PowerShell 5.1 默认按 GBK 显示。用 `Get-Content -Encoding UTF8`，或直接用编辑器打开 |
| 日志里机器码是 `ABC****89` 这种 | 正常。默认脱敏只保留首尾几位，要完整值把 `hwid_patch.js` 的 `CONFIG.mask.enabled` 临时设为 `false` |
| `logs/` 目录不存在 | 第一次成功启动后才会创建 |

## 网络

| 现象 | 原因 / 处理 |
| --- | --- |
| 游戏能进但服务器列表加载失败 | 与本项目无关，通常是 DNS 或网络问题 |
| 能进服务器但很快被踢 | 与本项目无关（机器标识已经改了）。这是账号侧或网络侧判定，需要单独排查 |

## 仍然解决不了

按这个顺序采集信息，比直接猜快得多：

```powershell
# 1. 确认解释器与依赖
python -c "import sys, frida; print(sys.executable, frida.__version__)"

# 2. 用侦察模式跑一次，看反作弊实际的调用者与采集面
set SL_PROBE_SECONDS=120
python src\spawn_probe.py

# 3. 看日志
Get-Content logs\probe_runtime.log -Encoding UTF8 -Tail 80
```

把第 3 步的输出（机器码已自动打码）连同问题现象一起提 issue 即可。
