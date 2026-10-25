# YH-SLSpoofer

在 **SCP: Secret Laboratory** 启动的瞬间，把它读到的 SMBIOS 机器标识换成另一组
看起来完全正常的硬件信息。

- 不改游戏目录里的任何文件
- 不安装驱动，不需要测试签名
- 不碰注册表、磁盘序列号、网卡 MAC
- 每次启动只需一次注入

> 用于本机环境研究与自测。请在你拥有或明确获授权的机器上使用。

---

## 快速开始

### 1. 安装依赖

```powershell
py -m pip install frida
```

需要 Windows 10/11 x64、Python 3.9+、已登录的 Steam 客户端，普通用户权限即可。

### 2. 配置

游戏目录按「`SL_GAME_DIR` 环境变量 → Steam 注册表 → 各库目录」的顺序自动定位，
一般不用配。自动定位失败时再手动指定：

```powershell
setx SL_GAME_DIR "<游戏安装目录>"
```

然后在 [src/hwid_patch.js](src/hwid_patch.js) 的 `CONFIG.identity` 里填一组自己的机器身份
（仓库里是占位示例）：

```javascript
identity: {
  systemSerial: 'EXAMPLE000000001',  // 系统序列号（Type 1）
  boardSerial: 'EXAMPLE0001',        // 主板序列号（Type 2）
  chassisSerial: 'EXAMPLE000000001', // 机箱序列号（Type 3）
  systemUuid: [...16 个字节...],      // 系统 UUID
},
```

长度不必和真值一致，代码会按目标字符串长度自动截断或补齐。

### 3. 启动

双击 `scripts\start_scpsl.bat`，或给它建一个快捷方式。

启动成功的标志：`logs/patch_runtime.log` 里出现 `[PATCH]` 行。

> **不要用 Steam 的「开始游戏」按钮。** 那条路直接运行原版 exe，不经过本项目注入，
> 反作弊会读到真实机器标识。

---

## 目录结构

```
YH-SLSpoofer/
├── docs/            原理、排错、逆向实测记录
├── scripts/         启动脚本与环境修复脚本
├── src/             改写器、侦察器、Python 编排
└── logs/            运行日志（自动创建，不进版本库）
```

## 常见问题

| 现象 | 处理 |
| --- | --- |
| 双击没反应 | 看 `logs/patch_runtime.log`，通常是没有 `pip install frida` |
| 日志只有 `[READY]` 没有 `[PATCH]` | 不是从本入口启动，或反作弊模块名变了 |
| 弹框要求关闭测试签名 | 管理员运行 `scripts\repair-environment.ps1` 后重启 |

完整列表见 [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)。

## 已知限制

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

只有跑过 `scripts\repair-environment.ps1` 才会动系统设置（关闭测试签名、内核调试、
清 Defender 排除项），需要时自行用 `bcdedit` 恢复。

## 文档

| 文档 | 内容 |
| --- | --- |
| [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md) | 工作原理、时序、三个设计取舍、日志格式、侦察模式 |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | 完整故障排查 |
| [docs/REVERSE-NOTES.md](docs/REVERSE-NOTES.md) | 逆向实测证据：样本结构、启动闸门、采集面、被否决的方案 |
