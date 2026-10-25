"""
sl_common.py —— 三个脚本共用的工具函数
======================================

这个文件只做四件事，每件都尽量薄：

1. 统一路径解析：仓库相关的目录（脚本、日志、仓库根）都从本文件位置推导，
   仓库放在哪个盘符、哪个目录都不用改代码。
   游戏目录优先取 config.json 的 game_dir；留空则按「SL_GAME_DIR → Steam
   注册表 → 各库目录」自动探测。

2. 统一日志写入：UTF-8、追加、失败不抛异常（日志坏了不能让游戏起不来）。

3. 进程查重：目标游戏已经在跑时不要再拉起第二个。

4. Frida 会话装配：把"读 JS 文件 → create_script → 挂消息回调 → load"
   这段重复流程收拢到一处，两个入口脚本只写各自关心的逻辑。
"""

import json
import os
import re
import subprocess
import time

import frida

# ---------------------------------------------------------------------------
# 路径
# ---------------------------------------------------------------------------

# 本文件位于 <repo>/src/，所以上两级就是仓库根目录
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SRC_DIR)
LOG_DIR = os.path.join(REPO_ROOT, "logs")

# 本地配置文件（不进版本库）与模板
CONFIG_PATH = os.path.join(REPO_ROOT, "config.json")
CONFIG_EXAMPLE_PATH = os.path.join(REPO_ROOT, "config.example.json")

# SCP: Secret Laboratory 的 Steam AppID 与安装目录名
APP_ID = "700330"
GAME_FOLDER = "SCP Secret Laboratory"


def load_config():
    """
    读取仓库根目录的 config.json。

    设计约束：
      - 配置坏了不能把启动弄挂，所以任何解析错误都退回空配置；
      - 不缓存，启动流程只会调用几次，读文件比维护缓存更省心。
    """
    try:
        with open(CONFIG_PATH, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {}

    return data if isinstance(data, dict) else {}


def _steam_install_roots():
    """
    从注册表读出 Steam 安装目录（三个常见位置，去重保序）。

    这样就不需要把任何盘符写死在代码里。非 Windows 或读不到时返回空列表。
    """
    try:
        import winreg
    except ImportError:
        return []

    candidates = [
        (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam", "InstallPath"),
    ]

    roots = []
    for hive, subkey, value_name in candidates:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                value, _ = winreg.QueryValueEx(key, value_name)
        except OSError:
            continue
        if value and value not in roots:
            roots.append(value)
    return roots


def _library_roots(steam_root):
    """
    返回「Steam 根目录 + libraryfolders.vdf 里记录的所有库目录」。

    vdf 是 Valve 的简化 keyvalue 文本，内容形如：

        "libraryfolders" { "0" { "path" "D:\\SteamLibrary" } }

    路径里的反斜杠是双写的。这里不引入 vdf 解析依赖，直接抽取形如
    "X:\\..." 的字符串就够了——多抽到几个无关路径也无害，后面会逐个校验。
    """
    roots = [steam_root]
    vdf_path = os.path.join(steam_root, "steamapps", "libraryfolders.vdf")
    try:
        with open(vdf_path, encoding="utf-8", errors="ignore") as handle:
            text = handle.read()
    except OSError:
        return roots

    for raw in re.findall(r'"([A-Za-z]:[\\/][^"]*)"', text):
        path = raw.replace("\\\\", "\\")
        if path not in roots:
            roots.append(path)
    return roots


def find_game_dir():
    """
    定位游戏安装目录，找不到返回 None。

    顺序：
      1. 环境变量 SL_GAME_DIR（显式指定永远优先）
      2. 各 Steam 库目录下的 steamapps\\common\\SCP Secret Laboratory
    """
    override = os.environ.get("SL_GAME_DIR")
    if override:
        return override

    for steam_root in _steam_install_roots():
        for library in _library_roots(steam_root):
            candidate = os.path.join(library, "steamapps", "common", GAME_FOLDER)
            if os.path.isdir(candidate):
                return candidate
    return None


def game_dir():
    """
    游戏目录，解析顺序（前面的优先）：

      1. 环境变量 SL_GAME_DIR —— 临时覆盖，不改文件
      2. config.json 里的 game_dir —— 常规配置入口
      3. Steam 注册表 + 各库目录自动探测 —— 不想配也能跑

    返回空串表示三种方式都没找到，由调用方给出可读提示。
    """
    override = os.environ.get("SL_GAME_DIR")
    if override:
        return override

    configured = load_config().get("game_dir")
    if isinstance(configured, str) and configured.strip():
        # 允许写 %USERPROFILE% 之类的环境变量，便于在不同机器间复用配置
        return os.path.expandvars(os.path.expanduser(configured.strip()))

    return find_game_dir() or ""


def game_exe():
    return os.path.join(game_dir(), "SCPSL.exe")


def probe_seconds(default=300.0):
    """
    侦察模式的观察窗口秒数。

    优先级：SL_PROBE_SECONDS 环境变量 → config.json 的 probe_seconds → 内置默认。
    """
    raw = os.environ.get("SL_PROBE_SECONDS")
    if raw is None:
        raw = load_config().get("probe_seconds", default)

    try:
        return float(raw)
    except (TypeError, ValueError):
        return float(default)


def script_config(js_filename):
    """
    取出 config.json 里 js.<文件名> 这一段的覆盖配置。

    这段 JSON 会被原样注入到 JS 脚本最前面（见 load_script），
    JS 侧用同样的键名做默认值合并，所以两边键名必须一致（camelCase）。
    """
    js_section = load_config().get("js")
    if not isinstance(js_section, dict):
        return {}

    override = js_section.get(js_filename)
    return override if isinstance(override, dict) else {}


def script_path(filename):
    return os.path.join(SRC_DIR, filename)


def log_path(filename):
    os.makedirs(LOG_DIR, exist_ok=True)
    return os.path.join(LOG_DIR, filename)


# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------


class Log(object):
    """
    极简的追加式日志。

    刻意不做文件轮转：这些日志只是一次启动的诊断记录，几十 KB 量级，
    真要清理直接删文件即可。写入失败静默忽略——日志系统不应该成为
    启动失败的原因。
    """

    def __init__(self, filename):
        self.path = log_path(filename)

    def write(self, text):
        try:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(text + "\n")
        except Exception:
            pass

    def section(self, title):
        self.write("")
        self.write("=== %s ===" % title)


def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# 进程查重
# ---------------------------------------------------------------------------


def game_running():
    """
    判断游戏是否已在运行。

    注意这里**不能用 text=True**：中文版 Windows 的 tasklist 输出是 GBK，
    Python 按默认编码解码会抛 UnicodeDecodeError，异常被吞掉后就永远返回
    False，查重会静默失效（踩过这个坑）。
    直接对原始字节做包含判断，绕开编码问题。
    """
    try:
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq SCPSL.exe", "/NH"],
            capture_output=True,
            timeout=10,
        )
        return b"SCPSL.EXE" in (result.stdout or b"").upper()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Frida 会话装配
# ---------------------------------------------------------------------------


def spawn_suspended(device):
    """
    以挂起状态启动游戏。

    为什么必须挂起：目标反作弊在进程启动约 0.7 秒时就会读取机器标识。
    普通 attach 注入需要几百毫秒，很可能赶不上；spawn 让进程停在入口点
    之前，等脚本装好再 resume，才能保证那次读取一定经过钩子。

    SteamAppId / SteamGameId 是为了让游戏的 Steamworks 初始化认为自己
    是由 Steam 客户端启动的，避免它调用 RestartAppIfNecessary 主动退出。
    """
    env = {
        "SteamAppId": APP_ID,
        "SteamGameId": APP_ID,
    }
    return device.spawn([game_exe()], cwd=game_dir(), env=env)


def load_script(session, js_filename, on_message):
    """
    读取 JS 文件并在目标进程里执行它。

    执行时机：此时进程还处于挂起状态，所以 JS 里的 Interceptor.attach
    会在游戏真正开始运行之前生效。

    返回 script 对象，调用方通常只需要丢弃它（session 会持有引用）。
    """
    path = script_path(js_filename)
    with open(path, encoding="utf-8") as handle:
        source = handle.read()

    # 把集中配置注入成脚本最前面的一个全局变量。
    # 这样 JS 里不需要读文件，也不依赖 Frida 的文件 API；
    # JS 侧再用同样的默认值做合并兜底（直接用 frida CLI 加载时也能跑）。
    injected = json.dumps(script_config(js_filename), ensure_ascii=False)
    source = "globalThis.__SLSPOOFER_CONFIG__ = %s;\n%s" % (injected, source)

    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    return script


def make_message_handler(log, print_to_console=False):
    """
    生成一个 Frida 消息回调。

    Frida 的 send() 会以 {"type": "send", "payload": {...}} 的形式到达；
    JS 里抛出的未捕获异常则以 {"type": "error"} 到达。两者都记录下来，
    后者往往是 hook 写错了，排查时最关键。
    """

    def handler(message, data):
        kind = message.get("type")

        if kind == "send":
            payload = message.get("payload") or {}
            elapsed = payload.get("t", 0) / 1000.0
            tag = payload.get("tag", "?")
            text = payload.get("msg", "")
            line = "[%8.2fs][%s] %s" % (elapsed, tag, text)
            log.write(line)
            if print_to_console:
                print(line, flush=True)

        elif kind == "error":
            line = "[SCRIPT-ERROR] %s" % message.get("description", "")
            log.write(line)
            if print_to_console:
                print(line, flush=True)
            stack = message.get("stack")
            if stack:
                log.write(stack)

    return handler
