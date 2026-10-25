"""
sl_common.py —— 三个脚本共用的工具函数
======================================

这个文件只做四件事，每件都尽量薄：

1. 统一路径解析：仓库根目录、脚本目录、日志目录都从本文件位置推导，
   这样整个仓库可以放在任何盘符下，不需要改代码里的绝对路径。
   游戏目录默认按 Steam 库位置给一个值，可用环境变量 SL_GAME_DIR 覆盖。

2. 统一日志写入：UTF-8、追加、失败不抛异常（日志坏了不能让游戏起不来）。

3. 进程查重：目标游戏已经在跑时不要再拉起第二个。

4. Frida 会话装配：把"读 JS 文件 → create_script → 挂消息回调 → load"
   这段重复流程收拢到一处，两个入口脚本只写各自关心的逻辑。
"""

import os
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

# SCP: Secret Laboratory 的 Steam AppID。
APP_ID = "700330"

# 默认游戏安装目录；不对的话设环境变量 SL_GAME_DIR 指过去
DEFAULT_GAME_DIR = r"D:\SteamLibrary\steamapps\common\SCP Secret Laboratory"


def game_dir():
    return os.environ.get("SL_GAME_DIR", DEFAULT_GAME_DIR)


def game_exe():
    return os.path.join(game_dir(), "SCPSL.exe")


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
