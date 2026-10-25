"""
spawn_probe.py —— 侦察模式启动入口
===================================

和 spawn_patch.py 的区别：除了改写器，再额外挂一个侦察器（hwid_probe.js），
把目标进程里所有"能读到机器标识"的系统调用连同调用者一起记录到日志。

用途：换机器、换游戏版本、或者怀疑反作弊改了采集范围时，用它重新摸底。
它本身也会应用改写，所以侦察和正常游玩可以同时进行。

用法：

    pythonw src\\spawn_probe.py            # 默认观察 300 秒
    set SL_PROBE_SECONDS=600 && python src\\spawn_probe.py

观察窗口结束后不会断开，钩子继续挂着直到游戏退出——否则中途卸载会让
反作弊后续读到的值恢复成真值，反而不一致。
"""

import os
import threading
import time

import frida

from sl_common import (
    game_dir,
    game_exe,
    game_running,
    load_script,
    make_message_handler,
    spawn_suspended,
    Log,
    timestamp,
)

# 先改装写器，再装侦察器。顺序有意义：侦察器会记录到"改写后的表"，
# 日志里能直接对照 BEFORE/AFTER 是否生效。
SCRIPTS = ["hwid_patch.js", "hwid_probe.js"]

LOG_FILE = "probe_runtime.log"

# 观察窗口：这段时间内额外把日志打到控制台，方便实时观察。
# 窗口结束后仍然保持挂载，只是不再刷屏。
DEFAULT_WINDOW_SECONDS = 300


def main():
    log = Log(LOG_FILE)
    log.section("start " + timestamp())

    resolved = game_dir()
    if not resolved:
        log.write("[!] 自动定位游戏目录失败（Steam 注册表里没有可用的库）")
        log.write("[!] 手动指定：setx SL_GAME_DIR \"<游戏安装目录>\"")
        return 1

    log.write("[*] 游戏目录：" + resolved)
    if not os.path.isfile(game_exe()):
        log.write("[!] 该目录下没有 SCPSL.exe：" + resolved)
        return 1

    if game_running():
        log.write("[!] SCPSL.exe 已在运行，跳过（避免双开）")
        return 0

    window = float(os.environ.get("SL_PROBE_SECONDS", DEFAULT_WINDOW_SECONDS))

    device = frida.get_local_device()
    try:
        pid = spawn_suspended(device)
    except Exception as exc:
        log.write("[!] spawn 失败：%r" % (exc,))
        return 1

    session = device.attach(pid)

    finished = threading.Event()

    def on_detach(reason, crash):
        finished.set()
        log.write("[DETACH] %s" % reason)

    session.on("detached", on_detach)

    handler = make_message_handler(log, print_to_console=True)
    for name in SCRIPTS:
        try:
            load_script(session, name, handler)
            log.write("[*] 已载入 " + name)
        except Exception as exc:
            log.write("[!] 载入 %s 失败：%r" % (name, exc))
            try:
                device.kill(pid)
            except Exception:
                pass
            return 1

    device.resume(pid)
    log.write("[*] pid=%d 已放行，观察窗口 %ds" % (pid, int(window)))

    deadline = time.time() + window
    while time.time() < deadline and not finished.is_set():
        time.sleep(0.5)

    log.write("[*] 观察窗口结束，钩子保持挂载直到游戏退出")

    # 不要在这里 kill 进程：侦察结束后用户可能还在游戏里，
    # 强行结束会中断会话，而且会让钩子数据变得不完整。
    finished.wait()
    log.write("[*] 游戏已退出")
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception as exc:
        Log(LOG_FILE).write("[FATAL] %r" % (exc,))
        exit_code = 1

    # 同 spawn_patch.py：frida 线程会阻止解释器正常退出
    os._exit(exit_code)
