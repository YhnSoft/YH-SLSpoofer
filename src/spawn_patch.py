"""
spawn_patch.py —— 带机器标识改写的启动入口
==========================================

流程只有五步：

    1. 查重：游戏已经在跑就直接退出，避免双开把当前会话弄乱
    2. frida.spawn：以挂起状态创建游戏进程（此时游戏一条指令都还没执行）
    3. 载入 hwid_patch.js：在挂起状态下装好 GetSystemFirmwareTable 的钩子
    4. frida.resume：放行，游戏开始正常启动
    5. 守候：一直等到游戏退出，期间保持钩子存活

直接运行（在仓库根目录）：

    pythonw src\\spawn_patch.py

日常用仓库根目录的 scripts\\start_scpsl.bat 或桌面快捷方式即可。
"""

import os
import threading

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

# 改写器：钩住 GetSystemFirmwareTable，把 SMBIOS 里的机器标识换成假身份
PATCH_SCRIPT = "hwid_patch.js"

# 每次启动追加一段记录，内容形如：
#   === start 2026-10-25 10:30:00 ===
#   [   0.72s][PATCH] 表已改写：长度=4703 字段=4 调用者=SL-AC.dll+0xe630c5
#   [   0.72s][FIELD] T1 System Serial: "ABC***********89" -> "XYZ***********01"
LOG_FILE = "patch_runtime.log"


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
        # 双开会让两个实例抢同一个 Steam 会话，而且只有先启动的那个带钩子，
        # 后启动的反而会让反作弊读到真值，所以这里直接放弃。
        log.write("[!] SCPSL.exe 已在运行，跳过（避免双开）")
        return 0

    device = frida.get_local_device()
    try:
        pid = spawn_suspended(device)
    except Exception as exc:
        log.write("[!] spawn 失败：%r" % (exc,))
        return 1

    session = device.attach(pid)

    # 用 Event 而不是轮询，进程退出时由 detached 回调唤醒
    finished = threading.Event()

    def on_detach(reason, crash):
        finished.set()
        log.write("[DETACH] %s%s" % (reason, "" if not crash else " / " + str(crash)))

    session.on("detached", on_detach)

    handler = make_message_handler(log)
    try:
        load_script(session, PATCH_SCRIPT, handler)
    except Exception as exc:
        log.write("[!] 载入 %s 失败：%r" % (PATCH_SCRIPT, exc))
        try:
            device.kill(pid)
        except Exception:
            pass
        return 1

    device.resume(pid)
    log.write("[*] pid=%d 已放行，等待游戏退出" % pid)

    # 一直挂到游戏结束：只要这个进程还在，钩子就有效。
    # 这也意味着别在游戏运行时关掉本进程（关掉后钩子随 agent 一起卸载）。
    finished.wait()
    log.write("[*] 游戏已退出")
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception as exc:  # 任何未预期异常都要留下痕迹，否则双击后什么都没发生
        Log(LOG_FILE).write("[FATAL] %r" % (exc,))
        exit_code = 1

    # 必须强制退出：frida 的 agent 线程不是守护线程，正常 return 会让
    # 解释器卡在退出阶段（表现为窗口关了但进程还在）。
    os._exit(exit_code)
