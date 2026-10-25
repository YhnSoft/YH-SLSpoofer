@echo off
rem ===========================================================================
rem  YH-SLSpoofer launcher
rem ---------------------------------------------------------------------------
rem  Starts SCP:SL through spawn_patch.py (same directory as this file) so the
rem  SMBIOS patch is installed before the anti-cheat reads machine identifiers.
rem
rem  Do NOT use the Steam "Play" button: that path launches the original
rem  executable directly and no patch is applied.
rem
rem  Layout: src\ holds code + config + this launcher. Logs go to ..\logs\.
rem
rem  Optional environment variables:
rem    SL_PYTHONW       full path to pythonw.exe (default: first on PATH)
rem    SL_GAME_DIR      game install directory (default: config.json, then Steam registry)
rem ===========================================================================
setlocal

rem %~dp0 已经以反斜杠结尾，指向本文件所在目录（src\）
set "ENTRY=%~dp0spawn_patch.py"
set "CONFIG=%~dp0config.json"

if not exist "%ENTRY%" (
  echo [x] entry script not found: %ENTRY%
  pause
  exit /b 1
)

if not exist "%CONFIG%" (
  echo [!] config.json not found, built-in defaults will be used.
  echo     Copy config.example.json to config.json to customize.
)

set "PYTHONW=%SL_PYTHONW%"
if not defined PYTHONW (
  for /f "delims=" %%I in ('where pythonw 2^>nul') do (
    if not defined PYTHONW set "PYTHONW=%%I"
  )
)

if not defined PYTHONW (
  echo [x] pythonw.exe not found.
  echo     Install Python 3.9+ and run: pip install frida
  echo     Or set SL_PYTHONW to the full path of pythonw.exe
  pause
  exit /b 1
)

echo [*] launching SCP:SL with SMBIOS patch...
echo     python : %PYTHONW%
echo     entry  : %ENTRY%
start "" "%PYTHONW%" "%ENTRY%"

exit /b 0
