@echo off
rem ===========================================================================
rem  YH-SLSpoofer launcher
rem ---------------------------------------------------------------------------
rem  Starts SCP:SL through src\spawn_patch.py so the SMBIOS patch is installed
rem  before the anti-cheat reads machine identifiers.
rem
rem  Do NOT use the Steam "Play" button: that path launches the original
rem  executable directly and no patch is applied.
rem
rem  Optional environment variables:
rem    SL_PYTHONW       full path to pythonw.exe (default: first on PATH)
rem    SL_GAME_DIR      game install directory (default: config.json, then Steam registry)
rem ===========================================================================
setlocal

set "REPO=%~dp0.."
set "ENTRY=%REPO%\src\spawn_patch.py"

if not exist "%ENTRY%" (
  echo [x] entry script not found: %ENTRY%
  pause
  exit /b 1
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
