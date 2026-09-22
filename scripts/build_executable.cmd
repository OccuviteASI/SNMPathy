@echo off
rem Build SNMPathy.exe and store it in <Claude folder>\SNMPathy (double-click or run from a prompt).
rem Extra arguments are passed through, e.g.  build_executable.cmd --dest D:\Tools\SNMPathy
setlocal
cd /d "%~dp0.."
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 scripts\build_executable.py %*
) else (
  python scripts\build_executable.py %*
)
set rc=%errorlevel%
if "%~1"=="" pause
exit /b %rc%
