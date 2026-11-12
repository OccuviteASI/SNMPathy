@echo off
rem Update SNMPathy: pull the latest code, rebuild SNMPathy.exe and restart it.
rem Double-click, or run with options: update.cmd --force | --schedule | --unschedule | --no-restart
setlocal
cd /d "%~dp0.."
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 scripts\update.py %*
) else (
  python scripts\update.py %*
)
set rc=%errorlevel%
if "%~1"=="" pause & exit /b %rc%
if not "%rc%"=="0" pause
exit /b %rc%
