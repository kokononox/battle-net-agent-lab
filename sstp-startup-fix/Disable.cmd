@echo off
setlocal
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%~dp0Launcher.ps1" (
 echo Missing Launcher.ps1. Extract ALL files from the ZIP first.
 pause
 exit /b 1
)
"%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0Launcher.ps1" -Action Disable
if errorlevel 1 (
 echo.
 echo Startup failed. Send the code above or startup-error.json, NOT the firewall journal.
 pause
 exit /b 1
)

exit /b 0
