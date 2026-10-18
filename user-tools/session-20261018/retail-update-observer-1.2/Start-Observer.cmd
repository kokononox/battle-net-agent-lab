@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0RetailUpdateObserver.ps1"
if errorlevel 1 echo Observer stopped with an error. No update was started by this tool.
pause
