@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SSTP-Preflight.ps1" -VpnProfileName "holand"
echo.
pause
endlocal
