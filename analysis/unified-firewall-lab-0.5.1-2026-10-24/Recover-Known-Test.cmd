@echo off
setlocal
cd /d "%~dp0"
echo Explicit cleanup of ONE known DISABLED 0.5.0 test rule. NOT Apply or SELFTEST.
echo Run as Administrator. A precise confirmation is required inside the script.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0lab\recover-known.ps1"
echo.
pause
endlocal
