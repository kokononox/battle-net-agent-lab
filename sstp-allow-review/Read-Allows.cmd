@echo off
setlocal
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%~dp0Read-Allows.ps1" (
 echo Extract ALL files from the ZIP first.
 pause
 exit /b 1
)
"%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0Read-Allows.ps1"
if errorlevel 1 (
 echo Send allow-review-error.json from THIS folder, not any private journal.
 pause
 exit /b 1
)
echo Review and send outbound-allow-report.json from THIS folder.
echo No Enable, reset, rule removal, hosts change or VPN connection was performed.
pause
exit /b 0
