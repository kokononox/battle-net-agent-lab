@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0runtime\python.exe" (
 echo Extract this ADD-ON inside the existing tested Unified-Firewall-0.8.1 folder.
 echo This launcher must be beside runtime, lab and HTTPS-Coexistence-Test.cmd.
 pause
 exit /b 1
)
echo Same EXE paths, connectivity diagnostics ONLY. No firewall/VPN/route changes. No admin required.
"%~dp0runtime\python.exe" -I "%~dp0diagnostic081\run.py"
endlocal
