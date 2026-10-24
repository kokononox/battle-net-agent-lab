@echo off
setlocal
cd /d "%~dp0"
echo Connectivity diagnostics ONLY. No firewall, VPN or route changes. No admin needed.
"%~dp0runtime\python.exe" -I "%~dp0diag\run.py"
endlocal
