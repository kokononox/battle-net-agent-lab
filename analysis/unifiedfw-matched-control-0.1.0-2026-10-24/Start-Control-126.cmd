@echo off
setlocal
cd /d "%~dp0"
echo Network control ONLY. No firewall, VPN or route changes. No admin required.
"%~dp0runtime\python.exe" -I "%~dp0control126\run.py"
endlocal
