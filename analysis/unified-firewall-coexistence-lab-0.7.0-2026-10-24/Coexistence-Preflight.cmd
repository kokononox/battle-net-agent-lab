@echo off
setlocal
cd /d "%~dp0"
echo READ-ONLY route and configuration preflight. No endpoint connections or firewall rules.
echo Run as Administrator. Keep VPN connected. Not global whitelist/kill-switch certification.
"%~dp0runtime\python.exe" -I "%~dp0lab\coexistence-console.py" --preflight
endlocal
