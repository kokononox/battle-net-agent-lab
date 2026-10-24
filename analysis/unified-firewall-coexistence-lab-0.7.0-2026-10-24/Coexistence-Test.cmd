@echo off
setlocal
cd /d "%~dp0"
echo SCOPED coexistence traffic test. Requires a separate authorized SSTP-routed endpoint.
echo Run as Administrator. Keep VPN connected. Not global whitelist/kill-switch certification.
"%~dp0runtime\python.exe" -I "%~dp0lab\coexistence-console.py"
endlocal
