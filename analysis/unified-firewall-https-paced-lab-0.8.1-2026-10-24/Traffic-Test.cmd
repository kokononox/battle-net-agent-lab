@echo off
setlocal
cd /d "%~dp0"
echo Real IPv4 TCP traffic test with TEMPORARY executable-specific blocking rules.
echo Run as Administrator. Requires an authorized test server. Not a VPN/kill-switch test.
"%~dp0runtime\python.exe" -I "%~dp0lab\traffic.py"
endlocal
