@echo off
setlocal
cd /d "%~dp0"
echo ONE HTTPS request; NO firewall/VPN changes. Administrator NOT required.
"%~dp0runtime\python.exe" -I "%~dp0lab\https-console.py" --mode check
endlocal
