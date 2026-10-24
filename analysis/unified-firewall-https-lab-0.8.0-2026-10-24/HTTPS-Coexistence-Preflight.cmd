@echo off
setlocal
cd /d "%~dp0"
echo READ-ONLY SSTP route/config preflight. Run as Administrator.
"%~dp0runtime\python.exe" -I "%~dp0lab\https-console.py" --mode preflight
endlocal
