@echo off
setlocal
cd /d "%~dp0"
echo SCOPED HTTPS coexistence test. Run as Administrator only after preflight acceptance.
"%~dp0runtime\python.exe" -I "%~dp0lab\https-console.py" --mode test
endlocal
