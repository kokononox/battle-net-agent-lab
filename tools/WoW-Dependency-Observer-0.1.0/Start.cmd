@echo off
setlocal
cd /d "%~dp0"
"%~dp0runtime\python.exe" -I "%~dp0app\observe.py"
echo.
echo Send ONLY output\dependency-result-....json. NEVER PML or XML.
pause
