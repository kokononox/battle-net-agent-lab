@echo off
setlocal
cd /d "%~dp0"
"%~dp0runtime\python.exe" -I "%~dp0app\target_monitor.py"
echo.
pause
endlocal
