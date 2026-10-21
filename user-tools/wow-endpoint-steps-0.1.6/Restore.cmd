@echo off
setlocal
cd /d "%~dp0"
echo Run as administrator. Close the main tool console first.
"%~dp0runtime\python.exe" -I "%~dp0app\main.py" --restore
pause
