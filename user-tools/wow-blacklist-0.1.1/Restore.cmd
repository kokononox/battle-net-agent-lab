@echo off
setlocal
cd /d "%~dp0"
start "" "%~dp0runtime\pythonw.exe" -I "%~dp0app\main.py" --restore
exit /b
