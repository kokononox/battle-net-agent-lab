@echo off
setlocal
cd /d "%~dp0"
"%~dp0runtime\python.exe" -I "%~dp0app\passive_game.py"
echo.
echo Send ONLY the passive-network JSON, not raw captures.
pause
