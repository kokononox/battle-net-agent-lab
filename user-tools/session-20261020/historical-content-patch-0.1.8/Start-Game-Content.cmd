@echo off
setlocal
cd /d "%~dp0"
"%~dp0runtime\python.exe" -I "%~dp0app\game_content.py"
echo.
echo Observation stopped. Game and downloads were NOT closed or paused.
pause
