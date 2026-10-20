@echo off
setlocal
cd /d "%~dp0"
"%~dp0runtime\python.exe" -I "%~dp0app\launcher_destinations.py"
echo.
echo Observation stopped. Launcher and downloads were NOT paused.
pause
