@echo off
setlocal
cd /d "%~dp0"
echo Run as administrator. Extract ZIP fully first.
echo Keep this console open. Use the browser Stop and Restore button before exit.
"%~dp0runtime\python.exe" -I "%~dp0app\main.py"
echo.
echo If restoration was not verified, run Restore.cmd as administrator.
pause
