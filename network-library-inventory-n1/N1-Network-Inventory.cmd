@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0runtime\python.exe" (
 echo Extract the addon INSIDE the original Level3-Request-Audit-T1.1 folder first.
 pause
 exit /b 1
)
"%~dp0runtime\python.exe" -I "%~dp0app\n1_inventory.py"
echo.
pause
endlocal
