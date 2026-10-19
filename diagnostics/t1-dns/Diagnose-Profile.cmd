@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0runtime\python.exe" (
 echo Extract these files INSIDE the existing Level3-Request-Audit-T1 folder first.
 pause
 exit /b 1
)
"%~dp0runtime\python.exe" -I "%~dp0app\diagnose_profile.py"
echo.
pause
endlocal
