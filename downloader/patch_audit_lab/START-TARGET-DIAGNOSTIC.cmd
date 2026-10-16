@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 diagnose_target.py
) else (
  python diagnose_target.py
)
echo.
pause
