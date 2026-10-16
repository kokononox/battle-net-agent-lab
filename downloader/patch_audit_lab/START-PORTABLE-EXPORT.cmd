@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 -B portable_export.py
) else (
  python -B portable_export.py
)
echo.
pause
