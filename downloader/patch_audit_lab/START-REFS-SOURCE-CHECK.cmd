@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 refs_source_check.py
) else (
  python refs_source_check.py
)
echo.
pause
