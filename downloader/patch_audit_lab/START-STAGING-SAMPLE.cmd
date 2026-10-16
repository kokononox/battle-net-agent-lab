@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 staging_sample.py
) else (
  python staging_sample.py
)
echo.
pause
