@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 -B installed_profile_launcher.py
) else (
  python -B installed_profile_launcher.py
)
echo.
echo TWO-FILE METADATA ONLY. This is NOT a game installer/updater.
pause
