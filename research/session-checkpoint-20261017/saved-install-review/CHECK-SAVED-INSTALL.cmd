@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 -B saved_install_launcher.py
) else (
  python -B saved_install_launcher.py
)
echo.
echo READ-ONLY RESEARCH. ZERO archive payload reads. NOT a game installer/updater.
pause