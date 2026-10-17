@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 -B install_download_coverage.py
) else (
  python -B install_download_coverage.py
)
echo.
echo READ-ONLY SAVED METADATA. NOT an installer or updater.
echo Do NOT delete Lab, change permissions or restart scans.
pause
