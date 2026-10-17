@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 -B local_review_launcher.py
) else (
  python -B local_review_launcher.py
)
echo.
echo This is a read-only research review, NOT a game installer/updater.
pause
