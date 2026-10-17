@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 -B prepare_review_launcher.py
) else (
  python -B prepare_review_launcher.py
)
echo.
echo This is a read-only research review, NOT a game installer/updater.
echo Default entry prepares metadata only. No archive payload batch is started.
pause
