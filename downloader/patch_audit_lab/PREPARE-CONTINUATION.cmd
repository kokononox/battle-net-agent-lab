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
echo PREPARE ONLY: no archive payload reads. Keep the report for continuation.
echo This is NOT a game installer/updater.
pause
