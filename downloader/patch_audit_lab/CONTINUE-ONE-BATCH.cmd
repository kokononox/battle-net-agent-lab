@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 -B continue_review_launcher.py
) else (
  python -B continue_review_launcher.py
)
echo.
echo ONE bounded read-only batch only. No next batch is automatic.
echo This is NOT a game installer/updater.
pause
