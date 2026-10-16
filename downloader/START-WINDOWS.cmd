@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
  py -3 -B "%~dp0windows_app.py"
  goto finished
)
where python >nul 2>nul
if not errorlevel 1 (
  python -B "%~dp0windows_app.py"
  goto finished
)
echo Python 3.9+ with Tcl/Tk is required. No automatic installation was attempted.
pause
exit /b 1
:finished
if errorlevel 1 pause
