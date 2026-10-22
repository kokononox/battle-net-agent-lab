@echo off
setlocal
where py >nul 2>&1
if errorlevel 1 (
  python "%~dp0rebuild.py"
) else (
  py -3 "%~dp0rebuild.py"
)
if errorlevel 1 echo Rebuild failed. Do not use an unverified archive.
pause
