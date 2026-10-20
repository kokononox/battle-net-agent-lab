@echo off
setlocal
cd /d "%~dp0"
echo Extract this package onto a local NTFS NON-C, NON-SYSTEM drive.
echo Run this file as administrator. Leave WoW normally running at login.
"%~dp0runtime\python.exe" -I "%~dp0app\observe.py"
echo.
echo Send ONLY output\dependency-result-....json. NEVER capture.pml.
pause
