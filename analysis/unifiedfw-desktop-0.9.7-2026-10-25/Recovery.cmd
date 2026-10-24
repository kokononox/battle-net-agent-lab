@echo off
cd /d "%~dp0"
echo Explicit Administrator access is required for STATUS / RESTORE.
echo No automatic operation is performed. Keep the old package and protected journal.
"%~dp0runtime\python.exe" -I "%~dp0app\recovery.py"
