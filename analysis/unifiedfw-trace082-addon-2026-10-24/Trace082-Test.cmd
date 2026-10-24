@echo off
setlocal
cd /d "%~dp0"
echo Explicit Administrator launch required. Scoped lab only, not production protection.
"%~dp0runtime\python.exe" -I "%~dp0trace082\run.py" --mode test
endlocal
