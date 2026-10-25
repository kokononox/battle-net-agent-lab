@echo off
cd /d "%~dp0"
echo Run as Administrator. Status or explicit scoped isolation Restore; no automatic reset.
"%~dp0runtime\python.exe" -I "%~dp0app\isolation_recovery.py"
