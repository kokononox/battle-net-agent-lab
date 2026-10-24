@echo off
setlocal
cd /d "%~dp0"
echo REAL WINDOWS FIREWALL LAB - NOT PRODUCTION. Run explicitly as Administrator.
echo STATUS is read-only. APPLY LAB may disrupt connectivity. RESTORE uses protected journal.
"%~dp0runtime\python.exe" -I "%~dp0lab\console.py"
endlocal
