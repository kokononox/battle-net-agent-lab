@echo off
cd /d "%~dp0"
echo Explicit Administrator required. This tool does NOT restore firewall rules.
"%~dp0runtime\python.exe" -I "%~dp0app\audit_ops.py"
