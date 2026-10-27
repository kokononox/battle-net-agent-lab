@echo off
setlocal
set "UFD_HF11_ACTION=Open"
call "%~dp0HF11-Verified-Start.cmd"
exit /b %errorlevel%
