@echo off
setlocal
set "UFD_HF11_ACTION=Check"
call "%~dp0HF11-Verified-Start.cmd"
exit /b %errorlevel%
