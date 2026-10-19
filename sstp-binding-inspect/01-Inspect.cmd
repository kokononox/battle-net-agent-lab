@echo off
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Inspect-SstpBinding.ps1" -OutputPath "%~dp0SstpBindingReport.json"
exit /b %errorlevel%
