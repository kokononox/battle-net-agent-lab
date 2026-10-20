@echo off
setlocal
cd /d "%~dp0"
set "CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" (
 echo Built-in x64 .NET Framework compiler missing. Nothing launched.
 pause
 exit /b 1
)
"%CSC%" /nologo /platform:x64 /target:exe /optimize+ /out:"%~dp0ControlFixture.exe" /reference:System.Core.dll "%~dp0Shared.cs" "%~dp0Fixture.cs"
if errorlevel 1 goto :failed
"%CSC%" /nologo /platform:x64 /target:winexe /optimize+ /out:"%~dp0CdbControlOnly.exe" /reference:System.Core.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:System.Security.dll "%~dp0Shared.cs" "%~dp0Runner.cs"
if errorlevel 1 goto :failed
"%~dp0CdbControlOnly.exe"
exit /b
:failed
echo Build failed. Send compiler text only. Do not disable protection.
pause
exit /b 1
