@echo off
setlocal
cd /d "%~dp0"
set "CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" (
 echo Built-in x64 .NET Framework compiler not found. Nothing launched.
 pause
 exit /b 1
)
"%CSC%" /nologo /target:winexe /platform:x64 /optimize+ /out:"%~dp0WowCryptoApiProbe.exe" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:System.Security.dll /reference:System.Core.dll "%~dp0Core.cs" "%~dp0UI.cs" "%~dp0Binding.cs"
if errorlevel 1 (
 echo Build failed. Send compiler error text only. Do not disable security controls.
 pause
 exit /b 1
)
"%CSC%" /nologo /target:exe /platform:x64 /optimize+ /out:"%~dp0ProbeControl.exe" "%~dp0Control.cs"
if errorlevel 1 (
 echo Control build failed. No debugging session started.
 pause
 exit /b 1
)
"%~dp0WowCryptoApiProbe.exe"
endlocal
