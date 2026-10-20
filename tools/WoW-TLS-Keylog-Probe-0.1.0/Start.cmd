@echo off
setlocal
cd /d "%~dp0"
set "CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" (
 echo Windows x64 and the built-in .NET Framework 4 compiler are required.
 echo Nothing launched. Do not change PowerShell execution policy.
 pause
 exit /b 1
)
"%CSC%" /nologo /target:winexe /platform:x64 /optimize+ /out:"%~dp0WowTlsKeylogProbe.exe" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:System.Security.dll /reference:System.Core.dll "%~dp0ProbeCore.cs" "%~dp0ProbeUI.cs"
if errorlevel 1 (
 echo Build failed. Nothing launched. Send the compiler error text only.
 pause
 exit /b 1
)
"%~dp0WowTlsKeylogProbe.exe"
endlocal
