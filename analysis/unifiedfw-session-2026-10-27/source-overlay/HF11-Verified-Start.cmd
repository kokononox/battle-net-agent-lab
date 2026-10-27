@echo off
setlocal
set "UFD_HF11_ROOT=%~dp0"
cd /d "%~dp0"
echo HF1.1 LAB - local test PC only. No automatic isolation Apply or Restore.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy RemoteSigned -Command "$ErrorActionPreference='Stop';try{$root=$env:UFD_HF11_ROOT;if($root.StartsWith('\\')){throw 'Use a local extracted folder'};$who=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run this CMD as administrator'};$manifest=Join-Path $root 'PAYLOAD-SHA256.json';if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ne 'e9fceb0d2e776c05b0a724bbff4d39f6749fd2751c259b49a1ea2b79bc074d58'){throw 'Payload manifest mismatch'};$items=Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json;foreach($p in $items.PSObject.Properties){$rel=[string]$p.Name;if([IO.Path]::IsPathRooted($rel) -or $rel.Split('/') -contains '..' -or $rel.Contains('\')){throw 'Invalid payload path'};$file=Join-Path $root $rel;if((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $p.Value){throw ('Payload mismatch: '+$rel)}};foreach($p in $items.PSObject.Properties){if($p.Name -like '*.ps1'){Unblock-File -LiteralPath (Join-Path $root $p.Name)}};Write-Host 'Payload verified. Only this package PS1 files were unblocked.';if($env:UFD_HF11_ACTION -ceq 'Check'){& (Join-Path $root 'runtime/python.exe') -I (Join-Path $root 'app/hf11_readiness.py')}elseif($env:UFD_HF11_ACTION -ceq 'Open'){& (Join-Path $root 'runtime/pythonw.exe') -I (Join-Path $root 'app/launch.py')}else{throw 'Unknown launcher action'};if($null -ne $LASTEXITCODE){exit $LASTEXITCODE}}catch{Write-Host ('ERROR: '+$_.Exception.Message);exit 1}"
set "rc=%errorlevel%"
if not "%rc%"=="0" echo Stopped or preflight not ready. Do not bypass security policy or retry Apply blindly.
pause
exit /b %rc%
