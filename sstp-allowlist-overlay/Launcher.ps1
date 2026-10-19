param([ValidateSet('Window','Disable')][string]$Action='Window')
$ErrorActionPreference='Stop'
try{
 $script=Join-Path $PSScriptRoot 'Run.ps1'
 Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -WindowStyle Hidden -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$script+'"'),'-Action',$Action)|Out-Null
 exit 0
}catch{exit 1}
