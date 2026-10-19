param([switch]$Elevated)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$report=Join-Path $PSScriptRoot 'system-audit-report.json'
$errpath=Join-Path $PSScriptRoot 'audit-error.json'
try{
 foreach($file in @('Audit.ps1','AuditReadCore.ps1','KnownHosts.ps1','Ranges.ps1','Inventory.ps1')){if(-not [IO.File]::Exists((Join-Path $PSScriptRoot $file))){throw 'audit_missing_files'}}
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=New-Object Security.Principal.WindowsPrincipal($identity)
 if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
  if($Elevated){throw 'audit_admin_required'}
  $child=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -WindowStyle Normal -Wait -PassThru -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-STA','-File',('"'+$PSCommandPath+'"'),'-Elevated')
  if(-not $child.HasExited -or $child.ExitCode -ne 0){throw 'audit_child_failed'}
  exit 0
 }
 if([IO.File]::Exists($report)){[IO.File]::Delete($report)}
 if([IO.File]::Exists($errpath)){[IO.File]::Delete($errpath)}
 . (Join-Path $PSScriptRoot 'Audit.ps1')
 $result=GetSystemAudit
 $json=ConvertTo-Json -InputObject $result -Depth 12
 if($json.Length -gt 60000){throw 'audit_report_size'}
 [IO.File]::WriteAllText($report,$json,(New-Object Text.UTF8Encoding($false)))
 [Console]::WriteLine('Audit saved: system-audit-report.json. No network settings changed by this tool.')
 exit 0
}catch{
 $code='audit_failed';if($_.Exception.Message -cmatch '^audit_[a-z_0-9]{1,80}$'){$code=$_.Exception.Message}
 $safe=[pscustomobject]@{schema='sstp-audit-error-1';code=$code;exception_type=$_.Exception.GetType().Name;line=[int]$_.InvocationInfo.ScriptLineNumber}
 try{[IO.File]::WriteAllText($errpath,($safe|ConvertTo-Json),(New-Object Text.UTF8Encoding($false)))}catch{}
 [Console]::Error.WriteLine($code);exit 1
}
