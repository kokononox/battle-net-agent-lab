param([Parameter(Mandatory=$true)][ValidateSet('status','enable','restore')][string]$Action,[string]$Confirmation='', [Parameter(Mandatory=$true)][string]$Output)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lab/session-core.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lab/native.ps1')
. (Join-Path $PSScriptRoot 'audit-private.ps1')
. (Join-Path $PSScriptRoot 'audit-model.ps1')
try{
 UAdmin
 # Authority is the fixed child-process arguments, never the editable diagnostic job JSON.
 $q=[pscustomobject]@{action=$Action;confirmation=$Confirmation}
 if(-not ('UnifiedAudit096.Native' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'audit-native.cs')}
 [UnifiedAudit096.Native]::EnableSecurityPrivilege()
 $root=Get-AuditPrivateRoot ($q.action -ne 'status');$lock=$null
 try{
  if([IO.Directory]::Exists($root)){$lock=UOpenPrivateFile (Join-Path $root 'audit.lock') ([IO.FileMode]::OpenOrCreate)}
  $r=Invoke-AuditPolicy $root ([string]$q.action) ([string]$q.confirmation) { [int][UnifiedAudit096.Native]::Read() } {param([int]$Flags)[UnifiedAudit096.Native]::Write([uint32]$Flags)}
  try{$log=Get-WinEvent -ListLog Security -ErrorAction Stop;$r|Add-Member NoteProperty security_log_readable_enabled ([bool]$log.IsEnabled)}catch{$r|Add-Member NoteProperty security_log_readable_enabled $false}
  $answer=@{ok=$true;audit=$r}
 }finally{if($null -ne $lock){$lock.Dispose()}}
}catch{$answer=@{ok=$false;error=([string]$_.Exception.Message);audit_change_status='unknown_if_write_started; use audit status and protected receipt; no blind retry';firewall_changed=$false;hosts_changed=$false}}
[IO.File]::WriteAllText($Output,(ConvertTo-Json -InputObject $answer -Depth 10),(New-Object Text.UTF8Encoding($false)))
if(-not $answer.ok){exit 1}
