# User-consented recovery of exact persisted DNS ETW sessions only, never other traces.
param([Parameter(Mandatory=$true)][string]$Request,[Parameter(Mandatory=$true)][string]$Output)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator_required_for_DNS_cleanup'}
Add-Type -Path (Join-Path $PSScriptRoot 'dns-trace.cs')
$j=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Request));if($j.owner -cnotmatch '^[a-f0-9]{32}$' -or @($j.receipts).Count -gt 200){throw 'cleanup_scope'}
$result=@()
foreach($r in @($j.receipts)){
 $status='invalid_receipt'
 try{
  if($r.owner -cne $j.owner -or $r.capture_id -cnotmatch '^[a-f0-9]{32}$' -or $r.session_name -cne ('UnifiedFW-DNS-'+$j.owner+'-'+$r.capture_id)){throw 'receipt_scope'}
  $active=$false;$unreadable=$false
  try{$p=Get-Process -Id ([int]$r.collector_pid) -ErrorAction Stop;try{$active=($p.StartTime.ToUniversalTime().Ticks.ToString() -ceq $r.collector_birth_ticks)}catch{$unreadable=$true}}catch{}
  if($active -or $unreadable){$status='active_or_unreadable_collector_skipped'}else{$code=[UnifiedDns.Collector]::Cleanup($r.session_name,$r.session_guid);$status=if($code -in @(0,4201)){'stopped_or_already_absent'}else{'cleanup_error_'+$code}}
 }catch{$status='invalid_receipt_or_GUID_mismatch'}
 $result+=,[pscustomobject]@{capture_id=$r.capture_id;status=$status}
}
[IO.File]::WriteAllText($Output,(ConvertTo-Json -InputObject @{sessions=$result;firewall_changed=$false;hosts_changed=$false;audit_or_channel_changed=$false} -Depth 6),(New-Object Text.UTF8Encoding($false)))
