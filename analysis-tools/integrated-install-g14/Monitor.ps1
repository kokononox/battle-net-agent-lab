param([Parameter(Mandatory=$true)][string]$Config)
. (Join-Path $PSScriptRoot 'Common.ps1')
. (Join-Path $PSScriptRoot 'Inventory.ps1')
$c=Read-Context $Config;$null=[Reflection.Assembly]::LoadFrom($c.exe)
$r=[ordered]@{schema='bnet-inventory-monitor-g14-1';system_identity=([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18');status='stopped';service_change_count=0;task_change_count=0;foreign_job_member=$false;unclassified_process_count=0;error_code=$null}
try{
 Save-Private (Join-Path $c.root 'monitor-ready.json') @{system_identity=$r.system_identity}
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while($watch.Elapsed.TotalSeconds -lt 120){
  $delta=Get-InventoryDelta $c
  $r.service_change_count=@($delta.service_names).Count;$r.task_change_count=@($delta.task_keys).Count;$r.foreign_job_member=$delta.foreign_job_member;$r.unclassified_process_count=$delta.unclassified_process_count
  if($r.service_change_count -gt 0 -or $r.task_change_count -gt 0 -or $r.foreign_job_member -or $r.unclassified_process_count -gt 0){
   $r.status='unclassified_change_detected';Save-Private (Join-Path $c.root 'monitor-alert.json') $r
   & (Join-Path $c.root 'Recover.ps1') -Config $Config -Origin monitor
   throw 'unexpected_restore_after_inventory_alert'
  }
  if(-not (Test-Path (Join-Path $c.root 'monitor-baseline-checked.json'))){Save-Private (Join-Path $c.root 'monitor-baseline-checked.json') @{clean=$true}}
  Start-Sleep -Milliseconds 700
 }
 throw 'monitor_observation_timeout'
}catch{
 $message=$_.Exception.Message;$r.error_code=if($message -match '^[a-z_]{1,80}$'){$message}else{'inventory_monitor_operation_failed'}
 Save-Private (Join-Path $c.root 'monitor-result.json') $r
 # Failure to observe is not permission to restore or continue forwarding.
 if(-not (Test-Path (Join-Path $c.root 'recovery-result.json'))){try{& (Join-Path $c.root 'Recover.ps1') -Config $Config -Origin monitor}catch{}}
 $lease=Get-Content -Raw (Join-Path $c.root 'lease.json') | ConvertFrom-Json
 if($lease.phase -ne 'released'){Close-ProxyForQuarantine $c}
}
