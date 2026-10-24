# TCP samples and explicitly consented temporary DNS ETW. No DNS queries, persistent log/audit, firewall, hosts or service changes.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Request,[Parameter(Mandatory=$true)][string]$Output)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'observe-core.ps1')
. (Join-Path $PSScriptRoot 'live-model.ps1')
. (Join-Path $PSScriptRoot 'live-evidence-model.ps1')
$script:inventoryStamp=''
$script:lastInventory=[pscustomobject]@{schema='unified-monitor-inventory-1';available=$false;complete=$false;checked_utc=$null;rules=@();reason='readback_pending_or_unavailable';configuration_changed=$false;packet_drop_verified=$false}
function Read-MonitorSnapshot {
 try{
  if(-not [IO.File]::Exists($j.inventory_path)){return $script:lastInventory}
  $f=Get-Item -LiteralPath $j.inventory_path
  if($f.Length -gt 4194304){throw 'snapshot_too_large'}
  $stamp=[string]$f.LastWriteTimeUtc.Ticks+'|'+[string]$f.Length
  if($stamp -cne $script:inventoryStamp){
   $value=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($j.inventory_path))
   if($value.schema -cne 'unified-monitor-inventory-1' -or @($value.rules).Count -gt 256 -or $value.available -isnot [bool] -or $value.complete -isnot [bool]){throw 'snapshot_schema'}
   $script:lastInventory=$value;$script:inventoryStamp=$stamp
  }
 }catch{$script:lastInventory=[pscustomobject]@{schema='unified-monitor-inventory-1';available=$false;complete=$false;checked_utc=$null;rules=@();reason='snapshot_read_error';configuration_changed=$false;packet_drop_verified=$false}}
 return $script:lastInventory
}
$j=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Request))
if($j.seconds -notin @(0,30,60,120,300) -or @($j.programs).Count -lt 1 -or @($j.programs).Count -gt 32 -or $j.capture_id -cnotmatch '^[a-f0-9]{32}$'){throw 'invalid_monitor_plan'}
foreach($p in $j.programs){
 if($p.id -cnotmatch '^[a-f0-9]{24}$' -or [IO.Path]::GetExtension([string]$p.path) -ine '.exe' -or -not (Test-Path -LiteralPath $p.path -PathType Leaf)){throw 'program_invalid'}
 if((Get-FileHash -LiteralPath $p.path -Algorithm SHA256).Hash -ine $p.sha256){throw 'program_changed_reselect_required'}
}
function Write-LiveJson([string]$Path,$Value){
 $tmp=$Path+'.next-'+[guid]::NewGuid().ToString('N')
 try{
  $text=ConvertTo-Json -InputObject $Value -Depth 20
  if([Text.Encoding]::UTF8.GetByteCount($text) -gt 16777216){throw 'monitor_output_limit'}
  [IO.File]::WriteAllText($tmp,$text,(New-Object Text.UTF8Encoding($false)))
  if([IO.File]::Exists($Path)){[IO.File]::Replace($tmp,$Path,[NullString]::Value)}else{[IO.File]::Move($tmp,$Path)}
 }finally{if([IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
}
$script:unreadable=0
function Read-LiveProcesses($Programs){
 $paths=@{};foreach($p in $Programs){$paths[([string]$p.path).ToLowerInvariant()]=$true}
 $rows=@()
 foreach($proc in @(Get-Process -ErrorAction Stop)){
  try{
   $path=[string]$proc.Path
   if($path -and $paths.ContainsKey($path.ToLowerInvariant())){$rows+=,[pscustomobject]@{pid=[int]$proc.Id;path=$path;ticks=$proc.StartTime.ToUniversalTime().Ticks.ToString()}}
  }catch{$script:unreadable++}
 }
 return $rows
}
$flows=@{};$queryErrors=0;$samples=0;$truncated=$false;$start=[DateTime]::UtcNow;$clock=[Diagnostics.Stopwatch]::StartNew()
. (Join-Path $PSScriptRoot 'live-events.ps1')
. (Join-Path $PSScriptRoot 'live-dns.ps1')
$inventory=Read-MonitorSnapshot
$revision=0;$publishErrors=0;$lastSample=$null;$lastOk=$false;$stopReason='duration';$script:ready=$false
function Frame([string]$Status){
 $script:revision++
 return [pscustomobject][ordered]@{schema='unified-live-monitor-1';capture_id=[string]$j.capture_id;revision=$script:revision;status=$Status;ready=$script:ready;published_utc=[DateTime]::UtcNow.ToString('o');started_utc=$start.ToString('o');ended_utc=$(if($Status -ceq 'finished'){[DateTime]::UtcNow.ToString('o')}else{$null});last_sample_utc=$lastSample;last_sample_ok=$lastOk;programs=@($j.programs);successful_samples=$samples;query_errors=$queryErrors;publication_errors=$publishErrors;unreadable_process_instances=$script:unreadable;truncated=$truncated;record_limit=5000;requested_seconds=[int]$j.seconds;stop_reason=$stopReason;endpoints=@($flows.Values);scope='sampled_TCP_sockets_exact_path_PID_birth_ticks';UDP_remote_destinations_collected=$false;DNS_events_collected=(@($script:eventRows|Where-Object{$_.kind -ceq 'dns_query'}).Count -gt 0);event_evidence=(Event-Evidence);block_inventory=$inventory;payload_collected=$false;firewall_changed=$false;hosts_changed=$false;packet_drop_verified=$false;binary_identity='disk_hash_at_start_not_memory_image_verification'}
}
try{
Start-DnsTrace
try{Write-LiveJson $j.live_path (Frame 'starting')}catch{$publishErrors++}
while([int]$j.seconds -eq 0 -or $clock.Elapsed.TotalSeconds -lt [int]$j.seconds){
 if(Test-Path -LiteralPath $j.stop_path){$stopReason='stop_requested';break}
 if(-not (Get-Process -Id ([int]$j.parent_pid) -ErrorAction SilentlyContinue)){$stopReason='parent_exited';break}
 $at=[DateTime]::UtcNow.ToString('o');$lastOk=$false
 try{
  $before=@(Read-LiveProcesses $j.programs)
  $tcp=@(Get-NetTCPConnection -ErrorAction Stop|ForEach-Object{[pscustomobject]@{pid=[int]$_.OwningProcess;local_ip=[string]$_.LocalAddress;local_port=[int]$_.LocalPort;remote_ip=[string]$_.RemoteAddress;remote_port=[int]$_.RemotePort;state=[string]$_.State}})
  $after=@(Read-LiveProcesses $j.programs);$at=[DateTime]::UtcNow.ToString('o')
  if(Add-TcpFrame $j.programs $before $after $tcp $flows $at 5000){$truncated=$true}
  $samples++;$lastOk=$true;$script:ready=$true
 }catch{$queryErrors++}
 $lastSample=$at;Set-LivePresence $flows $at $lastOk
 Update-EventEvidence
 Update-DnsTrace
 $inventory=Read-MonitorSnapshot
 Set-MonitorEvidence $flows $inventory (Event-Evidence)
 try{Write-LiveJson $j.live_path (Frame 'recording')}catch{$publishErrors++}
 Start-Sleep -Milliseconds 1000
}
}finally{Stop-DnsTrace}
$inventory=Read-MonitorSnapshot
Update-EventEvidence $true
Set-MonitorEvidence $flows $inventory (Event-Evidence)
$final=Frame 'finished'
# Final file publication failure is not reported as a successful capture.
Write-LiveJson $Output $final
try{Write-LiveJson $j.live_path $final}catch{}
