# TCP samples and explicitly consented temporary DNS ETW. No DNS queries, persistent log/audit, firewall, hosts or service changes.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Request,[Parameter(Mandatory=$true)][string]$Output)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'observe-core.ps1')
. (Join-Path $PSScriptRoot 'live-model.ps1')
. (Join-Path $PSScriptRoot 'live-evidence-model.ps1')
$j=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Request))
if($j.seconds -notin @(0,30,60,120,300) -or $j.capture_id -cnotmatch '^[a-f0-9]{32}$' -or $j.observation_mode -cne 'new_processes'){throw 'invalid_monitor_plan'}
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
function Read-AllProcessInstances {
 $rows=@()
 foreach($proc in @(Get-Process -ErrorAction Stop)){
  try{$path=[string]$proc.Path;$ticks=$proc.StartTime.ToUniversalTime().Ticks.ToString();if($path){$rows+=,[pscustomobject]@{pid=[long]$proc.Id;path=$path;ticks=$ticks}}else{$script:unreadable++}}catch{$script:unreadable++}
 };return ,$rows
}
. (Join-Path $PSScriptRoot 'baseline-model.ps1')
$script:autoPrograms=@{};$script:newProcesses=@{};$script:baselineTruncated=$false
# Enumerate first. The cutoff is taken after this setup: processes born before readiness are conservatively excluded.
$initial=@(Get-Process -ErrorAction Stop);$baselineCount=$initial.Count;$baselineUnreadable=0
foreach($proc in $initial){try{$null=$proc.StartTime.ToUniversalTime().Ticks}catch{$baselineUnreadable++}}
$script:baselineCutoff=[DateTime]::UtcNow.Ticks;$baselineUtc=(New-Object DateTime($script:baselineCutoff,[DateTimeKind]::Utc)).ToString('o')
$flows=@{};$queryErrors=0;$samples=0;$truncated=$false;$start=[DateTime]::UtcNow;$clock=[Diagnostics.Stopwatch]::StartNew()
$script:eventRows=New-Object Collections.Generic.List[object];$script:eventTruncated=$false;$script:hostsByName=@{}
function Event-Evidence {return @{schema='unified-event-evidence-1';events=@($script:eventRows.ToArray());streams=@{dns=@{status='not_collected'};wfp=@{status='not_collected'}};dns_trace=$script:dnsState;truncated=$script:eventTruncated;temporary_etw_session_requested=$j.dns_etw_requested;hosts_snapshot_available=$false;hosts_snapshot_truncated=$false;configuration_changed=$false}}
. (Join-Path $PSScriptRoot 'live-dns.ps1')
$inventory=[pscustomobject]@{schema='unified-monitor-inventory-1';available=$false;complete=$false;checked_utc=$null;rules=@();reason='unregistered_discovery_no_native_snapshot';configuration_changed=$false;packet_drop_verified=$false}
$revision=0;$publishErrors=0;$lastSample=$null;$lastOk=$false;$stopReason='duration';$script:ready=$false
function Frame([string]$Status){
 $script:revision++
 return [pscustomobject][ordered]@{schema='unified-new-process-monitor-1';observation_mode='new_processes';baseline_ready=$true;baseline_cutoff_ticks=$script:baselineCutoff.ToString();baseline_utc=$baselineUtc;baseline_existing_count=$baselineCount;baseline_unreadable_count=$baselineUnreadable;processes=@($script:newProcesses.Values);capture_id=[string]$j.capture_id;revision=$script:revision;status=$Status;ready=$script:ready;published_utc=[DateTime]::UtcNow.ToString('o');started_utc=$start.ToString('o');ended_utc=$(if($Status -ceq 'finished'){[DateTime]::UtcNow.ToString('o')}else{$null});last_sample_utc=$lastSample;last_sample_ok=$lastOk;programs=@($script:autoPrograms.Values);successful_samples=$samples;query_errors=$queryErrors;publication_errors=$publishErrors;unreadable_process_instances=$script:unreadable;truncated=($truncated -or $script:baselineTruncated);record_limit=5000;requested_seconds=[int]$j.seconds;stop_reason=$stopReason;endpoints=@($flows.Values);scope='sampled_TCP_sockets_exact_path_PID_birth_ticks';UDP_remote_destinations_collected=$false;DNS_events_collected=(@($script:eventRows|Where-Object{$_.kind -ceq 'dns_query'}).Count -gt 0);event_evidence=(Event-Evidence);block_inventory=$inventory;payload_collected=$false;firewall_changed=$false;hosts_changed=$false;packet_drop_verified=$false;binary_identity='observed_path_only_not_hash_verified_no_auto_registration'}
}
try{
Start-DnsTrace
$clock.Restart()
try{Write-LiveJson $j.live_path (Frame 'starting')}catch{$publishErrors++}
while([int]$j.seconds -eq 0 -or $clock.Elapsed.TotalSeconds -lt [int]$j.seconds){
 if(Test-Path -LiteralPath $j.stop_path){$stopReason='stop_requested';break}
 if(-not (Get-Process -Id ([int]$j.parent_pid) -ErrorAction SilentlyContinue)){$stopReason='parent_exited';break}
 $at=[DateTime]::UtcNow.ToString('o');$lastOk=$false
 try{
  $before=Read-AllProcessInstances;$before=Add-NewProcessSnapshot $before ([DateTime]::UtcNow.ToString('o')) $true
  $tcp=@(Get-NetTCPConnection -ErrorAction Stop|ForEach-Object{[pscustomobject]@{pid=[int]$_.OwningProcess;local_ip=[string]$_.LocalAddress;local_port=[int]$_.LocalPort;remote_ip=[string]$_.RemoteAddress;remote_port=[int]$_.RemotePort;state=[string]$_.State}})
  $after=Read-AllProcessInstances;$at=[DateTime]::UtcNow.ToString('o')
  $after=Add-NewProcessSnapshot $after $at $true
  if(Add-TcpFrame @($script:autoPrograms.Values) $before $after $tcp $flows $at 5000){$truncated=$true}
  $samples++;$lastOk=$true;$script:ready=$true
 }catch{$queryErrors++;$null=Add-NewProcessSnapshot @() $at $false}
 $lastSample=$at;Set-LivePresence $flows $at $lastOk
 Update-DnsTrace
 $inventory=[pscustomobject]@{schema='unified-monitor-inventory-1';available=$false;complete=$false;checked_utc=$null;rules=@();reason='unregistered_discovery_no_native_snapshot';configuration_changed=$false;packet_drop_verified=$false}
 Set-MonitorEvidence $flows $inventory (Event-Evidence)
 try{Write-LiveJson $j.live_path (Frame 'recording')}catch{$publishErrors++}
 Start-Sleep -Milliseconds 1000
}
}finally{Stop-DnsTrace}
$inventory=[pscustomobject]@{schema='unified-monitor-inventory-1';available=$false;complete=$false;checked_utc=$null;rules=@();reason='unregistered_discovery_no_native_snapshot';configuration_changed=$false;packet_drop_verified=$false}
Set-MonitorEvidence $flows $inventory (Event-Evidence)
$final=Frame 'finished'
# Final file publication failure is not reported as a successful capture.
Write-LiveJson $Output $final
try{Write-LiveJson $j.live_path $final}catch{}
