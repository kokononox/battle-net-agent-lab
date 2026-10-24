# Read-only TCP sampling. Does not enable logs, ETW, DNS, firewall or services.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Request,[Parameter(Mandatory=$true)][string]$Output)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'observe-core.ps1')
$j=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Request))
if($j.seconds -lt 1 -or $j.seconds -gt 120 -or @($j.programs).Count -lt 1 -or @($j.programs).Count -gt 32){throw 'invalid_observation_plan'}
foreach($p in $j.programs){
 if($p.id -cnotmatch '^[a-f0-9]{24}$' -or [IO.Path]::GetExtension([string]$p.path) -ine '.exe' -or -not (Test-Path -LiteralPath $p.path -PathType Leaf)){throw 'program_invalid'}
 if((Get-FileHash -LiteralPath $p.path -Algorithm SHA256).Hash -ine $p.sha256){throw 'program_changed_reselect_required'}
}
$script:unreadable=0
function Read-SelectedProcesses($Programs){
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
$flows=@{};$queryErrors=0;$samples=0;$truncated=$false;$start=[DateTime]::UtcNow;$clock=[Diagnostics.Stopwatch]::StartNew();$stopRequested=$false
while($clock.Elapsed.TotalSeconds -lt [int]$j.seconds){
 if(Test-Path -LiteralPath $j.stop_path){$stopRequested=$true;break}
 if(-not (Get-Process -Id ([int]$j.parent_pid) -ErrorAction SilentlyContinue)){break}
 try{
  $before=@(Read-SelectedProcesses $j.programs)
  $tcp=@(Get-NetTCPConnection -ErrorAction Stop|ForEach-Object{[pscustomobject]@{pid=[int]$_.OwningProcess;local_ip=[string]$_.LocalAddress;local_port=[int]$_.LocalPort;remote_ip=[string]$_.RemoteAddress;remote_port=[int]$_.RemotePort;state=[string]$_.State}})
  $after=@(Read-SelectedProcesses $j.programs)
  $at=[DateTime]::UtcNow.ToString('o')
  if(Add-TcpFrame $j.programs $before $after $tcp $flows $at){$truncated=$true}
  $samples++
 }catch{$queryErrors++}
 Start-Sleep -Milliseconds 1000
}
$r=[pscustomobject]@{schema='unified-multiprogram-observation-1';started_utc=$start.ToString('o');ended_utc=[DateTime]::UtcNow.ToString('o');programs=@($j.programs);successful_samples=$samples;query_errors=$queryErrors;unreadable_process_instances=$script:unreadable;truncated=$truncated;stop_requested=$stopRequested;endpoints=@($flows.Values);scope='sampled_TCP_socket_state_multiple_exact_executable_paths';UDP_remote_destinations_collected=$false;DNS_events_collected=$false;payload_collected=$false;firewall_changed=$false;packet_drop_verified=$false;binary_identity='selected_path_and_disk_hash_at_start; not_memory_image_verification'}
[IO.File]::WriteAllText($Output,(ConvertTo-Json -InputObject $r -Depth 16),(New-Object Text.UTF8Encoding($false)))
