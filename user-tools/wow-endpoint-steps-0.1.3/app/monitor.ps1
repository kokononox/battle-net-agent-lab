# Read-only sampled TCP metadata + existing Security block events. Never enables auditing.
$ErrorActionPreference='Stop'
$jpath=$env:WOW_STEPS_MONITOR_JOURNAL
$stem=[IO.Path]::Combine([IO.Path]::GetDirectoryName($jpath),[IO.Path]::GetFileNameWithoutExtension($jpath))
$start=[DateTime]::UtcNow;$end=$start
$result=[ordered]@{schema='wow-endpoint-monitor-1';status='starting';tcp_query_errors=0;process_query_errors=0;owned_process_instances_seen=0;tcp_endpoints=@();target_tcp_states=@();target_established_in_new_process_seen=$false;matching_wfp_block_events=0;wfp_query_status='not_attempted';wfp_events_read=0;wfp_query_at_limit=$false;audit_settings_changed=$false;rule_causality_proven=$false;payload_read=$false}
function WriteResult {
 $result.elapsed_seconds=[math]::Round(($end-$start).TotalSeconds,1)
 $temp=$stem+'.monitor-result.tmp'
 [IO.File]::WriteAllText($temp,($result | ConvertTo-Json -Depth 10),(New-Object Text.UTF8Encoding($false)))
 Move-Item -LiteralPath $temp -Destination ($stem+'.monitor-result') -Force
}
try {
 $j=Get-Content -LiteralPath $jpath -Raw -Encoding UTF8 | ConvertFrom-Json
 if($j.id -notmatch '^[a-f0-9]{32}$' -or $j.name -cne ('WoWEndpointSteps-'+$j.id)){throw 'invalid_owner'}
 if($j.protocol -ne 'TCP'){throw 'tcp_only'}
 [void](Get-Command Get-NetTCPConnection -ErrorAction Stop)
 $seen=@{};$flows=@{};$targetStates=@{}
 [IO.File]::WriteAllText(($stem+'.monitor-ready'),'ready')
 $clock=[Diagnostics.Stopwatch]::StartNew()
 while($clock.Elapsed.TotalSeconds -lt 90){
  if(Test-Path -LiteralPath ($stem+'.monitor-stop')){break}
  if(!(Get-Process -Id $j.parent_pid -ErrorAction SilentlyContinue)){break}
  $now=[DateTime]::UtcNow;$owned=@{}
  foreach($proc in @(Get-Process -Name Wow -ErrorAction SilentlyContinue)){
   try {
    if($proc.Path -ine $j.program){continue}
    $born=$proc.StartTime.ToUniversalTime();$key=([string]$proc.Id)+'/'+$born.Ticks
    $owned[[int]$proc.Id]=$key
    if(!$seen.ContainsKey($key)){$seen[$key]=@{pid=[int]$proc.Id;born=$born;last=$now}}
    $seen[$key].last=$now
   }catch{$result.process_query_errors++}
  }
  if($owned.Count -gt 0){
   try {
    $connections=@(Get-NetTCPConnection -ErrorAction Stop)
    $observedAt=[DateTime]::UtcNow
    foreach($c in $connections){
     if(!$owned.ContainsKey([int]$c.OwningProcess)){continue}
     # Re-check PID identity after the TCP query; reject reuse or a changed executable.
     try {
      $live=Get-Process -Id $c.OwningProcess -ErrorAction Stop
      $liveKey=([string]$live.Id)+'/'+$live.StartTime.ToUniversalTime().Ticks
      if($live.Path -ine $j.program -or $liveKey -ne $owned[[int]$c.OwningProcess]){continue}
     }catch{continue}
     if(Test-Path -LiteralPath ($stem+'.monitor-stop')){break}
     $ip=[string]$c.RemoteAddress;$port=[int]$c.RemotePort;$state=[string]$c.State
     if($port -le 0 -or $ip -in @('0.0.0.0','::','::1','127.0.0.1')){continue}
     $key=$ip+'/'+$port+'/'+$state
     if(!$flows.ContainsKey($key) -and $flows.Count -lt 500){$flows[$key]=[ordered]@{ip=$ip;port=$port;state=$state;samples=0;new_process_seen=$false}}
     if($flows.ContainsKey($key)){$flows[$key].samples++;if($live.StartTime.ToUniversalTime() -ge $start){$flows[$key].new_process_seen=$true}}
     if($ip -eq $j.ip -and $port -eq [int]$j.port){$targetStates[$state]=$true;if($state -eq 'Established' -and $live.StartTime.ToUniversalTime() -ge $start){$result.target_established_in_new_process_seen=$true}}
    }
   }catch{$result.tcp_query_errors++}
  }
  Start-Sleep -Milliseconds 1000
 }
 $end=[DateTime]::UtcNow
 if(Test-Path -LiteralPath ($stem+'.monitor-stop')){
  try{$stop=Get-Content -LiteralPath ($stem+'.monitor-stop') -Raw | ConvertFrom-Json;$stopAt=[DateTimeOffset]::FromUnixTimeMilliseconds([long]$stop.epoch_ms).UtcDateTime;if($stopAt -lt $end){$end=$stopAt}}catch{}
 }
 $result.owned_process_instances_seen=$seen.Count
 $result.tcp_endpoints=@($flows.Values)
 $result.target_tcp_states=@($targetStates.Keys)
 # Security events are queried only if already present. No auditpol/Set-* command is used.
 try {
  $queryErrors=@()
  $events=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=@(5152,5157);StartTime=$start.ToLocalTime();EndTime=$end.ToLocalTime()} -MaxEvents 2000 -ErrorAction SilentlyContinue -ErrorVariable queryErrors)
  $bad=@($queryErrors | Where-Object {$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'})
  if($bad.Count -gt 0){$result.wfp_query_status='unavailable'}else{$result.wfp_query_status='queried';$result.wfp_events_read=$events.Count;$result.wfp_query_at_limit=($events.Count -eq 2000)}
  if($result.wfp_query_status -eq 'queried'){
   foreach($event in $events){
    try {
     [xml]$xml=$event.ToXml();$fields=@{}
     foreach($data in $xml.Event.EventData.Data){$fields[[string]$data.Name]=[string]$data.InnerText}
     if($fields.DestAddress -ne $j.ip -or $fields.DestPort -ne [string]$j.port -or $fields.Protocol -ne '6' -or $fields.Direction -ne '%%14593'){continue}
     $pidText=[string]$fields.ProcessID
     $eventPid=if($pidText.StartsWith('0x')){[Convert]::ToInt32($pidText.Substring(2),16)}else{[int]$pidText}
     $at=$event.TimeCreated.ToUniversalTime();$matched=$false
     foreach($life in $seen.Values){if($life.pid -eq $eventPid -and $at -ge $life.born -and $at -le $life.last -and $at -ge $start -and $at -le $end){$matched=$true;break}}
     if($matched){$result.matching_wfp_block_events++}
    }catch{}
   }
  }
 }catch{$result.wfp_query_status='unavailable'}
 $result.status='sample_finished'
 WriteResult
}catch{
 $end=[DateTime]::UtcNow;$result.status='monitor_inconclusive';WriteResult
}
