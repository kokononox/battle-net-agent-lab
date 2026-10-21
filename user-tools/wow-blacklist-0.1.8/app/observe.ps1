$ErrorActionPreference='Stop';$stage='observe_setup'
try {
 $j=Get-Content -LiteralPath $env:WOW_BL_REQUEST -Raw -Encoding UTF8|ConvertFrom-Json
 if($j.seconds -notin @(0,60,120,300) -or [IO.Path]::GetFileName($j.program) -ine 'Wow.exe' -or !(Test-Path -LiteralPath $j.program -PathType Leaf)){throw 'invalid_observe_plan'}
 if((Get-FileHash -LiteralPath $j.program -Algorithm SHA256).Hash -ine $j.program_sha256){throw 'program_changed'}
 [void](Get-Command Get-NetTCPConnection -ErrorAction Stop)
 $flows=@{};$errors=0;$truncated=$false;$start=[DateTime]::UtcNow;$clock=[Diagnostics.Stopwatch]::StartNew()
 if($j.live_path){. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $env:WOW_BL_APP 'observe-live.ps1'))))}
 if($j.event_evidence_enabled){. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $env:WOW_BL_APP 'observe-events.ps1'))))}
 if($j.phase_path){. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $env:WOW_BL_APP 'observe-phase.ps1'))));Read-StageJournal}
 if($j.live_path){Write-LiveSnapshot}
 [IO.File]::WriteAllText($j.ready_path,'ready');$stage='observe_sample'
 while([int]$j.seconds -eq 0 -or $clock.Elapsed.TotalSeconds -lt [int]$j.seconds){
  if(Test-Path -LiteralPath $j.stop_path){break}
  if(!(Get-Process -Id $j.parent_pid -ErrorAction SilentlyContinue)){break}
  foreach($row in $flows.Values){$row.seen_in_latest_sample=$false;$row.latest_sample_states=@{}}
  $owned=@{}
  foreach($proc in @(Get-Process -Name Wow -ErrorAction SilentlyContinue)){
   try{if($proc.Path -ieq $j.program){$owned[[int]$proc.Id]=$proc.StartTime.ToUniversalTime().Ticks}}catch{$errors++}
  }
  if($owned.Count -gt 0){
   try{
    $tcpSample=@(Get-NetTCPConnection -ErrorAction Stop);$sampleUtc=[DateTime]::UtcNow
    if($j.phase_path){Read-StageJournal}
    foreach($c in $tcpSample){
     if(!$owned.ContainsKey([int]$c.OwningProcess)){continue}
     try{$live=Get-Process -Id $c.OwningProcess -ErrorAction Stop;if($live.Path -ine $j.program -or $live.StartTime.ToUniversalTime().Ticks -ne $owned[[int]$c.OwningProcess]){continue}}catch{continue}
     $ip=[string]$c.RemoteAddress;$port=[int]$c.RemotePort
     if($port -le 0 -or $ip -in @('0.0.0.0','::','::1','127.0.0.1')){continue}
     $parsedIP=$null;if(![Net.IPAddress]::TryParse($ip,[ref]$parsedIP)){continue};$ip=$parsedIP.ToString().ToLowerInvariant()
     if($j.live_path -and !(Test-LivePublic $ip)){continue}
     $born=$live.StartTime.ToUniversalTime();$now=$sampleUtc.ToString('o');$state=[string]$c.State
     if($state -notin @('Closed','Listen','SynSent','SynReceived','Established','FinWait1','FinWait2','CloseWait','Closing','LastAck','TimeWait','DeleteTCB')){$state='Unknown'}
     # Never merge old/new process evidence just because both saw the same IP:port.
     $key=[string]$c.OwningProcess+'/'+[string]$born.Ticks+'/'+$ip+'/'+[string]$port
     if(!$flows.ContainsKey($key)){
      if($flows.Count -ge 2000){$truncated=$true;continue}
      $flows[$key]=[ordered]@{record_id=[Guid]::NewGuid().ToString('N');discovery_sequence=($flows.Count+1);seen_in_latest_sample=$true;latest_sample_states=@{};destination_history=$(if($j.live_path){Live-HistoryStatus $ip $port}else{'history_uncertain'});ip=$ip;port=$port;pid=[int]$c.OwningProcess;process_started_utc=$born.ToString('o');samples=0;fresh_process_seen=($born -ge $start);state_samples=@{};phase_hits=@{};first_seen_utc=$now;last_seen_utc=$now}
     }
     $row=$flows[$key];if($j.phase_path){Add-PhaseSample $row $sampleUtc};$row.samples++;$row.last_seen_utc=$now;$row.seen_in_latest_sample=$true;$row.latest_sample_states[$state]=$true
     if(!$row.state_samples.ContainsKey($state)){$row.state_samples[$state]=0};$row.state_samples[$state]++
    }
   }catch{$errors++}
  }
  $script:lastSampleUtc=[DateTime]::UtcNow.ToString('o')
  if($j.phase_path){Read-StageJournal}
  if($j.event_evidence_enabled){Update-EventEvidence}
  if($j.live_path){Write-LiveSnapshot}
  Start-Sleep -Milliseconds 1000
 }
 if($j.phase_path){Read-StageJournal}
 if($j.event_evidence_enabled){Update-EventEvidence $true}
 if($j.live_path){Write-LiveSnapshot $true}
 @{ok=$true;phase_recording=$(if($j.phase_path){Stage-Recording}else{$null});event_evidence=$(if($j.event_evidence_enabled){Event-Evidence}else{$null});capture_started_utc=$start.ToString('o');capture_ended_utc=[DateTime]::UtcNow.ToString('o');seconds=[math]::Round($clock.Elapsed.TotalSeconds,1);query_errors=$errors;truncated=$truncated;endpoints=@($flows.Values|Sort-Object {[int]$_.discovery_sequence})}|ConvertTo-Json -Depth 12 -Compress
}catch{@{ok=$false;stage=$stage}|ConvertTo-Json -Compress;exit 3}
