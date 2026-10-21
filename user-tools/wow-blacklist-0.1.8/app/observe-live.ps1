# Local progress only. No DNS, firewall mutations, or network requests.
. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $env:WOW_BL_APP 'ui-model.ps1'))))
$script:liveWrites=0;$script:liveWriteErrors=0;$script:liveKnown=@{}
foreach($key in @($j.history_baseline.keys)){$script:liveKnown[[string]$key]=$true}
function Test-LivePublic([string]$text){
 try{
  $a=[Net.IPAddress]::Parse($text)
  if($a.AddressFamily -eq 'InterNetwork'){
   foreach($net in @($j.public_exclusions_v4)){if(Ui-Contains ([pscustomobject]@{ip=[string]$net}) $text){return $false}}
  }elseif($a.AddressFamily -eq 'InterNetworkV6'){
   if(!(Ui-Contains ([pscustomobject]@{ip='2000::/3'}) $text)){return $false}
   foreach($net in @($j.public_exclusions_v6)){if(Ui-Contains ([pscustomobject]@{ip=[string]$net}) $text){return $false}}
  }else{return $false}
  return $true
 }catch{return $false}
}
function Live-HistoryStatus([string]$ip,[int]$port){
 $key=$ip.ToLowerInvariant()+'|'+[string]$port+'|TCP'
 if($script:liveKnown.ContainsKey($key)){return 'previously_seen'}
 if($j.history_baseline.complete -eq $true){return 'first_in_local_history'}
 return 'history_uncertain'
}
function Write-LiveSnapshot([bool]$finished=$false){
 if(!$j.live_path){return}
 $script:liveWrites++
 try{
  $history=@{complete=($j.history_baseline.complete -eq $true);files_total=$j.history_baseline.files_total;files_examined=$j.history_baseline.files_examined;invalid_files=$j.history_baseline.invalid_files;source_truncated=$j.history_baseline.source_truncated;max_files=$j.history_baseline.max_files;max_keys=$j.history_baseline.max_keys}
  $live=@{sampled_utc=$script:lastSampleUtc;phase_recording=$(if($j.phase_path){Stage-Recording}else{$null});schema='wow-live-observation-1';capture_id=$j.capture_id;revision=$script:liveWrites;finished=$finished;published_utc=[DateTime]::UtcNow.ToString('o');capture_started_utc=$start.ToString('o');seconds=[math]::Round($clock.Elapsed.TotalSeconds,1);query_errors=$errors;live_write_errors=$script:liveWriteErrors;truncated=$truncated;history_baseline=$history;stage_baseline=$j.stage_baseline;block_snapshot_start=$j.block_snapshot_start;event_evidence=$(if($j.event_evidence_enabled){Event-Evidence}else{$null});endpoints=@($flows.Values|Sort-Object {[int]$_.discovery_sequence})}
  $tmp=[string]$j.live_path+'.tmp';[IO.File]::WriteAllText($tmp,($live|ConvertTo-Json -Depth 10 -Compress),(New-Object Text.UTF8Encoding($false)))
  if([IO.File]::Exists($j.live_path)){[IO.File]::Replace($tmp,[string]$j.live_path,[NullString]::Value)}else{[IO.File]::Move($tmp,[string]$j.live_path)}
 }catch{$script:liveWriteErrors++}
}
