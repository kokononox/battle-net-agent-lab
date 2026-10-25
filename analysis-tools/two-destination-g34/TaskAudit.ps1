# Read local operational log. A separate scoped diagnostic probe may temporarily enable this channel; no Windows audit policy or task changes.
function Start-TaskAudit {
 $r=@{schema='task_audit_baseline_v1';started_utc=[DateTime]::UtcNow.ToString('o');operational_log_enabled=$false;read_complete=$false;last_record_id=$null}
 try{$log=Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction Stop;$r.operational_log_enabled=[bool]$log.IsEnabled
  if($r.operational_log_enabled -and $log.RecordCount -gt 0){$r.last_record_id=[long](Get-WinEvent -LogName $log.LogName -MaxEvents 1 -ErrorAction Stop).RecordId};$r.read_complete=$true
 }catch{$r.error_code='existing_log_baseline_unavailable'}
 return $r
}
function Finish-TaskAudit($Context){
 $r=@{schema='task_mutation_audit_v1';scope='existing_local_operational_log_read_only';logging_enabled_by_experiment=$false;audit_policy_changed=$false;mutation_actor_proven=$false;log_continuity_proven=$false;capture_complete=$false;events=@();matching_events_omitted=0;provider_pid_not_used_as_mutation_actor=$true}
 try{
  $b=Get-Content -Raw (Join-Path $Context.root 'task-audit-baseline.json') | ConvertFrom-Json
  $probePath=Join-Path $Context.root 'log-probe.json';if(Test-Path $probePath){$probe=Get-Content -Raw $probePath | ConvertFrom-Json;$r.logging_enabled_by_experiment=[bool]$probe.changed}
  $r.operational_log_enabled=$b.operational_log_enabled;$r.baseline_read_complete=$b.read_complete
  if(-not $b.read_complete){$r.status='baseline_unavailable';return $r}
  if(-not $b.operational_log_enabled){$r.status='existing_log_disabled';return $r}
  $log=Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction Stop
  if(-not $log.IsEnabled){$r.status='log_disabled_during_observation';return $r}
  $rows=@();try{$rows=@(Get-WinEvent -FilterHashtable @{LogName=$log.LogName;StartTime=[DateTime]$b.started_utc;Id=@(106,140,141,142,100,102,107,129,200,201,110)} -MaxEvents 2001 -ErrorAction Stop)}catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}
  $r.query_bound_hit=($rows.Count -ge 2001);$r.events_examined=$rows.Count
  foreach($e in $rows){
   $doc=[xml]$e.ToXml();$data=@{};foreach($v in @($doc.Event.EventData.Data)){$data[[string]$v.Name]=[string]$v.'#text'}
   $name=$data['TaskName'];if(-not $name){continue};$id=Focus-Hash $name;if(-not $script:FocusIds.ContainsKey($id)){continue}
   if($r.events.Count -ge 64){$r.matching_events_omitted++;continue}
   $user=[string]$data['UserContext'];$cat=switch($user){'S-1-5-18'{'local_system'};'S-1-5-19'{'local_service'};'S-1-5-20'{'network_service'};''{'not_present'};default{'other_context'}}
   $item=@{identifier=$script:FocusIds[$id];identity_sha256=$id;event_id=[int]$e.Id;record_id=[long]$e.RecordId;captured_event_utc=$e.TimeCreated.ToUniversalTime().ToString('o');event_user_context=$cat;client_pid_field_present=$false;client_process_resolved_at_collection=$false;client_identity_at_mutation_proven=$false}
   # ONLY a field explicitly named ClientProcessId is considered; provider Execution PID is not the caller.
   $pidText=[string]$data['ClientProcessId'];$clientId=0
   if([int]::TryParse($pidText,[ref]$clientId) -and $clientId -gt 0){
    $item.client_pid_field_present=$true
    try{$process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$clientId) -ErrorAction Stop
     if($process -and $process.ExecutablePath){$image=[string]$process.ExecutablePath;$item.client_process_resolved_at_collection=$true
      $item.client_image_category=if($image.StartsWith(($env:SystemRoot+'\System32\'),[StringComparison]::OrdinalIgnoreCase)){'system32'}else{'other_image'}
      if($item.client_image_category -eq 'system32'){$file=Get-Item -LiteralPath $image;if($file.Length -le 33554432 -and ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0){$item.client_image_sha256=(Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant()}}
     }
    }catch{$item.client_resolution_error='process_not_resolved'}
   }
   $r.events+=@($item)
  }
  $r.capture_complete=(-not $r.query_bound_hit -and $r.matching_events_omitted -eq 0);$r.status=if($r.capture_complete){'existing_log_read'}else{'bounded_partial_read'}
 }catch{$r.status='existing_log_query_failed';$r.error_code='existing_task_event_read_failed'}
 return $r
}
