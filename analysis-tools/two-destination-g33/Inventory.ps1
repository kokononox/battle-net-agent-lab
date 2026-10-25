. (Join-Path $PSScriptRoot 'TaskTrust.ps1')
# Global registration snapshot + observed named Job members, not a kernel process-creation barrier.
function Get-RegistrationSnapshot {
 $services=@{};$tasks=@{};$serviceCommands=@{};$taskImages=@{};$taskXml=@{};$serviceConfig=@{};$svcBinding=@{capture_complete=$false;error_code="pinned_task_missing"}
 foreach($s in @(Get-CimInstance Win32_Service)){
  $value=ConvertTo-Json -Compress -InputObject @([string]$s.PathName,[string]$s.StartMode,[string]$s.StartName)
  $serviceConfig[[string]$s.Name]=@{PathName=[string]$s.PathName;StartMode=[string]$s.StartMode;StartName=[string]$s.StartName}
  $serviceCommands[[string]$s.Name]=[string]$s.PathName
  $services[[string]$s.Name]=Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($value))
 }
 foreach($t in @(Get-ScheduledTask)){
  $key=[string]$t.TaskPath+[string]$t.TaskName
  $xml=[string](Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath)
  $taskImages[$key]=@($t.Actions | ForEach-Object {[string]$_.Execute})
  $taskXml[$key]=$xml;$keySha=(Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($key))).Replace('-','').ToLowerInvariant();if($keySha -eq '4023f1322db1c44e9afe47a715033f592132e209dd8511b71be83c290ae8c7a2'){$svcBinding=Get-SvcBinding $xml};$tasks[$key]=Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($xml))
 }
 return @{services=$services;tasks=$tasks;service_commands=$serviceCommands;task_images=$taskImages;task_xml=$taskXml;service_config=$serviceConfig;svc_binding=$svcBinding}
}
function Registration-Changes($Context){
 $before=Get-Content -Raw (Join-Path $Context.root 'registrations-before.json') | ConvertFrom-Json;$after=Get-RegistrationSnapshot;Save-Private (Join-Path $Context.root 'registrations-after.json') $after;$changed=0
 foreach($kind in @('services','tasks')){
  $prior=@{};foreach($entry in $before.$kind.PSObject.Properties){$prior[$entry.Name]=[string]$entry.Value}
  foreach($key in $after[$kind].Keys){if(-not $prior.ContainsKey($key) -or $prior[$key] -ne $after[$kind][$key]){$changed++}}
  foreach($key in $prior.Keys){if(-not $after[$kind].ContainsKey($key)){$changed++}}
 };Save-Private (Join-Path $Context.root 'focus-classification-current.json') (Get-FocusTasks $Context 'classification_current' 0 -Deep)
 $class=Invoke-TaskClassifier $Context
 if([int]$class.raw_changes -ne $changed -or [int]$class.classified_reschedules -gt 3 -or [int]$class.classified_two_time_reschedules -gt 2 -or ([int]$class.classified_reschedules-[int]$class.classified_two_time_reschedules) -gt 1 -or [int]$class.blocked_changes -lt 0){throw 'classifier_count_mismatch'}
 $allowed=@($class.details | Where-Object {$_.allowed -eq $true})
 $pins=@('4023f1322db1c44e9afe47a715033f592132e209dd8511b71be83c290ae8c7a2','6137a887b08bde613f10c2469a266d09ae1a4771d17512f64acba2c4d4d1e883','2b11947a6c63d26c27256985033a4d1d7e97e56883cf36ed29a8beb6f79a4559')
 if($allowed.Count -ne [int]$class.classified_reschedules -or @($allowed | Where-Object {$_.kind -ne 'tasks' -or $_.identity_sha256 -notin $pins}).Count -gt 0 -or @($allowed | Select-Object -ExpandProperty identity_sha256 -Unique).Count -ne $allowed.Count){throw 'classifier_allowed_identity_mismatch'}
 return [int]$class.blocked_changes
}
# Local read-only BITS COM enumeration through the built-in module; never cancel/suspend/alter jobs.
function Get-BitsSnapshot {
 try {
  Import-Module BitsTransfer -ErrorAction Stop
  $found=@(Get-BitsTransfer -AllUsers -ErrorAction Stop)
  if($found.Count -gt 512){throw 'bits_job_bound'}
  $jobs=@{}
  foreach($j in $found){
   $id=[string]$j.JobId;$files=@($j.FileList | ForEach-Object {[ordered]@{remote=[string]$_.RemoteName;local=[string]$_.LocalName}} | Sort-Object remote,local)
   if($id -notmatch '^[0-9a-fA-F-]{36}$' -or $files.Count -gt 64 -or [string]::IsNullOrEmpty([string]$j.TransferType) -or -not $j.CreationTime){throw 'bits_record_incomplete'}
   $core=[ordered]@{id=$id;owner=[string]$j.OwnerAccount;transfer_type=[string]$j.TransferType;created=$j.CreationTime.ToUniversalTime().ToString('o');files=$files}
   $encoded=ConvertTo-Json -Depth 8 -Compress -InputObject $core
   $jobs[$id]=@{definition=$core;definition_hash=(Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($encoded)));state=[string]$j.JobState;bytes_transferred=[long]$j.BytesTransferred}
  }
  return @{complete=$true;jobs=$jobs;captured_utc=[DateTime]::UtcNow.ToString('o')}
 }catch{throw 'bits_inventory_failed'}
}
function Compare-Bits($Before,$After){
 $a=@{};foreach($p in $Before.jobs.PSObject.Properties){$a[$p.Name]=[string]$p.Value.definition_hash}
 $b=@{};if($After.jobs -is [Collections.IDictionary]){foreach($k in $After.jobs.Keys){$b[$k]=[string]$After.jobs[$k].definition_hash}}else{foreach($p in $After.jobs.PSObject.Properties){$b[$p.Name]=[string]$p.Value.definition_hash}}
 $added=0;$modified=0;$removed=0
 foreach($k in $b.Keys){if(-not $a.ContainsKey($k)){$added++}elseif($a[$k] -ne $b[$k]){$modified++}}
 foreach($k in $a.Keys){if(-not $b.ContainsKey($k)){$removed++}}
 return @{added=$added;modified=$modified;removed=$removed}
}

function Invoke-TaskClassifier($Context){
 $lines=& $Context.python -I (Join-Path $Context.root 'Classify.py') $Context.root 2> (Join-Path $Context.root 'classifier-stderr.private.txt')
 if($LASTEXITCODE -ne 0){throw 'task_classifier_failed'}
 $joined=$lines -join "`n";if($joined.Length -gt 65536){throw 'classifier_output_bound'}
 $result=$joined | ConvertFrom-Json
 if($result.schema -ne 'narrow_task_g33_v1'){throw 'classifier_schema_refused'}
 return $result
}
