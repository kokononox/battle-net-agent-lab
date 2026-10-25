# Global registration snapshot + observed named Job members, not a kernel process-creation barrier.
function Get-RegistrationSnapshot {
 $services=@{};$tasks=@{};$serviceCommands=@{};$taskImages=@{}
 foreach($s in @(Get-CimInstance Win32_Service)){
  $value=ConvertTo-Json -Compress -InputObject @([string]$s.PathName,[string]$s.StartMode,[string]$s.StartName)
  $serviceCommands[[string]$s.Name]=[string]$s.PathName
  $services[[string]$s.Name]=Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($value))
 }
 foreach($t in @(Get-ScheduledTask)){
  $key=[string]$t.TaskPath+[string]$t.TaskName
  $xml=[string](Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath)
  $taskImages[$key]=@($t.Actions | ForEach-Object {[string]$_.Execute})
  $tasks[$key]=Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($xml))
 }
 return @{services=$services;tasks=$tasks;service_commands=$serviceCommands;task_images=$taskImages}
}
function Get-InventoryDelta($Context){
 $base=Get-Content -Raw (Join-Path $Context.root 'registration-baseline.json') | ConvertFrom-Json
 $now=Get-RegistrationSnapshot;$serviceChanged=New-Object 'Collections.Generic.List[string]';$taskChanged=New-Object 'Collections.Generic.List[string]'
 foreach($kind in @('services','tasks')){
  $prior=@{};foreach($entry in $base.$kind.PSObject.Properties){$prior[$entry.Name]=[string]$entry.Value}
  $changes=$serviceChanged;if($kind -eq 'tasks'){$changes=$taskChanged}
  foreach($key in $now[$kind].Keys){if(-not $prior.ContainsKey($key) -or $prior[$key] -ne $now[$kind][$key]){$changes.Add([string]$key)}}
  foreach($key in $prior.Keys){if(-not $now[$kind].ContainsKey($key)){$changes.Add([string]$key)}}
 }
 $images=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 $observedPath=Join-Path $Context.root 'unclassified-images.json'
 if(Test-Path $observedPath){foreach($image in @((Get-Content -Raw $observedPath | ConvertFrom-Json).images)){$null=$images.Add([string]$image)}}
 foreach($name in $serviceChanged){
  if($now.service_commands.ContainsKey($name)){
   $command=[string]$now.service_commands[$name]
   if($command -match '^"([^"\r\n]+)"(?:\s|$)'){$null=$images.Add($Matches[1])}elseif($command -match '^([^\s"]+)(?:\s|$)'){$null=$images.Add($Matches[1])}else{throw 'inventory_service_image_unresolved'}
  }
 }
 foreach($key in $taskChanged){if($now.task_images.ContainsKey($key)){foreach($image in $now.task_images[$key]){if($image){$null=$images.Add([string]$image)}}}}
 $job=[ExternalProbe]::OpenOwnedJob($Context.job_name);$foreign=$false
 try{
  if($job -eq [IntPtr]::Zero){throw 'inventory_job_missing'}
  foreach($member in [ExternalProbe]::InspectJobMembers($job,$Context.exe)){if($member.kind -eq 'unknown'){$foreign=$true;$null=$images.Add($member.image)}}
 }finally{if($job -ne [IntPtr]::Zero){[ExternalProbe]::CloseOwnedJob($job)}}
 if($images.Count -gt 64){throw 'inventory_image_limit'}
 foreach($image in $images){if(-not [IO.Path]::IsPathRooted($image)){throw 'inventory_image_unresolved'}}
 if($images.Count -gt 0){Save-Private $observedPath @{images=@($images | ForEach-Object {$_})}}
 $unclassified=0
 foreach($process in @(Get-CimInstance Win32_Process)){if($process.ExecutablePath -and $images.Contains([string]$process.ExecutablePath)){$unclassified++}}
 return @{unclassified_process_count=$unclassified;service_names=@($serviceChanged.ToArray());task_keys=@($taskChanged.ToArray());foreign_job_member=$foreign}
}
function Close-ProxyForQuarantine($Context){
 foreach($row in @(Get-CimInstance Win32_Process -Filter "Name='TwoHostProxy.exe'")){
  if([string]::Equals($row.ExecutablePath,$Context.proxy_exe,[StringComparison]::OrdinalIgnoreCase)){
   $p=Get-Process -Id $row.ProcessId -ErrorAction SilentlyContinue
   if($p){try{
    $null=$p.Handle
    if(-not [string]::Equals($p.MainModule.FileName,$Context.proxy_exe,[StringComparison]::OrdinalIgnoreCase)){throw 'proxy_quarantine_identity_changed'}
    if(-not $p.HasExited){try{$p.Kill()}catch{if(-not $p.HasExited){throw}}}
    if(-not $p.WaitForExit(5000)){throw 'proxy_quarantine_survived'}
   }finally{$p.Dispose()}}
  }
 }
 if(@(Get-CimInstance Win32_Process -Filter "Name='TwoHostProxy.exe'" | Where-Object {[string]::Equals($_.ExecutablePath,$Context.proxy_exe,[StringComparison]::OrdinalIgnoreCase)}).Count -ne 0){throw 'proxy_quarantine_not_verified'}
}
