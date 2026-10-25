param([Parameter(Mandatory=$true)][string]$Config,[ValidateSet('deadline','fallback','resolution','monitor')][string]$Origin='fallback')
. (Join-Path $PSScriptRoot 'Common.ps1')
. (Join-Path $PSScriptRoot 'Inventory.ps1')
$c=Read-Context $Config;$mutex=$null;$job=[IntPtr]::Zero;$handles=New-Object Collections.Generic.List[Diagnostics.Process]
$r=[ordered]@{schema='bnet-integrated-recovery-g16-1';origin=$Origin;system_identity=([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18');status='stopped';lease_closed=$false;abandoned_mutex_reclaimed=$false;unknown_task_detected=$false;unknown_service_detected=$false;unknown_process_detected=$false;restore_refused_for_unknown=$false;gate_proxy_closed=$false;global_service_change_count=0;global_task_change_count=0;peer_ledger_revoked=$false;foreign_job_member=$false;unclassified_process_count=0;supervisor_exited=$false;service_removed=$false;task_removed=$false;job_active_zero=$false;all_observed_members_exited=$false;fixture_images_gone=$false;hosts_restored=$false;firewall_restored=$false;iis_restored=$false;error_code=$null;error_shape=$null}
try{
 $mutex=Enter-Lease $c;$r.abandoned_mutex_reclaimed=$script:LastLeaseAbandoned
 $lease=Get-Content -Raw (Join-Path $c.root 'lease.json') | ConvertFrom-Json
 if($lease.phase -eq 'released'){
  # Do not replace a prior deadline receipt during always-step cleanup.
  exit 0
 }
 Save-Private (Join-Path $c.root 'lease.json') @{phase='releasing'};$r.lease_closed=$true
 Write-Peers $c @();$r.peer_ledger_revoked=$true
 Close-ProxyForQuarantine $c;$r.gate_proxy_closed=$true
 if(Test-Path (Join-Path $c.root 'supervisor-process.json')){
  $id=Get-Content -Raw (Join-Path $c.root 'supervisor-process.json') | ConvertFrom-Json;$proc=Open-Verified $id
  if($proc){try{$proc.Kill();if(-not $proc.WaitForExit(5000)){throw 'supervisor_survived'}}finally{$proc.Dispose()}}
 }
 $r.supervisor_exited=$true
 $null=[Reflection.Assembly]::LoadFrom($c.exe)
 $delta=Get-InventoryDelta $c
 $r.global_service_change_count=@($delta.service_names).Count;$r.global_task_change_count=@($delta.task_keys).Count;$r.foreign_job_member=$delta.foreign_job_member;$r.unclassified_process_count=$delta.unclassified_process_count
 if($r.global_service_change_count -gt 0){$r.unknown_service_detected=$true}
 if($r.global_task_change_count -gt 0){$r.unknown_task_detected=$true}
 if($r.foreign_job_member -or $r.unclassified_process_count -gt 0){$r.unknown_process_detected=$true}
 # Real inventory guard scoped to the protected fixture directory; not arbitrary installer discovery.
 $prefix=$c.root+'\'
 foreach($task in @(Get-ScheduledTask)){
  foreach($action in @($task.Actions)){
   if($action.Execute -and ([string]$action.Execute).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){
    if($task.TaskPath -ne '\' -or @($task.Actions).Count -ne 1 -or $task.TaskName -ne $c.task_name -or $action.Execute -ne $c.exe -or $action.Arguments -ne $c.task_arguments){$r.unknown_task_detected=$true}
   }
  }
 }
 foreach($service in @(Get-CimInstance Win32_Service)){
  $command=[string]$service.PathName
  if($command.StartsWith('"'+$prefix,[StringComparison]::OrdinalIgnoreCase) -or $command.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){
   if($service.Name -ne $c.service_name -or $command -ne $c.service_command){$r.unknown_service_detected=$true}
  }
 }
 $known=New-Object 'Collections.Generic.Dictionary[int,long]'
 foreach($file in @('owner-process.json','owner.json','root.json','leaf.json','service.json','task.json')){
  $path=Join-Path $c.root $file;if(Test-Path $path){$state=Get-Content -Raw $path | ConvertFrom-Json;$known[[int]$state.pid]=[long]$state.created}
 }
 foreach($row in @(Get-CimInstance Win32_Process)){
  $image=[string]$row.ExecutablePath
  if($image.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and -not [string]::Equals($image,$c.proxy_exe,[StringComparison]::OrdinalIgnoreCase)){
   $pidValue=[int]$row.ProcessId
   if(-not [string]::Equals($image,$c.exe,[StringComparison]::OrdinalIgnoreCase) -or -not $known.ContainsKey($pidValue)){$r.unknown_process_detected=$true}else{
    $identity=@{pid=$pidValue;created=$known[$pidValue];image=$c.exe};$verified=Open-Verified $identity
    if($verified){$verified.Dispose()}else{$r.unknown_process_detected=$true}
   }
  }
 }
 if($r.unknown_task_detected -or $r.unknown_service_detected -or $r.unknown_process_detected){Close-ProxyForQuarantine $c;$r.gate_proxy_closed=$true;$r.restore_refused_for_unknown=$true;throw 'unclassified_fixture_component_blocks_restore'}
 $null=[Reflection.Assembly]::LoadFrom($c.exe)
 $job=[ExternalProbe]::OpenOwnedJob($c.job_name)
 if($job -ne [IntPtr]::Zero){
  foreach($member in [ExternalProbe]::JobMembers($job,$c.exe)){$proc=Open-Verified $member;if($proc){$handles.Add($proc)}}
 }elseif(Test-Path (Join-Path $c.root 'owner.json')){
  $owner=Get-Content -Raw (Join-Path $c.root 'owner.json') | ConvertFrom-Json
  foreach($member in $owner.members){$proc=Open-Verified $member;if($proc){$handles.Add($proc)}}
 }
 $task=Get-ScheduledTask -TaskName $c.task_name -ErrorAction SilentlyContinue
 if($task){
  if(@($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -ne $c.exe -or $task.Actions[0].Arguments -ne $c.task_arguments){throw 'task_identity_changed'}
  $null=Disable-ScheduledTask $c.task_name;$null=New-Item -ItemType File -Force (Join-Path $c.root 'stop-task');Stop-ScheduledTask $c.task_name -ErrorAction SilentlyContinue;Unregister-ScheduledTask $c.task_name -Confirm:$false
 }
 $service=Get-CimInstance Win32_Service -Filter ("Name='"+$c.service_name+"'")
 if($service){
  if($service.PathName -ne $c.service_command){throw 'service_identity_changed'}
  Set-Service $c.service_name -StartupType Disabled;Stop-Service $c.service_name
  $ctl=Get-Service $c.service_name;try{$ctl.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(10))}finally{$ctl.Dispose()}
  $null=& "$env:SystemRoot\System32\sc.exe" delete $c.service_name;if($LASTEXITCODE -ne 0){throw 'service_delete_failed'}
 }
 if($job -ne [IntPtr]::Zero){$r.job_active_zero=[ExternalProbe]::EndOwnedJob($job)}else{$r.job_active_zero=$true}
 if(-not $r.job_active_zero){throw 'job_not_empty'}
 foreach($row in @(Get-CimInstance Win32_Process -Filter "Name='ExternalProbe.exe'")){
  if([string]::Equals($row.ExecutablePath,$c.exe,[StringComparison]::OrdinalIgnoreCase)){
   $proc=Get-Process -Id $row.ProcessId -ErrorAction SilentlyContinue;if($proc){$null=$proc.Handle
    try{if(-not [string]::Equals($proc.MainModule.FileName,$c.exe,[StringComparison]::OrdinalIgnoreCase)){throw 'fixture_identity_changed'};if(-not $proc.HasExited){$proc.Kill()};if(-not $proc.WaitForExit(5000)){throw 'fixture_survived'}}finally{$proc.Dispose()}
   }
  }
 }
 $r.all_observed_members_exited=($handles.Count -gt 0)
 foreach($proc in $handles){if(-not $proc.WaitForExit(5000)){$r.all_observed_members_exited=$false}}
 # Even without owner.json, the live named Job must supply member identity/exit coverage. Missing coverage still fails closed.
 if(-not $r.all_observed_members_exited){throw 'member_exit_coverage_not_verified'}
 Start-Sleep -Milliseconds 500
 $r.service_removed=-not (Get-CimInstance Win32_Service -Filter ("Name='"+$c.service_name+"'"))
 $r.task_removed=-not (Get-ScheduledTask -TaskName $c.task_name -ErrorAction SilentlyContinue)
 $r.fixture_images_gone=(@(Get-CimInstance Win32_Process -Filter "Name='ExternalProbe.exe'" | Where-Object {[string]::Equals($_.ExecutablePath,$c.exe,[StringComparison]::OrdinalIgnoreCase)}).Count -eq 0)
 if(-not ($r.service_removed -and $r.task_removed -and $r.fixture_images_gone)){throw 'components_still_registered_or_alive'}
 Save-Private (Join-Path $c.root 'components-exited.json') @{verified=$true}
 foreach($row in @(Get-CimInstance Win32_Process -Filter "Name='TwoHostProxy.exe'")){
  if([string]::Equals($row.ExecutablePath,$c.proxy_exe,[StringComparison]::OrdinalIgnoreCase)){$proc=Get-Process -Id $row.ProcessId -ErrorAction SilentlyContinue;if($proc){try{$null=$proc.Handle;if(-not [string]::Equals($proc.MainModule.FileName,$c.proxy_exe,[StringComparison]::OrdinalIgnoreCase)){throw 'proxy_identity_changed'};if(-not $proc.HasExited){try{$proc.Kill()}catch{if(-not $proc.HasExited){throw}}};if(-not $proc.WaitForExit(5000)){throw 'proxy_survived'}}finally{$proc.Dispose()}}}
 }
 $hosts="$env:SystemRoot\System32\drivers\etc\hosts";$old=[IO.File]::ReadAllBytes((Join-Path $c.root 'hosts-before.bak'));$expected=[IO.File]::ReadAllBytes((Join-Path $c.root 'hosts-after.expected'));$current=[IO.File]::ReadAllBytes($hosts)
 if((Hash-Bytes $current) -ne (Hash-Bytes $old) -and (Hash-Bytes $current) -ne (Hash-Bytes $expected)){throw 'hosts_restore_conflict'}
 [IO.File]::WriteAllBytes($hosts,$old);$null=& "$env:SystemRoot\System32\ipconfig.exe" /flushdns
 $r.hosts_restored=($LASTEXITCODE -eq 0 -and (Hash-Bytes ([IO.File]::ReadAllBytes($hosts))) -eq (Hash-Bytes $old))
 if(-not $r.hosts_restored){throw 'hosts_restore_not_verified'}
 $restored=Invoke-Gate $c 'Restore';$r.firewall_restored=($restored.restored_modified_fields -eq $true)
 if(-not $r.firewall_restored){throw 'firewall_restore_not_verified'}
 if($c.iis_original -eq 'Running'){Start-Service W3SVC;$ctl=Get-Service W3SVC;try{$ctl.WaitForStatus('Running',[TimeSpan]::FromSeconds(15))}finally{$ctl.Dispose()}}
 $r.iis_restored=([string](Get-Service W3SVC).Status -eq $c.iis_original)
 if(-not $r.iis_restored){throw 'iis_restore_not_verified'}
 Save-Private (Join-Path $c.root 'lease.json') @{phase='released'};$r.status='recovered_after_verified_component_exit'
 Save-Private (Join-Path $c.root 'recovery-result.json') $r
 Unregister-ScheduledTask $c.watchdog_name -Confirm:$false -ErrorAction SilentlyContinue
}catch{
 $triggerError=$_
 try{Close-ProxyForQuarantine $c;$r.gate_proxy_closed=$true}catch{}
 $message=$triggerError.Exception.Message;$r.error_code=if($message -match '^[a-z_]{1,80}$'){$message}else{'independent_recovery_operation_failed'}
 $r.error_shape=Error-Shape $triggerError
 $priorPath=Join-Path $c.root 'recovery-result.json'
 if(Test-Path $priorPath){$prior=Get-Content -Raw $priorPath | ConvertFrom-Json}else{$prior=$null}
 if($prior -and (($prior.origin -eq 'deadline' -and $prior.status -eq 'recovered_after_verified_component_exit') -or ($prior.restore_refused_for_unknown -eq $true -and $Origin -in @('fallback','deadline')))){
  Save-Private (Join-Path $c.root 'fallback-error.json') $r
 }else{Save-Private $priorPath $r}
 throw 'independent_recovery_stopped_no_unconditional_import'
}finally{
 foreach($proc in $handles){$proc.Dispose()};if($job -ne [IntPtr]::Zero){[ExternalProbe]::CloseOwnedJob($job)}
 if($mutex){$mutex.ReleaseMutex();$mutex.Dispose()}
}
