# Read-only service/PID corroboration. Necessary evidence, NEVER full helper/IPC authority.
function Assert-UfwServiceCensus($Rows){
 if($Rows -isnot [array] -or $Rows.Count -lt 1 -or $Rows.Count -gt 8192){throw 'ufw_unified_service_census_shape'}
 $seen=@{}
 foreach($s in $Rows){
  if((@($s.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'account,command,name,pid,start_mode,state,type'){throw 'ufw_unified_service_census_shape'}
  foreach($key in @('name','account','command','start_mode','state','type')){if($s.$key -isnot [string] -or [string]::IsNullOrWhiteSpace($s.$key) -or $s.$key.Length -gt 32768){throw 'ufw_unified_service_visibility'}}
  if($s.name.Length -gt 512 -or $s.name -match '[\x00-\x1f]' -or $seen.ContainsKey($s.name)){throw 'ufw_unified_service_identity'};$seen[$s.name]=$true
  if(($s.pid -isnot [long] -and $s.pid -isnot [int]) -or $s.pid -lt 0 -or $s.pid -gt [int]::MaxValue){throw 'ufw_unified_service_identity'}
  if($s.state -cnotin @('Stopped','Start Pending','Stop Pending','Running','Continue Pending','Pause Pending','Paused') -or $s.start_mode -cnotin @('Auto','Manual','Disabled','Boot','System')){throw 'ufw_unified_service_visibility'}
  if(($s.state -ceq 'Stopped' -and $s.pid -ne 0) -or ($s.state -cne 'Stopped' -and $s.pid -eq 0)){throw 'ufw_unified_service_pid_unresolved'}
 }
}
function Read-UfwWindowsServiceCensus {
 $cim=@();$scm=@()
 try{
  $cim=@(Get-CimInstance -ClassName Win32_Service -OperationTimeoutSec 10 -ErrorAction Stop)
  $scm=@(Get-Service -ErrorAction Stop)
  if($cim.Count -gt 8192 -or $scm.Count -gt 8192){throw 'ufw_unified_service_census_shape'}
  $rows=@();$managed=@{}
  $states=@{Stopped='Stopped';StartPending='Start Pending';StopPending='Stop Pending';Running='Running';ContinuePending='Continue Pending';PausePending='Pause Pending';Paused='Paused'}
  foreach($s in $scm){
   $name=$s.ServiceName;$state=[string]$s.Status
   if($name -isnot [string] -or [string]::IsNullOrWhiteSpace($name) -or $managed.ContainsKey($name) -or -not $states.ContainsKey($state)){throw 'ufw_unified_service_enumerator_disagreement'}
   $managed[$name]=$states[$state]
  }
  foreach($s in $cim){
   if($s.ProcessId -isnot [uint32] -and $s.ProcessId -isnot [int] -and $s.ProcessId -isnot [long]){throw 'ufw_unified_service_identity'}
   $rows+=,[pscustomobject][ordered]@{name=$s.Name;pid=[long]$s.ProcessId;state=$s.State;start_mode=$s.StartMode;command=$s.PathName;account=$s.StartName;type=$s.ServiceType}
  }
  Assert-UfwServiceCensus $rows
  if($managed.Count -ne $rows.Count){throw 'ufw_unified_service_enumerator_disagreement'}
  foreach($s in $rows){if(-not $managed.ContainsKey($s.name) -or $managed[$s.name] -cne $s.state){throw 'ufw_unified_service_enumerator_disagreement'}}
  return ,@($rows|Sort-Object name)
 }finally{foreach($s in (@($cim)+@($scm))){if($s -is [IDisposable]){$s.Dispose()}}}
}
function New-UfwWindowsServiceOps {
 return @{Census=(New-UfwLocalModuleCallback {param($unused)return ,(Read-UfwWindowsServiceCensus)} $null)}
}
function Get-UfwIndependentServiceQuiet($Storage,[string]$Binding,$QuietOps,$ServiceOps){
 $r=[ordered]@{service_process_links_quiet=$false;service_passes=0;process_passes=0;complete_helper_service_IPC_coverage=$false;quiescence_authorized=$false;code='ufw_unified_service_unavailable'}
 $watch=[Diagnostics.Stopwatch]::StartNew()
 try{
  foreach($key in @('Actor','Boot','Census')){if(-not $QuietOps.ContainsKey($key) -or $QuietOps[$key] -isnot [scriptblock]){throw 'ufw_unified_service_adapter'}}
  if(-not $ServiceOps.ContainsKey('Census') -or $ServiceOps.Census -isnot [scriptblock]){throw 'ufw_unified_service_adapter'}
  if($null -eq $Storage.lock -or -not $Storage.lock.CanWrite){throw 'ufw_unified_service_lock_required'}
  $before=Read-UfwUnifiedStorage $Storage
  if($before.records[0].data.binding -cne $Binding){throw 'ufw_unified_service_binding'}
  $actor=& $QuietOps.Actor;$boot=& $QuietOps.Boot
  $proof=Read-UfwRuntimeRecoveryWitness $Storage $actor $boot
  $lineage=Get-UfwRecoveryLineage $proof
  if(-not $lineage.complete_observed_exits){throw 'ufw_unified_service_lineage_unresolved'}
  $lastServices='';$lastProcesses=''
  for($pass=0;$pass -lt 2;$pass++){
   $services=& $ServiceOps.Census;Assert-UfwServiceCensus $services;$r.service_passes++
   $processes=& $QuietOps.Census;Assert-UfwQuiescenceCensus $processes;$r.process_passes++
   $byPID=@{}
   foreach($p in $processes){
    $byPID[$p.pid]=$p
    if($p.kernel){continue}
    if($lineage.known_pids -contains $p.pid -or $lineage.known_pids -contains $p.parent_pid){throw 'ufw_unified_service_known_execution_active'}
    foreach($path in $lineage.known_paths){if([string]::Equals($path,$p.path,[StringComparison]::OrdinalIgnoreCase)){throw 'ufw_unified_service_known_execution_active'}}
   }
   foreach($s in $services){
    # Even a stopped service is NOT proof it cannot start again. Never parse/execute PathName.
    if($s.pid -eq 0){continue}
    if($s.pid -in @(0,4) -or -not $byPID.ContainsKey($s.pid) -or $byPID[$s.pid].kernel){throw 'ufw_unified_service_pid_unresolved'}
   }
   $serviceText=Get-UfwLocalJson @($services|Sort-Object name);$processText=Get-UfwLocalJson @($processes|Sort-Object pid)
   if($pass -eq 1 -and ($serviceText -cne $lastServices -or $processText -cne $lastProcesses)){throw 'ufw_unified_service_observation_changed'}
   $lastServices=$serviceText;$lastProcesses=$processText
   if((& $QuietOps.Actor) -cne $actor -or (& $QuietOps.Boot) -cne $boot){throw 'ufw_unified_service_observation_changed'}
  }
  $after=Read-UfwUnifiedStorage $Storage
  if($after.head -cne $before.head -or $after.sequence -ne $before.sequence -or $watch.ElapsedMilliseconds -gt 15000){throw 'ufw_unified_service_observation_changed'}
  $r.service_process_links_quiet=$true;$r.code='ufw_unified_service_links_only_not_IPC_coverage'
 }catch{$code=[string]$_.Exception.GetBaseException().Message;if($code -cmatch '^ufw_unified_(service|quiet|witness)_[A-Za-z_]{1,80}$'){$r.code=$code}}
 finally{$watch.Stop()}
 return [pscustomobject]$r
}
function New-UfwServiceObservationGuard($Storage,$QuietOps,$ServiceOps,[scriptblock]$IndependentCoverageGuard){
 if($null -eq $IndependentCoverageGuard){throw 'ufw_unified_service_independent_coverage_required'}
 return New-UfwLocalModuleCallback {
  param($b,$phase,$view)
  if($phase -cnotin @('backup','forward','immediately_before_forward','restore','immediately_before_restore','recovery','finish')){return $false}
  if($phase -cin @('restore','immediately_before_restore','recovery','finish')){
   $observed=Get-UfwIndependentServiceQuiet $b.storage $view.binding $b.quiet $b.service
   if(-not $observed.service_process_links_quiet){return $false}
  }
  $allowed=& $b.coverage $phase $view
  if($allowed -isnot [bool] -or -not $allowed){return $false}
  if($phase -cin @('restore','immediately_before_restore','recovery','finish')){
   $fresh=Get-UfwIndependentServiceQuiet $b.storage $view.binding $b.quiet $b.service
   if(-not $fresh.service_process_links_quiet){return $false}
  }
  return $true
 } ([pscustomobject]@{storage=$Storage;quiet=$QuietOps;service=$ServiceOps;coverage=$IndependentCoverageGuard})
}
function New-UfwServiceReviewedPolicyRecovery($PolicyIO,$RuntimeOps,$QuietOps,$ServiceOps,[scriptblock]$IndependentCoverageGuard,$UI,[scriptblock]$ExistingGuard){
 if($null -eq $IndependentCoverageGuard -or $null -eq $ExistingGuard){throw 'ufw_unified_service_independent_coverage_required'}
 return New-UfwLocalModuleCallback {
  param($b,$handle)
  $coverage=New-UfwServiceObservationGuard $handle $b.quiet $b.service $b.coverage
  $recover=New-UfwReviewedPolicyRecovery $b.policy $b.runtime $b.quiet $coverage $b.ui $b.existing
  return & $recover $handle
 } ([pscustomobject]@{policy=$PolicyIO;runtime=$RuntimeOps;quiet=$QuietOps;service=$ServiceOps;coverage=$IndependentCoverageGuard;ui=$UI;existing=$ExistingGuard})
}
