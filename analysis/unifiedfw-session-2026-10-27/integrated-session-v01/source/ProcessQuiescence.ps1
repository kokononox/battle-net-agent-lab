# Private necessary process checks + guard composition. No termination or native setters.
# Census visibility/lineage are NOT service/IPC coverage or atomic execution prevention.
function Assert-UfwQuiescenceCensus($Rows){
 if($Rows -isnot [array] -or $Rows.Count -lt 2 -or $Rows.Count -gt 8192){throw 'ufw_unified_quiet_census_shape'}
 $seen=@{};$kernel=@{}
 foreach($p in $Rows){
  if((@($p.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'kernel,parent_pid,path,pid,started_utc'){throw 'ufw_unified_quiet_census_shape'}
  foreach($k in @('pid','parent_pid')){if(($p.$k -isnot [int] -and $p.$k -isnot [long]) -or $p.$k -lt 0 -or $p.$k -gt [int]::MaxValue){throw 'ufw_unified_quiet_census_identity'}}
  if($seen.ContainsKey($p.pid) -or $p.kernel -isnot [bool] -or $p.path -isnot [string] -or $p.started_utc -isnot [string]){throw 'ufw_unified_quiet_census_identity'};$seen[$p.pid]=$true
  if($p.pid -in @(0,4)){
   if(-not $p.kernel -or $p.path -cne '' -or $p.started_utc -cne '' -or $p.parent_pid -ne 0){throw 'ufw_unified_quiet_kernel_identity'};$kernel[$p.pid]=$true
  }else{
   if($p.kernel -or $p.pid -lt 1 -or [string]::IsNullOrWhiteSpace($p.path) -or $p.started_utc -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$'){throw 'ufw_unified_quiet_process_visibility'}
   if((ConvertTo-UfwRuntimePath $p.path @()) -cne $p.path){throw 'ufw_unified_quiet_process_visibility'}
   $time=[datetime]::ParseExact($p.started_utc,'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
   if($time.Kind -ne [DateTimeKind]::Utc){throw 'ufw_unified_quiet_process_visibility'}
  }
 }
 if($kernel.Count -ne 2){throw 'ufw_unified_quiet_census_kernel_missing'}
}
function Read-UfwWindowsProcessCensus {
 # Cross-check TWO independent enumerators, never the old skip-errors path reader.
 $processes=@();$handles=@()
 try{
  $processes=@(Get-CimInstance -ClassName Win32_Process -OperationTimeoutSec 10 -ErrorAction Stop)
  $handles=@(Get-Process -ErrorAction Stop)
  if($processes.Count -gt 8192 -or $handles.Count -gt 8192){throw 'ufw_unified_quiet_census_shape'}
  $cim=@{};$managed=@{};$rows=@()
  foreach($p in $processes){
   if($p.ProcessId -isnot [uint32] -and $p.ProcessId -isnot [int] -and $p.ProcessId -isnot [long]){throw 'ufw_unified_quiet_census_identity'}
   $id=[long]$p.ProcessId
   if($id -lt 0 -or $id -gt [int]::MaxValue -or $cim.ContainsKey($id)){throw 'ufw_unified_quiet_census_identity'};$cim[$id]=$true
   if($id -in @(0,4)){
    $expected='System';if($id -eq 0){$expected='System Idle Process'}
    if($p.Name -cne $expected -or $p.ParentProcessId -ne 0){throw 'ufw_unified_quiet_kernel_identity'}
    $rows+=,[pscustomobject][ordered]@{pid=$id;parent_pid=[long]0;path='';started_utc='';kernel=$true}
   }else{
    if($p.CreationDate -isnot [datetime] -or $p.ExecutablePath -isnot [string] -or [string]::IsNullOrWhiteSpace($p.ExecutablePath) -or ($p.ParentProcessId -isnot [uint32] -and $p.ParentProcessId -isnot [int] -and $p.ParentProcessId -isnot [long])){throw 'ufw_unified_quiet_process_visibility'}
    $rows+=,[pscustomobject][ordered]@{pid=$id;parent_pid=[long]$p.ParentProcessId;path=(ConvertTo-UfwRuntimePath $p.ExecutablePath @());started_utc=$p.CreationDate.ToUniversalTime().ToString('o');kernel=$false}
   }
  }
  foreach($p in $handles){$id=[long]$p.Id;if($managed.ContainsKey($id)){throw 'ufw_unified_quiet_census_identity'};$managed[$id]=$true}
  if($cim.Count -ne $managed.Count){throw 'ufw_unified_quiet_enumerator_disagreement'}
  foreach($id in $cim.Keys){if(-not $managed.ContainsKey($id)){throw 'ufw_unified_quiet_enumerator_disagreement'}}
  $rows=@($rows|Sort-Object pid);Assert-UfwQuiescenceCensus $rows;return ,$rows
 }finally{foreach($p in (@($handles)+@($processes))){if($p -is [IDisposable]){$p.Dispose()}}}
}
function New-UfwWindowsQuiescenceOps {
 return @{
  Actor=(New-UfwLocalModuleCallback {param($unused)return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value} $null)
  Boot=(New-UfwLocalModuleCallback {param($unused)return Get-UfwWindowsBootMarker} $null)
  Census=(New-UfwLocalModuleCallback {param($unused)return ,(Read-UfwWindowsProcessCensus)} $null)
 }
}
function Get-UfwRecoveryLineage($Proof){
 $r=[ordered]@{complete_observed_exits=$false;roots=0;descendants=0;known_pids=@();known_paths=@();code='ufw_unified_quiet_lineage_incomplete'}
 try{
  if($null -eq $Proof.arm -or $null -eq $Proof.evidence -or -not $Proof.same_boot){throw 'ufw_unified_quiet_witness_incomplete'}
  $e=$Proof.evidence
  # The old collector may set completed for a PARTIAL proposal: explicit code gate.
  if(-not $e.capture_completed -or -not $e.audit_restore_verified -or $e.capture_interrupted -or $e.parse_errors -ne 0 -or $e.capture_code -cnotin @('ufw_runtime_proposals_pending_review','ufw_runtime_selected_started_zero_endpoints_not_safety_proof')){throw 'ufw_unified_quiet_capture_incomplete'}
  $programs=@(ConvertFrom-Json $Proof.arm.programs_json);$events=@(ConvertFrom-Json $e.events_json)
  $active=@{};$pids=@{};$paths=@{};$last=[long]0
  foreach($p in $programs){$paths[$p.path.ToLowerInvariant()]=$p.path}
  foreach($x in $events){
   if($x.record -le $last -or $x.id -notin @(4688,4689)){throw 'ufw_unified_quiet_lineage_integrity'};$last=$x.record
   if($x.id -eq 4688){
    if($active.ContainsKey($x.pid)){throw 'ufw_unified_quiet_pid_reuse'}
    $tracked=$false;$root=$false
    foreach($p in $programs){if([string]::Equals($x.path,$p.path,[StringComparison]::OrdinalIgnoreCase)){$root=$true;break}}
    if($root){if($x.actor -cne $Proof.arm.actor_sid){throw 'ufw_unified_quiet_actor_changed'};$tracked=$true;$r.roots++}
    elseif($active.ContainsKey($x.parent_pid) -and $active[$x.parent_pid].tracked){
     if(-not [string]::Equals($x.parent_path,$active[$x.parent_pid].path,[StringComparison]::OrdinalIgnoreCase)){throw 'ufw_unified_quiet_parent_unknown'}
     $tracked=$true;$r.descendants++
    }elseif($paths.ContainsKey($x.parent_path.ToLowerInvariant()) -or $pids.ContainsKey($x.parent_pid)){throw 'ufw_unified_quiet_orphan_unknown'}
    if($tracked){$pids[$x.pid]=$true;$paths[$x.path.ToLowerInvariant()]=$x.path}
    $active[$x.pid]=[pscustomobject]@{path=$x.path;tracked=$tracked}
   }else{
    if($active.ContainsKey($x.pid)){
     if(-not [string]::Equals($x.path,$active[$x.pid].path,[StringComparison]::OrdinalIgnoreCase)){throw 'ufw_unified_quiet_exit_unknown'}
     $active.Remove($x.pid)
    }elseif($paths.ContainsKey($x.path.ToLowerInvariant())){throw 'ufw_unified_quiet_exit_unknown'}
   }
  }
  if($r.roots -lt 1 -or @($active.Values|Where-Object{$_.tracked}).Count -gt 0){throw 'ufw_unified_quiet_observed_process_open'}
  $r.known_pids=@($pids.Keys|Sort-Object);$r.known_paths=@($paths.Values|Sort-Object);$r.complete_observed_exits=$true;$r.code='ufw_unified_quiet_observed_lineage_closed'
 }catch{$code=[string]$_.Exception.GetBaseException().Message;if($code -cmatch '^ufw_unified_quiet_[a-z_]{1,80}$'){$r.code=$code}}
 return [pscustomobject]$r
}
function Get-UfwIndependentProcessQuiet($Storage,[string]$Binding,$Ops){
 # Returns aggregate necessary evidence ONLY. No cached/portable restore permit.
 $r=[ordered]@{process_quiet_observed=$false;quiescence_authorized=$false;census_passes=0;code='ufw_unified_quiet_unavailable'}
 $watch=[Diagnostics.Stopwatch]::StartNew()
 try{
  foreach($k in @('Actor','Boot','Census')){if(-not $Ops.ContainsKey($k) -or $Ops[$k] -isnot [scriptblock]){throw 'ufw_unified_quiet_adapter'}}
  if($null -eq $Storage.lock -or -not $Storage.lock.CanWrite){throw 'ufw_unified_quiet_session_lock'}
  $before=Read-UfwUnifiedStorage $Storage
  if($before.records[0].data.binding -cne $Binding){throw 'ufw_unified_quiet_policy_binding'}
  $actor=& $Ops.Actor;$boot=& $Ops.Boot
  $proof=Read-UfwRuntimeRecoveryWitness $Storage $actor $boot
  $lineage=Get-UfwRecoveryLineage $proof
  if(-not $lineage.complete_observed_exits){throw $lineage.code}
  $last=''
  for($pass=0;$pass -lt 2;$pass++){
   $rows=& $Ops.Census;Assert-UfwQuiescenceCensus $rows;$r.census_passes++
   foreach($p in $rows){
    if($p.kernel){continue}
    foreach($path in $lineage.known_paths){if([string]::Equals($p.path,$path,[StringComparison]::OrdinalIgnoreCase)){throw 'ufw_unified_quiet_known_process_active'}}
    if($lineage.known_pids -contains $p.pid -or $lineage.known_pids -contains $p.parent_pid){throw 'ufw_unified_quiet_pid_or_descendant_active'}
   }
   $text=Get-UfwLocalJson @($rows|Sort-Object pid)
   if($pass -eq 1 -and $text -cne $last){throw 'ufw_unified_quiet_census_changed'};$last=$text
   if((& $Ops.Actor) -cne $actor -or (& $Ops.Boot) -cne $boot){throw 'ufw_unified_quiet_observation_changed'}
  }
  $after=Read-UfwUnifiedStorage $Storage
  if($after.head -cne $before.head -or $after.sequence -ne $before.sequence -or $watch.ElapsedMilliseconds -gt 15000){throw 'ufw_unified_quiet_observation_changed'}
  $r.process_quiet_observed=$true;$r.code='ufw_unified_quiet_processes_only_not_service_coverage'
 }catch{$code=[string]$_.Exception.GetBaseException().Message;if($code -cmatch '^ufw_unified_(quiet|witness)_[a-z_]{1,80}$'){$r.code=$code}}
 finally{$watch.Stop()}
 return [pscustomobject]$r
}
function New-UfwQuiescenceBackendGuard($Storage,$Ops,[scriptblock]$ExistingGuard,[scriptblock]$HelperCoverageGuard){
 if($null -eq $ExistingGuard -or $null -eq $HelperCoverageGuard){throw 'ufw_unified_quiet_independent_guard_required'}
 foreach($k in @('Actor','Boot','Census')){if(-not $Ops.ContainsKey($k) -or $Ops[$k] -isnot [scriptblock]){throw 'ufw_unified_quiet_adapter'}}
 return New-UfwLocalModuleCallback {
  param($b,$phase,$view)
  if($phase -cnotin @('backup','forward','immediately_before_forward','restore','immediately_before_restore','recovery','finish')){return $false}
  $old=& $b.existing $phase $view;if($old -isnot [bool] -or -not $old){return $false}
  if($phase -cin @('restore','immediately_before_restore','recovery','finish')){
   $quiet=Get-UfwIndependentProcessQuiet $b.storage $view.binding $b.ops
   if(-not $quiet.process_quiet_observed){return $false}
   # MUST be an independent bound safety check, NOT a user JSON flag, process count,
   # or the evidence's quiescence_authorized field (which always remains false).
   $coverage=& $b.coverage $phase $view
   if($coverage -isnot [bool] -or -not $coverage){return $false}
   $fresh=& $b.existing $phase $view
   if($fresh -isnot [bool] -or -not $fresh){return $false}
  }
  return $true
 } ([pscustomobject]@{storage=$Storage;ops=$Ops;existing=$ExistingGuard;coverage=$HelperCoverageGuard})
}
