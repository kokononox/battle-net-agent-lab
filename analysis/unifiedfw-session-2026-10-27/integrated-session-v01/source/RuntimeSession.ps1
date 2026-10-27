# Private composition of the unchanged runtime collector. No EXE execution/grants.
function New-UfwWindowsRuntimeOps {
 $b=@{
  Pending={Read-UfwRuntimePending};Confirm={param($mode,$p)Confirm-UfwRuntime $mode $p}
  Actor={[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
  AuditQuery={param($id)[UfwRuntime01.Audit]::Query($id)};AuditSet={param($id,$value)[UfwRuntime01.Audit]::Set($id,[uint32]$value)}
  Archive={param($j)Archive-UfwRuntimePending $j};Select={Select-UfwObserverCandidate};Load={param($p)Read-UfwObserverCandidate $p}
  Observe={param($p)Read-UfwProgramNativeObservation $p};Clock={[datetime]::UtcNow};FirewallGuard={Get-UfwRuntimeFirewallGuard}
  ExistingProcesses={param($p)Get-UfwObserverProcesses $p};DeviceMap={Get-UfwRuntimeDeviceMap}
  WriteJournal={param($d)Write-UfwRuntimePending $d};LogEdge={param($reverse)Get-UfwRuntimeLogEdge $reverse}
  SelfTest={param($map)Test-UfwRuntimeNativeEvents $map};Window={param($guard,$witness)
   if($null -eq $witness -or -not $witness.armed -or $null -eq $witness.storage.lock -or -not $witness.storage.lock.CanWrite){throw 'ufw_unified_witness_required_before_native_window'}
   $back=Read-UfwUnifiedStorage $witness.storage
   $state=Get-UfwLocalBackendState ([pscustomobject]@{storage=$witness.storage;view=$back.records[0].data})
   if($state.closed -or $state.restore_started -or $null -eq $state.runtime_arm -or (Get-UfwLocalJson $state.runtime_arm) -cne (Get-UfwLocalJson $witness.arm)){throw 'ufw_unified_witness_required_before_native_window'}
   Show-UfwRuntimeWindow $guard
  }
  ReadEvents={param($start,$end,$map)Read-UfwRuntimeEvents $start $end $map};Save={param($d)Save-UfwRuntimeProposals $d}
 }
 $ops=@{};foreach($k in $b.Keys){$ops[$k]=New-UfwLocalModuleCallback {param($body)return & $body @args} $b[$k]};return $ops
}
function Assert-UfwBoundRuntimeRecord($Context,$Record){
 Assert-UfwObserverRecord $Record
 if($Record.head -cne $Context.record.head -or $Record.data.receipt.actor_sid -cne $Context.actor -or (Get-UfwCandidateProgramDigest $Record.data.programs) -cne $Context.program_digest){throw 'ufw_unified_bound_candidate_changed'}
}
function New-UfwBoundRuntimeContext($RuntimeOps,$Selection,$Record,$Live){
 foreach($k in @('Load','Select','Window','ReadEvents','FirewallGuard','Actor')){if(-not $RuntimeOps.ContainsKey($k) -or $RuntimeOps[$k] -isnot [scriptblock]){throw 'ufw_unified_bound_runtime_adapter'}}
 Assert-UfwObserverRecord $Record
 if($Selection.cancelled -isnot [bool] -or $Selection.cancelled -or $Selection.path -isnot [string] -or [string]::IsNullOrWhiteSpace($Selection.path)){throw 'ufw_unified_bound_candidate_selection'}
 $digest=Get-UfwCandidateProgramDigest $Live.programs
 if($Record.data.receipt.actor_sid -cne $Live.actor -or (Get-UfwCandidateProgramDigest $Record.data.programs) -cne $digest -or (& $RuntimeOps.Actor) -cne $Live.actor){throw 'ufw_unified_bound_candidate_identity'}
 $c=[pscustomobject]@{ops=$RuntimeOps;path=$Selection.path;record=(Copy-UfwLocalData $Record);actor=$Live.actor;program_digest=$digest;live=$Live;used=$false;window_attempted=$false;batch=$null;capture_result=$null;witness=$null}
 # Fresh protected read; saved program-selection consent is NOT isolation consent.
 $fresh=& $RuntimeOps.Load $c.path;Assert-UfwBoundRuntimeRecord $c $fresh
 return $c
}
function New-UfwBoundRuntimeOps($Context){
 $copy=@{};foreach($key in $Context.ops.Keys){$copy[$key]=$Context.ops[$key]}
 $copy.Select=New-UfwLocalModuleCallback {param($c)return [pscustomobject]@{cancelled=$false;path=$c.path}} $Context
 $copy.Load=New-UfwLocalModuleCallback {
  param($c,$path)
  if($path -isnot [string] -or $path -cne $c.path){throw 'ufw_unified_bound_candidate_path'}
  $record=& $c.ops.Load $c.path;Assert-UfwBoundRuntimeRecord $c $record;return $record
 } $Context
 $copy.Window=New-UfwLocalModuleCallback {
  param($c,$guard)
  # Exception after UI effect must still be treated as possible manual launch.
  if($null -ne $c.witness){Write-UfwRuntimeArm $c}
  $c.window_attempted=$true
  & $guard|Out-Null
  return & $c.ops.Window $guard $c.witness
 } $Context
 $copy.ReadEvents=New-UfwLocalModuleCallback {
  param($c,$start,$end,$map)
  $batch=& $c.ops.ReadEvents $start $end $map
  $c.batch=Copy-UfwLocalData $batch
  return $batch
 } $Context
 return $copy
}
function Invoke-UfwBoundRuntimeCapture($Context,[scriptblock]$PolicyGuard){
 if($Context.used -or $null -eq $PolicyGuard){throw 'ufw_unified_bound_capture_invocation'}
 $Context.used=$true
 $guard=New-UfwLocalModuleCallback {
  param($b,$binding)
  if($binding -cne $b.context.live.view.binding -or -not (Test-UfwLiveLease $b.context.live)){return $false}
  $ok=& $b.policy $binding
  return $ok -is [bool] -and $ok
 } ([pscustomobject]@{context=$Context;policy=$PolicyGuard})
 $result=Invoke-UfwUnifiedRuntimeBridge (New-UfwBoundRuntimeOps $Context) $Context.live.view.binding $guard
 $Context.capture_result=$result
 if($null -ne $Context.witness -and $Context.witness.armed){Write-UfwRuntimeEvidence $Context}
 return $result
}
function Get-UfwCapturedLifecycleStatus($Context){
 # Necessary evidence ONLY; never an independent target/helper quiescence proof.
 $r=[ordered]@{observed_all_exits=$false;roots=0;descendants=0;open_tracked=0;quiescence_authorized=$false;code='lifecycle_unavailable'}
 try{
  if(-not $Context.window_attempted -or $null -eq $Context.batch -or $null -eq $Context.capture_result){throw 'lifecycle_unavailable'}
  $result=$Context.capture_result
  if($result.capture_interrupted -or -not $result.audit_restore_verified -or $result.audit_recovery_required -or $result.selected_file_revalidation_failed -or $Context.batch.parse_errors -ne 0){throw 'lifecycle_incomplete'}
  if(@($Context.batch.events).Count -gt 50000){throw 'lifecycle_event_cap'}
  $active=@{};$known=@{};$last=[long]0
  foreach($e in $Context.batch.events){
   $record=[long]$e.record;if($record -le $last){throw 'lifecycle_order_unknown'};$last=$record
   if($e.id -cin @(0,-1,1101,1102,1104,4719)){throw 'lifecycle_integrity_unknown'}
   if($e.id -notin @(4688,4689)){continue}
   $pidValue=[int]$e.pid;$path=[string]$e.path
   if($pidValue -le 0 -or [string]::IsNullOrWhiteSpace($path)){throw 'lifecycle_identity_unknown'}
   if($e.id -eq 4688){
    if($active.ContainsKey($pidValue)){throw 'lifecycle_pid_reuse_unknown'}
    $tracked=$false;$selected=$false
    foreach($p in $Context.record.data.programs){if([string]::Equals($path,$p.path,[StringComparison]::OrdinalIgnoreCase)){$selected=$true;break}}
    if($selected){if($e.actor -cne $Context.actor){throw 'lifecycle_actor_unknown'};$tracked=$true;$r.roots++}
    elseif($active.ContainsKey([int]$e.parent_pid) -and $active[[int]$e.parent_pid].tracked){
     if(-not [string]::Equals([string]$e.parent_path,$active[[int]$e.parent_pid].path,[StringComparison]::OrdinalIgnoreCase)){throw 'lifecycle_parent_unknown'}
     $tracked=$true;$r.descendants++
    }elseif($known.ContainsKey(([string]$e.parent_path).ToLowerInvariant())){throw 'lifecycle_orphan_unknown'}
    if($tracked){$known[$path.ToLowerInvariant()]=$true}
    $active[$pidValue]=[pscustomobject]@{path=$path;tracked=$tracked}
   }else{
    if($active.ContainsKey($pidValue)){
     if(-not [string]::Equals($path,$active[$pidValue].path,[StringComparison]::OrdinalIgnoreCase)){throw 'lifecycle_exit_identity_unknown'}
     $active.Remove($pidValue)
    }elseif($known.ContainsKey($path.ToLowerInvariant())){throw 'lifecycle_exit_without_start'}
   }
  }
  if($result.root_start_events -ne $r.roots -or $result.descendant_start_events -ne $r.descendants){throw 'lifecycle_reducer_disagrees'}
  $r.open_tracked=@($active.Values|Where-Object{$_.tracked}).Count
  $r.observed_all_exits=$r.roots -gt 0 -and $r.open_tracked -eq 0
  $r.code='lifecycle_tracked_process_still_open';if($r.observed_all_exits){$r.code='lifecycle_exits_observed_not_quiescence_authority'}elseif($r.roots -eq 0){$r.code='lifecycle_no_root_not_safety_proof'}
 }catch{$m=[string]$_.Exception.GetBaseException().Message;if($m -cmatch '^lifecycle_[a-z_]{1,70}$'){$r.code=$m}else{$r.code='lifecycle_unavailable'};$r.observed_all_exits=$false}
 return [pscustomobject]$r
}
function Test-UfwBoundRuntimeQuiescence($Context,[scriptblock]$IndependentProbe){
 # Missing native complete-enumeration/recovery witness must NOT become true.
 if($null -eq $IndependentProbe){return $false}
 $evidence=Get-UfwCapturedLifecycleStatus $Context
 if(-not $evidence.observed_all_exits){return $false}
 $ok=& $IndependentProbe $Context $evidence
 return $ok -is [bool] -and $ok
}
