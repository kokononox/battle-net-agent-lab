# Witness payloads are PRIVATE evidence, never quiescence/restore authority.
function Assert-UfwRuntimeWitnessPayload($Data,[string]$Kind,[string]$Binding,$Arm){
 if($Kind -ceq 'runtime_arm'){
  $fields='actor_sid,boot_marker,candidate_head,phase,programs_json,programs_sha256,schema,view_binding'
  if($Data.schema -ceq 'ufw-runtime-arm-02'){
   $fields='actor_sid,audit_pending_head,audit_plan,audit_session_id,boot_marker,candidate_head,phase,programs_json,programs_sha256,schema,view_binding'
   # The pinned runtime validator is required when opening v02 journals, not a
   # replacement validator or user-supplied approval. It performs no native writes.
   Assert-UfwRuntimeAuditPlan $Data.audit_plan
   if($Data.audit_pending_head -isnot [string] -or $Data.audit_pending_head -cnotmatch '^[a-f0-9]{64}$' -or $Data.audit_session_id -isnot [string] -or $Data.audit_session_id -cnotmatch '^[a-f0-9]{32}$'){throw 'ufw_unified_witness_audit_binding'}
  }elseif($Data.schema -cne 'ufw-runtime-arm-01'){throw 'ufw_unified_witness_arm_shape'}
  if((@($Data.PSObject.Properties.Name|Sort-Object)-join ',') -cne $fields -or $Data.phase -cne 'manual_window_may_open' -or $Data.view_binding -cne $Binding){throw 'ufw_unified_witness_arm_shape'}
  if($Data.actor_sid -isnot [string] -or $Data.actor_sid -cnotmatch '^S-1-[0-9]+(-[0-9]+)+$'){throw 'ufw_unified_witness_actor'}
  foreach($k in @('boot_marker','candidate_head','programs_sha256','view_binding')){if($Data.$k -isnot [string] -or $Data.$k -cnotmatch '^[a-f0-9]{64}$'){throw 'ufw_unified_witness_binding'}}
  if($Data.programs_json -isnot [string] -or -not $Data.programs_json.StartsWith('[') -or $Data.programs_json.Length -gt 262144 -or (Get-UfwJournalHash $Data.programs_json) -cne $Data.programs_sha256){throw 'ufw_unified_witness_programs'}
  $programs=ConvertFrom-Json $Data.programs_json
  if(@($programs).Count -lt 1 -or @($programs).Count -gt 16){throw 'ufw_unified_witness_programs'}
 }elseif($Kind -ceq 'runtime_evidence'){
  if($null -eq $Arm -or (@($Data.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'arm_sha256,audit_restore_verified,capture_code,capture_completed,capture_interrupted,events_json,events_sha256,parse_errors,schema' -or $Data.schema -cne 'ufw-runtime-evidence-01' -or $Data.arm_sha256 -cne (Get-UfwJournalHash (Get-UfwLocalJson $Arm))){throw 'ufw_unified_witness_evidence_shape'}
  foreach($k in @('audit_restore_verified','capture_completed','capture_interrupted')){if($Data.$k -isnot [bool]){throw 'ufw_unified_witness_evidence_shape'}}
  if(($Data.parse_errors -isnot [int] -and $Data.parse_errors -isnot [long]) -or $Data.parse_errors -lt 0 -or $Data.capture_code -isnot [string] -or $Data.capture_code -cnotmatch '^[a-z][a-z0-9_]{0,120}$'){throw 'ufw_unified_witness_evidence_shape'}
  if($Data.events_json -isnot [string] -or -not $Data.events_json.StartsWith('[') -or $Data.events_json.Length -gt 2097152 -or $Data.events_sha256 -isnot [string] -or $Data.events_sha256 -cnotmatch '^[a-f0-9]{64}$' -or (Get-UfwJournalHash $Data.events_json) -cne $Data.events_sha256){throw 'ufw_unified_witness_events'}
  $events=ConvertFrom-Json $Data.events_json
  if(@($events).Count -gt 8192){throw 'ufw_unified_witness_events'}
  $last=[long]0
  foreach($e in $events){
   if((@($e.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'actor,id,parent_path,parent_pid,path,pid,record'){throw 'ufw_unified_witness_events'}
   foreach($k in @('id','record','pid','parent_pid')){if(($e.$k -isnot [int] -and $e.$k -isnot [long]) -or $e.$k -lt 0){throw 'ufw_unified_witness_events'}}
   if($e.id -notin @(4688,4689,1101,1102,1104,4719) -or $e.record -le $last -or $e.pid -gt [int]::MaxValue -or $e.parent_pid -gt [int]::MaxValue){throw 'ufw_unified_witness_events'};$last=$e.record
   foreach($k in @('actor','path','parent_path')){if($e.$k -isnot [string] -or $e.$k.Length -gt 32760){throw 'ufw_unified_witness_events'}}
   if($e.id -in @(4688,4689) -and ($e.pid -lt 1 -or $e.path -cnotmatch '^[A-Za-z]:\\')){throw 'ufw_unified_witness_events'}
   if($e.id -eq 4688 -and $e.actor -cnotmatch '^S-1-[0-9]+(-[0-9]+)+$'){throw 'ufw_unified_witness_events'}
  }
 }else{throw 'ufw_unified_witness_kind'}
}
# PRIVATE backend; local mode is preserved, mixed mode uses MixedPolicyBackend.ps1.
# Human review, native SSTP observation and integrated live UI are not faked here.
# Actual native IO is injectable for internal tests; this is not an admin sandbox.
function Assert-UfwLocalBackendView($View){
 if($View.scope -ceq 'mixed_transport_quarantine_backend_development'){Assert-UfwMixedBackendView $View;return}
 if($View.scope -cne 'local_quarantine_backend_development' -or $View.binding -cne (Get-UfwJournalHash (Get-UfwLocalSnapshotText $View.snapshot))){throw 'ufw_unified_native_view_binding'}
 $expected=New-UfwLocalQuarantineOperations $View.snapshot
 if((Get-UfwLocalJson $expected) -cne (Get-UfwLocalJson $View.operations)){throw 'ufw_unified_native_plan_changed'}
}
function New-UfwLocalBackendView($Snapshot){
 return [pscustomobject]@{scope='local_quarantine_backend_development';binding=(Get-UfwJournalHash (Get-UfwLocalSnapshotText $Snapshot));snapshot=(Copy-UfwLocalData $Snapshot);operations=(New-UfwLocalQuarantineOperations $Snapshot)}
}
function Get-UfwLocalBackendState($Context){
 Assert-UfwLocalBackendView $Context.view
 $back=Read-UfwUnifiedStorage $Context.storage
 if($back.sequence -ne $Context.storage.sequence -or $back.head -cne $Context.storage.head -or $back.sequence -lt 1){throw 'ufw_unified_native_checkpoint_head'}
 if((Get-UfwLocalJson $back.records[0].data) -cne (Get-UfwLocalJson $Context.view)){throw 'ufw_unified_native_checkpoint_baseline'}
 $saved=@();$results=0;$restoreStarted=$false;$restoring=$null;$restored=0;$closed=$false;$materialized=@{};$runtimeArm=$null;$runtimeEvidence=$null
 for($i=1;$i -lt $back.records.Count;$i++){
  $entry=$back.records[$i]
  switch -CaseSensitive ($entry.kind){
   'intent'{
    if($restoreStarted -or $saved.Count -ne $results -or $saved.Count -ge $Context.view.operations.Count -or (Get-UfwLocalJson $entry.data) -cne (Get-UfwLocalJson $Context.view.operations[$saved.Count])){throw 'ufw_unified_native_intent_order'}
    $saved+=,$entry.data
   }
   'result'{
    $opData=$entry.data
    if($saved.Count -eq $results+1 -and $saved[$results].kind -ceq 'create_disabled_transport'){
     if((@($entry.data.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'observed,operation'){throw 'ufw_unified_transport_result_materialization'}
     $opData=$entry.data.operation
     Assert-UfwOwnedPair $entry.data.observed $Context.view.transport 'False'
     $materialized[$saved[$results].name]=$entry.data.observed
    }
    if($restoreStarted -or $saved.Count -ne $results+1 -or (Get-UfwLocalJson $opData) -cne (Get-UfwLocalJson $saved[$results])){throw 'ufw_unified_native_result_order'};$results++
   }
   'runtime_arm'{
    if($restoreStarted -or $null -ne $runtimeArm -or $saved.Count -ne $Context.view.operations.Count -or $results -ne $saved.Count){throw 'ufw_unified_witness_arm_order'}
    Assert-UfwRuntimeWitnessPayload $entry.data 'runtime_arm' $Context.view.binding $null;$runtimeArm=$entry.data
   }
   'runtime_evidence'{
    if($restoreStarted -or $null -eq $runtimeArm -or $null -ne $runtimeEvidence){throw 'ufw_unified_witness_evidence_order'}
    Assert-UfwRuntimeWitnessPayload $entry.data 'runtime_evidence' $Context.view.binding $runtimeArm;$runtimeEvidence=$entry.data
   }
   'restore_intent'{
    if($null -ne $restoring -or $restored -ge $saved.Count -or (Get-UfwLocalJson $entry.data) -cne (Get-UfwLocalJson $saved[$saved.Count-1-$restored])){throw 'ufw_unified_native_restore_order'}
    $restoreStarted=$true;$restoring=$entry.data
   }
   'restore_result'{
    if($null -eq $restoring -or (Get-UfwLocalJson $entry.data) -cne (Get-UfwLocalJson $restoring)){throw 'ufw_unified_native_restore_result_order'};$restoring=$null;$restored++
   }
   'restored'{if($entry.data.verified -isnot [bool] -or -not $entry.data.verified -or $restored -ne $saved.Count -or $null -ne $restoring){throw 'ufw_unified_native_close_order'};$closed=$true}
   default{throw 'ufw_unified_native_checkpoint_protocol'}
  }
 }
 return [pscustomobject]@{saved=$saved;results=$results;restore_started=$restoreStarted;restoring=$restoring;restored=$restored;closed=$closed;materialized=$materialized;runtime_arm=$runtimeArm;runtime_evidence=$runtimeEvidence}
}
function Get-UfwLocalExpectedSnapshot($Context,$Applied){
 $expected=Copy-UfwLocalData $Context.view.snapshot
 foreach($op in $Applied){
  foreach($pair in @(@('PersistentStore','local'),@('ActiveStore','effective'))){
   $map=Get-UfwLocalRecordMap $expected.($pair[0]).records
   if(-not $map.ContainsKey($op.name)){throw 'ufw_unified_native_expected_rule_missing'}
   $old=$map[$op.name];$new=$op.after.($pair[1]);$old.enabled=$new.enabled;$old.record.rule.properties.Enabled.value=$new.record.rule.properties.Enabled.value
  }
 }
 return $expected
}
function Assert-UfwLocalBackendGuard($Context,[string]$Phase){
 # Unimplemented review/transport/quiescence/native qualification must remain unbound,
 # not replaced by a flag read from a user snapshot or a fake success in production.
 $permit=& $Context.guard $Phase $Context.view
 if($permit -isnot [bool] -or -not $permit){throw 'ufw_unified_native_bound_guard_refused'}
}
function Get-UfwLocalReconciledObservation($Context,$State){
 if($Context.view.scope -ceq 'mixed_transport_quarantine_backend_development'){return Get-UfwMixedReconciledObservation $Context $State}
 $count=$State.saved.Count-$State.restored
 $applied=@();for($i=0;$i -lt $count;$i++){$applied+=,$State.saved[$i]}
 $read=Read-UfwLocalStableSnapshot $Context.io;$text=Get-UfwLocalSnapshotText $read.snapshot
 $after=Get-UfwLocalExpectedSnapshot $Context $applied
 if($text -ceq (Get-UfwLocalSnapshotText $after)){return [pscustomobject]@{read=$read;applied=$applied;tail_applied=($count -gt 0)}}
 # Only the most recent saved intent can have an unknown effect. Earlier completed
 # operations must remain applied unless individually restored in reverse order.
 if($count -gt 0 -and ($State.results -lt $State.saved.Count -or $null -ne $State.restoring)){
  $less=@();for($i=0;$i -lt $count-1;$i++){$less+=,$applied[$i]}
  if($text -ceq (Get-UfwLocalSnapshotText (Get-UfwLocalExpectedSnapshot $Context $less))){return [pscustomobject]@{read=$read;applied=$less;tail_applied=$false}}
 }
 throw 'ufw_unified_native_global_policy_drift'
}
function Invoke-UfwLocalForward($Context,$Operation){
 Assert-UfwLocalBackendGuard $Context 'forward'
 $state=Get-UfwLocalBackendState $Context
 if($state.closed -or $state.restore_started -or $state.saved.Count -ne $state.results+1 -or (Get-UfwLocalJson $Operation) -cne (Get-UfwLocalJson $state.saved[-1])){throw 'ufw_unified_native_forward_intent_missing'}
 $obs=Get-UfwLocalReconciledObservation $Context $state
 if($obs.tail_applied){throw 'ufw_unified_native_forward_not_exact_before'}
 if($Operation.kind -cne 'create_disabled_transport' -and -not $obs.read.handles.ContainsKey($Operation.name)){throw 'ufw_unified_native_fresh_handle_missing'}
 Assert-UfwLocalBackendGuard $Context 'immediately_before_forward'
 switch -CaseSensitive ($Operation.kind){
  'create_disabled_transport'{& $Context.io.CreateTransport $Context.view.transport}
  'enable_owned_transport'{& $Context.io.SetEnabled $obs.read.handles[$Operation.name] 'True'}
  'disable_reviewed_local_allow'{& $Context.io.SetEnabled $obs.read.handles[$Operation.name] 'False'}
  default{throw 'ufw_unified_transport_mutation_kind'}
 }
 # Failure after effect is intentionally not swallowed. SAVED intent owns recovery.
 $check=Get-UfwLocalReconciledObservation $Context $state
 if(-not $check.tail_applied){throw 'ufw_unified_native_forward_readback'}
}
function Restore-UfwLocalSavedOperation($Context,$Operation){
 Assert-UfwLocalBackendGuard $Context 'restore'
 $state=Get-UfwLocalBackendState $Context;$count=$state.saved.Count-$state.restored
 if($state.closed -or $count -lt 1 -or (Get-UfwLocalJson $Operation) -cne (Get-UfwLocalJson $state.saved[$count-1])){throw 'ufw_unified_native_restore_saved_intent_missing'}
 if($null -eq $state.restoring){Write-UfwUnifiedStorage $Context.storage 'restore_intent' $Operation|Out-Null;$state=Get-UfwLocalBackendState $Context}
 $obs=Get-UfwLocalReconciledObservation $Context $state
 if($obs.tail_applied){
  if(-not $obs.read.handles.ContainsKey($Operation.name)){throw 'ufw_unified_native_fresh_handle_missing'}
  Assert-UfwLocalBackendGuard $Context 'immediately_before_restore'
  switch -CaseSensitive ($Operation.kind){
   'create_disabled_transport'{& $Context.io.RemoveOwned $obs.read.handles[$Operation.name] $Context.view.transport}
   'enable_owned_transport'{& $Context.io.SetEnabled $obs.read.handles[$Operation.name] 'False'}
   'disable_reviewed_local_allow'{& $Context.io.SetEnabled $obs.read.handles[$Operation.name] 'True'}
   default{throw 'ufw_unified_transport_restore_kind'}
  }
 }
 $check=Get-UfwLocalReconciledObservation $Context $state
 if($check.tail_applied){throw 'ufw_unified_native_restore_readback'}
 Write-UfwUnifiedStorage $Context.storage 'restore_result' $Operation|Out-Null
 return $true
}
function Recover-UfwLocalBackend($Context){
 # Local, network-independent journal reconciliation, not yet a public Windows recovery UI.
 # Caller must bind audit-clean/quiescent/exit-consent guards before this can run.
 Assert-UfwLocalBackendGuard $Context 'recovery'
 $state=Get-UfwLocalBackendState $Context
 if($state.closed){
  $fresh=Read-UfwLocalStableSnapshot $Context.io
  if((Get-UfwLocalSnapshotText $fresh.snapshot) -cne (Get-UfwLocalSnapshotText $Context.view.snapshot)){throw 'ufw_unified_native_closed_baseline_drift'}
  Assert-UfwLocalBackendGuard $Context 'finish'
  return $true
 }
 for($i=$state.saved.Count-1-$state.restored;$i -ge 0;$i--){[void](Restore-UfwLocalSavedOperation $Context $state.saved[$i])}
 Assert-UfwLocalBackendGuard $Context 'finish'
 $fresh=Read-UfwLocalStableSnapshot $Context.io
 if((Get-UfwLocalSnapshotText $fresh.snapshot) -cne (Get-UfwLocalSnapshotText $Context.view.snapshot)){throw 'ufw_unified_native_recovery_baseline_drift'}
 # Recheck actor/audit/consent after the potentially slow final policy read.
 Assert-UfwLocalBackendGuard $Context 'finish'
 Write-UfwUnifiedStorage $Context.storage 'restored' ([pscustomobject]@{verified=$true})|Out-Null
 return $true
}
function New-UfwLocalBackendContext($IO,$Storage,$View,[scriptblock]$Guard){
 if($null -eq $Guard -or -not $IO.ContainsKey('SetEnabled') -or $IO.SetEnabled -isnot [scriptblock]){throw 'ufw_unified_native_backend_binding_missing'}
 Assert-UfwLocalBackendView $View
 if($View.scope -ceq 'mixed_transport_quarantine_backend_development'){
  if($Storage.id -cne $View.transport.session_id){throw 'ufw_unified_transport_storage_binding'}
  foreach($k in @('CreateTransport','RemoveOwned')){if(-not $IO.ContainsKey($k) -or $IO[$k] -isnot [scriptblock]){throw 'ufw_unified_transport_io_binding'}}
 }
 return [pscustomobject]@{io=$IO;storage=$Storage;view=(Copy-UfwLocalData $View);guard=$Guard}
}
function New-UfwLocalModuleCallback([scriptblock]$Body,$Bound){
 $owner=$ExecutionContext.SessionState.Module
 if($null -eq $owner){throw 'ufw_unified_native_private_module_required'}
 # GetNewClosure alone creates a dynamic module that cannot resolve the existing
 # journal's PRIVATE helper functions. Re-enter their owning module explicitly.
 return {& $owner $Body $Bound @args}.GetNewClosure()
}
function New-UfwLocalCoordinatorBindings($Context){
 # Merge into the EXISTING coordinator. Transport uses the same journal grammar;
 # human review, runtime, quiescence and qualification adapters are not invented.
 $c=$Context
 return @{
  Backup=(New-UfwLocalModuleCallback {param($c,$view,$answer)
   Assert-UfwLocalBackendGuard $c 'backup'
   if((Get-UfwLocalJson $view) -cne (Get-UfwLocalJson $c.view) -or $answer.binding -cne $view.binding -or $c.storage.sequence -ne 0){throw 'ufw_unified_native_backup_binding'}
   Write-UfwUnifiedStorage $c.storage 'baseline' $c.view
  } $c)
  SaveIntent=(New-UfwLocalModuleCallback {param($c,$backup,$op)
   $s=Get-UfwLocalBackendState $c
   if($s.closed -or $s.restore_started -or $s.results -ne $s.saved.Count -or $s.saved.Count -ge $c.view.operations.Count -or (Get-UfwLocalJson $op) -cne (Get-UfwLocalJson $c.view.operations[$s.saved.Count])){throw 'ufw_unified_native_save_intent_order'}
   Write-UfwUnifiedStorage $c.storage 'intent' $op
  } $c)
  ObserveOperation=(New-UfwLocalModuleCallback {param($c,$op)
   $s=Get-UfwLocalBackendState $c
   if($s.saved.Count -lt 1 -or $s.results -ne $s.saved.Count-1 -or (Get-UfwLocalJson $op) -cne (Get-UfwLocalJson $s.saved[-1])){return 'unknown'}
   $o=Get-UfwLocalReconciledObservation $c $s
   if(-not $o.tail_applied){return 'exact_before'};return 'unknown'
  } $c)
  Mutate=(New-UfwLocalModuleCallback {param($c,$op)Invoke-UfwLocalForward $c $op} $c)
  VerifyOperation=(New-UfwLocalModuleCallback {param($c,$op)
   $s=Get-UfwLocalBackendState $c
   if($s.saved.Count -lt 1 -or (Get-UfwLocalJson $op) -cne (Get-UfwLocalJson $s.saved[-1])){return $false}
   $o=Get-UfwLocalReconciledObservation $c $s;return $o.tail_applied
  } $c)
  SaveResult=(New-UfwLocalModuleCallback {param($c,$backup,$op)
   $s=Get-UfwLocalBackendState $c
   if($s.closed -or $s.restore_started -or $s.results -ne $s.saved.Count-1 -or (Get-UfwLocalJson $op) -cne (Get-UfwLocalJson $s.saved[-1])){throw 'ufw_unified_native_save_result_order'}
   $o=Get-UfwLocalReconciledObservation $c $s;if(-not $o.tail_applied){throw 'ufw_unified_native_save_result_effect'}
   $data=$op
   if($op.kind -ceq 'create_disabled_transport'){
    if($null -eq $o.owned_pair){throw 'ufw_unified_transport_materialization_missing'}
    $data=[pscustomobject]@{operation=$op;observed=$o.owned_pair}
   }
   Write-UfwUnifiedStorage $c.storage 'result' $data
  } $c)
  RestoreOperation=(New-UfwLocalModuleCallback {param($c,$backup,$intent)Restore-UfwLocalSavedOperation $c $intent.operation} $c)
  VerifyRestored=(New-UfwLocalModuleCallback {param($c,$backup,$view)
   $s=Get-UfwLocalBackendState $c
   if($s.restored -ne $s.saved.Count -or $null -ne $s.restoring){return $false}
   $read=Read-UfwLocalStableSnapshot $c.io
   return (Get-UfwLocalSnapshotText $read.snapshot) -ceq (Get-UfwLocalSnapshotText $c.view.snapshot)
  } $c)
  Finish=(New-UfwLocalModuleCallback {param($c,$backup)
   $s=Get-UfwLocalBackendState $c
   if($s.closed -or $s.restored -ne $s.saved.Count -or $null -ne $s.restoring){throw 'ufw_unified_native_finish_order'}
   Assert-UfwLocalBackendGuard $c 'finish';$read=Read-UfwLocalStableSnapshot $c.io
   if((Get-UfwLocalSnapshotText $read.snapshot) -cne (Get-UfwLocalSnapshotText $c.view.snapshot)){throw 'ufw_unified_native_finish_drift'}
   Assert-UfwLocalBackendGuard $c 'finish'
   Write-UfwUnifiedStorage $c.storage 'restored' ([pscustomobject]@{verified=$true})
  } $c)
 }
}
