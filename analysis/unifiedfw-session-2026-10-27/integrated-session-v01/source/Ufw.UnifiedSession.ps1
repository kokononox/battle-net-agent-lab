# Development integration coordinator. Not exported as a Windows Apply entrypoint.
# Private observations/receipts are returned by bound adapters, NEVER imported approval JSON.
function Get-UfwUnifiedRequiredAdapters {
 return @('Lock','Unlock','Pending','Recover','Inspect','Capabilities','Review','Refresh','Backup','SaveIntent','ObserveOperation','Mutate','VerifyOperation','SaveResult','PolicyGuard','Capture','Quiescent','ExitConsent','RestoreOperation','VerifyRestored','Finish')
}
function Assert-UfwUnifiedReceipt($Value){
 if($null -eq $Value -or $Value.readback_verified -isnot [bool] -or -not $Value.readback_verified -or $Value.head -isnot [string] -or $Value.head -cnotmatch '^[a-f0-9]{64}$'){throw 'ufw_unified_checkpoint_unverified'}
}
function Assert-UfwUnifiedPlan($View){
 if($null -eq $View -or $View.binding -isnot [string] -or $View.binding -cnotmatch '^[a-f0-9]{64}$' -or $View.operations -isnot [array] -or $View.operations.Count -gt 512){throw 'ufw_unified_plan_shape'}
 $ids=@{};$quarantineStarted=$false
 foreach($op in $View.operations){
  if($op.id -isnot [string] -or $op.id -cnotmatch '^[a-z0-9_-]{1,64}$' -or $ids.ContainsKey($op.id) -or $op.kind -cnotin @('create_disabled_transport','enable_owned_transport','disable_reviewed_local_allow')){throw 'ufw_unified_operation_scope'}
  $ids[$op.id]=$true
  if($op.kind -ceq 'disable_reviewed_local_allow'){$quarantineStarted=$true}elseif($quarantineStarted){throw 'ufw_unified_transport_order'}
  if($op.PSObject.Properties.Name -cnotcontains 'before' -or $op.PSObject.Properties.Name -cnotcontains 'after'){throw 'ufw_unified_operation_snapshot_missing'}
 }
}
function Get-UfwUnifiedBlockers($Capabilities){
 # These are independent native qualification gates, not booleans loaded from a user file.
 $keys=@('private_snapshot_readback','live_semantic_local_effective_match','current_profile_Block','exact_SSTP_transport_review','warm_SSTP_operating_scope','network_independent_recovery','documented_threat_scope','scoped_native_policy_writer','scoped_native_restore','capture_adapter_binding')
 $missing=@()
 foreach($key in $keys){if($null -eq $Capabilities -or $Capabilities.PSObject.Properties.Name -cnotcontains $key -or $Capabilities.$key -isnot [string] -or $Capabilities.$key -cne 'qualified'){$missing+=$key}}
 return ,$missing
}
function Invoke-UfwUnifiedSession($Ops){
 $r=[ordered]@{schema='ufw-unified-session-result-01';completed=$false;stage='adapter_binding';code='';blockers=@();mode='session';lock_acquired=$false;review_received=$false;backup_readback_verified=$false;policy_intents_saved=0;policy_effects_verified=0;capture_requested=$false;capture_completed=$false;audit_recovery_required=$false;restore_requested=$false;restore_verified=$false;pending_recovery=$false;policy_restore_operations=0;policy_change_attempted=$false;raw_identity_exported=$false;automatic_target_execution=$false;application_grants_added=0;profile_defaults_changed=$false;ready_for_apply=$false;no_leak_certified=$false}
 $locked=$false;$backup=$null;$view=$null;$intents=@();$captured=$null;$journalUncertain=$false
 try{
  do{
  foreach($name in Get-UfwUnifiedRequiredAdapters){if(-not $Ops.ContainsKey($name) -or $Ops[$name] -isnot [scriptblock]){throw 'ufw_unified_adapter_missing'}}
  $lock=& $Ops.Lock;if($lock -isnot [bool] -or -not $lock){throw 'ufw_unified_session_busy'};$locked=$true;$r.lock_acquired=$true
  $r.stage='pending_recovery'
  $pending=& $Ops.Pending
  if($null -ne $pending){
   $r.mode='recovery_only';$r.pending_recovery=$true;$recovered=& $Ops.Recover $pending
   if($recovered.completed -isnot [bool] -or $recovered.restored -isnot [bool] -or -not $recovered.completed -or -not $recovered.restored){throw 'ufw_unified_pending_recovery_unresolved'}
   $r.restore_verified=$true;$r.pending_recovery=$false;$r.completed=$true;$r.stage='completed';$r.code='ufw_unified_recovered_no_new_session';break
  }
  $r.stage='native_qualification_gates';$cap=& $Ops.Capabilities;$r.blockers=Get-UfwUnifiedBlockers $cap
  if($r.blockers.Count -gt 0){$r.code='ufw_unified_native_prerequisites_unresolved';break}
  $r.stage='inspect_existing_local_state';$view=& $Ops.Inspect;Assert-UfwUnifiedPlan $view
  $r.stage='combined_local_review';$answer=& $Ops.Review $view
  if($answer.cancelled -isnot [bool]){throw 'ufw_unified_review_shape'}
  if($answer.cancelled){$r.completed=$true;$r.code='ufw_unified_cancelled_no_policy_change';break}
  if($answer.binding -isnot [string] -or $answer.binding -cne $view.binding){throw 'ufw_unified_review_binding_changed'};$r.review_received=$true
  # Bound adapter checks actor, monotonic expiry, exact file identity and full current policy.
  $r.stage='fresh_before_backup';$fresh=& $Ops.Refresh $view $answer $backup $intents
  if($fresh -isnot [bool] -or -not $fresh){throw 'ufw_unified_freshness_failed'}
  $r.stage='backup_and_readback';$r.pending_recovery=$true;$backup=& $Ops.Backup $view $answer;Assert-UfwUnifiedReceipt $backup;$r.backup_readback_verified=$true
  foreach($op in $view.operations){
   $r.stage='policy_intent_before_effect';$journalUncertain=$true;$intent=& $Ops.SaveIntent $backup $op;Assert-UfwUnifiedReceipt $intent;$journalUncertain=$false
   $intents+=,[pscustomobject]@{operation=$op;intent=$intent};$r.policy_intents_saved++
   $r.stage='observe_policy_operation';$status=& $Ops.ObserveOperation $op
   if($status -isnot [string] -or $status -cne 'exact_before'){throw 'ufw_unified_before_state_drift'}
   # Recheck consent/target/transport immediately before every potential native effect.
   $fresh=& $Ops.Refresh $view $answer $backup $intents;if($fresh -isnot [bool] -or -not $fresh){throw 'ufw_unified_freshness_failed'}
   $r.stage='apply_scoped_policy_operation';$r.policy_change_attempted=$true;& $Ops.Mutate $op
   $r.stage='verify_scoped_policy_effect';$verified=& $Ops.VerifyOperation $op
   if($verified -isnot [bool] -or -not $verified){throw 'ufw_unified_effect_unverified'};$r.policy_effects_verified++
   $journalUncertain=$true;$entry=& $Ops.SaveResult $backup $op;Assert-UfwUnifiedReceipt $entry;$journalUncertain=$false
  }
  $r.stage='verify_restricted_policy';$safe=& $Ops.PolicyGuard $view
  if($safe -isnot [bool] -or -not $safe){throw 'ufw_unified_policy_guard_refused'}
  $r.stage='runtime_capture_and_scoped_audit_restore';$r.capture_requested=$true
  $r.audit_recovery_required=$true;$captured=& $Ops.Capture $view $answer
  if($captured.audit_recovery_required -isnot [bool]){throw 'ufw_unified_capture_receipt_shape'}
  $r.audit_recovery_required=$captured.audit_recovery_required
  if($captured.completed -isnot [bool] -or -not $captured.completed -or $captured.audit_recovery_required -or $captured.capture_window_completed -isnot [bool] -or -not $captured.capture_window_completed -or $captured.audit_restore_verified -isnot [bool] -or -not $captured.audit_restore_verified){throw 'ufw_unified_capture_incomplete'}
  $r.capture_completed=$true;$r.code='ufw_unified_capture_done_policy_restore_pending'
  }while($false)
 }catch{
  $message=[string]$_.Exception.GetBaseException().Message
  if($message -cmatch '^ufw_unified_[a-z_0-9]{1,90}$'){$r.code=$message}else{$r.code='ufw_unified_stage_failed'}
 }finally{
  # Capture may have allowed MANUAL target launch. Never reopen old foreign grants
  # until target/helpers are independently quiescent and local exit consent is bound.
  if($null -ne $backup -and $r.backup_readback_verified){
   try{
    if($journalUncertain){throw 'ufw_unified_journal_recovery_pending'}
    $r.stage='quiescence_before_policy_restore';$quiet=& $Ops.Quiescent $view $captured
    if($quiet -isnot [bool] -or -not $quiet){throw 'ufw_unified_target_active_recovery_pending'}
    if($r.audit_recovery_required){throw 'ufw_unified_audit_recovery_before_policy_restore'}
    $permit=& $Ops.ExitConsent $view $answer
    if($permit -isnot [bool] -or -not $permit){throw 'ufw_unified_exit_consent_missing_recovery_pending'}
    $r.stage='restore_only_session_policy_intents';$r.restore_requested=$true
    for($i=$intents.Count-1;$i -ge 0;$i--){
     # Adapter reconciles before/after from this exact SAVED intent, journals each
     # inverse before effect, and refuses drift. Unknown effect is NOT skipped.
     $restored=& $Ops.RestoreOperation $backup $intents[$i]
     if($restored -isnot [bool] -or -not $restored){throw 'ufw_unified_policy_restore_unverified'};$r.policy_restore_operations++
    }
    $restored=& $Ops.VerifyRestored $backup $view
    if($restored -isnot [bool] -or -not $restored){throw 'ufw_unified_baseline_restore_unverified'}
    $finished=& $Ops.Finish $backup;Assert-UfwUnifiedReceipt $finished
    $r.restore_verified=$true;$r.pending_recovery=$false
    if($r.capture_completed){$r.completed=$true;$r.code='ufw_unified_capture_and_policy_restore_completed';$r.stage='completed'}
   }catch{$r.completed=$false;$r.pending_recovery=$true;$message=[string]$_.Exception.GetBaseException().Message;if($message -cmatch '^ufw_unified_[a-z_0-9]{1,90}$'){$r.code=$message}else{$r.code='ufw_unified_policy_recovery_required'}}
  }
  if($locked){try{& $Ops.Unlock}catch{$r.completed=$false;$r.code='ufw_unified_unlock_failed'}}
 }
 return [pscustomobject]$r
}
