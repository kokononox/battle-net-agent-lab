param([string]$SourceRoot,[string]$RuntimeHarness,[string]$RuntimeRoot,[string]$InventoryCore,[string]$LocalFixture)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. $RuntimeHarness -Root $RuntimeRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ufw-exit-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($temp)
$total=0
$modes=@('normal','cancel','wrong_answer','coverage_missing','coverage_refused','process_open','audit_drift','audit_wrong_type','audit_pending','legacy_arm','prompt_policy_drift','prompt_head_changed','prompt_actor_changed','prompt_expired','lease_expired','clock_reverse','existing_guard_refused','no_consent_restore','reopen_restore','exact_restore','audit_drift_during_restore','coverage_revoked','dispatcher_restore','dispatcher_cancel','dispatcher_audit_mismatch','dispatcher_audit_match','dispatcher_existing_refused')
try{
 foreach($mode in $modes){
  $ops=Run-Case 'normal'
  $n=& $m {
   param($src,$ops,$mode,$root,$inv,$fixture,$runtime)
   foreach($f in @('CandidateEntry.ps1','ObserverEntry.ps1','RuntimeCore.ps1','RuntimeEntry.ps1')){. (Join-Path $runtime $f)}
   . $fixture -src $src -root $root -inv $inv
   foreach($f in @('RuntimeBridge.ps1','RuntimeSession.ps1','RuntimeWitness.ps1','SessionRegistry.ps1','ProcessQuiescence.ps1','ExitReview.ps1','RecoveryFirst.ps1')){. (Join-Path $src $f)}
   $script:EC=0
   function CheckE($ok,$name){if(-not $ok){throw ('exit_test_'+$name)};$script:EC++}
   function ThrowsE($fn,$code){$got='';try{& $fn|Out-Null}catch{$got=$_.Exception.GetBaseException().Message};CheckE ($got -ceq $code) ('expected_'+$code+'_got_'+$got)}
   function Test-UfwLiveLease($c){return $true}
   $f=StartCase ('exit_'+$mode);$c=$f.ctx;$a=$f.adapters;$lease=$null
   try{
    & $a.Backup $c.view ([pscustomobject]@{binding=$c.view.binding})|Out-Null
    foreach($op in $c.view.operations){& $a.SaveIntent $null $op|Out-Null;Invoke-UfwLocalForward $c $op;& $a.SaveResult $null $op|Out-Null}
    $live=[pscustomobject]@{actor=$script:D.receipt.actor_sid;programs=$script:D.programs;view=$c.view}
    $record=& $ops.Load 'PRIVATE_CANDIDATE_PATH'
    $captureContext=New-UfwBoundRuntimeContext $ops ([pscustomobject]@{cancelled=$false;path='PRIVATE_CANDIDATE_PATH'}) $record $live
    Connect-UfwRuntimeWitness $captureContext $c.storage {return ('a'*64)}
    if($mode -ceq 'legacy_arm'){Write-UfwRuntimeArm $captureContext}else{
     $old=$ops.ReadEvents
     $ops.ReadEvents=New-UfwLocalModuleCallback {
      param($b,$start,$end,$map)
      $batch=& $b.old $start $end $map;$t=$batch.events[0].time
      $batch.events+=,[pscustomobject]@{id=4689;record=[long]104;time=$t;pid=42;path='C:\Fixture\installer.exe';parent_pid=0;parent_path='';actor=''}
      if($b.mode -cne 'process_open'){$batch.events+=,[pscustomobject]@{id=4689;record=[long]105;time=$t;pid=43;path='C:\Fixture\helper.exe';parent_pid=0;parent_path='';actor=''}}
      return $batch
     } ([pscustomobject]@{old=$old;mode=$mode})
     $capture=Invoke-UfwBoundRuntimeCapture $captureContext {param($binding)return $true}
     CheckE ($capture.audit_restore_verified -and $captureContext.witness.arm.schema -ceq 'ufw-runtime-arm-02') 'durable_original_audit_baseline'
     CheckE ((Get-UfwLocalJson $captureContext.witness.arm.audit_plan) -cmatch '"before":0') 'saved_before_not_current_during'
    }
    $script:E=[pscustomobject]@{mode=$mode;actor=$live.actor;tick=[long]1000;display=0;answer=0;coverage=0;existing=0;pending=$null;coverageOK=$true}
    $ops.Actor={return $script:E.actor};$ops.Pending={return $script:E.pending}
    $quietOps=@{
     Actor={return $script:E.actor};Boot={return ('a'*64)}
     Census={return ,@([pscustomobject]@{pid=[long]0;parent_pid=[long]0;path='';started_utc='';kernel=$true},[pscustomobject]@{pid=[long]4;parent_pid=[long]0;path='';started_utc='';kernel=$true},[pscustomobject]@{pid=[long]900;parent_pid=[long]4;path='C:\Windows\explorer.exe';started_utc='2026-10-27T07:00:00.0000000Z';kernel=$false})}
    }
    $coverage={param($phase,$view)$script:E.coverage++;return $script:E.coverageOK}
    $ui=@{
     Tick={return $script:E.tick}
     Display={param($current)$script:E.display++}
     Answer=(New-UfwLocalModuleCallback {
      param($b,$challenge)
      $script:E.answer++
      switch -CaseSensitive ($script:E.mode){
       'cancel'{return ''}
       'dispatcher_cancel'{return ''}
       'wrong_answer'{return 'RESTORE'}
       'prompt_policy_drift'{$script:B.snapshot.ActiveStore.records[0].source_path='PRIVATE_OTHER'}
       'prompt_head_changed'{Write-UfwUnifiedStorage $b.storage 'restore_intent' $b.view.operations[-1]|Out-Null}
       'prompt_actor_changed'{$script:E.actor='S-1-5-21-999'}
       'prompt_expired'{$script:E.tick=[long]122000}
      }
      return $challenge
     } $c)
    }
    if($mode -ceq 'coverage_missing'){ThrowsE {New-UfwExitReviewContext $c.storage $c.io $ops $quietOps $null $ui} 'ufw_unified_exit_coverage_required';return $script:EC}
    if($mode -ceq 'coverage_refused'){$script:E.coverageOK=$false}
    if($mode -ceq 'audit_drift'){$script:T.mask[$captureContext.witness.arm.audit_plan[0].id]=2}
    if($mode -ceq 'audit_wrong_type'){$ops.AuditQuery={param($id)return '0'}}
    if($mode -ceq 'audit_pending'){$script:E.pending=[pscustomobject]@{private='pending'}}
    if($mode -ceq 'reopen_restore'){
     Close-UfwUnifiedStorage $c.storage;$lease=Open-UfwSessionRegistry;$h=Find-UfwPendingSession $lease
     $c=New-UfwLocalBackendContext $c.io $h $c.view {return $false}
     $ops.Load={throw 'PRIVATE_NO_PICKER_OR_EXE_REOPEN'};$ops.Observe={throw 'PRIVATE_NO_CURRENT_EXE_REQUIRED'}
    }
    if($mode -cin @('dispatcher_restore','dispatcher_cancel','dispatcher_audit_mismatch','dispatcher_audit_match','dispatcher_existing_refused')){
     $auditArchives=$script:T.archives
     if($mode -cin @('dispatcher_audit_mismatch','dispatcher_audit_match')){
      $arm=$captureContext.witness.arm
      $journal=[pscustomobject][ordered]@{schema='ufw-runtime-audit-journal-01';session_id=$arm.audit_session_id;actor_sid=$arm.actor_sid;created_utc='2026-10-27 07:00:00.0000000 UTC';audit_plan=$arm.audit_plan}
      if($mode -ceq 'dispatcher_audit_mismatch'){$journal.session_id='f'*32}
      $head=Get-UfwJournalHash (Get-UfwCandidateJson $journal)
      if($mode -ceq 'dispatcher_audit_match'){CheckE ($head -ceq $arm.audit_pending_head) 'exact_original_audit_head_restored_from_fixture'}
      $script:E.pending=[pscustomobject]@{data=$journal;head=$head;readback_verified=$true}
      foreach($item in $arm.audit_plan){$script:T.mask[$item.id]=$item.during}
      $oldArchive=$ops.Archive
      $ops.Archive=New-UfwLocalModuleCallback {param($old,$pending)& $old $pending;$script:E.pending=$null} $oldArchive
     }
     Close-UfwUnifiedStorage $c.storage
     $state=[pscustomobject]@{lease=$null}
     $recover=New-UfwReviewedPolicyRecovery $c.io $ops $quietOps $coverage $ui {param($phase,$view)return $script:E.mode -cne 'dispatcher_existing_refused'}
     $bindings=New-UfwRecoveryFirstBindings $state $ops $recover
     $session=@{};foreach($key in Get-UfwUnifiedRequiredAdapters){$session[$key]={throw 'PRIVATE_NEW_SESSION_MUST_NOT_RUN'}}
     foreach($key in $bindings.Keys){$session[$key]=$bindings[$key]}
     $result=Invoke-UfwUnifiedSession $session
     CheckE ($result.mode -ceq 'recovery_only' -and -not $result.ready_for_apply -and -not $result.automatic_target_execution) 'same_coordinator_recovery_only'
     if($mode -cin @('dispatcher_restore','dispatcher_audit_match')){
      CheckE ($result.completed -and $result.restore_verified -and -not $result.pending_recovery -and $script:B.restores -eq 2) 'dispatcher_reviewed_exact_restore'
     }else{CheckE (-not $result.completed -and $result.pending_recovery -and $script:B.restores -eq 0) 'dispatcher_cancel_or_mismatch_keeps_pending'}
     CheckE ($null -eq $state.lease -and $script:E.answer -eq $(if($mode -cin @('dispatcher_audit_mismatch','dispatcher_existing_refused')){0}else{1})) 'review_once_and_release_global_lock'
     if($mode -ceq 'dispatcher_audit_mismatch'){CheckE ($result.code -ceq 'ufw_unified_witness_audit_pending_mismatch' -and $script:T.archives -eq $auditArchives) 'mismatch_before_audit_archive_or_exit_prompt'}
     if($mode -ceq 'dispatcher_audit_match'){CheckE ($null -eq $script:E.pending -and $script:T.archives -eq $auditArchives+1) 'linked_audit_recovered_before_policy_review'}
     return $script:EC
    }
    $ctx=New-UfwExitReviewContext $c.storage $c.io $ops $quietOps $coverage $ui
    $oldGuard={param($phase,$view)$script:E.existing++;return $script:E.mode -cne 'existing_guard_refused'}
    $exitGuard=New-UfwExitConsentBackendGuard $ctx $oldGuard
    $guard=New-UfwQuiescenceBackendGuard $c.storage $quietOps $exitGuard $coverage
    $backend=New-UfwLocalBackendContext $c.io $c.storage $c.view $guard
    if($mode -ceq 'no_consent_restore'){ThrowsE {Recover-UfwLocalBackend $backend} 'ufw_unified_native_bound_guard_refused';CheckE ($script:B.restores -eq 0) 'no_prompt_no_inverse';return $script:EC}
    $errors=@{coverage_refused='ufw_unified_exit_helper_coverage_unresolved';process_open='ufw_unified_exit_processes_unresolved';audit_drift='ufw_unified_exit_audit_baseline_changed';audit_wrong_type='ufw_unified_exit_audit_baseline_changed';audit_pending='ufw_unified_exit_audit_pending';legacy_arm='ufw_unified_exit_saved_audit_baseline_missing';prompt_policy_drift='ufw_unified_native_global_policy_drift';prompt_head_changed='ufw_unified_exit_changed_during_review';prompt_actor_changed='ufw_unified_exit_actor_changed';prompt_expired='ufw_unified_exit_review_expired'}
    if($errors.ContainsKey($mode)){
     ThrowsE {Invoke-UfwExitReview $ctx} $errors[$mode]
     CheckE (-not $ctx.accepted -and $ctx.revoked -and $script:B.restores -eq 0) 'refusal_no_inverse'
     if($mode -cin @('coverage_refused','process_open','audit_drift','audit_wrong_type','audit_pending','legacy_arm')){CheckE ($script:E.display -eq 0 -and $script:E.answer -eq 0) 'no_meaningless_consent_prompt'}
     return $script:EC
    }
    $consent=Invoke-UfwExitReview $ctx
    if($mode -cin @('cancel','wrong_answer')){CheckE (-not $consent -and $ctx.revoked -and -not (Test-UfwExitConsent $ctx $c.view)) 'cancel_no_authority';CheckE ($script:B.restores -eq 0) 'cancel_no_inverse';return $script:EC}
    CheckE ($consent -is [bool] -and $consent -and $script:E.display -eq 1 -and $script:E.answer -eq 1) 'explicit_local_consent_only'
    if($mode -ceq 'lease_expired'){$script:E.tick=[long]181001;CheckE (-not (Test-UfwExitConsent $ctx $c.view) -and $ctx.revoked) 'lease_expires';return $script:EC}
    if($mode -ceq 'clock_reverse'){$script:E.tick=[long]999;CheckE (-not (Test-UfwExitConsent $ctx $c.view) -and $ctx.revoked) 'monotonic_clock_required';return $script:EC}
    if($mode -ceq 'coverage_revoked'){$script:E.coverageOK=$false;ThrowsE {Recover-UfwLocalBackend $backend} 'ufw_unified_native_bound_guard_refused';CheckE ($script:B.restores -eq 0) 'coverage_rechecked_before_inverse';return $script:EC}
    if($mode -ceq 'existing_guard_refused'){ThrowsE {Recover-UfwLocalBackend $backend} 'ufw_unified_native_bound_guard_refused';CheckE ($script:B.restores -eq 0) 'existing_guard_preserved';return $script:EC}
    if($mode -ceq 'audit_drift_during_restore'){
     $original=$c.io.SetEnabled
     $c.io.SetEnabled=New-UfwLocalModuleCallback {
      param($b,$handle,$enabled)
      & $b.old $handle $enabled
      if($enabled -ceq 'True'){$script:T.mask[$b.id]=2}
     } ([pscustomobject]@{old=$original;id=$captureContext.witness.arm.audit_plan[0].id})
     ThrowsE {Recover-UfwLocalBackend $backend} 'ufw_unified_native_bound_guard_refused'
     CheckE ($script:B.restores -eq 1 -and -not (Get-UfwLocalBackendState $backend).closed -and $ctx.revoked) 'audit_drift_does_not_close_or_continue'
     return $script:EC
    }
    if($mode -cin @('exact_restore','reopen_restore')){
     CheckE (Recover-UfwLocalBackend $backend) 'same_backend_restored'
     CheckE ((Get-UfwLocalSnapshotText $script:B.snapshot) -ceq (Get-UfwLocalSnapshotText $c.view.snapshot)) 'exact_saved_baseline_not_global_allow'
     CheckE ($script:B.restores -eq 2 -and (Get-UfwLocalBackendState $backend).closed) 'only_saved_inverses_and_verified_finish'
    }else{
     CheckE ((& $guard 'recovery' $c.view) -is [bool] -and (& $guard 'recovery' $c.view)) 'composed_guards_accept_fixture'
     CheckE ($script:B.restores -eq 0) 'consent_is_not_effect'
     $native=New-UfwWindowsExitReviewUI;CheckE ($native.Count -eq 3 -and (& $native.Tick) -is [long]) 'native_local_console_adapter_scope'
    }
    return $script:EC
   }finally{if($null -ne $lease){Close-UfwSessionRegistry $lease};Close-UfwUnifiedStorage $c.storage}
  } $SourceRoot $ops $mode $temp $InventoryCore $LocalFixture $RuntimeRoot
  $total+=$n
 }
 $report=[ordered]@{passed=$true;assertions=$total;cases=$modes.Count;original_audit_baseline_persisted=$true;memory_only_exit_consent=$true;same_reopened_policy_backend=$true;no_global_Allow_or_reset=$true;native_Windows_effects_executed=$false;native_exit_UI_executed=$false;independent_helper_service_coverage_implemented=$false;ready_for_apply=$false;private_values_exported=$false}
 $report|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path (Split-Path $SourceRoot -Parent) 'evidence/exit-review-tests.json') -Encoding UTF8
 $report|ConvertTo-Json -Depth 6
}finally{Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
