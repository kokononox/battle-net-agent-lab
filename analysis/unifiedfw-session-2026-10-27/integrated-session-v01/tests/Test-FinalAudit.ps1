param([string]$SourceRoot,[string]$RuntimeHarness,[string]$RuntimeRoot,[string]$InventoryCore,[string]$LocalFixture)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. $RuntimeHarness -Root $RuntimeRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ufw-final-audit-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($temp)
$total=0
$modes=@('normal','pre_drift','pre_string','late_drift','late_string','late_actor','late_pending','query_actor_drift','query_pending_drift','final_snapshot_drift','coordinator_finish_snapshot_drift','closed_snapshot_drift')
try{
 foreach($mode in $modes){
  $ops=Run-Case 'normal'
  $n=& $m {
   param($src,$ops,$mode,$root,$inv,$fixture,$runtime)
   foreach($f in @('CandidateEntry.ps1','ObserverEntry.ps1','RuntimeCore.ps1','RuntimeEntry.ps1')){. (Join-Path $runtime $f)}
   . $fixture -src $src -root $root -inv $inv
   foreach($f in @('RuntimeBridge.ps1','RuntimeSession.ps1','RuntimeWitness.ps1','SessionRegistry.ps1','ProcessQuiescence.ps1','ExitReview.ps1','RecoveryFirst.ps1')){. (Join-Path $src $f)}
   $script:EC=0
   function CheckE($ok,$name){if(-not $ok){throw ('final_audit_test_'+$name)};$script:EC++}
   function ThrowsE($fn,$code){$got='';try{& $fn|Out-Null}catch{$got=$_.Exception.GetBaseException().Message};CheckE ($got -ceq $code) ('expected_'+$code+'_got_'+$got)}
   function Test-UfwLiveLease($c){return $true}
   $f=StartCase ('final_audit_'+$mode);$c=$f.ctx;$a=$f.adapters;$lease=$null
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

    $id=$captureContext.witness.arm.audit_plan[0].id
    $script:F=[pscustomobject]@{phase='';callbacks=0;queryCalls=0;closed=$false;id=$id;mode=$mode}
    if($mode -cin @('final_snapshot_drift','coordinator_finish_snapshot_drift','closed_snapshot_drift')){
     $ctx=New-UfwExitReviewContext $c.storage $c.io $ops $quietOps $coverage $ui
     $oldGuard={param($phase,$view)$script:F.phase=$phase;return $true}
     $exitGuard=New-UfwExitConsentBackendGuard $ctx $oldGuard
     $guard=New-UfwQuiescenceBackendGuard $c.storage $quietOps $exitGuard $coverage
     $backend=New-UfwLocalBackendContext $c.io $c.storage $c.view $guard
     CheckE (Invoke-UfwExitReview $ctx) 'consent_before_test'
     if($mode -ceq 'closed_snapshot_drift'){CheckE (Recover-UfwLocalBackend $backend) 'first_exact_restore_closed'}
     if($mode -ceq 'coordinator_finish_snapshot_drift'){
      foreach($op in @($c.view.operations[-1],$c.view.operations[0])){CheckE (Restore-UfwLocalSavedOperation $backend $op) 'saved_inverse'}
     }
     $oldRead=$c.io.ReadStore
     $c.io.ReadStore=New-UfwLocalModuleCallback {
      param($old,$store)
      $result=& $old $store
      if(($script:F.mode -ceq 'closed_snapshot_drift' -or $script:F.phase -ceq 'finish') -and $script:B.restores -eq 2){$script:T.mask[$script:F.id]=2}
      return $result
     } $oldRead
     if($mode -ceq 'coordinator_finish_snapshot_drift'){
      $bindings=New-UfwLocalCoordinatorBindings $backend
      ThrowsE {& $bindings.Finish $null} 'ufw_unified_native_bound_guard_refused'
     }else{ThrowsE {Recover-UfwLocalBackend $backend} 'ufw_unified_native_bound_guard_refused'}
     CheckE ($script:B.restores -eq 2 -and $ctx.revoked) 'late_drift_revokes_no_extra_inverse'
     CheckE ((Get-UfwLocalBackendState $backend).closed -eq ($mode -ceq 'closed_snapshot_drift')) 'no_new_false_terminal_record'
     return $script:EC
    }
    if($mode -ceq 'pre_drift'){$script:T.mask[$id]=2}
    if($mode -ceq 'pre_string'){$ops.AuditQuery={param($id)return '0'}}
    if($mode -cin @('query_actor_drift','query_pending_drift')){
     $oldQuery=$ops.AuditQuery
     $ops.AuditQuery=New-UfwLocalModuleCallback {
      param($old,$id)
      $value=& $old $id;$script:F.queryCalls++
      if($script:F.queryCalls -eq 1){
       if($script:F.mode -ceq 'query_actor_drift'){$script:E.actor='S-1-5-21-999'}
       else{$script:E.pending=[pscustomobject]@{private='new_pending'}}
      }
      return $value
     } $oldQuery
    }
    Close-UfwUnifiedStorage $c.storage
    $state=[pscustomobject]@{lease=$null}
    # This callback deliberately has no audit guard: test the OUTER dispatcher.
    # Policy effects remain fixtures; the actual durable reconciler still runs.
    $recover=New-UfwLocalModuleCallback {
     param($b,$handle)
     $script:F.callbacks++
     $back=Read-UfwUnifiedStorage $handle
     $backend=New-UfwLocalBackendContext $b.io $handle $back.records[0].data {return $true}
     $ok=Recover-UfwLocalBackend $backend
     $script:F.closed=(Get-UfwLocalBackendState $backend).closed
     switch -CaseSensitive ($script:F.mode){
      'late_drift'{$script:T.mask[$script:F.id]=2}
      'late_string'{$b.ops.AuditQuery={param($id)return '0'}}
      'late_actor'{$script:E.actor='S-1-5-21-999'}
      'late_pending'{$script:E.pending=[pscustomobject]@{private='new_pending'}}
     }
     return $ok
    } ([pscustomobject]@{io=$c.io;ops=$ops})
    $bound=New-UfwRecoveryFirstBindings $state $ops $recover
    $session=@{};foreach($key in Get-UfwUnifiedRequiredAdapters){$session[$key]={throw 'PRIVATE_NEW_SESSION_MUST_NOT_RUN'}}
    foreach($key in $bound.Keys){$session[$key]=$bound[$key]}
    $result=Invoke-UfwUnifiedSession $session
    CheckE ($result.mode -ceq 'recovery_only' -and -not $result.ready_for_apply) 'recovery_only_no_native_authority'
    if($mode -ceq 'normal'){
     CheckE ($result.completed -and $result.restore_verified -and -not $result.pending_recovery) 'saved_baseline_verified_without_audit_pending'
     CheckE ($script:B.restores -eq 2 -and $script:F.callbacks -eq 1) 'exact_saved_inverses'
    }else{
     CheckE (-not $result.completed -and -not $result.restore_verified -and $result.pending_recovery) 'no_success_on_audit_or_actor_drift'
     $late=$mode.StartsWith('late_',[StringComparison]::Ordinal)
     CheckE ($script:F.callbacks -eq $(if($late){1}else{0}) -and $script:B.restores -eq $(if($late){2}else{0})) 'early_check_prevents_policy_callback'
     if($mode -cin @('pre_drift','pre_string','late_drift','late_string')){CheckE ($result.code -ceq 'ufw_unified_audit_restore_drift') 'strict_original_numeric_masks'}
     if($late){CheckE $script:F.closed 'terminal_policy_record_not_sufficient_for_outer_success'}
    }
    CheckE ($script:E.answer -eq 0 -and $null -eq $state.lease) 'no_picker_no_exit_prompt_and_lock_released'
    return $script:EC
   }finally{if($null -ne $lease){Close-UfwSessionRegistry $lease};Close-UfwUnifiedStorage $c.storage}
  } $SourceRoot $ops $mode $temp $InventoryCore $LocalFixture $RuntimeRoot
  $total+=$n
 }
 $report=[ordered]@{passed=$true;assertions=$total;cases=$modes.Count;saved_arm_audit_baseline_checked_without_pending=$true;strict_numeric_audit_masks=$true;actor_and_pending_rechecked_after_mask_reads=$true;finish_guard_after_final_policy_snapshot=$true;closed_journal_alone_not_success=$true;closed_historical_journals_automatically_rescanned=$false;atomic_OS_snapshot_claimed=$false;native_Windows_effects_executed=$false;ready_for_apply=$false;private_values_exported=$false}
 $report|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path (Split-Path $SourceRoot -Parent) 'evidence/final-audit-tests.json') -Encoding UTF8
 $report|ConvertTo-Json -Depth 6
}finally{Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
