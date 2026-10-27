param([string]$SourceRoot,[string]$RuntimeHarness,[string]$RuntimeRoot,[string]$InventoryCore,[string]$LocalFixture)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. $RuntimeHarness -Root $RuntimeRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ufw-runtime-bind-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($temp)
$total=0
try{
 foreach($mode in @('normal','ended','child_open','interrupted','parse_warning','cancel_review','restore_failure','bound_drift','lease_refused','policy_refused','window_failure','orphan','pid_reuse','exit_mismatch')){
  $runtimeMode=$mode;if($mode -cin @('ended','child_open','bound_drift','lease_refused','policy_refused','orphan','pid_reuse','exit_mismatch')){$runtimeMode='normal'}
  $ops=Run-Case $runtimeMode
  $n=& $m {
   param($src,$ops,$mode,$runtime)
   foreach($f in @('CandidateEntry.ps1','ObserverEntry.ps1','RuntimeCore.ps1','RuntimeEntry.ps1')){. (Join-Path $runtime $f)}
   foreach($f in @('NativePolicyIO.ps1','LocalPolicyBackend.ps1','RuntimeBridge.ps1','RuntimeSession.ps1')){. (Join-Path $src $f)}
   $script:RC=0
   function Verify($ok,$name){if(-not $ok){throw ('runtime_binding_test_'+$name)};$script:RC++}
   $native=New-UfwWindowsRuntimeOps
   Verify ($native.Count -eq 19 -and @($native.Values|Where-Object{$_ -isnot [scriptblock]}).Count -eq 0) 'private_native_ops_factory_shape'
   Verify ((& $native.Clock) -is [datetime]) 'private_native_ops_callback_scope'
   function Test-UfwLiveLease($c){return $c.permit}
   $live=[pscustomobject]@{actor=$script:D.receipt.actor_sid;programs=$script:D.programs;view=[pscustomobject]@{binding=('e'*64)};permit=($mode -cne 'lease_refused')}
   $selection=[pscustomobject]@{cancelled=$false;path='PRIVATE_CANDIDATE_PATH'}
   $record=& $ops.Load $selection.path
   # The original picker must NEVER be invoked during bound capture.
   $ops.Select={throw 'PRIVATE_SECOND_PICKER_MUST_NOT_RUN'}
   if($mode -cin @('ended','child_open','orphan','pid_reuse','exit_mismatch')){
    $old=$ops.ReadEvents
    $ops.ReadEvents=New-UfwLocalModuleCallback {
     param($b,$start,$end,$map)
     $batch=& $b.old $start $end $map;$time=$batch.events[0].time
     if($b.mode -ceq 'orphan'){$batch.events[1].parent_pid=999}
     elseif($b.mode -ceq 'pid_reuse'){$batch.events[1].pid=42}
     else{
      $batch.events+=,[pscustomobject]@{id=4689;record=[long]104;time=$time;pid=42;path='C:\Fixture\installer.exe'}
      if($b.mode -ne 'child_open'){$batch.events+=,[pscustomobject]@{id=4689;record=[long]105;time=$time;pid=43;path=$(if($b.mode -ceq 'exit_mismatch'){'C:\Fixture\wrong.exe'}else{'C:\Fixture\helper.exe'})}}
     }
     return $batch
    } ([pscustomobject]@{old=$old;mode=$mode})
   }
   $context=New-UfwBoundRuntimeContext $ops $selection $record $live
   if($mode -ceq 'bound_drift'){$script:D.receipt.nonce_sha256='f'*64}
   $guard=New-UfwLocalModuleCallback {param($mode,$binding)return $mode -cne 'policy_refused'} $mode
   $r=Invoke-UfwBoundRuntimeCapture $context $guard
   Verify (-not $script:T.calls.Contains('select')) 'no_second_picker'
   Verify (-not $r.ready_for_apply -and -not $r.destinations_approved -and -not $r.target_launched_by_tool) 'no_authority_upgrade'
   $status=Get-UfwCapturedLifecycleStatus $context
   Verify (-not $status.quiescence_authorized -and -not (Test-UfwBoundRuntimeQuiescence $context $null)) 'no_invented_native_quiescence'
   if($mode -ceq 'ended'){
    Verify ($r.completed -and $r.audit_restore_verified -and $status.observed_all_exits -and $status.roots -eq 1 -and $status.descendants -eq 1) 'all_exits_evidence'
    Verify (Test-UfwBoundRuntimeQuiescence $context {param($c,$e)return $true}) 'independent_probe_required_fixture_only'
    Verify (-not (Test-UfwBoundRuntimeQuiescence $context {param($c,$e)return 'true'})) 'probe_strict_bool'
   }else{Verify (-not $status.observed_all_exits) ('not_exit_proof_'+$mode)}
   if($mode -cin @('bound_drift','lease_refused','policy_refused')){Verify ($script:T.windows -eq 0 -and $script:T.sets -eq 0) 'blocked_before_audit_or_window'}
   if($mode -ceq 'window_failure'){Verify ($context.window_attempted -and $null -eq $context.batch) 'exception_after_window_unknown'}
   if($mode -ceq 'restore_failure'){Verify ($r.audit_recovery_required -and -not $status.observed_all_exits) 'audit_failure_not_quiet'}
   if($mode -ceq 'child_open'){Verify ($status.open_tracked -eq 1) 'child_outlives_parent'}
   $twice=$false;try{Invoke-UfwBoundRuntimeCapture $context $guard|Out-Null}catch{$twice=$true};Verify $twice 'one_capture_per_context'
   Verify (($status|ConvertTo-Json -Compress) -cnotmatch 'PRIVATE_|C:\\|S-1-|[a-f0-9]{32}') 'aggregate_only'
   return $script:RC
  } $SourceRoot $ops $mode $RuntimeRoot
  $total+=$n
 }
 foreach($mode in @('audit_only','policy_only','both','cancel','wrong_actor','audit_drift','archive_failure','archive_drift','policy_refused','changed_prompt','policy_audit_drift','policy_actor_drift','policy_false_close','clean')){
  $runtimeMode='recover_success';if($mode -cin @('policy_only','clean')){$runtimeMode='normal'}
  $ops=Run-Case $runtimeMode
  $n=& $m {
   param($src,$ops,$mode,$root,$inv,$fixture,$runtime)
   foreach($f in @('CandidateEntry.ps1','ObserverEntry.ps1','RuntimeCore.ps1','RuntimeEntry.ps1')){. (Join-Path $runtime $f)}
   . $fixture -src $src -root $root -inv $inv
   foreach($f in @('SessionRegistry.ps1','NativeReadiness.ps1','RecoveryFirst.ps1')){. (Join-Path $src $f)}
   $script:RC=0
   function Verify($ok,$name){if(-not $ok){throw ('recovery_first_test_'+$name)};$script:RC++}
   $script:R=[pscustomobject]@{lease=$null;policyCalls=0;io=$null;mode=$mode;nativeSetsAtArchive=0}
   if($mode -cin @('policy_only','both','cancel','wrong_actor','audit_drift','archive_failure','archive_drift','policy_refused','changed_prompt','policy_audit_drift','policy_actor_drift','policy_false_close')){
    $f=StartCase ('policy_fixture_'+$mode);$c=$f.ctx;$script:R.io=$c.io
    & $f.adapters.Backup $c.view ([pscustomobject]@{binding=$c.view.binding})|Out-Null
    $op=$c.view.operations[0];& $f.adapters.SaveIntent $null $op|Out-Null;Invoke-UfwLocalForward $c $op
    Close-UfwUnifiedStorage $c.storage
   }else{$script:TestBackendRoot=Join-Path $root $mode}
   if($mode -ceq 'cancel'){$ops.Confirm={return $false}}
   if($mode -ceq 'wrong_actor'){$ops.Actor={return 'S-1-5-21-999'}}
   if($mode -ceq 'audit_drift'){$script:T.mask[$script:T.pending.data.audit_plan[0].id]=2}
   if($mode -ceq 'archive_failure'){$ops.Archive={throw 'PRIVATE_ARCHIVE_FAILED'}}
   if($mode -ceq 'archive_drift'){$ops.Archive={param($j)$script:T.pending=$null;$script:T.mask[$j.data.audit_plan[0].id]=$j.data.audit_plan[0].during}}
   if($mode -ceq 'changed_prompt'){$ops.Confirm={$script:T.pending=Copy-UfwLocalData $script:T.pending;$script:T.pending.head='f'*64;return $true}}
   if($mode -ceq 'policy_audit_drift'){$script:T|Add-Member -NotePropertyName savedPlan -NotePropertyValue (Copy-UfwLocalData $script:T.pending.data.audit_plan)}
   $recover=New-UfwLocalModuleCallback {
    param($ops,$handle)
    $script:R.policyCalls++
    if($null -ne (& $ops.Pending)){throw 'PRIVATE_POLICY_BEFORE_AUDIT_CLEAN'}
    $back=Read-UfwUnifiedStorage $handle
    $guard={param($phase,$view)return $script:R.mode -cne 'policy_refused'}
    $context=New-UfwLocalBackendContext $script:R.io $handle $back.records[0].data $guard
    if($script:R.mode -ceq 'policy_false_close'){return $true}
    $ok=Recover-UfwLocalBackend $context
    if($script:R.mode -ceq 'policy_audit_drift'){$script:T.mask[$script:T.savedPlan[0].id]=$script:T.savedPlan[0].during}
    if($script:R.mode -ceq 'policy_actor_drift'){$ops.Actor={return 'S-1-5-21-999'}}
    return $ok
   } $ops
   $bound=New-UfwRecoveryFirstBindings $script:R $ops $recover
   # The real coordinator must select recovery BEFORE capabilities/Inspect/capture.
   $session=@{};foreach($key in Get-UfwUnifiedRequiredAdapters){$session[$key]={throw 'PRIVATE_NEW_SESSION_PATH_MUST_NOT_RUN'}}
   foreach($key in $bound.Keys){$session[$key]=$bound[$key]}
   if($mode -ceq 'clean'){$session.Capabilities={return Get-UfwIntegratedNativeReadiness}}
   $r=Invoke-UfwUnifiedSession $session
   if($mode -cin @('audit_only','policy_only','both')){
    Verify ($r.completed -and $r.mode -ceq 'recovery_only' -and $r.restore_verified -and -not $r.pending_recovery) ('recovered_'+$mode)
    Verify ($null -eq (& $ops.Pending)) 'audit_clean'
    Verify ($script:R.policyCalls -eq $(if($mode -ceq 'audit_only'){0}else{1})) 'policy_callback_count'
   }elseif($mode -ceq 'clean'){Verify (-not $r.completed -and $r.blockers.Count -eq 10 -and -not $r.policy_change_attempted) 'clean_still_native_gated'}
   else{
    Verify (-not $r.completed -and $r.pending_recovery) ('refused_'+$mode)
    if($mode -cin @('policy_refused','policy_audit_drift','policy_actor_drift','policy_false_close')){Verify ($script:R.policyCalls -eq 1) 'policy_callback_reached_but_not_success'}else{Verify ($script:R.policyCalls -eq 0) 'no_policy_after_failed_audit'}
   }
   Verify ($script:T.windows -eq 0 -and $script:T.saves -eq 0 -and -not $script:T.calls.Contains('select')) 'no_vpn_picker_window_or_capture'
   Verify (-not $r.ready_for_apply -and -not $r.automatic_target_execution) 'boundaries'
   Verify ($null -eq $script:R.lease) 'global_lease_released'
   return $script:RC
  } $SourceRoot $ops $mode $temp $InventoryCore $LocalFixture $RuntimeRoot
  $total+=$n
 }
 $report=[ordered]@{passed=$true;assertions=$total;bound_capture_cases=14;recovery_first_coordinator_cases=14;real_runtime_coordinator_used=$true;real_policy_reconciler_and_journal_used=$true;native_Windows_effects_executed=$false;native_quiescence_probe_implemented=$false;ready_for_apply=$false;private_values_exported=$false}
 $report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path (Split-Path $SourceRoot -Parent) 'evidence/runtime-recovery-binding-tests.json') -Encoding UTF8
 $report|ConvertTo-Json -Depth 8
}finally{Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
