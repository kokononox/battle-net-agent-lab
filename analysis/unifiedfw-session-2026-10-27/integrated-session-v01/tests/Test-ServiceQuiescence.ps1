param([string]$SourceRoot,[string]$RuntimeHarness,[string]$RuntimeRoot,[string]$InventoryCore,[string]$LocalFixture)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. $RuntimeHarness -Root $RuntimeRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ufw-service-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($temp)
$total=0
$modes=@('normal','service_helper_active','service_pid_missing','service_kernel_pid','service_census_changed','process_census_changed','service_denied','service_null','service_empty','service_duplicate','service_unknown_state','service_wrong_pid_type','service_stopped_pid','service_pending_zero','service_missing_command','service_missing_account','service_extra_field','wrong_actor','wrong_boot','wrong_binding','head_changed','coverage_refused','coverage_non_bool','coverage_changes_service','missing_coverage','unknown_phase','dispatcher_restore','dispatcher_cancel','dispatcher_refused','dispatcher_finish_refused','dispatcher_drift')
try{
 foreach($mode in $modes){
  $ops=Run-Case 'normal'
  $n=& $m {
   param($src,$ops,$mode,$root,$inv,$fixture,$runtime)
   foreach($f in @('CandidateEntry.ps1','ObserverEntry.ps1','RuntimeCore.ps1','RuntimeEntry.ps1')){. (Join-Path $runtime $f)}
   . $fixture -src $src -root $root -inv $inv
   foreach($f in @('RuntimeBridge.ps1','RuntimeSession.ps1','RuntimeWitness.ps1','SessionRegistry.ps1','ProcessQuiescence.ps1','ExitReview.ps1','RecoveryFirst.ps1','ServiceQuiescence.ps1')){. (Join-Path $src $f)}
   $script:EC=0
   function CheckE($ok,$name){if(-not $ok){throw ('service_test_'+$name)};$script:EC++}
   function ThrowsE($fn,$code){$got='';try{& $fn|Out-Null}catch{$got=$_.Exception.GetBaseException().Message};CheckE ($got -ceq $code) ('expected_'+$code+'_got_'+$got)}
   function Test-UfwLiveLease($c){return $true}
   $f=StartCase ('service_'+$mode);$c=$f.ctx;$a=$f.adapters;$lease=$null
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

    $script:SV=[pscustomobject]@{mode=$mode;calls=0;processCalls=0;coverage=0}
    $serviceOps=@{Census={
     $script:SV.calls++
     $rows=@(
      [pscustomobject]@{name='FixtureService';pid=[long]900;state='Running';start_mode='Auto';command='C:\Windows\explorer.exe -fixture';account='LocalSystem';type='Share Process'},
      [pscustomobject]@{name='FixtureStopped';pid=[long]0;state='Stopped';start_mode='Manual';command='C:\Fixture\installer.exe';account='LocalSystem';type='Own Process'}
     )
     switch -CaseSensitive ($script:SV.mode){
      'service_pid_missing'{$rows[0].pid=[long]901}
      'service_kernel_pid'{$rows[0].pid=[long]4}
      'service_census_changed'{$rows[0].command+=(' '+$script:SV.calls)}
      'service_denied'{throw 'PRIVATE_DENIED'}
      'service_null'{return $null}
      'service_empty'{return ,@()}
      'service_duplicate'{$rows+=,$rows[0]}
      'service_unknown_state'{$rows[0].state='Unknown'}
      'service_wrong_pid_type'{$rows[0].pid='900'}
      'service_stopped_pid'{$rows[0].state='Stopped'}
      'service_pending_zero'{$rows[0].state='Start Pending';$rows[0].pid=[long]0}
      'service_missing_command'{$rows[0].command=$null}
      'service_missing_account'{$rows[0].account=$null}
      'service_extra_field'{$rows[0]|Add-Member -NotePropertyName extra -NotePropertyValue $true}
      'wrong_actor'{$script:E.actor='S-1-5-21-999'}
     }
     return ,$rows
    }}
    $baseCensus=$quietOps.Census
    $quietOps.Census=New-UfwLocalModuleCallback {
     param($b)
     $script:SV.processCalls++;$rows=& $b.old
     if($script:SV.mode -ceq 'service_helper_active'){$rows[2].path='C:\Fixture\helper.exe'}
     if($script:SV.mode -ceq 'process_census_changed' -and $script:SV.processCalls -gt 1){$rows[2].parent_pid=[long](900+$script:SV.processCalls)}
     if($script:SV.mode -ceq 'head_changed' -and $script:SV.processCalls -eq 1){Write-UfwUnifiedStorage $b.storage 'restore_intent' $b.view.operations[-1]|Out-Null}
     return ,$rows
    } ([pscustomobject]@{old=$baseCensus;storage=$c.storage;view=$c.view})
    if($mode -ceq 'wrong_boot'){$quietOps.Boot={return ('b'*64)}}
    $independent={param($phase,$view)
     $script:SV.coverage++
     if($script:SV.mode -ceq 'coverage_non_bool'){return 'true'}
     if($script:SV.mode -ceq 'coverage_changes_service'){$script:SV.mode='service_pid_missing'}
     if($script:SV.mode -ceq 'dispatcher_drift' -and $script:B.restores -gt 0){$script:SV.mode='service_pid_missing'}
     if($script:SV.mode -ceq 'dispatcher_finish_refused' -and $phase -ceq 'finish'){return $false}
     return $script:SV.mode -cnotin @('coverage_refused','dispatcher_refused')
    }
    if($mode -ceq 'missing_coverage'){
     ThrowsE {New-UfwServiceObservationGuard $c.storage $quietOps $serviceOps $null} 'ufw_unified_service_independent_coverage_required'
     ThrowsE {New-UfwServiceReviewedPolicyRecovery $c.io $ops $quietOps $serviceOps $null $ui {return $true}} 'ufw_unified_service_independent_coverage_required'
     return $script:EC
    }
    if($mode.StartsWith('dispatcher_',[StringComparison]::Ordinal)){
     Close-UfwUnifiedStorage $c.storage
     $state=[pscustomobject]@{lease=$null}
     $recover=New-UfwServiceReviewedPolicyRecovery $c.io $ops $quietOps $serviceOps $independent $ui {return $true}
     $bindings=New-UfwRecoveryFirstBindings $state $ops $recover
     $session=@{};foreach($key in Get-UfwUnifiedRequiredAdapters){$session[$key]={throw 'PRIVATE_NEW_SESSION_MUST_NOT_RUN'}}
     foreach($key in $bindings.Keys){$session[$key]=$bindings[$key]}
     $result=Invoke-UfwUnifiedSession $session
     CheckE ($result.mode -ceq 'recovery_only' -and -not $result.ready_for_apply) 'same_recovery_first_dispatcher'
     $expected=0;if($mode -ceq 'dispatcher_restore' -or $mode -ceq 'dispatcher_finish_refused'){$expected=2};if($mode -ceq 'dispatcher_drift'){$expected=1}
     CheckE ($script:B.restores -eq $expected) ('saved_inverse_count_'+$mode)
     if($mode -ceq 'dispatcher_restore'){CheckE ($result.completed -and $result.restore_verified -and -not $result.pending_recovery) 'exact_restore_closed'}
     else{CheckE (-not $result.completed -and $result.pending_recovery) 'refusal_no_false_close'}
     CheckE ($null -eq $state.lease -and $script:E.answer -eq $(if($mode -ceq 'dispatcher_refused'){0}else{1})) 'release_lock_review_after_safety'
     return $script:EC
    }
    $guard=New-UfwServiceObservationGuard $c.storage $quietOps $serviceOps $independent
    if($mode -ceq 'unknown_phase'){CheckE (-not (& $guard 'unknown' $c.view) -and $script:SV.calls -eq 0 -and $script:SV.coverage -eq 0) 'unknown_phase_refused';return $script:EC}
    $binding=$c.view.binding;if($mode -ceq 'wrong_binding'){$binding='f'*64}
    $observation=Get-UfwIndependentServiceQuiet $c.storage $binding $quietOps $serviceOps
    CheckE (-not $observation.quiescence_authorized -and -not $observation.complete_helper_service_IPC_coverage) 'observation_never_complete_authority'
    CheckE (($observation|ConvertTo-Json -Compress) -cnotmatch 'PRIVATE_|C:\\|S-1-|Fixture') 'aggregate_only'
    $positive=$mode -cin @('normal','coverage_refused','coverage_non_bool','coverage_changes_service')
    CheckE ($observation.service_process_links_quiet -eq $positive) ('service_observation_'+$mode+'_'+$observation.code)
    if($mode -ceq 'head_changed'){CheckE ($script:B.restores -eq 0) 'head_change_no_effect';return $script:EC}
    $codes=@{service_helper_active='known_execution_active';service_pid_missing='pid_unresolved';service_kernel_pid='pid_unresolved';service_census_changed='observation_changed';process_census_changed='observation_changed';service_denied='unavailable';service_null='census_shape';service_empty='census_shape';service_duplicate='identity';service_unknown_state='visibility';service_wrong_pid_type='identity';service_stopped_pid='pid_unresolved';service_pending_zero='pid_unresolved';service_missing_command='visibility';service_missing_account='visibility';service_extra_field='census_shape';wrong_actor='observation_changed';wrong_boot='lineage_unresolved';wrong_binding='binding'}
    if($codes.ContainsKey($mode)){CheckE ($observation.code -ceq ('ufw_unified_service_'+$codes[$mode])) ('exact_refusal_'+$mode+'_'+$observation.code)}
    $guardView=$c.view;if($mode -ceq 'wrong_binding'){$guardView=[pscustomobject]@{binding=$binding}}
    CheckE ((& $guard 'recovery' $guardView) -eq ($mode -ceq 'normal')) ('guard_outcome_'+$mode)
    CheckE ($script:B.restores -eq 0) 'read_only_no_policy_effect'
    if($mode -ceq 'normal'){
     CheckE ($observation.service_passes -eq 2 -and $observation.process_passes -eq 2) 'two_service_and_process_passes'
     CheckE ($script:SV.coverage -eq 1) 'independent_coverage_preserved'
     $native=New-UfwWindowsServiceOps;CheckE ($native.Count -eq 1 -and $native.Census -is [scriptblock]) 'native_factory'
     $script:ServiceProviderMode='normal'
     function Get-CimInstance {
      param($ClassName,$OperationTimeoutSec,$ErrorAction)
      CheckE ($ClassName -ceq 'Win32_Service' -and $OperationTimeoutSec -eq 10 -and $ErrorAction -ceq 'Stop') 'bounded_native_provider'|Out-Null
      if($script:ServiceProviderMode -ceq 'denied'){throw 'PRIVATE_ACCESS_DENIED'}
      $rows=@([pscustomobject]@{Name='FixtureService';ProcessId=[uint32]900;State='Running';StartMode='Auto';PathName='C:\Windows\explorer.exe';StartName='LocalSystem';ServiceType='Own Process'})
      if($script:ServiceProviderMode -ceq 'null_command'){$rows[0].PathName=$null}
      return $rows
     }
     function Get-Service {
      param($ErrorAction)
      if($script:ServiceProviderMode -ceq 'empty'){return @()}
      if($script:ServiceProviderMode -ceq 'wrong_state'){return [pscustomobject]@{ServiceName='FixtureService';Status='Stopped'}}
      if($script:ServiceProviderMode -ceq 'duplicate'){return @([pscustomobject]@{ServiceName='FixtureService';Status='Running'},[pscustomobject]@{ServiceName='fixtureservice';Status='Running'})}
      return [pscustomobject]@{ServiceName='FixtureService';Status='Running'}
     }
     CheckE ((Read-UfwWindowsServiceCensus).Count -eq 1) 'native_reader_with_mocked_providers'
     foreach($pair in @(@('empty','ufw_unified_service_enumerator_disagreement'),@('wrong_state','ufw_unified_service_enumerator_disagreement'),@('duplicate','ufw_unified_service_enumerator_disagreement'),@('null_command','ufw_unified_service_visibility'),@('denied','PRIVATE_ACCESS_DENIED'))){$script:ServiceProviderMode=$pair[0];ThrowsE {Read-UfwWindowsServiceCensus} $pair[1]}
    }
    return $script:EC
   }finally{Close-UfwUnifiedStorage $c.storage}
  } $SourceRoot $ops $mode $temp $InventoryCore $LocalFixture $RuntimeRoot
  $total+=$n
 }
 $report=[ordered]@{passed=$true;assertions=$total;cases=$modes.Count;two_service_and_process_passes=$true;CIM_SCM_service_identity_crosscheck=$true;same_reopened_recovery_backend=$true;cancel_and_drift_leave_pending=$true;independent_coverage_still_required=$true;complete_helper_service_IPC_coverage=$false;native_Windows_effects_executed=$false;native_service_reader_Windows_qualified=$false;ready_for_apply=$false;private_values_exported=$false}
 $report|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path (Split-Path $SourceRoot -Parent) 'evidence/service-quiescence-tests.json') -Encoding UTF8
 $report|ConvertTo-Json -Depth 6
}finally{Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
