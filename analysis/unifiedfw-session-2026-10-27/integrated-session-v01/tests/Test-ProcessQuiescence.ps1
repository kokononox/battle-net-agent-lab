param([string]$SourceRoot,[string]$RuntimeHarness,[string]$RuntimeRoot,[string]$InventoryCore,[string]$LocalFixture)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. $RuntimeHarness -Root $RuntimeRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ufw-quiet-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($temp)
$total=0
$modes=@('normal','root_active','helper_active','pid_reused','new_child','census_changes','visibility_missing','duplicate_pid','census_failure','wrong_actor','reboot','boot_changes','actor_changes','open_child','no_evidence','partial_capture','orphan','pid_reuse_events','exit_mismatch','old_guard_refused','coverage_refused','coverage_non_bool','unknown_phase','missing_coverage','restore_reopen','restore_active','restore_coverage_refused','restore_audit_guard_refused','restore_finish_refused')
try{
 foreach($mode in $modes){
  $ops=Run-Case 'normal'
  $n=& $m {
   param($src,$ops,$mode,$root,$inv,$fixture,$runtime)
   foreach($f in @('CandidateEntry.ps1','ObserverEntry.ps1','RuntimeCore.ps1','RuntimeEntry.ps1')){. (Join-Path $runtime $f)}
   . $fixture -src $src -root $root -inv $inv
   foreach($f in @('RuntimeBridge.ps1','RuntimeSession.ps1','RuntimeWitness.ps1','SessionRegistry.ps1','ProcessQuiescence.ps1')){. (Join-Path $src $f)}
   $script:QC=0
   function CheckQ($ok,$name){if(-not $ok){throw ('quiet_test_'+$name)};$script:QC++}
   function ThrowsQ($fn,$code){$s='';try{& $fn|Out-Null}catch{$s=$_.Exception.GetBaseException().Message};CheckQ ($s -ceq $code) ('expected_'+$code+'_got_'+$s)}
   function Test-UfwLiveLease($c){return $true}
   $f=StartCase ('quiet_'+$mode);$c=$f.ctx;$a=$f.adapters
   try{
    & $a.Backup $c.view ([pscustomobject]@{binding=$c.view.binding})|Out-Null
    foreach($op in $c.view.operations){& $a.SaveIntent $null $op|Out-Null;Invoke-UfwLocalForward $c $op;& $a.SaveResult $null $op|Out-Null}
    $live=[pscustomobject]@{actor=$script:D.receipt.actor_sid;programs=$script:D.programs;view=$c.view}
    $record=& $ops.Load 'PRIVATE_CANDIDATE_PATH'
    $ctx=New-UfwBoundRuntimeContext $ops ([pscustomobject]@{cancelled=$false;path='PRIVATE_CANDIDATE_PATH'}) $record $live
    Connect-UfwRuntimeWitness $ctx $c.storage {return ('a'*64)}
    $script:Q=[pscustomobject]@{actor=$ctx.actor;boot=('a'*64);calls=0;oldCalls=0;coverageCalls=0;mode=$mode}
    if($mode -ceq 'no_evidence'){Write-UfwRuntimeArm $ctx}else{
     $oldEvents=$ops.ReadEvents
     $ops.ReadEvents=New-UfwLocalModuleCallback {
      param($b,$start,$end,$map)
      $batch=& $b.old $start $end $map
      $t=$batch.events[0].time
      if($b.mode -ceq 'orphan'){$batch.events[1].parent_pid=999}
      if($b.mode -ceq 'pid_reuse_events'){$batch.events[1].pid=42}
      $batch.events+=,[pscustomobject]@{id=4689;record=[long]104;time=$t;pid=42;path='C:\Fixture\installer.exe';parent_pid=0;parent_path='';actor=''}
      if($b.mode -cne 'open_child'){$batch.events+=,[pscustomobject]@{id=4689;record=[long]105;time=$t;pid=43;path=$(if($b.mode -ceq 'exit_mismatch'){'C:\Fixture\wrong.exe'}else{'C:\Fixture\helper.exe'});parent_pid=0;parent_path='';actor=''}}
      if($b.mode -ceq 'partial_capture'){$batch.parse_errors=1}
      return $batch
     } ([pscustomobject]@{old=$oldEvents;mode=$mode})
     $capture=Invoke-UfwBoundRuntimeCapture $ctx {param($binding)return $true}
     CheckQ ($ctx.witness.evidence_saved -and -not $capture.ready_for_apply) 'same_collector_durable_evidence'
    }
    $census=@(
     [pscustomobject]@{pid=[long]0;parent_pid=[long]0;path='';started_utc='';kernel=$true},
     [pscustomobject]@{pid=[long]4;parent_pid=[long]0;path='';started_utc='';kernel=$true},
     [pscustomobject]@{pid=[long]900;parent_pid=[long]4;path='C:\Windows\explorer.exe';started_utc='2026-10-27T07:00:00.0000000Z';kernel=$false}
    )
    $qops=@{
     Actor={return $script:Q.actor}
     Boot={return $script:Q.boot}
     Census=(New-UfwLocalModuleCallback {
      param($base)
      $script:Q.calls++;$rows=Copy-UfwLocalData $base
      foreach($row in $rows){if($row.started_utc -is [datetime]){$row.started_utc=$row.started_utc.ToUniversalTime().ToString('o')}}
      switch -CaseSensitive ($script:Q.mode){
       'root_active'{$rows[2].path='C:\Fixture\installer.exe'}
       'helper_active'{$rows[2].path='C:\Fixture\helper.exe'}
       'pid_reused'{$rows[2].pid=[long]42}
       'new_child'{$rows[2].parent_pid=[long]43}
       'census_changes'{$rows[2].started_utc=[datetime]::Parse('2026-10-27T07:00:00Z').ToUniversalTime().AddSeconds($script:Q.calls).ToString('o')}
       'visibility_missing'{$rows[2].path=''}
       'duplicate_pid'{$rows+=,$rows[2]}
       'census_failure'{throw 'PRIVATE_CENSUS_DENIED'}
       'boot_changes'{$script:Q.boot='b'*64}
       'actor_changes'{$script:Q.actor='S-1-5-21-999'}
       'restore_active'{$rows[2].path='C:\Fixture\helper.exe'}
      }
      return ,$rows
     } $census)
    }
    if($mode -ceq 'wrong_actor'){$script:Q.actor='S-1-5-21-999'}
    if($mode -ceq 'reboot'){$script:Q.boot='b'*64}
    $old={param($phase,$view)$script:Q.oldCalls++;if($script:Q.mode -ceq 'restore_finish_refused' -and $phase -ceq 'finish'){return $false};return $script:Q.mode -cnotin @('old_guard_refused','restore_audit_guard_refused')}
    $coverage={param($phase,$view)$script:Q.coverageCalls++;if($script:Q.mode -ceq 'coverage_non_bool'){return 'true'};return $script:Q.mode -cnotin @('coverage_refused','restore_coverage_refused')}
    if($mode -ceq 'missing_coverage'){ThrowsQ {New-UfwQuiescenceBackendGuard $c.storage $qops $old $null} 'ufw_unified_quiet_independent_guard_required';return $script:QC}
    $guard=New-UfwQuiescenceBackendGuard $c.storage $qops $old $coverage
    if($mode -ceq 'unknown_phase'){CheckQ (-not (& $guard 'wrong_phase' $c.view) -and $script:Q.calls -eq 0) 'unknown_phase_no_observe';return $script:QC}
    if($mode.StartsWith('restore_',[StringComparison]::Ordinal)){
     $id=$c.storage.id;Close-UfwUnifiedStorage $c.storage;$lease=Open-UfwSessionRegistry
     try{
      $handle=Find-UfwPendingSession $lease;CheckQ ($handle.id -ceq $id) 'same_reopened_journal'
      $guard=New-UfwQuiescenceBackendGuard $handle $qops $old $coverage
      $recovery=New-UfwLocalBackendContext $c.io $handle $c.view $guard
      if($mode -ceq 'restore_reopen'){
       CheckQ (Recover-UfwLocalBackend $recovery) 'real_reconciler_completed'
       CheckQ ($script:B.restores -eq 2 -and (Get-UfwLocalBackendState $recovery).closed) 'only_two_saved_intents_restored'
       CheckQ ($script:Q.calls -ge 10 -and $script:Q.coverageCalls -ge 5) 'fresh_checks_during_each_inverse'
      }else{
       ThrowsQ {Recover-UfwLocalBackend $recovery} 'ufw_unified_native_bound_guard_refused'
       CheckQ ($script:B.restores -eq $(if($mode -ceq 'restore_finish_refused'){2}else{0}) -and -not (Get-UfwLocalBackendState $recovery).closed) 'no_false_close_on_uncertainty'
      }
     }finally{Close-UfwSessionRegistry $lease}
     return $script:QC
    }
    $quiet=Get-UfwIndependentProcessQuiet $c.storage $c.view.binding $qops
    CheckQ (-not $quiet.quiescence_authorized) 'process_observation_never_authority'
    CheckQ (($quiet|ConvertTo-Json -Compress) -cnotmatch 'PRIVATE_|C:\\|S-1-|[a-f0-9]{32}') 'aggregate_only'
    $positive=$mode -cin @('normal','coverage_refused','coverage_non_bool','old_guard_refused')
    CheckQ ($quiet.process_quiet_observed -eq $positive) ('process_outcome_'+$mode+'_'+$quiet.code)
    $permit=& $guard 'recovery' $c.view
    CheckQ ($permit -is [bool] -and $permit -eq ($mode -ceq 'normal')) ('guard_outcome_'+$mode)
    CheckQ ($script:B.restores -eq 0) 'observation_does_not_restore'
    if($mode -ceq 'normal'){
     CheckQ ($quiet.census_passes -eq 2 -and $script:Q.oldCalls -eq 2 -and $script:Q.coverageCalls -eq 1) 'both_independent_guards_preserved'
     $native=New-UfwWindowsQuiescenceOps;CheckQ ($native.Count -eq 3) 'native_factory_shape'
     $proof=Read-UfwRuntimeRecoveryWitness $c.storage $ctx.actor ('a'*64)
     $more=@(ConvertFrom-Json $proof.arm.programs_json);$extra=Copy-UfwLocalData $more[0];$extra.path='C:\Fixture\not_started.exe';$more+=,$extra;$proof.arm.programs_json=Get-UfwCandidateJson $more
     $lineage=Get-UfwRecoveryLineage $proof
     CheckQ ($lineage.known_paths -contains $extra.path) 'all_selections_tracked_even_unstarted'
     # Execute the actual native reader logic against controlled CIM/process providers.
     $script:CensusFixture='normal'
     function Get-CimInstance {
      param($ClassName,$OperationTimeoutSec,$ErrorAction)
      $rows=@(
       [pscustomobject]@{ProcessId=[uint32]0;ParentProcessId=[uint32]0;Name='System Idle Process';ExecutablePath=$null;CreationDate=$null},
       [pscustomobject]@{ProcessId=[uint32]4;ParentProcessId=[uint32]0;Name='System';ExecutablePath=$null;CreationDate=$null},
       [pscustomobject]@{ProcessId=[uint32]900;ParentProcessId=[uint32]4;Name='explorer.exe';ExecutablePath='C:\Windows\explorer.exe';CreationDate=[datetime]::Parse('2026-10-27T07:00:00Z').ToUniversalTime()}
      )
      if($script:CensusFixture -ceq 'denied'){$rows[2].ExecutablePath=$null}
      if($script:CensusFixture -ceq 'bad_kernel'){$rows[1].Name='fake'}
      if($script:CensusFixture -ceq 'duplicate'){$rows+=,$rows[2]}
      return $rows
     }
     function Get-Process {
      param($ErrorAction)
      $rows=@([pscustomobject]@{Id=0},[pscustomobject]@{Id=4},[pscustomobject]@{Id=900})
      if($script:CensusFixture -ceq 'omitted'){$rows=@($rows[0],$rows[1])}
      return $rows
     }
     CheckQ ((Read-UfwWindowsProcessCensus).Count -eq 3) 'real_native_reader_with_providers'
     foreach($pair in @(@('denied','ufw_unified_quiet_process_visibility'),@('bad_kernel','ufw_unified_quiet_kernel_identity'),@('duplicate','ufw_unified_quiet_census_identity'),@('omitted','ufw_unified_quiet_enumerator_disagreement'))){
      $script:CensusFixture=$pair[0];ThrowsQ {Read-UfwWindowsProcessCensus} $pair[1]
     }

    }
    return $script:QC
   }finally{Close-UfwUnifiedStorage $c.storage}
  } $SourceRoot $ops $mode $temp $InventoryCore $LocalFixture $RuntimeRoot
  $total+=$n
 }
 $report=[ordered]@{passed=$true;assertions=$total;cases=$modes.Count;two_pass_current_process_checks=$true;real_collector_and_durable_witness=$true;real_reopened_backend_recovery=$true;existing_guard_and_independent_helper_coverage_required=$true;native_Windows_effects_executed=$false;native_process_observer_Windows_qualified=$false;service_IPC_coverage_implemented=$false;ready_for_apply=$false;private_values_exported=$false}
 $report|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path (Split-Path $SourceRoot -Parent) 'evidence/process-quiescence-tests.json') -Encoding UTF8
 $report|ConvertTo-Json -Depth 6
}finally{Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
