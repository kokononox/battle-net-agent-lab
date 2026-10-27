param([string]$SourceRoot,[string]$RuntimeHarness,[string]$RuntimeRoot,[string]$InventoryCore,[string]$LocalFixture)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. $RuntimeHarness -Root $RuntimeRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ufw-witness-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($temp)
$total=0
$modes=@('normal','window_failure','arm_only','before_policy_complete','wrong_binding','wrong_actor','bad_boot','boot_changes','duplicate_connect','duplicate_arm','evidence_without_arm','duplicate_evidence','evidence_wrong_arm','wrong_program_digest','after_restore','reopen_wrong_actor','reboot','stale_head','write_failure','corrupt_record','recovery_refused','dispatcher_wrong_actor','dispatcher_false_close','dispatcher_actor_changes')
try{
 foreach($mode in $modes){
  $ops=Run-Case $(if($mode -ceq 'window_failure'){'window_failure'}else{'normal'})
  $n=& $m {
   param($src,$ops,$mode,$root,$inv,$fixture,$runtime)
   foreach($f in @('CandidateEntry.ps1','ObserverEntry.ps1','RuntimeCore.ps1','RuntimeEntry.ps1')){. (Join-Path $runtime $f)}
   . $fixture -src $src -root $root -inv $inv
   foreach($f in @('RuntimeBridge.ps1','RuntimeSession.ps1','RuntimeWitness.ps1','SessionRegistry.ps1','RecoveryFirst.ps1')){. (Join-Path $src $f)}
   $script:WC=0
   function CheckW($ok,$name){if(-not $ok){throw ('witness_test_'+$name)};$script:WC++}
   function ThrowsW($fn,$code){$msg='';try{& $fn|Out-Null}catch{$msg=$_.Exception.GetBaseException().Message};CheckW ($msg -ceq $code) ('expected_'+$code+'_got_'+$msg)}
   function Test-UfwLiveLease($c){return $true}
   if($mode -ceq 'normal'){$native=New-UfwWindowsRuntimeOps;ThrowsW {& $native.Window {return $true} $null} 'ufw_unified_witness_required_before_native_window'}
   $f=StartCase ('witness_'+$mode);$c=$f.ctx;$a=$f.adapters
   try{
    & $a.Backup $c.view ([pscustomobject]@{binding=$c.view.binding})|Out-Null
    if($mode -cne 'before_policy_complete'){
     foreach($op in $c.view.operations){& $a.SaveIntent $null $op|Out-Null;Invoke-UfwLocalForward $c $op;& $a.SaveResult $null $op|Out-Null}
    }
    $live=[pscustomobject]@{actor=$script:D.receipt.actor_sid;programs=$script:D.programs;view=$c.view}
    $selection=[pscustomobject]@{cancelled=$false;path='PRIVATE_CANDIDATE_PATH'}
    $record=& $ops.Load $selection.path
    $ctx=New-UfwBoundRuntimeContext $ops $selection $record $live
    $boot={return ('a'*64)}
    if($mode -ceq 'wrong_binding'){$ctx.live.view=Copy-UfwLocalData $c.view;$ctx.live.view.binding='f'*64;ThrowsW {Connect-UfwRuntimeWitness $ctx $c.storage $boot} 'ufw_unified_witness_policy_binding';return $script:WC}
    Connect-UfwRuntimeWitness $ctx $c.storage $boot
    CheckW (-not $ctx.witness.armed -and (Get-UfwLocalBackendState $c).runtime_arm -eq $null) 'connect_no_window_intent'
    if($mode -ceq 'duplicate_connect'){ThrowsW {Connect-UfwRuntimeWitness $ctx $c.storage $boot} 'ufw_unified_witness_connect_order';return $script:WC}
    if($mode -ceq 'evidence_without_arm'){ThrowsW {Write-UfwRuntimeEvidence $ctx} 'ufw_unified_witness_evidence_order';return $script:WC}
    if($mode -ceq 'before_policy_complete'){ThrowsW {Write-UfwRuntimeArm $ctx} 'ufw_unified_witness_arm_order';CheckW ($script:T.windows -eq 0) 'no_ui_incomplete_policy';return $script:WC}
    if($mode -ceq 'wrong_actor'){$ops.Actor={return 'S-1-5-21-999'}}
    if($mode -ceq 'bad_boot'){$ctx.witness.boot={return 'bad'}}
    if($mode -ceq 'stale_head'){$c.storage.head='f'*64}
    if($mode -ceq 'write_failure'){Close-UfwUnifiedStorage $c.storage}
    if($mode -cin @('wrong_actor','bad_boot','stale_head','write_failure')){
     $r=Invoke-UfwBoundRuntimeCapture $ctx {param($binding)return $true}
     CheckW ($script:T.windows -eq 0 -and -not $ctx.window_attempted -and -not $ctx.witness.armed) 'durable_arm_failure_prevents_ui'
     CheckW (-not $r.completed -and -not $r.ready_for_apply) 'no_upgrade_after_write_failure'
     return $script:WC
    }
    if($mode -cin @('arm_only','duplicate_arm','after_restore','wrong_program_digest','evidence_wrong_arm')){
     Write-UfwRuntimeArm $ctx
     if($mode -ceq 'duplicate_arm'){ThrowsW {Write-UfwRuntimeArm $ctx} 'ufw_unified_witness_arm_order';return $script:WC}
     if($mode -ceq 'wrong_program_digest'){
      $bad=Copy-UfwLocalData $ctx.witness.arm;$bad.programs_sha256='f'*64
      ThrowsW {Assert-UfwRuntimeWitnessPayload $bad 'runtime_arm' $c.view.binding $null} 'ufw_unified_witness_programs';return $script:WC
     }
     if($mode -ceq 'after_restore'){
      CheckW (Recover-UfwLocalBackend $c) 'fixture_independent_recovery'
      ThrowsW {Write-UfwRuntimeArm $ctx} 'ufw_unified_witness_arm_order';return $script:WC
     }
     if($mode -ceq 'evidence_wrong_arm'){
      $bad=[pscustomobject]@{schema='ufw-runtime-evidence-01';arm_sha256=('f'*64);events_json='[]';events_sha256=(Get-UfwJournalHash '[]');parse_errors=0;capture_code='test';capture_completed=$true;audit_restore_verified=$true;capture_interrupted=$false}
      ThrowsW {Assert-UfwRuntimeWitnessPayload $bad 'runtime_evidence' $c.view.binding $ctx.witness.arm} 'ufw_unified_witness_evidence_shape';return $script:WC
     }
    }else{
     # The unchanged collector's Window sees an already durable arm and readback.
     $oldWindow=$ops.Window
     $ops.Window=New-UfwLocalModuleCallback {
      param($b,$guard)
      $state=Get-UfwLocalBackendState $b.backend
      if($null -eq $state.runtime_arm -or -not $b.context.witness.armed){throw 'PRIVATE_WINDOW_BEFORE_DURABLE_ARM'}
      return & $b.old $guard
     } ([pscustomobject]@{old=$oldWindow;backend=$c;context=$ctx})
     if($mode -ceq 'boot_changes'){$script:BootReads=0;$ctx.witness.boot={$script:BootReads++;if($script:BootReads -eq 1){return ('a'*64)}else{return ('b'*64)}}}
     if($mode -ceq 'boot_changes'){ThrowsW {Invoke-UfwBoundRuntimeCapture $ctx {param($binding)return $true}} 'ufw_unified_witness_observation_changed'}
     else{$r=Invoke-UfwBoundRuntimeCapture $ctx {param($binding)return $true};CheckW (-not $r.ready_for_apply -and -not $r.destinations_approved) 'zero_authority'}
     CheckW $ctx.witness.armed 'arm_saved_before_possible_window'
     if($mode -ceq 'duplicate_evidence'){ThrowsW {Write-UfwRuntimeEvidence $ctx} 'ufw_unified_witness_evidence_order';return $script:WC}
    }
    $id=$c.storage.id;Close-UfwUnifiedStorage $c.storage
    $lease=Open-UfwSessionRegistry
    try{
     $h=Find-UfwPendingSession $lease
     CheckW ($null -ne $h -and $h.id -ceq $id) 'registry_reopen_same_session'
     if($mode -ceq 'corrupt_record'){
      $path=Join-Path $h.dir '00000006.json';[IO.File]::WriteAllText($path,'{"sequence":6}')
      ThrowsW {Read-UfwRuntimeRecoveryWitness $h $ctx.actor ('a'*64)} 'ufw_unified_storage_envelope';return $script:WC
     }
     if($mode -ceq 'reopen_wrong_actor'){ThrowsW {Read-UfwRuntimeRecoveryWitness $h 'S-1-5-21-999' ('a'*64)} 'ufw_unified_witness_actor_mismatch';return $script:WC}
     # No current EXE/open, candidate reread, audit write or VPN observer required.
     $ops.Load={throw 'PRIVATE_NO_CANDIDATE_READ_ON_RECOVERY'};$ops.Observe={throw 'PRIVATE_NO_EXE_OPEN_ON_RECOVERY'}
     $proof=Read-UfwRuntimeRecoveryWitness $h $ctx.actor $(if($mode -ceq 'reboot'){'b'*64}else{'a'*64})
     CheckW ($proof.may_have_run -and -not $proof.quiescence_authorized) 'reopened_not_safe_to_restore'
     CheckW ($proof.same_boot -eq ($mode -cne 'reboot')) 'boot_not_assumed'
     CheckW ((Get-UfwLocalJson $proof.arm) -ceq (Get-UfwLocalJson $ctx.witness.arm)) 'private_selection_survives_reopen'
     if($mode -cin @('arm_only','boot_changes')){CheckW ($proof.status -ceq 'armed_capture_unknown' -and $null -eq $proof.evidence) 'missing_capture_not_never_ran'}
     else{CheckW ($proof.status -ceq 'capture_evidence_not_quiescence_proof' -and $null -ne $proof.evidence) 'evidence_persisted'}
     if($null -ne $proof.evidence){
      CheckW ($proof.evidence.events_json -cnotmatch 'address|port|command_line') 'no_network_or_command_payload'
      if($mode -ceq 'normal'){
       foreach($badEvents in @('{"id":4688}','[{"id":4688}]','[{"actor":"S-1-5-21-123","id":5157,"parent_path":"","parent_pid":0,"path":"C:\\Fixture\\x.exe","pid":1,"record":1}]')){
        $bad=Copy-UfwLocalData $proof.evidence;$bad.events_json=$badEvents;$bad.events_sha256=Get-UfwJournalHash $badEvents
        ThrowsW {Assert-UfwRuntimeWitnessPayload $bad 'runtime_evidence' $c.view.binding $proof.arm} 'ufw_unified_witness_events'
       }
      }
     }
     if($mode -cin @('dispatcher_wrong_actor','dispatcher_false_close','dispatcher_actor_changes')){
      $script:DispatcherCalls=0
      if($mode -ceq 'dispatcher_wrong_actor'){$ops.Actor={return 'S-1-5-21-999'}}
      $callback=New-UfwLocalModuleCallback {
       param($b,$handle)
       $script:DispatcherCalls++
       if($b.mode -ceq 'dispatcher_false_close'){return $true}
       $recovery=New-UfwLocalBackendContext $b.context.io $handle $b.context.view {param($phase,$view)return $true}
       $ok=Recover-UfwLocalBackend $recovery
       $b.ops.Actor={return 'S-1-5-21-999'}
       return $ok
      } ([pscustomobject]@{context=$c;ops=$ops;mode=$mode})
      $bindings=New-UfwRecoveryFirstBindings ([pscustomobject]@{lease=$lease}) $ops $callback
      ThrowsW {& $bindings.Recover ([pscustomobject]@{policy=$h;audit=$null})} $(if($mode -ceq 'dispatcher_false_close'){'ufw_unified_policy_recovery_not_closed'}else{'ufw_unified_witness_actor_mismatch'})
      CheckW ($script:DispatcherCalls -eq $(if($mode -ceq 'dispatcher_wrong_actor'){0}else{1})) 'dispatcher_does_not_trust_witness_or_callback'
     }
     if($mode -ceq 'recovery_refused'){
      $recovery=New-UfwLocalBackendContext $c.io $h $c.view {param($phase,$view)return $false}
      ThrowsW {Recover-UfwLocalBackend $recovery} 'ufw_unified_native_bound_guard_refused'
      CheckW ($script:B.restores -eq 0) 'witness_never_bypasses_guard'
     }
    }finally{Close-UfwSessionRegistry $lease}
    return $script:WC
   }finally{Close-UfwUnifiedStorage $c.storage}
  } $SourceRoot $ops $mode $temp $InventoryCore $LocalFixture $RuntimeRoot
  $total+=$n
 }
 $report=[ordered]@{passed=$true;assertions=$total;cases=$modes.Count;same_policy_journal_and_registry=$true;durable_before_window=$true;reopened_without_live_EXE_or_VPN=$true;native_Windows_effects_executed=$false;quiescence_authorized=$false;ready_for_apply=$false;private_values_exported=$false}
 $report|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path (Split-Path $SourceRoot -Parent) 'evidence/runtime-witness-tests.json') -Encoding UTF8
 $report|ConvertTo-Json -Depth 6
}finally{Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
