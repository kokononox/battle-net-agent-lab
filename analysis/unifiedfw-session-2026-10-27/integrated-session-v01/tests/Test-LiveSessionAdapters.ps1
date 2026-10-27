param([string]$SourceRoot,[string]$JournalModule,[string]$InventoryCore,[string]$LocalFixture,[string]$TransportPlan,[string]$RuntimeRoot,[string]$MixedFixture)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$m=Import-Module $JournalModule -Force -PassThru -DisableNameChecking
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ufw-live-adapters-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($temp)
try{
 $report=& $m {
  param($src,$root,$inv,$fixture,$plan,$runtime,$mixedFixture)
  . $fixture -src $src -root $root -inv $inv
  . $plan
  foreach($f in @('OwnedTransport.ps1','MixedPolicyBackend.ps1','SessionRegistry.ps1','LiveReview.ps1','NativeReadiness.ps1')){. (Join-Path $src $f)}
  . (Join-Path $runtime 'CandidateEntry.ps1')
  Add-Type -Path (Join-Path $runtime 'ProgramReader.cs')
  $script:BackendChecks=0
  $baseline=New-UfwLocalBackendView (Snapshot);$operation=$baseline.operations[0]
  $script:TestBackendRoot=Join-Path $root 'registry'
  $lease=Open-UfwSessionRegistry
  try{
   $busy=$false;try{$other=Open-UfwSessionRegistry;Close-UfwSessionRegistry $other}catch{$busy=$true};Check $busy 'global_share_none'
   Check ($null -eq (Find-UfwPendingSession $lease)) 'empty_root'
   $id=[guid]::NewGuid().ToString('N');$h=New-UfwRegisteredStorage $lease $id
   Check ($h.id -ceq $id) 'reserved_id'
   Write-UfwUnifiedStorage $h 'baseline' $baseline|Out-Null
   Write-UfwUnifiedStorage $h 'intent' $operation|Out-Null
   $oldHead=$h.head;Close-UfwUnifiedStorage $h
  }finally{Close-UfwSessionRegistry $lease}
  $lease=Open-UfwSessionRegistry
  try{
   $pending=Find-UfwPendingSession $lease
   Check ($pending.id -ceq $id -and $pending.sequence -eq 2 -and $pending.head -ceq $oldHead) 'reopen_pending_hydrated'
   Throws {New-UfwRegisteredStorage $lease} 'ufw_registry_pending_scan_required'
   # Real inverse protocol, not a bare terminal marker. Effects remain mocked.
   Write-UfwUnifiedStorage $pending 'restore_intent' $operation|Out-Null
   Write-UfwUnifiedStorage $pending 'restore_result' $operation|Out-Null
   Write-UfwUnifiedStorage $pending 'restored' ([pscustomobject]@{verified=$true})|Out-Null
  }finally{Close-UfwSessionRegistry $lease}
  $lease=Open-UfwSessionRegistry
  try{Check ($null -eq (Find-UfwPendingSession $lease) -and $lease.closed_count -eq 1) 'closed_skipped';$h=New-UfwRegisteredStorage $lease;Close-UfwUnifiedStorage $h}finally{Close-UfwSessionRegistry $lease}
  $lease=Open-UfwSessionRegistry
  try{Throws {Find-UfwPendingSession $lease} 'ufw_registry_empty_session_requires_local_review'}finally{Close-UfwSessionRegistry $lease}
  foreach($mode in @('unknown','multiple','corrupt','gap','busy_session','symlink','fake_closed')){
   $script:TestBackendRoot=Join-Path $root $mode;$lease=Open-UfwSessionRegistry
   try{
    if($mode -ceq 'unknown'){[IO.File]::WriteAllText((Join-Path $lease.root 'unexpected'),'PRIVATE')}
    elseif($mode -ceq 'symlink'){
     $target=Join-Path $root 'link-target';[void][IO.Directory]::CreateDirectory($target)
     New-Item -ItemType SymbolicLink -Path (Join-Path $lease.root ('session-'+('f'*32))) -Target $target|Out-Null
    }else{
     $h=New-UfwUnifiedStorage;Write-UfwUnifiedStorage $h 'baseline' $baseline|Out-Null
     if($mode -ceq 'fake_closed'){Write-UfwUnifiedStorage $h 'intent' $operation|Out-Null;Write-UfwUnifiedStorage $h 'restored' ([pscustomobject]@{verified=$true})|Out-Null}
     if($mode -ceq 'gap'){Write-UfwUnifiedStorage $h 'intent' ([pscustomobject]@{})|Out-Null;[IO.File]::Delete((Join-Path $h.dir '00000001.json'))}
     if($mode -ceq 'corrupt'){[IO.File]::WriteAllText((Join-Path $h.dir '00000001.json'),'{}')}
     if($mode -cne 'busy_session'){Close-UfwUnifiedStorage $h}
     if($mode -ceq 'multiple'){$h2=New-UfwUnifiedStorage;Write-UfwUnifiedStorage $h2 'baseline' $baseline|Out-Null;Close-UfwUnifiedStorage $h2}
    }
    $refused=$false;try{Find-UfwPendingSession $lease|Out-Null}catch{$refused=$true};Check $refused ('registry_refused_'+$mode)
    Check ($null -eq $lease.pending -and -not $lease.scanned) ('registry_no_partial_handle_'+$mode)
   }finally{if($mode -ceq 'busy_session'){Close-UfwUnifiedStorage $h};Close-UfwSessionRegistry $lease}
  }
  # Fixed private fixture values; native Windows API is NOT invoked.
  function FreshLive($mode){
   $script:L=[pscustomobject]@{actor='S-1-5-21-123';candidate=$null;programs=@();tick=[long]1000;display=0;observations=0;mode=$mode;snapshot=(Snapshot);answer='';slow=$false}
   $inputRecord=[pscustomobject][ordered]@{schema='sstp-endpoint-review-input-01';profile_guid='11111111-1111-1111-1111-111111111111';profile_scope='current_user';profile_owner_sid=$script:L.actor;server='192.0.2.1';endpoint_ips=@('192.0.2.1')}
   $script:L.candidate=[pscustomobject]@{binding=[pscustomobject]@{profile_name='PRIVATE';ras_handle='PRIVATE_HANDLE';interface_guid='PRIVATE_GUID'};draft=(New-SstpExactTransportDraft $inputRecord);tuple='PRIVATE_FLOW';pid=42;creation='PRIVATE_CREATION';image_hash=('a'*64)}
   $script:L.programs=@([pscustomobject][ordered]@{program_id='program01';path='C:\Fixture\Installer.exe';sha256=('b'*64);file_id=('c'*16);volume_id=('d'*8);length=4096;architecture='x64'})
   $io=@{
    Actor={return $script:L.actor}
    Candidate={param($previous)$script:L.observations++;if($script:L.slow){$script:L.tick+=180001};return Copy-UfwLocalData $script:L.candidate}
    Programs={return ,$script:L.programs}
    Snapshot={return Copy-UfwLocalData $script:L.snapshot}
    HostPath={return 'C:\Windows\System32\svchost.exe'}
    Tick={return $script:L.tick}
    Display={param($c)$script:L.display++;if($script:L.mode -ceq 'policy_drift'){$script:L.snapshot.PersistentStore.records[0].record.associated_filters.Security.properties.Opaque.value='PRIVATE_DRIFT'}}
    Answer={param($challenge)if($script:L.mode -ceq 'cancel'){return ''};return $challenge}
   }
   return New-UfwLiveReviewContext $io ('e'*32)
  }
  $c=FreshLive 'normal';$bindings=New-UfwLiveCoordinatorBindings $c
  $v=& $bindings.Inspect;$answer=& $bindings.Review $v
  Check (-not $answer.cancelled -and $answer.binding -ceq $v.binding -and $script:L.display -eq 1) 'review_actual_plan_binding'
  Check ((& $bindings.Refresh) -and $v.transport.observation_binding -cmatch '^[a-f0-9]{64}$') 'lease_bound_program_and_sstp'
  Check ($v.operations.Count -eq 4 -and $v.operations[0].kind -ceq 'create_disabled_transport') 'same_mixed_plan'
  $script:L.tick=[long]181000;Check (Test-UfwLiveLease $c) 'lease_boundary'
  $script:L.tick=[long]181001;Check (-not (Test-UfwLiveLease $c) -and $c.revoked) 'lease_expired'
  $script:L.tick=[long]1000;Check (-not (Test-UfwLiveLease $c)) 'lease_no_revival'
  foreach($mode in @('actor','flow','ras','program','host','clock','slow','disconnect')){
   $c=FreshLive 'normal';Invoke-UfwLiveReview $c $c.view|Out-Null
   switch($mode){
    'actor'{$script:L.actor='S-1-5-21-999'}
    'flow'{$script:L.candidate.tuple='PRIVATE_OTHER_FLOW'}
    'ras'{$script:L.candidate.binding.ras_handle='PRIVATE_OTHER_HANDLE'}
    'program'{$script:L.programs[0].sha256='f'*64}
    'host'{$script:L.candidate.image_hash='f'*64}
    'clock'{$script:L.tick=[long]999}
    'slow'{$script:L.slow=$true}
    'disconnect'{$c.io.Candidate={throw 'PRIVATE_DISCONNECTED'}}
   }
   Check (-not (Test-UfwLiveLease $c) -and $c.revoked) ('live_refuse_'+$mode)
  }
  $c=FreshLive 'normal';$c.io.Programs=New-UfwLocalModuleCallback {param($b)return ,$script:L.programs} $null
  Invoke-UfwLiveReview $c $c.view|Out-Null;Check (Test-UfwLiveLease $c) 'private_module_program_callback'
  $guard=New-UfwLiveBackendGuard $c {param($phase,$view)return $true}
  Check (& $guard 'forward' $c.view) 'combined_forward_guard'
  $c.io.Candidate={throw 'PRIVATE_DISCONNECTED'}
  Check (-not (& $guard 'forward' $c.view)) 'combined_disconnect_refused'
  Check ((& $guard 'restore' $c.view) -and (& $guard 'immediately_before_restore' $c.view) -and (& $guard 'recovery' $c.view) -and (& $guard 'finish' $c.view)) 'recovery_no_live_observation'
  $guard=New-UfwLiveBackendGuard $c {param($phase,$view)return $false}
  Check (-not (& $guard 'restore' $c.view)) 'independent_restore_guard_not_bypassed'
  Check (-not (& $guard 'unrecognized' $c.view)) 'guard_unknown_phase'
  $c=FreshLive 'cancel';$a=Invoke-UfwLiveReview $c $c.view;Check ($a.cancelled -and -not $c.accepted) 'cancel'
  $c=FreshLive 'policy_drift';Throws {Invoke-UfwLiveReview $c $c.view} 'ufw_live_policy_changed_during_review'
  $c=FreshLive 'normal';$v=Copy-UfwLocalData $c.view;$v.binding='f'*64;Throws {Invoke-UfwLiveReview $c $v} 'ufw_live_review_context'
  Check (@((Get-UfwIntegratedNativeReadiness).PSObject.Properties|Where-Object{$_.Value -ceq 'qualified'}).Count -eq 0) 'still_no_native_qualification'
  # Recovery registry can reopen with no live adapter loaded/called.
  $script:TestBackendRoot=Join-Path $root 'network_independent';$lease=Open-UfwSessionRegistry
  try{Find-UfwPendingSession $lease|Out-Null;$h=New-UfwRegisteredStorage $lease;Write-UfwUnifiedStorage $h 'baseline' $baseline|Out-Null;Close-UfwUnifiedStorage $h}finally{Close-UfwSessionRegistry $lease}
  $lease=Open-UfwSessionRegistry
  try{$pending=Find-UfwPendingSession $lease;Check ($pending.sequence -eq 1) 'discovery_without_vpn'}finally{Close-UfwSessionRegistry $lease}
  # Same real coordinator/backend, now with live bindings and global registry.
  # Providers/native effects remain fixtures. No native qualification is inferred.
  $priorChecks=$script:BackendChecks
  . $mixedFixture -src $src -root $root -inv $inv -fixture $fixture -transportPlan $plan -capture {throw 'unused'}
  $script:BackendChecks=$priorChecks
  foreach($flow in @('normal','cancel','disconnect_capture')){
   $f=StartMixed ('live_'+$flow);Close-UfwUnifiedStorage $f.ctx.storage
   $policy=$f.ctx.io
   $script:TestBackendRoot=Join-Path $root ('assembled_'+$flow)
   $script:A=[pscustomobject]@{lease=$null;live=$null;backend=$null;adapters=$null;storage=$null;capture=0;flow=$flow;guardRestore=0}
   $ops=New-UfwRegistryCoordinatorBindings $script:A
   $ops.Capabilities={$v=[ordered]@{};foreach($key in (Get-UfwIntegratedNativeReadiness).PSObject.Properties.Name){$v[$key]='qualified'};return [pscustomobject]$v}
   $ops.Inspect={
    $mode='normal';if($script:A.flow -ceq 'cancel'){$mode='cancel'}
    $script:A.live=FreshLive $mode
    $script:MIX.spec=$script:A.live.view.transport
    return $script:A.live.view
   }
   $ops.Review={param($v)return Invoke-UfwLiveReview $script:A.live $v}
   $ops.Refresh={return Test-UfwLiveLease $script:A.live}
   $ops.Backup={param($v,$answer)
    $script:A.storage=New-UfwRegisteredStorage $script:A.lease $v.transport.session_id
    $guard=New-UfwLiveBackendGuard $script:A.live {param($phase,$view)if($phase -cin @('restore','immediately_before_restore')){$script:A.guardRestore++};return $true}
    $script:A.backend=New-UfwLocalBackendContext $policy $script:A.storage $v $guard
    $script:A.adapters=New-UfwLocalCoordinatorBindings $script:A.backend
    return & $script:A.adapters.Backup $v $answer
   }
   foreach($key in @('SaveIntent','ObserveOperation','Mutate','VerifyOperation','SaveResult','RestoreOperation','VerifyRestored','Finish')){
    $ops[$key]=New-UfwLocalModuleCallback {param($key)return & $script:A.adapters[$key] @args} $key
   }
   $ops.PolicyGuard={
    $state=Get-UfwLocalBackendState $script:A.backend
    $observed=Get-UfwLocalReconciledObservation $script:A.backend $state
    return $state.results -eq 4 -and (Test-UfwLiveLease $script:A.live)
   }
   $ops.Capture={
    $script:A.capture++
    if($script:A.flow -ceq 'disconnect_capture'){$script:A.live.io.Candidate={throw 'PRIVATE_DISCONNECTED'};[void](Test-UfwLiveLease $script:A.live)}
    $completed=$script:A.flow -ceq 'normal'
    return [pscustomobject]@{completed=$completed;capture_window_completed=$completed;audit_restore_verified=$true;audit_recovery_required=$false}
   }
   $ops.Quiescent={return $true};$ops.ExitConsent={return $true};$ops.Recover={throw 'unused'}
   $registryUnlock=$ops.Unlock
   $ops.Unlock=New-UfwLocalModuleCallback {param($original)Close-UfwUnifiedStorage $script:A.storage;& $original} $registryUnlock
   $before=Get-UfwLocalSnapshotText $script:B.snapshot
   $result=Invoke-UfwUnifiedSession $ops
   if($flow -ceq 'normal'){if(-not $result.completed){Write-Host ($result|ConvertTo-Json -Compress)};Check ($result.completed -and $result.restore_verified -and $script:A.capture -eq 1) 'assembled_normal'}
   elseif($flow -ceq 'cancel'){Check ($result.completed -and -not $result.policy_change_attempted -and $null -eq $script:A.storage) 'assembled_cancel_no_empty_session'}
   else{Check (-not $result.completed -and $result.restore_verified -and -not $result.pending_recovery -and $script:A.live.revoked -and $script:A.guardRestore -gt 0) 'assembled_disconnect_restores_without_live_lease'}
   Check ((Get-UfwLocalSnapshotText $script:B.snapshot) -ceq $before) ('assembled_exact_baseline_'+$flow)
   $lease=Open-UfwSessionRegistry
   try{Check ($null -eq (Find-UfwPendingSession $lease)) ('assembled_no_pending_'+$flow)}finally{Close-UfwSessionRegistry $lease}
  }
  $errors=@();foreach($f in Get-ChildItem -LiteralPath $src -Filter '*.ps1'){$tokens=$null;$parse=$null;[void][Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$tokens,[ref]$parse);$errors+=@($parse)};Check ($errors.Count -eq 0) 'all_source_parsed'
  return [pscustomobject][ordered]@{passed=$true;assertions=$script:BackendChecks;registry_refusal_cases=7;assembled_coordinator_cases=3;live_revocation_cases=8;real_filesystem_exercised=$true;native_Windows_effects_executed=$false;native_SSTP_observed=$false;native_local_review_executed=$false;ready_for_apply=$false;private_values_exported=$false}
 } $SourceRoot $temp $InventoryCore $LocalFixture $TransportPlan $RuntimeRoot $MixedFixture
 $out=Join-Path (Split-Path $SourceRoot -Parent) 'evidence/live-session-adapter-tests.json';$report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $out -Encoding UTF8;$report|ConvertTo-Json -Depth 8
}finally{Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
