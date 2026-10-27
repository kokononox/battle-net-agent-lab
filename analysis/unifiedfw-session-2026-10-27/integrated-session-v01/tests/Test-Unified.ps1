param([string]$RuntimeHarness,[string]$RuntimeRoot,[string]$SourceRoot)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. $RuntimeHarness -Root $RuntimeRoot
$script:checks=0
function Check($v,$label){if(-not $v){throw ('test_failed_'+$label)};$script:checks++}
$global:UnifiedCaptureFixture={param($mode)Run-Case $mode}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ufw-unified-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
function Run-UnifiedCase($Mode){
 & $m {
  param($src,$root,$mode,$capture)
  . (Join-Path $src 'Ufw.UnifiedSession.ps1');. (Join-Path $src 'StorageBridge.ps1');. (Join-Path $src 'NativeReadiness.ps1')
  $script:UnifiedRoot=Join-Path $root $mode
  function Get-UfwUnifiedStorageRoot{return $script:UnifiedRoot}
  $script:S=[pscustomobject]@{mode=$mode;h=$null;trace=(New-Object 'Collections.Generic.List[string]');memory=@{transport=0;alpha=1;beta=1};baseline=@{transport=0;alpha=1;beta=1};policyRestricted=$false;mutations=0;refresh=0;captures=0;restores=0;inspect=0;finished=$false;capture=$capture;captureResult=$null}
  $ops=@{
   Lock={$script:S.trace.Add('lock');return $script:S.mode -cne 'busy'}
   Unlock={$script:S.trace.Add('unlock');Close-UfwUnifiedStorage $script:S.h;if($script:S.mode -ceq 'unlock_failed'){throw 'PRIVATE_UNLOCK_FAILURE'}}
   Pending={if($script:S.mode -cin @('recover','recover_refused')){return [pscustomobject]@{private='PRIVATE_PENDING'}};return $null}
   Recover={param($p)$script:S.trace.Add('recover');return [pscustomobject]@{completed=($script:S.mode -ceq 'recover');restored=($script:S.mode -ceq 'recover')}}
   Capabilities={
    if($script:S.mode -ceq 'native_blocked'){return Get-UfwIntegratedNativeReadiness}
    $v=[ordered]@{};foreach($k in (Get-UfwIntegratedNativeReadiness).PSObject.Properties.Name){$v[$k]='qualified'};return [pscustomobject]$v
   }
   Inspect={
    $script:S.inspect++;$ops=@(
     [pscustomobject]@{id='transport-create';kind='create_disabled_transport';key='transport';before=0;after=1},
     [pscustomobject]@{id='transport-enable';kind='enable_owned_transport';key='transport';before=1;after=2},
     [pscustomobject]@{id='allow-alpha';kind='disable_reviewed_local_allow';key='alpha';before=1;after=0},
     [pscustomobject]@{id='allow-beta';kind='disable_reviewed_local_allow';key='beta';before=1;after=0})
    if($script:S.mode -ceq 'bad_order'){$ops=@($ops[2],$ops[0])}
    if($script:S.mode -ceq 'bad_kind'){$ops[0].kind='disable_all_rules'}
    return [pscustomobject]@{binding=('a'*64);operations=$ops;private_snapshot='PRIVATE_PATH_AND_RULES'}
   }
   Review={param($v)$script:S.trace.Add('review');return [pscustomobject]@{cancelled=($script:S.mode -ceq 'cancel');binding=$(if($script:S.mode -ceq 'review_changed'){'b'*64}else{$v.binding})}}
   Refresh={param($v,$a,$b,$i)$script:S.refresh++;return -not ($script:S.mode -ceq 'freshness' -and $script:S.refresh -eq 2)}
   Backup={param($v,$a)$script:S.trace.Add('backup');$script:S.h=New-UfwUnifiedStorage;$x=Write-UfwUnifiedStorage $script:S.h 'baseline' $v;if($script:S.mode -ceq 'backup_unverified'){$x.readback_verified=$false};return $x}
   SaveIntent={param($b,$op)$script:S.trace.Add('intent-'+$op.id);$receipt=Write-UfwUnifiedStorage $script:S.h 'intent' $op;if($script:S.mode -ceq 'intent_uncertain'){throw 'PRIVATE_STORAGE_FAILED_AFTER_WRITE'};return $receipt}
   ObserveOperation={param($op)if($script:S.mode -ceq 'before_drift'){return 'unknown'};if($script:S.memory[$op.key] -eq $op.before){return 'exact_before'};return 'unknown'}
   Mutate={param($op)$script:S.trace.Add('mutate-'+$op.id);$script:S.mutations++;$script:S.memory[$op.key]=$op.after;if($script:S.mode -ceq 'write_failed_after_effect'){throw 'PRIVATE_NATIVE_PARTIAL'}}
   VerifyOperation={param($op)return ($script:S.mode -cne 'effect_unverified' -and $script:S.memory[$op.key] -eq $op.after)}
   SaveResult={param($b,$op)$r=Write-UfwUnifiedStorage $script:S.h 'result' $op;if($script:S.mode -ceq 'result_uncertain'){throw 'PRIVATE_STORAGE_AFTER_EFFECT'};return $r}
   PolicyGuard={param($v)$script:S.policyRestricted=($script:S.memory.alpha -eq 0 -and $script:S.memory.beta -eq 0 -and $script:S.memory.transport -eq 2);return $script:S.policyRestricted -and $script:S.mode -cne 'guard_failed'}
   Capture={param($v,$answer)
    $script:S.captures++;$script:S.trace.Add('capture')
    if($script:S.mode -ceq 'capture_threw'){throw 'PRIVATE_CAPTURE_AMBIGUOUS'}
    if($script:S.mode -ceq 'bridge_guard_failed'){$script:S.policyRestricted=$false}
    $mode='normal';if($script:S.mode -ceq 'audit_recovery'){$mode='restore_failure'};if($script:S.mode -ceq 'capture_cancelled'){$mode='cancel_review'}
    $result=& $script:S.capture $mode;$script:S.captureResult=$result;return $result
   }
   Quiescent={param($v,$c)$script:S.trace.Add('quiescent');return $script:S.mode -cne 'target_active'}
   ExitConsent={param($v,$a)return $script:S.mode -cne 'exit_refused'}
   RestoreOperation={param($b,$intent)
    $op=$intent.operation;$script:S.trace.Add('restore-'+$op.id)
    if($script:S.mode -ceq 'restore_failed'){throw 'PRIVATE_RESTORE_FAILURE'}
    if($script:S.memory[$op.key] -notin @($op.before,$op.after)){throw 'ufw_unified_restore_drift'}
    Write-UfwUnifiedStorage $script:S.h 'restore_intent' $op|Out-Null
    $script:S.memory[$op.key]=$op.before;$script:S.restores++
    Write-UfwUnifiedStorage $script:S.h 'restore_result' $op|Out-Null;return $true
   }
   VerifyRestored={param($b,$v)if($script:S.mode -ceq 'restore_readback_failed'){return $false};foreach($k in $script:S.baseline.Keys){if($script:S.memory[$k] -ne $script:S.baseline[$k]){return $false}};return $true}
   Finish={param($b)$r=Write-UfwUnifiedStorage $script:S.h 'restored' ([pscustomobject]@{verified=$true});$script:S.finished=$true;return $r}
  }
  if($mode -ceq 'missing_adapter'){$ops.Remove('Capture')}
  try{
   $result=Invoke-UfwUnifiedSession $ops
   $recordCount=0;if($null -ne $script:S.h){$state=Read-UfwUnifiedStorage $script:S.h;$recordCount=$state.sequence}
   [pscustomobject]@{result=$result;trace=@($script:S.trace.ToArray());mutations=$script:S.mutations;captures=$script:S.captures;restores=$script:S.restores;inspect=$script:S.inspect;finished=$script:S.finished;record_count=$recordCount;baseline_equal=($script:S.memory.alpha -eq 1 -and $script:S.memory.beta -eq 1 -and $script:S.memory.transport -eq 0);runtime=$script:S.captureResult}
  }finally{Close-UfwUnifiedStorage $script:S.h}
 } $SourceRoot $temp $Mode $global:UnifiedCaptureFixture
}
try{
 $modes=@('normal','unlock_failed','missing_adapter','busy','native_blocked','recover','recover_refused','cancel','bad_order','bad_kind','review_changed','backup_unverified','freshness','before_drift','intent_uncertain','result_uncertain','write_failed_after_effect','effect_unverified','guard_failed','capture_threw','audit_recovery','capture_cancelled','bridge_guard_failed','target_active','exit_refused','restore_failed','restore_readback_failed')
 foreach($mode in $modes){
  $c=Run-UnifiedCase $mode;$r=$c.result
  Check (-not $r.ready_for_apply -and -not $r.no_leak_certified -and -not $r.automatic_target_execution -and $r.application_grants_added -eq 0) ('boundary_'+$mode)
  Check (($r|ConvertTo-Json -Depth 16) -cnotmatch 'PRIVATE_|Fixture|C:\\|S-1-5|[a-f0-9]{32}') ('privacy_'+$mode)
  if($mode -ceq 'normal'){
   Check ($r.completed -and $r.restore_verified -and $r.capture_completed -and -not $r.pending_recovery -and $c.baseline_equal) 'normal_completed'
   Check ($c.mutations -eq 4 -and $c.restores -eq 4 -and $c.captures -eq 1 -and $c.record_count -eq 18) 'single_full_flow'
   Check ($c.runtime.blocked_events -eq 1 -and $c.runtime.suggestion_count -eq 1 -and $c.runtime.audit_restore_verified -and $c.runtime.private_proposals_saved) 'actual_existing_runtime_core'
   Check ([Array]::IndexOf($c.trace,'backup') -lt [Array]::IndexOf($c.trace,'mutate-transport-create') -and [Array]::IndexOf($c.trace,'mutate-transport-enable') -lt [Array]::IndexOf($c.trace,'mutate-allow-alpha') -and [Array]::IndexOf($c.trace,'capture') -lt [Array]::IndexOf($c.trace,'restore-allow-beta')) 'ordering'
  }elseif($mode -ceq 'recover'){Check ($r.completed -and $r.mode -ceq 'recovery_only' -and $c.inspect -eq 0 -and $c.mutations -eq 0 -and $c.captures -eq 0) 'recovery_only'}
  else{Check (-not $r.completed -or $mode -ceq 'cancel') ('not_success_'+$mode)}
  if($mode -cin @('missing_adapter','native_blocked','busy','recover','recover_refused','cancel','bad_order','bad_kind','review_changed','backup_unverified','intent_uncertain')){Check ($c.mutations -eq 0 -and $c.captures -eq 0) ('pre_write_'+$mode)}
  if($mode -ceq 'native_blocked'){Check ($c.inspect -eq 0 -and $r.blockers.Count -eq 10 -and $c.record_count -eq 0) 'no_pretend_native_qualification'}
  if($mode -cin @('intent_uncertain','result_uncertain','capture_threw','audit_recovery','target_active','exit_refused','restore_failed','restore_readback_failed','backup_unverified')){Check ($r.pending_recovery -and -not $r.restore_verified) ('keep_pending_'+$mode)}
  if($mode -cin @('freshness','before_drift','write_failed_after_effect','effect_unverified','guard_failed','capture_cancelled','bridge_guard_failed')){Check ($r.restore_verified -and -not $r.pending_recovery -and $c.baseline_equal) ('scoped_restore_'+$mode)}
  if($mode -cin @('capture_threw','audit_recovery','target_active','exit_refused','intent_uncertain','result_uncertain')){Check ($c.restores -eq 0) ('no_fail_open_'+$mode)}
  if($mode -ceq 'unlock_failed'){Check (-not $r.completed -and $r.code -ceq 'ufw_unified_unlock_failed' -and $c.baseline_equal) 'finally_error_reported'}
  if($mode -ceq 'capture_cancelled'){Check (-not $r.capture_completed -and $r.code -ceq 'ufw_unified_capture_incomplete') 'cancel_not_fake_capture_success'}
 }
 # Snapshot semantic comparison: unknown fields/security/application deltas are never ignored.
 $sem=& $m {
  param($src). (Join-Path $src 'SemanticComparison.ps1')
  function FixtureRecord {
   $p=[ordered]@{};foreach($key in @('Name','Enabled','Action','Direction','Owner','UnknownNewField','PolicyStoreSource')){$p[$key]=[pscustomobject]@{cim_type='String';value='PRIVATE_'+$key}}
   $filters=[ordered]@{};foreach($kind in @('Address','Application','Interface','InterfaceType','Port','Security','Service')){$filters[$kind]=[pscustomobject]@{class=$kind;properties=[pscustomobject]@{private='PRIVATE_FILTER'}}}
   return [pscustomobject]@{rule=[pscustomobject]@{class='MSFT_NetFirewallRule';namespace='root/StandardCimv2';properties=[pscustomobject]$p};associated_filters=[pscustomobject]$filters}
  }
  $a=FixtureRecord;$b=FixtureRecord;$b.rule.properties.PolicyStoreSource.value='PRIVATE_OTHER_SOURCE';$equal=Compare-UfwPrivateSnapshotPair $a $b
  $b.rule.properties.UnknownNewField.value='PRIVATE_CHANGED';$different=Compare-UfwPrivateSnapshotPair $a $b
  $b=FixtureRecord;$b.associated_filters.Security.properties.private='PRIVATE_SECURITY_CHANGED';$security=Compare-UfwPrivateSnapshotPair $a $b
  [pscustomobject]@{equal=$equal;different=$different;security=$security}
 } $SourceRoot
 Check ($sem.equal.semantic_fields_match -and -not $sem.equal.write_authority -and -not $sem.equal.same_source_owner_verified) 'comparison_not_authority'
 Check (-not $sem.different.semantic_fields_match -and -not $sem.security.semantic_fields_match) 'unknown_and_security_fields_compared'
 # A partial checkpoint or stale writer head must never be silently overwritten.
 $storage=& $m {
  param($src). (Join-Path $src 'StorageBridge.ps1')
  function Get-UfwUnifiedStorageRoot{return $script:UnifiedRoot}
  $script:UnifiedRoot=Join-Path $script:UnifiedRoot 'storage-fixtures';$h=New-UfwUnifiedStorage
  try{
   $a=Write-UfwUnifiedStorage $h 'baseline' ([pscustomobject]@{private='PRIVATE_BASELINE'})
   $stale=$h.PSObject.Copy();Write-UfwUnifiedStorage $h 'intent' ([pscustomobject]@{id='op01'})|Out-Null
   $staleRefused=$false;try{Write-UfwUnifiedStorage $stale 'result' 1|Out-Null}catch{$staleRefused=$true}
   [IO.File]::WriteAllText((Join-Path $h.dir '00000003.json'),'{partial')
   $partialRefused=$false;try{Read-UfwUnifiedStorage $h|Out-Null}catch{$partialRefused=$true}
   [pscustomobject]@{stale=$staleRefused;partial=$partialRefused}
  }finally{Close-UfwUnifiedStorage $h}
 } $SourceRoot
 Check ($storage.stale -and $storage.partial) 'partial_and_stale_refused'
 $report=[pscustomobject]@{suite='unified-session-integration-01';passed=$true;assertions=$script:checks;integrated_cases=$modes.Count;existing_runtime_coordinator_executed=$true;real_Linux_journal_IO_executed=$true;Windows_firewall_writes_executed=$false;live_native_entrypoint_published=$false;user_test_requested=$false;ready_for_apply=$false;no_leak_certified=$false}
 $report|ConvertTo-Json|Set-Content -LiteralPath (Join-Path (Split-Path $SourceRoot -Parent) 'evidence/integration-tests.json') -Encoding UTF8
 $report|ConvertTo-Json -Compress
}finally{Remove-Variable UnifiedCaptureFixture -Scope Global -ErrorAction SilentlyContinue;Remove-Module $m.Name -Force;[IO.Directory]::Delete($temp,$true)}
