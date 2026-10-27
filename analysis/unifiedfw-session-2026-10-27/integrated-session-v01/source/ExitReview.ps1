# Memory-only explicit exit consent bound to the existing journal and audit baseline.
# No broad Allow, policy reset, process termination, VPN dependency or saved approval.
function New-UfwExitReviewContext($Storage,$PolicyIO,$RuntimeOps,$QuietOps,[scriptblock]$CoverageGuard,$UI){
 if($null -eq $CoverageGuard){throw 'ufw_unified_exit_coverage_required'}
 foreach($pair in @(@($RuntimeOps,'Actor'),@($RuntimeOps,'Pending'),@($RuntimeOps,'AuditQuery'),@($UI,'Tick'),@($UI,'Display'),@($UI,'Answer'))){if(-not $pair[0].ContainsKey($pair[1]) -or $pair[0][$pair[1]] -isnot [scriptblock]){throw 'ufw_unified_exit_adapter'}}
 return [pscustomobject]@{storage=$Storage;policy=$PolicyIO;runtime=$RuntimeOps;quiet=$QuietOps;coverage=$CoverageGuard;ui=$UI;attempted=$false;accepted=$false;revoked=$false;accepted_tick=[long]0;last_tick=[long]0;binding='';arm_json='';saved_json='';materialized_json=''}
}
function Read-UfwExitState($Context,[bool]$ReadPolicy){
 if($null -eq $Context.storage.lock -or -not $Context.storage.lock.CanWrite){throw 'ufw_unified_exit_lock_required'}
 $back=Read-UfwUnifiedStorage $Context.storage;$view=$back.records[0].data
 $state=Get-UfwLocalBackendState ([pscustomobject]@{storage=$Context.storage;view=$view})
 $arm=$state.runtime_arm
 if($null -eq $arm -or $arm.schema -cne 'ufw-runtime-arm-02'){throw 'ufw_unified_exit_saved_audit_baseline_missing'}
 if((& $Context.runtime.Actor) -cne $arm.actor_sid){throw 'ufw_unified_exit_actor_changed'}
 if($null -ne (& $Context.runtime.Pending)){throw 'ufw_unified_exit_audit_pending'}
 Assert-UfwRuntimeAuditPlan $arm.audit_plan
 foreach($p in $arm.audit_plan){
  $actual=& $Context.runtime.AuditQuery $p.id
  if(($actual -isnot [int] -and $actual -isnot [uint32] -and $actual -isnot [long]) -or $actual -ne $p.before){throw 'ufw_unified_exit_audit_baseline_changed'}
 }
 $snapshot=''
 if($ReadPolicy){
  $backend=New-UfwLocalBackendContext $Context.policy $Context.storage $view {return $false}
  $observation=Get-UfwLocalReconciledObservation $backend $state
  $snapshot=Get-UfwLocalSnapshotText $observation.read.snapshot
 }
 return [pscustomobject]@{head=$back.head;view=$view;state=$state;arm=$arm;snapshot=$snapshot;remaining=($state.saved.Count-$state.restored)}
}
function Assert-UfwExitSafetyObservation($Context,$Current){
 $quiet=Get-UfwIndependentProcessQuiet $Context.storage $Current.view.binding $Context.quiet
 if(-not $quiet.process_quiet_observed){throw 'ufw_unified_exit_processes_unresolved'}
 $covered=& $Context.coverage 'recovery' $Current.view
 if($covered -isnot [bool] -or -not $covered){throw 'ufw_unified_exit_helper_coverage_unresolved'}
}
function Get-UfwExitReviewStamp($Current){
 return Get-UfwJournalHash (Get-UfwLocalJson ([pscustomobject]@{head=$Current.head;arm=$Current.arm;view=$Current.view;snapshot=$Current.snapshot}))
}
function Invoke-UfwExitReview($Context){
 if($Context.attempted -or $Context.revoked){throw 'ufw_unified_exit_review_order'}
 $Context.attempted=$true
 try{
  $start=& $Context.ui.Tick
  if($start -isnot [long] -or $start -lt 0){throw 'ufw_unified_exit_clock'}
  $before=Read-UfwExitState $Context $true
  if($before.state.closed -or $before.remaining -lt 1){throw 'ufw_unified_exit_nothing_to_review'}
  Assert-UfwExitSafetyObservation $Context $before
  & $Context.ui.Display $before
  $challenge='RESTORE '+$Context.storage.id.Substring(0,12)+' '+[guid]::NewGuid().ToString('N').Substring(0,8)
  $answer=& $Context.ui.Answer $challenge
  if($answer -isnot [string] -or $answer -cne $challenge){$Context.revoked=$true;return $false}
  $accepted=& $Context.ui.Tick
  if($accepted -isnot [long] -or $accepted -lt $start -or $accepted-$start -gt 120000){throw 'ufw_unified_exit_review_expired'}
  $after=Read-UfwExitState $Context $true
  if((Get-UfwExitReviewStamp $before) -cne (Get-UfwExitReviewStamp $after)){throw 'ufw_unified_exit_changed_during_review'}
  Assert-UfwExitSafetyObservation $Context $after
  # Slow observations cannot extend the deadline past the answer tick.
  $end=& $Context.ui.Tick
  if($end -isnot [long] -or $end -lt $accepted -or $end-$accepted -gt 180000){throw 'ufw_unified_exit_review_expired'}
  $Context.binding=$after.view.binding;$Context.arm_json=Get-UfwLocalJson $after.arm
  $Context.saved_json=Get-UfwLocalJson $after.state.saved;$Context.materialized_json=Get-UfwLocalJson $after.state.materialized
  $Context.accepted_tick=$accepted;$Context.last_tick=$end;$Context.accepted=$true
  return $true
 }catch{$Context.revoked=$true;$Context.accepted=$false;throw}
}
function Test-UfwExitConsent($Context,$View){
 if(-not $Context.accepted -or $Context.revoked){return $false}
 try{
  $tick=& $Context.ui.Tick
  if($tick -isnot [long] -or $tick -lt $Context.last_tick -or $tick-$Context.accepted_tick -gt 180000){throw 'ufw_unified_exit_consent_expired'}
  $Context.last_tick=$tick
  $current=Read-UfwExitState $Context $false
  if($View.binding -cne $Context.binding -or $current.view.binding -cne $Context.binding -or (Get-UfwLocalJson $current.arm) -cne $Context.arm_json -or (Get-UfwLocalJson $current.state.saved) -cne $Context.saved_json -or (Get-UfwLocalJson $current.state.materialized) -cne $Context.materialized_json){throw 'ufw_unified_exit_consent_binding_changed'}
  $end=& $Context.ui.Tick
  if($end -isnot [long] -or $end -lt $tick -or $end-$Context.accepted_tick -gt 180000){throw 'ufw_unified_exit_consent_expired'}
  $Context.last_tick=$end;return $true
 }catch{$Context.revoked=$true;$Context.accepted=$false;return $false}
}
function New-UfwExitConsentBackendGuard($Context,[scriptblock]$ExistingGuard){
 if($null -eq $ExistingGuard){throw 'ufw_unified_exit_existing_guard_required'}
 return New-UfwLocalModuleCallback {
  param($b,$phase,$view)
  if($phase -cnotin @('backup','forward','immediately_before_forward','restore','immediately_before_restore','recovery','finish')){return $false}
  $existing=& $b.existing $phase $view
  if($existing -isnot [bool] -or -not $existing){return $false}
  if($phase -cin @('restore','immediately_before_restore','recovery','finish')){return Test-UfwExitConsent $b.context $view}
  return $true
 } ([pscustomobject]@{context=$Context;existing=$ExistingGuard})
}
function New-UfwWindowsExitReviewUI {
 return @{
  Tick={return [long]([Diagnostics.Stopwatch]::GetTimestamp()*1000.0/[Diagnostics.Stopwatch]::Frequency)}
  Display=(New-UfwLocalModuleCallback {param($unused,$current)Show-UfwLocalExitReview $current} $null)
  Answer={param($challenge)return Read-Host ('Type exactly "'+$challenge+'" to restore ONLY this session saved baseline; Enter cancels')}
 }
}
function Show-UfwLocalExitReview($Current){
 Write-Host 'LOCAL ONLY: do not share this view, a transcript or screenshot.'
 Write-Host 'Exit review: ONLY the saved operations of this session, in reverse journal order.'
 Write-Host 'This is NOT a firewall reset, global Allow, or assurance of restored general Internet.'
 Write-Host 'Saved profile defaults remain unchanged. A saved Block baseline stays Block.'
 Write-Host 'No VPN/EXE launch, process termination, new child/service grants or DNS query occurs.'
 Write-Host 'Process observations alone do not prove full service/IPC coverage; independent guards remain required.'
 foreach($program in (ConvertFrom-Json $Current.arm.programs_json)){Write-Host ('Selected program: '+$program.path+' / SHA256 '+$program.sha256)}
 Write-Host ('Remaining saved inverse operations: '+$Current.remaining)
 for($i=$Current.state.saved.Count-1-$Current.state.restored;$i -ge 0;$i--){$op=$Current.state.saved[$i];Write-Host (Get-UfwLocalJson $op)}
 Write-Host 'Current policy has been reconciled against this exact journal; drift refuses exit.'
 Write-Host 'Cancel or refusal leaves recovery pending. Consent is temporary, memory-only and rechecked before inverse effects.'
}
function New-UfwReviewedPolicyRecovery($PolicyIO,$RuntimeOps,$QuietOps,[scriptblock]$CoverageGuard,$UI,[scriptblock]$ExistingGuard){
 if($null -eq $CoverageGuard -or $null -eq $ExistingGuard){throw 'ufw_unified_exit_independent_guards_required'}
 return New-UfwLocalModuleCallback {
  param($b,$handle)
  # Called by RecoveryFirst AFTER audit recovery, using its exact reopened handle.
  # No picker, fresh EXE open, live SSTP lease or generic policy reset is required.
  $initial=Read-UfwUnifiedStorage $handle
  $allowed=& $b.existing 'recovery' $initial.records[0].data
  if($allowed -isnot [bool] -or -not $allowed){return $false}
  $context=New-UfwExitReviewContext $handle $b.policy $b.runtime $b.quiet $b.coverage $b.ui
  if(-not (Invoke-UfwExitReview $context)){return $false}
  $consentGuard=New-UfwExitConsentBackendGuard $context $b.existing
  $guard=New-UfwQuiescenceBackendGuard $handle $b.quiet $consentGuard $b.coverage
  $back=Read-UfwUnifiedStorage $handle
  $backend=New-UfwLocalBackendContext $b.policy $handle $back.records[0].data $guard
  return Recover-UfwLocalBackend $backend
 } ([pscustomobject]@{policy=$PolicyIO;runtime=$RuntimeOps;quiet=$QuietOps;coverage=$CoverageGuard;ui=$UI;existing=$ExistingGuard})
}
