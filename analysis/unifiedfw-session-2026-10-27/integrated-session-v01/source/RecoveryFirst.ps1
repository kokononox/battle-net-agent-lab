# Recover audit before policy, before any candidate picker/network observation.
function Invoke-UfwIntegratedAuditRecovery($RuntimeOps,$ExpectedPending){
 foreach($k in @('Pending','Actor','Confirm','AuditQuery','AuditSet','Archive')){if(-not $RuntimeOps.ContainsKey($k) -or $RuntimeOps[$k] -isnot [scriptblock]){throw 'ufw_unified_audit_recovery_adapter'}}
 $pending=& $RuntimeOps.Pending
 if($null -eq $ExpectedPending){if($null -ne $pending){throw 'ufw_unified_audit_pending_changed'};return $true}
 if($null -eq $pending){throw 'ufw_unified_audit_pending_changed'}
 Assert-UfwRuntimeJournal $pending.data
 if($pending.readback_verified -isnot [bool] -or -not $pending.readback_verified -or $pending.head -cne $ExpectedPending.head -or $pending.head -cne (Get-UfwJournalHash (Get-UfwCandidateJson $pending.data)) -or (& $RuntimeOps.Actor) -cne $pending.data.actor_sid){throw 'ufw_unified_audit_recovery_binding'}
 $answer=& $RuntimeOps.Confirm 'recovery' @()
 if($answer -isnot [bool] -or -not $answer){return $false}
 # Re-read after the local prompt; do not restore a replaced pending journal.
 $again=& $RuntimeOps.Pending
 if($null -eq $again -or $again.readback_verified -isnot [bool] -or -not $again.readback_verified -or $again.head -cne $pending.head -or $again.head -cne (Get-UfwJournalHash (Get-UfwCandidateJson $again.data)) -or (& $RuntimeOps.Actor) -cne $pending.data.actor_sid){throw 'ufw_unified_audit_pending_changed'}
 $ok=Restore-UfwRuntimeAuditPlan $pending.data.audit_plan $RuntimeOps.AuditQuery $RuntimeOps.AuditSet
 if($ok -isnot [bool] -or -not $ok){return $false}
 & $RuntimeOps.Archive $pending
 if($null -ne (& $RuntimeOps.Pending)){throw 'ufw_unified_audit_archive_unverified'}
 if((& $RuntimeOps.Actor) -cne $pending.data.actor_sid){throw 'ufw_unified_audit_recovery_binding'}
 foreach($item in $pending.data.audit_plan){if((& $RuntimeOps.AuditQuery $item.id) -ne $item.before){throw 'ufw_unified_audit_restore_drift'}}
 return $true
}
function New-UfwRecoveryFirstBindings($State,$RuntimeOps,[scriptblock]$PolicyRecovery){
 if($null -eq $PolicyRecovery){throw 'ufw_unified_policy_recovery_binding_required'}
 $base=New-UfwRegistryCoordinatorBindings $State
 $bound=[pscustomobject]@{state=$State;runtime=$RuntimeOps;recover=$PolicyRecovery}
 $base.Pending=New-UfwLocalModuleCallback {
  param($b)
  $policy=Find-UfwPendingSession $b.state.lease
  $audit=& $b.runtime.Pending
  if($null -eq $policy -and $null -eq $audit){return $null}
  return [pscustomobject]@{policy=$policy;audit=$audit}
 } $bound
 $base.Recover=New-UfwLocalModuleCallback {
  param($b,$pending)
  $r=[pscustomobject]@{completed=$false;restored=$false}
  # Preserve the expected audit baseline across archive/policy callbacks.
  $auditProof=$null
  if($null -ne $pending.audit){$auditProof=Copy-UfwLocalData $pending.audit.data}
  if($null -ne $pending.policy -and $null -ne $pending.audit){
   $policyBefore=Read-UfwUnifiedStorage $pending.policy
   $protocolBefore=Get-UfwLocalBackendState ([pscustomobject]@{storage=$pending.policy;view=$policyBefore.records[0].data})
   if($null -ne $protocolBefore.runtime_arm -and $protocolBefore.runtime_arm.schema -ceq 'ufw-runtime-arm-02'){
    if($pending.audit.head -cne $protocolBefore.runtime_arm.audit_pending_head -or $pending.audit.data.session_id -cne $protocolBefore.runtime_arm.audit_session_id){throw 'ufw_unified_witness_audit_pending_mismatch'}
   }
  }
  if(-not (Invoke-UfwIntegratedAuditRecovery $b.runtime $pending.audit)){return $r}
  if($null -ne $pending.policy){
   $policyBack=Read-UfwUnifiedStorage $pending.policy
   $policyState=Get-UfwLocalBackendState ([pscustomobject]@{storage=$pending.policy;view=$policyBack.records[0].data})
   if($null -ne $policyState.runtime_arm -and (& $b.runtime.Actor) -cne $policyState.runtime_arm.actor_sid){throw 'ufw_unified_witness_actor_mismatch'}
   # Callback must bind independent actor/audit/quiescence/exit checks and the
   # exact reopened backend. No current VPN or selected EXE is required here.
   $ok=& $b.recover $pending.policy
   if($ok -isnot [bool] -or -not $ok){return $r}
   $state=Read-UfwUnifiedStorage $pending.policy
   $protocol=Get-UfwLocalBackendState ([pscustomobject]@{storage=$pending.policy;view=$state.records[0].data})
   if(-not $protocol.closed){throw 'ufw_unified_policy_recovery_not_closed'}
   if($null -ne $policyState.runtime_arm -and (& $b.runtime.Actor) -cne $policyState.runtime_arm.actor_sid){throw 'ufw_unified_witness_actor_mismatch'}
  }
  # Audit drift/reappearance before returning recovery success is not ignored.
  if($null -ne (& $b.runtime.Pending)){throw 'ufw_unified_audit_pending_changed'}
  if($null -ne $auditProof){
   if((& $b.runtime.Actor) -cne $auditProof.actor_sid){throw 'ufw_unified_audit_recovery_binding'}
   foreach($item in $auditProof.audit_plan){if((& $b.runtime.AuditQuery $item.id) -ne $item.before){throw 'ufw_unified_audit_restore_drift'}}
  }
  $r.completed=$true;$r.restored=$true;return $r
 } $bound
 return $base
}
