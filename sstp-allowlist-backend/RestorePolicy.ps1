Set-StrictMode -Version Latest
# Pure comparison only. No operating-system changes are performed here.
function GetRestoreDecision([string]$Before,[string]$Applied,[string]$Current,[bool]$OwnershipVerified,[bool]$GuardVerified) {
 if (-not $OwnershipVerified) { return 'stop_ownership_unverified' }
 if ($Current -ceq $Before) { return 'already_restored' }
 if ($Current -cne $Applied) { return 'stop_external_change' }
 if (-not $GuardVerified) { return 'stop_guard_unverified' }
 return 'restore_exact_before'
}
function GetGuardReleaseDecision([bool]$AllChangesReadBack,[bool]$PolicyVerified,[bool]$Conflict,[bool]$JournalHealthy) {
 if ($AllChangesReadBack -and $PolicyVerified -and -not $Conflict -and $JournalHealthy) { return 'release_may_be_planned' }
 return 'keep_guard_required'
}
