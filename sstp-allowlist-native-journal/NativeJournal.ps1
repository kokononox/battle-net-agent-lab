# P5 real NetSecurity staging journal. All owned rules remain DISABLED; no network guard is installed.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../sstp-allowlist-backend/Journal.ps1')
. (Join-Path $PSScriptRoot '../sstp-allowlist-adapter/Firewall.ps1')
function OpenNativeStagingLock([string]$Root) {
 $Root=AssertJournalPath $Root;AssertJournalAcl $Root
 $path=AssertJournalPath (Join-Path $Root 'transaction.lock')
 New-Object IO.FileStream($path,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
}
function NativeSpecHash($Spec) { AdapterHash ($Spec | ConvertTo-Json -Depth 5 -Compress) }
function AssertNativeStagingState($State) {
 if ($null -eq $State -or (($State.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'phase,schema,snapshot,spec,spec_sha256' -or $State.schema -cne 'sstp-native-staging-1' -or $State.phase -cnotin @('prepared','create_intent','staged','remove_intent','removed')) { throw 'staging_state_schema' }
 $s=AssertStagedRuleSpec $State.spec
 if ($State.spec_sha256 -cne (NativeSpecHash $s)) { throw 'staging_spec_integrity' }
 if ($State.phase -in @('prepared','create_intent')) {
  if ($null -ne $State.snapshot) { throw 'staging_snapshot_schema' }
 } else {
  $snap=$State.snapshot
  if ($null -eq $snap -or (($snap.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'image,name,schema,sha256' -or $snap.schema -cne 'sstp-rule-snapshot-1' -or $snap.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $snap.sha256 -cne (AdapterHash ($snap.image | ConvertTo-Json -Depth 8 -Compress))) { throw 'staging_snapshot_schema' }
  AssertStagedRuleReadback $s $snap | Out-Null
 }
}
function AssertNativeObserved($State,$Actual) {
 if ($null -eq $Actual -or $Actual.sha256 -cne $State.snapshot.sha256) { throw 'staging_external_change' }
 AssertStagedRuleReadback $State.spec $Actual | Out-Null
}
function InvokeNativeStaging {
 param([string]$Root,[ValidateSet('Stage','Remove')][string]$Action,$Spec=$null,[ValidateSet('None','BeforeCreate','AfterCreate','AfterRecord','BeforeRemove','AfterRemove')][string]$Fault='None')
 $lock=OpenNativeStagingLock $Root
 try {
  $journal=ReadJournal $Root
  if ($journal.status -eq 'recovery_required') { throw 'staging_journal_recovery_required' }
  if ($journal.status -eq 'absent') {
   if ($Action -ne 'Stage') { throw 'staging_missing_journal' }
   $s=AssertStagedRuleSpec $Spec
   if ($null -ne (ReadStagedRule (StagedRuleName $s))) { throw 'staging_name_exists' }
   $state=[pscustomobject][ordered]@{schema='sstp-native-staging-1';phase='prepared';spec=$s;spec_sha256=(NativeSpecHash $s);snapshot=$null}
   $record=WriteJournal $Root -1 $state
  } else { $record=$journal.record }
  $state=$record.state;AssertNativeStagingState $state
  if ($null -ne $Spec) { $s=AssertStagedRuleSpec $Spec;if ((NativeSpecHash $s) -cne $state.spec_sha256) { throw 'staging_plan_mismatch' } }
  $name=StagedRuleName $state.spec
  if ($Action -eq 'Stage') {
   if ($state.phase -in @('remove_intent','removed')) { throw 'staging_closed_or_removing' }
   if ($state.phase -eq 'prepared') {
    if ($null -ne (ReadStagedRule $name)) { throw 'staging_external_change' }
    $state.phase='create_intent';$record=WriteJournal $Root $record.revision $state;$state=$record.state
   }
   if ($state.phase -eq 'create_intent') {
    $actual=ReadStagedRule $name
    # A rule that exists but has no durable readback hash is ambiguous, even if its name/spec match.
    # Never silently adopt it or delete it after an interrupted create.
    if ($null -ne $actual) { throw 'staging_unacknowledged_rule_requires_review' }
    if ($Fault -eq 'BeforeCreate') { [Environment]::Exit(73) }
    $created=NewDisabledStagedRule $state.spec
    if ($Fault -eq 'AfterCreate') { [Environment]::Exit(73) }
    $state.snapshot=$created;$state.phase='staged'
    $record=WriteJournal $Root $record.revision $state;$state=$record.state
    if ($Fault -eq 'AfterRecord') { [Environment]::Exit(73) }
   }
   AssertNativeObserved $state (ReadStagedRule $name)
   return [pscustomobject]@{phase='staged';revision=$record.revision;ready_for_user_apply=$false}
  }
  # Remove restores only known absence of this tool's disabled rule. It never resets a profile or rule group.
  if ($state.phase -eq 'prepared' -or $state.phase -eq 'create_intent') {
   if ($null -ne (ReadStagedRule $name)) { throw 'staging_unacknowledged_rule_requires_review' }
   throw 'staging_no_observed_rule'
  }
  if ($state.phase -eq 'removed') {
   if ($null -ne (ReadStagedRule $name)) { throw 'staging_external_change' }
   return [pscustomobject]@{phase='removed';revision=$record.revision;ready_for_user_apply=$false}
  }
  if ($state.phase -eq 'staged') {
   AssertNativeObserved $state (ReadStagedRule $name)
   $state.phase='remove_intent';$record=WriteJournal $Root $record.revision $state;$state=$record.state
  }
  $actual=ReadStagedRule $name
  if ($null -ne $actual) { AssertNativeObserved $state $actual }
  if ($Fault -eq 'BeforeRemove') { [Environment]::Exit(73) }
  if ($null -ne $actual) { RemoveDisabledStagedRule $state.spec $state.snapshot.sha256 | Out-Null }
  if ($Fault -eq 'AfterRemove') { [Environment]::Exit(73) }
  if ($null -ne (ReadStagedRule $name)) { throw 'staging_remove_readback' }
  $state.phase='removed';$record=WriteJournal $Root $record.revision $state
  return [pscustomobject]@{phase='removed';revision=$record.revision;ready_for_user_apply=$false}
 } finally { $lock.Dispose() }
}
