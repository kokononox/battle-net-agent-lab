# P7 native Enabled-only quarantine/restore library. NOT a user-facing kill switch.
# No guard, profile changes, network exceptions, rule creation/deletion, or background process.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../sstp-allowlist-backend/Journal.ps1')
. (Join-Path $PSScriptRoot '../sstp-allowlist-adapter/Firewall.ps1')
function AssertQSnapshot($Snapshot) {
 if ($null -eq $Snapshot -or (($Snapshot.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'image,name,schema,sha256' -or $Snapshot.schema -cne 'sstp-rule-snapshot-1') { throw 'quarantine_snapshot_schema' }
 if ($Snapshot.name -isnot [string] -or [string]::IsNullOrWhiteSpace($Snapshot.name) -or $Snapshot.name.Length -gt 512 -or $Snapshot.sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'quarantine_snapshot_schema' }
 if ((($Snapshot.image.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'address,application,interface,interface_type,port,rule,security,service,view' -or $Snapshot.sha256 -cne (AdapterHash ($Snapshot.image | ConvertTo-Json -Depth 8 -Compress))) { throw 'quarantine_snapshot_integrity' }
 $v=$Snapshot.image.view
 # SDK CIM Enabled enum: 1=True, 2=False. Refuse any unrecognized provider representation.
 if ($v.name -cne $Snapshot.name -or $v.enabled -cne 'True' -or $v.direction -cne 'Outbound' -or $v.action -cne 'Allow' -or $Snapshot.image.rule.Enabled -cne '1') { throw 'quarantine_not_enabled_outbound_allow' }
}
function QExpected($Before,[bool]$Disabled) {
 AssertQSnapshot $Before
 $copy=$Before | ConvertTo-Json -Depth 12 -Compress | ConvertFrom-Json
 if ($Disabled) { $copy.image.rule.Enabled='2';$copy.image.view.enabled='False' }
 $copy.sha256=AdapterHash ($copy.image | ConvertTo-Json -Depth 8 -Compress)
 return $copy
}
function OpenQLock([string]$Root) {
 $Root=AssertJournalPath $Root;AssertJournalAcl $Root
 New-Object IO.FileStream((AssertJournalPath (Join-Path $Root 'transaction.lock')),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
}
function AssertQState($State) {
 if ($null -eq $State -or (($State.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'cursor,pending,phase,rules,schema' -or $State.schema -cne 'sstp-native-quarantine-1' -or $State.phase -cnotin @('quarantine','quarantined','restore','restored') -or $State.rules -isnot [array] -or $State.rules.Count -lt 1 -or $State.rules.Count -gt 512 -or $State.cursor -isnot [int] -or $State.pending -isnot [bool] -or $State.cursor -lt 0 -or $State.cursor -gt $State.rules.Count) { throw 'quarantine_state_schema' }
 $names=@();foreach($b in $State.rules) { AssertQSnapshot $b;$names+=,$b.name }
 # Windows firewall identities are not assumed case-sensitive even though readback requires exact case.
 if (@($names | Sort-Object -Unique).Count -ne $names.Count -or (($names | Sort-Object) -join "`n") -cne ($names -join "`n")) { throw 'quarantine_duplicate_or_unsorted' }
 if (($State.phase -eq 'quarantined' -and ($State.cursor -ne $State.rules.Count -or $State.pending)) -or ($State.phase -eq 'restored' -and ($State.cursor -ne 0 -or $State.pending)) -or ($State.phase -eq 'quarantine' -and $State.pending -and $State.cursor -eq $State.rules.Count) -or ($State.phase -eq 'restore' -and $State.pending -and $State.cursor -eq 0)) { throw 'quarantine_state_frontier' }
}
function AssertQFrontier($State) {
 AssertQState $State
 $pendingAfter=$false
 for($i=0;$i -lt $State.rules.Count;$i++) {
  $b=$State.rules[$i];$a=ReadStagedRule $b.name
  if ($null -eq $a) { throw 'quarantine_missing_rule' }
  $disabled=($i -lt $State.cursor)
  $expected=QExpected $b $disabled
  $isPending=$State.pending -and (($State.phase -eq 'quarantine' -and $i -eq $State.cursor) -or ($State.phase -eq 'restore' -and $i -eq ($State.cursor-1)))
  if ($a.sha256 -ceq $expected.sha256) { continue }
  if ($isPending) {
   $after=QExpected $b (-not $disabled)
   if ($a.sha256 -ceq $after.sha256) { $pendingAfter=$true;continue }
  }
  throw 'quarantine_external_change'
 }
 return $pendingAfter
}
function SetQEnabled($Before,[bool]$Disabled) {
 $from=QExpected $Before (-not $Disabled);$to=QExpected $Before $Disabled
 $actual=ReadStagedRule $Before.name
 if ($null -eq $actual -or $actual.sha256 -cne $from.sha256) { throw 'quarantine_external_change' }
 # InputObject rather than -Name avoids interpreting existing rule names as wildcard expressions.
 $rule=GetExactLocalRule $Before.name
 $latest=ReadStagedRule $Before.name
 if ($null -eq $rule -or $null -eq $latest -or $latest.sha256 -cne $from.sha256) { throw 'quarantine_external_change' }
 $value='True';if ($Disabled) { $value='False' }
 Set-NetFirewallRule -InputObject $rule -Enabled $value -ErrorAction Stop | Out-Null
 $readback=ReadStagedRule $Before.name
 if ($null -eq $readback -or $readback.sha256 -cne $to.sha256) { throw 'quarantine_mutation_readback' }
}
function InvokeNativeQuarantine {
 param([string]$Root,[ValidateSet('Quarantine','Restore')][string]$Action,[object[]]$Snapshots=$null,[ValidateSet('None','BeforeMutation','AfterMutation')][string]$Fault='None',[int]$FaultIndex=0)
 $lock=OpenQLock $Root
 try {
  $j=ReadJournal $Root
  if ($j.status -eq 'recovery_required') { throw 'quarantine_journal_recovery_required' }
  if ($j.status -eq 'absent') {
   if ($Action -ne 'Quarantine') { throw 'quarantine_missing_journal' }
   if ($null -eq $Snapshots -or $Snapshots.Count -eq 0) { throw 'quarantine_snapshots_required' }
   $state=[pscustomobject][ordered]@{schema='sstp-native-quarantine-1';phase='quarantine';cursor=0;pending=$false;rules=@($Snapshots | Sort-Object name)}
   AssertQState $state;AssertQFrontier $state | Out-Null
   # WriteJournal's size limit is checked BEFORE the first firewall mutation.
   $record=WriteJournal $Root -1 $state
  } else { $record=$j.record }
  $state=$record.state;AssertQState $state
  if ($null -ne $Snapshots -and $Snapshots.Count -gt 0) {
   $incoming=@($Snapshots | Sort-Object name);foreach($s in $incoming) { AssertQSnapshot $s }
   if (($incoming | ConvertTo-Json -Depth 12 -Compress) -cne ($state.rules | ConvertTo-Json -Depth 12 -Compress)) { throw 'quarantine_plan_mismatch' }
  }
  $after=AssertQFrontier $state
  if ($Action -eq 'Quarantine' -and $state.phase -in @('restore','restored')) { throw 'quarantine_restore_started' }
  # Resolve only an already durable single-resource intent, with every other resource unchanged.
  if ($state.pending) {
   if ($after) { if ($state.phase -eq 'quarantine') { $state.cursor++ } else { $state.cursor-- } }
   $state.pending=$false;$record=WriteJournal $Root $record.revision $state;$state=$record.state
  }
  if ($Action -eq 'Restore' -and $state.phase -in @('quarantine','quarantined')) {
   $state.phase='restore';$record=WriteJournal $Root $record.revision $state;$state=$record.state
  }
  $done=($state.phase -in @('quarantined','restored'))
  while (-not $done) {
   AssertQFrontier $state | Out-Null
   if (($state.phase -eq 'quarantine' -and $state.cursor -eq $state.rules.Count) -or ($state.phase -eq 'restore' -and $state.cursor -eq 0)) {
    if ($state.phase -eq 'quarantine') { $state.phase='quarantined' } else { $state.phase='restored' }
    $record=WriteJournal $Root $record.revision $state;$state=$record.state;$done=$true;continue
   }
   $index=$state.cursor;$disabled=$true
   if ($state.phase -eq 'restore') { $index=$state.cursor-1;$disabled=$false }
   $state.pending=$true;$record=WriteJournal $Root $record.revision $state;$state=$record.state
   AssertQFrontier $state | Out-Null
   if ($Fault -eq 'BeforeMutation' -and $index -eq $FaultIndex) { [Environment]::Exit(73) }
   SetQEnabled $state.rules[$index] $disabled
   if ($Fault -eq 'AfterMutation' -and $index -eq $FaultIndex) { [Environment]::Exit(73) }
   AssertQFrontier $state | Out-Null
   if ($disabled) { $state.cursor++ } else { $state.cursor-- }
   $state.pending=$false;$record=WriteJournal $Root $record.revision $state;$state=$record.state
  }
  AssertQFrontier $state | Out-Null
  [pscustomobject]@{phase=$state.phase;revision=$record.revision;ready_for_user_apply=$false}
 } finally { $lock.Dispose() }
}
