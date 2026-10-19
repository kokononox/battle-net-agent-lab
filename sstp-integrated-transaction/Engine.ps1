# P9: native Enabled-only transaction + complete P8 inventory seals. Not a kill switch.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../sstp-allowlist-backend/Journal.ps1')
. (Join-Path $PSScriptRoot '../sstp-policy-compare/Inventory.ps1')
function IntegratedHash($Object) { JournalHash (ConvertTo-Json -InputObject $Object -Depth 16 -Compress) }
function SealIntegratedRow($Row,[bool]$Owned) {
 $projected=[ordered]@{}
 foreach($p in $Row.PSObject.Properties) {
  if ($p.Name -cne 'rule' -or $Owned) { $projected[$p.Name]=$p.Value;continue }
  $raw=[ordered]@{}
  foreach($field in $p.Value.PSObject.Properties) {
   if ($field.Name -cin @('Description','DisplayGroup','DisplayName') -and ($null -eq $field.Value -or $field.Value -is [string])) { $raw[$field.Name]=[pscustomobject][ordered]@{kind='localized_string_or_null'} }
   else { $raw[$field.Name]=$field.Value }
  };$projected[$p.Name]=[pscustomobject]$raw
 }
 [pscustomobject][ordered]@{name=$Row.name;policy_sha256=(IntegratedHash ([pscustomobject]$projected));strict_sha256=(IntegratedHash $Row)}
}
function IntegratedExpected($Before,[bool]$Disabled) {
 $copy=$Before | ConvertTo-Json -Depth 16 -Compress | ConvertFrom-Json
 if ($Disabled) { $copy.rule.Enabled='2' };return $copy
}
function AssertIntegratedCapacity($State) {
 $worst=$State | ConvertTo-Json -Depth 24 -Compress | ConvertFrom-Json
 $worst.phase='quarantined';$worst.cursor=$worst.selected.Count;$worst.pending=$false
 $payload=ConvertTo-Json -InputObject ([ordered]@{schema='sstp-journal-1';revision=[int]::MaxValue;state=$worst}) -Depth 32 -Compress
 $envelope=ConvertTo-Json -InputObject ([ordered]@{schema='sstp-journal-envelope-1';payload=$payload;sha256=(JournalHash $payload)}) -Compress
 if ([Text.Encoding]::UTF8.GetByteCount($envelope) -gt 1048576) { throw 'integrated_journal_capacity' }
}
function AssertIntegratedState($State) {
 if ($null -eq $State -or (($State.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'baseline,cursor,owned,pending,phase,profiles,schema,selected' -or $State.schema -cne 'sstp-integrated-transaction-1' -or $State.phase -cnotin @('quarantine','quarantined','restore','restored') -or $State.selected -isnot [array] -or $State.selected.Count -lt 1 -or $State.selected.Count -gt 512 -or $State.baseline -isnot [array] -or $State.baseline.Count -lt $State.selected.Count -or $State.baseline.Count -gt 10000 -or $State.owned -isnot [array] -or $State.pending -isnot [bool] -or $State.cursor -isnot [int] -or $State.cursor -lt 0 -or $State.cursor -gt $State.selected.Count) { throw 'integrated_state_schema' }
 AssertPolicyInventory ([pscustomobject]@{schema='sstp-policy-inventory-1';rules=$State.selected;profiles=$State.profiles})
 $base=@{};foreach($seal in $State.baseline) {
  if ((($seal.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'name,policy_sha256,strict_sha256' -or $seal.name -isnot [string] -or [string]::IsNullOrWhiteSpace($seal.name) -or $base.ContainsKey($seal.name) -or $seal.policy_sha256 -cnotmatch '^[a-f0-9]{64}$' -or $seal.strict_sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'integrated_seal_schema' };$base[$seal.name]=$seal
 }
 $owned=@{};foreach($name in $State.owned) { if ($name -isnot [string] -or $owned.ContainsKey($name) -or -not $base.ContainsKey($name) -or $base[$name].name -cne $name) { throw 'integrated_owned_identity' };$owned[$name]=$true }
 $names=@();foreach($row in $State.selected) {
  if ($row.rule.Enabled -cne '1' -or $row.rule.Direction -cne '2' -or $row.rule.Action -cne '2' -or $owned.ContainsKey($row.name)) { throw 'integrated_selection' }
  $s=SealIntegratedRow $row $false
  if (-not $base.ContainsKey($row.name) -or $base[$row.name].name -cne $row.name -or $s.policy_sha256 -cne $base[$row.name].policy_sha256 -or $s.strict_sha256 -cne $base[$row.name].strict_sha256) { throw 'integrated_original_integrity' };$names+=,$row.name
 }
 if ((($names | Sort-Object) -join "`n") -cne ($names -join "`n")) { throw 'integrated_selection_order' }
 if (($State.phase -eq 'quarantined' -and ($State.cursor -ne $State.selected.Count -or $State.pending)) -or ($State.phase -eq 'restored' -and ($State.cursor -ne 0 -or $State.pending)) -or ($State.phase -eq 'quarantine' -and $State.pending -and $State.cursor -eq $State.selected.Count) -or ($State.phase -eq 'restore' -and $State.pending -and $State.cursor -eq 0)) { throw 'integrated_frontier_schema' }
}
function NewIntegratedState($Inventory,[string[]]$Names,[string[]]$Owned=@()) {
 AssertPolicyInventory $Inventory
 if ($null -eq $Names -or $Names.Count -lt 1 -or $Names.Count -gt 512) { throw 'integrated_selection' }
 $selected=@();$seen=@{};$ownedSet=@{};foreach($n in $Owned) { if ([string]::IsNullOrWhiteSpace($n) -or $ownedSet.ContainsKey($n)) { throw 'integrated_owned_identity' };$ownedSet[$n]=$true }
 $map=@{};foreach($r in $Inventory.rules) { $map[$r.name]=$r }
 foreach($n in $Owned) { if (-not $map.ContainsKey($n) -or $map[$n].name -cne $n) { throw 'integrated_owned_identity' } }
 foreach($n in @($Names | Sort-Object)) { if ([string]::IsNullOrWhiteSpace($n) -or $seen.ContainsKey($n) -or -not $map.ContainsKey($n) -or $map[$n].name -cne $n) { throw 'integrated_selection' };$seen[$n]=$true;$selected+=,$map[$n] }
 $baseline=@();foreach($r in $Inventory.rules) { $baseline+=,(SealIntegratedRow $r ($ownedSet.ContainsKey($r.name))) }
 $s=[pscustomobject][ordered]@{schema='sstp-integrated-transaction-1';phase='quarantine';cursor=0;pending=$false;selected=$selected;owned=@($Owned | Sort-Object);baseline=$baseline;profiles=$Inventory.profiles}
 AssertIntegratedState $s;AssertIntegratedCapacity $s;return $s
}
function CompareIntegratedFrontier($State,$Actual) {
 AssertIntegratedState $State;AssertPolicyInventory $Actual
 if ($Actual.rules.Count -ne $State.baseline.Count) { throw 'integrated_inventory_membership' }
 foreach($p in $State.profiles) {
  $a=@($Actual.profiles | Where-Object { $_.store -ceq $p.store -and $_.name -ceq $p.name })
  if ($a.Count -ne 1 -or (RawDifferenceFields $p.image $a[0].image).Count -ne 0) { throw 'integrated_profile_conflict' }
 }
 $observed=@{};$owned=@{};$selected=@{};foreach($n in $State.owned) { $owned[$n]=$true };foreach($r in $Actual.rules) { $observed[$r.name]=SealIntegratedRow $r ($owned.ContainsKey($r.name)) }
 for($i=0;$i -lt $State.selected.Count;$i++) { $selected[$State.selected[$i].name]=$i }
 $after=$false;$display=0
 foreach($base in $State.baseline) {
  if (-not $observed.ContainsKey($base.name) -or $observed[$base.name].name -cne $base.name) { throw 'integrated_inventory_membership' }
  $a=$observed[$base.name];$expected=$base
  if ($selected.ContainsKey($base.name)) {
   $i=[int]$selected[$base.name];$disabled=$i -lt $State.cursor
   $expected=SealIntegratedRow (IntegratedExpected $State.selected[$i] $disabled) $false
   $isPending=$State.pending -and (($State.phase -eq 'quarantine' -and $i -eq $State.cursor) -or ($State.phase -eq 'restore' -and $i -eq ($State.cursor-1)))
   if ($a.policy_sha256 -cne $expected.policy_sha256 -and $isPending) {
    $candidate=SealIntegratedRow (IntegratedExpected $State.selected[$i] (-not $disabled)) $false
    if ($a.policy_sha256 -ceq $candidate.policy_sha256) { $expected=$candidate;$after=$true }
   }
  }
  if ($a.policy_sha256 -cne $expected.policy_sha256) { throw 'integrated_policy_conflict' }
  if ($a.strict_sha256 -cne $expected.strict_sha256) { $display++ }
 }
 [pscustomobject]@{pending_after=$after;display_changed_rules=$display}
}
function ReadIntegratedFrontier($State) { CompareIntegratedFrontier $State (ReadPolicyInventory) }
function GetIntegratedRule([string]$Name) {
 $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name ([Management.Automation.WildcardPattern]::Escape($Name)) -ErrorAction Stop)
 if ($rules.Count -ne 1 -or $rules[0].Name -cne $Name -or [string]$rules[0].PolicyStoreSourceType -cne 'Local') { throw 'integrated_rule_identity' };return $rules[0]
}
function ReadIntegratedRow($Rule) {
 $row=[ordered]@{name=[string]$Rule.Name;rule=(InventoryRaw $Rule)}
 foreach($p in @(@('address','Get-NetFirewallAddressFilter'),@('application','Get-NetFirewallApplicationFilter'),@('interface','Get-NetFirewallInterfaceFilter'),@('interface_type','Get-NetFirewallInterfaceTypeFilter'),@('port','Get-NetFirewallPortFilter'),@('security','Get-NetFirewallSecurityFilter'),@('service','Get-NetFirewallServiceFilter'))) {
  $f=@(& $p[1] -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
  if ($f.Count -ne 1) { throw 'integrated_filter_identity' };$raw=InventoryRaw $f[0];if ($raw.InstanceID -cne $row.name) { throw 'integrated_filter_identity' };$row[$p[0]]=$raw
 };return [pscustomobject]$row
}
function SetIntegratedEnabled($Before,[bool]$Disabled) {
 $from=SealIntegratedRow (IntegratedExpected $Before (-not $Disabled)) $false;$to=SealIntegratedRow (IntegratedExpected $Before $Disabled) $false
 $rule=GetIntegratedRule $Before.name;$actual=SealIntegratedRow (ReadIntegratedRow $rule) $false
 if ($actual.policy_sha256 -cne $from.policy_sha256) { throw 'integrated_policy_conflict' }
 $enabled='True';if ($Disabled) { $enabled='False' }
 # Only this exact object's Enabled is written; no label, filter, group, or profile is restored/reset.
 Set-NetFirewallRule -InputObject $rule -Enabled $enabled -ErrorAction Stop | Out-Null
 $after=SealIntegratedRow (ReadIntegratedRow (GetIntegratedRule $Before.name)) $false
 if ($after.policy_sha256 -cne $to.policy_sha256) { throw 'integrated_mutation_readback' }
}
function OpenIntegratedLock([string]$Root) {
 $Root=AssertJournalPath $Root;AssertJournalAcl $Root
 New-Object IO.FileStream((AssertJournalPath (Join-Path $Root 'transaction.lock')),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
}
function InvokeIntegratedTransaction {
 param([string]$Root,[ValidateSet('Quarantine','Restore')][string]$Action,[string[]]$Names=$null,[string[]]$Owned=@(),[ValidateSet('None','BeforeMutation','AfterMutation')][string]$Fault='None',[int]$FaultIndex=0)
 $lock=OpenIntegratedLock $Root
 try {
  $j=ReadJournal $Root
  if ($j.status -eq 'recovery_required') { throw 'integrated_journal_recovery_required' }
  if ($j.status -eq 'absent') {
   if ($Action -ne 'Quarantine') { throw 'integrated_missing_journal' }
   $one=ReadPolicyInventory;$two=ReadPolicyInventory
   if (-not (ComparePolicyInventory $one $two $Owned).policy_equal) { throw 'integrated_unstable_inventory' }
   $state=NewIntegratedState $two $Names $Owned;$record=WriteJournal $Root -1 $state
  } else { $record=$j.record }
  $state=$record.state;AssertIntegratedState $state
  if ($null -ne $Names -and $Names.Count -gt 0 -and ((@($Names | Sort-Object) -join "`n") -cne (@($state.selected.name) -join "`n"))) { throw 'integrated_plan_mismatch' }
  # Recovery always uses durable ownership; callers cannot silently replace the stored set.
  if ($Owned.Count -gt 0 -and ((@($Owned | Sort-Object) -join "`n") -cne (@($state.owned) -join "`n"))) { throw 'integrated_plan_mismatch' }
  $observed=ReadIntegratedFrontier $state
  if ($Action -eq 'Quarantine' -and $state.phase -in @('restore','restored')) { throw 'integrated_restore_started' }
  if ($state.pending) {
   if ($observed.pending_after) { if ($state.phase -eq 'quarantine') { $state.cursor++ } else { $state.cursor-- } }
   $state.pending=$false;$record=WriteJournal $Root $record.revision $state;$state=$record.state
  }
  if ($Action -eq 'Restore' -and $state.phase -in @('quarantine','quarantined')) { $state.phase='restore';$record=WriteJournal $Root $record.revision $state;$state=$record.state }
  while ($state.phase -notin @('quarantined','restored')) {
   if (($state.phase -eq 'quarantine' -and $state.cursor -eq $state.selected.Count) -or ($state.phase -eq 'restore' -and $state.cursor -eq 0)) {
    # Full checkpoint before declaring completion. A conflict leaves the transaction unfinished.
    $observed=ReadIntegratedFrontier $state
    if ($state.phase -eq 'quarantine') { $state.phase='quarantined' } else { $state.phase='restored' }
    $record=WriteJournal $Root $record.revision $state;$state=$record.state;break
   }
   $index=$state.cursor;$disabled=$true;if ($state.phase -eq 'restore') { $index=$state.cursor-1;$disabled=$false }
   # The full inventory was checked on entry/recovery. Guard is a REQUIRED future coordinator boundary.
   # Only this resource is compared immediately before/after its setter; full inventory is checked again before completion.
   $state.pending=$true;$record=WriteJournal $Root $record.revision $state;$state=$record.state
   if ($Fault -eq 'BeforeMutation' -and $index -eq $FaultIndex) { [Environment]::Exit(73) }
   SetIntegratedEnabled $state.selected[$index] $disabled
   if ($Fault -eq 'AfterMutation' -and $index -eq $FaultIndex) { [Environment]::Exit(73) }
   # SetIntegratedEnabled already verified the exact after image of all seven filters and the rule.
   if ($disabled) { $state.cursor++ } else { $state.cursor-- }
   $state.pending=$false;$record=WriteJournal $Root $record.revision $state;$state=$record.state
  }
  # No policy writes occur after the last full checkpoint; caller must recheck under its guard before releasing it.
  [pscustomobject]@{phase=$state.phase;revision=$record.revision;display_changed_rules=$observed.display_changed_rules;ready_for_user_apply=$false}
 } finally { $lock.Dispose() }
}
