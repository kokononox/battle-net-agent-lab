param([Parameter(Mandatory=$true)][string]$OutputPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Inventory.ps1"
$script:checks=0;$rawCases=0;$filterCases=0;$ownedCases=0;$missingCases=0;$associationChecks=0;$ruleCount=-1;$passed=$false;$errorCode=$null;$nativeDisplayChanges=-1
function Check([bool]$Ok) { if (-not $Ok) { throw 'inventory_test_assertion' };$script:checks++ }
function Clone($Object) { $Object | ConvertTo-Json -Depth 16 -Compress | ConvertFrom-Json }
function Reject([scriptblock]$Body) { $caught=$false;try { & $Body | Out-Null } catch { if ($_.Exception.Message -notmatch '^inventory_[a-z_]+$') { throw };$caught=$true };Check $caught }
function ChangedValue($Value) { if ($Value -is [array]) { return ,(@($Value)+@('fixture-value')) };return 'fixture-value' }
try {
 $native=ReadPolicyInventory;$ruleCount=$native.rules.Count;Check ($ruleCount -ge 6)
 $base=Clone $native;$base.rules=@($base.rules | Select-Object -First 2)
 Check ((ComparePolicyInventory $base $base).decision -ceq 'unchanged')
 # Every observed raw property of one rule AND all seven filters is exercised in memory.
 foreach($part in @('rule')+$script:InventoryParts) {
  foreach($prop in $base.rules[0].$part.PSObject.Properties) {
   $changed=Clone $base;$name=$prop.Name;$changed.rules[0].$part.$name=ChangedValue $prop.Value
   if ($name -ceq 'InstanceID') { Reject { ComparePolicyInventory $base $changed };$rawCases++;continue }
   $c=ComparePolicyInventory $base $changed
   if ($part -ceq 'rule' -and $name -cin @('Description','DisplayGroup','DisplayName')) {
    Check ($c.decision -ceq 'display_only' -and $c.policy_equal -and -not $c.strict_equal)
    $owned=ComparePolicyInventory $base $changed @($base.rules[0].name)
    Check ($owned.decision -ceq 'stop_policy_change' -and $owned.owned_display_rule_changes -eq 1);$ownedCases++
   } else { Check ($c.decision -ceq 'stop_policy_change' -and ($c.policy_property_changes -ccontains ($part+'.'+$name))) }
   $rawCases++
  }
  if ($part -cne 'rule') { $filterCases++ }
 }
 foreach($prop in $base.profiles[0].image.PSObject.Properties) {
  $changed=Clone $base;$changed.profiles[0].image.($prop.Name)=ChangedValue $prop.Value
  $c=ComparePolicyInventory $base $changed;Check ($c.decision -ceq 'stop_policy_change' -and $c.profiles_changed -eq 1);$rawCases++
 }
 foreach($part in $script:InventoryParts) {
  $changed=Clone $base;$changed.rules[0].PSObject.Properties.Remove($part)
  Reject { ComparePolicyInventory $base $changed };$missingCases++
 }
 # New/removed provider properties, including future fields, must NOT be treated as display drift.
 $changed=Clone $base;$changed.rules[0].address | Add-Member FutureProviderField 'fixture'
 Check ((ComparePolicyInventory $base $changed).decision -ceq 'stop_policy_change')
 $changed=Clone $base;$changed.rules[0].address.PSObject.Properties.Remove('RemoteAddress')
 Check ((ComparePolicyInventory $base $changed).decision -ceq 'stop_policy_change')
 $changed=Clone $base;$changed.rules[0].rule | Add-Member display_name 'fixture'
 Check ((ComparePolicyInventory $base $changed).decision -ceq 'stop_policy_change')
 $changed=Clone $base;$changed.rules=@($changed.rules[0]);Check ((ComparePolicyInventory $base $changed).rules_removed -eq 1)
 $changed=Clone $base;$extra=Clone $base.rules[0];$extra.name='fixture-extra-rule';$extra.rule.InstanceID=$extra.name
 foreach($part in $script:InventoryParts) { $extra.$part.InstanceID=$extra.name }
 $changed.rules=@($changed.rules)+@($extra);Check ((ComparePolicyInventory $base $changed).rules_added -eq 1)
 $changed=Clone $base;$changed.rules=@($changed.rules[0],$changed.rules[0]);Reject { ComparePolicyInventory $base $changed }
 Reject { ComparePolicyInventory $base $base @('not-an-owned-rule') }
 $changed=Clone $base;$changed.rules=[object[]]@($changed.rules[1],$changed.rules[0]);Check ((ComparePolicyInventory $base $changed).decision -ceq 'unchanged')
 # Qualify all seven bulk joins against actual AssociatedNetFirewallRule reads on six spaced rules.
 $indices=@(0,[int][Math]::Floor($ruleCount/5),[int][Math]::Floor(2*$ruleCount/5),[int][Math]::Floor(3*$ruleCount/5),[int][Math]::Floor(4*$ruleCount/5),($ruleCount-1))
 foreach($index in $indices) {
  $row=$native.rules[$index];$escaped=[Management.Automation.WildcardPattern]::Escape($row.name)
  $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name $escaped -ErrorAction Stop)
  Check ($rules.Count -eq 1 -and $rules[0].Name -ceq $row.name)
  foreach($pair in @(@('address','Get-NetFirewallAddressFilter'),@('application','Get-NetFirewallApplicationFilter'),@('interface','Get-NetFirewallInterfaceFilter'),@('interface_type','Get-NetFirewallInterfaceTypeFilter'),@('port','Get-NetFirewallPortFilter'),@('security','Get-NetFirewallSecurityFilter'),@('service','Get-NetFirewallServiceFilter'))) {
   $f=@(& $pair[1] -AssociatedNetFirewallRule $rules[0] -ErrorAction Stop)
   Check ($f.Count -eq 1 -and (RawDifferenceFields $row.($pair[0]) (InventoryRaw $f[0])).Count -eq 0);$associationChecks++
  }
 }
 $after=ReadPolicyInventory;$comparison=ComparePolicyInventory $native $after;$nativeDisplayChanges=$comparison.display_rule_changes
 Check ($comparison.policy_equal)
 Check ($rawCases -ge 50 -and $filterCases -eq 7 -and $ownedCases -eq 3 -and $missingCases -eq 7 -and $associationChecks -eq 42)
 $passed=$true
} catch {
 $errorCode='inventory_native_failure'
 if ($_.Exception.Message -match '^inventory_[a-z_]+$') { Write-Host $_.Exception.Message } else { Write-Host ('inventory_provider_failure_'+$_.Exception.GetType().Name.ToLowerInvariant()) }
 Write-Host ('inventory_checks_before_failure_'+$script:checks)
}
$r=[ordered]@{schema='sstp-policy-compare-test-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;passed=$passed;error_code=$errorCode;checks=$script:checks;raw_field_cases=$rawCases;filter_types_tested=$filterCases;owned_display_cases=$ownedCases;missing_filter_cases=$missingCases;association_checks=$associationChecks;native_rule_count=$ruleCount;native_display_changes=$nativeDisplayChanges;read_only=$true;firewall_mutations=$false;mutation_modules_imported=$false;enforcement_tested=$false;user_device_tested=$false;ready_for_user_apply=$false}
[IO.File]::WriteAllText($OutputPath,($r | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
if (-not $passed) { exit 1 };exit 0
