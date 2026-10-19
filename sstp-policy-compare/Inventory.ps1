# Read-only inventory and comparison; never imports mutation or transaction modules.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:InventoryParts=@('address','application','interface','interface_type','port','security','service')
function InventoryRaw($Cim) {
 $out=[ordered]@{};$ignored=@('Status','PrimaryStatus','StatusCode','EnforcementStatus','OperationalStatus','HealthState','CommunicationStatus','DetailedStatus','OperatingStatus')
 foreach($p in @($Cim.CimInstanceProperties | Sort-Object Name)) {
  if ($p.Name -in $ignored) { continue }
  if ($null -eq $p.Value) { $out[$p.Name]=$null }
  elseif ($p.Value -is [array]) { $out[$p.Name]=@($p.Value | ForEach-Object {[string]$_}) }
  elseif ($p.Value -is [string] -or $p.Value.GetType().IsPrimitive -or $p.Value.GetType().IsEnum -or $p.Value -is [datetime] -or $p.Value -is [guid]) { $out[$p.Name]=[string]$p.Value }
  else { throw 'inventory_unsupported_cim_type' }
 };[pscustomobject]$out
}
function AssertInventoryRaw($Raw) {
 if ($null -eq $Raw -or $Raw -isnot [pscustomobject] -or @($Raw.PSObject.Properties).Count -lt 1 -or @($Raw.PSObject.Properties).Count -gt 128) { throw 'inventory_raw_schema' }
 foreach($p in $Raw.PSObject.Properties) {
  if ($p.Name -cnotmatch '^[A-Za-z][A-Za-z0-9_]{0,80}$') { throw 'inventory_raw_schema' }
  if ($null -eq $p.Value -or $p.Value -is [string]) { continue }
  if ($p.Value -isnot [array]) { throw 'inventory_raw_type' }
  foreach($v in $p.Value) { if ($v -isnot [string]) { throw 'inventory_raw_type' } }
 }
}
function AssertPolicyInventory($Inventory) {
 if ($null -eq $Inventory -or (($Inventory.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'profiles,rules,schema' -or $Inventory.schema -cne 'sstp-policy-inventory-1' -or $Inventory.rules -isnot [array] -or $Inventory.profiles -isnot [array] -or $Inventory.rules.Count -lt 1 -or $Inventory.rules.Count -gt 10000 -or $Inventory.profiles.Count -ne 6) { throw 'inventory_schema' }
 $names=@{};$profileNames=@{}
 foreach($r in $Inventory.rules) {
  if ((($r.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'address,application,interface,interface_type,name,port,rule,security,service' -or $r.name -isnot [string] -or [string]::IsNullOrWhiteSpace($r.name) -or $names.ContainsKey($r.name)) { throw 'inventory_rule_identity' }
  $names[$r.name]=$true;AssertInventoryRaw $r.rule
  if ($r.rule.InstanceID -cne $r.name) { throw 'inventory_rule_identity' }
  foreach($part in $script:InventoryParts) { AssertInventoryRaw $r.$part;if ($r.$part.InstanceID -cne $r.name) { throw 'inventory_filter_identity' } }
 }
 foreach($p in $Inventory.profiles) {
  if ((($p.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'image,name,store' -or $p.store -cnotin @('PersistentStore','ActiveStore') -or $p.name -cnotin @('Domain','Private','Public')) { throw 'inventory_profile_identity' }
  $key=$p.store+'/'+$p.name;if ($profileNames.ContainsKey($key)) { throw 'inventory_profile_identity' };$profileNames[$key]=$true;AssertInventoryRaw $p.image
 }
}
function ReadPolicyInventory {
 $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Sort-Object Name);$map=@{}
 foreach($r in $rules) { if ($map.ContainsKey([string]$r.Name) -or [string]$r.PolicyStoreSourceType -cne 'Local') { throw 'inventory_rule_identity' };$map[[string]$r.Name]=[ordered]@{name=[string]$r.Name;rule=(InventoryRaw $r)} }
 foreach($pair in @(@('address','Get-NetFirewallAddressFilter'),@('application','Get-NetFirewallApplicationFilter'),@('interface','Get-NetFirewallInterfaceFilter'),@('interface_type','Get-NetFirewallInterfaceTypeFilter'),@('port','Get-NetFirewallPortFilter'),@('security','Get-NetFirewallSecurityFilter'),@('service','Get-NetFirewallServiceFilter'))) {
  $seen=@{};$filters=@(& $pair[1] -PolicyStore PersistentStore -ErrorAction Stop)
  foreach($f in $filters) {
   $raw=InventoryRaw $f;$key=[string]$raw.InstanceID
   if (-not $map.ContainsKey($key) -or $seen.ContainsKey($key) -or $map[$key].name -cne $key) { throw ('inventory_filter_join_'+$pair[0]) }
   $seen[$key]=$true;$map[$key][$pair[0]]=$raw
  }
  if ($seen.Count -ne $rules.Count) { throw ('inventory_filter_coverage_'+$pair[0]) }
 }
 $out=@();foreach($r in $rules) { $out+=,[pscustomobject]$map[[string]$r.Name] }
 $profiles=@();foreach($store in @('PersistentStore','ActiveStore')) { foreach($p in @(Get-NetFirewallProfile -PolicyStore $store -ErrorAction Stop | Sort-Object Name)) { $profiles+=,[pscustomobject][ordered]@{store=$store;name=[string]$p.Name;image=(InventoryRaw $p)} } }
 $inventory=[pscustomobject][ordered]@{schema='sstp-policy-inventory-1';rules=$out;profiles=$profiles};AssertPolicyInventory $inventory;return $inventory
}
function RawDifferenceFields($Before,$After) {
 $names=@(@($Before.PSObject.Properties.Name)+@($After.PSObject.Properties.Name) | Sort-Object -Unique);$out=@()
 foreach($name in $names) {
  $b=$Before.PSObject.Properties[$name];$a=$After.PSObject.Properties[$name]
  if ($null -eq $b -or $null -eq $a -or (ConvertTo-Json -InputObject $b.Value -Depth 4 -Compress) -cne (ConvertTo-Json -InputObject $a.Value -Depth 4 -Compress)) { $out+=,$name }
 };return ,$out
}
function ComparePolicyInventory($Before,$After,[string[]]$OwnedRuleNames=@()) {
 AssertPolicyInventory $Before;AssertPolicyInventory $After
 $owned=@{};foreach($name in $OwnedRuleNames) { if ([string]::IsNullOrWhiteSpace($name) -or $owned.ContainsKey($name)) { throw 'inventory_owned_identity' };$owned[$name]=$true }
 $b=@{};$a=@{};foreach($r in $Before.rules) { $b[$r.name]=$r };foreach($r in $After.rules) { $a[$r.name]=$r }
 foreach($name in $owned.Keys) { if (-not $b.ContainsKey($name) -or -not $a.ContainsKey($name) -or $b[$name].name -cne $name -or $a[$name].name -cne $name) { throw 'inventory_owned_identity' } }
 $added=0;$removed=0;$policyRules=0;$displayRules=0;$ownedDisplayRules=0;$policyFields=@();$displayFields=@();$components=@()
 foreach($name in $b.Keys) {
  if (-not $a.ContainsKey($name)) { $removed++;continue }
  $policy=$false;$display=$false
  foreach($part in @('rule')+$script:InventoryParts) {
   foreach($field in (RawDifferenceFields $b[$name].$part $a[$name].$part)) {
    if ($part -ceq 'rule' -and $field -cin @('Description','DisplayGroup','DisplayName')) {
     $display=$true;$displayFields+=,$field
     $bp=$b[$name].rule.PSObject.Properties[$field];$ap=$a[$name].rule.PSObject.Properties[$field]
     $safeDisplay=$null -ne $bp -and $null -ne $ap
     if ($safeDisplay) { $safeDisplay=($null -eq $bp.Value -or $bp.Value -is [string]) -and ($null -eq $ap.Value -or $ap.Value -is [string]) }
     # A missing field or provider TYPE change is NOT ordinary label drift.
     if ($owned.ContainsKey($name) -or -not $safeDisplay) { $policy=$true;$policyFields+=,($part+'.'+$field);$components+=,$part }
    }
    else { $policy=$true;$policyFields+=,($part+'.'+$field);$components+=,$part }
   }
  }
  if ($policy) { $policyRules++ };if ($display) { $displayRules++;if ($owned.ContainsKey($name)) { $ownedDisplayRules++ } }
 }
 foreach($name in $a.Keys) { if (-not $b.ContainsKey($name)) { $added++ } }
 $profiles=0;foreach($p in $Before.profiles) { $other=@($After.profiles | Where-Object { $_.store -ceq $p.store -and $_.name -ceq $p.name });if ($other.Count -ne 1 -or (RawDifferenceFields $p.image $other[0].image).Count -gt 0) { $profiles++ } }
 $equal=($added -eq 0 -and $removed -eq 0 -and $policyRules -eq 0 -and $profiles -eq 0)
 $strict=$equal -and $displayRules -eq 0;$decision='stop_policy_change';if ($strict) { $decision='unchanged' } elseif ($equal) { $decision='display_only' }
 [pscustomobject][ordered]@{schema='sstp-policy-comparison-1';decision=$decision;policy_equal=$equal;strict_equal=$strict;rules_added=$added;rules_removed=$removed;policy_rule_changes=$policyRules;display_rule_changes=$displayRules;owned_display_rule_changes=$ownedDisplayRules;profiles_changed=$profiles;changed_components=@($components | Sort-Object -Unique);policy_property_changes=@($policyFields | Sort-Object -Unique);display_property_changes=@($displayFields | Sort-Object -Unique)}
}
