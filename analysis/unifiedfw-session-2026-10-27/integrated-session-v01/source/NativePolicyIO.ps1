# PRIVATE development adapter. Dot-sourcing defines functions; no native operation runs.
# Requires unchanged InventoryCore.ps1 and SemanticComparison.ps1 in the private module.
# This is NOT a qualified Windows entrypoint or complete transport/app-grant writer.
function Get-UfwLocalJson($Value){return ConvertTo-Json -InputObject $Value -Depth 64 -Compress}
function Copy-UfwLocalData($Value){return ConvertFrom-Json (Get-UfwLocalJson $Value)}
function Get-UfwLocalSnapshotText($Snapshot){
 $stores=@()
 foreach($store in @('PersistentStore','ActiveStore')){
  if($Snapshot.PSObject.Properties.Name -cnotcontains $store){throw 'ufw_unified_native_snapshot_store'}
  $s=$Snapshot.$store;$records=@()
  foreach($r in $s.records){$records+=,[pscustomobject][ordered]@{name=$r.name;enabled=$r.enabled;action=$r.action;direction=$r.direction;source_type=$r.source_type;source_path=$r.source_path;semantic=(Get-UfwSemanticRecord $r.record)}}
  $stores+=,[pscustomobject][ordered]@{store=$store;profiles=$s.profiles;records=$records}
 }
 return Get-UfwLocalJson $stores
}
function Assert-UfwLocalProfiles($Store){
 if($Store.profiles -isnot [array] -or $Store.profiles.Count -ne 3 -or (@($Store.profiles.name|Sort-Object)-join ',') -cne 'Domain,Private,Public'){throw 'ufw_unified_native_profiles_shape'}
 foreach($p in $Store.profiles){if($p.enabled -cne 'True' -or $p.outbound -cne 'Block'){throw 'ufw_unified_native_profiles_not_block'}}
}
function Get-UfwLocalRecordMap($Records){
 $map=New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
 if($Records -isnot [array] -or $Records.Count -gt 4096){throw 'ufw_unified_native_rule_cap'}
 foreach($r in $Records){
  if($r.name -isnot [string] -or [string]::IsNullOrWhiteSpace($r.name) -or $r.name.Length -gt 65536 -or $map.ContainsKey($r.name)){throw 'ufw_unified_native_rule_identity'}
  if($r.enabled -cnotin @('True','False') -or $r.direction -cnotin @('Inbound','Outbound') -or $r.action -cnotin @('Allow','Block')){throw 'ufw_unified_native_rule_state'}
  if($r.record.rule.properties.PSObject.Properties.Name -cnotcontains 'InstanceID' -or $r.record.rule.properties.InstanceID.cim_type -cne 'String' -or $r.record.rule.properties.InstanceID.value -cne $r.name){throw 'ufw_unified_native_rule_name_projection'}
  $raw=$r.record.rule.properties.Enabled
  if($raw.cim_type -cne 'UInt16' -or $raw.value -is [string] -or $raw.value -is [bool] -or $raw.value -notin @(1,2) -or (($raw.value -eq 1) -ne ($r.enabled -ceq 'True'))){throw 'ufw_unified_native_enabled_projection'}
  [void](Get-UfwSemanticRecord $r.record);$map.Add($r.name,$r)
 }
 return ,$map
}
function Read-UfwLocalStableSnapshot($IO){
 # TWO full passes include all seven filters, not the old inventory's header-only check.
 # Still sequential observations: not an atomic WFP snapshot or a compare-and-swap.
 foreach($key in @('ReadStore','CheckTime','Actor')){if(-not $IO.ContainsKey($key) -or $IO[$key] -isnot [scriptblock]){throw 'ufw_unified_native_reader_missing'}}
 $actor=& $IO.Actor;$first=$null;$last=$null
 for($pass=0;$pass -lt 2;$pass++){
  $snap=[ordered]@{};$handles=$null
  foreach($store in @('PersistentStore','ActiveStore')){
   & $IO.CheckTime;$read=& $IO.ReadStore $store
   Assert-UfwLocalProfiles $read;[void](Get-UfwLocalRecordMap $read.records)
   $snap[$store]=[pscustomobject]@{profiles=$read.profiles;records=$read.records}
   if($store -ceq 'PersistentStore'){$handles=$read.handles}
  }
  $last=[pscustomobject]@{snapshot=[pscustomobject]$snap;handles=$handles;actor=$actor}
  $text=Get-UfwLocalSnapshotText $last.snapshot
  if($pass -eq 0){$first=$text}elseif($text -cne $first){throw 'ufw_unified_native_full_filter_drift'}
 }
 if((& $IO.Actor) -cne $actor){throw 'ufw_unified_native_actor_drift'}
 & $IO.CheckTime
 return $last
}
function New-UfwLocalQuarantineOperations($Snapshot){
 Assert-UfwLocalProfiles $Snapshot.PersistentStore;Assert-UfwLocalProfiles $Snapshot.ActiveStore
 $local=Get-UfwLocalRecordMap $Snapshot.PersistentStore.records;$active=Get-UfwLocalRecordMap $Snapshot.ActiveStore.records;$ops=@();$n=0
 foreach($r in $Snapshot.ActiveStore.records){
  if($r.enabled -cne 'True' -or $r.direction -cne 'Outbound' -or $r.action -cne 'Allow'){continue}
  if($r.source_type -cne 'Local' -or [string]::IsNullOrWhiteSpace($r.source_path) -or -not $local.ContainsKey($r.name)){throw 'ufw_unified_native_allow_not_local'}
  $l=$local[$r.name]
  if($l.name -cne $r.name -or $l.enabled -cne 'True' -or $l.direction -cne 'Outbound' -or $l.action -cne 'Allow' -or -not (Compare-UfwPrivateSnapshotPair $l.record $r.record).semantic_fields_match){throw 'ufw_unified_native_local_effective_mismatch'}
  $before=[pscustomobject]@{local=(Copy-UfwLocalData $l);effective=(Copy-UfwLocalData $r)};$after=Copy-UfwLocalData $before
  foreach($side in @('local','effective')){$after.$side.enabled='False';$after.$side.record.rule.properties.Enabled.value=2}
  $n++;$ops+=,[pscustomobject][ordered]@{id=('local-'+$n.ToString('0000'));kind='disable_reviewed_local_allow';name=$r.name;before=$before;after=$after}
 }
 if($ops.Count -gt 510){throw 'ufw_unified_native_operation_cap'}
 return ,$ops
}
function New-UfwWindowsLocalPolicyIO {
 # Merely constructing this private dictionary grants no review/qualification.
 # Scope and qualified live entrypoint are deliberately still absent.
 $watch=[Diagnostics.Stopwatch]::StartNew()
 $check=New-UfwLocalModuleCallback {param($watch)if($watch.Elapsed.TotalMinutes -gt 15){throw 'ufw_unified_native_time_cap'}} $watch
 $read=New-UfwLocalModuleCallback {param($check,$store)
  & $check;$budget=[pscustomobject]@{nodes=0}
  if($store -ceq 'ActiveStore'){$rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop)}
  elseif($store -ceq 'PersistentStore'){$rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)}else{throw 'ufw_unified_native_store_scope'}
  if($rules.Count -gt 4096){throw 'ufw_unified_native_rule_cap'}
  $profiles=@(Get-NetFirewallProfile -PolicyStore $store -ErrorAction Stop|Sort-Object Name|ForEach-Object{[pscustomobject]@{name=[string]$_.Name;enabled=[string]$_.Enabled;outbound=[string]$_.DefaultOutboundAction;record=(ConvertTo-UfwInventoryValue $_ 0 $budget)}})
  $pairs=New-Object 'Collections.Generic.SortedDictionary[string,object]' ([StringComparer]::Ordinal)
  $handles=New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
  foreach($rule in $rules){$name=[string]$rule.Name;if([string]::IsNullOrWhiteSpace($name) -or $handles.ContainsKey($name)){throw 'ufw_unified_native_rule_identity'};$pairs.Add($name,$rule);$handles.Add($name,$rule)}
  $records=@()
  foreach($pair in $pairs.GetEnumerator()){
   & $check;$rule=$pair.Value;$filters=[ordered]@{}
   foreach($kind in @('Address','Application','Interface','InterfaceType','Port','Security','Service')){
    $items=@(switch -CaseSensitive ($kind){
     'Address'{$rule|Get-NetFirewallAddressFilter -ErrorAction Stop}
     'Application'{$rule|Get-NetFirewallApplicationFilter -ErrorAction Stop}
     'Interface'{$rule|Get-NetFirewallInterfaceFilter -ErrorAction Stop}
     'InterfaceType'{$rule|Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop}
     'Port'{$rule|Get-NetFirewallPortFilter -ErrorAction Stop}
     'Security'{$rule|Get-NetFirewallSecurityFilter -ErrorAction Stop}
     'Service'{$rule|Get-NetFirewallServiceFilter -ErrorAction Stop}
    })
    if($items.Count -ne 1){throw 'ufw_unified_native_filter_cardinality'};$filters[$kind]=ConvertTo-UfwInventoryValue $items[0] 0 $budget
   }
   $records+=,[pscustomobject]@{name=$pair.Key;enabled=[string]$rule.Enabled;action=[string]$rule.Action;direction=[string]$rule.Direction;source_type=[string]$rule.PolicyStoreSourceType;source_path=[string]$rule.PolicyStoreSource;record=[pscustomobject]@{rule=(ConvertTo-UfwInventoryValue $rule 0 $budget);associated_filters=[pscustomobject]$filters}}
  }
  [pscustomobject]@{profiles=$profiles;records=$records;handles=$handles}
 } $check
 $set={param($native,$enabled)
  if($env:OS -cne 'Windows_NT' -or $native.GetType().FullName -cne 'Microsoft.Management.Infrastructure.CimInstance' -or $native.CimSystemProperties.ClassName -cne 'MSFT_NetFirewallRule' -or $enabled -cnotin @('True','False')){throw 'ufw_unified_native_setter_scope'}
  # ONE freshly observed PersistentStore object. No Name/DisplayName/group wildcard.
  Set-NetFirewallRule -InputObject $native -Enabled $enabled -Confirm:$false -ErrorAction Stop|Out-Null
 }
 return @{ReadStore=$read;CheckTime=$check;Actor={[Security.Principal.WindowsIdentity]::GetCurrent().User.Value};SetEnabled=$set}
}
