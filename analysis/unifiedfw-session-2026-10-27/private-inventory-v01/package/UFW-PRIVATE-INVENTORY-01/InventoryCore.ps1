function ConvertTo-UfwInventoryValue($Value,[int]$Depth,$Budget){
 $Budget.nodes++;if($Budget.nodes -gt 1000000 -or $Depth -gt 12){throw 'ufw_inventory_serialization_cap'}
 if($null -eq $Value){return $null}
 if($Value -is [string] -and $Value.Length -gt 65536){throw 'ufw_inventory_string_cap'}
 if($Value -is [string] -or $Value -is [bool] -or $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64] -or $Value -is [decimal]){return $Value}
 if($Value -is [single] -or $Value -is [double]){if([double]::IsNaN([double]$Value) -or [double]::IsInfinity([double]$Value)){throw 'ufw_inventory_numeric_value'};return $Value}
 if($Value -is [datetime]){return [pscustomobject]@{kind='datetime';text=$Value.ToString('o')}}
 if($Value -is [timespan]){return [pscustomobject]@{kind='timespan';text=$Value.ToString('c')}}
 if($Value.GetType().IsEnum){return [pscustomobject]@{kind='enum';type=$Value.GetType().FullName;text=[string]$Value}}
 if($Value -is [array]){if($Value.Length -gt 32768){throw 'ufw_inventory_array_cap'};$out=@();foreach($v in $Value){$out+=,(ConvertTo-UfwInventoryValue $v ($Depth+1) $Budget)};return ,$out}
 if($Value.GetType().FullName -ceq 'Microsoft.Management.Infrastructure.CimInstance' -or ($Value.PSObject.Properties.Name -contains 'CimInstanceProperties' -and $Value.PSObject.Properties.Name -contains 'CimSystemProperties')){
  $names=[string[]]@($Value.CimInstanceProperties|ForEach-Object{$_.Name});[Array]::Sort($names,[StringComparer]::Ordinal)
  $out=[ordered]@{};foreach($name in $names){if($out.Contains($name)){throw 'ufw_inventory_duplicate_property'};$p=$Value.CimInstanceProperties[$name];$out[$name]=[pscustomobject]@{cim_type=[string]$p.CimType;value=(ConvertTo-UfwInventoryValue $p.Value ($Depth+1) $Budget)}}
  return [pscustomobject]@{class=[string]$Value.CimSystemProperties.ClassName;namespace=[string]$Value.CimSystemProperties.Namespace;properties=[pscustomobject]$out}
 }
 throw 'ufw_inventory_unsupported_value_type'
}
function Get-UfwInventoryJson($Value){return ConvertTo-Json -InputObject $Value -Depth 64 -Compress}
function Get-UfwInventoryOriginCounts($Rules,$PersistentRules){
 $counts=[ordered]@{Local=0;GroupPolicy=0;Dynamic=0;Generated=0;Hardcoded=0;Unknown=0}
 $local=New-Object 'System.Collections.Generic.Dictionary[string,int]' ([StringComparer]::Ordinal)
 foreach($r in $PersistentRules){$name=[string]$r.Name;if($local.ContainsKey($name)){$local[$name]++}else{$local[$name]=1}}
 $allows=0;$candidates=0
 foreach($r in $Rules){if([string]$r.Enabled -ceq 'True' -and [string]$r.Direction -ceq 'Outbound' -and [string]$r.Action -ceq 'Allow'){
  $allows++;$source='Unknown';if($r.PSObject.Properties.Name -contains 'PolicyStoreSourceType'){$candidate=[string]$r.PolicyStoreSourceType;if($counts.Contains($candidate) -and $candidate -cne 'Unknown'){$source=$candidate}}
  $counts[$source]++;$name=[string]$r.Name;if($source -ceq 'Local' -and $local.ContainsKey($name) -and $local[$name] -eq 1){$candidates++}
 }}
 return [pscustomobject]@{enabled_outbound_allow_rules=$allows;source_counts=$counts;unique_local_name_candidates=$candidates;candidate_is_semantic_equivalence=$false;candidate_is_write_authority=$false}
}
function Invoke-UfwInventoryCapture($Ops){
 $r=[ordered]@{schema='ufw-private-inventory-result-01';completed=$false;stage='local_storage_consent';current_store='not_started';current_filter_kind='not_started';code='';consent_received=$false;stores_read=0;rules_read=0;rules_with_filter_sets=0;filter_objects_read=0;profiles_read=0;header_rechecks=0;header_rechecks_match=$false;private_write_attempted=$false;private_snapshot_readback_verified=$false;origins=$null;snapshot_atomic=$false;filter_stability_verified=$false;whole_WFP_inventory_verified=$false;native_restore_qualified=$false;ready_for_apply=$false;target_execution_authorized=$false;raw_identity_exported=$false}
 try{
  foreach($k in @('Confirm','Actor','Clock','Rules','Profiles','Filters','Serialize','Save','Progress','CheckTime')){if(-not $Ops.ContainsKey($k) -or $Ops[$k] -isnot [scriptblock]){throw 'ufw_inventory_adapter_missing'}}
  $answer=& $Ops.Confirm;if($answer -isnot [bool] -or -not $answer){$r.completed=$true;$r.code='ufw_inventory_cancelled_no_snapshot';return [pscustomobject]$r};$r.consent_received=$true
  $actor=& $Ops.Actor;$started=& $Ops.Clock;$stores=@();$headers=@{};$native=@{}
  foreach($store in @('PersistentStore','ActiveStore')){
   $r.current_store=$store;& $Ops.CheckTime;$r.stage='read_profiles_and_rules';$profiles=@(& $Ops.Profiles $store);$rules=@(& $Ops.Rules $store)
   if($profiles.Count -ne 3 -or (@($profiles.Name|Sort-Object)-join ',') -cne 'Domain,Private,Public'){throw 'ufw_inventory_profile_shape'}
   if($rules.Count -gt 4096){throw 'ufw_inventory_rule_cap'}
   $r.profiles_read+=$profiles.Count;$r.rules_read+=$rules.Count;$native[$store]=$rules
   $pairs=@();$seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
   foreach($rule in $rules){$name=[string]$rule.Name;if([string]::IsNullOrWhiteSpace($name) -or -not $seen.Add($name)){throw 'ufw_inventory_rule_identity_ambiguous'};$pairs+=,[pscustomobject]@{name=$name;rule=$rule}}
   $pairs=@($pairs|Sort-Object -Property name -CaseSensitive)
   $head=@();$records=@()
   foreach($pair in $pairs){
    & $Ops.CheckTime;$r.stage='serialize_rule';$r.current_filter_kind='RuleProperties';$converted=& $Ops.Serialize $pair.rule;$head+=,$converted;$filters=[ordered]@{}
    foreach($kind in @('Application','Service','Port','Address','Interface','InterfaceType','Security')){
     $r.stage='read_associated_filters';$r.current_filter_kind=$kind;$items=@(& $Ops.Filters $kind $pair.rule)
     if($items.Count -ne 1){throw 'ufw_inventory_filter_cardinality'}
     $filters[$kind]=& $Ops.Serialize $items[0];$r.filter_objects_read++
    }
    $records+=,[pscustomobject]@{rule=$converted;associated_filters=[pscustomobject]$filters};$r.rules_with_filter_sets++
    & $Ops.Progress $r.rules_with_filter_sets
   }
   $profileData=@($profiles|Sort-Object Name|ForEach-Object{& $Ops.Serialize $_})
   $headers[$store]=Get-UfwInventoryJson ([pscustomobject]@{profiles=$profileData;rules=$head})
   $stores+=,[pscustomobject]@{store=$store;profiles=$profileData;rules=$records};$r.stores_read++
  }
  $r.stage='header_recheck'
  foreach($store in @('PersistentStore','ActiveStore')){
   $r.current_store=$store;$r.current_filter_kind='HeaderRecheck';& $Ops.CheckTime;$rules=@(& $Ops.Rules $store);$profiles=@(& $Ops.Profiles $store)
   if($rules.Count -gt 4096){throw 'ufw_inventory_rule_cap'}
   $head=@($rules|Sort-Object Name -CaseSensitive|ForEach-Object{& $Ops.Serialize $_});$prof=@($profiles|Sort-Object Name|ForEach-Object{& $Ops.Serialize $_})
   if((Get-UfwInventoryJson ([pscustomobject]@{profiles=$prof;rules=$head})) -cne $headers[$store]){throw 'ufw_inventory_headers_changed'};$r.header_rechecks++
  }
  if((& $Ops.Actor) -cne $actor){throw 'ufw_inventory_actor_changed'}
  $r.header_rechecks_match=$true;$r.origins=Get-UfwInventoryOriginCounts $native.ActiveStore $native.PersistentStore
  $private=[pscustomobject]@{schema='ufw-private-policy-snapshot-01';scope='storage_only_no_restore_authority';actor_sid=$actor;created_utc=$started;finished_utc=(& $Ops.Clock);filter_snapshot_atomic=$false;full_WFP_coverage=$false;native_restore_qualified=$false;stores=$stores}
  & $Ops.CheckTime;$r.stage='save_private_snapshot';$r.private_write_attempted=$true;$saved=& $Ops.Save $private
  if($saved.readback_verified -isnot [bool] -or -not $saved.readback_verified){throw 'ufw_inventory_readback_unverified'}
  $r.private_snapshot_readback_verified=$true;$r.completed=$true;$r.stage='completed';$r.code='ufw_inventory_private_snapshot_saved_not_apply_authority'
 }catch{$msg=[string]$_.Exception.GetBaseException().Message;if($msg -cmatch '^ufw_(inventory|journal)_[a-z_0-9]{1,90}$'){$r.code=$msg}else{$r.code='ufw_inventory_unavailable'}}
 return [pscustomobject]$r
}
