# Read-only profile foundation; no imports from the legacy mutation runtime.
Set-StrictMode -Version 2.0
function Assert-UfwReadPlatform {
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'ufw_read_windows_required'}
 if(-not [Environment]::Is64BitProcess){throw 'ufw_read_x64_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1){throw 'ufw_read_ps51_required'}
}
function ConvertTo-UfwProfileRows($Rows,[string]$Store) {
 if($Store -cnotin @('PersistentStore','ActiveStore')){throw 'ufw_read_store_invalid'}
 $items=@($Rows)
 if($items.Count -ne 3){throw 'ufw_read_profile_coverage'}
 $seen=@{};$out=@()
 foreach($item in $items){
  if($null -eq $item){throw 'ufw_read_profile_null'}
  foreach($field in @('Name','DefaultOutboundAction','Enabled','AllowLocalFirewallRules','DisabledInterfaceAliases')){
   if($null -eq $item.PSObject.Properties[$field]){throw 'ufw_read_profile_field_missing'}
  }
  $name=[string]$item.Name
  if($name -cnotin @('Domain','Private','Public') -or $seen.ContainsKey($name)){throw 'ufw_read_profile_identity'}
  $seen[$name]=$true
  if($null -eq $item.DefaultOutboundAction -or $null -eq $item.Enabled -or $null -eq $item.AllowLocalFirewallRules){throw 'ufw_read_profile_value_missing'}
  $outbound=[string]$item.DefaultOutboundAction;$enabled=[string]$item.Enabled;$localRules=[string]$item.AllowLocalFirewallRules
  if($outbound -cnotin @('Allow','Block','NotConfigured') -or $enabled -cnotin @('True','False','NotConfigured') -or $localRules -cnotin @('True','False','NotConfigured')){throw 'ufw_read_profile_encoding'}
  # A typed empty CIM StringArray is valid; an arbitrary null is not evidence.
  $aliases=$item.DisabledInterfaceAliases
  if($null -eq $aliases){
   if($null -eq $item.PSObject.Properties['CimInstanceProperties']){throw 'ufw_read_exclusions_unknown'}
   $meta=$item.CimInstanceProperties['DisabledInterfaceAliases']
   if($null -eq $meta -or [string]$meta.CimType -cne 'StringArray' -or $null -ne $meta.Value){throw 'ufw_read_exclusions_unknown'}
  }else{
   if($aliases -isnot [array] -and $aliases -isnot [string]){throw 'ufw_read_exclusions_encoding'}
   foreach($alias in @($aliases)){
    if($null -eq $alias -or [string]::IsNullOrWhiteSpace([string]$alias)){throw 'ufw_read_exclusions_unknown'}
    if([string]$alias -ine 'NotConfigured'){throw 'ufw_read_excluded_interface_present'}
   }
  }
  $out+=,[pscustomobject][ordered]@{store=$Store;name=$name;outbound=$outbound;enabled=$enabled;allow_local_rules=$localRules;no_excluded_interfaces_reported=$true}
 }
 return @($out|Sort-Object name)
}
function Read-UfwProfilePair([ref]$ReadCount) {
 # Exactly two native queries per observation, not one query per property/profile.
 $ReadCount.Value++;$local=@(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop)
 $ReadCount.Value++;$effective=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
 return [pscustomobject][ordered]@{local=@(ConvertTo-UfwProfileRows $local 'PersistentStore');effective=@(ConvertTo-UfwProfileRows $effective 'ActiveStore')}
}
function Get-UfwProfileAssessment($Pair){
 $rows=@();$reasons=@();$explicit=$true;$compatible=$true;$normal=$true
 foreach($name in @('Domain','Private','Public')){
  $l=@($Pair.local|Where-Object{$_.name -ceq $name});$e=@($Pair.effective|Where-Object{$_.name -ceq $name})
  if($l.Count -ne 1 -or $e.Count -ne 1){throw 'ufw_read_assessment_coverage'}
  $l=$l[0];$e=$e[0]
  if($l.outbound -cnotin @('Allow','Block')){$explicit=$false;$compatible=$false;$reasons+=,($name+':local_outbound_not_explicit')}
  if($l.outbound -cne $e.outbound){$compatible=$false;$reasons+=,($name+':local_effective_outbound_mismatch')}
  if($e.enabled -cne 'True'){$compatible=$false;$reasons+=,($name+':effective_firewall_not_enabled')}
  # Unknown effective local-rule policy does not authorize a later mutation.
  if($e.allow_local_rules -cne 'True'){$compatible=$false;$reasons+=,($name+':effective_local_rules_not_true')}
  if($l.outbound -cne 'Allow' -or $e.outbound -cne 'Allow'){$normal=$false}
  $rows+=,[pscustomobject][ordered]@{name=$name;local_outbound=$l.outbound;effective_outbound=$e.outbound;local_enabled=$l.enabled;effective_enabled=$e.enabled;local_allow_local_rules=$l.allow_local_rules;effective_allow_local_rules=$e.allow_local_rules}
 }
 return [pscustomobject][ordered]@{profiles=$rows;explicit_local_outbound_baseline_present=$explicit;profile_fields_compatible_for_later_review=$compatible;all_outbound_allow=$normal;reasons=$reasons;requires_explicit_future_consent=$true;ready_for_apply=$false;normal_mode_record_authorized=$false;original_restore_verified=$false;no_leak_certified=$false}
}
function Invoke-UfwProfilePreflightReadOnly {
 $r=[ordered]@{schema='ufw-readonly-profile-preflight-01';completed=$false;code='';assessment=$null;observation_started_utc=[datetime]::UtcNow.ToString('o');observation_finished_utc=$null;two_observations_match=$false;native_store_reads_attempted=0;snapshot_is_atomic=$false;legacy_runtime_imported=$false;legacy_journal_read=$false;file_write_requested=$false;firewall_change_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;ready_for_apply=$false;no_leak_certified=$false}
 $reads=0
 try {
  Assert-UfwReadPlatform
  $before=Read-UfwProfilePair ([ref]$reads)
  $after=Read-UfwProfilePair ([ref]$reads)
  if((ConvertTo-Json -InputObject $before -Depth 10 -Compress) -cne (ConvertTo-Json -InputObject $after -Depth 10 -Compress)){throw 'ufw_read_profile_drift_between_observations'}
  $r.two_observations_match=$true;$r.assessment=Get-UfwProfileAssessment $after;$r.completed=$true;$r.code='ufw_read_observed_profiles_only'
 }catch {
  $m=[string]$_.Exception.GetBaseException().Message
  if($m -cmatch '^ufw_read_[a-z_0-9]{1,100}$'){$r.code=$m}else{$r.code='ufw_read_native_unavailable'}
 }finally{$r.native_store_reads_attempted=$reads;$r.observation_finished_utc=[datetime]::UtcNow.ToString('o')}
 return [pscustomobject]$r
}
Export-ModuleMember -Function Invoke-UfwProfilePreflightReadOnly
