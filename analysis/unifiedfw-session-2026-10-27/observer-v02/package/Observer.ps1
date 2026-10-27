# Read-only profile lifecycle observer. This file never authorizes firewall changes.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Identity.ps1')
function Read-SstpObserverCallerSid{
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'observer_windows_required'}
 return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}
function Read-SstpObserverProfiles{
 $rows=@()
 foreach($scope in @('current_user','all_users')){
  $args=@{ErrorAction='Stop'};if($scope -ceq 'all_users'){$args.AllUserConnection=$true}
  try{$items=@(Get-VpnConnection @args)}catch{throw 'observer_profile_inventory_unavailable'}
  foreach($v in $items){
   foreach($key in @('Guid','Name','ServerAddress','TunnelType','ConnectionStatus','SplitTunneling')){if($null -eq $v.PSObject.Properties[$key]){throw ('observer_profile_property_missing_'+$key.ToLowerInvariant())}}
   $guid=[guid]::Empty;try{$guid=[guid]$v.Guid}catch{throw 'observer_profile_guid_invalid'}
   if($v.SplitTunneling -isnot [bool]){throw 'observer_split_tunneling_unknown'}
   $rows+=,[pscustomobject][ordered]@{guid=$guid.ToString('D');scope=$scope;name=[string]$v.Name;server=[string]$v.ServerAddress;tunnel=[string]$v.TunnelType;status=[string]$v.ConnectionStatus;split_tunneling=$v.SplitTunneling}
  }
 };return ,$rows
}
function Assert-SstpObserverSelection($Expected){
 $keys=@('schema','profile_guid','profile_scope','profile_name','server','owner_sid')
 if($null -eq $Expected -or ((@($Expected.PSObject.Properties.Name|Sort-Object))-join ',') -cne ((@($keys|Sort-Object))-join ',')){throw 'observer_selection_schema'}
 foreach($k in $keys){if($Expected.$k -isnot [string] -or [string]::IsNullOrWhiteSpace($Expected.$k)){throw 'observer_selection_schema'}}
 if($Expected.schema -cne 'sstp-observer-selection-1' -or $Expected.profile_scope -cnotin @('current_user','all_users') -or $Expected.owner_sid -cnotmatch '^S-1-[0-9]+(-[0-9]+)+$'){throw 'observer_selection_schema'}
 $g=[guid]::Empty;try{$g=[guid]$Expected.profile_guid}catch{throw 'observer_selection_schema'}
 if($g -eq [guid]::Empty -or $g.ToString('D') -cne $Expected.profile_guid){throw 'observer_selection_schema'}
 # Literal-safe eventual interface rule input; never treat a wildcard alias as identity.
 if($Expected.profile_name -cne $Expected.profile_name.Trim() -or $Expected.profile_name.Length -gt 128 -or $Expected.profile_name -ieq 'Any' -or $Expected.profile_name -match '[*?\[\]`\r\n]' -or $Expected.server -match '[\r\n]'){throw 'observer_selection_schema'}
}
function Get-SstpObserverSelected($Profiles,$Expected){
 $sameGuid=@($Profiles|Where-Object{$_.guid -ceq $Expected.profile_guid})
 if($sameGuid.Count -ne 1){throw 'observer_selected_guid_missing_or_ambiguous'}
 $p=$sameGuid[0]
 if($p.scope -cne $Expected.profile_scope -or $p.name -cne $Expected.profile_name -or -not $p.server.Equals($Expected.server,[StringComparison]::OrdinalIgnoreCase) -or $p.tunnel -cne 'Sstp' -or $p.split_tunneling){throw 'observer_selected_profile_changed'}
 if($p.status -cnotin @('Connected','Disconnected','Connecting')){throw 'observer_connection_state_unknown'}
 $other=@($Profiles|Where-Object{$_.status -ceq 'Connected' -and $_.guid -cne $Expected.profile_guid})
 if($other.Count){throw 'observer_other_vpn_connected'}
 return $p
}
function Invoke-SstpLifecycleObservation{
 param($Expected,[ref]$PrivateBinding,$PreviousBinding=$null)
 if($null -ne $PrivateBinding){$PrivateBinding.Value=$null}
 $r=[ordered]@{schema='sstp-lifecycle-observation-02';completed=$false;stage='selection';code='';vpn_state='unknown';selected_profile_matched=$false;identity_chain_verified=$false;interface_alias_literal_safe=$false;binding_compared_to_previous=$false;binding_changed_since_previous=$false;endpoint_verified=$false;DNS_bootstrap_verified=$false;TLS_bootstrap_verified=$false;firewall_approval_granted=$false;read_only=$true;network_policy_changed=$false;credentials_read=$false;DNS_query_generated=$false;vpn_dial_or_hangup_called=$false;raw_identity_exported=$false;snapshots_atomic=$false;guardian_integration=$false;ready_for_apply=$false;no_leak_certified=$false;native_error_line=0;identity_chain_status='';native_api_code=''}
 try{
  Assert-SstpObserverSelection $Expected
  $r.stage='caller_context';$sid=Read-SstpObserverCallerSid
  if($Expected.profile_scope -ceq 'current_user' -and $sid -cne $Expected.owner_sid){throw 'observer_current_user_context_mismatch'}
  $r.stage='profile_inventory';$first=Get-SstpObserverSelected (Read-SstpObserverProfiles) $Expected
  $r.vpn_state=$first.status.ToLowerInvariant()
  $r.stage='native_helper';ImportIdentityNativeHelper
  if($first.status -cne 'Connected'){
   # An entry reported disconnected is not enough: check RAS, then repeat both reads.
   $r.stage='offline_ras_check';$a=@(ReadNativeRasRecords|Where-Object{$_.EntryGuid.ToString('D') -ceq $Expected.profile_guid})
   if($a.Count -gt 1){throw 'observer_ras_entry_ambiguous'}
   if($first.status -ceq 'Disconnected' -and $a.Count){throw 'observer_transition_during_read'}
   WaitIdentityRecheck
   $r.stage='offline_recheck';$again=Get-SstpObserverSelected (Read-SstpObserverProfiles) $Expected
   $b=@(ReadNativeRasRecords|Where-Object{$_.EntryGuid.ToString('D') -ceq $Expected.profile_guid})
   if($again.status -cne $first.status -or $b.Count -ne $a.Count){throw 'observer_transition_during_read'}
   if($Expected.profile_scope -ceq 'current_user' -and (Read-SstpObserverCallerSid) -cne $Expected.owner_sid){throw 'observer_current_user_context_mismatch'}
   $r.completed=$true;$r.selected_profile_matched=$true;$r.stage='completed';$r.code='profile_observed_without_live_binding'
   return [pscustomobject]$r
  }
  $r.stage='live_identity_chain';$private=$null;$chain=InvokeReadOnlyIdentityInspection ([ref]$private)
  if([string]$chain.status -cmatch '^[a-z_]{1,90}$'){$r.identity_chain_status=[string]$chain.status}
  if([string]$chain.code -cmatch '^(ras|binding)_[a-z_0-9]{1,90}$'){$r.native_api_code=[string]$chain.code}
  if(-not $chain.passed -or $null -eq $private){throw 'observer_identity_chain_not_verified'}
  if($chain.observation.candidate_alias_literal_safe -ne $true){throw 'observer_interface_alias_unsafe'}
  if($private.profile_guid -cne $Expected.profile_guid -or $private.profile_scope -cne $Expected.profile_scope -or $private.profile_name -cne $Expected.profile_name){throw 'observer_chain_profile_mismatch'}
  $r.stage='connected_recheck';$again=Get-SstpObserverSelected (Read-SstpObserverProfiles) $Expected
  if($again.status -cne 'Connected'){throw 'observer_transition_during_read'}
  if($Expected.profile_scope -ceq 'current_user' -and (Read-SstpObserverCallerSid) -cne $Expected.owner_sid){throw 'observer_current_user_context_mismatch'}
  if($null -ne $PreviousBinding){
   # Previous binding is only compared, never accepted as a live interface identity.
   $previousKeys=@('profile_guid','profile_scope','profile_name','ras_handle','ras_correlation','client_ipv4','interface_guid','interface_alias','interface_index','net_luid')
   if(((@($PreviousBinding.PSObject.Properties.Name|Sort-Object))-join ',') -cne ((@($previousKeys|Sort-Object))-join ',')){throw 'observer_previous_binding_schema'}
   foreach($key in $previousKeys){
    $value=$PreviousBinding.$key
    if($key -ceq 'interface_index'){
     if(($value -isnot [int] -and $value -isnot [uint32] -and $value -isnot [int64]) -or $value -lt 1 -or $value -gt [uint32]::MaxValue){throw 'observer_previous_binding_schema'}
    }elseif($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)){throw 'observer_previous_binding_schema'}
   }
   if($PreviousBinding.profile_guid -cne $Expected.profile_guid -or $PreviousBinding.profile_scope -cne $Expected.profile_scope -or $PreviousBinding.profile_name -cne $Expected.profile_name){throw 'observer_previous_binding_profile_mismatch'}
   $r.binding_compared_to_previous=$true
   foreach($key in @('ras_handle','ras_correlation','client_ipv4','interface_guid','interface_alias','interface_index','net_luid')){if([string]$private.$key -cne [string]$PreviousBinding.$key){$r.binding_changed_since_previous=$true}}
  }
  $r.completed=$true;$r.selected_profile_matched=$true;$r.identity_chain_verified=$true;$r.interface_alias_literal_safe=$true;$r.stage='completed';$r.code='live_identity_observed_not_enforcement_qualified'
  if($null -ne $PrivateBinding){$PrivateBinding.Value=$private}
 }catch{
  $message=[string]$_.Exception.GetBaseException().Message
  if($message -cmatch '^(ras|binding)_[a-z_0-9]{1,90}$'){$r.native_api_code=$message}
  if($message -cmatch '^observer_[a-z_0-9]{1,90}$'){$r.code=$message}else{$r.code='observer_read_unavailable'}
  $r.completed=$false;$r.selected_profile_matched=$false;$r.identity_chain_verified=$false
  if($null -ne $_.InvocationInfo){$r.native_error_line=[int]$_.InvocationInfo.ScriptLineNumber}
 }
 return [pscustomobject]$r
}
