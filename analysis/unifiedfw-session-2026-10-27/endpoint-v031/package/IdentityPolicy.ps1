Set-StrictMode -Version Latest
function NewRasIdentityObservation {
 [pscustomobject][ordered]@{
  profile_inventory_complete=$false;active_sstp_count=$null;profile_guid_unique=$null
  ras_inventory_available=$null;ras_profile_guid_match_count=$null;ras_name_matches=$null;ras_scope_matches=$null;ras_device_is_vpn=$null;ras_session_marker_available=$null
  projection_ipv4_available=$null;projection_ip_matching_interfaces=$null;candidate_is_ppp=$null;candidate_operational_up=$null
  interface_index_luid_guid_roundtrip=$null;connection_stable_on_recheck=$null;alias_equal_to_profile_name=$null;candidate_alias_literal_safe=$null
 }
}
function GetRasIdentityDecision($Observation) {
 $keys=@((NewRasIdentityObservation).PSObject.Properties.Name | Sort-Object)
 if ($null -eq $Observation -or (($Observation.PSObject.Properties.Name | Sort-Object) -join ',') -cne ($keys -join ',')) { return 'invalid_observation_schema' }
 foreach($k in $keys) {
  $v=$Observation.$k
  if($null -eq $v) { continue }
  if($k -in @('active_sstp_count','ras_profile_guid_match_count','projection_ip_matching_interfaces')) { if($v -isnot [int] -or $v -lt 0 -or $v -gt 128) { return 'invalid_observation_schema' } }
  elseif($v -isnot [bool]) { return 'invalid_observation_schema' }
 }
 if ($Observation.profile_inventory_complete -ne $true) { return 'profile_inventory_incomplete' }
 if ($Observation.active_sstp_count -ne 1) { return 'no_unique_active_sstp' }
 if ($Observation.profile_guid_unique -ne $true) { return 'profile_guid_unavailable_or_ambiguous' }
 if ($Observation.ras_inventory_available -ne $true) { return 'ras_inventory_unavailable' }
 if ($Observation.ras_profile_guid_match_count -ne 1) { return 'ras_entry_guid_not_unique' }
 if ($Observation.ras_name_matches -ne $true -or $Observation.ras_scope_matches -ne $true -or $Observation.ras_device_is_vpn -ne $true) { return 'ras_entry_metadata_conflict' }
 if ($Observation.ras_session_marker_available -ne $true) { return 'ras_session_marker_unavailable' }
 if ($Observation.projection_ipv4_available -ne $true) { return 'projection_ipv4_unavailable' }
 if ($Observation.projection_ip_matching_interfaces -ne 1) { return 'projection_address_not_unique' }
 if ($Observation.candidate_is_ppp -ne $true -or $Observation.candidate_operational_up -ne $true) { return 'candidate_not_up_ppp' }
 if ($Observation.interface_index_luid_guid_roundtrip -ne $true) { return 'interface_identifier_mismatch' }
 if ($Observation.connection_stable_on_recheck -ne $true) { return 'connection_changed_during_read' }
 return 'identity_chain_observed'
}
