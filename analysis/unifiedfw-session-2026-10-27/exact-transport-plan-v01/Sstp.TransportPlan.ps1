# OFFLINE, NON-EXECUTABLE DRAFT. Shape validation is not approval or native proof.
Set-StrictMode -Version 2.0
function ConvertTo-SstpPlanIP($Value){
 if($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value) -or $Value -cne $Value.Trim() -or $Value -match '[/%,*?\[\]\s]'){throw 'plan_exact_ip_required'}
 $ip=$null;if(-not [Net.IPAddress]::TryParse($Value,[ref]$ip)){throw 'plan_exact_ip_required'}
 if($ip.IsIPv4MappedToIPv6){throw 'plan_mapped_ip_not_supported'}
 $bytes=$ip.GetAddressBytes()
 if($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork){
  if($Value -cne $ip.ToString()){throw 'plan_canonical_ipv4_required'}
  if($bytes[0] -eq 0 -or $bytes[0] -eq 127 -or $bytes[0] -ge 224 -or ($bytes[0] -eq 169 -and $bytes[1] -eq 254)){throw 'plan_unicast_endpoint_required'}
 }elseif($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){
  if($ip.Equals([Net.IPAddress]::IPv6Any) -or $ip.Equals([Net.IPAddress]::IPv6Loopback) -or $ip.IsIPv6Multicast -or $ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal){throw 'plan_unicast_endpoint_required'}
 }else{throw 'plan_exact_ip_required'}
 return $ip.ToString()
}
function ConvertTo-SstpPlanServer($Value){
 if($Value -isnot [string] -or $Value -cne $Value.Trim() -or $Value.Length -gt 254 -or [string]::IsNullOrWhiteSpace($Value)){throw 'plan_server_invalid'}
 $ip=$null;if([Net.IPAddress]::TryParse($Value,[ref]$ip)){return ConvertTo-SstpPlanIP $Value}
 $hostValue=$Value.TrimEnd('.').ToLowerInvariant()
 foreach($part in $hostValue.Split('.')){if($part.Length -gt 63 -or $part -notmatch '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'){throw 'plan_server_invalid'}}
 return $hostValue
}
function New-SstpExactTransportDraft($InputRecord){
 $r=[ordered]@{schema='sstp-exact-transport-draft-01';input_valid=$false;code='plan_invalid_input';input_digest=$null;normalized_input=$null;transport_templates=@();application_constraint='verified_SSTP_binding_only_never_physical_adapter';physical_adapter_name_or_index_used=$false;server_name_rewrite_requested=$false;TLS_validation_bypass_requested=$false;external_DNS_exception_requested=$false;endpoint_approval_status='not_verified';plan_executable=$false;firewall_mutation_requested=$false;native_executor_implemented=$false;ready_for_apply=$false;no_leak_certified=$false;blockers=@('explicit_endpoint_approval_not_verified','native_profile_and_identity_revalidation_required','exact_transport_service_filter_not_live_verified','cold_DNS_bootstrap_not_verified','TLS_certificate_dependencies_not_verified','underlay_route_and_DHCP_not_verified','scoped_transaction_and_recovery_not_implemented','packet_reboot_and_reconnect_tests_not_passed')}
 try{
  $keys=@('schema','profile_guid','profile_scope','profile_owner_sid','server','endpoint_ips')
  if($null -eq $InputRecord -or ((@($InputRecord.PSObject.Properties.Name|Sort-Object))-join ',') -cne (($keys|Sort-Object)-join ',')){throw 'plan_input_schema'}
  if($InputRecord.schema -cne 'sstp-endpoint-review-input-01'){throw 'plan_input_schema'}
  foreach($k in @('schema','profile_guid','profile_scope','profile_owner_sid','server')){if($InputRecord.$k -isnot [string]){throw 'plan_input_schema'}}
  $g=[guid]::Empty;try{$g=[guid]$InputRecord.profile_guid}catch{throw 'plan_profile_guid_invalid'}
  if($g -eq [guid]::Empty -or $g.ToString('D') -cne $InputRecord.profile_guid){throw 'plan_profile_guid_invalid'}
  if($InputRecord.profile_scope -cnotin @('current_user','all_users')){throw 'plan_profile_scope_invalid'}
  if($InputRecord.profile_owner_sid -cnotmatch '^S-1-[0-9]+(-[0-9]+)+$'){throw 'plan_owner_sid_invalid'}
  $server=ConvertTo-SstpPlanServer $InputRecord.server
  if($InputRecord.endpoint_ips -isnot [array] -or $InputRecord.endpoint_ips.Count -lt 1 -or $InputRecord.endpoint_ips.Count -gt 8){throw 'plan_bounded_endpoint_array_required'}
  $ips=@($InputRecord.endpoint_ips|ForEach-Object{ConvertTo-SstpPlanIP $_}|Sort-Object -Unique)
  if($ips.Count -ne $InputRecord.endpoint_ips.Count){throw 'plan_duplicate_endpoint'}
  $literal=$null
  if([Net.IPAddress]::TryParse($InputRecord.server,[ref]$literal) -and ($ips.Count -ne 1 -or $ips[0] -cne $literal.ToString())){throw 'plan_literal_server_mismatch'}
  $normalized=[pscustomobject][ordered]@{schema='sstp-endpoint-review-input-01';profile_guid=$InputRecord.profile_guid;profile_scope=$InputRecord.profile_scope;profile_owner_sid=$InputRecord.profile_owner_sid;server=$server;endpoint_ips=$ips}
  $encoded=[Text.Encoding]::UTF8.GetBytes(($normalized|ConvertTo-Json -Compress -Depth 8));$hash=[Security.Cryptography.SHA256]::Create()
  try{$digest=([BitConverter]::ToString($hash.ComputeHash($encoded))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
  $templates=@(foreach($address in $ips){[pscustomobject][ordered]@{kind='non_executable_transport_template';direction='Outbound';action='Allow';protocol='TCP';remote_port=443;remote_address=$address;program_path_token='TRUSTED_WINDOWS_SYSTEM32_SVCHOST_REQUIRES_NATIVE_RESOLUTION';service='SstpSvc';interface_alias='Any';interface_type='Any';enabled_by_this_module=$false}})
  $r.input_valid=$true;$r.code='plan_draft_only_approval_and_bootstrap_required';$r.input_digest=$digest;$r.normalized_input=$normalized;$r.transport_templates=$templates
 }catch{
  $m=[string]$_.Exception.GetBaseException().Message;if($m -cmatch '^plan_[a-z_0-9]{1,90}$'){$r.code=$m}else{$r.code='plan_invalid_input'}
 }
 return [pscustomobject]$r
}
