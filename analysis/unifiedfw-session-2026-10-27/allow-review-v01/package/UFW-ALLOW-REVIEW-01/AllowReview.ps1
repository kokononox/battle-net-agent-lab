# Pure classifier: same acceptance predicate as RUNTIME-CAPTURE-01; reasons are observations, not grants.
function Get-UfwAllowClassification($Rule,$Services,$Apps,$Ports,$Addresses,[string]$HostPath){
 $why=New-Object 'System.Collections.Generic.List[string]'
 $dynamic=@();if($Rule.PSObject.Properties.Name -contains 'RemoteDynamicKeywordAddresses'){$dynamic=@($Rule.RemoteDynamicKeywordAddresses|Where-Object{-not [string]::IsNullOrWhiteSpace([string]$_)})}
 if($dynamic.Count -ne 0){$why.Add('dynamic_remote_keywords')}
 if(@($Services).Count -ne 1){$why.Add('service_filter_cardinality')}
 elseif([string]$Services[0].Service -cne 'SstpSvc'){$why.Add('service_not_exact_sstpsvc')}
 if(@($Apps).Count -ne 1){$why.Add('application_filter_cardinality')}
 elseif(-not [string]::Equals([string]$Apps[0].Program,$HostPath,[StringComparison]::OrdinalIgnoreCase)){$why.Add('application_not_exact_system_svchost')}
 if(@($Ports).Count -ne 1){$why.Add('port_filter_cardinality')}
 else{
  if([string]$Ports[0].Protocol -cnotin @('TCP','6')){$why.Add('protocol_not_tcp')}
  if(@($Ports[0].RemotePort).Count -ne 1 -or [string]$Ports[0].RemotePort -cne '443'){$why.Add('remote_port_not_exact_443')}
 }
 if(@($Addresses).Count -ne 1){$why.Add('address_filter_cardinality')}
 else{
  $ips=@($Addresses[0].RemoteAddress)
  if($ips.Count -lt 1 -or $ips.Count -gt 8){$why.Add('remote_address_count_outside_1_to_8')}
  $nonliteral=$false;$excluded=$false
  foreach($text in $ips){$ip=$null;if(-not [Net.IPAddress]::TryParse([string]$text,[ref]$ip)){$nonliteral=$true}else{if($null -eq (Get-UfwRuntimeEndpoint ([string]$text) 443 6)){$excluded=$true}}}
  if($nonliteral){$why.Add('remote_address_not_literal_ip')};if($excluded){$why.Add('remote_address_excluded_by_runtime_predicate')}
 }
 return [pscustomobject]@{matches_runtime_transport_predicate=($why.Count -eq 0);reasons=@($why.ToArray())}
}
function New-UfwAllowSummary {
 $reasons=[ordered]@{}
 foreach($k in @('dynamic_remote_keywords','service_filter_cardinality','service_not_exact_sstpsvc','application_filter_cardinality','application_not_exact_system_svchost','port_filter_cardinality','protocol_not_tcp','remote_port_not_exact_443','address_filter_cardinality','remote_address_count_outside_1_to_8','remote_address_not_literal_ip','remote_address_excluded_by_runtime_predicate')){$reasons[$k]=0}
 return [pscustomobject][ordered]@{schema='ufw-allow-review-result-01';completed=$false;stage='profiles';code='';profiles_observed=0;profiles_expected_set=$false;profiles_enabled_count=0;profiles_outbound_block_count=0;profile_gate_matches=$false;total_rules_observed=0;enabled_outbound_allow_rules=0;rules_examined=0;transport_predicate_matches=0;runtime_predicate_mismatches=0;filter_reads_indeterminate=0;reason_counts=$reasons;reason_counts_overlap=$true;snapshot_atomic=$false;runtime_gate_observation_matches=$false;runtime_execution_authorized=$false;no_leak_certified=$false;raw_rule_identity_exported=$false}
}
function Invoke-UfwAllowReview($Ops){
 $r=New-UfwAllowSummary
 try{
  $profiles=@(& $Ops.Profiles);$r.profiles_observed=$profiles.Count
  $r.profiles_expected_set=$profiles.Count -eq 3 -and (@($profiles.Name|Sort-Object)-join ',') -ceq 'Domain,Private,Public'
  foreach($p in $profiles){if([string]$p.Enabled -ceq 'True'){$r.profiles_enabled_count++};if([string]$p.DefaultOutboundAction -ceq 'Block'){$r.profiles_outbound_block_count++}}
  $r.profile_gate_matches=$r.profiles_expected_set -and $r.profiles_enabled_count -eq 3 -and $r.profiles_outbound_block_count -eq 3
  $r.stage='rules';$rules=@(& $Ops.Rules);$r.total_rules_observed=$rules.Count
  if($rules.Count -gt 32768){throw 'ufw_allow_review_rule_cap'}
  $allows=@($rules|Where-Object{[string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow'})
  $r.enabled_outbound_allow_rules=$allows.Count
  if($allows.Count -gt 4096){throw 'ufw_allow_review_allow_cap'}
  $hostPath=& $Ops.HostPath;if([string]::IsNullOrWhiteSpace([string]$hostPath)){throw 'ufw_allow_review_host_unavailable'}
  $r.stage='filters'
  foreach($rule in $allows){
   try{
    $service=@(& $Ops.Service $rule);$app=@(& $Ops.App $rule);$port=@(& $Ops.Port $rule);$address=@(& $Ops.Address $rule)
    $c=Get-UfwAllowClassification $rule $service $app $port $address $hostPath
    if($c.matches_runtime_transport_predicate){$r.transport_predicate_matches++}else{$r.runtime_predicate_mismatches++;foreach($reason in $c.reasons){$r.reason_counts[$reason]++}}
   }catch{$r.filter_reads_indeterminate++}
   $r.rules_examined++
  }
  $r.completed=$r.filter_reads_indeterminate -eq 0
  $r.runtime_gate_observation_matches=$r.completed -and $r.profile_gate_matches -and $r.runtime_predicate_mismatches -eq 0
  if(-not $r.completed){$r.code='ufw_allow_review_filter_reads_incomplete'}elseif(-not $r.profile_gate_matches){$r.code='ufw_allow_review_profile_gate_mismatch'}elseif($r.runtime_predicate_mismatches -gt 0){$r.code='ufw_allow_review_runtime_mismatches_observed'}else{$r.code='ufw_allow_review_no_mismatch_observed_not_launch_authority'}
  $r.stage='completed'
 }catch{$r.completed=$false;$r.runtime_gate_observation_matches=$false;$msg=[string]$_.Exception.GetBaseException().Message;if($msg -cmatch '^ufw_allow_review_[a-z_0-9]{1,80}$'){$r.code=$msg}else{$r.code='ufw_allow_review_read_unavailable'}}
 return $r
}
function Invoke-UfwAllowReviewNative {
 $ops=@{
  Profiles={Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop}
  Rules={Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop}
  HostPath={Join-Path ([Environment]::SystemDirectory) 'svchost.exe'}
  Service={param($r)$r|Get-NetFirewallServiceFilter -ErrorAction Stop}
  App={param($r)$r|Get-NetFirewallApplicationFilter -ErrorAction Stop}
  Port={param($r)$r|Get-NetFirewallPortFilter -ErrorAction Stop}
  Address={param($r)$r|Get-NetFirewallAddressFilter -ErrorAction Stop}
 };return Invoke-UfwAllowReview $ops
}
