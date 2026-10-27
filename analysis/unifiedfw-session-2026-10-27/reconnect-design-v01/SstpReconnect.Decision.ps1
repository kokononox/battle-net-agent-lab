# Pure decision kernel ONLY. Not a firewall executor, native observer, or security certificate.
# Inputs must eventually be supplied by separately validated native adapters, not a user config.
function New-SstpReconnectObservation{
 [pscustomobject][ordered]@{
  baseline_verified=$false;transport_rule_verified=$false;saved_profile_matches=$false;server_pin_current=$false
  dns_bootstrap_ready=$false;tls_policy_intact=$false;tls_bootstrap_ready=$false;underlay_ready=$false
  vpn_state='unknown';data_rules_disabled_verified=$false;identity_chain_verified=$false
  endpoint_matches_pin=$false;binding_matches=$false;fresh_data_validation=$false
 }
}
function Get-SstpReconnectDecision($Observation){
 $result=[ordered]@{schema='sstp-reconnect-decision-01';state='inspection_required';reason='invalid_observation';application_action='do_not_authorize';transport_action='do_not_authorize';native_executor_implemented=$false;firewall_mutation_requested=$false;no_leak_certified=$false}
 $shape=New-SstpReconnectObservation
 if($null -eq $Observation -or ((@($Observation.PSObject.Properties.Name|Sort-Object)) -join ',') -cne ((@($shape.PSObject.Properties.Name|Sort-Object)) -join ',')){return [pscustomobject]$result}
 foreach($p in $shape.PSObject.Properties){
  $v=$Observation.($p.Name)
  if($p.Name -ceq 'vpn_state'){if($v -isnot [string] -or $v -cnotin @('disconnected','connecting','connected','unknown')){return [pscustomobject]$result}}
  elseif($v -isnot [bool]){return [pscustomobject]$result}
 }
 $result.reason='baseline_not_verified'
 if(-not $Observation.baseline_verified){return [pscustomobject]$result}
 if(-not $Observation.saved_profile_matches -or -not $Observation.server_pin_current){$result.state='explicit_review_required';$result.reason='profile_or_server_pin_changed';return [pscustomobject]$result}
 if(-not $Observation.transport_rule_verified){$result.reason='exact_transport_not_verified';return [pscustomobject]$result}
 if(-not $Observation.tls_policy_intact){$result.reason='tls_policy_not_intact';return [pscustomobject]$result}
 $result.transport_action='retain_only_preapproved_exact_transport'
 # DNS/TLS readiness describes the OFFLINE bootstrap path, not an excuse to open new traffic.
 if($Observation.vpn_state -cin @('disconnected','connecting')){
  $result.application_action='require_disabled_data_rules_via_scoped_executor'
  if(-not $Observation.data_rules_disabled_verified){$result.state='suspend_data_first';$result.reason='data_rules_not_sealed_disabled';return [pscustomobject]$result}
  $result.application_action='keep_data_disabled'
  if(-not $Observation.underlay_ready){$result.state='bootstrap_blocked';$result.reason='underlay_not_ready';return [pscustomobject]$result}
  if(-not $Observation.dns_bootstrap_ready){$result.state='bootstrap_blocked';$result.reason='server_name_resolution_not_ready';return [pscustomobject]$result}
  if(-not $Observation.tls_bootstrap_ready){$result.state='bootstrap_blocked';$result.reason='certificate_dependencies_not_ready';return [pscustomobject]$result}
  $result.state='waiting_for_sstp';$result.reason='exact_transport_retained_data_disabled';return [pscustomobject]$result
 }
 if($Observation.vpn_state -cne 'connected'){$result.reason='connection_state_unknown';return [pscustomobject]$result}
 if(-not $Observation.identity_chain_verified -or -not $Observation.endpoint_matches_pin){$result.application_action='require_disabled_data_rules_via_scoped_executor';$result.reason='live_identity_or_endpoint_not_verified';return [pscustomobject]$result}
 if(-not $Observation.binding_matches){
  $result.application_action='require_disabled_data_rules_via_scoped_executor'
  if(-not $Observation.data_rules_disabled_verified){$result.state='suspend_data_first';$result.reason='new_connection_before_data_suspension';return [pscustomobject]$result}
  $result.state='scoped_rebind_needed';$result.reason='verified_same_profile_new_connection';$result.application_action='plan_exact_tunnel_rebind_only';return [pscustomobject]$result
 }
 if(-not $Observation.fresh_data_validation){$result.state='fresh_validation_needed';$result.reason='binding_not_yet_freshly_validated';return [pscustomobject]$result}
 $result.state='bound_online_candidate';$result.reason='observed_binding_passed_no_packet_qualification';$result.application_action='eligible_for_separate_fresh_transaction_validation'
 return [pscustomobject]$result
}
