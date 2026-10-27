Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';. (Join-Path $PSScriptRoot 'SstpReconnect.Decision.ps1')
$script:n=0;function Check($b,$m){$script:n++;if(-not $b){throw $m}}
function Good($State='connected'){$o=New-SstpReconnectObservation;foreach($p in $o.PSObject.Properties){if($p.Name -ceq 'vpn_state'){$o.vpn_state=$State}else{$o.($p.Name)=$true}};return $o}
function Decide($o){Get-SstpReconnectDecision $o}
$o=Good;$d=Decide $o;Check ($d.state -ceq 'bound_online_candidate') 'online candidate';Check (-not $d.firewall_mutation_requested -and -not $d.native_executor_implemented -and -not $d.no_leak_certified) 'no executor or certification'
foreach($p in @('baseline_verified','transport_rule_verified','saved_profile_matches','server_pin_current','tls_policy_intact','identity_chain_verified','endpoint_matches_pin','binding_matches','fresh_data_validation')){
 $o=Good;$o.$p=$false;Check ((Decide $o).state -cne 'bound_online_candidate') ('missing live check '+$p)
}
foreach($state in @('disconnected','connecting')){
 $o=Good $state;$d=Decide $o;Check ($d.state -ceq 'waiting_for_sstp' -and $d.application_action -ceq 'keep_data_disabled') ('waiting '+$state)
 foreach($p in @('underlay_ready','dns_bootstrap_ready','tls_bootstrap_ready')){
  $o=Good $state;$o.$p=$false;$d=Decide $o;Check ($d.state -ceq 'bootstrap_blocked' -and $d.application_action -ceq 'keep_data_disabled') ('dependency '+$p)
 }
 $o=Good $state;$o.data_rules_disabled_verified=$false;Check ((Decide $o).state -ceq 'suspend_data_first') 'disable before waiting'
}
$o=Good;$o.binding_matches=$false;Check ((Decide $o).state -ceq 'scoped_rebind_needed') 'new interface not auto online'
$o.data_rules_disabled_verified=$false;Check ((Decide $o).state -ceq 'suspend_data_first') 'rebind waits for suspension'
Check ((Decide (Good 'unknown')).state -ceq 'inspection_required') 'unknown not offline or online success'
foreach($p in @((New-SstpReconnectObservation).PSObject.Properties.Name|Where-Object{$_ -cne 'vpn_state'})){
 foreach($v in @('true',1,$null)){$o=Good;$o.$p=$v;Check ((Decide $o).reason -ceq 'invalid_observation') ('type rejection '+$p)}
}
$o=Good;$o|Add-Member NoteProperty unexpected $true;Check ((Decide $o).reason -ceq 'invalid_observation') 'unknown property rejected'
$o=Good;$o.PSObject.Properties.Remove('dns_bootstrap_ready');Check ((Decide $o).reason -ceq 'invalid_observation') 'missing property rejected'
Check ((Decide $null).reason -ceq 'invalid_observation') 'null rejected'
# Exercise online -> offline -> cache loss -> reconnect with new interface -> validated binding.
$states=@();$o=Good;$states+=(Decide $o).state
$o.vpn_state='disconnected';$states+=(Decide $o).state
$o.dns_bootstrap_ready=$false;$states+=(Decide $o).state
$o.dns_bootstrap_ready=$true;$o.vpn_state='connecting';$states+=(Decide $o).state
$o.vpn_state='connected';$o.binding_matches=$false;$states+=(Decide $o).state
$o.binding_matches=$true;$o.fresh_data_validation=$false;$states+=(Decide $o).state
$o.fresh_data_validation=$true;$states+=(Decide $o).state
Check (($states -join ',') -ceq 'bound_online_candidate,waiting_for_sstp,bootstrap_blocked,waiting_for_sstp,scoped_rebind_needed,fresh_validation_needed,bound_online_candidate') 'lifecycle with no permissive fallback'
@{suite='sstp-reconnect-pure-decision-v01';passed=$true;assertions=$script:n;Windows_API_executed=$false;native_executor_implemented=$false;firewall_changed=$false;DNS_queries_generated=$false;actual_reconnect_tested=$false}|ConvertTo-Json|Set-Content (Join-Path $PSScriptRoot 'model-results.json')
Write-Host ('Passed '+$script:n+' decision checks; native execution NOT implemented.')
