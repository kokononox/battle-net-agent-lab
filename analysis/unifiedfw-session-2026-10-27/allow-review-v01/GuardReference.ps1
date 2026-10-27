function Get-UfwRuntimeSystemHostPath {return Join-Path ([Environment]::SystemDirectory) 'svchost.exe'}
function Get-UfwRuntimeFirewallGuard {
 $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
 if($profiles.Count -ne 3 -or (@($profiles.Name|Sort-Object)-join ',') -cne 'Domain,Private,Public'){throw 'ufw_runtime_firewall_profiles'}
 foreach($p in $profiles){if([string]$p.Enabled -cne 'True' -or [string]$p.DefaultOutboundAction -cne 'Block'){throw 'ufw_runtime_firewall_not_blocked_no_launch'}}
 $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
 if($rules.Count -gt 32768){throw 'ufw_runtime_firewall_rule_cap'}
 $allows=@($rules|Where-Object{[string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow'})
 $foreign=0;$transport=0
 foreach($rule in $allows){
  # Only already-existing exact SstpSvc/TCP443/literal-unicast transport grants may remain.
  $service=@($rule|Get-NetFirewallServiceFilter -ErrorAction Stop);$app=@($rule|Get-NetFirewallApplicationFilter -ErrorAction Stop);$port=@($rule|Get-NetFirewallPortFilter -ErrorAction Stop);$address=@($rule|Get-NetFirewallAddressFilter -ErrorAction Stop)
  $dynamic=@();if($rule.PSObject.Properties.Name -contains 'RemoteDynamicKeywordAddresses'){$dynamic=@($rule.RemoteDynamicKeywordAddresses|Where-Object{-not [string]::IsNullOrWhiteSpace([string]$_)})}
  $ok=$dynamic.Count -eq 0 -and $service.Count -eq 1 -and $app.Count -eq 1 -and $port.Count -eq 1 -and $address.Count -eq 1
  if($ok){$ok=[string]$service[0].Service -ceq 'SstpSvc' -and [string]::Equals([string]$app[0].Program,(Get-UfwRuntimeSystemHostPath),[StringComparison]::OrdinalIgnoreCase) -and [string]$port[0].Protocol -cin @('TCP','6') -and @($port[0].RemotePort).Count -eq 1 -and [string]$port[0].RemotePort -ceq '443'}
  if($ok){$ips=@($address[0].RemoteAddress);if($ips.Count -lt 1 -or $ips.Count -gt 8){$ok=$false};foreach($text in $ips){$ip=$null;if(-not [Net.IPAddress]::TryParse([string]$text,[ref]$ip) -or $null -eq (Get-UfwRuntimeEndpoint ([string]$text) 443 6)){$ok=$false}}}
  if($ok){$transport++}else{$foreign++}
 }
 if($foreign -gt 0){throw 'ufw_runtime_unreviewed_allow_rules_no_launch'}
 return [pscustomobject]@{profiles_blocked=$true;existing_sstp_transport_rules=$transport;unreviewed_allow_rules=$foreign;isolation_certified=$false}
}
