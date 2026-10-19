# Read-only local diagnostic. No firewall/VPN/DNS/route changes and no uploads.
param([string]$OutputPath=(Join-Path $PSScriptRoot 'SstpBindingReport.json'),[switch]$SelfTest)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function SelectInspectProfile($Profiles,[bool]$Complete) {
 if (-not $Complete) { return [pscustomobject]@{status='inventory_incomplete';profile=$null} }
 $sstp=@($Profiles | Where-Object {$_.tunnel -ieq 'Sstp'})
 $active=@($sstp | Where-Object {$_.connected -eq $true})
 if ($active.Count -gt 1) { return [pscustomobject]@{status='multiple_active';profile=$null} }
 if ($active.Count -eq 1) { return [pscustomobject]@{status='selected_active';profile=$active[0]} }
 if ($sstp.Count -eq 1) { return [pscustomobject]@{status='selected_only';profile=$sstp[0]} }
 $preferred=@($sstp | Where-Object {$_.name -ieq 'holand'})
 if ($preferred.Count -eq 1) { return [pscustomobject]@{status='selected_preferred';profile=$preferred[0]} }
 return [pscustomobject]@{status='ambiguous_or_absent';profile=$null}
}
if ($SelfTest) {
 $p1=[pscustomobject]@{name='holand';tunnel='Sstp';connected=$true;scope='current_user'}
 $p2=[pscustomobject]@{name='holand';tunnel='Sstp';connected=$false;scope='all_users'}
 $cases=@(
  ((SelectInspectProfile @($p1) $false).status -eq 'inventory_incomplete'),
  ((SelectInspectProfile @($p1) $true).status -eq 'selected_active'),
  ((SelectInspectProfile @($p2) $true).status -eq 'selected_only'),
  ((SelectInspectProfile @($p2,$p2) $true).status -eq 'ambiguous_or_absent'),
  ((SelectInspectProfile @($p1,$p1) $true).status -eq 'multiple_active'),
  ((SelectInspectProfile @() $true).status -eq 'ambiguous_or_absent')
 )
 if (@($cases | Where-Object {$_ -ne $true}).Count -ne 0) { throw 'inspect_self_test_failure' }
 Write-Output 'inspect_selection_checks_passed_6';exit 0
}
$queries=[ordered]@{current_user_vpn='not_run';all_users_vpn='not_run';interfaces='not_run';routes='not_run';stored_profiles='not_run';effective_profiles='not_run';local_rules='not_run';effective_rules='not_run'}
$profiles=@()
foreach($scope in @('current_user','all_users')) {
 try {
  if ($scope -eq 'current_user') { $rows=@(Get-VpnConnection -ErrorAction Stop) } else { $rows=@(Get-VpnConnection -AllUserConnection -ErrorAction Stop) }
  foreach($p in $rows) {
   $profiles+=,[pscustomobject]@{name=[string]$p.Name;scope=$scope;tunnel=[string]$p.TunnelType;connected=([string]$p.ConnectionStatus -eq 'Connected');server=[string]$p.ServerAddress}
  }
  $queries[$scope+'_vpn']='ok'
 } catch { $queries[$scope+'_vpn']='unavailable' }
}
$complete=($queries.current_user_vpn -eq 'ok' -and $queries.all_users_vpn -eq 'ok')
$selection=SelectInspectProfile $profiles $complete
$summary=@();$selectedLabel=$null;$label=0
foreach($p in $profiles) {
 if ($p.tunnel -ine 'Sstp') { continue };$label++
 $ip=$null;$kind='hostname_or_unrecognized'
 if ([Net.IPAddress]::TryParse($p.server,[ref]$ip)) { $kind='literal_ipv4';if($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { $kind='literal_ipv6' } }
 if ($selection.profile -and $p.name -ceq $selection.profile.name -and $p.scope -ceq $selection.profile.scope) { $selectedLabel='profile-'+$label }
 $summary+=,[pscustomobject][ordered]@{label=('profile-'+$label);scope=$p.scope;connected=$p.connected;preferred_name_match=($p.name -ieq 'holand');server_kind=$kind}
}
$interfaces=@();$routes=@();$matching=@();$index=$null
try { $interfaces=@(Get-NetIPInterface -ErrorAction Stop);$queries.interfaces='ok' } catch { $queries.interfaces='unavailable' }
if ($selection.profile -and $queries.interfaces -eq 'ok') {
 $matching=@($interfaces | Where-Object {$_.InterfaceAlias -ieq $selection.profile.name})
 $indices=@($matching | Select-Object -ExpandProperty InterfaceIndex -Unique)
 if ($indices.Count -eq 1) { $index=$indices[0] }
}
try { $routes=@(Get-NetRoute -ErrorAction Stop);$queries.routes='ok' } catch { $queries.routes='unavailable' }
$binding=[ordered]@{alias_match_interface_count=$null;ipv4_candidate_connected=$null;ipv6_candidate_connected=$null;candidate_ipv4_default_route_count=$null;candidate_ipv6_default_route_count=$null;other_ipv4_default_route_count=$null;other_ipv6_default_route_count=$null;alias_match_is_profile_identity_proof=$false;sstp_binding_qualified=$false}
if ($queries.interfaces -eq 'ok' -and $selection.profile) {
 $binding.alias_match_interface_count=@($matching | Select-Object -ExpandProperty InterfaceIndex -Unique).Count
 if ($null -ne $index) {
  $binding.ipv4_candidate_connected=(@($matching | Where-Object {[string]$_.AddressFamily -eq 'IPv4' -and [string]$_.ConnectionState -eq 'Connected'}).Count -gt 0)
  $binding.ipv6_candidate_connected=(@($matching | Where-Object {[string]$_.AddressFamily -eq 'IPv6' -and [string]$_.ConnectionState -eq 'Connected'}).Count -gt 0)
  if ($queries.routes -eq 'ok') {
   $binding.candidate_ipv4_default_route_count=@($routes | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0' -and $_.InterfaceIndex -eq $index}).Count
   $binding.candidate_ipv6_default_route_count=@($routes | Where-Object {$_.DestinationPrefix -eq '::/0' -and $_.InterfaceIndex -eq $index}).Count
   $binding.other_ipv4_default_route_count=@($routes | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0' -and $_.InterfaceIndex -ne $index}).Count
   $binding.other_ipv6_default_route_count=@($routes | Where-Object {$_.DestinationPrefix -eq '::/0' -and $_.InterfaceIndex -ne $index}).Count
  }
 }
}
$firewall=[ordered]@{stored_profiles=$null;effective_profiles=$null;enabled_local_outbound_allows=$null;enabled_effective_outbound_allows=$null;enabled_effective_nonlocal_outbound_allows=$null;effective_rule_source_traced=$false}
foreach($pair in @(@('PersistentStore','stored_profiles'),@('ActiveStore','effective_profiles'))) {
 try {
  $rows=@(Get-NetFirewallProfile -PolicyStore $pair[0] -ErrorAction Stop)
  $firewall[$pair[1]]=@($rows | Sort-Object Name | ForEach-Object {[pscustomobject][ordered]@{name=[string]$_.Name;enabled=[string]$_.Enabled;default_inbound=[string]$_.DefaultInboundAction;default_outbound=[string]$_.DefaultOutboundAction;allow_local_rules=[string]$_.AllowLocalFirewallRules}})
  $queries[$pair[1]]='ok'
 } catch { $queries[$pair[1]]='unavailable' }
}
foreach($pair in @(@('PersistentStore','local_rules'),@('ActiveStore','effective_rules'))) {
 try {
  $params=@{PolicyStore=$pair[0];ErrorAction='Stop'};$traced=$false
  if ($pair[1] -eq 'effective_rules' -and (Get-Command Get-NetFirewallRule -ErrorAction Stop).Parameters.ContainsKey('TracePolicyStore')) { $params.TracePolicyStore=$true;$traced=$true }
  $rows=@(Get-NetFirewallRule @params | Where-Object {[string]$_.Enabled -eq 'True' -and [string]$_.Direction -eq 'Outbound' -and [string]$_.Action -eq 'Allow'})
  if ($pair[1] -eq 'local_rules') { $firewall.enabled_local_outbound_allows=$rows.Count }
  else {
   $firewall.enabled_effective_outbound_allows=$rows.Count;$firewall.effective_rule_source_traced=$traced
   if ($traced) { $firewall.enabled_effective_nonlocal_outbound_allows=@($rows | Where-Object {[string]$_.PolicyStoreSourceType -ne 'Local'}).Count }
  }
  $queries[$pair[1]]='ok'
 } catch { $queries[$pair[1]]='unavailable' }
}
$admin=$false
try { $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());$admin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}
$report=[ordered]@{schema='sstp-binding-inspect-1';created_utc=[DateTime]::UtcNow.ToString('o');os_build=[Environment]::OSVersion.Version.Build;powershell_version=$PSVersionTable.PSVersion.ToString();elevated=$admin;profile_inventory_scope='account_running_this_tool_and_all_users';queries=$queries;sstp_profiles=$summary;selection_status=$selection.status;selected_label=$selectedLabel;binding=[pscustomobject]$binding;firewall=[pscustomobject]$firewall;network_policy_changed=$false;dns_queried=$false;credentials_exported=$false;raw_profile_names_exported=$false;ip_addresses_exported=$false;uploaded=$false;enforcement_tested=$false;ready_for_user_apply=$false}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),($report | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
Write-Output 'Read-only inspection finished. Report: SstpBindingReport.json'
exit 0
