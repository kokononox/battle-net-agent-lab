# Read-only effective Allow filter inspection. Never approves activation.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'AllowModel.ps1')
. (Join-Path $PSScriptRoot 'Inventory.ps1')
function AllowReadContext {
 $server=$null;$serverStatus='absent';$dns=$null;$dnsStatus='unavailable'
 $path=Join-Path $env:ProgramData 'SstpKillSwitch\firewall-state.json'
 if([IO.File]::Exists($path)){
  try{if((Get-Item -LiteralPath $path).Length -gt 1048576){throw 'allow_legacy_size'};$s=[IO.File]::ReadAllText($path)|ConvertFrom-Json;if([string]$s.Version -cne '1.2'){throw 'allow_legacy_version'};$server=@{};foreach($v in @($s.ServerIps)){$a=AddressNumber ([string]$v);$server[([string]$a.bits+':'+$a.number.ToString())]=$true};$serverStatus='saved_snapshot_unverified'}catch{$server=$null;$serverStatus='unavailable'}
 }
 try{$dns=@{};foreach($d in @(Get-DnsClientServerAddress -ErrorAction Stop)){foreach($v in @($d.ServerAddresses)){$a=AddressNumber ([string]$v);$dns[([string]$a.bits+':'+$a.number.ToString())]=$true}};$dnsStatus='current_windows_configuration_not_vpn_pinned'}catch{$dns=$null}
 [pscustomobject]@{server=$server;dns=$dns;server_status=$serverStatus;dns_status=$dnsStatus}
}
function AllowHeaderSignature($Rules){
 $data=@($Rules|ForEach-Object{InventoryRaw $_}|Sort-Object InstanceID)
 AllowHash (ConvertTo-Json -InputObject $data -Depth 8 -Compress)
}
function GetOutboundAllowReview {
 $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop|Where-Object{[string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow'})
 if($rules.Count -gt 1000){throw 'allow_rule_limit'}
 $header=AllowHeaderSignature $rules;$records=@{}
 foreach($r in $rules){$id=[string]$r.CimInstanceProperties['InstanceID'].Value;if(-not $id -or $records.ContainsKey($id)){throw 'allow_duplicate_identity'};$records[$id]=[ordered]@{rule=$r;raw=[ordered]@{rule=(InventoryRaw $r)};filters=@{}}}
 foreach($pair in @(@('address','Get-NetFirewallAddressFilter'),@('application','Get-NetFirewallApplicationFilter'),@('interface','Get-NetFirewallInterfaceFilter'),@('interface_type','Get-NetFirewallInterfaceTypeFilter'),@('port','Get-NetFirewallPortFilter'),@('security','Get-NetFirewallSecurityFilter'),@('service','Get-NetFirewallServiceFilter'))){
  $filters=@(& $pair[1] -PolicyStore ActiveStore -ErrorAction Stop)
  if($filters.Count -gt 40000){throw 'allow_filter_limit'}
  foreach($f in $filters){$id=[string]$f.CimInstanceProperties['InstanceID'].Value;if(-not $records.ContainsKey($id)){continue};if($records[$id].filters.ContainsKey($pair[0])){throw 'allow_filter_duplicate'};$records[$id].filters[$pair[0]]=$f;$records[$id].raw[$pair[0]]=InventoryRaw $f}
 }
 $context=AllowReadContext;$rows=@();$legacyNames=@('SSTP Allow VPN tunnel traffic','SSTP Allow server TCP 443','SSTP Allow DNS UDP','SSTP Allow DNS TCP','SSTP Allow DHCPv4','SSTP Allow DHCPv6')
 foreach($id in @($records.Keys|Sort-Object)){
  $record=$records[$id];if($record.filters.Count -ne 7){throw 'allow_filter_missing'};$f=$record.filters;$r=$record.rule
  $label='other';$legacy=[string]$r.Group -ceq 'SSTP Kill Switch'
  if($legacy){$label='legacy_other';if($legacyNames -ccontains [string]$r.DisplayName){$label=[string]$r.DisplayName}}
  $scope=AllowScope $f.interface_type.InterfaceType $f.interface.InterfaceAlias
  $program=AllowProgram $f.application
  $remote=AllowAddresses $f.address.RemoteAddress $context;$local=AllowAddresses $f.address.LocalAddress $context
  $service=[string]$f.service.Service;$serviceLabel='other';if($service -cin @('Any','Dhcp','Dnscache','BFE','MpsSvc','RasMan','SstpSvc','NlaSvc','W32Time','WinHttpAutoProxySvc')){$serviceLabel=$service}
  $protocol=[string]$f.port.Protocol;$proto='Unknown';switch -CaseSensitive ($protocol){'Any'{$proto='Any'};'256'{$proto='Any'};'TCP'{$proto='TCP'};'6'{$proto='TCP'};'UDP'{$proto='UDP'};'17'{$proto='UDP'};'ICMPv4'{$proto='ICMPv4'};'1'{$proto='ICMPv4'};'ICMPv6'{$proto='ICMPv6'};'58'{$proto='ICMPv6'}}
  if($proto -ceq 'Unknown' -and $protocol -cmatch '^\d{1,3}$'){$proto='IP-'+$protocol}
  $security=$f.security;$sec=[ordered]@{additional_security_conditions_fully_interpreted=$false}
  foreach($name in @('LocalUser','RemoteUser','RemoteMachine')){$v=AllowProp $security $name;$sec[$name+'_value_available']=$null -ne $v;$sec[$name+'_any']=AllowAny $v}
  $sec.authentication=AllowEnum (AllowProp $security 'Authentication') @('NotRequired','Required','NoEncap')
  $sec.encryption=AllowEnum (AllowProp $security 'Encryption') @('NotRequired','Required','Dynamic')
  $sec.override_block_rules=AllowBool (AllowProp $security 'OverrideBlockRules')
  $status=@($r.CimInstanceProperties['EnforcementStatus'].Value|ForEach-Object{[int]$_});if($status.Count -gt 64){throw 'allow_status_limit'}
  $rows+=,[pscustomobject][ordered]@{rule_id_sha256=(AllowHash $id);image_sha256=(AllowHash (ConvertTo-Json -InputObject $record.raw -Depth 20 -Compress));category=$label;legacy_group=$legacy;label_is_not_ownership=$true;profiles=(AllowTokens $r.Profile @('Any','Domain','Private','Public'));policy_source_type=(AllowEnum $r.PolicyStoreSourceType @('Local','GroupPolicy','Dynamic','Generated','Hardcoded','MDM'));enforcement_status_codes=$status;primary_status_code=[int]$r.CimInstanceProperties['PrimaryStatus'].Value;scope=$scope;program=$program;service=[pscustomobject]@{label=$serviceLabel;any=($service -ceq 'Any');value_sha256=(AllowHash $service)};protocol=$proto;local_ports=(AllowPorts $f.port.LocalPort);remote_ports=(AllowPorts $f.port.RemotePort);local_addresses=$local;remote_addresses=$remote;security=[pscustomobject]$sec;rule_override_block_rules=(AllowBool (AllowProp $r 'OverrideBlockRules'));is_proven_leak=$false;is_proven_safe=$false}
 }
 $after=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop|Where-Object{[string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow'})
 [pscustomobject][ordered]@{schema='sstp-outbound-allow-review-1';scope='ActiveStore_enabled_outbound_Allow';network_settings_changed_by_tool=$false;activation_approved=$false;outside_vpn_protection_certified=$false;snapshot_not_transaction=$true;rule_headers_unchanged_during_read=($header -ceq (AllowHeaderSignature $after));filters_rechecked_at_end=$false;context=[pscustomobject]@{legacy_server_snapshot_status=$context.server_status;server_snapshot_matches_connected_vpn_verified=$false;dns_status=$context.dns_status};summary=[pscustomobject]@{rule_count=$rows.Count;legacy_group_count=@($rows|Where-Object{$_.legacy_group}).Count;remote_access_type_only_count=@($rows|Where-Object{$_.scope.remote_access_type_only}).Count;non_vpn_review_candidate_count=@($rows|Where-Object{$_.scope.candidate_for_non_vpn_review}).Count};rows=$rows;raw_names_paths_addresses_exported=$false;block_rules_and_conflict_precedence_fully_reviewed=$false;third_party_wfp_and_packets_tested=$false}
}
