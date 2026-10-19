# P3: PersistentStore staging adapter. It cannot enable a rule or change profile defaults.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../sstp-allowlist-policy/Policy.ps1')
function AdapterHash([string]$Text) {
 $s=[Security.Cryptography.SHA256]::Create()
 try { ([BitConverter]::ToString($s.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant() } finally { $s.Dispose() }
}
function NewStagedRuleSpec([string]$Session,[string]$Id,[string]$Kind,[string]$Alias,[string[]]$Addresses) {
 if ($Session -cnotmatch '^[a-f0-9]{32}$' -or $Id -cnotmatch '^[a-z0-9-]{1,32}$') { throw 'adapter_identity' }
 if ([string]::IsNullOrWhiteSpace($Alias) -or $Alias.Length -gt 128 -or $Alias -match '[*?\[\]`\r\n]' -or $Alias -cne $Alias.Trim() -or $Alias -ieq 'Any') { throw 'adapter_alias' }
 if ($Kind -notin @('target','dns-tcp','dns-udp','transport')) { throw 'adapter_kind' }
 $ips=@($Addresses | ForEach-Object { PolicyIp $_ } | Sort-Object -Unique)
 if ($ips.Count -lt 1 -or $ips.Count -gt 64) { throw 'adapter_addresses' }
 $protocol='Any';$port='Any';$type='RemoteAccess';$program='Any';$service='Any'
 if ($Kind -eq 'dns-tcp') { $protocol='TCP';$port='53' }
 if ($Kind -eq 'dns-udp') { $protocol='UDP';$port='53' }
 if ($Kind -eq 'transport') { $protocol='TCP';$port='443';$type='Any';$program=Join-Path $env:windir 'System32\svchost.exe';$service='SstpSvc' }
 [pscustomobject][ordered]@{schema='sstp-staged-rule-1';session=$Session;id=$Id;kind=$Kind;alias=$Alias;addresses=$ips;protocol=$protocol;remote_port=$port;interface_type=$type;program=$program;service=$service}
}
function AssertStagedRuleSpec($Spec) {
 $keys='addresses,alias,id,interface_type,kind,program,protocol,remote_port,schema,service,session'
 if ($null -eq $Spec -or (($Spec.PSObject.Properties.Name | Sort-Object) -join ',') -cne $keys -or $Spec.schema -cne 'sstp-staged-rule-1' -or $Spec.addresses -isnot [array]) { throw 'adapter_spec_schema' }
 $canonical=NewStagedRuleSpec $Spec.session $Spec.id $Spec.kind $Spec.alias $Spec.addresses
 if (($Spec | ConvertTo-Json -Depth 5 -Compress) -cne ($canonical | ConvertTo-Json -Depth 5 -Compress)) { throw 'adapter_spec_noncanonical' }
 return $canonical
}
function StagedRuleName($Spec) { 'SstpAllowlist-'+$Spec.session+'-'+$Spec.id }
function StagedRuleGroup($Spec) { 'SstpAllowlist-'+$Spec.session }
function GetExactLocalRule([string]$Name) {
 # Never suppress permission/provider errors as if the rule were absent.
 try { $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name $Name -ErrorAction Stop) }
 catch { if ($_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound_Name,*') { return $null };throw }
 if ($rules.Count -ne 1 -or $rules[0].Name -cne $Name -or [string]$rules[0].PolicyStoreSourceType -ne 'Local') { throw 'adapter_rule_identity' }
 return $rules[0]
}
function ConvertAdapterCim($Object) {
 # Include all provider CIM fields except documented runtime status, not just the display name.
 $out=[ordered]@{}
 $ignored=@('Status','PrimaryStatus','StatusCode','EnforcementStatus','OperationalStatus','HealthState','CommunicationStatus','DetailedStatus','OperatingStatus')
 foreach($p in @($Object.CimInstanceProperties | Sort-Object Name)) {
  if ($p.Name -in $ignored) { continue }
  if ($null -eq $p.Value) { $out[$p.Name]=$null }
  elseif ($p.Value -is [array]) { $out[$p.Name]=@($p.Value | ForEach-Object {[string]$_} | Sort-Object) }
  else { $out[$p.Name]=[string]$p.Value }
 }
 [pscustomobject]$out
}
function ReadStagedRule([string]$Name) {
 $rule=GetExactLocalRule $Name
 if ($null -eq $rule) { return $null }
 $image=[ordered]@{rule=(ConvertAdapterCim $rule)}
 $view=[ordered]@{name=[string]$rule.Name;display_name=[string]$rule.DisplayName;description=[string]$rule.Description;group=[string]$rule.Group;enabled=[string]$rule.Enabled;direction=[string]$rule.Direction;action=[string]$rule.Action;profile=[string]$rule.Profile}
 foreach($pair in @(@('address','Get-NetFirewallAddressFilter'),@('port','Get-NetFirewallPortFilter'),@('application','Get-NetFirewallApplicationFilter'),@('service','Get-NetFirewallServiceFilter'),@('interface','Get-NetFirewallInterfaceFilter'),@('interface_type','Get-NetFirewallInterfaceTypeFilter'),@('security','Get-NetFirewallSecurityFilter'))) {
  $filters=@(& $pair[1] -AssociatedNetFirewallRule $rule -ErrorAction Stop)
  if ($filters.Count -ne 1) { throw 'adapter_filter_count' }
  $image[$pair[0]]=ConvertAdapterCim $filters[0]
  switch($pair[0]) {
   'address' { $view.local_address=@($filters[0].LocalAddress);$view.remote_address=@($filters[0].RemoteAddress) }
   'port' { $view.protocol=[string]$filters[0].Protocol;$view.local_port=@($filters[0].LocalPort);$view.remote_port=@($filters[0].RemotePort) }
   'application' { $view.program=[string]$filters[0].Program }
   'service' { $view.service=[string]$filters[0].Service }
   'interface' { $view.alias=@($filters[0].InterfaceAlias) }
   'interface_type' { $view.interface_type=[string]$filters[0].InterfaceType }
  }
 }
 $image['view']=[pscustomobject]$view
 $json=ConvertTo-Json -InputObject $image -Depth 8 -Compress
 [pscustomobject]@{schema='sstp-rule-snapshot-1';name=$Name;image=[pscustomobject]$image;sha256=(AdapterHash $json)}
}
function AssertStagedRuleReadback($Spec,$Snapshot) {
 $Spec=AssertStagedRuleSpec $Spec
 if ($null -eq $Snapshot) { throw 'adapter_missing_readback' }
 $v=$Snapshot.image.view
 if ($Snapshot.name -cne (StagedRuleName $Spec) -or $v.name -cne $Snapshot.name -or $v.display_name -cne $Snapshot.name -or $v.description -cne 'SSTP allowlist P3 staging only; never enabled' -or $v.group -cne (StagedRuleGroup $Spec) -or $v.enabled -ne 'False' -or $v.direction -ne 'Outbound' -or $v.action -ne 'Allow' -or $v.profile -ne 'Any') { throw 'adapter_rule_readback' }
 if ((@($v.alias) -join ',') -cne $Spec.alias -or (@($v.local_address) -join ',') -ne 'Any') { throw 'adapter_interface_readback' }
 $remote=@($v.remote_address | ForEach-Object { PolicyIp ([string]$_) } | Sort-Object -Unique)
 if (($remote -join ',') -cne ($Spec.addresses -join ',')) { throw 'adapter_address_readback' }
 $protocol=@{Any=@('Any','256');TCP=@('TCP','6');UDP=@('UDP','17')}[$Spec.protocol]
 if ($v.protocol -notin $protocol -or (@($v.local_port) -join ',') -ne 'Any' -or (@($v.remote_port) -join ',') -ne $Spec.remote_port -or $v.interface_type -ne $Spec.interface_type -or $v.program -ine $Spec.program -or $v.service -ine $Spec.service) { throw 'adapter_filter_readback' }
 return $true
}
function NewDisabledStagedRule($Spec) {
 $Spec=AssertStagedRuleSpec $Spec;$name=StagedRuleName $Spec
 if ($null -ne (GetExactLocalRule $name)) { throw 'adapter_name_exists' }
 $params=@{PolicyStore='PersistentStore';Name=$name;DisplayName=$name;Description='SSTP allowlist P3 staging only; never enabled';Group=(StagedRuleGroup $Spec);Enabled='False';Profile='Any';Direction='Outbound';Action='Allow';EdgeTraversalPolicy='Block';LocalAddress='Any';RemoteAddress=$Spec.addresses;Protocol=$Spec.protocol;LocalPort='Any';RemotePort=$Spec.remote_port;Program=$Spec.program;Service=$Spec.service;InterfaceAlias=$Spec.alias;InterfaceType=$Spec.interface_type;ErrorAction='Stop'}
 if ($Spec.protocol -eq 'Any') { $params.Remove('LocalPort');$params.Remove('RemotePort') }
 New-NetFirewallRule @params | Out-Null
 # If creation/readback fails, leave the rule DISABLED and stop; never enable or reset anything.
 $snapshot=ReadStagedRule $name
 AssertStagedRuleReadback $Spec $snapshot | Out-Null
 return $snapshot
}
function RemoveDisabledStagedRule($Spec,[string]$ExpectedHash) {
 $Spec=AssertStagedRuleSpec $Spec
 if ($ExpectedHash -cnotmatch '^[a-f0-9]{64}$') { throw 'adapter_expected_hash' }
 $name=StagedRuleName $Spec;$s=ReadStagedRule $name
 if ($null -eq $s) { return 'already_absent' }
 if ($s.sha256 -cne $ExpectedHash) { throw 'adapter_external_change' }
 AssertStagedRuleReadback $Spec $s | Out-Null
 # Re-read immediately before deleting. A hostile concurrent administrator is outside this guarantee.
 $latest=ReadStagedRule $name
 if ($null -eq $latest -or $latest.sha256 -cne $ExpectedHash) { throw 'adapter_external_change' }
 Remove-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop
 if ($null -ne (GetExactLocalRule $name)) { throw 'adapter_remove_readback' }
 return 'removed'
}
