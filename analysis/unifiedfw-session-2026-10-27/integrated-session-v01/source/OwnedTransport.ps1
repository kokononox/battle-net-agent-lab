# PRIVATE transport contract, not evidence of a connected/reviewed SSTP tunnel.
# Requires ConvertTo-SstpPlanIP from the unchanged exact-transport draft helper.
function Assert-UfwOwnedTransportSpec($Spec){
 $keys=@('endpoint_ips','observation_binding','schema','session_id','system_host_path','system_host_sha256')
 if((@($Spec.PSObject.Properties.Name|Sort-Object)-join ',') -cne ($keys-join ',') -or $Spec.schema -cne 'ufw-owned-sstp-spec-01' -or $Spec.session_id -isnot [string] -or $Spec.session_id -cnotmatch '^[a-f0-9]{32}$' -or $Spec.observation_binding -isnot [string] -or $Spec.observation_binding -cnotmatch '^[a-f0-9]{64}$' -or $Spec.system_host_sha256 -isnot [string] -or $Spec.system_host_sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'ufw_unified_transport_spec_shape'}
 if($Spec.system_host_path -isnot [string] -or $Spec.system_host_path -cnotmatch '^[A-Za-z]:\\[^*?%\r\n]*\\System32\\svchost\.exe$' -or $Spec.system_host_path.Contains('..') -or $Spec.system_host_path.Contains('/')){throw 'ufw_unified_transport_host_path'}
 if($Spec.endpoint_ips -isnot [array] -or $Spec.endpoint_ips.Count -lt 1 -or $Spec.endpoint_ips.Count -gt 8){throw 'ufw_unified_transport_endpoints'}
 $ips=@($Spec.endpoint_ips|ForEach-Object{ConvertTo-SstpPlanIP $_}|Sort-Object -Unique)
 if($ips.Count -ne $Spec.endpoint_ips.Count -or (Get-UfwLocalJson $ips) -cne (Get-UfwLocalJson $Spec.endpoint_ips)){throw 'ufw_unified_transport_canonical_endpoints'}
}
function Get-UfwOwnedTransportName($Spec){return 'UFW-SSTP-'+$Spec.session_id}
function Get-UfwOwnedTransportMarker($Spec){return 'UnifiedFW scoped transport '+$Spec.session_id+'/'+$Spec.observation_binding}
function Get-UfwOwnedCreationParameters($Spec){
 Assert-UfwOwnedTransportSpec $Spec
 return @{
  PolicyStore='PersistentStore';Name=(Get-UfwOwnedTransportName $Spec);DisplayName='UnifiedFW session SSTP transport';Description=(Get-UfwOwnedTransportMarker $Spec);Group=('UnifiedFW.Session.'+$Spec.session_id)
  Enabled='False';Profile='Any';Direction='Outbound';Action='Allow';Program=$Spec.system_host_path;Service='SstpSvc';Protocol='TCP';RemotePort='443';RemoteAddress=[string[]]$Spec.endpoint_ips
  LocalPort='Any';LocalAddress='Any';InterfaceAlias='Any';InterfaceType='Any';EdgeTraversalPolicy='Block';LooseSourceMapping=$false;LocalOnlyMapping=$false
  Authentication='NotRequired';Encryption='NotRequired';OverrideBlockRules=$false
 }
}
function Assert-UfwOwnedProperties($Object,[string[]]$Allowed){
 if($null -eq $Object -or $Object.namespace.Replace('\','/').ToLowerInvariant() -cne 'root/standardcimv2'){throw 'ufw_unified_transport_cim_namespace'}
 foreach($p in $Object.properties.PSObject.Properties){if($p.Name -cnotin $Allowed){throw 'ufw_unified_transport_unknown_property'}}
}
function Get-UfwOwnedValue($Object,[string]$Name,[string]$Type){
 if($Object.properties.PSObject.Properties.Name -cnotcontains $Name -or $Object.properties.$Name.cim_type -cne $Type){throw 'ufw_unified_transport_required_property'}
 return ,$Object.properties.$Name.value
}
function Assert-UfwOwnedScalar($Object,[string]$Name,[string]$Type,$Expected){
 $v=Get-UfwOwnedValue $Object $Name $Type
 if($Expected -is [bool]){if($v -isnot [bool] -or $v -ne $Expected){throw 'ufw_unified_transport_constraint'}}
 elseif($Expected -is [string]){if($v -isnot [string] -or $v -cne $Expected){throw 'ufw_unified_transport_constraint'}}
 elseif($v -is [string] -or $v -is [bool] -or $v -ne $Expected){throw 'ufw_unified_transport_constraint'}
}
function Assert-UfwOwnedArray($Object,[string]$Name,[string[]]$Expected){
 $v=Get-UfwOwnedValue $Object $Name 'StringArray'
 if($v -isnot [array] -or (Get-UfwLocalJson @($v|Sort-Object)) -cne (Get-UfwLocalJson @($Expected|Sort-Object))){throw 'ufw_unified_transport_constraint'}
}
function Assert-UfwOwnedRecord($Row,$Spec,[string]$Enabled){
 Assert-UfwOwnedTransportSpec $Spec
 [void](Get-UfwLocalRecordMap @($Row))
 if($Row.name -cne (Get-UfwOwnedTransportName $Spec) -or $Row.enabled -cne $Enabled -or $Row.direction -cne 'Outbound' -or $Row.action -cne 'Allow'){throw 'ufw_unified_transport_identity'}
 $rule=$Row.record.rule
 $knownRule=@('InstanceID','Profiles','LooseSourceMapping','LocalOnlyMapping','RuleGroup','DisplayName','DisplayGroup','EdgeTraversalPolicy','Platforms','Direction','Action','PrimaryStatus','StatusCode','Status','EnforcementStatus','PolicyStoreSourceType','PolicyStoreSource','Owner','SystemCreationClassName','SystemName','CreationClassName','PolicyRuleName','ConditionListType','RuleUsage','Priority','Mandatory','SequencedActions','ExecutionStrategy','PolicyDecisionStrategy','PolicyRoles','Enabled','CommonName','PolicyKeywords','Caption','Description','ElementName','RemoteDynamicKeywordAddresses')
 Assert-UfwOwnedProperties $rule $knownRule
 if($rule.class -cne 'MSFT_NetFirewallRule'){throw 'ufw_unified_transport_rule_class'}
 Assert-UfwOwnedScalar $rule 'Description' 'String' (Get-UfwOwnedTransportMarker $Spec)
 Assert-UfwOwnedScalar $rule 'RuleGroup' 'String' ('UnifiedFW.Session.'+$Spec.session_id)
 Assert-UfwOwnedScalar $rule 'Action' 'UInt16' 2;Assert-UfwOwnedScalar $rule 'Direction' 'UInt16' 2
 Assert-UfwOwnedScalar $rule 'EdgeTraversalPolicy' 'UInt16' 0
 Assert-UfwOwnedScalar $rule 'LooseSourceMapping' 'Boolean' $false;Assert-UfwOwnedScalar $rule 'LocalOnlyMapping' 'Boolean' $false
 if($rule.properties.PSObject.Properties.Name -ccontains 'RemoteDynamicKeywordAddresses'){
  $v=$rule.properties.RemoteDynamicKeywordAddresses.value;if($null -ne $v -and @($v).Count -ne 0){throw 'ufw_unified_transport_dynamic_address'}
 }
 $base=@('Name','SystemCreationClassName','SystemName','CreationClassName','IsNegated','InstallDate','OperationalStatus','StatusDescriptions','Status','HealthState','CommunicationStatus','DetailedStatus','OperatingStatus','PrimaryStatus','InstanceID','Caption','Description','ElementName')
 $shapes=@{
  Address=@('MSFT_NetAddressFilter',@('LocalAddress','RemoteAddress','RemoteDynamicKeywordAddresses'))
  Application=@('MSFT_NetApplicationFilter',@('AppPath','Package'))
  Service=@('MSFT_NetServiceFilter',@('ServiceName'))
  Port=@('MSFT_NetProtocolPortFilter',@('Protocol','LocalPort','RemotePort','IcmpType','DynamicTransport'))
  Interface=@('MSFT_NetInterfaceFilter',@('InterfaceAlias'))
  InterfaceType=@('MSFT_NetInterfaceTypeFilter',@('InterfaceType'))
  Security=@('MSFT_NetNetworkLayerSecurityFilter',@('Authentication','Encryption','OverrideBlockRules','LocalUsers','RemoteUsers','RemoteMachines'))
 }
 foreach($kind in $shapes.Keys){
  $f=$Row.record.associated_filters.$kind
  Assert-UfwOwnedProperties $f ($base+$shapes[$kind][1])
  if($f.class -cne $shapes[$kind][0]){throw 'ufw_unified_transport_filter_class'}
  Assert-UfwOwnedScalar $f 'IsNegated' 'Boolean' $false
 }
 $f=$Row.record.associated_filters
 $path=Get-UfwOwnedValue $f.Application 'AppPath' 'String'
 if($path -isnot [string] -or -not [string]::Equals($path,$Spec.system_host_path,[StringComparison]::OrdinalIgnoreCase)){throw 'ufw_unified_transport_program'}
 Assert-UfwOwnedScalar $f.Service 'ServiceName' 'String' 'SstpSvc'
 $protocol=Get-UfwOwnedValue $f.Port 'Protocol' 'String';if($protocol -cnotin @('6','TCP')){throw 'ufw_unified_transport_protocol'}
 Assert-UfwOwnedArray $f.Port 'RemotePort' @('443');Assert-UfwOwnedArray $f.Port 'LocalPort' @('Any')
 Assert-UfwOwnedScalar $f.Port 'DynamicTransport' 'UInt32' 0
 Assert-UfwOwnedArray $f.Address 'RemoteAddress' $Spec.endpoint_ips;Assert-UfwOwnedArray $f.Address 'LocalAddress' @('Any')
 if($f.Address.properties.PSObject.Properties.Name -ccontains 'RemoteDynamicKeywordAddresses'){
  $v=$f.Address.properties.RemoteDynamicKeywordAddresses.value;if($null -ne $v -and @($v).Count -ne 0){throw 'ufw_unified_transport_dynamic_address'}
 }
 Assert-UfwOwnedArray $f.Interface 'InterfaceAlias' @('Any')
 # InterfaceType Any has no security restriction in this infrastructure template.
 # Its raw provider value is pinned by the materialized receipt before enable;
 # never use this field to claim application data is restricted to the VPN NIC.
 [void](Get-UfwOwnedValue $f.InterfaceType 'InterfaceType' 'UInt32')
 Assert-UfwOwnedScalar $f.Security 'Authentication' 'UInt16' 0;Assert-UfwOwnedScalar $f.Security 'Encryption' 'UInt16' 0
 Assert-UfwOwnedScalar $f.Security 'OverrideBlockRules' 'Boolean' $false
}
function Get-UfwOwnedPairText($Pair){
 $r=[ordered]@{}
 foreach($side in @('local','effective')){$v=$Pair.$side;$r[$side]=[pscustomobject]@{name=$v.name;enabled=$v.enabled;action=$v.action;direction=$v.direction;source_type=$v.source_type;source_path=$v.source_path;semantic=(Get-UfwSemanticRecord $v.record)}}
 return Get-UfwLocalJson ([pscustomobject]$r)
}
function Assert-UfwOwnedPair($Pair,$Spec,[string]$Enabled){
 foreach($side in @('local','effective')){Assert-UfwOwnedRecord $Pair.$side $Spec $Enabled}
 if($Pair.effective.source_type -cne 'Local' -or [string]::IsNullOrWhiteSpace($Pair.effective.source_path) -or -not (Compare-UfwPrivateSnapshotPair $Pair.local.record $Pair.effective.record).semantic_fields_match){throw 'ufw_unified_transport_effective_mismatch'}
}
function New-UfwWindowsOwnedTransportIO {
 $create=New-UfwLocalModuleCallback {param($unused,$spec)
  Assert-UfwOwnedTransportSpec $spec
  if($env:OS -cne 'Windows_NT' -or -not [Environment]::Is64BitProcess){throw 'ufw_unified_transport_native_platform'}
  $path=Join-Path ([Environment]::SystemDirectory) 'svchost.exe'
  if(-not [string]::Equals($path,$spec.system_host_path,[StringComparison]::OrdinalIgnoreCase)){throw 'ufw_unified_transport_system_host'}
  $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $spec.system_host_sha256){throw 'ufw_unified_transport_host_changed'}
  $sig=Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
  if([string]$sig.Status -cne 'Valid' -or $null -eq $sig.SignerCertificate -or $sig.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)'){throw 'ufw_unified_transport_host_signature'}
  $parameters=Get-UfwOwnedCreationParameters $spec
  New-NetFirewallRule @parameters -ErrorAction Stop -Confirm:$false|Out-Null
 } $null
 $remove={param($native,$spec)
  if($env:OS -cne 'Windows_NT' -or $native.GetType().FullName -cne 'Microsoft.Management.Infrastructure.CimInstance' -or $native.CimSystemProperties.ClassName -cne 'MSFT_NetFirewallRule'){throw 'ufw_unified_transport_remove_scope'}
  Assert-UfwOwnedTransportSpec $spec
  if($native.CimInstanceProperties['InstanceID'].Value -cne (Get-UfwOwnedTransportName $spec) -or $native.CimInstanceProperties['Enabled'].Value -ne 2 -or $native.CimInstanceProperties['Description'].Value -cne (Get-UfwOwnedTransportMarker $spec) -or $native.CimInstanceProperties['RuleGroup'].Value -cne ('UnifiedFW.Session.'+$spec.session_id)){throw 'ufw_unified_transport_remove_identity'}
  # Full fresh seven-filter/receipt checks happen in the journal-bound backend too.
  Remove-NetFirewallRule -InputObject $native -ErrorAction Stop -Confirm:$false|Out-Null
 }
 return @{CreateTransport=$create;RemoveOwned=$remove}
}
