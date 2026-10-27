function IsoSecureRoot([bool]$Create){
 $root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'UnifiedFirewallIsolation-098';UAssertPath $root
 if(-not [IO.Directory]::Exists($root)){
  if(-not $Create){return $root}
  $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false)
  $admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544');$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18');$acl.SetOwner($admins)
  foreach($sid in @($admins,$system)){$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($rule)}
  $dir=New-Object IO.DirectoryInfo($root);$dir.Create($acl)
 }
 UAssertPath $root;$actual=Get-Acl -LiteralPath $root -ErrorAction Stop
 if(-not $actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')){throw 'unsafe_journal_acl_or_owner'}
 $rules=@($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));$seen=@{}
 foreach($r in $rules){if($r.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18') -or $r.AccessControlType -ne 'Allow' -or $r.FileSystemRights -ne 'FullControl' -or [string]$r.InheritanceFlags -ne 'ContainerInherit, ObjectInherit' -or [string]$r.PropagationFlags -ne 'None'){throw 'unsafe_journal_access_rule'};$seen[$r.IdentityReference.Value]=$true}
 if($seen.Count -ne 2){throw 'incomplete_journal_acl'}
 # Refuse unsafe pre-existing children; do not silently repair their permissions.
 foreach($child in @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)){
  UAssertPath $child.FullName;if($child.PSIsContainer){throw 'unexpected_journal_subdirectory'}
  $ca=Get-Acl -LiteralPath $child.FullName -ErrorAction Stop
  if($ca.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')){throw 'unsafe_journal_file_owner'}
  foreach($r in $ca.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($r.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18') -or $r.AccessControlType -ne 'Allow' -or $r.FileSystemRights -ne 'FullControl'){throw 'unsafe_journal_file_acl'}}
 }
 return $root
}
function IsoValidateNative($Image,$Rule,[string]$Session,[string]$Store='PersistentStore',[string]$Enabled='False'){
 if($null -eq $Image){throw 'created_rule_missing'}
 $r=UGetRule $Rule.name $Store;$s=$Rule.spec
 foreach($pair in @(@($r.Name,$Rule.name),@($r.DisplayName,$Rule.name),@($r.Group,('UnifiedFW-ISO-'+$Rule.owner)),@($r.Description,(IsoMarker $Rule $Session)),@($r.Enabled,$Enabled),@($r.Direction,'Outbound'),@($r.Action,'Allow'),@($r.Profile,'Any'),@($r.EdgeTraversalPolicy,'Block'),@($r.LooseSourceMapping,'False'),@($r.LocalOnlyMapping,'False'))){if(-not (UStringEqual $pair[0] $pair[1])){throw 'created_rule_behavior_mismatch'}}
 $a=$r|Get-NetFirewallApplicationFilter -ErrorAction Stop;$p=$r|Get-NetFirewallPortFilter -ErrorAction Stop;$ad=$r|Get-NetFirewallAddressFilter -ErrorAction Stop;$it=$r|Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop;$ia=$r|Get-NetFirewallInterfaceFilter -ErrorAction Stop;$sec=$r|Get-NetFirewallSecurityFilter -ErrorAction Stop;$svc=$r|Get-NetFirewallServiceFilter -ErrorAction Stop
 foreach($pair in @(@('application.Program',$a.Program,$s.program),@('port.Protocol',$p.Protocol,$s.protocol),@('interface_type.InterfaceType',$it.InterfaceType,$s.interface_type),@('security.Authentication',$sec.Authentication,'NotRequired'),@('security.Encryption',$sec.Encryption,'NotRequired'),@('security.OverrideBlockRules',$sec.OverrideBlockRules,'False'),@('service.Service',$svc.Service,$s.service))){
  # NetSecurity may expose protocol as a numeric string rather than an enum.
  if($pair[0] -ceq 'port.Protocol' -and $pair[2] -ceq 'TCP' -and [string]$pair[1] -ceq '6'){continue};if($pair[0] -ceq 'port.Protocol' -and $pair[2] -ceq 'UDP' -and [string]$pair[1] -ceq '17'){continue};if($pair[0] -ceq 'port.Protocol' -and $pair[2] -ceq 'Any' -and [string]$pair[1] -ceq '256'){continue}
  if(-not (UStringEqual $pair[1] $pair[2])){throw ('created_filter_behavior_mismatch:'+ $pair[0])}
 }
 if(-not (UPackageUnrestricted $a)){throw 'created_filter_behavior_mismatch:application.Package'}
 foreach($pair in @(@(@($p.LocalPort),@('Any')),@(@($p.RemotePort),@([string]$s.port)),@(@($ad.LocalAddress),@('Any')),@(@($ia.InterfaceAlias),@($s.interface_alias)))){if(-not (USetEqual $pair[0] $pair[1])){throw 'created_filter_set_mismatch'}}
 if((UAddressSignature $ad.RemoteAddress) -cne (UAddressSignature $s.remote_addresses)){throw 'created_remote_address_mismatch'}
 # Seal only the image that was validated, never a subsequently changed image.
 if(-not (UEqual $Image (UReadNative $Rule.name $Store))){throw 'created_rule_changed_during_validation'}
 if($Enabled -ceq 'False'){$null=UEnabledNative $Image}elseif($Image.rule.Enabled -cne '1'){throw 'unsupported_enabled_provider_encoding'}
}
function IsoMarker($Rule,[string]$Session){'UnifiedFW ISO LAB 0.9.8;session='+$Session+';owner='+$Rule.owner}
function IsoCreateNative($Rule,[string]$Session){
 $s=$Rule.spec
 $args=@{PolicyStore='PersistentStore';Name=$Rule.name;DisplayName=$Rule.name;Group=('UnifiedFW-ISO-'+$Rule.owner);Description=(IsoMarker $Rule $Session);Enabled='False';Direction='Outbound';Action='Allow';Profile='Any';Program=$s.program;Service=$s.service;InterfaceAlias=$s.interface_alias;InterfaceType=$s.interface_type;LocalAddress='Any';RemoteAddress=@($s.remote_addresses);Protocol=$s.protocol;LocalPort='Any';RemotePort=[string]$s.port;EdgeTraversalPolicy='Block';Authentication='NotRequired';Encryption='NotRequired';OverrideBlockRules=$false;LooseSourceMapping=$false;LocalOnlyMapping=$false;ErrorAction='Stop'}
 New-NetFirewallRule @args|Out-Null
}
function IsoAssertNoExcludedInterfaces($Profile){
 # Fail closed when NetSecurity cannot report the exclusion list. Do not change
 # the exclusions automatically or add fields to the existing journal schema.
 if($null -eq $Profile -or $Profile.PSObject.Properties.Name -cnotcontains 'DisabledInterfaceAliases'){throw 'iso_interface_exclusions_unreadable'}
 # NetSecurity's effective CIM StringArray may be null when it has no entries.
 # Accept that typed empty representation, never an absent/untyped property.
 if($null -eq $Profile.DisabledInterfaceAliases){
  if($Profile.PSObject.Properties.Name -cnotcontains 'CimInstanceProperties'){throw 'iso_interface_exclusions_unreadable'}
  $meta=$Profile.CimInstanceProperties['DisabledInterfaceAliases']
  if($null -eq $meta -or [string]$meta.CimType -cne 'StringArray' -or $null -ne $meta.Value){throw 'iso_interface_exclusions_unreadable'}
  return
 }
 foreach($alias in @($Profile.DisabledInterfaceAliases)){
  if($null -eq $alias -or [string]::IsNullOrWhiteSpace([string]$alias)){throw 'iso_interface_exclusions_unreadable'}
  if([string]$alias -ine 'NotConfigured'){throw 'iso_firewall_interface_exclusion_detected'}
 }
}
function IsoProfileRead([string]$Name,[string]$Store='PersistentStore'){
 $p=@(Get-NetFirewallProfile -PolicyStore $Store -ErrorAction Stop|Where-Object{[string]$_.Name -ceq $Name});if($p.Count -ne 1){throw 'iso_profile_identity'}
 IsoAssertNoExcludedInterfaces $p[0]
 $effective=$p[0];if($Store -ceq 'PersistentStore'){
  $active=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop|Where-Object{[string]$_.Name -ceq $Name})
  if($active.Count -ne 1){throw 'iso_profile_identity'}
  $effective=$active[0];IsoAssertNoExcludedInterfaces $effective
 }
 return [pscustomobject][ordered]@{name=[string]$p[0].Name;default_outbound=[string]$p[0].DefaultOutboundAction;enabled=[string]$effective.Enabled;allow_local_rules=[string]$effective.AllowLocalFirewallRules}
}
function IsoProfileSet([string]$Name,[string]$Default){
 if($Name -cnotin @('Domain','Private','Public') -or $Default -cnotin @('Block','Allow','NotConfigured')){throw 'iso_profile_input'}
 Set-NetFirewallProfile -PolicyStore PersistentStore -Name $Name -DefaultOutboundAction $Default -ErrorAction Stop|Out-Null
}
function IsoSave($S){
 $text=UJson $S;if([Text.Encoding]::UTF8.GetByteCount($text) -gt 30000000){throw 'iso_journal_size_limit'}
 USave $script:IsoRoot $S
 $e=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $script:IsoRoot 'session.json')))
 if($e.payload -cne $text -or $e.sha256 -cne (UHash $text)){throw 'iso_backup_readback_failed'}
}
function IsoLoad{
 $path=Join-Path $script:IsoRoot 'session.json';UAssertPath $path;if(-not [IO.File]::Exists($path)){return $null}
 if((Get-Item -LiteralPath $path).Length -gt 33554432){throw 'iso_journal_size'}
 $e=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($path));if($e.sha256 -cne (UHash ([string]$e.payload))){throw 'iso_journal_checksum'}
 $s=ConvertFrom-Json -InputObject $e.payload
 if($s.schema -cne 'unified-isolation-session-1' -or $s.owner -cnotmatch '^[a-f0-9]{32}$' -or $s.id -cnotmatch '^[a-f0-9]{32}$' -or $s.entries -isnot [array] -or $s.foreign -isnot [array] -or $s.profiles.Count -ne 3){throw 'iso_journal_schema'}
 $seen=@{};foreach($r in $s.entries){if($r.name -cnotmatch ('^UnifiedFW-ISO-'+$s.owner+'-[a-f0-9]{24}$') -or $seen.ContainsKey($r.name)){throw 'iso_journal_rule_schema'};$seen[$r.name]=$true}
 if(@($s.profiles|ForEach-Object{$_.name}|Sort-Object) -join ',' -cne 'Domain,Private,Public'){throw 'iso_journal_profile_schema'}
 return $s
}
# Read-only group reader; validated on Windows samples, not an atomic snapshot.
function IsoBulkIndex($Rows,[string]$Key){
 $index=New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
 foreach($r in @($Rows)){
  $p=$r.PSObject.Properties[$Key]
  if($null -eq $p -or [string]::IsNullOrEmpty([string]$p.Value)){throw 'iso_bulk_missing_identity'}
  $id=[string]$p.Value;if($index.ContainsKey($id)){throw 'iso_bulk_duplicate_identity'}
  $index.Add($id,$r)
 };return ,$index
}
function Read-IsoBulkSnapshot([string]$Store='PersistentStore'){
 if($Store -cnotin @('PersistentStore','ActiveStore')){throw 'iso_bulk_store'}
 $rules=IsoBulkIndex @(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop) 'Name'
 $parts=[ordered]@{}
 foreach($part in $script:UParts.Keys){$parts[$part]=IsoBulkIndex @(& $script:UParts[$part] -PolicyStore $Store -ErrorAction Stop) 'InstanceID'}
 return [pscustomobject]@{store=$Store;rules=$rules;parts=$parts;atomic=$false;mutation_qualified=$false}
}
function Get-IsoBulkImage($Snapshot,[string]$Name){
 if(-not $Snapshot.rules.ContainsKey($Name)){return $null}
 $r=$Snapshot.rules[$Name];if([string]$r.PolicyStoreSourceType -cne 'Local'){throw 'not_local_rule'}
 # Name can be a PowerShell-adapted alias, absent from raw CimInstanceProperties.
 if([string]$r.Name -cne $Name){throw 'iso_bulk_rule_identity'}
 $raw=URaw $r
 $image=[ordered]@{rule=$raw}
 foreach($part in $script:UParts.Keys){
  if(-not $Snapshot.parts[$part].ContainsKey($Name)){throw 'filter_coverage'}
  $raw=URaw $Snapshot.parts[$part][$Name];if([string]$raw.InstanceID -cne $Name){throw 'filter_identity'}
  $image[$part]=$raw
 };return [pscustomobject]$image
}

# Prepare-only planning reads. No snapshot is installed into IsoNativeOps or guardian.
function IsoPrepareForeignAllows($S){
 $own=@();if($null -ne $S){$own=@($S.entries|Where-Object{-not $_.removed}|ForEach-Object{$_.name})}
 # The original exact per-rule reader remains mandatory around all mutations.
 $snapshot=Read-IsoBulkSnapshot 'PersistentStore'
 $effective=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop|Where-Object{[string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow'})
 foreach($r in $effective){
  if([string]$r.PolicyStoreSourceType -cne 'Local'){throw 'iso_nonlocal_allow_cannot_quarantine_review_GPO'}
  $name=[string]$r.Name
  if(-not $snapshot.rules.ContainsKey($name)){throw 'iso_effective_allow_not_mutable_locally'}
  $p=$snapshot.rules[$name]
  if([string]$p.Enabled -cne 'True' -or [string]$p.Direction -cne 'Outbound' -or [string]$p.Action -cne 'Allow'){throw 'iso_effective_allow_not_mutable_locally'}
 }
 $persistent=@($snapshot.rules.Values|Where-Object{[string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow'}|Sort-Object Name)
 $items=@();$seen=@{}
 foreach($r in $persistent){
  $name=[string]$r.Name
  if($own -ccontains $name){continue}
  if([string]$r.PolicyStoreSourceType -cne 'Local'){throw 'iso_nonlocal_allow_cannot_quarantine_review_GPO'}
  if($seen.ContainsKey($name)){throw 'iso_duplicate_active_allow'};$seen[$name]=$true
  if($items.Count -ge 2048){throw 'iso_foreign_allow_limit'}
  $image=Get-IsoBulkImage $snapshot $name
  if($null -eq $image -or $image.rule.Enabled -cne '1'){throw 'iso_effective_allow_not_mutable_locally'}
  $items+=,[pscustomobject]@{name=$name;image=$image}
 }
 return ,$items
}

function IsoForeignAllows($S){
 $own=@();if($null -ne $S){$own=@($S.entries|Where-Object{-not $_.removed}|ForEach-Object{$_.name})}
 $items=@();$seen=@{}
 $effective=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop|Where-Object{[string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow'})
 foreach($r in $effective){if([string]$r.PolicyStoreSourceType -cne 'Local'){throw 'iso_nonlocal_allow_cannot_quarantine_review_GPO'}}
 $persistent=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
 foreach($r in $effective){if(@($persistent|Where-Object{[string]$_.Name -ceq [string]$r.Name -and [string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow'}).Count -ne 1){throw 'iso_effective_allow_not_mutable_locally'}}
 foreach($r in @($persistent|Where-Object{[string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow'}|Sort-Object Name)){
  if($own -ccontains [string]$r.Name){continue}
  if([string]$r.PolicyStoreSourceType -cne 'Local'){throw 'iso_nonlocal_allow_cannot_quarantine_review_GPO'}
  if($seen.ContainsKey([string]$r.Name)){throw 'iso_duplicate_active_allow'};$seen[[string]$r.Name]=$true
  $image=UReadNative ([string]$r.Name);if($null -eq $image -or $image.rule.Enabled -cne '1'){throw 'iso_effective_allow_not_mutable_locally'}
  $items+=,[pscustomobject]@{name=[string]$r.Name;image=$image}
 }
 if($items.Count -gt 2048){throw 'iso_foreign_allow_limit'};return ,$items
}
function IsoVerify($S){
 foreach($name in @('Domain','Private','Public')){foreach($store in @('PersistentStore','ActiveStore')){$p=IsoProfileRead $name $store;if($p.enabled -cne 'True' -or $p.default_outbound -cne 'Block' -or $p.allow_local_rules -ceq 'False'){throw 'iso_profile_effective_block_not_verified'}}}
 foreach($e in @($S.entries|Where-Object{-not $_.removed})){
  $image=UReadNative $e.name;if($null -eq $e.enabled -or -not (UEqual $image $e.enabled)){throw 'iso_owned_rule_drift'}
  IsoValidateNative $image $e.spec $S.id 'PersistentStore' 'True';IsoValidateNative (UReadNative $e.name 'ActiveStore') $e.spec $S.id 'ActiveStore' 'True'
 }
 foreach($r in @($S.foreign|Where-Object{$_.intent -and -not $_.restored})){if(-not (UEqual (UReadNative $r.name) $r.after)){throw 'iso_quarantined_allow_drift'}}
 $remaining=IsoForeignAllows $S;if($remaining.Count){throw 'iso_unquarantined_effective_allow'}
 $bypass=@(Get-NetFirewallSecurityFilter -PolicyStore ActiveStore -ErrorAction Stop|Where-Object{[string]$_.OverrideBlockRules -ceq 'True'});if($bypass.Count){throw 'iso_authenticated_bypass_detected'}
}
# Restore-only exception: exact-owned DISABLED Allow may be deleted after alias lifecycle drift.
# Never used for activation, update, verification, foreign rules, or journal rebasing.
function IsoValidateDisabledRemoval($Image,$Entry,$S){
 if($S.owner -cnotmatch '^[a-f0-9]{32}$' -or $S.id -cnotmatch '^[a-f0-9]{32}$' -or
    $Entry.name -cnotmatch ('^UnifiedFW-ISO-'+$S.owner+'-[a-f0-9]{24}$') -or
    $Entry.spec.name -cne $Entry.name -or $Entry.spec.owner -cne $S.owner){throw 'iso_removal_ownership_schema'}
 if($null -eq $Image -or $null -eq $Entry.disabled -or $Image.rule.Enabled -cne '2' -or $Entry.disabled.rule.Enabled -cne '2'){throw 'iso_removal_disabled_required'}
 if($null -eq $Image.interface.PSObject.Properties['InterfaceAlias'] -or $null -eq $Entry.disabled.interface.PSObject.Properties['InterfaceAlias']){throw 'iso_removal_alias_property_missing'}
 $copy=IsoCopy $Image;$copy.interface.InterfaceAlias=$Entry.disabled.interface.InterfaceAlias
 if(-not (UEqual $copy $Entry.disabled)){throw 'iso_removal_additional_drift'}
 $r=UGetRule $Entry.name
 if($null -eq $r){throw 'iso_removal_rule_disappeared_retry'}
 foreach($pair in @(@($r.Name,$Entry.name),@($r.DisplayName,$Entry.name),@($r.Group,('UnifiedFW-ISO-'+$S.owner)),@($r.Description,(IsoMarker $Entry.spec $S.id)),@($r.Enabled,'False'),@($r.Direction,'Outbound'),@($r.Action,'Allow'),@($r.PolicyStoreSourceType,'Local'))){if([string]$pair[0] -cne [string]$pair[1]){throw 'iso_removal_native_identity'}}
 if(-not (UEqual $Image (UReadNative $Entry.name))){throw 'iso_removal_concurrent_change'}
}
function IsoNativeOps{
 return @{ValidateDisabledRemoval={param($i,$e,$s)IsoValidateDisabledRemoval $i $e $s};Save={param($s)IsoSave $s};Read={param($n)UReadNative $n};Create={param($r,$id)IsoCreateNative $r $id};Validate={param($i,$r,$id,$en)IsoValidateNative $i $r $id 'PersistentStore' $en};Disable={param($n)$r=UGetRule $n;$r|Set-NetFirewallRule -Enabled False -ErrorAction Stop|Out-Null};Enable={param($n)UEnableNative $n};Remove={param($n)URemoveNative $n};ProfileRead={param($n)IsoProfileRead $n};ProfileSet={param($n,$d)IsoProfileSet $n $d};Verify={param($s)IsoVerify $s}}
}
function IsoAssertNoOtherEngine($S){
 $env=UReadEnvironment
 if($null -ne $S){$owned=@($S.entries|Where-Object{-not $_.removed}|ForEach-Object{$_.name});$env.legacy_enabled_rule_names=@($env.legacy_enabled_rule_names|Where-Object{$owned -cnotcontains $_})}
 UAssertEnvironment $env 'blacklist_only'
 $root=USecureRoot $false;$old=ULoad $root;if($null -ne $old -and $old.phase -cne 'restored'){throw 'iso_restore_native_blacklist_first_no_conflicting_Block'}
 return $env
}
function IsoDetectSstp{
 $env=UReadEnvironment
 if(@($env.vpn_query_errors).Count){throw 'iso_vpn_inventory_incomplete'}
 $connected=@($env.vpn|Where-Object{$_.status -ceq 'Connected'})
 if($connected.Count -ne 1 -or $connected[0].tunnel -cne 'Sstp' -or $connected[0].split_tunneling){throw 'iso_exactly_one_connected_full_tunnel_SSTP_required'}
 $v=$connected[0];if($v.name -match '[*?\[\]]'){throw 'iso_ambiguous_interface_alias'}
 $interfaces=@(Get-NetIPInterface -ErrorAction Stop|Where-Object{[string]$_.InterfaceAlias -ceq $v.name -and [string]$_.ConnectionState -ceq 'Connected'})
 $indexes=@($interfaces|ForEach-Object{[int]$_.InterfaceIndex}|Sort-Object -Unique);if($indexes.Count -ne 1){throw 'iso_unique_connected_VPN_interface_required'}
 $service=Get-CimInstance Win32_Service -Filter "Name='SstpSvc'" -ErrorAction Stop
 if($null -eq $service -or [string]$service.State -cne 'Running' -or [int]$service.ProcessId -lt 1){throw 'iso_SstpSvc_not_running'}
 $program=Join-Path $env:SystemRoot 'System32\svchost.exe';$process=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$service.ProcessId) -ErrorAction Stop
 if(-not (UStringEqual $process.ExecutablePath $program)){throw 'iso_SstpSvc_binary_identity_not_qualified'}
 $sig=Get-AuthenticodeSignature -LiteralPath $program -ErrorAction Stop;if([string]$sig.Status -cne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft'){throw 'iso_system_binary_signature'}
 # Do not perform an external DNS lookup. Use active TCP endpoints, qualified against IP or cache-only server name.
 $serverIPs=@();$parsed=$null
 if([Net.IPAddress]::TryParse([string]$v.server,[ref]$parsed)){$serverIPs=@($parsed.ToString())}else{
  $cache=@(Get-DnsClientCache -ErrorAction Stop|Where-Object{($_.PSObject.Properties.Name -contains 'Entry' -and [string]$_.Entry -ieq $v.server) -or ($_.PSObject.Properties.Name -contains 'Name' -and [string]$_.Name -ieq $v.server)})
  foreach($c in $cache){$ip=$null;if([Net.IPAddress]::TryParse([string]$c.Data,[ref]$ip)){$serverIPs+=,$ip.ToString()}}
 }
 $actual=@(Get-NetTCPConnection -State Established -ErrorAction Stop|Where-Object{[int]$_.OwningProcess -eq [int]$service.ProcessId -and [int]$_.RemotePort -eq 443 -and $serverIPs -contains [string]$_.RemoteAddress}|ForEach-Object{[string]$_.RemoteAddress}|Sort-Object -Unique)
 if(-not $actual.Count){throw 'iso_cannot_prove_SstpSvc_server_endpoint_no_broad_fallback'}
 $dns=@(Get-DnsClientServerAddress -InterfaceIndex $indexes[0] -ErrorAction Stop|ForEach-Object{$_.ServerAddresses}|Where-Object{$_}|Sort-Object -Unique)
 foreach($address in $dns){$ip=[Net.IPAddress]::Parse($address);if($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and $ip.ScopeId -gt 0){throw 'iso_scoped_DNS_requires_manual_review'}}
 return [pscustomobject][ordered]@{name=[string]$v.name;server=[string]$v.server;scope=[string]$v.scope;interface_index=$indexes[0];server_ips=$actual;dns_servers=$dns;svchost=$program;svchost_sha256=(Get-FileHash -LiteralPath $program -Algorithm SHA256).Hash.ToLowerInvariant();detection='connected_full_tunnel_SSTP_and_service_TCP443_and_cache_only_server_IP'}
}
function IsoRule($Policy,$Spec){
 $name='UnifiedFW-ISO-'+$Policy.owner+'-'+(UHash (UJson $Spec)).Substring(0,24)
 return [pscustomobject][ordered]@{name=$name;owner=$Policy.owner;spec=$Spec}
}
function IsoPrepare($Policy,$S){
 if($Policy.schema -cne 'unified-isolation-policy-1' -or $Policy.owner -cnotmatch '^[a-f0-9]{32}$' -or $Policy.whitelist.Count -lt 1 -or $Policy.whitelist.Count -gt 256){throw 'iso_policy_schema'}
 $connection=if($Policy.PSObject.Properties.Name -contains 'connection'){[string]$Policy.connection}else{'vpn'}
 if($connection -cnotin @('direct','vpn')){throw 'iso_invalid_connection_method'}
 if($null -ne $S -and $null -ne $S.plan){$previous=if($S.plan.policy.PSObject.Properties.Name -contains 'connection'){[string]$S.plan.policy.connection}else{'vpn'};if($connection -cne $previous){throw 'iso_connection_change_requires_explicit_restore'}}
 $env=IsoAssertNoOtherEngine $S;$vpn=$null;$rules=@();$early=@();$alias='Any';$interfaceType='Any'
 if($connection -ceq 'vpn'){$vpn=IsoDetectSstp;$alias=$vpn.name;$interfaceType='RemoteAccess'}
 foreach($w in $Policy.whitelist){
  if($w.protocol -cnotin @('Any','TCP','UDP') -or [string]$w.remote_port -cnotmatch '^(Any|[0-9]{1,5}(-[0-9]{1,5})?)$'){throw 'iso_whitelist_transport'}
  $null=UAddressSignature @($w.remote_addresses)
  $spec=[pscustomobject][ordered]@{program='Any';service='Any';interface_alias=$alias;interface_type=$interfaceType;remote_addresses=@($w.remote_addresses);protocol=$w.protocol;port=[string]$w.remote_port}
  $rules+=,(IsoRule $Policy $spec)
 }
 if($connection -ceq 'vpn'){
 $transport=[pscustomobject][ordered]@{program=$vpn.svchost;service='SstpSvc';interface_alias='Any';interface_type='Any';remote_addresses=@($vpn.server_ips);protocol='TCP';port='443'};$transportRule=IsoRule $Policy $transport;$rules+=,$transportRule;$early+=,$transportRule.name
 foreach($proto in @('TCP','UDP')){if($vpn.dns_servers.Count){$spec=[pscustomobject][ordered]@{program=$vpn.svchost;service='Dnscache';interface_alias=$vpn.name;interface_type='RemoteAccess';remote_addresses=@($vpn.dns_servers);protocol=$proto;port='53'};$rules+=,(IsoRule $Policy $spec)}}
 }
 $rules=@($rules|Sort-Object name -Unique);$foreign=IsoPrepareForeignAllows $S;$profiles=@()
 foreach($name in @('Domain','Private','Public')){$profile=IsoProfileRead $name;if($profile.enabled -cne 'True' -or $profile.allow_local_rules -ceq 'False'){throw 'iso_profile_not_ready_for_isolation'};$profiles+=,$profile}
 $bypass=@(Get-NetFirewallSecurityFilter -PolicyStore ActiveStore -ErrorAction Stop|Where-Object{[string]$_.OverrideBlockRules -ceq 'True'});if($bypass.Count){throw 'iso_authenticated_bypass_detected'}
 return [pscustomobject][ordered]@{policy=$Policy;vpn=$vpn;rules=$rules;pre_block_rule_names=@($early);foreign=$foreign;profiles=$profiles;no_leak_certified=$false;control_plane=$(if($connection -ceq 'direct'){'explicit_systemwide_whitelist_only; no_automatic_DNS_DHCP_or_VPN_transport_exception'}else{'SstpSvc_to_observed_server_TCP443;Dnscache_to_VPN_DNS_inside_exact_tunnel_only;no_external_DNS_or_DHCP_exception'})}
}
