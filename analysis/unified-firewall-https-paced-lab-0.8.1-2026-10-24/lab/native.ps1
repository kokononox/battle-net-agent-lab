# Real Windows adapter. Imported ONLY by the explicit administrator lab entry.
# No profile writes, rule adoption, service/hosts/DNS/ETW changes, or group deletion.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$script:UParts=[ordered]@{address='Get-NetFirewallAddressFilter';application='Get-NetFirewallApplicationFilter';interface='Get-NetFirewallInterfaceFilter';interface_type='Get-NetFirewallInterfaceTypeFilter';port='Get-NetFirewallPortFilter';security='Get-NetFirewallSecurityFilter';service='Get-NetFirewallServiceFilter'}
function URaw($Cim){
 $out=[ordered]@{};$ignore=@('Status','PrimaryStatus','StatusCode','EnforcementStatus','OperationalStatus','HealthState','CommunicationStatus','DetailedStatus','OperatingStatus')
 foreach($p in @($Cim.CimInstanceProperties|Sort-Object Name)){
  if($p.Name -in $ignore){continue};if($null -eq $p.Value){$out[$p.Name]=$null}
  elseif($p.Value -is [array]){$out[$p.Name]=@($p.Value|ForEach-Object{[string]$_})}
  elseif($p.Value -is [string] -or $p.Value.GetType().IsPrimitive -or $p.Value.GetType().IsEnum -or $p.Value -is [datetime] -or $p.Value -is [guid]){$out[$p.Name]=[string]$p.Value}
  else{throw 'unsupported_cim_image_type'}
 };return [pscustomobject]$out
}
function UGetRule([string]$Name,[string]$Store='PersistentStore'){
 # Enumerate then exact equality: wildcard -Name must not interpret untrusted input.
 $rows=@(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop|Where-Object{[string]$_.Name -ceq $Name})
 if($rows.Count -gt 1){throw 'duplicate_rule_identity'};if($rows.Count -eq 0){return $null};return $rows[0]
}
function UReadNative([string]$Name,[string]$Store='PersistentStore'){
 $r=UGetRule $Name $Store;if($null -eq $r){return $null}
 if([string]$r.PolicyStoreSourceType -cne 'Local'){throw 'not_local_rule'}
 $image=[ordered]@{rule=(URaw $r)}
 foreach($part in $script:UParts.Keys){$f=@($r|& $script:UParts[$part] -ErrorAction Stop);if($f.Count -ne 1){throw 'filter_coverage'};$raw=URaw $f[0];if([string]$raw.InstanceID -cne $Name){throw 'filter_identity'};$image[$part]=$raw}
 return [pscustomobject]$image
}
function UEnabledNative($Image){
 $c=ConvertFrom-Json -InputObject (UJson $Image)
 if($c.rule.Enabled -cne '2'){throw 'unsupported_disabled_provider_encoding'}
 $c.rule.Enabled='1';return $c
}
function UStringEqual($a,$b){([string]$a).Equals([string]$b,[StringComparison]::OrdinalIgnoreCase)}
function USetEqual($a,$b){((@($a|ForEach-Object{([string]$_).ToLowerInvariant()}|Sort-Object)-join '|') -ceq (@($b|ForEach-Object{([string]$_).ToLowerInvariant()}|Sort-Object)-join '|'))}
function UIPNumber([Net.IPAddress]$Address){
 $big=$Address.GetAddressBytes();[array]::Reverse($big);$little=New-Object byte[] ($big.Length+1);[array]::Copy($big,$little,$big.Length)
 return [Numerics.BigInteger]::new($little)
}
function UAddressSignature($Values){
 $ranges=@();foreach($text in @($Values)){
  $text=[string]$text;$prefix=$null
  if($text.Contains('/')){$pieces=$text.Split('/');if($pieces.Count -ne 2 -or $pieces[1] -notmatch '^\d{1,3}$'){throw 'provider_address_prefix'};$a=[Net.IPAddress]::Parse($pieces[0]);$b=$a;$prefix=[int]$pieces[1]}
  elseif($text.Contains('-')){$pieces=$text.Split('-');if($pieces.Count -ne 2){throw 'provider_address_range'};$a=[Net.IPAddress]::Parse($pieces[0]);$b=[Net.IPAddress]::Parse($pieces[1])}
  else{$a=[Net.IPAddress]::Parse($text);$b=$a}
  if($a.AddressFamily -ne $b.AddressFamily){throw 'provider_mixed_address_family'}
  $bits=32;if($a.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){$bits=128}
  $low=UIPNumber $a;$high=UIPNumber $b
  if($null -ne $prefix){if($prefix -lt 0 -or $prefix -gt $bits){throw 'provider_address_prefix'};$size=[Numerics.BigInteger]::Pow(2,($bits-$prefix));$low=$low-($low%$size);$high=$low+$size-1}
  if($low -gt $high){throw 'provider_address_order'}
  $ranges+=,[pscustomobject]@{bits=$bits;low=$low;high=$high}
 }
 $merged=@();foreach($r in @($ranges|Sort-Object bits,low,high)){
  if($merged.Count -gt 0 -and $merged[-1].bits -eq $r.bits -and $r.low -le ($merged[-1].high+1)){if($r.high -gt $merged[-1].high){$merged[-1].high=$r.high}}
  else{$merged+=,$r}
 }
 return (@($merged|ForEach-Object{[string]$_.bits+':'+$_.low.ToString()+':'+$_.high.ToString()}) -join '|')
}
function UMarker($Rule,[string]$Session){'UnifiedFW LAB 0.6.0;session='+$Session+';owner='+$Rule.owner+';component='+$Rule.component}
function UCreateNative($Rule,[string]$Session){
 $s=$Rule.spec
 # Every input is data to fixed cmdlet parameters; no script evaluation.
 $args=@{PolicyStore='PersistentStore';Name=$Rule.name;DisplayName=$Rule.name;Group=('UnifiedFW-LAB-'+$Rule.owner);Description=(UMarker $Rule $Session);Enabled='False';Direction='Outbound';Action='Block';Profile='Any';Program=$s.program;Service='Any';InterfaceAlias='Any';InterfaceType=$s.interface_type;LocalAddress='Any';RemoteAddress=@($s.remote_addresses);Protocol=$s.protocol;LocalPort='Any';RemotePort=[string]$s.port;EdgeTraversalPolicy='Block';Authentication='NotRequired';Encryption='NotRequired';OverrideBlockRules=$false;LooseSourceMapping=$false;LocalOnlyMapping=$false;ErrorAction='Stop'}
 New-NetFirewallRule @args|Out-Null
}
function UPackageUnrestricted($Application){
 $property=$Application.PSObject.Properties['Package']
 if($null -eq $property){return $false}
 if($null -eq $property.Value){return $true}
 return ($property.Value -is [string] -and (UStringEqual $property.Value 'Any'))
}
function UValidateCaptureNative($Image,$Rule,[string]$Session){
 if($null -eq $Image -or $Image.rule.Enabled -cne '2'){throw 'capture_disabled_rule_required'}
 $r=UGetRule $Rule.name
 if($null -eq $r -or [string]$r.Name -cne $Rule.name -or [string]$r.DisplayName -cne $Rule.name -or [string]$r.Group -cne ('UnifiedFW-LAB-'+$Rule.owner) -or [string]$r.Description -cne (UMarker $Rule $Session) -or [string]$r.Enabled -cne 'False' -or [string]$r.PolicyStoreSourceType -cne 'Local'){throw 'capture_ownership_mismatch'}
 if(-not (UEqual $Image (UReadNative $Rule.name))){throw 'capture_rule_changed'}
}
function UValidateNative($Image,$Rule,[string]$Session,[string]$Store='PersistentStore',[string]$Enabled='False'){
 if($null -eq $Image){throw 'created_rule_missing'}
 $r=UGetRule $Rule.name $Store;$s=$Rule.spec
 foreach($pair in @(@($r.Name,$Rule.name),@($r.DisplayName,$Rule.name),@($r.Group,('UnifiedFW-LAB-'+$Rule.owner)),@($r.Description,(UMarker $Rule $Session)),@($r.Enabled,$Enabled),@($r.Direction,'Outbound'),@($r.Action,'Block'),@($r.Profile,'Any'),@($r.EdgeTraversalPolicy,'Block'),@($r.LooseSourceMapping,'False'),@($r.LocalOnlyMapping,'False'))){if(-not (UStringEqual $pair[0] $pair[1])){throw 'created_rule_behavior_mismatch'}}
 $a=$r|Get-NetFirewallApplicationFilter -ErrorAction Stop;$p=$r|Get-NetFirewallPortFilter -ErrorAction Stop;$ad=$r|Get-NetFirewallAddressFilter -ErrorAction Stop;$it=$r|Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop;$ia=$r|Get-NetFirewallInterfaceFilter -ErrorAction Stop;$sec=$r|Get-NetFirewallSecurityFilter -ErrorAction Stop;$svc=$r|Get-NetFirewallServiceFilter -ErrorAction Stop
 foreach($pair in @(@('application.Program',$a.Program,$s.program),@('port.Protocol',$p.Protocol,$s.protocol),@('interface_type.InterfaceType',$it.InterfaceType,$s.interface_type),@('security.Authentication',$sec.Authentication,'NotRequired'),@('security.Encryption',$sec.Encryption,'NotRequired'),@('security.OverrideBlockRules',$sec.OverrideBlockRules,'False'),@('service.Service',$svc.Service,'Any'))){
  # NetSecurity may expose protocol as a numeric string rather than an enum.
  if($pair[0] -ceq 'port.Protocol' -and $pair[2] -ceq 'TCP' -and [string]$pair[1] -ceq '6'){continue};if($pair[0] -ceq 'port.Protocol' -and $pair[2] -ceq 'UDP' -and [string]$pair[1] -ceq '17'){continue};if($pair[0] -ceq 'port.Protocol' -and $pair[2] -ceq 'Any' -and [string]$pair[1] -ceq '256'){continue}
  if(-not (UStringEqual $pair[1] $pair[2])){throw ('created_filter_behavior_mismatch:'+ $pair[0])}
 }
 if(-not (UPackageUnrestricted $a)){throw 'created_filter_behavior_mismatch:application.Package'}
 foreach($pair in @(@(@($p.LocalPort),@('Any')),@(@($p.RemotePort),@([string]$s.port)),@(@($ad.LocalAddress),@('Any')),@(@($ia.InterfaceAlias),@('Any')))){if(-not (USetEqual $pair[0] $pair[1])){throw 'created_filter_set_mismatch'}}
 if((UAddressSignature $ad.RemoteAddress) -cne (UAddressSignature $s.remote_addresses)){throw 'created_remote_address_mismatch'}
 # Seal only the image that was validated, never a subsequently changed image.
 if(-not (UEqual $Image (UReadNative $Rule.name $Store))){throw 'created_rule_changed_during_validation'}
 if($Enabled -ceq 'False'){$null=UEnabledNative $Image}elseif($Image.rule.Enabled -cne '1'){throw 'unsupported_enabled_provider_encoding'}
}
function UEnableNative([string]$Name){
 $r=UGetRule $Name;if($null -eq $r){throw 'enable_rule_missing'}
 $r|Set-NetFirewallRule -Enabled True -ErrorAction Stop|Out-Null
}
function URemoveNative([string]$Name){
 $r=UGetRule $Name;if($null -eq $r){throw 'remove_rule_missing'}
 $r|Remove-NetFirewallRule -ErrorAction Stop|Out-Null
}
function UAdmin{
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'windows_required'}
 if(-not [Environment]::Is64BitProcess){throw 'windows_64bit_process_required'}
 $id=[Security.Principal.WindowsIdentity]::GetCurrent();$p=New-Object Security.Principal.WindowsPrincipal($id)
 if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'explicit_administrator_launch_required'}
}
function USecureRoot([bool]$Create){
 $root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'UnifiedFirewallLab-050';UAssertPath $root
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
function UReadEnvironment{
 $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop|Sort-Object Name|ForEach-Object{[pscustomobject][ordered]@{name=[string]$_.Name;enabled=[string]$_.Enabled;allow_local_rules=[string]$_.AllowLocalFirewallRules;default_outbound=[string]$_.DefaultOutboundAction}})
 $vpn=@();$vpnErrors=@()
 foreach($scope in @('current_user','all_users')){try{$args=@{ErrorAction='Stop'};if($scope -ceq 'all_users'){$args.AllUserConnection=$true};foreach($v in @(Get-VpnConnection @args)){$vpn+=,[pscustomobject][ordered]@{scope=$scope;name=[string]$v.Name;server=[string]$v.ServerAddress;tunnel=[string]$v.TunnelType;status=[string]$v.ConnectionStatus;split_tunneling=[bool]$v.SplitTunneling}}}catch{$vpnErrors+=,$scope}}
 $active=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop);$legacy=@($active|Where-Object{[string]$_.Enabled -eq 'True' -and (([string]$_.Name+' '+[string]$_.Group) -match '(?i)WoWBlacklist|SstpWhitelist|SstpIsolation') }|ForEach-Object{[string]$_.Name})
 $bypass=@(Get-NetFirewallSecurityFilter -PolicyStore ActiveStore -ErrorAction Stop|Where-Object{[string]$_.OverrideBlockRules -eq 'True'}|ForEach-Object{[string]$_.InstanceID})
 return [pscustomobject][ordered]@{profiles=$profiles;vpn=$vpn;vpn_query_errors=$vpnErrors;legacy_enabled_rule_names=$legacy;authenticated_bypass_filter_ids=$bypass;active_rule_count=$active.Count;read_only=$true;dns_resolution_performed=$false;no_leak_certified=$false}
}
function UAssertEnvironment($Env,[string]$Mode){
 if($Env.profiles.Count -ne 3){throw 'firewall_profile_coverage'}
 foreach($p in $Env.profiles){if($p.enabled -cne 'True' -or $p.allow_local_rules -ceq 'False'){throw 'firewall_disabled_or_local_rules_disallowed'}}
 if($Env.authenticated_bypass_filter_ids.Count -gt 0){throw 'authenticated_bypass_rules_require_review'}
 if($Env.legacy_enabled_rule_names.Count -gt 0){throw 'legacy_rules_active_restore_old_tool_first'}
 if($Mode -ceq 'vpn_allowlist'){
  if($Env.vpn_query_errors.Count -gt 0){throw 'vpn_inventory_incomplete'}
  $connected=@($Env.vpn|Where-Object{$_.status -ceq 'Connected'});if($connected.Count -eq 0 -or @($connected|Where-Object{$_.tunnel -cne 'Sstp'}).Count -gt 0){throw 'connected_sstp_only_required'}
 }
}
