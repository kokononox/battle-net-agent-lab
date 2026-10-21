$ErrorActionPreference='Stop'
$stage='read_plan';$mutex=$null;$held=$false
. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $env:WOW_BL_APP 'ui-model.ps1'))))
# Windows can return IPv4 remote subnets with a dotted netmask.
function ComparableTarget([string]$value) {
 $parts=$value.Split('/')
 if($parts.Count -eq 2 -and $parts[1].Contains('.')){
  $mask=([Net.IPAddress]::Parse($parts[1])).GetAddressBytes();if($mask.Length -ne 4){throw 'invalid_mask'}
  $prefix=0;$zeroSeen=$false
  foreach($byte in $mask){for($bit=7;$bit -ge 0;$bit--){$one=($byte -band (1 -shl $bit)) -ne 0;if($one){if($zeroSeen){throw 'noncontiguous_mask'};$prefix++}else{$zeroSeen=$true}}}
  return (Ui-Target ($parts[0]+'/'+$prefix))
 }
 return (Ui-Target $value)
}
function Owned([string]$store) {
 $rows=@(Get-NetFirewallRule -PolicyStore $store -ErrorAction Stop | Where-Object {$_.Group -ceq $script:group})
 foreach($row in $rows){if($row.Name -cnotmatch ('^WoWBlacklist-'+$script:j.owner+'-[a-f0-9]{24}$')){throw 'ownership_mismatch'}}
 return $rows
}
function VerifySpec($rule,$entry) {
 if($rule.Group -cne $script:group -or $rule.Enabled -ne 'True' -or $rule.Direction -ne 'Outbound' -or $rule.Action -ne 'Block'){throw 'rule_mismatch'}
 if(([string]$rule.Profile) -notin @('Any','0')){throw 'profile_mismatch'}
 $aa=@($rule|Get-NetFirewallApplicationFilter -ErrorAction Stop);$dd=@($rule|Get-NetFirewallAddressFilter -ErrorAction Stop);$pp=@($rule|Get-NetFirewallPortFilter -ErrorAction Stop)
 if($aa.Count -ne 1 -or $dd.Count -ne 1 -or $pp.Count -ne 1){throw 'filter_count_mismatch'}
 if([Environment]::ExpandEnvironmentVariables([string]$aa[0].Program) -ine $script:j.program){throw 'program_mismatch'}
 $addresses=@($dd[0].RemoteAddress)
 if($addresses.Count -ne 1 -or (ComparableTarget ([string]$addresses[0])) -cne (Ui-Target ([string]$entry.ip))){throw 'address_mismatch'}
 $number=if($entry.protocol -eq 'TCP'){'6'}else{'17'}
 if([string]$pp[0].Protocol -ine $entry.protocol -and [string]$pp[0].Protocol -ne $number){throw 'protocol_mismatch'}
 $ports=@($pp[0].RemotePort);if($ports.Count -ne 1 -or [string]$ports[0] -ne [string]$entry.port){throw 'port_mismatch'}
}
# Inventory is intentionally conservative: only classify unconstrained rules created by this tool.
function VerifyInventoryScope($rule,$entry) {
 VerifySpec $rule $entry
 $aa=@($rule|Get-NetFirewallApplicationFilter -ErrorAction Stop);$dd=@($rule|Get-NetFirewallAddressFilter -ErrorAction Stop);$pp=@($rule|Get-NetFirewallPortFilter -ErrorAction Stop)
 if(@($dd[0].LocalAddress).Count -ne 1 -or [string]$dd[0].LocalAddress -ine 'Any' -or @($pp[0].LocalPort).Count -ne 1 -or [string]$pp[0].LocalPort -ine 'Any'){throw 'local_scope_restricted'}
 if([string]$aa[0].Package -notin @('','Any')){throw 'package_restricted'}
 $iface=@($rule|Get-NetFirewallInterfaceFilter -ErrorAction Stop);$itype=@($rule|Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop);$service=@($rule|Get-NetFirewallServiceFilter -ErrorAction Stop);$security=@($rule|Get-NetFirewallSecurityFilter -ErrorAction Stop)
 if($iface.Count -ne 1 -or $itype.Count -ne 1 -or $service.Count -ne 1 -or $security.Count -ne 1){throw 'scope_filter_count'}
 if(@($iface[0].InterfaceAlias).Count -ne 1 -or [string]$iface[0].InterfaceAlias -ine 'Any' -or [string]$itype[0].InterfaceType -ine 'Any' -or [string]$service[0].Service -ine 'Any'){throw 'interface_or_service_restricted'}
 foreach($property in @('LocalUser','RemoteUser','RemoteMachine')){if([string]$security[0].$property -notin @('','Any')){throw 'security_restricted'}}
 if([string]$security[0].Authentication -notin @('','NotRequired') -or [string]$security[0].Encryption -notin @('','NotRequired')){throw 'ipsec_restricted'}
}
function VerifyDesired([string]$store) {
 $rows=@(Owned $store)
 if($rows.Count -ne @($script:j.entries).Count){throw 'rule_count_mismatch'}
 foreach($entry in $script:j.entries){$matches=@($rows|Where-Object {$_.Name -ceq $entry.name});if($matches.Count -ne 1){throw 'rule_missing'};VerifySpec $matches[0] $entry}
}
try {
 $script:j=Get-Content -LiteralPath $env:WOW_BL_REQUEST -Raw -Encoding UTF8|ConvertFrom-Json
 if($j.owner -cnotmatch '^[a-f0-9]{32}$' -or $j.action -notin @('apply','restore','status','inventory')){throw 'invalid_plan'}
 $script:group='WoWBlacklistOwner-'+$j.owner
 $stage='operation_lock';$mutex=New-Object Threading.Mutex($false,'Local\WoWBlacklistFirewallExclusiveV1')
 try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
 if(!$held){throw 'another_operation_running'}
 $stage='read_owned_rules';$before=@(Owned 'PersistentStore');$active=@(Owned 'ActiveStore')
 if($j.action -eq 'inventory'){
  $stage='verify_inventory';$valid=@();$unknown=0
  $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
  if($profiles.Count -ne 3 -or @($profiles|Where-Object {$_.Enabled -ne 'True'}).Count -gt 0 -or (Get-Service MpsSvc -ErrorAction Stop).Status -ne 'Running'){throw 'firewall_not_enabled'}
  foreach($rule in $before){
   try{
    $aa=@($rule|Get-NetFirewallApplicationFilter -ErrorAction Stop);$dd=@($rule|Get-NetFirewallAddressFilter -ErrorAction Stop);$pp=@($rule|Get-NetFirewallPortFilter -ErrorAction Stop)
    if($aa.Count -ne 1 -or $dd.Count -ne 1 -or $pp.Count -ne 1){throw 'invalid_filters'}
    if([Environment]::ExpandEnvironmentVariables([string]$aa[0].Program) -ine $j.program){continue}
    if(@($dd[0].RemoteAddress).Count -ne 1 -or @($pp[0].RemotePort).Count -ne 1){throw 'ambiguous_spec'}
    $target=ComparableTarget ([string]$dd[0].RemoteAddress);$proto=[string]$pp[0].Protocol
    if($proto -eq '6'){$proto='TCP'}elseif($proto -eq '17'){$proto='UDP'};$proto=$proto.ToUpperInvariant()
    $port=0;if(![int]::TryParse([string]$pp[0].RemotePort,[ref]$port) -or $port -lt 1 -or $port -gt 65535 -or $proto -notin @('TCP','UDP')){throw 'invalid_port_protocol'}
    $entry=[pscustomobject]@{ip=$target;port=$port;protocol=$proto;name=$rule.Name}
    VerifyInventoryScope $rule $entry
    $matches=@($active|Where-Object {$_.Name -ceq $entry.name});if($matches.Count -ne 1){throw 'active_missing'};VerifyInventoryScope $matches[0] $entry
    $valid+=,$entry
   }catch{$unknown++}
  }
  @{ok=$true;inventory_verified=$true;entries=$valid;unverified_owned_count=$unknown;checked_utc=[DateTime]::UtcNow.ToString('o');packet_block_verified=$false}|ConvertTo-Json -Depth 6 -Compress
 }elseif($j.action -eq 'status'){
  $details=@(foreach($entry in @($j.entries)){
   $p=@($before|Where-Object {$_.Name -ceq $entry.name});$a=@($active|Where-Object {$_.Name -ceq $entry.name});$pv=$false;$av=$false
   if($p.Count -eq 1){try{VerifySpec $p[0] $entry;$pv=$true}catch{}}
   if($a.Count -eq 1){try{VerifySpec $a[0] $entry;$av=$true}catch{}}
   @{ip=$entry.ip;port=$entry.port;protocol=$entry.protocol;persistent_present=($p.Count -gt 0);active_present=($a.Count -gt 0);persistent_verified=$pv;active_verified=$av}
  })
  @{ok=$true;persistent_count=$before.Count;active_count=$active.Count;entries=$details;packet_block_verified=$false}|ConvertTo-Json -Depth 6 -Compress
 }elseif($j.action -eq 'restore'){
  $stage='remove_owned_rules';$failed=$false
  foreach($row in $before){try{$row|Remove-NetFirewallRule -ErrorAction Stop}catch{$failed=$true}}
  $stage='verify_absence';$absent=$false
  for($k=0;$k -lt 5;$k++){
   if(@(Owned 'PersistentStore').Count -eq 0 -and @(Owned 'ActiveStore').Count -eq 0){$absent=$true;break};Start-Sleep -Milliseconds 500
  }
  if(!$absent){throw 'absence_not_verified'}
  @{ok=$true;persistent_count=0;active_count=0;absence_verified=$true;removed_count=$before.Count}|ConvertTo-Json -Compress
 }else{
  $stage='validate_plan'
  if(@($j.entries).Count -lt 1 -or @($j.entries).Count -gt 100){throw 'invalid_entry_count'}
  if([IO.Path]::GetFileName($j.program) -ine 'Wow.exe' -or !(Test-Path -LiteralPath $j.program -PathType Leaf)){throw 'program_missing'}
  $names=@{}
  foreach($entry in $j.entries){
   if($entry.name -cnotmatch ('^WoWBlacklist-'+$j.owner+'-[a-f0-9]{24}$') -or $entry.protocol -notin @('TCP','UDP') -or $entry.port -lt 1 -or $entry.port -gt 65535 -or $names.ContainsKey($entry.name)){throw 'invalid_entry'}
   [void](Ui-Target ([string]$entry.ip));$names[$entry.name]=$true
  }
  $stage='check_security_prerequisites';$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
  if($profiles.Count -ne 3 -or @($profiles|Where-Object {$_.Enabled -ne 'True'}).Count -gt 0 -or (Get-Service MpsSvc -ErrorAction Stop).Status -ne 'Running'){throw 'firewall_not_already_enabled'}
  $stage='check_name_collisions';$all=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
  foreach($entry in $j.entries){if(@($all|Where-Object {$_.Name -ceq $entry.name -and $_.Group -cne $group}).Count -gt 0){throw 'ownership_mismatch'}}
  $stage='add_missing_rules'
  foreach($entry in $j.entries){
   $existing=@($before|Where-Object {$_.Name -ceq $entry.name})
   if($existing.Count -gt 1){throw 'duplicate_owned_rule'}
   if($existing.Count -eq 0){New-NetFirewallRule -PolicyStore PersistentStore -Name $entry.name -DisplayName $entry.name -Group $group -Direction Outbound -Action Block -Enabled True -Profile Any -Program $j.program -Protocol ([string]$entry.protocol) -RemoteAddress ([string]$entry.ip) -RemotePort ([string]$entry.port) -ErrorAction Stop|Out-Null}
  }
  $stage='verify_new_rules';$now=@(Owned 'PersistentStore')
  foreach($entry in $j.entries){$matches=@($now|Where-Object {$_.Name -ceq $entry.name});if($matches.Count -ne 1){throw 'new_rule_missing'};VerifySpec $matches[0] $entry}
  $stage='remove_obsolete_rules';$failed=$false
  foreach($row in $before){if(!$names.ContainsKey($row.Name)){try{$row|Remove-NetFirewallRule -ErrorAction Stop}catch{$failed=$true}}}
  if($failed){throw 'obsolete_removal_incomplete'}
  $stage='verify_persistent';VerifyDesired 'PersistentStore'
  $stage='verify_active';$verified=$false
  for($k=0;$k -lt 5;$k++){try{VerifyDesired 'ActiveStore';$verified=$true;break}catch{if($k -lt 4){Start-Sleep -Milliseconds 500}}}
  if(!$verified){throw 'active_verification_failed'}
  @{ok=$true;config_verified=$true;persistent_count=@($j.entries).Count;active_count=@($j.entries).Count;packet_block_verified=$false}|ConvertTo-Json -Compress
 }
}catch{
 @{ok=$false;stage=$stage;hresult=([int]$_.Exception.HResult)}|ConvertTo-Json -Compress
 exit 3
}finally{if($held){$mutex.ReleaseMutex()};if($mutex){$mutex.Dispose()}}
