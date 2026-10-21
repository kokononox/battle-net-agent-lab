$ErrorActionPreference='Stop'
$stage='read_plan';$mutex=$null;$held=$false
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
 $addresses=@($dd[0].RemoteAddress);$suffix=if(([Net.IPAddress]::Parse($entry.ip)).AddressFamily -eq 'InterNetwork'){'/32'}else{'/128'}
 if($addresses.Count -ne 1 -or ([string]$addresses[0] -ne [string]$entry.ip -and [string]$addresses[0] -ne ([string]$entry.ip+$suffix))){throw 'address_mismatch'}
 $number=if($entry.protocol -eq 'TCP'){'6'}else{'17'}
 if([string]$pp[0].Protocol -ine $entry.protocol -and [string]$pp[0].Protocol -ne $number){throw 'protocol_mismatch'}
 $ports=@($pp[0].RemotePort);if($ports.Count -ne 1 -or [string]$ports[0] -ne [string]$entry.port){throw 'port_mismatch'}
}
function VerifyDesired([string]$store) {
 $rows=@(Owned $store)
 if($rows.Count -ne @($script:j.entries).Count){throw 'rule_count_mismatch'}
 foreach($entry in $script:j.entries){$matches=@($rows|Where-Object {$_.Name -ceq $entry.name});if($matches.Count -ne 1){throw 'rule_missing'};VerifySpec $matches[0] $entry}
}
try {
 $script:j=Get-Content -LiteralPath $env:WOW_BL_REQUEST -Raw -Encoding UTF8|ConvertFrom-Json
 if($j.owner -cnotmatch '^[a-f0-9]{32}$' -or $j.action -notin @('apply','restore','status')){throw 'invalid_plan'}
 $script:group='WoWBlacklistOwner-'+$j.owner
 $stage='operation_lock';$mutex=New-Object Threading.Mutex($false,'Local\WoWBlacklistFirewallExclusiveV1')
 try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
 if(!$held){throw 'another_operation_running'}
 $stage='read_owned_rules';$before=@(Owned 'PersistentStore');$active=@(Owned 'ActiveStore')
 if($j.action -eq 'status'){
  @{ok=$true;persistent_count=$before.Count;active_count=$active.Count;packet_block_verified=$false}|ConvertTo-Json -Compress
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
   [void][Net.IPAddress]::Parse($entry.ip);$names[$entry.name]=$true
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
