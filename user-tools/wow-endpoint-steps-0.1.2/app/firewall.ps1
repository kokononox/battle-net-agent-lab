$ErrorActionPreference = 'Stop'
$stage='read_journal'
$reason='operation_failed'
$checks=[ordered]@{}
function ExactRules([string]$store,[string]$name) {
 @(Get-NetFirewallRule -PolicyStore $store -ErrorAction Stop | Where-Object {$_.Name -ceq $name})
}
try {
 $j=Get-Content -LiteralPath $env:WOW_STEPS_JOURNAL -Raw -Encoding UTF8 | ConvertFrom-Json
 if($j.id -notmatch '^[a-f0-9]{32}$' -or $j.name -cne ('WoWEndpointSteps-'+$j.id) -or $j.group -cne ('WoWEndpointStepsOwner-'+$j.id)){$reason='invalid_owner';throw 'invalid_owner'}
 $stage='check_ownership';$rows=@(ExactRules 'PersistentStore' $j.name)
 if(@($rows | Where-Object {$_.Group -cne $j.group}).Count -gt 0){$reason='ownership_mismatch';throw 'ownership_mismatch'}
 switch($env:WOW_STEPS_ACTION) {
  'probe' {
   $stage='check_profiles';$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
   if($profiles.Count -ne 3 -or @($profiles | Where-Object {$_.Enabled -ne 'True'}).Count -gt 0){$reason='profiles_not_already_enabled';throw 'profiles_not_already_enabled'}
   $stage='check_service'
   if((Get-Service -Name MpsSvc -ErrorAction Stop).Status -ne 'Running'){$reason='service_not_running';throw 'service_not_running'}
   @{ok=$true;firewall_profiles_enabled=$true} | ConvertTo-Json -Compress
  }
  'add' {
   $stage='validate_endpoint'
   if($rows.Count -ne 0){$reason='existing_rule_restore_first';throw 'existing_rule_restore_first'}
   if($j.protocol -notin @('TCP','UDP') -or $j.port -lt 1 -or $j.port -gt 65535){$reason='invalid_endpoint';throw 'invalid_endpoint'}
   [void][Net.IPAddress]::Parse($j.ip)
   if([IO.Path]::GetFileName($j.program) -ine 'Wow.exe' -or !(Test-Path -LiteralPath $j.program -PathType Leaf)){$reason='selected_program_missing';throw 'selected_program_missing'}
   $stage='create_rule'
   New-NetFirewallRule -PolicyStore PersistentStore -Name $j.name -DisplayName $j.name -Group $j.group -Direction Outbound -Action Block -Enabled True -Profile Any -Program $j.program -Protocol ([string]$j.protocol) -RemoteAddress ([string]$j.ip) -RemotePort ([string]$j.port) -ErrorAction Stop | Out-Null
   $stage='read_persistent_rule';$rr=@(ExactRules 'PersistentStore' $j.name)
   if($rr.Count -ne 1){$reason='persistent_rule_count_mismatch';throw 'persistent_rule_count_mismatch'}
   $r=$rr[0]
   $stage='read_application_filter';$aa=@($r | Get-NetFirewallApplicationFilter -ErrorAction Stop)
   $stage='read_address_filter';$dd=@($r | Get-NetFirewallAddressFilter -ErrorAction Stop)
   $stage='read_port_filter';$pp=@($r | Get-NetFirewallPortFilter -ErrorAction Stop)
   $stage='verify_persistent_rule'
   $checks.owner=($r.Group -ceq $j.group)
   $checks.enabled=($r.Enabled -eq 'True')
   $checks.action=($r.Action -eq 'Block')
   $checks.direction=($r.Direction -eq 'Outbound')
   $checks.application_filter_count=($aa.Count -eq 1)
   $checks.address_filter_count=($dd.Count -eq 1)
   $checks.port_filter_count=($pp.Count -eq 1)
   $checks.program=$false;$checks.remote_address=$false;$checks.protocol=$false;$checks.remote_port=$false
   if($aa.Count -eq 1){$actual=[Environment]::ExpandEnvironmentVariables([string]$aa[0].Program);$checks.program=($actual -ieq [string]$j.program)}
   if($dd.Count -eq 1){$addresses=@($dd[0].RemoteAddress);$checks.remote_address=($addresses.Count -eq 1 -and ([string]$addresses[0] -eq [string]$j.ip -or [string]$addresses[0] -eq ([string]$j.ip+'/32')))}
   if($pp.Count -eq 1){
    $actualProtocol=[string]($pp[0].Protocol)
    $expectedNumber=if($j.protocol -eq 'TCP'){'6'}else{'17'}
    $checks.protocol=($actualProtocol -eq $expectedNumber -or $actualProtocol -ieq [string]$j.protocol)
    $ports=@($pp[0].RemotePort);$checks.remote_port=($ports.Count -eq 1 -and [string]$ports[0] -eq [string]$j.port)
   }
   if(@($checks.Values | Where-Object {$_ -ne $true}).Count -gt 0){$reason='persistent_filter_mismatch';throw 'persistent_filter_mismatch'}
   $stage='wait_effective_policy';$found=$false
   # Readback retries only; rule creation happens exactly once. No fallback/duplicate add.
   for($attempt=0;$attempt -lt 5;$attempt++){
    $active=@(ExactRules 'ActiveStore' $j.name | Where-Object {$_.Group -ceq $j.group -and $_.Enabled -eq 'True' -and $_.Action -eq 'Block' -and $_.Direction -eq 'Outbound'})
    if($active.Count -eq 1){$found=$true;break}
    if($attempt -lt 4){Start-Sleep -Milliseconds 500}
   }
   if(!$found){$reason='rule_not_effective_after_readback_wait';throw 'rule_not_effective_after_readback_wait'}
   @{ok=$true;present=$true;rule_config_verified=$true;packet_block_verified=$false} | ConvertTo-Json -Compress
  }
  'remove' {
   $stage='remove_owned_rule'
   foreach($r in $rows){$r | Remove-NetFirewallRule -ErrorAction Stop}
   $stage='verify_rule_absence';$absent=$false
   for($attempt=0;$attempt -lt 5;$attempt++){
    $persistent=@(ExactRules 'PersistentStore' $j.name);$active=@(ExactRules 'ActiveStore' $j.name)
    if($persistent.Count -eq 0 -and $active.Count -eq 0){$absent=$true;break}
    if($attempt -lt 4){Start-Sleep -Milliseconds 500}
   }
   if(!$absent){$reason='absence_not_verified';throw 'absence_not_verified'}
   @{ok=$true;present=$false} | ConvertTo-Json -Compress
  }
  default {$stage='validate_action';$reason='invalid_action';throw 'invalid_action'}
 }
} catch {
 $hr=$null;try{$hr=[int]$_.Exception.HResult}catch{}
 $native=$null;try{if($null -ne $_.Exception.NativeErrorCode){$native=[int]$_.Exception.NativeErrorCode}}catch{}
 $safe=[ordered]@{ok=$false;stage=$stage;reason=$reason;hresult=$hr;native_error=$native;category=([string]$_.CategoryInfo.Category);checks=$checks}
 $safe | ConvertTo-Json -Compress -Depth 6
 # No raw exception, path, host name, command line, credentials or account data exported.
 exit 3
}
