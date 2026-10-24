param([Parameter(Mandatory=$true)][ValidateSet('status','apply','restore','selftest')][string]$Action,[Parameter(Mandatory=$true)][string]$Output,[string]$Request)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'session-core.ps1')
. (Join-Path $PSScriptRoot 'native.ps1')
. (Join-Path $PSScriptRoot 'request.ps1')
$result=$null;$lock=$null;$root=$null;$mutating=$false;$exitCode=0;$selfTestID=$null;$selfBaseline=$null
try{
 UAdmin;Import-Module NetSecurity -ErrorAction Stop
 UAssertPath $Output;if(-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Output)))){throw 'output_directory_missing'}
 # Read/validate request BEFORE making a journal directory or touching a rule.
 $q=$null
 if($Action -in @('apply','selftest')){
  UAssertPath $Request;if((Get-Item -LiteralPath $Request).Length -gt 4194304){throw 'lab_request_size'}
  $q=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Request));UValidateRequest $q
  if($Action -ceq 'selftest'){
   if($q.mode -cne 'blacklist_only' -or $q.plan.rules.Count -ne 2){throw 'selftest_fixture_only'}
   foreach($r in $q.plan.rules){if($r.component -cne 'blacklist' -or $r.spec.protocol -cne 'TCP' -or $r.spec.port -ne 9 -or $r.spec.remote_addresses.Count -ne 1 -or $r.spec.remote_addresses[0] -cne '1.1.1.1/32'){throw 'selftest_fixture_only'}}
  }
 }
 $root=USecureRoot ($Action -in @('apply','selftest'))
 if([IO.Directory]::Exists($root)){$lockPath=Join-Path $root 'session.lock';UAssertPath $lockPath;$lock=UOpenPrivateFile $lockPath ([IO.FileMode]::OpenOrCreate)}
 $read={param($name) UReadNative $name};$session=$null
 if($Action -ceq 'status'){
  if([IO.Directory]::Exists($root)){$session=ULoad $root}
  $environment=UReadEnvironment
  $result=[ordered]@{ok=$true;action=$Action;session=$session;environment=$environment;firewall_changed=$false;journal_root=$root;protection_verified=$false}
 }elseif($Action -ceq 'restore'){
  if([IO.Directory]::Exists($root)){$mutating=$true;$session=RestoreUSession $root $read {param($name) URemoveNative $name}}
  $result=[ordered]@{ok=$true;action=$Action;session=$session;owned_session_restored=($null -eq $session -or $session.phase -ceq 'restored');foreign_rules_modified=$false;profiles_modified=$false;journal_root=$root;protection_verified=$false}
 }else{
  $environment=UReadEnvironment;UAssertEnvironment $environment $q.mode
  if($Action -ceq 'selftest'){
   . (Join-Path $PSScriptRoot 'inventory.ps1');$selfBaseline=ReadPolicyInventory
  }
  $beforeProfiles=@(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop|Sort-Object Name|ForEach-Object{URaw $_})
  # Environment and initial profiles are persisted BEFORE creating the first rule.
  $s=NewUSession $root $q.plan $read;if($Action -ceq 'selftest'){
   $selfTestID=$s.id
   UWritePrivateBytes (Join-Path $root ('baseline-'+$s.id+'.json')) ([Text.Encoding]::UTF8.GetBytes((UJson $selfBaseline)))
  }
  $evidence=Join-Path $root ('environment-'+$s.id+'.json');UWritePrivateBytes $evidence ([Text.Encoding]::UTF8.GetBytes((UJson ([ordered]@{environment=$environment;persistent_profiles=$beforeProfiles}))))
  $mutating=$true
  $session=InvokeUSession $root $read {param($rule,$id) UCreateNative $rule $id} {param($image,$rule,$id) UValidateNative $image $rule $id} {param($image) UEnabledNative $image} {param($name) UEnableNative $name} -ValidateCapture {param($image,$rule,$id) UValidateCaptureNative $image $rule $id}
  $activeNames=@();foreach($e in $session.entries){$r=UGetRule $e.name 'ActiveStore';if($null -eq $r -or [string]$r.Enabled -cne 'True' -or [string]$r.Action -cne 'Block' -or [string]$r.PolicyStoreSourceType -cne 'Local'){throw 'active_store_readback_failed'};UValidateNative (UReadNative $e.name 'ActiveStore') $e.rule $session.id 'ActiveStore' 'True';$activeNames+=,$e.name}
  $afterProfiles=@(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop|Sort-Object Name|ForEach-Object{URaw $_})
  if(-not (UEqual $beforeProfiles $afterProfiles)){throw 'profile_changed_externally_during_apply'}
  $result=[ordered]@{ok=$true;action=$Action;session=$session;active_store_enabled_rule_names=$activeNames;profiles_unchanged=$true;environment=$environment;journal_root=$root;packet_enforcement_tested=$false;outside_vpn_guard_installed=$false;protection_verified=$false;notice='LAB ONLY. Restore before every policy change. VPN-only whitelist does not protect outside the VPN.'}
  if($Action -ceq 'selftest'){
   $session=RestoreUSession $root $read {param($name) URemoveNative $name}
   $after=ReadPolicyInventory;UWritePrivateBytes (Join-Path $root ('after-'+$selfTestID+'.json')) ([Text.Encoding]::UTF8.GetBytes((UJson $after)));$comparison=ComparePolicyInventory $selfBaseline $after
   $comparisonFile=Join-Path $root ('selftest-'+$selfTestID+'.json')
   UWritePrivateBytes $comparisonFile ([Text.Encoding]::UTF8.GetBytes((UJson $comparison)))
   if(-not $comparison.strict_equal){throw 'selftest_baseline_drift_not_passed'}
   $result=[ordered]@{ok=$true;action=$Action;session_id=$selfTestID;restored=$true;baseline_strict_equal=$true;comparison=$comparison;journal_root=$root;packet_enforcement_tested=$false;vpn_whitelist_tested=$false;outside_vpn_guard_installed=$false;protection_verified=$false;scope='two_executable_block_rules_apply_readback_restore_only'}
  }
 }
}catch{
 $exitCode=1;$message=$_.Exception.Message
 # Never claim no changes after a mutation attempt. No timeout/kill or blind rollback.
 $cleanup='not_attempted'
 if($Action -ceq 'selftest' -and $null -ne $selfTestID){
  try{$current=ULoad $root;if($current.id -cne $selfTestID){throw 'selftest_session_identity_changed'};$null=RestoreUSession $root $read {param($name) URemoveNative $name};$cleanup='owned_session_restored'}catch{$cleanup='restore_failed_requires_inspection: '+$_.Exception.Message}
 }
 $result=[ordered]@{ok=$false;action=$Action;error=$message;firewall_change_status=$(if($mutating){'unknown_partial_or_applied; run RESTORE'}else{'no_rule_mutation_attempted'});journal_root=$root;selftest_cleanup=$cleanup;automatic_rollback_attempted=($Action -ceq 'selftest' -and $null -ne $selfTestID);protection_verified=$false}
}finally{if($null -ne $lock){$lock.Dispose()}}
if($null -ne $result){UAssertPath $Output;[IO.File]::WriteAllText([IO.Path]::GetFullPath($Output),(ConvertTo-Json -InputObject $result -Depth 64),(New-Object Text.UTF8Encoding($false)))}
exit $exitCode
