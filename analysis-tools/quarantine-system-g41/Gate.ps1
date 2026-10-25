param([ValidateSet('Prepare','Apply','Verify','Restore')][string]$Action,[string]$Config)
$ErrorActionPreference='Stop';$script:Stage='entry'
function Save($Path,$Value){$tmp=$Path+'.tmp';[IO.File]::WriteAllText($tmp,($Value|ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false));Move-Item -LiteralPath $tmp -Destination $Path -Force}
function Fingerprint{
 $s=[ordered]@{
 profiles=@(& { $script:Stage='snapshot_profiles';Get-NetFirewallProfile -PolicyStore PersistentStore | Sort-Object Name | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowLocalFirewallRules,AllowLocalIPsecRules,AllowInboundRules,AllowUnicastResponseToMulticast,NotifyOnListen,DisabledInterfaceAliases,LogFileName,LogMaxSizeKilobytes,LogAllowed,LogBlocked})
 rules=@(& { $script:Stage='snapshot_rules';Get-NetFirewallRule -PolicyStore PersistentStore | Sort-Object Name | Select-Object Name,DisplayName,Description,Group,Enabled,Profile,Direction,Action,EdgeTraversalPolicy,LooseSourceMapping,LocalOnlyMapping,Owner})
 apps=@(& { $script:Stage='snapshot_apps';Get-NetFirewallApplicationFilter -PolicyStore PersistentStore | Sort-Object InstanceID | Select-Object InstanceID,Program,Package})
 ports=@(& { $script:Stage='snapshot_ports';Get-NetFirewallPortFilter -PolicyStore PersistentStore | Sort-Object InstanceID | Select-Object InstanceID,Protocol,LocalPort,RemotePort,IcmpType,DynamicTarget})
 addresses=@(& { $script:Stage='snapshot_addresses';Get-NetFirewallAddressFilter -PolicyStore PersistentStore | Sort-Object InstanceID | Select-Object InstanceID,LocalAddress,RemoteAddress})
 services=@(& { $script:Stage='snapshot_services';Get-NetFirewallServiceFilter -PolicyStore PersistentStore | Sort-Object InstanceID | Select-Object InstanceID,Service})
 interfaces=@(& { $script:Stage='snapshot_interfaces';Get-NetFirewallInterfaceFilter -PolicyStore PersistentStore | Sort-Object InstanceID | Select-Object InstanceID,InterfaceAlias})
 interface_types=@(& { $script:Stage='snapshot_interface_types';Get-NetFirewallInterfaceTypeFilter -PolicyStore PersistentStore | Sort-Object InstanceID | Select-Object InstanceID,InterfaceType})
 security=@(& { $script:Stage='snapshot_security';Get-NetFirewallSecurityFilter -PolicyStore PersistentStore | Sort-Object InstanceID | Select-Object InstanceID,Authentication,Encryption,OverrideBlockRules,LocalUserAuthorizedList,RemoteUserAuthorizedList,RemoteMachineAuthorizedList})
 }
 $bytes=[Text.Encoding]::UTF8.GetBytes(($s|ConvertTo-Json -Depth 8 -Compress));$h=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($h.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
}
try{
 $full=[IO.Path]::GetFullPath($Config);$c=Get-Content -LiteralPath $full -Raw|ConvertFrom-Json
 $base=(Join-Path $env:ProgramData 'BNetOnlineG41')+'\'
 if(-not $full.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -ne 'config.json' -or (Split-Path $full) -ne $c.root -or (Split-Path $c.root -Leaf) -notmatch '^[a-f0-9]{32}$' -or $c.job_name -ne ('Global\BNetOnlineG41_'+(Split-Path $c.root -Leaf))){throw 'context_rejected'}
 $state=Join-Path $c.root 'gate-state.json';$backup=Join-Path $c.root 'before.wfw';$group='BNetQuarantineG41_'+(Split-Path $c.root -Leaf)
 function Verify{
  $profiles=@(& { $script:Stage='snapshot_$profiles';Get-NetFirewallProfile -PolicyStore ActiveStore})
  if($profiles.Count -ne 3 -or @($profiles|Where-Object {$_.Enabled -ne 'True' -or $_.DefaultOutboundAction -ne 'Block' -or $_.DefaultInboundAction -ne 'Block' -or @($_.DisabledInterfaceAliases|Where-Object {$_ -and $_ -ne 'NotConfigured'}).Count -gt 0}).Count -gt 0){throw 'profiles_not_enforced'}
  $saved=Get-Content -Raw $state|ConvertFrom-Json;$allows=@(& { $script:Stage='snapshot_$saved';Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Action Allow})
  if($allows.Count -ne @($saved.management_paths).Count){throw 'unexpected_allow_count'}
  foreach($rule in $allows){$p=[string](($rule|Get-NetFirewallApplicationFilter).Program);if($rule.Group -ne $group -or $rule.Direction -ne 'Outbound' -or $p -notin @($saved.management_paths)){throw 'unexpected_allow_rule'}}
  return @{verified=$true;management_exceptions=$allows.Count;target_allow_rules=0;proxy_external_allow_rules=0}
 }
 if($Action -eq 'Prepare'){
  if(Test-Path $backup){throw 'backup_exists'}
  if((Get-Service mpssvc).Status -ne 'Running'){throw 'firewall_not_running'}
  $paths=@(Get-Process -Name 'Runner.Listener','Runner.Worker' -ErrorAction SilentlyContinue|ForEach-Object {$_.Path}|Sort-Object -Unique)
  if($paths.Count -lt 1 -or $paths.Count -gt 4 -or @($paths|Where-Object {$_ -notmatch '(?i)\\bin\\Runner\.(Listener|Worker)\.exe$'}).Count){throw 'management_identity_rejected'}
  $script:Stage='prepare_fingerprint';$before=Fingerprint;$script:Stage='prepare_export';$null=& "$env:SystemRoot\System32\netsh.exe" advfirewall export $backup
  $script:ExportCode=$LASTEXITCODE;$script:BackupExists=Test-Path -LiteralPath $backup;$script:BackupLength=0
  if($script:BackupExists){$script:BackupLength=(Get-Item -LiteralPath $backup).Length}
  if($LASTEXITCODE -ne 0 -or -not (Test-Path $backup) -or (Get-Item $backup).Length -lt 100){throw 'backup_failed'}
  Save $state @{fingerprint=$before;management_paths=$paths};@{prepared=$true}|ConvertTo-Json -Compress
 }elseif($Action -eq 'Apply'){
  if(-not (Test-Path (Join-Path $c.root 'watchdog-ready.json'))){throw 'watchdog_not_ready'}
  $saved=Get-Content -Raw $state|ConvertFrom-Json
  Save (Join-Path $c.root 'gate-armed.json') @{armed=$true}
  Get-NetFirewallRule -PolicyStore PersistentStore -Enabled True -Action Allow|Disable-NetFirewallRule
  foreach($p in @($saved.management_paths)){$null=New-NetFirewallRule -DisplayName ('G41 management '+[IO.Path]::GetFileName($p)) -Group $group -Direction Outbound -Action Allow -Profile Any -Enabled True -Program $p}
  Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultOutboundAction Block -DefaultInboundAction Block -AllowLocalFirewallRules True -DisabledInterfaceAliases @()
  Verify|ConvertTo-Json -Compress
 }elseif($Action -eq 'Verify'){Verify|ConvertTo-Json -Compress}
 else{
  $proof=Get-Content -Raw (Join-Path $c.root 'component-proof.json')|ConvertFrom-Json
  if($proof.job_active_zero -ne $true -or $proof.job_terminated -ne $true){throw 'component_exit_not_verified'}
  if(-not (Test-Path $backup)){throw 'backup_missing'}
  $null=& "$env:SystemRoot\System32\netsh.exe" advfirewall import $backup
  if($LASTEXITCODE -ne 0){throw 'import_failed'}
  $saved=Get-Content -Raw $state|ConvertFrom-Json;$match=((Fingerprint) -eq $saved.fingerprint)
  if(-not $match){throw 'restored_fingerprint_mismatch'}
  @{restored=$true;fingerprint_match=$true}|ConvertTo-Json -Compress
 }
}catch{
 $m=$_.Exception.Message;if($m -notmatch '^[a-z_]{1,80}$'){$m='gate_operation_failed'}
 $failure=@{error_code=$m;failure_stage=$script:Stage;error_type=$_.Exception.GetType().Name}
 if($script:Stage -eq 'prepare_export'){$failure.export_exit_code=$script:ExportCode;$failure.backup_exists=$script:BackupExists;$failure.backup_length=$script:BackupLength}
 $failure|ConvertTo-Json -Compress;exit 2
}
