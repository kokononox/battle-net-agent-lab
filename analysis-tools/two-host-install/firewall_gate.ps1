param([ValidateSet('Prepare','Apply','Verify','Restore')][string]$Action,[string]$Work,[string]$ProxyExe,[string]$Config)
$ErrorActionPreference='Stop'
$group='BNet-Two-Hosts-G1'
$state=Join-Path $Work 'gate-state.json'
$backup=Join-Path $Work 'before.wfw'
$task='BNet-Two-Hosts-G1-Rollback'
function Fingerprint {
 $p=@(Get-NetFirewallProfile -PolicyStore PersistentStore | Sort-Object Name | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowLocalFirewallRules,DisabledInterfaceAliases)
 $r=@(Get-NetFirewallRule -PolicyStore PersistentStore | Sort-Object Name | Select-Object Name,Enabled,Direction,Action,Profile)
 $json=ConvertTo-Json -Depth 6 -Compress -InputObject @{profiles=$p;rules=$r}
 $sha=[Security.Cryptography.SHA256]::Create()
 try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json)))).Replace('-','').ToLowerInvariant() } finally {$sha.Dispose()}
}
function Verify-Gate {
 $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore)
 if($profiles.Count -ne 3 -or @($profiles | Where-Object {$_.Enabled -ne 'True' -or $_.DefaultOutboundAction -ne 'Block' -or @($_.DisabledInterfaceAliases | Where-Object {$_ -and $_ -ne 'NotConfigured'}).Count -gt 0}).Count -ne 0){throw 'gate_profile_not_enforced'}
 $allows=@(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Action Allow)
 if($allows.Count -lt 2 -or @($allows | Where-Object {$_.Group -ne $group}).Count -ne 0){throw 'unexpected_enabled_allow_rule'}
 $proxy=@($allows | Where-Object {$_.DisplayName -eq 'BNet G1 proxy outbound'})
 if($proxy.Count -ne 1){throw 'proxy_rule_missing'}
 if((($proxy | Get-NetFirewallApplicationFilter).Program) -ne $ProxyExe){throw 'proxy_program_mismatch'}
 $cfg=Get-Content -Raw $Config | ConvertFrom-Json
 $expected=@($cfg.hosts.'us.version.battle.net')+@($cfg.hosts.'level3.blizzard.com') | Sort-Object -Unique
 $actual=@(($proxy | Get-NetFirewallAddressFilter).RemoteAddress) | Sort-Object -Unique
 if(($expected -join ',') -ne ($actual -join ',')){throw 'proxy_remote_address_mismatch'}
 return @{verified=$true;enabled_allow_rules=$allows.Count;management_rules=@($allows | Where-Object {$_.DisplayName -like 'BNet G1 management *'}).Count;profiles=3}
}
try {
 if($Action -eq 'Prepare'){
  if((Get-Service mpssvc).Status -ne 'Running'){throw 'firewall_service_not_running'}
  $admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if(-not $admin){throw 'administrator_required'}
  if(Test-Path $backup){throw 'backup_already_exists'}
  $null=& "$env:SystemRoot\System32\netsh.exe" advfirewall export $backup
  if($LASTEXITCODE -ne 0 -or -not (Test-Path $backup)){throw 'firewall_export_failed'}
  $paths=@(Get-Process -Name 'Runner.Listener','Runner.Worker' -ErrorAction SilentlyContinue | ForEach-Object {$_.Path} | Sort-Object -Unique)
  if($paths.Count -lt 1 -or $paths.Count -gt 4 -or @($paths | Where-Object {$_ -notmatch '(?i)\\bin\\Runner\.(Listener|Worker)\.exe$'}).Count -ne 0){throw 'management_identity_not_found'}
  @{fingerprint=(Fingerprint);management_paths=$paths} | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $state
  $rollback=Join-Path $Work 'rollback.ps1'
  @'
param([string]$Backup,[string]$Marker)
$ErrorActionPreference='Stop'
$null=& "$env:SystemRoot\System32\netsh.exe" advfirewall import $Backup
if($LASTEXITCODE -eq 0){'watchdog_imported' | Set-Content $Marker}
'@ | Set-Content -Encoding UTF8 $rollback
  $a=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$rollback+'" -Backup "'+$backup+'" -Marker "'+(Join-Path $Work 'watchdog-fired')+'"')
  $t=New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(180)
  $null=Register-ScheduledTask -TaskName $task -Action $a -Trigger $t -User 'SYSTEM' -RunLevel Highest -Force
  if(-not (Get-ScheduledTask -TaskName $task)){throw 'watchdog_not_registered'}
  @{prepared=$true;backup=$true;watchdog=$true;management_process_count=$paths.Count} | ConvertTo-Json -Compress
 } elseif($Action -eq 'Apply'){
  if(-not (Test-Path $state) -or -not (Test-Path $backup) -or -not (Get-ScheduledTask -TaskName $task)){throw 'backup_and_watchdog_required'}
  $cfg=Get-Content -Raw $Config | ConvertFrom-Json
  $ips=@($cfg.hosts.'us.version.battle.net')+@($cfg.hosts.'level3.blizzard.com') | Sort-Object -Unique
  if($ips.Count -lt 1 -or -not (Test-Path $ProxyExe)){throw 'proxy_not_prepared'}
  Get-NetFirewallRule -PolicyStore PersistentStore -Enabled True -Action Allow | Disable-NetFirewallRule
  Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultOutboundAction Block -DefaultInboundAction Block -AllowLocalFirewallRules True -DisabledInterfaceAliases @()
  $null=New-NetFirewallRule -DisplayName 'BNet G1 proxy outbound' -Group $group -Direction Outbound -Action Allow -Enabled True -Profile Any -Program $ProxyExe -Protocol TCP -RemoteAddress $ips -RemotePort 80,443
  $saved=Get-Content -Raw $state | ConvertFrom-Json
  foreach($path in @($saved.management_paths)){
   $null=New-NetFirewallRule -DisplayName ('BNet G1 management '+[IO.Path]::GetFileName($path)) -Group $group -Direction Outbound -Action Allow -Enabled True -Profile Any -Program $path
  }
  Verify-Gate | ConvertTo-Json -Compress
 } elseif($Action -eq 'Verify'){
  if(Test-Path (Join-Path $Work 'watchdog-fired')){throw 'watchdog_already_released_gate'}
  Verify-Gate | ConvertTo-Json -Compress
 } else {
  if(-not (Test-Path $backup)){throw 'restore_backup_missing'}
  $null=& "$env:SystemRoot\System32\netsh.exe" advfirewall import $backup
  if($LASTEXITCODE -ne 0){throw 'firewall_restore_import_failed'}
  $saved=Get-Content -Raw $state | ConvertFrom-Json
  $verified=(Fingerprint) -eq $saved.fingerprint
  if($verified){Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue}
  @{restored_modified_fields=$verified;import_exit_code=0} | ConvertTo-Json -Compress
 }
} catch {
 # Enum only: never export command errors, private paths, rule inventories or IPs.
 @{ok=$false;error='firewall_gate_operation_failed';action=$Action} | ConvertTo-Json -Compress
 exit 1
}
