param([ValidateSet('Prepare','Apply','Verify','Restore')][string]$Action,[string]$Work)
$ErrorActionPreference='Stop';$c=Get-Content -Raw (Join-Path $Work 'config.json') | ConvertFrom-Json;$group='BNet-Online-G27'
function Fingerprint{
 $p=@(Get-NetFirewallProfile -PolicyStore PersistentStore | Sort-Object Name | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowLocalFirewallRules,DisabledInterfaceAliases)
 $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore | Sort-Object Name | Select-Object Name,Enabled,Direction,Action,Profile)
 $bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Depth 6 -Compress -InputObject @{profiles=$p;rules=$rules}));$h=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($h.ComputeHash($bytes))}finally{$h.Dispose()}
}
function Verify{
 $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore)
 if($profiles.Count -ne 3 -or @($profiles | Where-Object {$_.Enabled -ne 'True' -or $_.DefaultOutboundAction -ne 'Block' -or @($_.DisabledInterfaceAliases | Where-Object {$_ -and $_ -ne 'NotConfigured'}).Count -gt 0}).Count -gt 0){throw 'profiles_not_enforced'}
 $saved=Get-Content -Raw (Join-Path $Work 'gate-state.json') | ConvertFrom-Json;$allows=@(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Action Allow)
 if($allows.Count -ne (@($saved.management_paths).Count+2)){throw 'unexpected_allow_count'}
 $management=@($allows | Where-Object {$_.DisplayName -like 'BNet G27 management *'})
 if($management.Count -ne @($saved.management_paths).Count){throw 'management_rule_count'}
 foreach($r in $management){$program=[string](($r | Get-NetFirewallApplicationFilter).Program);if($r.Group -ne $group -or $r.Direction -ne 'Outbound' -or $program -notin @($saved.management_paths)){throw 'unexpected_allow_rule'}}
 foreach($name in @('web','version')){
  $rule=@($allows | Where-Object {$_.DisplayName -eq ('BNet G27 proxy '+$name)})
  if($rule.Count -ne 1 -or $rule[0].Group -ne $group -or $rule[0].Direction -ne 'Outbound' -or [string](($rule | Get-NetFirewallApplicationFilter).Program) -ne $c.proxy_exe){throw 'proxy_rule_identity'}
  $port=$rule | Get-NetFirewallPortFilter;$expectedPorts=if($name -eq 'web'){'443,80'}else{'1119'}
  if($port.Protocol -ne 'TCP' -or ((@($port.RemotePort) | Sort-Object)-join ',') -ne $expectedPorts){throw 'proxy_ports'}
  $wanted=if($name -eq 'web'){@($c.hosts.'level3.blizzard.com')+@($c.hosts.'us.version.battle.net')}else{@($c.hosts.'us.version.battle.net')}
  $actual=@(($rule | Get-NetFirewallAddressFilter).RemoteAddress) | Sort-Object -Unique
  if(((@($wanted) | Sort-Object -Unique)-join ',') -ne ($actual-join ',')){throw 'proxy_addresses'}
 }
 return @{verified=$true;profiles=3;target_allow_rules=0;proxy_allow_rules=2;management_allow_rules=$management.Count}

}
try{
 if($Action -eq 'Prepare'){
  if((Get-Service mpssvc).Status -ne 'Running'){throw 'firewall_service_not_running'}
  if(Test-Path (Join-Path $Work 'before.wfw')){throw 'backup_already_exists'}
  $null=& "$env:SystemRoot\System32\netsh.exe" advfirewall export (Join-Path $Work 'before.wfw');if($LASTEXITCODE -ne 0){throw 'backup_failed'}
  $paths=@(Get-Process -Name 'Runner.Listener','Runner.Worker' -ErrorAction SilentlyContinue | ForEach-Object {$_.Path} | Sort-Object -Unique)
  if($paths.Count -lt 1 -or $paths.Count -gt 4 -or @($paths | Where-Object {$_ -notmatch '(?i)\\bin\\Runner\.(Listener|Worker)\.exe$'}).Count -gt 0){throw 'management_identity_refused'}
  if(-not (Get-ScheduledTask -TaskName $c.watchdog_name)){throw 'watchdog_missing'}
  @{fingerprint=(Fingerprint);management_paths=$paths} | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Work 'gate-state.json') -Encoding UTF8
  @{prepared=$true} | ConvertTo-Json -Compress
 }elseif($Action -eq 'Apply'){
  $saved=Get-Content -Raw (Join-Path $Work 'gate-state.json') | ConvertFrom-Json
  Get-NetFirewallRule -PolicyStore PersistentStore -Enabled True -Action Allow | Disable-NetFirewallRule
  Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultOutboundAction Block -DefaultInboundAction Block -AllowLocalFirewallRules True -DisabledInterfaceAliases @()
  foreach($path in @($saved.management_paths)){$null=New-NetFirewallRule -DisplayName ('BNet G27 management '+[IO.Path]::GetFileName($path)) -Group $group -Direction Outbound -Action Allow -Enabled True -Profile Any -Program $path}
  $ips=@($c.hosts.'level3.blizzard.com')+@($c.hosts.'us.version.battle.net') | Sort-Object -Unique
  if(-not (Test-Path $c.proxy_exe) -or $ips.Count -lt 1){throw 'proxy_not_prepared'}
  $null=New-NetFirewallRule -DisplayName 'BNet G27 proxy web' -Group $group -Direction Outbound -Action Allow -Enabled True -Profile Any -Program $c.proxy_exe -Protocol TCP -RemoteAddress $ips -RemotePort 80,443
  $null=New-NetFirewallRule -DisplayName 'BNet G27 proxy version' -Group $group -Direction Outbound -Action Allow -Enabled True -Profile Any -Program $c.proxy_exe -Protocol TCP -RemoteAddress @($c.hosts.'us.version.battle.net') -RemotePort 1119
  Verify | ConvertTo-Json -Compress
 }elseif($Action -eq 'Verify'){Verify | ConvertTo-Json -Compress}else{
  $proof=Get-Content -Raw (Join-Path $Work 'ended-proof.json') | ConvertFrom-Json
  if($proof.verified -ne $true){throw 'component_exit_not_verified'}
  $null=& "$env:SystemRoot\System32\netsh.exe" advfirewall import (Join-Path $Work 'before.wfw');if($LASTEXITCODE -ne 0){throw 'restore_import_failed'}
  $saved=Get-Content -Raw (Join-Path $Work 'gate-state.json') | ConvertFrom-Json
  @{restored=((Fingerprint) -eq $saved.fingerprint)} | ConvertTo-Json -Compress
 }
}catch{$m=$_.Exception.Message;if($m -notmatch '^[a-z_]{1,80}$'){$m='operation_failed'};@{error_code=$m} | ConvertTo-Json -Compress;exit 1}
