$ErrorActionPreference = 'Stop'
try {
 $j = Get-Content -LiteralPath $env:WOW_STEPS_JOURNAL -Raw | ConvertFrom-Json
 if ($j.id -notmatch '^[a-f0-9]{32}$' -or $j.name -cne ('WoWEndpointSteps-' + $j.id) -or $j.group -cne ('WoWEndpointStepsOwner-' + $j.id)) {throw 'Invalid ownership journal'}
 $rows = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object {$_.Name -ceq $j.name})
 if (@($rows | Where-Object {$_.Group -cne $j.group}).Count -gt 0) {throw 'Ownership mismatch; no deletion permitted'}
 switch ($env:WOW_STEPS_ACTION) {
  'probe' {
   $p = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
   if ($p.Count -ne 3 -or @($p | Where-Object {$_.Enabled -ne 'True'}).Count -gt 0) {throw 'All Windows Firewall profiles must already be enabled; tool will not enable them'}
   if ((Get-Service -Name MpsSvc -ErrorAction Stop).Status -ne 'Running') {throw 'Windows Firewall service is not running'}
   @{ok=$true; firewall_profiles_enabled=$true} | ConvertTo-Json -Compress
  }
  'add' {
   if ($rows.Count -ne 0) {throw 'Rule already exists; restore first'}
   if ($j.protocol -notin @('TCP','UDP') -or $j.port -lt 1 -or $j.port -gt 65535) {throw 'Invalid endpoint'}
   $ip=[System.Net.IPAddress]::Parse($j.ip)
   if ([System.IO.Path]::GetFileName($j.program) -ine 'Wow.exe' -or !(Test-Path -LiteralPath $j.program -PathType Leaf)) {throw 'Selected Wow.exe missing'}
   New-NetFirewallRule -PolicyStore PersistentStore -Name $j.name -DisplayName $j.name -Group $j.group -Direction Outbound -Action Block -Enabled True -Profile Any -Program $j.program -Protocol $j.protocol -RemoteAddress $j.ip -RemotePort $j.port -ErrorAction Stop | Out-Null
   $r=Get-NetFirewallRule -PolicyStore PersistentStore -Name $j.name -ErrorAction Stop
   $a=$r | Get-NetFirewallApplicationFilter -ErrorAction Stop
   $d=$r | Get-NetFirewallAddressFilter -ErrorAction Stop
   $p=$r | Get-NetFirewallPortFilter -ErrorAction Stop
   $expected=if ($j.protocol -eq 'TCP') {6} else {17}
   if ($r.Group -cne $j.group -or $r.Enabled -ne 'True' -or $r.Action -ne 'Block' -or $r.Direction -ne 'Outbound' -or $a.Program -ine $j.program -or @($d.RemoteAddress).Count -ne 1 -or $d.RemoteAddress[0] -ne $j.ip -or [string]$p.Protocol -notin @([string]$expected,$j.protocol) -or [string]$p.RemotePort -ne [string]$j.port) {throw 'Persistent rule readback mismatch'}
   $active=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {$_.Name -ceq $j.name -and $_.Group -ceq $j.group -and $_.Enabled -eq 'True' -and $_.Action -eq 'Block' -and $_.Direction -eq 'Outbound'})
   if ($active.Count -ne 1) {throw 'Rule not found enabled in effective policy'}
   @{ok=$true;present=$true;rule_config_verified=$true;packet_block_verified=$false} | ConvertTo-Json -Compress
  }
  'remove' {
   foreach ($r in $rows) {$r | Remove-NetFirewallRule -ErrorAction Stop}
   $remain=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object {$_.Name -ceq $j.name})
   $active=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {$_.Name -ceq $j.name})
   if ($remain.Count -gt 0 -or $active.Count -gt 0) {throw 'Rule absence not confirmed'}
   @{ok=$true;present=$false} | ConvertTo-Json -Compress
  }
  default {throw 'Invalid operation'}
 }
} catch {
 # Error text stays local, never exported to the shareable report.
 [Console]::Error.WriteLine($_.Exception.Message)
 exit 3
}
