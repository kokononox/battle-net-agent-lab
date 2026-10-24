param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $Root 'app/live-evidence-model.ps1')
$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not $Value){throw ('test_failed: '+$Name)};$script:checks++}
Check (Test-MonitorCidr '8.8.8.8' '8.8.8.0/24') 'IPv4-positive'
Check (-not (Test-MonitorCidr '8.8.9.8' '8.8.8.0/24')) 'IPv4-negative'
Check (Test-MonitorCidr '2606:4700:4700::1111' '2606:4700::/32') 'IPv6-positive'
Check (-not (Test-MonitorCidr '2606:4701::1' '2606:4700::/32')) 'IPv6-negative'
Check (-not (Test-MonitorCidr '8.8.8.8' '2606:4700::/32')) 'mixed-families'
Check (-not (Test-MonitorCidr 'bad' '8.8.8.0/24')) 'malformed'
$ips=Get-MonitorResultIPs 'type: 5 cdn.example;8.8.8.8;2606:4700:4700::1111;8.8.8.8;'
Check ($ips.Count -eq 2 -and $ips -contains '8.8.8.8') 'result-IP-not-CNAME'
$p=[pscustomobject]@{id=('a'*24);path='C:\Games\Same.exe'};$p2=[pscustomobject]@{id=('b'*24);path='C:\Other\Same.exe'}
$row=[ordered]@{program_id=$p.id;program_path=$p.path;remote_ip='8.8.8.8';remote_port=443;protocol='TCP';pid=99;process_start_ticks=[DateTime]::Parse('2026-10-24T11:59:00Z').ToUniversalTime().Ticks.ToString();last_seen_utc='2026-10-24T12:01:00Z'}
$rule=[pscustomobject]@{program_id=$p.id;program=$p.path;protocol='TCP';port=443;remote_addresses=@('8.8.8.0/24')}
$inv=[pscustomobject]@{available=$true;complete=$true;checked_utc='2026-10-24T12:00:00Z';rules=@($rule)}
Check ((Get-MonitorRuleState $row $inv) -ceq 'verified_owned_block_snapshot') 'exact-rule-positive'
$row.remote_port=80;Check ((Get-MonitorRuleState $row $inv) -ceq 'no_matching_owned_block_snapshot') 'different-port-no-match'
$inv.complete=$false;Check ((Get-MonitorRuleState $row $inv) -ceq 'unknown') 'partial-not-green'
$row.remote_port=443;Check ((Get-MonitorRuleState $row $inv) -ceq 'verified_owned_block_snapshot') 'partial-positive-still-known'
$inv.available=$false;Check ((Get-MonitorRuleState $row $inv) -ceq 'unknown') 'unavailable-not-green'
$inv.available=$true;$inv.complete=$true
$e=[pscustomobject]@{kind='dns_query';program_id=$p.id;pid=99;domain='query.example';observed_utc='2026-10-24T12:00:00Z';query_results='8.8.8.8;'}
$flows=@{a=$row};Set-MonitorEvidence $flows $inv ([pscustomobject]@{events=@($e)})
Check ($row.dns_names.Count -eq 1 -and $row.dns_names[0] -ceq 'query.example') 'same-PID-IP-time-domain-link'
$e.pid=100;Set-MonitorEvidence $flows $inv ([pscustomobject]@{events=@($e)})
Check ($row.dns_names.Count -eq 0) 'different-PID-no-link'
$e.pid=99;$e.observed_utc='2026-10-24T12:02:00Z';Set-MonitorEvidence $flows $inv ([pscustomobject]@{events=@($e)})
Check ($row.dns_names.Count -eq 0) 'future-event-no-link'
$e.observed_utc='2026-10-24T11:58:00Z';Set-MonitorEvidence $flows $inv ([pscustomobject]@{events=@($e)})
Check ($row.dns_names.Count -eq 0) 'before-process-birth-no-link'
# Existing logs only. Fake Get-WinEvent fixtures, no Windows logging used or enabled.
$start=[DateTime]::Parse('2026-10-24T11:00:00Z').ToUniversalTime()
$j=[pscustomobject]@{event_programs=@([pscustomobject]@{id=$p.id;path=$p.path;device_path='\Device\HarddiskVolume1\Games\Same.exe'},[pscustomobject]@{id=$p2.id;path=$p2.path;device_path=''});hosts_baseline=[pscustomobject]@{available=$true;truncated=$false;entries=@([pscustomobject]@{domain='query.example';addresses=@('0.0.0.0','::');mapping_kind='local_sink_mapping'})}}
function New-FakeEvent([long]$Id,[string]$Provider,[string]$XML){
 $e=[pscustomobject]@{RecordId=$Id;ProviderName=$Provider;TimeCreated=[DateTime]::Parse('2026-10-24T12:00:00Z').ToUniversalTime();Xml=$XML}
 $e|Add-Member ScriptMethod ToXml {$this.Xml};return $e
}
$global:fixtureDns=@(
 (New-FakeEvent 1 'Microsoft-Windows-Sysmon' '<Event><EventData><Data Name="Image">C:\Games\Same.exe</Data><Data Name="ProcessId">99</Data><Data Name="QueryName">query.example</Data><Data Name="QueryStatus">0</Data><Data Name="QueryResults">8.8.8.8;</Data></EventData></Event>'),
 (New-FakeEvent 2 'Microsoft-Windows-Sysmon' '<Event><EventData><Data Name="Image">C:\Other\Same.exe</Data><Data Name="ProcessId">100</Data><Data Name="QueryName">other.example</Data><Data Name="QueryStatus">0</Data><Data Name="QueryResults">1.1.1.1;</Data></EventData></Event>'),
 (New-FakeEvent 3 'Microsoft-Windows-Sysmon' '<Event><EventData><Data Name="Image">C:\Unselected\Same.exe</Data><Data Name="ProcessId">99</Data><Data Name="QueryName">wrong.example</Data><Data Name="QueryResults">8.8.8.8;</Data></EventData></Event>')
)
$global:fixtureWfp=@((New-FakeEvent 10 'Microsoft-Windows-Security-Auditing' '<Event><EventData><Data Name="Application">\Device\HarddiskVolume1\Games\Same.exe</Data><Data Name="ProcessID">0x63</Data><Data Name="Direction">%%14593</Data><Data Name="Protocol">6</Data><Data Name="DestAddress">8.8.8.8</Data><Data Name="DestPort">443</Data><Data Name="FilterRTID">123</Data></EventData></Event>'))
$global:fixtureLogError=$false
function Get-WinEvent {
 param($ListLog,$FilterHashtable,$MaxEvents)
 if($ListLog){return [pscustomobject]@{IsEnabled=$true}}
 if($global:fixtureLogError){throw 'fixture read access denied'}
 if($FilterHashtable.LogName -ceq 'Security'){return $global:fixtureWfp};return $global:fixtureDns
}
. (Join-Path $Root 'app/live-events.ps1')
Update-EventEvidence $true;$ev=Event-Evidence
Check ($ev.events.Count -eq 3) 'two-program-DNS-and-exact-device-WFP'
Check (@($ev.events|Where-Object{$_.program_id -ceq $p2.id}).Count -eq 1) 'same-basename-path-attribution'
Check (@($ev.events|Where-Object{$_.kind -ceq 'wfp_connection_block' -and $_.pid -eq 99}).Count -eq 1) 'WFP-hex-PID-and-outbound'
$dnsRow=@($ev.events|Where-Object{$_.kind -ceq 'dns_query' -and $_.program_id -ceq $p.id})[0]
Check ($dnsRow.hosts_mapping -ceq 'local_sink_mapping') 'DNS-hosts-context-not-block-proof'
Check (-not $dnsRow.HTTP_request_verified -and -not $dnsRow.rule_owner_verified) 'DNS-not-HTTP-or-rule-owner'
Update-EventEvidence $true;Check ((Event-Evidence).events.Count -eq 3) 'event-IDs-deduplicated'
$global:fixtureLogError=$true;Update-EventEvidence $true;Check ((Event-Evidence).streams.dns.status -ceq 'read_failed') 'log-error-not-empty-success'
Check (-not (Event-Evidence).configuration_changed -and -not (Event-Evidence).streams.dns.coverage_verified) 'read-only-unverified-coverage'
# Snapshot admission uses protected journal + BOTH readbacks. All Windows calls mocked.
. (Join-Path $Root 'lab/session-core.ps1')
. (Join-Path $Root 'app/live-inventory.ps1')
$temp=Join-Path ([IO.Path]::GetTempPath()) ('monitor-snapshot-fixture-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $temp
try{
 [IO.File]::WriteAllText((Join-Path $temp 'session.lock'),'lock fixture')
 $script:fixtureRoot=$temp;$script:fixtureAdmin=$true;$script:fixtureActive=$true;$script:fixturePersistent=$true;$script:validatedStores=@()
 $spec=[pscustomobject]@{program_id=$p.id;program=$p.path;action='Block';direction='Outbound';interface_type='Any';protocol='TCP';port=443;remote_addresses=@('8.8.8.0/24')}
 $entry=[pscustomobject]@{name='fixture';rule=[pscustomobject]@{name='fixture';owner=('f'*32);component='blacklist';spec=$spec};removed=$false;intent=$true;enabled_image=[pscustomobject]@{fixture='sealed'}}
 $script:fixtureSession=[pscustomobject]@{owner=('f'*32);id=('e'*32);phase='applied';entries=@($entry)}
 function UAdmin {if(-not $script:fixtureAdmin){throw 'fixture not admin'}}
 function Import-Module {param($Name)}
 function USecureRoot {param([bool]$Create) if($Create){throw 'must-not-create'};return $script:fixtureRoot}
 function ULoad {param($Root) return $script:fixtureSession}
 function UReadNative {param($Name,$Store) if($Store -ceq 'PersistentStore' -and -not $script:fixturePersistent){return [pscustomobject]@{drift='changed'}};return [pscustomobject]@{fixture='sealed'}}
 function UValidateNative {param($Image,$Rule,$Session,$Store,$Enabled) if($Enabled -cne 'True'){throw 'wrong-state'};if($Store -ceq 'ActiveStore' -and -not $script:fixtureActive){throw 'fixture active missing'};$script:validatedStores+=,$Store}
 $snapshot=Get-MonitorInventory ('f'*32) @($p)
 Check ($snapshot.available -and $snapshot.complete -and $snapshot.rules.Count -eq 1) 'snapshot-positive-only-after-readbacks'
 Check ($script:validatedStores -contains 'PersistentStore' -and $script:validatedStores -contains 'ActiveStore') 'both-stores-validated'
 $script:fixtureActive=$false;$snapshot=Get-MonitorInventory ('f'*32) @($p)
 Check ($snapshot.available -and -not $snapshot.complete -and $snapshot.rules.Count -eq 0) 'active-drift-no-green'
 $script:fixtureActive=$true;$script:fixturePersistent=$false;$snapshot=Get-MonitorInventory ('f'*32) @($p)
 Check (-not $snapshot.complete -and $snapshot.rules.Count -eq 0) 'sealed-persistent-drift-no-rule'
 $script:fixturePersistent=$true;$script:fixtureAdmin=$false;$snapshot=Get-MonitorInventory ('f'*32) @($p)
 Check (-not $snapshot.available -and -not $snapshot.complete) 'no-admin-unknown'
 $script:fixtureAdmin=$true;$snapshot=Get-MonitorInventory ('1'*32) @($p)
 Check (-not $snapshot.available) 'other-owner-unknown'
 $script:fixtureSession.phase='restoring';$snapshot=Get-MonitorInventory ('f'*32) @($p)
 Check (-not $snapshot.available) 'in-progress-session-unknown'
 Check ([IO.File]::ReadAllText((Join-Path $temp 'session.lock')) -ceq 'lock fixture') 'lock-read-only-no-byte-write'
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
$result=@{suite='monitor-evidence';passed=$true;assertions=$script:checks;environment='PowerShell 7 Linux; pure models and fake log/native readers';Windows_live_tested=$false;Windows_GUI_tested=$false}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/monitor-evidence-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
