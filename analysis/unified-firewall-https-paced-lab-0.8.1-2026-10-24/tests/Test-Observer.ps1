param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $Root 'app/observe-core.ps1')
$script:checks=0
function Check([bool]$Condition,[string]$Name){if(-not $Condition){throw ('test_failed: '+$Name)};$script:checks++}
$p1=[pscustomobject]@{id=('a'*24);path='C:\Games\Wow.exe'};$p2=[pscustomobject]@{id=('b'*24);path='C:\Agent\Agent.exe'}
$b1=[pscustomobject]@{pid=10;path=$p1.path;ticks='100'};$b2=[pscustomobject]@{pid=20;path=$p2.path;ticks='200'}
$c1=[pscustomobject]@{pid=10;local_ip='10.0.0.2';local_port=40000;remote_ip='8.8.8.8';remote_port=443;state='Established'}
$c2=[pscustomobject]@{pid=20;local_ip='10.0.0.2';local_port=40001;remote_ip='8.8.8.8';remote_port=443;state='Established'}
$flows=@{};$null=Add-TcpFrame @($p1,$p2) @($b1,$b2) @($b1,$b2) @($c1,$c2) $flows '2026-10-24T00:00:00Z'
Check ($flows.Count -eq 2) 'same-endpoint-different-programs-separated'
Check (@($flows.Values|ForEach-Object{$_.program_id}|Sort-Object -Unique).Count -eq 2) 'program-identities-preserved'
$null=Add-TcpFrame @($p1,$p2) @($b1,$b2) @($b1,$b2) @($c1,$c2) $flows '2026-10-24T00:00:01Z'
foreach($row in $flows.Values){Check ($row.samples -eq 2) 'repeated-sample-not-new-flow'}
$changed=[pscustomobject]@{pid=10;path=$p1.path;ticks='999'}
$flows=@{};$null=Add-TcpFrame @($p1) @($b1) @($changed) @($c1) $flows 'x'
Check ($flows.Count -eq 0) 'pid-reuse-during-frame-rejected'
$changed=[pscustomobject]@{pid=10;path='C:\Other\Wow.exe';ticks='100'}
$null=Add-TcpFrame @($p1) @($b1) @($changed) @($c1) $flows 'x'
Check ($flows.Count -eq 0) 'same-basename-different-path-rejected'
$null=Add-TcpFrame @($p1) @($b2) @($b2) @($c2) $flows 'x'
Check ($flows.Count -eq 0) 'unselected-program-rejected'
$flows=@{};$second=[pscustomobject]@{pid=11;path=$p1.path;ticks='101'};$otherConn=[pscustomobject]@{pid=11;local_ip='10.0.0.2';local_port=40002;remote_ip='8.8.8.8';remote_port=443;state='SynSent'}
$null=Add-TcpFrame @($p1) @($b1,$second) @($b1,$second) @($c1,$otherConn) $flows 'x'
Check ($flows.Count -eq 2) 'two-instances-same-exe-separated'
$flows=@{};$newPort=[pscustomobject]@{pid=10;local_ip='10.0.0.2';local_port=40003;remote_ip='8.8.8.8';remote_port=443;state='Established'}
$null=Add-TcpFrame @($p1) @($b1) @($b1) @($c1,$newPort) $flows 'x'
Check ($flows.Count -eq 2) 'different-local-sockets-separated'
$flows=@{};$cap=Add-TcpFrame @($p1,$p2) @($b1,$b2) @($b1,$b2) @($c1,$c2) $flows 'x' 1
Check ($cap -and $flows.Count -eq 1) 'bounded-output-reports-truncation'
$lower=[pscustomobject]@{pid=10;path='c:\games\WOW.EXE';ticks='100'}
$flows=@{};$null=Add-TcpFrame @($p1) @($lower) @($lower) @($c1) $flows 'x'
Check ($flows.Count -eq 1) 'case-insensitive-path-match'
$flows=@{};$null=Add-TcpFrame @($p1) @($b1) @($b1) @($c1,$c1) $flows 'x'
Check ($flows.Count -eq 1 -and @($flows.Values)[0].samples -eq 1) 'duplicate-row-not-two-samples'
$result=[pscustomobject]@{suite='multi-program-frame-matching';assertions=$script:checks;passed=$true;runtime=$PSVersionTable.PSVersion.ToString();fixture_only=$true;live_windows_observation_tested=$false}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/observer-tests.json'),(ConvertTo-Json $result))
$result|ConvertTo-Json -Compress
