param([string]$Root=(Join-Path $PSScriptRoot '..'),[string]$FixtureOutput='')
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not $Value){throw ('test_failed: '+$Name)};$script:checks++}
. (Join-Path $Root 'app/baseline-model.ps1')
$script:baselineCutoff=[DateTime]::UtcNow.AddMinutes(-1).Ticks;$script:newProcesses=@{};$script:autoPrograms=@{};$script:baselineTruncated=$false
$birth=($script:baselineCutoff+10000).ToString();$at=[DateTime]::UtcNow.ToString('o')
Check (-not (Test-NewProcessBirth $script:baselineCutoff.ToString() $script:baselineCutoff)) 'cutoff-equality-excluded'
Check (-not (Test-NewProcessBirth ($script:baselineCutoff-1).ToString() $script:baselineCutoff)) 'old-instance-excluded'
Check (Test-NewProcessBirth $birth $script:baselineCutoff) 'new-birth-included'
Check (-not (Test-NewProcessBirth 'bad' $script:baselineCutoff)) 'unreadable-birth-excluded'
Check ($null -eq (Register-NewProcess 7 ($script:baselineCutoff-1).ToString() 'C:\Apps\Game.exe' $at 'fixture')) 'baseline-process-never-registered'
$a=Register-NewProcess 7 $birth 'C:\Apps\Game.exe' $at 'fixture';Check ($null -ne $a) 'new-instance-registered-for-observation'
Check (-not $a.registered_for_firewall -and -not $a.hash_verified) 'discovery-not-native-registration'
$b=Register-NewProcess 7 ([long]$birth+1).ToString() 'C:\Apps\Game.exe' $at 'fixture';Check ($a.record_id -cne $b.record_id) 'PID-reuse-new-instance'
Check ($a.program_id -ceq $b.program_id) 'same-path-shares-display-program'
$c=Register-NewProcess 8 $birth 'C:\Other\Game.exe' $at 'fixture';Check ($a.program_id -cne $c.program_id) 'same-basename-distinct-path'
Check ($null -eq (Register-NewProcess 7 $birth 'C:\Different\Game.exe' $at 'fixture')) 'same-PID-birth-path-drift-rejected'
Check ($null -eq (Register-NewProcess 9 $birth '' $at 'fixture')) 'missing-path-no-guess'
$rows=@([pscustomobject]@{pid=7;path='C:\Apps\Game.exe';ticks=$birth})
$accepted=Add-NewProcessSnapshot $rows $at $true;Check ($accepted.Count -eq 1) 'snapshot-new-only'
Check ($a.presence -ceq 'present') 'sample-presence'
$null=Add-NewProcessSnapshot @() $at $false;Check ($a.presence -ceq 'unknown') 'read-error-not-exit'
$null=Add-NewProcessSnapshot @() $at $true;Check ($a.presence -ceq 'not_in_latest_snapshot') 'absence-not-termination-proof'
Add-Type -Path (Join-Path $Root 'app/dns-trace.cs')
Check ([UnifiedDns.Collector]::IsNewProcess(101,100)) 'CSharp-new-process-gate'
Check (-not [UnifiedDns.Collector]::IsNewProcess(100,100)) 'CSharp-baseline-equality-excluded'
$test=New-Object UnifiedDns.Collector(('a'*32),('b'*32),([guid]::NewGuid().ToString()),100L)
Check (-not $test.Running) 'baseline-constructor-no-native-start';$test.Dispose()
# Exercise shared DNS adapter with an unregistered new process, without invoking ETW.
$j=[pscustomobject]@{observation_mode='new_processes';event_programs=@();hosts_baseline=[pscustomobject]@{available=$false};dns_etw_requested=$false}
$start=New-Object DateTime($script:baselineCutoff,[DateTimeKind]::Utc);$script:eventRows=New-Object Collections.Generic.List[object];$script:eventTruncated=$false;$script:hostsByName=@{}
. (Join-Path $Root 'app/live-dns.ps1')
$q=[pscustomobject]@{domain='query.example';program_id='';program_path='C:\New\Helper.exe';observed_utc=$at;process_start_ticks=$birth;pid=22;event_id=3006;sequence=1;status='pending';results=''}
Add-DnsTraceQuery $q
Check ($script:eventRows.Count -eq 1) 'dynamic-DNS-without-saved-EXE'
Check ($q.program_id.Length -eq 24) 'dynamic-DNS-assigned-observation-id'
Check ($script:eventRows[0].source -ceq 'DNSClient_ETW') 'dynamic-DNS-source'
$q.pid=23;$q.process_start_ticks=($script:baselineCutoff-1).ToString();Add-DnsTraceQuery $q
Check ($script:eventRows.Count -eq 1) 'old-process-DNS-excluded'
# Execute actual new-process collector against fake OS readers; no process/network/policy changed.
$temp=Join-Path ([IO.Path]::GetTempPath()) ('baseline-fixture-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $temp
try{
 $req=Join-Path $temp 'request.json';$out=Join-Path $temp 'capture.json';$stop=Join-Path $temp 'stop.txt';$global:fixtureStop=$stop;$global:fixtureCalls=0;$global:fixtureBirth=$null
 $request=@{owner=('a'*32);capture_id=('c'*32);observation_mode='new_processes';programs=@();event_programs=@();hosts_baseline=@{available=$false;entries=@();truncated=$false};dns_etw_requested=$false;inventory_path=(Join-Path $temp 'absent.json');seconds=30;stop_path=$stop;live_path=(Join-Path $temp 'live.json');parent_pid=9999}
 [IO.File]::WriteAllText($req,(ConvertTo-Json $request -Depth 8))
 function Get-Process {param($Id,$ErrorAction)
  if($PSBoundParameters.ContainsKey('Id')){return [pscustomobject]@{Id=$Id}}
  $global:fixtureCalls++
  $old=[pscustomobject]@{Id=100;Path='C:\Existing\Old.exe';StartTime=[DateTime]::UtcNow.AddHours(-1)}
  if($global:fixtureCalls -le 1){return $old}
  if($null -eq $global:fixtureBirth){$global:fixtureBirth=[DateTime]::UtcNow}
  return @($old,[pscustomobject]@{Id=200;Path='C:\Games\New.exe';StartTime=$global:fixtureBirth})
 }
 $global:tcpCalls=0
 function Get-NetTCPConnection {param($ErrorAction)
  $global:tcpCalls++;if($global:tcpCalls -ge 2){[IO.File]::WriteAllText($global:fixtureStop,'stop')}
  return @([pscustomobject]@{OwningProcess=200;LocalAddress='10.0.0.2';LocalPort=50000;RemoteAddress='8.8.8.8';RemotePort=443;State='Established'},[pscustomobject]@{OwningProcess=100;LocalAddress='10.0.0.2';LocalPort=50001;RemoteAddress='1.1.1.1';RemotePort=443;State='Established'})
 }
 & (Join-Path $Root 'app/baseline.ps1') -Request $req -Output $out
 $c=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($out))
 Check ($c.schema -ceq 'unified-new-process-monitor-1') 'separate-schema'
 Check ($c.baseline_existing_count -eq 1) 'existing-count'
 Check (@($c.processes).Count -eq 1 -and $c.processes[0].pid -eq 200) 'only-new-process-in-capture'
 Check (@($c.endpoints).Count -eq 1 -and $c.endpoints[0].pid -eq 200) 'old-process-TCP-excluded'
 Check (-not $c.firewall_changed -and -not $c.hosts_changed) 'observation-no-mutation'
 Check ($c.dns_events_collected -eq $false) 'no-fake-DNS'
 Check ($c.stop_reason -ceq 'stop_requested') 'normal-stop'
 Check ($c.status -ceq 'finished') 'final-capture'
 if($FixtureOutput){[IO.File]::WriteAllText($FixtureOutput,[IO.File]::ReadAllText($out))}
}catch{$_.ScriptStackTrace|Write-Host;throw}finally{Remove-Item $temp -Recurse -Force}
$result=@{suite='baseline-new-process-discovery';passed=$true;assertions=$script:checks;Windows_live_tested=$false;Windows_GUI_tested=$false;environment='PowerShell 7 Linux; identity models and mocked process/TCP readers; C# gate compiled only'}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/baseline-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
