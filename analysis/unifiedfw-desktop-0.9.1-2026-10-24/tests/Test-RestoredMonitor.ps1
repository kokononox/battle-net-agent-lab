param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $Root 'app/observe-core.ps1')
. (Join-Path $Root 'app/live-model.ps1')
$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not $Value){throw ('test_failed: '+$Name)};$script:checks++}
$flows=@{};$p=[pscustomobject]@{id=('a'*24);path='C:\Games\Same.exe'}
$proc=[pscustomobject]@{pid=10;path=$p.path;ticks='99'}
$c=[pscustomobject]@{pid=10;local_ip='10.0.0.2';local_port=40000;remote_ip='8.8.8.8';remote_port=443;state='Established'}
$null=Add-TcpFrame @($p) @($proc) @($proc) @($c) $flows 't1';Set-LivePresence $flows 't1' $true
$row=@($flows.Values)[0]
Check ($row.presence -ceq 'present') 'present-current-sample'
Check ((Get-LivePulse $null $row) -ceq 'discovery') 'new-record-discovery'
$old=[pscustomobject]@{presence='present';samples=1}
Check ((Get-LivePulse $old $row) -ceq 'none') 'same-sample-no-pulse'
$null=Add-TcpFrame @($p) @($proc) @($proc) @($c) $flows 't2';Set-LivePresence $flows 't2' $true
Check ((Get-LivePulse $old $row) -ceq 'sample') 'new-sample-pulse'
Set-LivePresence $flows 't3' $true
Check ($row.presence -ceq 'absent') 'absence-only-successful-query'
Check ((Get-LivePulse $old $row) -ceq 'none') 'absent-never-pulses'
Set-LivePresence $flows 't4' $false
Check ($row.presence -ceq 'unknown') 'query-error-unknown-not-absent'
Check ($row.samples -eq 2) 'error-does-not-invent-samples'
$absent=[pscustomobject]@{presence='absent';samples=2};$unknown=[pscustomobject]@{presence='unknown';samples=2}
$null=Add-TcpFrame @($p) @($proc) @($proc) @($c) $flows 't5';Set-LivePresence $flows 't5' $true
Check ((Get-LivePulse $absent $row) -ceq 'reappeared') 'reappearance'
Check ((Get-LivePulse $unknown $row) -ceq 'sample') 'unknown-not-false-reappearance'
# Execute new collector using local file and mocked Windows readers, not a network test.
$temp=Join-Path ([IO.Path]::GetTempPath()) ('unified-monitor-fixture-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
try{
 $exe=Join-Path $temp 'fixture.exe';[IO.File]::WriteAllText($exe,'not executed fixture')
 $hash=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
 $stop=Join-Path $temp 'stop.txt';$req=Join-Path $temp 'request.json';$out=Join-Path $temp 'capture.json';$live=Join-Path $temp 'live.json'
 $global:fixturePath=$exe;$global:fixtureStep=0;$global:fixtureStop=$stop
 function Get-Process {
  param([int]$Id)
  if($PSBoundParameters.ContainsKey('Id')){return [pscustomobject]@{Id=$Id}}
  return [pscustomobject]@{Id=123;Path=$global:fixturePath;StartTime=[DateTime]::Parse('2026-10-24T00:00:00Z')}
 }
 function Get-NetTCPConnection {
  if($global:fixtureStep -eq 1){throw 'fixture query failure'}
  return [pscustomobject]@{OwningProcess=123;LocalAddress='10.0.0.2';LocalPort=41000;RemoteAddress='8.8.8.8';RemotePort=443;State='Established'}
 }
 function Start-Sleep {param([int]$Milliseconds) $global:fixtureStep++;if($global:fixtureStep -ge 3){[IO.File]::WriteAllText($global:fixtureStop,'stop')}}
 $request=@{capture_id=('d'*32);programs=@(@{id=('a'*24);path=$exe;sha256=$hash;enabled=$true});seconds=0;parent_pid=$PID;stop_path=$stop;live_path=$live}
 [IO.File]::WriteAllText($req,(ConvertTo-Json -InputObject $request -Depth 8))
 & (Join-Path $Root 'app/live.ps1') -Request $req -Output $out
 $final=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($out));$last=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($live))
 Check ($final.schema -ceq 'unified-live-monitor-1') 'collector-schema'
 Check ($final.status -ceq 'finished' -and $final.ready) 'collector-ready-and-finished'
 Check ($final.successful_samples -eq 2 -and $final.query_errors -eq 1) 'collector-error-accounting'
 Check ($final.stop_reason -ceq 'stop_requested' -and $final.requested_seconds -eq 0) 'unbounded-stops-explicitly'
 Check (@($final.endpoints).Count -eq 1 -and $final.endpoints[0].samples -eq 2) 'collector-uses-shared-core'
 Check ($final.revision -eq $last.revision -and $final.revision -eq 5) ('atomic-final-frame-replaces-live final='+$final.revision+' live='+$last.revision)
 Check (-not $final.firewall_changed -and -not $final.hosts_changed -and -not $final.packet_drop_verified) 'readonly-no-protection-claim'
 Check ($final.publication_errors -eq 0) 'publication-no-error'
 Check (@(Get-ChildItem -LiteralPath $temp -Filter '*.next-*').Count -eq 0) 'no-stale-publication-temp'
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
# Pure UI status helper without loading WinForms.
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/ui.ps1'),[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Live-StatusText'},$true)
. ([scriptblock]::Create($node.Extent.Text))
$final.status='recording';$final.published_utc=[DateTime]::UtcNow.AddSeconds(-10).ToString('o')
Check ((Live-StatusText $final) -match 'قاب قدیمی') 'stale-status-explicit'
$final.status='finished';Check ((Live-StatusText $final) -match 'ثبت پایان') 'finished-not-live-presence'
$final.status='interrupted';Check ((Live-StatusText $final) -match 'ناقص') 'interrupted-not-success'
$result=@{suite='restored-monitor';passed=$true;assertions=$script:checks;environment='PowerShell 7 Linux; pure models and mocked Windows collectors';Windows_GUI_tested=$false;Windows_TCP_collection_tested=$false}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/restored-monitor-tests.json'),(ConvertTo-Json $result))
$result|ConvertTo-Json -Compress
