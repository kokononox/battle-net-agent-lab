param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not $Value){throw ('test_failed: '+$Name)};$script:checks++}
Add-Type -Path (Join-Path $Root 'app/dns-trace.cs')
$layout=[UnifiedDns.Collector]::Layout();$expected=@(48,120,80,112,88,280,448,424)
for($i=0;$i -lt $expected.Count;$i++){Check ($layout[$i] -eq $expected[$i]) ('x64-layout-'+$i)}
$provider=[guid]'1c95126e-7eea-49a9-a3fe-a378b03ddb4d'
Check ([UnifiedDns.Collector]::Eligible(3006,$provider)) 'dns-query-called'
Check ([UnifiedDns.Collector]::Eligible(3008,$provider)) 'dns-query-completed'
Check (-not [UnifiedDns.Collector]::Eligible(3006,[guid]::Empty)) 'provider-exact'
Check (-not [UnifiedDns.Collector]::Eligible(3010,$provider)) 'event-id-exact'
$collector=New-Object UnifiedDns.Collector(('a'*32),('b'*32),([guid]::NewGuid().ToString()),[string[]]@('C:\Games\Game.exe'),[string[]]@('c'*24))
Check ($collector.SessionName -ceq ('UnifiedFW-DNS-'+('b'*32)+'-'+('a'*32))) 'owned-name'
Check (-not $collector.Running) 'constructor-no-start'
Check ($collector.Drain().Count -eq 0) 'initial-queue-empty'
$collector.Dispose();Check ($collector.StopStatus -eq 0) 'dispose-unstarted-no-native-call'
$threw=$false;try{[UnifiedDns.Collector]::Cleanup('arbitrary-other-session',[guid]::NewGuid().ToString())}catch{$threw=$true};Check $threw 'recovery-refuses-other-names-before-native-api'
$j=[pscustomobject]@{event_programs=@([pscustomobject]@{id=('c'*24);path='C:\Games\Game.exe'});hosts_baseline=[pscustomobject]@{available=$false}}
$start=[DateTime]::Parse('2026-10-24T12:00:00Z').ToUniversalTime();$script:eventRows=New-Object Collections.Generic.List[object];$script:eventTruncated=$false;$script:hostsByName=@{}
. (Join-Path $Root 'app/live-dns.ps1');Start-DnsTrace
Check ($script:dnsState.status -ceq 'not_requested') 'no-consent-no-native-start'
$q=[pscustomobject]@{domain='query.example';program_id=('c'*24);program_path='C:\Games\Game.exe';observed_utc='2026-10-24T12:00:01Z';process_start_ticks=($start.AddSeconds(-2).Ticks.ToString());pid=1234;event_id=3006;sequence=1;status='pending';results=''}
Add-DnsTraceQuery $q
Check ($script:eventRows.Count -eq 1) 'query-with-exact-path'
Check ($script:eventRows[0].source -ceq 'DNSClient_ETW') 'not-labelled-sysmon'
Check ($script:eventRows[0].dns_phase -ceq 'query_called') 'query-pending-visible'
$q.event_id=3008;$q.status='0';$q.results='8.8.8.8;';Add-DnsTraceQuery $q
Check ($script:eventRows.Count -eq 2 -and $script:eventRows[1].dns_phase -ceq 'query_completed') 'completion-visible'
$q.program_path='C:\Other\Game.exe';Add-DnsTraceQuery $q;Check ($script:eventRows.Count -eq 2) 'same-basename-not-selected'
$q.program_path='C:\Games\Game.exe';$q.process_start_ticks=$start.AddMinutes(1).Ticks.ToString();Add-DnsTraceQuery $q;Check ($script:eventRows.Count -eq 2) 'birth-after-event-rejected'
$q.process_start_ticks=$start.AddSeconds(-2).Ticks.ToString();$q.observed_utc='2026-10-24T11:59:59Z';Add-DnsTraceQuery $q;Check ($script:eventRows.Count -eq 2) 'before-start-rejected'
# Run the actual UI pulse functions against fake rows. No WinForms or native Windows invoked.
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/ui-evidence.ps1'),[ref]$tokens,[ref]$errors)
foreach($name in @('Apply-PulseCell','Expire-LivePulses')){$f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true);. ([scriptblock]::Create($f.Extent.Text))}
$base=[Drawing.ColorTranslator]::FromHtml('#FCE9E7');$selection=[Drawing.ColorTranslator]::FromHtml('#EAD7D5');$ink=[Drawing.Color]::Black
$row=[pscustomobject]@{Cells=@{pulse=[pscustomobject]@{Value='';Style=[pscustomobject]@{BackColor=[Drawing.Color]::Empty;ForeColor=$ink};Tag=$null};rule=[pscustomobject]@{Style=[pscustomobject]@{BackColor=$base}}};DefaultCellStyle=[pscustomobject]@{BackColor=$base;SelectionBackColor=$selection}}
Apply-PulseCell $row 'dns' $true;Check ($row.DefaultCellStyle.BackColor -ne $base) 'whole-row-flash'
Check ($row.Cells['rule'].Style.BackColor -eq $base) 'rule-cell-color-preserved'
$flash=[pscustomobject]@{Checked=$false};$liveGrid=[pscustomobject]@{Rows=@($row)};$popupGrid=$liveGrid;$domainMain=$liveGrid;$domainPopup=$liveGrid
Expire-LivePulses;Check ($row.DefaultCellStyle.BackColor -eq $base) 'base-color-restored'
Check ($row.DefaultCellStyle.SelectionBackColor -eq $selection) 'selection-color-restored'
Check ($null -eq $row.Cells['pulse'].Tag) 'pulse-state-cleared'
Apply-PulseCell $row 'sample' $false;Check ($row.DefaultCellStyle.BackColor -eq $base) 'disabled-flash-does-not-erase-state'
$result=@{suite='DNS-trace-ABI-models-and-row-pulses';passed=$true;assertions=$script:checks;CSharp_compiled=$true;x64_struct_layout_verified=$true;Windows_ETW_executed=$false;Windows_GUI_executed=$false;environment='PowerShell 7 Linux, C# compile and fake evidence/row models only'}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/dns-trace-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
