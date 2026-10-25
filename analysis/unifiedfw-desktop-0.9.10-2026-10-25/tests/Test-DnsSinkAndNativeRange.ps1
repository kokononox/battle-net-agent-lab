param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Check($b,$m){$script:checks++;if(-not $b){throw $m}}
. (Join-Path $Root 'app/live-evidence-model.ps1');. (Join-Path $Root 'app/denial-model.ps1');. (Join-Path $Root 'app/activity-model.ps1');. (Join-Path $Root 'app/activity-display-model.ps1');. (Join-Path $Root 'app/workspace-model.ps1');. (Join-Path $Root 'lab/request.ps1')
function Event($Results,$Mapping='hosts_unavailable'){[pscustomobject]@{kind='dns_query';record_id='r';program_id='p';program_path='C:\App.exe';pid=1;process_start_ticks='1';domain='a.example';query_results=$Results;dns_status='0';dns_phase='query_completed';hosts_mapping=$Mapping;hosts_addresses=@();observed_utc='2026-10-25T00:00:00Z'}}
function Row($E){$f=[pscustomobject]@{event_evidence=[pscustomobject]@{events=@($E)}};@(Get-DomainDisplayRows $f)[0]}
foreach($ip in @('0.0.0.0','::','::ffff:0:0','127.0.0.1')){$e=Event $ip;$r=Row $e;Check ($r.activity_state -ceq 'dns_sink') ('sink not recognized '+$ip);Check ($r.denied_count -eq 0) 'must not invent WFP denial';$caught=$false;try{$null=Get-ObservedDestination $ip}catch{$caught=$true};Check $caught 'sink must not transfer to endpoint blacklist'}
$r=Row (Event '::ffff:8.232.70.12');Check ($r.activity_state -ceq 'dns_answer') 'real answer not denial';Check ($r.answer_ips[0] -ceq '8.232.70.12') 'mapped IP canonical';Check ((Get-ObservedDestination '::ffff:8.232.70.12') -ceq '8.232.70.12') 'mapped transfer'
$r=Row (Event '0.0.0.0;8.8.8.8');Check ($r.activity_state -ceq 'dns_mixed') 'mixed answer not blanket block'
$r=Row (Event '8.8.8.8' 'local_sink_mapping');Check ($r.activity_state -ceq 'hosts_conflict') 'hosts configuration plus real answer not allow proof'
$e=Event '';$e.dns_phase='query_called';$r=Row $e;Check ($r.activity_state -ceq 'pending') 'query-called not connection'
Check ((Get-EvidencePulseColor 'dns') -ceq '#FBE6B7') 'DNS amber not blue';Check ((Get-EvidencePulseColor 'dns_sink') -ceq '#F4A6A6') 'sink separate red label'
foreach($p in @(1,65535,'1-65535','10000-65535')){Check (UValidBlackPort $p) ('native range reject '+$p)}
foreach($p in @($true,0,65536,'0-100','100-1','1-65536','01-100','Any')){Check (-not (UValidBlackPort $p)) ('unsafe range accepted '+$p)}
Check (Test-MonitorPort '10000-65535' 10000) 'lower boundary';Check (Test-MonitorPort '10000-65535' 65535) 'upper boundary';Check (-not (Test-MonitorPort '10000-65535' 9999)) 'below range'
$n=New-IPDraftRow @('p') '8.8.8.8' 'TCP' '10000-65535';$out=Export-IPDraft @($n);Check ($out[0].port -ceq '10000-65535') 'UI export must preserve range'
$result=@{suite='DNS-sink-and-native-port-range-regressions';passed=$true;assertions=$script:checks;Windows_GUI_executed=$false;Windows_firewall_executed=$false};[IO.File]::WriteAllText((Join-Path $Root 'evidence/dns-sink-native-range-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
