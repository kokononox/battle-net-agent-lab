param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Check($b,$m){$script:checks++;if(-not $b){throw $m}}
function Fails($block,$m){$caught=$false;try{& $block|Out-Null}catch{$caught=$true};Check $caught $m}
. (Join-Path $Root 'app/live-evidence-model.ps1');. (Join-Path $Root 'app/activity-model.ps1');. (Join-Path $Root 'app/workspace-model.ps1');. (Join-Path $Root 'app/package-model.ps1')
function Dns($Id,$Path,$PidText,$Birth,$IP){[pscustomobject]@{kind='dns_query';record_id=$Id;program_id=$Path;program_path=$Path;pid=$PidText;process_start_ticks=$Birth;domain='Telemetry-In.Battle.net.';query_results=$IP;observed_utc='2026-10-25T00:00:00Z'}}
function Tcp($Id,$Path,$PidText,$Birth,$IP){[pscustomobject]@{record_id=$Id;program_id=$Path;program_path=$Path;pid=$PidText;process_start_ticks=$Birth;remote_ip=$IP;remote_port=443;protocol='TCP';samples=2;last_seen_utc='2026-10-25T00:00:01Z'}}
function Frame($Events,$Flows){[pscustomobject]@{event_evidence=[pscustomobject]@{events=@($Events)};endpoints=@($Flows);processes=@()}}
$a=Dns 'd1' 'C:\Agent.exe' 1 '100' '8.8.8.8';$b=Dns 'd2' 'C:\Setup.exe' 2 '200' '1.1.1.1';$c=Dns 'd3' 'C:\Agent.exe' 3 '300' '8.8.8.8'
$f=Frame @($a,$a,$b,$c) @();$packages=@(Get-ActivityPackages $f);Check ($packages.Count -eq 1) 'one domain across EXEs';$p=$packages[0];Check ($p.domain -ceq 'telemetry-in.battle.net') 'normalized exact domain';Check ($p.routes.Count -eq 2) 'repeat route collapsed';Check ($p.paths.Count -eq 2) 'exact EXE paths retained';Check ($p.dns_count -eq 3) 'duplicate event not counted';Check ($p.routes[0].identities.Count -ge 1) 'birth/source details retained'
$progs=@([pscustomobject]@{id='a';path='C:\Agent.exe'},[pscustomobject]@{id='b';path='C:\Setup.exe'})
Fails {New-PackageTransferPlan $p $p.routes $progs blacklist '' 0 0} 'DNS route must not guess 443'
$plan=New-PackageTransferPlan $p $p.routes $progs blacklist TCP 10000 65535;Check ($plan.black.Count -eq 2) 'all routes staged';Check ($plan.black[0].port -ceq '10000-65535') 'compact native range';Check (-not $plan.saved -and -not $plan.applied -and -not $plan.future_addresses_covered) 'no IO/future claims';Check (($plan.black|Where-Object{$_.program_ids[0] -ceq 'a'}).Count -eq 1) 'exact binding'
$plan=New-PackageTransferPlan $p @($p.routes[0]) $progs blacklist Any 0 0;Check ($plan.black.Count -eq 2) 'Any TCP UDP only explicit';Check ($plan.black[0].port -ceq '1-65535') 'all ports compact'
$plan=New-PackageTransferPlan $p $p.routes $progs whitelist Any 0 0;Check ($plan.white.Count -eq 2) 'whitelist batch';Check ($plan.white[0].value.EndsWith('|ANY|*')) 'explicit global Any'
$plan=New-PackageTransferPlan $p @() @() hosts '' 0 0;Check ($plan.hosts.Count -eq 1 -and $plan.hosts[0].domain -ceq 'telemetry-in.battle.net') 'domain hosts once'
Fails {New-PackageTransferPlan $p $p.routes @($progs[0]) blacklist TCP 443 443} 'unregistered EXE whole plan fails'
$bad=$p.routes[0].PSObject.Copy();$bad.ip='9.9.9.9';Fails {New-PackageTransferPlan $p @($bad) $progs blacklist TCP 443 443} 'foreign/tampered route rejected'
$f=Frame @($a) @((Tcp 't1' 'C:\Agent.exe' 1 '100' '8.8.8.8'));$p=@(Get-ActivityPackages $f)[0];Check ($p.routes.Count -eq 1) 'DNS unknown replaced by observed transport';Check ($p.routes[0].protocol -ceq 'TCP' -and $p.routes[0].port -eq 443) 'observed port retained';Check ($p.routes[0].identities.Count -eq 2) 'DNS and TCP evidence source separated'
$plan=New-PackageTransferPlan $p $p.routes $progs blacklist '' 0 0;Check ($plan.black[0].port -eq 443) 'known port no user guess'
$f=Frame @($a) @((Tcp 't1' 'C:\Agent.exe' 1 '999' '8.8.8.8'));$ps=@(Get-ActivityPackages $f);Check ($ps.Count -eq 2) 'reused PID/birth must not correlate'
$t=Tcp 't1' 'C:\Agent.exe' 1 '100' '8.8.8.8';$t.last_seen_utc='2026-10-24T23:00:00Z';Check (@(Get-ActivityPackages (Frame @($a) @($t))).Count -eq 2) 'future DNS cannot label earlier socket'
$f=Frame @((Dns 'sink' 'C:\Agent.exe' 1 '100' '0.0.0.0;::;::ffff:0:0')) @();$p=@(Get-ActivityPackages $f)[0];Check ($p.routes.Count -eq 0 -and $p.sink_count -eq 1) 'sink not external route';Check ($p.denied_count -eq 0) 'sink not WFP proof';$plan=New-PackageTransferPlan $p @() @() hosts '' 0 0;Check ($plan.hosts.Count -eq 1) 'sink domain still actionable'
$ui=[IO.File]::ReadAllText((Join-Path $Root 'app/ui-packages.ps1'));Check ($ui.Contains('CheckOnClick=$true')) 'single click checks';Check ($ui.Contains('$d.AcceptButton=$cancel')) 'safe cancel default';Check ($ui.IndexOf('$newBlack=Merge-IPDraft') -lt $ui.IndexOf('$script:ipDraft=$newBlack')) 'all merges before assignment';Check ($ui.Contains('script:job.action')) 'backend operation guard'
Check ((Get-PackagePulse $null $p) -ceq 'dns_sink') 'package sink pulse red with separate reason'
Check ((Get-PackagePulse $p $p) -ceq 'none') 'no repeat pulse without activity'
Check (-not $ui.Contains('$packageGrid.Rows.Clear()')) 'stable rows retain pulses across refresh'
$main=[IO.File]::ReadAllText((Join-Path $Root 'app/ui.ps1'));Check (-not $main.Contains('Kill-switch پیاده نشده')) 'remove outdated kill-switch claim'
$result=@{suite='activity-packages';passed=$true;assertions=$script:checks;Windows_GUI_executed=$false;Windows_firewall_executed=$false};[IO.File]::WriteAllText((Join-Path $Root 'evidence/activity-packages-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
