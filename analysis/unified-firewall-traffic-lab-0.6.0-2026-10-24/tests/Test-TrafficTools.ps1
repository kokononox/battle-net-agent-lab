param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $Root 'lab/session-core.ps1')
. (Join-Path $Root 'lab/native.ps1')
. (Join-Path $Root 'lab/traffic-tools.ps1')
$script:checks=0
function Check([bool]$ok,[string]$why){$script:checks++;if(-not $ok){throw ('traffic_assertion:'+ $why)}}
function Throws([scriptblock]$body){$caught=$false;try{& $body|Out-Null}catch{$caught=$true};Check $caught 'expected_rejection'}
foreach($ip in @('8.8.8.8','1.1.1.1','9.9.9.9')){TAssertPublicIPv4 $ip;Check $true 'public_literal'}
foreach($ip in @('127.0.0.1','10.0.0.1','192.168.1.1','169.254.1.1','100.64.0.1','203.0.113.1','224.0.0.1','0.0.0.0','::1','example.com')){Throws {TAssertPublicIPv4 $ip}}
$ids=@{};foreach($role in @('A','B','REF')){for($i=0;$i -lt 8;$i++){$q=TChallenge $role;Check ($q.role -ceq $role -and $q.nonce -cmatch '^[a-f0-9]{64}$' -and $q.request_id -cmatch '^[a-f0-9]{32}$') 'bounded_challenge';Check (-not $ids.ContainsKey($q.request_id)) 'unique_request';$ids[$q.request_id]=$true}}
# Test matrix assembly with child/network doubles. These are not Windows firewall tests.
function Get-FileHash{param($LiteralPath,$Algorithm,$ErrorAction) [pscustomobject]@{Hash=('A'*64)}}
function TRunProcess{param($Exe,$Script,$Request,$Output) $q=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Request));[pscustomobject]@{probe_valid=$true;role=$q.challenge.role;request_id=$q.challenge.request_id;connected=$true;handshake_ok=$true}}
function TReference{param($Address,$Port,$Challenge) [pscustomobject]@{probe_valid=$true;role='REF';request_id=$Challenge.request_id;connected=$true;handshake_ok=$true}}
$dir=Join-Path ([IO.Path]::GetTempPath()) ('TrafficTools-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($dir)
try{
 $q=[pscustomobject]@{address='8.8.8.8';port=39443;programs=@([pscustomobject]@{role='A';path='C:\Fixture\python.exe';sha256=('a'*64)},[pscustomobject]@{role='B';path='C:\Fixture\pythonw.exe';sha256=('a'*64)})}
 $rows=TMatrix $q $dir $Root
 Check ($rows.Count -eq 9 -and (TBaselineGood $rows)) 'complete_valid_matrix'
 foreach($role in @('A','B','REF')){Check (@($rows|Where-Object{$_.role -ceq $role}).Count -eq 3) 'three_rounds_per_image'}
 Check (@($rows.request_id|Sort-Object -Unique).Count -eq 9) 'no_sample_reuse'
 $rows[0].probe_valid=$false;Check (-not (TBaselineGood $rows)) 'failed_process_not_counted_as_network_block'
 $report=[ordered]@{passed=$true;assertions=$script:checks;windows_live_traffic_executed=$false;backend='challenge and matrix helper test doubles'}
 [IO.File]::WriteAllText((Join-Path $Root 'evidence/traffic-tools-tests.json'),(UJson $report));$report|ConvertTo-Json -Compress
}finally{[IO.Directory]::Delete($dir,$true)}
