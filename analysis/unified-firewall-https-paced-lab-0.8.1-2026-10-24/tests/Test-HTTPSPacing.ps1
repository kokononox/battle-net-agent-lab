param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $Root 'lab/session-core.ps1')
. (Join-Path $Root 'lab/native.ps1')
. (Join-Path $Root 'lab/traffic-tools.ps1')
$script:checks=0
function Check([bool]$OK,[string]$Why){$script:checks++;if(-not $OK){throw ('pacing_assertion:'+ $Why)}}
$script:clock=0.0;$script:delays=@();$script:probes=0;$script:events=@();$script:fail=$false
function TMonotonicMilliseconds(){return $script:clock}
function TDelayMilliseconds([int]$Milliseconds){$script:delays+=,$Milliseconds;$script:clock+=$Milliseconds;$script:events+=,'delay'}
function Get-FileHash{param($LiteralPath,$Algorithm,$ErrorAction) [pscustomobject]@{Hash=('A'*64)}}
function HReference($URL,$Address,$Challenge){$script:probes++;$script:clock+=100;$script:events+=,'probe';[pscustomobject]@{probe_valid=$true;role='REF';request_id=$Challenge.request_id;transport='https_php';connected=$true;tls_verified=$true;http_status=200;handshake_ok=$true}}
function TRunProcess($Exe,$Script,$Request,$Output){
 $script:probes++;$script:clock+=100;$script:events+=,'probe';$q=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Request))
 [pscustomobject]@{probe_valid=$true;role=$q.challenge.role;request_id=$q.challenge.request_id;transport='https_php';connected=(-not $script:fail);tls_verified=(-not $script:fail);http_status=$(if($script:fail){$null}else{200});handshake_ok=(-not $script:fail)}
}
$q=[pscustomobject]@{schema='unifiedfw-coexistence-request-1';transport='https_php';https_url='https://ufw-test.example/probe.php';address='9.9.9.9';port=443;programs=@([pscustomobject]@{role='A';path='C:\Fixture\python.exe';sha256=('a'*64)},[pscustomobject]@{role='B';path='C:\Fixture\pythonw.exe';sha256=('a'*64)})}
$dir=Join-Path ([IO.Path]::GetTempPath()) ('Pacing-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($dir)
try{
 $script:guards=0;$guard={$script:guards++;$script:events+=,'guard'}
 $a=TMatrix $q $dir $Root $guard
 Check ($a.Count -eq 9 -and $script:probes -eq 9) 'exact9_no_retries'
 Check ($null -eq $a[0].gap_since_previous_probe_ms) 'no_wait_before_first_attempt'
 Check ($script:delays.Count -eq 8) 'eight_internal_gaps'
 foreach($row in @($a|Select-Object -Skip 1)){Check ($row.gap_since_previous_probe_ms -ge 4000) 'minimum_gap_observed'}
 Check ($script:guards -eq 15) 'round_and_each_attempt_route_guards'
 for($i=0;$i -lt $a.Count;$i++){Check ($a[$i].pacing_sequence -eq $i) 'strict_sequence';Check ($null -ne $a[$i].started_utc -and $null -ne $a[$i].ended_utc) 'UTC_stamps'}
 # Restore/apply metadata work consumes part of the same gap; do not reset clock.
 $script:clock+=1500;$b=TMatrix $q $dir $Root $guard
 Check ($b[0].gap_since_previous_probe_ms -eq 4000) 'gap_spans_matrix_restore_boundary'
 Check ($script:delays[8] -eq 2500) 'remaining_gap_only'
 Check ($b[0].pacing_sequence -eq 9 -and $b[8].pacing_sequence -eq 17) 'sequence_spans_matrices'
 Check ($script:probes -eq 18 -and $script:delays.Count -eq 17) '18attempts_17gaps'
 for($i=0;$i -lt $script:events.Count;$i++){if($script:events[$i] -ceq 'probe'){Check ($i -gt 0 -and $script:events[$i-1] -ceq 'guard') 'route_rechecked_immediately_before_attempt'}}
 # Long external work: no redundant 4-second sleep, but still report real gap.
 $count=$script:delays.Count;$script:clock+=6000;$gap=TWaitHTTPSProbeGap
 Check ($gap -ge 6000 -and $script:delays.Count -eq $count) 'long_restore_work_already_satisfies_gap'
 # An early wake must not shorten the gap; the monotonic loop waits again.
 $script:THttpsLastFinished=$script:clock;$script:early=$true
 function TDelayMilliseconds([int]$Milliseconds){if($script:early){$script:clock+=[Math]::Floor($Milliseconds/2);$script:early=$false}else{$script:clock+=$Milliseconds}}
 $gap=TWaitHTTPSProbeGap;Check ($gap -ge 4000) 'early_wake_rewaits'
 # Failure is retained with no retries; it cannot turn into baseline success.
 $before=$script:probes;$script:fail=$true;$bad=TMatrix $q $dir $Root $guard
 Check ($script:probes-$before -eq 9 -and -not (TBaselineGood $bad)) 'failed_attempts_retained_no_retry'
 # Route change during pacing stops before ANY further connection.
 $before=$script:probes;$caught=$false;$script:routeCalls=0
 try{$null=TMatrix $q $dir $Root {$script:routeCalls++;if($script:routeCalls -eq 2){throw 'route_changed_after_wait'}}}catch{$caught=$true}
 Check ($caught -and $script:probes -eq $before) 'route_change_after_wait_no_connection'
 # This scheduler must not slow or alter old raw TCP probes.
 $script:delayRaw=0
 function TDelayMilliseconds([int]$Milliseconds){$script:delayRaw++;throw 'raw_tcp_must_not_use_https_pacing'}
 function TReference($Address,$Port,$Challenge){[pscustomobject]@{probe_valid=$true;role='REF';request_id=$Challenge.request_id;connected=$true;handshake_ok=$true}}
 $raw=[pscustomobject]@{address='9.9.9.9';port=39443;programs=$q.programs};$script:fail=$false
 $legacy=TMatrix $raw $dir $Root
 Check ($legacy.Count -eq 9 -and $script:delayRaw -eq 0) 'raw_tcp_unchanged'
 $report=[ordered]@{passed=$true;assertions=$script:checks;backend='fake monotonic clock; child/network doubles; no Windows policy';windows_live_tested=$false}
 [IO.File]::WriteAllText((Join-Path $Root 'evidence/https-pacing-tests.json'),(UJson $report));$report|ConvertTo-Json -Compress
}finally{[IO.Directory]::Delete($dir,$true)}
