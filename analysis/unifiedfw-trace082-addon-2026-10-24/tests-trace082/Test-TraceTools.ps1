param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $Root 'lab/session-core.ps1')
. (Join-Path $Root 'lab/traffic-tools.ps1')
. (Join-Path $Root 'trace082/trace-tools.ps1')
$script:checks=0
function Check([bool]$OK,[string]$Why){$script:checks++;if(-not $OK){throw ('trace_test:'+ $Why)}}
$script:fake=1000.0
function TMonotonicMilliseconds(){return $script:fake}
$report=[ordered]@{progress='fixture';completed=$false;restore_verified=$false}
$dir=Join-Path ([IO.Path]::GetTempPath()) ('TraceTools-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($dir)
try{
 XInit (Join-Path $dir 'trace.jsonl');XAssertHealthy
 $value=XCall 'policy_inventory' {$script:fake+=7;[pscustomobject]@{a=1}}
 Check ($value.a -eq 1) 'return_value_unchanged'
 $seen=$false;try{XCall 'route_guard' {throw 'original_route_failure'}}catch{$seen=$_.Exception.Message -ceq 'original_route_failure'}
 Check $seen 'original_exception_not_swallowed';Check ($null -eq $script:XLastRoute) 'failed_route_not_successful'
 $null=XCall 'route_guard' {$script:fake+=3}
 XMarkRestored
 $script:fake+=4000;$script:THttpsLastFinished=$script:fake-4000;$script:THttpsSequence=123
 $c=[pscustomobject]@{request_id=('a'*32);role='REF'};$p=XProbeStart $c
 $row=[pscustomobject]@{role='REF';handshake_ok=$false;error='https_connect_timeout';pacing_sequence=123};XProbeEnd $p $row
 Check ($row.trace_context.actual_gap_before_dispatch_ms -eq 4000) 'real_gap_context'
 Check ($row.trace_context.ms_since_last_verified_restore -eq 4000) 'restore_age_context'
 Check ($row.trace_context.ms_since_last_policy_inventory -eq 4003) 'inventory_age_context'
 Check (-not $row.handshake_ok -and $row.error -ceq 'https_connect_timeout') 'failed_row_not_modified'
 XFinish;$s=XSummary;Check ($s.closed -and $s.trace_write_ok) 'healthy_closed'
 $events=@(Get-Content -LiteralPath (Join-Path $dir 'trace.jsonl')|ForEach-Object{ConvertFrom-Json -InputObject $_})
 Check (@($events|Where-Object{$_.event -ceq 'operation_end' -and -not $_.execution_ok}).Count -eq 1) 'one_original_failed_operation'
 # A closed writer simulates a disk/write failure: never throw over the caller's recovery.
 XWrite ([ordered]@{event='test_closed_stream'});Check (-not $script:XHealthy) 'write_failure_recorded'
 $caught=$false;try{XAssertHealthy}catch{$caught=$true};Check $caught 'new_activation_admission_stops'
 $null=XCall 'error_cleanup_restore' {[pscustomobject]@{restored=$true}}
 Check ($null -ne $script:XFirstError) 'cleanup_allowed_despite_logging_failure'
 $report=[ordered]@{progress='missing_metadata_fixture'};$finishCaught=$false;try{XFinish}catch{$finishCaught=$true};Check (-not $finishCaught) 'metadata_failure_cannot_throw_over_recovery'
 $result=[ordered]@{passed=$true;assertions=$script:checks;Windows_tested=$false;clock='test_double';native_provider_used=$false}
 [IO.File]::WriteAllText((Join-Path $Root 'evidence-trace082/trace-tools-tests.json'),(UJson $result));$result|ConvertTo-Json -Compress
}finally{if($null -ne $script:XWriter){$script:XWriter.Dispose()};[IO.Directory]::Delete($dir,$true)}
