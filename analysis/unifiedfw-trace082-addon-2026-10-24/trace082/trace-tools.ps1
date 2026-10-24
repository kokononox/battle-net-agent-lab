# Diagnostic observation only; failures must never suppress native recovery.
$script:XWriter=$null;$script:XHealthy=$true;$script:XFirstError=$null;$script:XCount=0;$script:XNextID=0;$script:XOrigin=0.0;$script:XClosed=$false
$script:XLastInventory=$null;$script:XLastRoute=$null;$script:XLastRestore=$null
function XNow(){return (TMonotonicMilliseconds)}
function XWrite($Event){
 if(-not $script:XHealthy){return}
 try{
  if($script:XCount -ge 5000){throw 'trace_event_limit'}
  $Event.sequence=$script:XCount;$Event.monotonic_ms=(XNow)-$script:XOrigin;$Event.utc=[datetime]::UtcNow.ToString('o')
  $line=ConvertTo-Json -InputObject $Event -Depth 10 -Compress
  if($line.Length -gt 16384){throw 'trace_event_size_limit'}
  $script:XWriter.WriteLine($line);$script:XCount++
 }catch{$script:XHealthy=$false;$script:XFirstError='trace_write_failed_or_limit; diagnostic_trace_incomplete'}
}
function XInit([string]$Path){
 $script:XOrigin=XNow
 try{UAssertPath $Path;$stream=New-Object IO.FileStream($Path,([IO.FileMode]::CreateNew),([IO.FileAccess]::Write),([IO.FileShare]::Read));$script:XWriter=New-Object IO.StreamWriter($stream,(New-Object Text.UTF8Encoding($false)));$script:XWriter.AutoFlush=$true}
 catch{$script:XHealthy=$false;$script:XFirstError='trace_open_failed; no_new_session_permitted'}
 XWrite ([ordered]@{event='controller_start';controller_pid=$PID})
}
function XStart([string]$Operation,$Context=$null){
 $script:XNextID++;$now=XNow
 $token=[pscustomobject]@{id=$script:XNextID;operation=$Operation;started=$now}
 $progress=$null;$rv=Get-Variable report -ErrorAction SilentlyContinue;if($null -ne $rv -and $rv.Value -is [System.Collections.IDictionary] -and $rv.Value.Contains('progress')){$progress=$rv.Value['progress']}
 XWrite ([ordered]@{event='operation_start';operation_id=$token.id;operation=$Operation;progress=$progress;context=$Context})
 return $token
}
function XEnd($Token,[bool]$OK,[string]$ErrorText=''){
 $end=XNow
 XWrite ([ordered]@{event='operation_end';operation_id=$Token.id;operation=$Token.operation;execution_ok=$OK;duration_ms=($end-$Token.started);error=$ErrorText})
 if($OK -and $Token.operation -ceq 'policy_inventory'){$script:XLastInventory=$end}
 if($OK -and $Token.operation -ceq 'route_guard'){$script:XLastRoute=$end}
}
function XCall([string]$Operation,[scriptblock]$Body){
 $token=XStart $Operation;$ok=$false;$message=''
 try{& $Body;$ok=$true}catch{$message=$_.Exception.Message;if($message.Length -gt 512){$message=$message.Substring(0,512)};throw}
 finally{XEnd $token $ok $message}
}
function XAssertHealthy(){if(-not $script:XHealthy){throw 'diagnostic_trace_incomplete; no_further_activation; restore_status_separate'}}
function XMarkRestored(){
 $script:XLastRestore=XNow
 XWrite ([ordered]@{event='restore_verified';progress=$report.progress})
}
function XProbeStart($Challenge){
 $now=XNow;$gap=$null;if($null -ne $script:THttpsLastFinished){$gap=$now-$script:THttpsLastFinished}
 $routeAge=$null;$inventoryAge=$null;$restoreAge=$null
 if($null -ne $script:XLastRoute){$routeAge=$now-$script:XLastRoute}
 if($null -ne $script:XLastInventory){$inventoryAge=$now-$script:XLastInventory}
 if($null -ne $script:XLastRestore){$restoreAge=$now-$script:XLastRestore}
 $context=[ordered]@{request_id=$Challenge.request_id;role=$Challenge.role;pacing_sequence=$script:THttpsSequence;actual_gap_before_dispatch_ms=$gap;ms_since_last_successful_route_guard=$routeAge;ms_since_last_policy_inventory=$inventoryAge;ms_since_last_verified_restore=$restoreAge}
 $token=XStart 'probe_dispatch' $context
 return [pscustomobject]@{token=$token;context=$context}
}
function XProbeEnd($Probe,$Row){
 XEnd $Probe.token $true
 Add-Member -InputObject $Row -NotePropertyName trace_context -NotePropertyValue ([pscustomobject]$Probe.context)
 XWrite ([ordered]@{event='probe_result';operation_id=$Probe.token.id;progress=$report.progress;row=$Row})
}
function XSummary(){return [pscustomobject]@{schema='unifiedfw-trace082-1';trace_file='operation-trace.jsonl';trace_write_ok=$script:XHealthy;trace_error=$script:XFirstError;events_written=$script:XCount;closed=$script:XClosed;clock='monotonic_Stopwatch';timing_is_not_causal_proof=$true;extra_connections=0;automatic_retries=0;native_core_replaced=$false;controller_pid=$PID;reference_version=[string]$PSVersionTable.PSVersion}}
function XFinish(){
 try{XWrite ([ordered]@{event='controller_end';completed=$report.completed;restore_verified=$report.restore_verified;progress=$report.progress})}catch{$script:XHealthy=$false;if($null -eq $script:XFirstError){$script:XFirstError='trace_finalize_metadata_failed'}}
 try{if($null -ne $script:XWriter){$script:XWriter.Dispose()}}catch{$script:XHealthy=$false;$script:XFirstError='trace_close_failed'}
 $script:XClosed=$true
}

function XCompare($Before,$After){XCall 'policy_inventory_compare' {ComparePolicyInventory $Before $After}}
