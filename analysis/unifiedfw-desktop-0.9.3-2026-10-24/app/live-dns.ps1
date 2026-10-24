# Optional, explicitly consented temporary DNS-Client ETW; no audit/channel/firewall/hosts changes.
$script:dnsCollector=$null;$script:dnsReceipt=$null
$script:dnsState=@{status='not_requested';coverage_verified=$false;source='DNSClient_ETW';seen=0;selected_events=0;unattributed=0;decode_errors=0;queue_dropped=0;events_lost=0;stop_status=$null;cleanup_required=$false;error_code=''}
function Start-DnsTrace {
 if(-not ($j.PSObject.Properties.Name -contains 'dns_etw_requested') -or $j.dns_etw_requested -ne $true){return}
 try{
  if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator_required_for_DNS_ETW'}
  if(-not ('UnifiedDns.Collector' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'dns-trace.cs') -ErrorAction Stop}
  $paths=[string[]]@($j.event_programs|ForEach-Object{$_.path});$ids=[string[]]@($j.event_programs|ForEach-Object{$_.id})
  $script:dnsCollector=New-Object UnifiedDns.Collector([string]$j.capture_id,[string]$j.owner,[string]$j.dns_session_guid,$paths,$ids)
  $script:dnsReceipt=@{schema='unified-dns-session-1';owner=[string]$j.owner;capture_id=[string]$j.capture_id;session_name=$script:dnsCollector.SessionName;session_guid=$script:dnsCollector.SessionGuid;collector_pid=$PID;collector_birth_ticks=(Get-Process -Id $PID).StartTime.ToUniversalTime().Ticks.ToString();ended=$false;created_utc=[DateTime]::UtcNow.ToString('o')}
  Write-LiveJson $j.dns_receipt_path $script:dnsReceipt
  $script:dnsCollector.Start();$script:dnsState.status='running_realtime_coverage_unverified'
 }catch{
  $script:dnsState.status='start_failed';$script:dnsState.error_code=([string]$_.Exception.Message).Substring(0,[Math]::Min(240,([string]$_.Exception.Message).Length))
  if($null -ne $script:dnsCollector){Stop-DnsTrace}
 }
}
function Add-DnsTraceQuery($q){
 if($script:eventRows.Count -ge 1000){$script:eventTruncated=$true;return}
 $name=([string]$q.domain).TrimEnd('.').ToLowerInvariant();if($name -notmatch '^[a-z0-9_][a-z0-9_.-]{0,252}$'){return}
 $matched=@($j.event_programs|Where-Object{$_.id -ceq $q.program_id -and $_.path -ieq $q.program_path});if($matched.Count -ne 1){return}
 $when=[DateTime]::Parse($q.observed_utc).ToUniversalTime();$birth=New-Object DateTime([long]$q.process_start_ticks,[DateTimeKind]::Utc)
 if($when -lt $start -or $birth -gt $when -or [long]$q.pid -le 0 -or $q.event_id -notin @(3006,3008)){return}
 $mapping=if($j.hosts_baseline.available){'not_listed'}else{'hosts_unavailable'};$addresses=@()
 if($script:hostsByName.ContainsKey($name)){$h=$script:hostsByName[$name];$mapping=$h.mapping_kind;$addresses=@($h.addresses)}
 $row=[pscustomobject]@{record_id=[guid]::NewGuid().ToString('N');program_id=[string]$q.program_id;program_path=[string]$q.program_path;pid=[long]$q.pid;process_start_ticks=[string]$q.process_start_ticks;event_record_id=[long]$q.sequence;observed_utc=$q.observed_utc;kind='dns_query';source='DNSClient_ETW';dns_event_id=[int]$q.event_id;dns_phase=$(if($q.event_id -eq 3006){'query_called'}else{'query_completed'});attribution='live_exact_path_PID_and_process_birth_at_event';HTTP_request_verified=$false;rule_owner_verified=$false;packet_drop_verified=$false;domain=$name;dns_status=[string]$q.status;query_results=[string]$q.results;hosts_mapping=$mapping;hosts_addresses=$addresses}
 $script:eventRows.Add($row);$script:dnsState.selected_events++
}
function Update-DnsTrace {
 if($null -eq $script:dnsCollector){return}
 foreach($q in $script:dnsCollector.Drain()){try{Add-DnsTraceQuery $q}catch{$script:dnsState.decode_errors++;$script:eventTruncated=$true}}
 $script:dnsState.seen=$script:dnsCollector.Seen;$script:dnsState.unattributed=$script:dnsCollector.Unattributed
 $script:dnsState.decode_errors=[Math]::Max($script:dnsState.decode_errors,$script:dnsCollector.Errors);$script:dnsState.queue_dropped=$script:dnsCollector.Dropped;$script:dnsState.events_lost=$script:dnsCollector.LostEvents
 if($script:dnsState.queue_dropped -or $script:dnsState.events_lost -or $script:dnsState.decode_errors){$script:eventTruncated=$true}
 if(-not $script:dnsCollector.Running -and $script:dnsState.status -ceq 'running_realtime_coverage_unverified'){$script:dnsState.status='consumer_stopped';$script:dnsState.error_code='ProcessTrace_'+$script:dnsCollector.ProcessStatus}
}
function Stop-DnsTrace {
 if($null -eq $script:dnsCollector){return}
 try{
  $previous=$script:dnsState.status;$script:dnsCollector.Dispose();Update-DnsTrace
  $script:dnsState.stop_status=$script:dnsCollector.StopStatus;$script:dnsState.cleanup_required=($script:dnsCollector.StopStatus -notin @(0,4201));$script:dnsState.events_lost=$script:dnsCollector.LostEvents
  if($previous -ceq 'running_realtime_coverage_unverified'){$script:dnsState.status=if($script:dnsState.cleanup_required){'stop_failed_cleanup_required'}else{'stopped'}}
  if($null -ne $script:dnsReceipt){$script:dnsReceipt.ended=(-not $script:dnsState.cleanup_required);$script:dnsReceipt['stop_status']=$script:dnsState.stop_status;Write-LiveJson $j.dns_receipt_path $script:dnsReceipt}
 }catch{$script:dnsState.status='stop_failed_cleanup_required';$script:dnsState.cleanup_required=$true}
 finally{$script:dnsCollector=$null}
}
