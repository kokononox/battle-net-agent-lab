# Existing logs only. Never install Sysmon, enable audit policy/channels, or mutate hosts.
$script:eventRows=New-Object Collections.Generic.List[object];$script:eventSeen=@{};$script:eventTruncated=$false;$script:eventTick=0;$script:hostsByName=@{};$script:eventStreams=@{}
foreach($entry in @($j.hosts_baseline.entries)){$script:hostsByName[[string]$entry.domain]=$entry}
foreach($source in @('dns','wfp')){
 $log=if($source -eq 'dns'){'Microsoft-Windows-Sysmon/Operational'}else{'Security'}
 try{$info=Get-WinEvent -ListLog $log -ErrorAction Stop;$available=($info.IsEnabled -eq $true)}catch{$available=$false}
 $script:eventStreams[$source]=@{status=$(if($available){'readable_logging_coverage_unverified'}else{'not_available_or_disabled'});available=$available;log=$log;last_id=0}
}
function Read-EventFields($event){
 $xml=New-Object Xml.XmlDocument;$xml.XmlResolver=$null;$xml.LoadXml($event.ToXml());$out=@{}
 foreach($d in $xml.Event.EventData.Data){$out[[string]$d.Name]=[string]$d.InnerText};return $out
}
function Event-ProcessId([string]$value){if($value -match '^0x[0-9a-f]+$'){return [Convert]::ToInt64($value.Substring(2),16)};return [long]::Parse($value)}
function Update-EventEvidence([bool]$force=$false){
 $script:eventTick++;if(!$force -and $script:eventTick % 2 -ne 1){return}
 foreach($source in @('dns','wfp')){
  $stream=$script:eventStreams[$source];if(!$stream.available){continue};$eventId=if($source -eq 'dns'){22}else{5157}
  try{
   $batch=@(Get-WinEvent -FilterHashtable @{LogName=$stream.log;Id=$eventId;StartTime=$start} -MaxEvents 501 -ErrorAction Stop)
   $stream.status='readable_logging_coverage_unverified'
   if($batch.Count -gt 500){$script:eventTruncated=$true}
   if($batch.Count -and [long]$batch[0].RecordId -lt $stream.last_id){$stream.last_id=0;$script:eventTruncated=$true}
   foreach($ev in @($batch|Sort-Object RecordId)){
    $ident=[long]$ev.RecordId;if($ident -le $stream.last_id){continue};$stream.last_id=$ident
    $when=$ev.TimeCreated.ToUniversalTime();if($when -lt $start){continue}
    if(($source -eq 'dns' -and $ev.ProviderName -ne 'Microsoft-Windows-Sysmon') -or ($source -eq 'wfp' -and $ev.ProviderName -ne 'Microsoft-Windows-Security-Auditing')){continue}
    try{
     $d=Read-EventFields $ev
     $image=if($source -eq 'dns'){$d.Image}else{$d.Application}
     $matched=$null
     foreach($candidate in @($j.event_programs)){if($image -and ($image -ieq $candidate.path -or ($candidate.device_path -and $image -ieq $candidate.device_path))){$matched=$candidate;break}}
     if($null -eq $matched){continue}
     $processId=if($source -eq 'dns'){Event-ProcessId $d.ProcessId}else{Event-ProcessId $d.ProcessID}
     if($processId -le 0 -or $processId -gt 4294967295){continue}
     $key=$source+'|'+$ident;if($script:eventSeen.ContainsKey($key)){continue}
     if($script:eventRows.Count -ge 1000){$script:eventTruncated=$true;continue}
     $row=@{program_id=[string]$matched.id;program_path=[string]$matched.path;attribution='logged_application_path_exact_match_not_process_birth_proof';HTTP_request_verified=$false;rule_owner_verified=$false;record_id=[Guid]::NewGuid().ToString('N');pid=$processId;event_record_id=$ident;observed_utc=$when.ToString('o')}
     if($source -eq 'dns'){
      $name=([string]$d.QueryName).TrimEnd('.').ToLowerInvariant();if($name -notmatch '^[a-z0-9_][a-z0-9_.-]{0,252}$'){continue}
      $mapping=if($j.hosts_baseline.available){'not_listed'}else{'hosts_unavailable'};$addresses=@()
      if($script:hostsByName.ContainsKey($name)){$h=$script:hostsByName[$name];$mapping=$h.mapping_kind;$addresses=@($h.addresses)}
      $row.kind='dns_query';$row.domain=$name;$row.dns_status=[string]$d.QueryStatus;$row.query_results=([string]$d.QueryResults).Substring(0,[Math]::Min(2000,([string]$d.QueryResults).Length));$row.hosts_mapping=$mapping;$row.hosts_addresses=$addresses
     }else{
      if($d.Direction -ne '%%14593'){continue}
      if($d.Protocol -notin @('6','17')){continue}
      $remote=$null;if(![Net.IPAddress]::TryParse([string]$d.DestAddress,[ref]$remote)){continue};$port=[int]$d.DestPort;if($port -lt 1 -or $port -gt 65535){continue}
      $row.kind='wfp_connection_block';$row.direction='outbound';$row.ip=$remote.ToString();$row.port=$port;$row.protocol=$(if($d.Protocol -eq '6'){'TCP'}else{'UDP'});$row.filter_id=[string]$d.FilterRTID
     }
     $script:eventRows.Add([pscustomobject]$row);$script:eventSeen[$key]=$true
    }catch{$script:eventTruncated=$true;continue}
   }
  }catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){$stream.status='read_failed'}}
 }
}
function Event-Evidence {
 $streams=@{};foreach($name in @('dns','wfp')){$streams[$name]=@{status=$script:eventStreams[$name].status;coverage_verified=$false}}
 return @{schema='unified-event-evidence-1';dns_trace=$(if(Get-Variable dnsState -Scope Script -ErrorAction SilentlyContinue){$script:dnsState}else{@{status='not_requested'}});streams=$streams;events=@($script:eventRows.ToArray());truncated=$script:eventTruncated;cap=1000;configuration_changed=$false;persistent_logging_configuration_changed=$false;temporary_etw_session_requested=($j.PSObject.Properties.Name -contains 'dns_etw_requested' -and $j.dns_etw_requested -eq $true);hosts_snapshot_checked_utc=$(if($j.hosts_baseline.PSObject.Properties.Name -contains 'checked_utc'){[string]$j.hosts_baseline.checked_utc}else{'unknown'});hosts_snapshot_available=($j.hosts_baseline.available -eq $true);hosts_snapshot_truncated=($j.hosts_baseline.truncated -eq $true)}
}
