# Counts are distinct Security records retained in this capture, NOT packets or HTTP requests.
function Get-DenialGroups($Events){
 $groups=@{};$seen=@{}
 foreach($e in @($Events)){
  if($e.kind -cne 'wfp_connection_block'){continue}
  $identity='Security|'+[string]$e.event_record_id
  if($seen.ContainsKey($identity)){continue};$seen[$identity]=$true
  $birth=if($e.PSObject.Properties.Name -contains 'process_start_ticks'){[string]$e.process_start_ticks}else{'0'}
  $key=ConvertTo-Json -Compress -InputObject @([string]$e.program_id,([string]$e.program_path).ToLowerInvariant(),[string]$e.pid,$birth,[string]$e.ip,[string]$e.port,[string]$e.protocol)
  if(-not $groups.ContainsKey($key)){
   $groups[$key]=[pscustomobject]@{record_id=$e.record_id;program_id=$e.program_id;program_path=$e.program_path;pid=$e.pid;process_start_ticks=$birth;remote_ip=$e.ip;remote_port=$e.port;protocol=$e.protocol;first_seen_utc=$e.observed_utc;last_seen_utc=$e.observed_utc;presence='event';samples=0;states=[pscustomobject]@{};rule_state='wfp_denial_event';dns_names=@();kind='wfp_connection_block'}
  }
  $g=$groups[$key];$g.samples++
  if([DateTimeOffset]::Parse($e.observed_utc) -lt [DateTimeOffset]::Parse($g.first_seen_utc)){$g.first_seen_utc=$e.observed_utc;$g.record_id=$e.record_id}
  if([DateTimeOffset]::Parse($e.observed_utc) -gt [DateTimeOffset]::Parse($g.last_seen_utc)){$g.last_seen_utc=$e.observed_utc}
 }
 return @($groups.Values)
}
function Get-DenialPulse($Previous,$Current){if($null -eq $Previous -or [int]$Current.samples -gt [int]$Previous.samples){return 'wfp'};return 'none'}
function Test-MonitorRowVisible($Row,[bool]$OnlyPresent){return (-not $OnlyPresent -or $Row.presence -ceq 'present' -or ($Row.PSObject.Properties.Name -contains 'kind' -and $Row.kind -ceq 'wfp_connection_block'))}
function Get-EvidencePulseColor([string]$Kind){if($Kind -ceq 'wfp'){return '#F4A6A6'};if($Kind -ceq 'reappeared'){return '#FBE6B7'};return '#B9DAF5'}
