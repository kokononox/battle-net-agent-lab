# Read-only display grouping. Exact EXE paths stay separate; underlying PID/birth evidence is retained.
function Get-ProcessDisplayRows($Frame){
 if($Frame.schema -cne 'unified-new-process-monitor-1'){return @()}
 $groups=@{};$identities=@{};$index=Get-FrameActivityIndex $Frame
 foreach($p in @($Frame.processes)){
  $identity=Get-ActivityKey $p;if(-not $identity -or $identities.ContainsKey($identity)){continue};$identities[$identity]=$true
  $key=([string]$p.program_path).ToLowerInvariant()
  if(-not $groups.ContainsKey($key)){$groups[$key]=New-Object Collections.Generic.List[object]};$groups[$key].Add($p)
 }
 foreach($key in $groups.Keys){
  $instances=@($groups[$key].ToArray());$latest=@($instances|Sort-Object last_seen_utc -Descending)[0];$activity=[pscustomobject]@{denied=0;dns=0;tcp=0;last_denied='';last_target='';reason='رویداد منع منتسب ثبت نشده؛ نه اثبات آزادبودن یا رسیدن درخواست'}
  $presence='not_in_latest_snapshot'
  foreach($p in $instances){
   $a=Get-RowActivity $Frame $p $false $index;$activity.denied+=$a.denied;$activity.dns+=$a.dns;$activity.tcp+=$a.tcp
   if($a.last_denied -and (-not $activity.last_denied -or [DateTimeOffset]::Parse($a.last_denied) -gt [DateTimeOffset]::Parse($activity.last_denied))){$activity.last_denied=$a.last_denied;$activity.last_target=$a.last_target;$activity.reason=$a.reason}
   if($p.presence -ceq 'present'){$presence='present'}elseif($p.presence -cne 'not_in_latest_snapshot' -and $presence -cne 'present'){$presence='unknown'}
  }
  $row=$latest.PSObject.Copy();$row.record_id='process|'+$key;$row.presence=$presence;$row.first_seen_utc=(@($instances|Sort-Object first_seen_utc)[0]).first_seen_utc
  $row|Add-Member NoteProperty instances $instances -Force;$row|Add-Member NoteProperty instance_count $instances.Count -Force
  $row|Add-Member NoteProperty display_pids ((@($instances|ForEach-Object{$_.pid}|Sort-Object -Unique)) -join ', ') -Force
  $row|Add-Member NoteProperty activity $activity -Force;$row
 }
}
function Get-DomainDisplayRows($Frame){
 if($Frame.PSObject.Properties.Name -notcontains 'event_evidence'){return @()}
 $groups=@{};$unique=@{};$denials=@{}
 foreach($e in @($Frame.event_evidence.events)){
  if($e.kind -ceq 'wfp_connection_block'){
   $identity=Get-ActivityKey $e;if(-not $identity){continue};$dk=$identity+'|'+[string]$e.ip
   if(-not $denials.ContainsKey($dk)){$denials[$dk]=New-Object Collections.Generic.List[object]};$denials[$dk].Add($e);continue
  }
  if($e.kind -cne 'dns_query'){continue}
  $record=[string]$e.record_id;if($unique.ContainsKey($record)){continue};$unique[$record]=$true
  $key=([string]$e.program_path).ToLowerInvariant()+'|'+([string]$e.domain).TrimEnd('.').ToLowerInvariant()
  if(-not $groups.ContainsKey($key)){$groups[$key]=New-Object Collections.Generic.List[object]};$groups[$key].Add($e)
 }
 foreach($key in $groups.Keys){
  $events=@($groups[$key].ToArray());$latest=@($events|Sort-Object observed_utc -Descending)[0];$ips=@{};$blocked=@{};$lastDeny='';$hosts=@{};$pids=@{}
  foreach($e in $events){
   $pids[[string]$e.pid]=$true
   if($e.hosts_mapping -in @('local_sink_mapping','mixed_mapping')){$hosts[[string]$e.hosts_mapping]=$true}
   foreach($ip in (Get-MonitorResultIPs ([string]$e.query_results))){
    $ips[$ip]=$true;$identity=Get-ActivityKey $e;if(-not $identity){continue};$dk=$identity+'|'+$ip
    if(-not $denials.ContainsKey($dk)){continue}
    foreach($w in $denials[$dk]){
     if([DateTimeOffset]::Parse($w.observed_utc) -lt [DateTimeOffset]::Parse($e.observed_utc)){continue}
     $blocked[[string]$w.event_record_id]=$true
     if(-not $lastDeny -or [DateTimeOffset]::Parse($w.observed_utc) -gt [DateTimeOffset]::Parse($lastDeny)){$lastDeny=[string]$w.observed_utc}
    }
   }
  }
  $row=$latest.PSObject.Copy();$row.domain=([string]$latest.domain).TrimEnd('.').ToLowerInvariant();$row.record_id='dns|'+$key;$row.query_results=(@($ips.Keys|Sort-Object) -join ';')
  $row|Add-Member NoteProperty events_count $events.Count -Force;$row|Add-Member NoteProperty denied_count $blocked.Count -Force
  $row|Add-Member NoteProperty last_denied $lastDeny -Force;$row|Add-Member NoteProperty display_pids (@($pids.Keys|Sort-Object) -join ', ') -Force
  $state='unknown';$label='نامعلوم؛ DNS شاهد برقراری اتصال نیست'
  $answerIPs=Get-MonitorResultIPs ([string]$latest.query_results);$sinkIPs=@($answerIPs|Where-Object{Test-DnsSink $_});$realIPs=@($answerIPs|Where-Object{-not (Test-DnsSink $_)})
  if($blocked.Count){$state='denied';$label='منع اتصال به IP مرتبط ثبت شد؛ نه اثبات منع خود DNS'}
  elseif($latest.PSObject.Properties.Name -contains 'dns_phase' -and $latest.dns_phase -ceq 'query_called'){$state='pending';$label='فقط تلاش DNS؛ نتیجه هنوز مشخص نیست'}
  elseif($sinkIPs.Count -gt 0 -and $realIPs.Count -eq 0){$state='dns_sink';$label='پاسخ DNS تهی/محلی؛ مقصد اینترنتی ارائه نشده — نه شاهد منع WFP'}
  elseif($sinkIPs.Count -gt 0){$state='dns_mixed';$label='پاسخ ترکیبی: آدرس محلی و واقعی؛ وضعیت اتصال نامعلوم'}
  elseif($hosts.Count -and $realIPs.Count){$state='hosts_conflict';$label='hosts محلی دارد ولی پاسخ واقعی ثبت شده؛ کش/منبع دیگر محتمل، اتصال اثبات نشده'}
  elseif($hosts.Count){$state='hosts_mapping';$label='نگاشت انسداد hosts در شروع رصد؛ نتیجهٔ اتصال اثبات نشده'}
  elseif([string]$latest.dns_status -and [string]$latest.dns_status -cne '0'){$state='dns_error';$label='خطای DNS؛ مسدودی فایروال اثبات نشده'}
  elseif([string]$latest.dns_status -ceq '0'){$state='dns_answer';$label='فقط پاسخ DNS با IP واقعی؛ نه شاهد اتصال یا تحویل'}
  $row|Add-Member NoteProperty answer_ips $answerIPs -Force
  $row|Add-Member NoteProperty activity_state $state -Force;$row|Add-Member NoteProperty activity_label $label -Force
  $row|Add-Member NoteProperty snapshot ([pscustomobject]@{dns=$events.Count;denied=$blocked.Count;tcp=0}) -Force;$row
 }
}
