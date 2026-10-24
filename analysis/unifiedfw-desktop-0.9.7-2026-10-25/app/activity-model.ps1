# Pure evidence aggregation. A blocked CONNECTION is not an entirely blocked process.
# Blue means observed TCP/DNS activity; never remote delivery. Red needs a Security 5157 event.
function Test-ActivityIdentity($Event,$Row){
 if($Event.PSObject.Properties.Name -notcontains 'process_start_ticks' -or $Row.PSObject.Properties.Name -notcontains 'process_start_ticks'){return $false}
 return ([string]$Event.program_id -ceq [string]$Row.program_id -and [string]$Event.program_path -ieq [string]$Row.program_path -and [long]$Event.pid -eq [long]$Row.pid -and [string]$Event.process_start_ticks -ceq [string]$Row.process_start_ticks)
}

function Get-ActivityKey($Row){
 if($Row.PSObject.Properties.Name -notcontains 'process_start_ticks'){return ''}
 return (ConvertTo-Json -Compress -InputObject @([string]$Row.program_id,([string]$Row.program_path).ToLowerInvariant(),[string]$Row.pid,[string]$Row.process_start_ticks))
}
function Get-ActivityEndpointKey($Row,[bool]$Event=$false){
 $identity=Get-ActivityKey $Row;if(-not $identity){return ''}
 $ip=if($Event){[string]$Row.ip}else{[string]$Row.remote_ip};$port=if($Event){[string]$Row.port}else{[string]$Row.remote_port}
 return $identity+'|'+$ip+'|'+$port+'|'+[string]$Row.protocol
}
function New-ActivityIndex($Frame){
 $index=@{processEvents=@{};remoteEvents=@{};dnsEvents=@{};tcp=@{}}
 foreach($e in @($Frame.event_evidence.events)){
  $key=Get-ActivityKey $e;if(-not $key){continue}
  if(-not $index.processEvents.ContainsKey($key)){$index.processEvents[$key]=New-Object Collections.Generic.List[object]};$index.processEvents[$key].Add($e)
  if($e.kind -ceq 'wfp_connection_block'){
   $remote=Get-ActivityEndpointKey $e $true
   if(-not $index.remoteEvents.ContainsKey($remote)){$index.remoteEvents[$remote]=New-Object Collections.Generic.List[object]};$index.remoteEvents[$remote].Add($e)
  }elseif($e.kind -ceq 'dns_query'){
   foreach($ip in (Get-MonitorResultIPs ([string]$e.query_results))){
    $dk=$key+'|'+$ip
    if(-not $index.dnsEvents.ContainsKey($dk)){$index.dnsEvents[$dk]=New-Object Collections.Generic.List[object]};$index.dnsEvents[$dk].Add($e)
   }
  }
 }
 foreach($r in @($Frame.endpoints)){$key=Get-ActivityKey $r;if($key){if(-not $index.tcp.ContainsKey($key)){$index.tcp[$key]=0};$index.tcp[$key]+=[int]$r.samples}}
 return $index
}
function Get-FrameActivityIndex($Frame){
 if(-not (Get-Variable activityFrame -Scope Script -ErrorAction SilentlyContinue) -or -not [object]::ReferenceEquals($script:activityFrame,$Frame)){
  $script:activityFrame=$Frame;$script:activityIndex=New-ActivityIndex $Frame
 };return $script:activityIndex
}

function Get-RowActivity($Frame,$Row,[bool]$Endpoint=$false,$Index=$null){
 $denied=0;$dns=0;$last='';$target='';$filters=@{};$seen=@{};$tcp=0
 $events=@($Frame.event_evidence.events)
 if($null -ne $Index){
  $events=@();$ik=Get-ActivityKey $Row
  if($Endpoint){
   $rk=Get-ActivityEndpointKey $Row;$dk=$ik+'|'+[string]$Row.remote_ip
   if($Index.remoteEvents.ContainsKey($rk)){$events+=@($Index.remoteEvents[$rk].ToArray())}
   if($Index.dnsEvents.ContainsKey($dk)){$events+=@($Index.dnsEvents[$dk].ToArray())}
  }elseif($Index.processEvents.ContainsKey($ik)){$events=@($Index.processEvents[$ik].ToArray())}
 }
 foreach($e in $events){
  if(-not (Test-ActivityIdentity $e $Row)){continue}
  if($e.kind -ceq 'wfp_connection_block'){
   if($Endpoint -and ([string]$e.ip -cne [string]$Row.remote_ip -or [int]$e.port -ne [int]$Row.remote_port -or [string]$e.protocol -cne [string]$Row.protocol)){continue}
   $key='wfp|'+[string]$e.event_record_id;if($seen.ContainsKey($key)){continue};$seen[$key]=$true;$denied++
   if($e.PSObject.Properties.Name -contains 'filter_id' -and $e.filter_id){$filters[[string]$e.filter_id]=$true}
   if(-not $last -or [DateTimeOffset]::Parse($e.observed_utc) -gt [DateTimeOffset]::Parse($last)){$last=[string]$e.observed_utc;$target=[string]$e.ip+':'+[string]$e.port+' / '+[string]$e.protocol}
  }elseif($e.kind -ceq 'dns_query'){
   if($Endpoint -and [string]$Row.remote_ip -cnotin (Get-MonitorResultIPs ([string]$e.query_results))){continue}
   $key='dns|'+[string]$e.record_id;if(-not $seen.ContainsKey($key)){$seen[$key]=$true;$dns++}
  }
 }
 if(-not $Endpoint){if($null -ne $Index){$ik=Get-ActivityKey $Row;if($Index.tcp.ContainsKey($ik)){$tcp=[int]$Index.tcp[$ik]}}else{foreach($r in @($Frame.endpoints)){if(Test-ActivityIdentity $r $Row){$tcp += [int]$r.samples}}}}else{$tcp=[int]$Row.samples}
 $reason=if($denied -gt 0){'منع اتصال خروجی توسط Windows WFP / Security 5157؛ قاعده یا نرم‌افزار عامل مشخص نیست'+$(if($filters.Count){' | Filter ID: '+(@($filters.Keys|Sort-Object|Select-Object -First 10) -join ', ')}else{''})}else{'رویداد منع منتسب ثبت نشده؛ نه اثبات آزادبودن یا رسیدن درخواست'}
 return [pscustomobject]@{denied=$denied;dns=$dns;tcp=$tcp;last_denied=$last;last_target=$target;reason=$reason}
}
function Get-ActivityPulse($Previous,$Current){
 if($Current.denied -gt 0 -and ($null -eq $Previous -or $Current.denied -gt $Previous.denied)){return 'wfp'}
 if($Current.dns -gt 0 -and ($null -eq $Previous -or $Current.dns -gt $Previous.dns)){return 'dns'}
 if($Current.tcp -gt 0 -and ($null -eq $Previous -or $Current.tcp -gt $Previous.tcp)){return 'sample'}
 return 'none'
}
function Test-ProcessActivityVisible($Activity,[int]$Filter,[bool]$OnlyPresent,[string]$Presence){
 if($Filter -eq 1 -and $Activity.denied -eq 0){return $false}
 if($Filter -eq 2 -and $Activity.denied -gt 0){return $false}
 return (-not $OnlyPresent -or $Presence -ceq 'present' -or $Activity.denied -gt 0)
}
