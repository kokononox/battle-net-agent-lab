# Pure, capture-bounded activity packages. Domain groups are NOT process identities or socket-hostname proof.
function Get-ActivityPackages($Frame){
 $packages=@{};$dnsIndex=@{};$seen=@{}
 function Package([string]$Key,[string]$Label,[string]$Domain=''){
  if(-not $packages.ContainsKey($Key)){$packages[$Key]=[pscustomobject]@{record_id=('package|'+$Key);key=$Key;label=$Label;domain=$Domain;routes=@{};paths=@{};dns_records=@{};denial_records=@{};sink_records=@{};tcp_samples=0}}
  return $packages[$Key]
 }
 function Route($P,[string]$Path,[string]$IP,[string]$Protocol,[int]$Port,[string]$PIDText,[string]$Source,[string]$Birth){
  try{$IP=Get-ObservedDestination $IP}catch{return}
  $key=$Path.ToLowerInvariant()+'|'+$IP+'|'+$Protocol+'|'+$Port
  if(-not $P.routes.ContainsKey($key)){$P.routes[$key]=[pscustomobject]@{key=$key;program_path=$Path;ip=$IP;protocol=$Protocol;port=$Port;pids=@{};sources=@{};identities=@{}}}
  $P.paths[$Path.ToLowerInvariant()]=$Path;$r=$P.routes[$key];$r.pids[$PIDText]=$true;$r.sources[$Source]=$true;$r.identities[($Source+' | PID '+$PIDText+' | birth '+$Birth)]=$true
 }
 $events=@();if($Frame.PSObject.Properties.Name -contains 'event_evidence'){$events=@($Frame.event_evidence.events)}
 foreach($e in $events){
  if($e.kind -cne 'dns_query' -or $seen.ContainsKey([string]$e.record_id)){continue};$seen[[string]$e.record_id]=$true
  $name=([string]$e.domain).TrimEnd('.').ToLowerInvariant();$p=Package ('dns|'+$name) $name $name;$p.paths[([string]$e.program_path).ToLowerInvariant()]=[string]$e.program_path;$p.dns_records[[string]$e.record_id]=$true
  $identity=Get-ActivityKey $e
  foreach($ip in (Get-MonitorResultIPs ([string]$e.query_results))){
   if(Test-DnsSink $ip){$p.sink_records[[string]$e.record_id]=$true;continue}
   Route $p $e.program_path $ip '' 0 ([string]$e.pid) 'DNS: فقط پاسخ، پورت نامعلوم' $(if($e.PSObject.Properties.Name -contains 'process_start_ticks'){[string]$e.process_start_ticks}else{'unknown'})
   if($identity){$key=$identity+'|'+$ip;if(-not $dnsIndex.ContainsKey($key)){$dnsIndex[$key]=New-Object Collections.Generic.List[object]};$dnsIndex[$key].Add([pscustomobject]@{domain=$name;utc=$e.observed_utc})}
  }
 }
 $flows=@();foreach($f in @($Frame.endpoints)){$flows+=,$f};foreach($e in $events){if($e.kind -ceq 'wfp_connection_block'){$flows+=,$e}}
 $seenFlows=@{}
 foreach($f in $flows){
  $denied=($f.PSObject.Properties.Name -contains 'kind' -and $f.kind -ceq 'wfp_connection_block');$flowId=$(if($denied){'wfp|'+[string]$f.event_record_id}else{'tcp|'+[string]$f.record_id});if($seenFlows.ContainsKey($flowId)){continue};$seenFlows[$flowId]=$true
  $ipText=if($denied){[string]$f.ip}else{[string]$f.remote_ip};try{$ip=Get-ObservedDestination $ipText}catch{continue}
  $port=if($denied){[int]$f.port}else{[int]$f.remote_port};$when=if($denied){[string]$f.observed_utc}else{[string]$f.last_seen_utc};$names=@{};$identity=Get-ActivityKey $f
  if($identity -and $dnsIndex.ContainsKey($identity+'|'+$ip)){
   foreach($q in $dnsIndex[$identity+'|'+$ip]){if([DateTimeOffset]::Parse($q.utc) -le [DateTimeOffset]::Parse($when)){$names[$q.domain]=$true}}
  }
  $targets=@();foreach($name in $names.Keys){$targets+=,(Package ('dns|'+$name) $name $name)}
  if(-not $targets.Count){$targets=@((Package ('exe|'+([string]$f.program_path).ToLowerInvariant()) ('بدون نام DNS — '+[IO.Path]::GetFileName($f.program_path))))}
  foreach($p in $targets){
   Route $p $f.program_path $ip ([string]$f.protocol) $port ([string]$f.pid) $(if($denied){'Security 5157: منع ثبت‌شده'}else{'TCP: نمونه، نه تحویل درخواست'}) $(if($f.PSObject.Properties.Name -contains 'process_start_ticks'){[string]$f.process_start_ticks}else{'unknown'})
   if($denied){$p.denial_records[[string]$f.event_record_id]=$true}else{$p.tcp_samples += [int]$f.samples}
  }
 }
 # Show process-only observations too; they do not invent any network endpoint.
 if($Frame.PSObject.Properties.Name -contains 'processes'){
  foreach($f in @($Frame.processes)){
   $path=[string]$f.program_path;$found=$false;foreach($p in $packages.Values){if($p.paths.ContainsKey($path.ToLowerInvariant())){$found=$true;break}}
   if(-not $found){$p=Package ('exe|'+$path.ToLowerInvariant()) ('بدون مسیر شبکه — '+[IO.Path]::GetFileName($path));$p.paths[$path.ToLowerInvariant()]=$path}
  }
 }
 foreach($p in $packages.Values){
  # Attach DNS evidence to the observed transport route rather than duplicating the same IP as an unknown-port row.
  foreach($r in @($p.routes.Values|Where-Object{-not $_.protocol})){
   $matches=@($p.routes.Values|Where-Object{$_.protocol -and $_.program_path -ieq $r.program_path -and $_.ip -ceq $r.ip})
   if($matches.Count){foreach($m in $matches){foreach($pidText in $r.pids.Keys){$m.pids[$pidText]=$true};foreach($source in $r.sources.Keys){$m.sources[$source]=$true};foreach($id in $r.identities.Keys){$m.identities[$id]=$true}};$p.routes.Remove($r.key)}
  }
  [pscustomobject]@{record_id=$p.record_id;key=$p.key;label=$p.label;domain=$p.domain;paths=@($p.paths.Values|Sort-Object);routes=@($p.routes.Values|Sort-Object program_path,ip,protocol,port);dns_count=$p.dns_records.Count;sink_count=$p.sink_records.Count;denied_count=$p.denial_records.Count;tcp_samples=$p.tcp_samples;scope='captured_routes_only; DNS_IP_correlation_not_socket_hostname_proof; identities_preserved'}
 }
}
function New-PackageTransferPlan($Package,$Routes,$Programs,[string]$Action,[string]$UnknownProtocol,[int]$PortFirst,[int]$PortLast){
 if($Action -cnotin @('blacklist','whitelist','hosts')){throw 'عملیات بسته معتبر نیست.'}
 $black=@();$white=@();$hostItems=@();$known=@{};foreach($r in $Package.routes){$known[$r.key]=$r}
 if($Action -ceq 'hosts'){
  if(-not $Package.domain){throw 'نام DNS ثبت نشده؛ از روی PTR یا IP نام حدس زده نمی‌شود.'}
  $hostItems=@((New-HostDraftRow $Package.domain 'sink'))
 }else{
  if(@($Routes).Count -eq 0){throw 'حداقل یک مسیر را تیک بزنید؛ یا خود دامنه را به hosts منتقل کنید.'}
  foreach($r in @($Routes)){
   if(-not $known.ContainsKey([string]$r.key) -or $known[$r.key].program_path -ine $r.program_path -or $known[$r.key].ip -cne $r.ip -or $known[$r.key].protocol -cne $r.protocol -or $known[$r.key].port -ne $r.port){throw 'مسیر انتخابی در همین بسته نیست؛ انتقال انجام نشد.'}
   $protocol=[string]$r.protocol;$first=[int]$r.port;$last=$first
   if($protocol -cnotin @('TCP','UDP') -or $first -lt 1 -or $first -gt 65535){
    if($UnknownProtocol -cnotin @('TCP','UDP','Any')){throw 'برای پاسخ DNS بدون پورت، پروتکل و بازه را خودتان انتخاب کنید؛ حدس زده نمی‌شود.'}
    $protocol=$UnknownProtocol;$first=$PortFirst;$last=$PortLast
    if($protocol -cne 'Any' -and ($first -lt 1 -or $first -gt $last -or $last -gt 65535)){throw 'پورت/بازهٔ صریح برای مسیر DNS لازم است.'}
   }
   $ip=Get-ObservedDestination $r.ip
   if($Action -ceq 'blacklist'){
    $registered=@($Programs|Where-Object{$_.path -ieq $r.program_path});if($registered.Count -ne 1){throw ('ابتدا EXE دقیق بسته را از برنامه‌ها ثبت کنید؛ هیچ انتقال ناقصی انجام نشد: '+$r.program_path)}
    $protos=@($protocol);if($protocol -ceq 'Any'){$protos=@('TCP','UDP');$first=1;$last=65535}
    foreach($proto in $protos){$port=$(if($first -eq $last){$first}else{[string]$first+'-'+[string]$last});$black+=,(New-IPDraftRow @($registered[0].id) $ip $proto $port $r.program_path)}
   }else{
    $value=if($protocol -ceq 'Any'){$ip+'|ANY|*'}else{$ip+'|'+$protocol+'|'+$first+$(if($first -ne $last){'-'+$last}else{''})}
    $white+=,[pscustomobject]@{value=$value;type='ip'}
   }
  }
 }
 return [pscustomobject]@{black=$black;white=$white;hosts=$hostItems;action=$Action;package_key=$Package.key;saved=$false;applied=$false;future_addresses_covered=$false}
}
function Get-PackagePulse($Previous,$Current){
 if($null -eq $Previous){if($Current.denied_count -gt 0){return 'wfp'};if($Current.sink_count -gt 0){return 'dns_sink'};if($Current.dns_count -gt 0){return 'dns'};if($Current.tcp_samples -gt 0){return 'sample'};return 'none'}
 if($Current.denied_count -gt $Previous.denied_count){return 'wfp'}
 if($Current.sink_count -gt $Previous.sink_count){return 'dns_sink'}
 if($Current.dns_count -gt $Previous.dns_count){return 'dns'}
 if($Current.tcp_samples -gt $Previous.tcp_samples){return 'sample'};return 'none'
}
