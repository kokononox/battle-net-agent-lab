function Get-ObservedDestination([string]$Value){
 $ip=$null;if(-not [Net.IPAddress]::TryParse($Value,[ref]$ip)){throw 'IP رصدشده معتبر نیست.'}
 if($ip.IsIPv4MappedToIPv6){$ip=$ip.MapToIPv4()}
 if($ip.Equals([Net.IPAddress]::Any) -or $ip.Equals([Net.IPAddress]::IPv6Any) -or [Net.IPAddress]::IsLoopback($ip)){throw 'این پاسخ DNS تهی/محلی است، نه مقصد اینترنتی؛ برای انسداد نام، خود دامنه را به hosts منتقل کنید.'}
 return $ip.ToString()
}
# Pure draft operations. No IO, registration, DNS, firewall or hosts mutation.
function New-HostDraftRow([string]$Domain,[string]$Operation,[string]$Id=''){
 $name=$Domain.Trim().TrimEnd('.').ToLowerInvariant()
 if($name -notmatch '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z0-9-]+$' -or $name.Length -gt 253 -or $Operation -cnotin @('sink','remove')){throw 'نام دقیق دامنه بدون URL، wildcard یا فاصله لازم است.'}
 if(-not $Id){$Id=[guid]::NewGuid().ToString('N')}
 return [pscustomobject]@{id=$Id;domain=$name;operation=$Operation}
}
function Merge-HostDraft($Rows,$NewRow){
 $result=New-Object Collections.Generic.List[object];$matched=$false
 foreach($r in @($Rows)){
  if($r.id -ceq $NewRow.id -or $r.domain -ieq $NewRow.domain){
   if($matched){continue};$result.Add($NewRow);$matched=$true
  }else{$result.Add($r)}
 }
 if(-not $matched){$result.Add($NewRow)}
 if($result.Count -gt 500){throw 'حداکثر ۵۰۰ دامنه در پیش‌نویس پشتیبانی می‌شود.'}
 return ,$result.ToArray()
}
function New-IPDraftRow($Ids,[string]$Target,[string]$Protocol, $Port,[string]$SourcePath='',[string]$Id=''){
 if(-not $Target.Trim()){throw 'مقصد IP لازم است.'};if(-not $Id){$Id=[guid]::NewGuid().ToString('N')}
 return [pscustomobject]@{id=$Id;program_ids=@($Ids);target=$Target.Trim();protocol=$Protocol;port=$Port;source_path=$SourcePath}
}
function Export-IPDraft($Rows){
 return ,@($Rows|ForEach-Object{@{program_ids=@($_.program_ids);target=[string]$_.target;protocol=[string]$_.protocol;port=$_.port;source_path=[string]$_.source_path}})
}
function Merge-IPDraft($Rows,$NewRows){
 $result=New-Object Collections.Generic.List[object];foreach($r in @($Rows)){$result.Add($r)}
 foreach($n in @($NewRows)){
  $key=(@($n.program_ids|Sort-Object)-join ',')+'|'+$n.target.ToLowerInvariant()+'|'+$n.protocol+'|'+$n.port+'|'+$n.source_path.ToLowerInvariant()
  $found=$false
  for($i=0;$i -lt $result.Count;$i++){
   $r=$result[$i];$rk=(@($r.program_ids|Sort-Object)-join ',')+'|'+$r.target.ToLowerInvariant()+'|'+$r.protocol+'|'+$r.port+'|'+$r.source_path.ToLowerInvariant()
   if($r.id -ceq $n.id){$result[$i]=$n;$found=$true;break}
   if($rk -ceq $key){$found=$true;break}
  }
  if(-not $found){$result.Add($n)}
 }
 if($result.Count -gt 256){throw 'حداکثر ۲۵۶ ردیف بلک‌لیست پشتیبانی می‌شود.'};return ,$result.ToArray()
}
function Observed-IPDraft($Row,[string]$IP,$Programs){
 $path='';if($Row.PSObject.Properties.Name -contains 'program_path'){$path=[string]$Row.program_path}
 $ids=@($Programs|Where-Object{$_.path -ieq $path}|ForEach-Object{$_.id})
 $protocol='';$port=0
 if($Row.PSObject.Properties.Name -contains 'protocol' -and $Row.protocol -cin @('TCP','UDP')){$protocol=[string]$Row.protocol}
 if($Row.PSObject.Properties.Name -contains 'remote_port'){$port=[int]$Row.remote_port}
 elseif($Row.PSObject.Properties.Name -contains 'port'){$port=[int]$Row.port}
 # DNS answers lack transport/port. Never guess TCP/443 or bind to other checked EXEs.
 $IP=Get-ObservedDestination $IP
 return New-IPDraftRow $ids $IP $protocol $port $path
}

function Get-ObservedPortRangeSeed($Rows,$Programs){
 if(@($Rows).Count -lt 1){throw 'یک یا چند IP را از جدول IP انتخاب کنید.'}
 $path='';$ips=@{};$protocol='';$sameProtocol=$true;$firstPort=0
 foreach($row in @($Rows)){
  if($row.PSObject.Properties.Name -notcontains 'program_path' -or -not $row.program_path){throw 'مسیر EXE ردیف مشخص نیست؛ حدس زده نمی‌شود.'}
  if(-not $path){$path=[string]$row.program_path;$protocol=[string]$row.protocol;$firstPort=[int]$row.remote_port}
  elseif($path -ine $row.program_path){throw 'IPهای متعلق به یک EXE دقیق را انتخاب کنید؛ چند برنامه را خودکار به یکدیگر متصل نمی‌کنیم.'}
  if($protocol -cne $row.protocol){$sameProtocol=$false}
  $ip=$null;if(-not [Net.IPAddress]::TryParse([string]$row.remote_ip,[ref]$ip)){throw 'IP رصدشده معتبر نیست.'};$ips[$ip.ToString()]=$true
 }
 $matches=@($Programs|Where-Object{$_.path -ieq $path})
 if($matches.Count -ne 1){throw 'ابتدا همین EXE دقیق را با انتقال صریح به برنامه‌ها ثبت کنید؛ ثبت خودکار انجام نمی‌شود.'}
 return [pscustomobject]@{program_ids=@($matches[0].id);path=$path;ips=@($ips.Keys|Sort-Object);protocol=$(if($sameProtocol -and $protocol -cin @('TCP','UDP')){$protocol}else{''});port=$firstPort}
}

function Get-IPDraftKey($Row){
 return (@($Row.program_ids|Sort-Object)-join ',')+'|'+([string]$Row.target).Trim().ToLowerInvariant()+'|'+[string]$Row.protocol+'|'+[string]$Row.port
}
function Get-BlacklistDisplayRows($Draft,$Saved,$Native){
 $savedByKey=@{};foreach($r in @($Saved)){$savedByKey[(Get-IPDraftKey $r)]=$r}
 $nativeById=@{};if($null -ne $Native){foreach($entry in @($Native.entries)){$nativeById[[string]$entry.entry_id]=$entry}}
 $seen=@{};$result=New-Object Collections.Generic.List[object]
 foreach($r in @($Draft)){
  $key=Get-IPDraftKey $r;$seen[$key]=$true;$exists=$savedByKey.ContainsKey($key)
  $status='unknown';if($exists -and $nativeById.ContainsKey([string]$savedByKey[$key].id)){$status=[string]$nativeById[[string]$savedByKey[$key].id].status}
  $result.Add([pscustomobject]@{row=$r;local_state=$(if($exists){'saved'}else{'draft'});native_state=$status;view_only=$false})
 }
 foreach($r in @($Saved)){
  if($seen.ContainsKey((Get-IPDraftKey $r))){continue}
  $status=if($nativeById.ContainsKey([string]$r.id)){[string]$nativeById[[string]$r.id].status}else{'unknown'}
  $result.Add([pscustomobject]@{row=$r;local_state='pending_removal';native_state=$status;view_only=$true})
 }
 if($null -ne $Native -and $Native.PSObject.Properties.Name -contains 'orphan_rules'){
  foreach($rule in @($Native.orphan_rules)){
   $row=New-IPDraftRow @($rule.program_id) (@($rule.remote_addresses)-join ', ') $rule.protocol $rule.port $rule.program ('active-'+$rule.name)
   $result.Add([pscustomobject]@{row=$row;local_state='active_only';native_state='active_verified';view_only=$true})
  }
 };return $result.ToArray()
}

# Atomic, exact-path rebinding of explicitly selected observed drafts only.
function Bind-ObservedIPDrafts($Rows,$SelectedIds,$Programs){
 $selected=@{};foreach($id in @($SelectedIds)){$selected[[string]$id]=$true}
 if(-not $selected.Count){throw 'ردیف پیش‌نویس را انتخاب کنید.'}
 $found=@{};$next=New-Object Collections.Generic.List[object]
 foreach($row in @($Rows)){
  if(-not $selected.ContainsKey([string]$row.id)){$next.Add($row);continue}
  $found[[string]$row.id]=$true;$path=[string]$row.source_path
  if(-not $path -or $path -notmatch '^[a-zA-Z]:\\' -or [IO.Path]::GetExtension($path) -ine '.exe'){throw 'ردیف مسیر EXE معتبر ندارد؛ از ویرایش ردیف استفاده کنید.'}
  $matches=@($Programs|Where-Object{$_.path -ieq $path})
  if($matches.Count -ne 1){throw 'همین EXE دقیق هنوز ثبت نشده یا مبهم است؛ هیچ اتصال پیش‌نویسی تغییر نکرد.'}
  $next.Add((New-IPDraftRow @($matches[0].id) $row.target $row.protocol $row.port $path $row.id))
 }
 if($found.Count -ne $selected.Count){throw 'ردیف انتخابی دیگر در پیش‌نویس نیست؛ دوباره انتخاب کنید.'}
 return ,$next.ToArray()
}
