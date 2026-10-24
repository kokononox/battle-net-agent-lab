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
function New-IPDraftRow($Ids,[string]$Target,[string]$Protocol,[int]$Port,[string]$SourcePath='',[string]$Id=''){
 if(-not $Target.Trim()){throw 'مقصد IP لازم است.'};if(-not $Id){$Id=[guid]::NewGuid().ToString('N')}
 return [pscustomobject]@{id=$Id;program_ids=@($Ids);target=$Target.Trim();protocol=$Protocol;port=$Port;source_path=$SourcePath}
}
function Export-IPDraft($Rows){
 return ,@($Rows|ForEach-Object{@{program_ids=@($_.program_ids);target=[string]$_.target;protocol=[string]$_.protocol;port=[int]$_.port;source_path=[string]$_.source_path}})
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
 return New-IPDraftRow $ids $IP $protocol $port $path
}
