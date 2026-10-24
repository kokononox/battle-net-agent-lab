# Pure correlation and display state. No allow claim, no packet-count inference.
function Test-MonitorCidr([string]$IP,[string]$CIDR){
 try{
  $parts=$CIDR.Split('/');if($parts.Count -ne 2){return $false}
  $a=[Net.IPAddress]::Parse($IP).GetAddressBytes();$b=[Net.IPAddress]::Parse($parts[0]).GetAddressBytes();$bits=[int]$parts[1]
  if($a.Length -ne $b.Length -or $bits -lt 0 -or $bits -gt $a.Length*8){return $false}
  for($i=0;$i -lt $a.Length;$i++){
   $take=[Math]::Min(8,[Math]::Max(0,$bits-$i*8));if($take -le 0){break};$mask=(255 -shl (8-$take)) -band 255
   if(($a[$i] -band $mask) -ne ($b[$i] -band $mask)){return $false}
  };return $true
 }catch{return $false}
}
function Get-MonitorRuleState($Row,$Inventory){
 if($null -eq $Inventory -or -not $Inventory.available){return 'unknown'}
 foreach($r in @($Inventory.rules)){
  if([string]$r.program_id -cne [string]$Row.program_id -or [string]$r.program -ine [string]$Row.program_path -or [string]$r.protocol -cne [string]$Row.protocol -or [int]$r.port -ne [int]$Row.remote_port){continue}
  foreach($cidr in @($r.remote_addresses)){if(Test-MonitorCidr $Row.remote_ip $cidr){return 'verified_owned_block_snapshot'}}
 }
 if($Inventory.complete){return 'no_matching_owned_block_snapshot'};return 'unknown'
}
function Get-MonitorResultIPs([string]$Text){
 $seen=@{};foreach($part in @([regex]::Split($Text,'[;,\s]+'))){$a=$null;if($part -notmatch '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$' -and -not ($part.Contains(':') -and $part -match '^[0-9a-fA-F:.]+$')){continue};if([Net.IPAddress]::TryParse($part,[ref]$a)){$seen[$a.ToString()]=$true;if($seen.Count -ge 64){break}}};return ,@($seen.Keys|Sort-Object)
}
function New-MonitorDnsIndex($Evidence){
 $index=@{}
 foreach($e in @($Evidence.events)){
  if($e.kind -cne 'dns_query'){continue}
  foreach($ip in (Get-MonitorResultIPs ([string]$e.query_results))){
   $key=[string]$e.program_id+'|'+[string]$e.pid+'|'+$ip
   if(-not $index.ContainsKey($key)){$index[$key]=New-Object Collections.Generic.List[object]};$index[$key].Add($e)
  }
 };return $index
}
function Set-MonitorEvidence($Flows,$Inventory,$Evidence){
 $index=New-MonitorDnsIndex $Evidence
 foreach($row in $Flows.Values){
  $row['rule_state']=Get-MonitorRuleState $row $Inventory;$row['rule_checked_utc']=$Inventory.checked_utc
  $names=@{};$key=[string]$row.program_id+'|'+[string]$row.pid+'|'+[string]$row.remote_ip
  if($index.ContainsKey($key)){
   foreach($e in $index[$key]){
    try{
     $t=[DateTime]::Parse($e.observed_utc).ToUniversalTime();$birth=New-Object DateTime([long]$row.process_start_ticks,[DateTimeKind]::Utc);$last=[DateTime]::Parse($row.last_seen_utc).ToUniversalTime()
     if($t -ge $birth -and $t -le $last){$names[[string]$e.domain]=$true}
    }catch{}
   }
  }
  $row['dns_names']=@($names.Keys|Sort-Object|Select-Object -First 20);$row['dns_association']='logged_same_executable_PID_result_IP_and_time_not_socket_hostname_proof'
 }
}
function Monitor-RuleLabel([string]$State){
 switch($State){
  'verified_owned_block_snapshot'{return 'Block تأییدشده در snapshot'}
  'no_matching_owned_block_snapshot'{return 'بدون Block مطابقِ این ابزار؛ نه تضمین آزادی'}
  'wfp_denial_event'{return 'رویداد واقعی منع اتصال WFP؛ مالک نامعلوم'}
  default{return 'وضعیت قاعده نامعلوم'}
 }
}
