# Pure frame matching for multiple executable paths. No system calls.
Set-StrictMode -Version 2.0
function Add-TcpFrame($Programs,$Before,$After,$Connections,[hashtable]$Flows,[string]$Utc,[int]$Cap=5000){
 $paths=@{};foreach($p in $Programs){$paths[([string]$p.path).ToLowerInvariant()]=$p}
 $beforeMap=@{};foreach($p in $Before){$beforeMap[[string]$p.pid]=$p}
 $afterMap=@{};foreach($p in $After){$afterMap[[string]$p.pid]=$p}
 $truncated=$false;$frameSeen=@{}
 foreach($c in $Connections){
  $key=[string]$c.pid;if(-not $beforeMap.ContainsKey($key) -or -not $afterMap.ContainsKey($key)){continue}
  $b=$beforeMap[$key];$a=$afterMap[$key];$path=([string]$b.path).ToLowerInvariant()
  if(-not $paths.ContainsKey($path) -or [string]$b.ticks -cne [string]$a.ticks -or [string]$b.path -ine [string]$a.path){continue}
  if([int]$c.remote_port -lt 1 -or [int]$c.remote_port -gt 65535){continue}
  $remote=$null;$local=$null
  if(-not [Net.IPAddress]::TryParse([string]$c.remote_ip,[ref]$remote) -or -not [Net.IPAddress]::TryParse([string]$c.local_ip,[ref]$local)){continue}
  if($remote.Equals([Net.IPAddress]::Any) -or $remote.Equals([Net.IPAddress]::IPv6Any)){continue}
  $program=$paths[$path]
  $flowKey=([string]$program.id)+'|'+$key+'|'+[string]$b.ticks+'|'+$local.ToString()+'|'+[string]$c.local_port+'|'+$remote.ToString()+'|'+[string]$c.remote_port+'|TCP'
  if($frameSeen.ContainsKey($flowKey)){continue};$frameSeen[$flowKey]=$true
  if(-not $Flows.ContainsKey($flowKey)){
   if($Flows.Count -ge $Cap){$truncated=$true;continue}
   $Flows[$flowKey]=[ordered]@{record_id=[guid]::NewGuid().ToString('N');program_id=[string]$program.id;program_path=[string]$program.path;pid=[int]$b.pid;process_start_ticks=[string]$b.ticks;protocol='TCP';local_ip=$local.ToString();local_port=[int]$c.local_port;remote_ip=$remote.ToString();remote_port=[int]$c.remote_port;first_seen_utc=$Utc;last_seen_utc=$Utc;samples=0;states=@{}}
  }
  $row=$Flows[$flowKey];$row.samples++;$row.last_seen_utc=$Utc
  $state=[string]$c.state;if($state -notin @('Closed','Listen','SynSent','SynReceived','Established','FinWait1','FinWait2','CloseWait','Closing','LastAck','TimeWait','DeleteTCB')){$state='Unknown'}
  if(-not $row.states.ContainsKey($state)){$row.states[$state]=0};$row.states[$state]++
 }
 return $truncated
}
