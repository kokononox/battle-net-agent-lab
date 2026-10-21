# Pure UI list operations; backend remains authoritative for public-IP validation.
function Ui-Key($entry) { return ([string]$entry.ip).ToLowerInvariant()+'|'+[string]$entry.port+'|'+([string]$entry.protocol).ToUpperInvariant() }
function Ui-Parse([string]$text) {
 $seen=@{};$result=New-Object Collections.Generic.List[object];$lineNumber=0
 foreach($raw in ($text -split '\r?\n')){
  $lineNumber++;$line=($raw -split '#',2)[0].Trim();if(!$line){continue}
  if($line -notmatch '^(\[[0-9a-fA-F:]+\]|[0-9.]+):([0-9]{1,5})\s+(TCP|UDP)$'){throw ('invalid_line_'+$lineNumber)}
  $ip=([Net.IPAddress]::Parse($Matches[1].Trim('[',']'))).ToString();$port=[int]$Matches[2];$proto=$Matches[3].ToUpperInvariant()
  if($port -lt 1 -or $port -gt 65535){throw ('invalid_port_line_'+$lineNumber)}
  $e=[pscustomobject]@{ip=$ip;port=$port;protocol=$proto};$key=Ui-Key $e
  if(!$seen.ContainsKey($key)){$seen[$key]=$true;$result.Add($e)}
  if($result.Count -gt 100){throw 'too_many_entries'}
 }
 return @($result.ToArray() | Sort-Object @{Expression={([Net.IPAddress]::Parse($_.ip)).GetAddressBytes().Length}},@{Expression={[BitConverter]::ToString(([Net.IPAddress]::Parse($_.ip)).GetAddressBytes())}},port,protocol)
}
function Ui-Text($entries) {
 return (@($entries | ForEach-Object { $ip=if($_.ip.Contains(':')){'['+$_.ip+']'}else{$_.ip};$ip+':'+[string]$_.port+' '+$_.protocol }) -join [Environment]::NewLine)
}
function Ui-Without($entries,$keys) { return @($entries | Where-Object { (Ui-Key $_) -notin $keys }) }
