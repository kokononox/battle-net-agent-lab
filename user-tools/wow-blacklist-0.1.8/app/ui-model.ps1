# Strict literal IPv4/IPv6 and CIDR parser. Backend validates public-only coverage.
function Ui-Target([string]$value) {
 $parts=$value.Split('/');$raw=$parts[0]
 if($raw.Contains(':')){$addr=[Net.IPAddress]::Parse($raw);if($addr.AddressFamily -ne 'InterNetworkV6'){throw 'invalid_ipv6'}}else{
  if($raw -notmatch '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$'){throw 'invalid_ipv4'}
  $addr=[Net.IPAddress]::Parse($raw)
 }
 $bytes=$addr.GetAddressBytes();$bits=$bytes.Length*8
 if($parts.Count -eq 1){return $addr.ToString()}
 if($parts.Count -ne 2 -or $parts[1] -notmatch '^[0-9]{1,3}$'){throw 'invalid_prefix'}
 $prefix=[int]$parts[1];if($prefix -lt 0 -or $prefix -gt $bits){throw 'invalid_prefix'}
 for($i=0;$i -lt $bytes.Length;$i++){$keep=[Math]::Min(8,[Math]::Max(0,$prefix-8*$i));$mask=if($keep -eq 0){0}else{(255 -shl (8-$keep)) -band 255};if(($bytes[$i] -band $mask) -ne $bytes[$i]){throw 'network_boundary_required'}}
 if($prefix -eq $bits){return $addr.ToString()};return $addr.ToString()+'/'+$prefix
}
function Ui-Contains($entry,[string]$address) {
 $parts=([string]$entry.ip).Split('/');$a=([Net.IPAddress]::Parse($parts[0])).GetAddressBytes();$b=([Net.IPAddress]::Parse($address)).GetAddressBytes()
 if($a.Length -ne $b.Length){return $false};$prefix=if($parts.Count -eq 2){[int]$parts[1]}else{$a.Length*8}
 for($i=0;$i -lt $a.Length;$i++){$keep=[Math]::Min(8,[Math]::Max(0,$prefix-8*$i));$mask=if($keep -eq 0){0}else{(255 -shl (8-$keep)) -band 255};if(($a[$i] -band $mask) -ne ($b[$i] -band $mask)){return $false}};return $true
}
# Pure UI list operations; backend remains authoritative for public-IP validation.
function Ui-Key($entry) { return ([string]$entry.ip).ToLowerInvariant()+'|'+[string]$entry.port+'|'+([string]$entry.protocol).ToUpperInvariant() }
function Ui-Parse([string]$text) {
 $seen=@{};$result=New-Object Collections.Generic.List[object];$lineNumber=0
 foreach($raw in ($text -split '\r?\n')){
  $lineNumber++;$line=($raw -split '#',2)[0].Trim();if(!$line){continue}
  if($line -notmatch '^(\[[0-9a-fA-F:]+(?:/[0-9]{1,3})?\]|[0-9.]+(?:/[0-9]{1,2})?):([0-9]{1,5})\s+(TCP|UDP)$'){throw ('invalid_line_'+$lineNumber)}
  $target=$Matches[1].Trim('[',']');$port=[int]$Matches[2];$proto=$Matches[3].ToUpperInvariant();$ip=Ui-Target $target
  if($port -lt 1 -or $port -gt 65535){throw ('invalid_port_line_'+$lineNumber)}
  $e=[pscustomobject]@{ip=$ip;port=$port;protocol=$proto};$key=Ui-Key $e
  if(!$seen.ContainsKey($key)){$seen[$key]=$true;$result.Add($e)}
  if($result.Count -gt 100){throw 'too_many_entries'}
 }
 return @($result.ToArray() | Sort-Object @{Expression={([Net.IPAddress]::Parse(($_.ip.Split('/'))[0])).GetAddressBytes().Length}},@{Expression={[BitConverter]::ToString(([Net.IPAddress]::Parse(($_.ip.Split('/'))[0])).GetAddressBytes())}},port,protocol)
}
function Ui-Text($entries) {
 return (@($entries | ForEach-Object { $ip=if($_.ip.Contains(':')){'['+$_.ip+']'}else{$_.ip};$ip+':'+[string]$_.port+' '+$_.protocol }) -join [Environment]::NewLine)
}
function Ui-Without($entries,$keys) { return @($entries | Where-Object { (Ui-Key $_) -notin $keys }) }
# View-only partition: the original observation array is never modified or truncated here.
function Ui-ObservationPartition($rows,[bool]$freshOnly,[bool]$hideCovered) {
 $main=New-Object Collections.Generic.List[object];$coveredRows=New-Object Collections.Generic.List[object];$oldHidden=0;$matchCount=0
 foreach($entry in @($rows)){
  if($entry.covered_by_verified_block){$matchCount++}
  if($freshOnly -and !$entry.fresh_process_seen){$oldHidden++;continue}
  if($entry.covered_by_verified_block){$coveredRows.Add($entry);if(!$hideCovered){$main.Add($entry)}}else{$main.Add($entry)}
 }
 return [pscustomobject]@{main=@($main.ToArray());covered=@($coveredRows.ToArray());old_hidden=$oldHidden;match_count=$matchCount}
}
