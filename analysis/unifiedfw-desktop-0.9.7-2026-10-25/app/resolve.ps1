$ErrorActionPreference='Stop'
# Only literal public IPs arrive from the authoritative backend; never execute hostname text.
try {
 $address=[Net.IPAddress]::Parse($env:WOW_PTR_IP)
 $rows=@(Resolve-DnsName -Name $address.ToString() -Type PTR -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
 $names=@($rows|Where-Object {$_.Type -eq 'PTR' -or $_.Type -eq 12}|ForEach-Object {[string]$_.NameHost}|Where-Object {$_}|Sort-Object -Unique)
 $state=if($names.Count){'found'}else{'no_ptr'}
 @{status=$state;names=$names}|ConvertTo-Json -Depth 4 -Compress
}catch{
 $id=[string]$_.FullyQualifiedErrorId
 $state=if($id -match 'DNS_ERROR_RCODE_NAME_ERROR|DNS_INFO_NO_RECORDS|DNS_ERROR_RECORD_DOES_NOT_EXIST'){'no_ptr'}elseif($id -match 'TIMEOUT'){'timeout'}else{'error'}
 @{status=$state;names=@()}|ConvertTo-Json -Compress
}
