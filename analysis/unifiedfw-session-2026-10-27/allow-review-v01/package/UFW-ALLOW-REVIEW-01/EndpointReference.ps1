function Get-UfwRuntimeEndpoint([string]$Address,[int]$Port,[int]$Protocol){
 if($Port -lt 1 -or $Port -gt 65535 -or $Protocol -cnotin @(6,17)){return $null}
 $ip=$null;if(-not [Net.IPAddress]::TryParse($Address,[ref]$ip)){throw 'ufw_runtime_event_ip'}
 if($ip.IsIPv4MappedToIPv6){$ip=$ip.MapToIPv4()};$v4=$ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork;$bytes=$ip.GetAddressBytes()
 if([Net.IPAddress]::IsLoopback($ip) -or $ip.Equals([Net.IPAddress]::Any) -or $ip.Equals([Net.IPAddress]::IPv6Any) -or ($v4 -and ($bytes[0] -eq 0 -or $bytes[0] -ge 224 -or ($bytes[0] -eq 169 -and $bytes[1] -eq 254))) -or (-not $v4 -and ($ip.IsIPv6Multicast -or $ip.IsIPv6LinkLocal -or $ip.ScopeId -ne 0))){return $null}
 return [pscustomobject]@{address=$ip.ToString();port=$Port;protocol=$(if($Protocol -eq 6){'TCP'}else{'UDP'})}
}
