# Pure policy/configuration functions only. No firewall, VPN, DNS, registry or hosts mutations.
Set-StrictMode -Version 2.0
function PolicyDomain([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { throw 'policy_domain' }
    $s=$Value.Trim().TrimEnd('.');$idn=New-Object Globalization.IdnMapping
    try { $s=$idn.GetAscii($s).ToLowerInvariant() } catch { throw 'policy_domain' }
    if ($s.Length -gt 253 -or $s -notmatch '\.' -or $s -match '[:/\\*\s]') { throw 'policy_domain' }
    $asIp=$null;if ([Net.IPAddress]::TryParse($s,[ref]$asIp)) { throw 'policy_domain_is_ip' }
    foreach ($label in ($s -split '\.')) { if ($label -cnotmatch '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$') { throw 'policy_domain' } }
    return $s
}
function PolicyIp([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -match '[/\s%]') { throw 'policy_ip' }
    $ip=$null;if (-not [Net.IPAddress]::TryParse($Value,[ref]$ip)) { throw 'policy_ip' }
    if ($ip.IsIPv4MappedToIPv6 -or [Net.IPAddress]::IsLoopback($ip) -or $ip.Equals([Net.IPAddress]::Any) -or $ip.Equals([Net.IPAddress]::IPv6Any) -or $ip.IsIPv6Multicast -or $ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal) { throw 'policy_ip' }
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { $b=$ip.GetAddressBytes();if ($b[0] -eq 0 -or $b[0] -ge 224 -or ($b[0] -eq 169 -and $b[1] -eq 254)) { throw 'policy_ip' } }
    return $ip.ToString()
}
function PolicyConfig($Config) {
    if ($null -eq $Config -or (@($Config.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'domains,ip_addresses,schema' -or $Config.schema -cne 'sstp-allowlist-config-1') { throw 'policy_config_schema' }
    if ($null -eq $Config.domains -or $null -eq $Config.ip_addresses -or $Config.domains -is [string] -or $Config.ip_addresses -is [string]) { throw 'policy_config_arrays' }
    $domains=@($Config.domains | ForEach-Object { if ($_ -isnot [string]) { throw 'policy_domain_type' };PolicyDomain $_ } | Sort-Object -Unique)
    $ips=@($Config.ip_addresses | ForEach-Object { if ($_ -isnot [string]) { throw 'policy_ip_type' };PolicyIp $_ } | Sort-Object -Unique)
    if ($domains.Count -gt 64 -or $ips.Count -gt 256 -or ($domains.Count+$ips.Count) -eq 0) { throw 'policy_config_size' }
    return [pscustomobject][ordered]@{schema='sstp-allowlist-config-1';domains=$domains;ip_addresses=$ips}
}
function EditPolicyConfig($Config,[ValidateSet('Add','Remove')][string]$Operation,[string]$Address) {
    $c=PolicyConfig $Config;$kind='domain';$value=$null
    try { $value=PolicyIp $Address;$kind='ip' } catch { $value=PolicyDomain $Address }
    $domains=@($c.domains);$ips=@($c.ip_addresses)
    if ($kind -eq 'ip') { if ($Operation -eq 'Add') { $ips+=,$value } else { $ips=@($ips | Where-Object { $_ -cne $value }) } }
    else { if ($Operation -eq 'Add') { $domains+=,$value } else { $domains=@($domains | Where-Object { $_ -cne $value }) } }
    return (PolicyConfig ([pscustomobject]@{schema=$c.schema;domains=$domains;ip_addresses=$ips}))
}
