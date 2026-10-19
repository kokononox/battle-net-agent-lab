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
function SelectPolicyVpn($Profiles,[string]$ExplicitName='',[string]$PreferredName='holand') {
    $sstp=@($Profiles | Where-Object { $_.tunnel_type -ieq 'Sstp' })
    if ($ExplicitName) {
        $matches=@($sstp | Where-Object { $_.name -ieq $ExplicitName })
        if ($matches.Count -ne 1) { throw 'policy_explicit_profile_ambiguous' };return $matches[0]
    }
    $connected=@($sstp | Where-Object { $_.connected -eq $true })
    if ($connected.Count -gt 1) { throw 'policy_active_profile_ambiguous' }
    if ($connected.Count -eq 1) { return $connected[0] }
    if ($sstp.Count -eq 1) { return $sstp[0] }
    $preferred=@($sstp | Where-Object { $_.name -ieq $PreferredName })
    if ($preferred.Count -eq 1) { return $preferred[0] }
    throw 'policy_available_profile_ambiguous'
}
function NewPolicyPlan($Config,$Profiles,$ResolvedTargets,$ServerIps,$TunnelDnsIps=@(),[string]$ExplicitName='') {
    $c=PolicyConfig $Config;$vpn=SelectPolicyVpn $Profiles $ExplicitName
    $targets=@($c.ip_addresses)
    foreach ($domain in $c.domains) {
        if (-not $ResolvedTargets.Contains($domain)) { throw 'policy_target_snapshot_missing' }
        $resolved=@($ResolvedTargets[$domain]);if ($resolved.Count -eq 0 -or $resolved.Count -gt 64) { throw 'policy_target_snapshot_empty' }
        foreach ($ip in $resolved) { $targets+=,(PolicyIp ([string]$ip)) }
    }
    $targets=@($targets | Sort-Object -Unique);if ($targets.Count -gt 512) { throw 'policy_target_cap' }
    $server=@($ServerIps | ForEach-Object { PolicyIp ([string]$_) } | Sort-Object -Unique)
    if ($server.Count -lt 1 -or $server.Count -gt 32) { throw 'policy_server_snapshot' }
    $dns=@($TunnelDnsIps | ForEach-Object { PolicyIp ([string]$_) } | Sort-Object -Unique);if ($dns.Count -gt 8) { throw 'policy_dns_cap' }
    return [pscustomobject][ordered]@{
        schema='sstp-allowlist-plan-1';policy_kind='allowlist_plus_vpn_kill_switch';profile_name=$vpn.name;profile_scope=$vpn.scope;profile_connected=[bool]$vpn.connected
        allow_target_ips=$targets;vpn_transport_ips=$server;vpn_transport_protocol='TCP';vpn_transport_remote_port=443;vpn_transport_service='SstpSvc'
        allowed_data_path='selected_sstp_interface_only';tunnel_dns_ips=$dns;dns_outside_tunnel_allowed=$false;ordinary_lan_allowed=$false
        default_for_other_destinations='deny';on_disconnect='deny';on_unknown_or_changed_binding='deny_until_explicit_refresh';on_unresolved_target='deny'
        auto_connect=$false;resident_process_required=$false;custom_resident_service_required=$false;recurring_task_required=$false;automatic_expiry=$false;persist_across_reboot=$true
        disable_strategy='restore_only_own_journal_under_transition_guard';existing_allow_policy='block_until_existing_local_allows_are_accounted_for';gpo_or_unmanaged_allow_policy='stop_without_weakened_fallback'
        domain_semantics='IP_snapshot_not_exclusive_hostname_identity';domain_refresh='explicit_one_shot_only';data_content_privacy_guaranteed=$false
        selected_interface_binding_qualified=$false;enforcement_tested=$false;user_device_tested=$false;ready_for_user_apply=$false
    }
}
