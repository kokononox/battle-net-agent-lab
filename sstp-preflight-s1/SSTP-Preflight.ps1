[CmdletBinding()]
param([string]$VpnProfileName = 'holand', [switch]$SelfTest)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:QueryErrors = New-Object System.Collections.ArrayList

function Field($Object, [string]$Name, $Default = $null) {
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop -or $null -eq $prop.Value) { return $Default }
    return $prop.Value
}
function QueryError([string]$Stage, $Record) {
    [void]$script:QueryErrors.Add([ordered]@{stage=$Stage; category=[string]$Record.CategoryInfo.Category; hresult=$Record.Exception.HResult})
}
function AddressScope([string]$Address) {
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$ip)) { return 'invalid' }
    if ([Net.IPAddress]::IsLoopback($ip)) { return 'loopback' }
    $b = $ip.GetAddressBytes()
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        if ($b[0] -eq 0) { return 'unspecified_or_reserved' }
        if ($b[0] -eq 10 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168)) { return 'private' }
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return 'link_local' }
        if ($b[0] -ge 224) { return 'multicast_or_reserved' }
        return 'other_unicast_not_public_ownership_verified'
    }
    if ($ip.Equals([Net.IPAddress]::IPv6Any)) { return 'unspecified' }
    if ($ip.IsIPv6LinkLocal) { return 'link_local' }
    if ($ip.IsIPv6Multicast) { return 'multicast' }
    if (($b[0] -band 254) -eq 252) { return 'private' }
    return 'other_unicast_not_public_ownership_verified'
}
function ServerMeta([string]$Value) {
    $answer = [ordered]@{state='unrecognized_redacted'; address=$null; port=$null; port_source=$null}
    $Value = $Value.Trim()
    $ip = $null
    if ([Net.IPAddress]::TryParse($Value,[ref]$ip)) {
        $answer.state='parsed'; $answer.address=$ip.ToString(); $answer.port=443; $answer.port_source='sstp_default_not_live_verified'; return $answer
    }
    try {
        $text = $Value
        if (-not $text.StartsWith('https://',[StringComparison]::OrdinalIgnoreCase)) { $text='https://' + $text }
        $uri = [Uri]$text
        if ($uri.Scheme -ne 'https' -or $uri.UserInfo -ne '' -or $uri.Query -ne '' -or $uri.Fragment -ne '' -or $uri.AbsolutePath -ne '/') { return $answer }
        $name = $uri.DnsSafeHost.ToLowerInvariant().TrimEnd('.')
        $valid = ($name.Length -le 253 -and $name -match '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$')
        foreach ($label in $name.Split('.')) { if ($label.Length -gt 63 -or $label -notmatch '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$') { $valid=$false } }
        if (-not $valid) { return $answer }
        $answer.state='parsed'; $answer.address=$name; $answer.port=$uri.Port
        $answer.port_source='uri_port_or_sstp_default_not_live_verified'
    } catch { }
    return $answer
}
function ProfileMeta($Raw, [string]$Scope) {
    return [ordered]@{name=[string](Field $Raw 'Name' ''); scope=$Scope;
        connection_status=[string](Field $Raw 'ConnectionStatus' 'unknown');
        tunnel_type=[string](Field $Raw 'TunnelType' 'unknown');
        split_tunneling=(Field $Raw 'SplitTunneling');
        server=(ServerMeta ([string](Field $Raw 'ServerAddress' '')))}
}
function GroupCounts($Items, [string]$Property, $Allowed) {
    $result=[ordered]@{}
    foreach ($item in @($Items)) {
        $key=[string](Field $item $Property 'Unknown')
        if ($Allowed -notcontains $key) { $key='Unknown' }
        if (-not $result.Contains($key)) { $result[$key]=0 }
        $result[$key]++
    }
    return $result
}
function ResolveMeta([string]$Name, [string]$Stage) {
    $addresses=@(); $state='not_tested'
    try {
        $addresses=@([Net.Dns]::GetHostAddresses($Name) | ForEach-Object { $_.ToString() } | Sort-Object -Unique | Select-Object -First 32)
        $state='resolved'
        if ($addresses.Count -eq 0) { $state='no_addresses' }
    } catch { $state='resolution_failed'; QueryError $Stage $_ }
    return [ordered]@{name=$Name; state=$state; addresses=$addresses; snapshot_only=$true; all_future_addresses_known=$false}
}
function RouteMeta([string]$RemoteAddress, $VpnIndices) {
    $result=[ordered]@{remote_address=$RemoteAddress; state='not_tested'; interface_indices=@(); uses_exact_profile_interface=$null; matched_prefix_lengths=@()}
    try {
        $found=@(Find-NetRoute -RemoteIPAddress $RemoteAddress -ErrorAction Stop)
        $indices=@($found | ForEach-Object { $v=Field $_ 'InterfaceIndex'; if ($null -ne $v) { [int]$v } } | Sort-Object -Unique)
        $prefixes=@($found | ForEach-Object { $v=[string](Field $_ 'DestinationPrefix' ''); if ($v.Contains('/')) { [int]$v.Split('/')[-1] } } | Sort-Object -Unique)
        $result.state='queried'; $result.interface_indices=$indices; $result.matched_prefix_lengths=$prefixes
        if ($indices.Count -eq 1 -and @($VpnIndices).Count -gt 0) { $result.uses_exact_profile_interface=(@($VpnIndices) -contains $indices[0]) }
    } catch { $result.state='unavailable'; QueryError 'find_route' $_ }
    return $result
}
function RunSelfTest {
    $script:Tests=0
    function Check($Condition) { if (-not $Condition) { throw 'fixture_assertion_failed' }; $script:Tests++ }
    $s=ServerMeta 'vpn.example.invalid'; Check ($s.address -eq 'vpn.example.invalid' -and $s.port -eq 443)
    $s=ServerMeta '203.0.113.44'; Check ($s.address -eq '203.0.113.44' -and $s.port_source -eq 'sstp_default_not_live_verified')
    $s=ServerMeta 'https://vpn.example.invalid:444/'; Check ($s.port -eq 444)
    $s=ServerMeta 'https://PRIVATE_USER:PRIVATE_PASSWORD@vpn.example.invalid/'; Check ($s.state -eq 'unrecognized_redacted' -and $null -eq $s.address)
    $s=ServerMeta 'https://vpn.example.invalid/private?token=PRIVATE'; Check ($s.state -eq 'unrecognized_redacted')
    $s=ServerMeta 'bad label.example.invalid'; Check ($s.state -eq 'unrecognized_redacted')
    $s=ServerMeta '2001:db8::1'; Check ($s.state -eq 'parsed' -and $s.port -eq 443)
    Check ((AddressScope '127.0.0.1') -eq 'loopback')
    Check ((AddressScope '0.0.0.0') -eq 'unspecified_or_reserved')
    Check ((AddressScope '192.168.1.1') -eq 'private')
    Check ((AddressScope '172.31.1.1') -eq 'private')
    Check ((AddressScope '169.254.4.1') -eq 'link_local')
    Check ((AddressScope '::1') -eq 'loopback')
    Check ((AddressScope 'fc00::1') -eq 'private')
    Check ((AddressScope 'not-an-address') -eq 'invalid')
    $raw=[pscustomobject]@{Name='holand';ServerAddress='vpn.example.invalid';ConnectionStatus='Connected';TunnelType='Sstp';SplitTunneling=$false;UserName='PRIVATE_USER';Password='PRIVATE_PASSWORD';L2tpPsk='PRIVATE_KEY'}
    $m=ProfileMeta $raw 'user'; $json=$m | ConvertTo-Json -Depth 8
    Check (-not $json.Contains('PRIVATE_'))
    Check ($m.name -eq 'holand' -and $m.tunnel_type -eq 'Sstp')
    $counts=GroupCounts @([pscustomobject]@{Action='Allow'},[pscustomobject]@{Action='Allow'},[pscustomobject]@{Action='Block'}) 'Action' @('Allow','Block')
    Check ($counts['Allow'] -eq 2 -and $counts['Block'] -eq 1)
    $counts=GroupCounts @([pscustomobject]@{PolicyStoreSourceType='PRIVATE_POLICY'}) 'PolicyStoreSourceType' @('Local','GroupPolicy')
    Check ($counts.Contains('Unknown') -and -not $counts.Contains('PRIVATE_POLICY'))
    Check ((Field ([pscustomobject]@{}) 'Missing' 'fallback') -eq 'fallback')
    return [ordered]@{schema='s1-preflight-fixture-1';passed=$true;tests=$script:Tests;real_vpn_or_firewall_queried=$false;network_dns_queried=$false;settings_changed=$false}
}
function RunPreflight {
    $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run_preflight_as_administrator' }
    Write-Host 'S1 SSTP isolation PREFLIGHT ONLY - no firewall/route/VPN changes.'
    Write-Host 'Keep game update PAUSED and WoW CLOSED. Do not Resume.'
    Write-Host 'Reads only the named VPN profile, routes, firewall policy and SSTP service TCP candidates.'
    Write-Host 'DNS lookups for the VPN server and level3.blizzard.com may contact the current DNS resolver.'
    $started=[DateTime]::UtcNow.ToString('o')
    $candidates=New-Object System.Collections.ArrayList
    $lookups=[ordered]@{user='not_tested';all_user='not_tested'}
    foreach ($scope in @('user','all_user')) {
        try {
            if ($scope -eq 'user') { $found=@(Get-VpnConnection -Name $VpnProfileName -ErrorAction Stop) }
            else { $found=@(Get-VpnConnection -Name $VpnProfileName -AllUserConnection -ErrorAction Stop) }
            $lookups[$scope]='queried'
            foreach ($v in $found) { if ([string](Field $v 'Name' '') -eq $VpnProfileName) { [void]$candidates.Add((ProfileMeta $v $scope)) } }
        } catch { $lookups[$scope]='not_found_or_unavailable' }
    }
    $profile=$null; $profileState='not_found_or_unavailable'
    if ($candidates.Count -eq 1) { $profile=$candidates[0]; $profileState='one_exact_match' }
    elseif ($candidates.Count -gt 1) { $profileState='ambiguous_same_name_multiple_scopes' }
    $interfaces=@(); $vpnIndices=@()
    try {
        $interfaces=@(Get-NetIPInterface -ErrorAction Stop | Where-Object { $_.InterfaceAlias -eq $VpnProfileName } | ForEach-Object {
            [ordered]@{interface_index=[int]$_.InterfaceIndex; address_family=[string]$_.AddressFamily; connection_state=[string]$_.ConnectionState; interface_metric=$_.InterfaceMetric; mtu_bytes=(Field $_ 'NlMtu' (Field $_ 'NlMtuBytes'))}
        })
        $vpnIndices=@($interfaces | ForEach-Object { $_.interface_index } | Sort-Object -Unique)
    } catch { QueryError 'vpn_interfaces' $_ }
    $serverResolution=$null
    if ($null -ne $profile -and $profile.server.state -eq 'parsed') { $serverResolution=ResolveMeta $profile.server.address 'vpn_server_dns' }
    $cdnResolution=ResolveMeta 'level3.blizzard.com' 'level3_dns'
    $defaultRoutes=@()
    try {
        $defaultRoutes=@(Get-NetRoute -ErrorAction Stop | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } | ForEach-Object {
            [ordered]@{address_family=[string]$_.AddressFamily; interface_index=[int]$_.InterfaceIndex; route_metric=$_.RouteMetric; next_hop_scope=(AddressScope ([string]$_.NextHop)); exact_vpn_interface=($vpnIndices -contains [int]$_.InterfaceIndex)}
        })
    } catch { QueryError 'default_routes' $_ }
    $routeChecks=@(); $allAddresses=@()
    if ($null -ne $serverResolution) { $allAddresses+=@($serverResolution.addresses) }
    $allAddresses+=@($cdnResolution.addresses)
    foreach ($address in @($allAddresses | Sort-Object -Unique | Select-Object -First 32)) { $routeChecks+=,(RouteMeta $address $vpnIndices) }
    $firewallProfiles=@(); $ruleCounts=$null; $services=@(); $outerCandidates=@()
    try {
        $firewallProfiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
            [ordered]@{name=[string]$_.Name; enabled=[string]$_.Enabled; default_inbound_action=[string]$_.DefaultInboundAction; default_outbound_action=[string]$_.DefaultOutboundAction;
                allow_local_firewall_rules=[string](Field $_ 'AllowLocalFirewallRules' 'Unknown'); allow_local_ipsec_rules=[string](Field $_ 'AllowLocalIPsecRules' 'Unknown')}
        })
    } catch { QueryError 'firewall_profiles' $_ }
    try {
        $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Enabled True -ErrorAction Stop | Select-Object -First 10001)
        $ruleCounts=[ordered]@{enabled_outbound_rules=$rules.Count; list_truncated=($rules.Count -gt 10000);
            action_counts=(GroupCounts $rules 'Action' @('Allow','Block','NotConfigured'));
            source_type_counts=(GroupCounts $rules 'PolicyStoreSourceType' @('Local','GroupPolicy','Dynamic','Generated','Hardcoded'));
            rule_names_program_paths_remote_addresses_or_policy_names_exported=$false}
    } catch { QueryError 'firewall_rules' $_ }
    try {
        $services=@(Get-CimInstance -ClassName Win32_Service -Filter "Name='SstpSvc' OR Name='RasMan' OR Name='MpsSvc' OR Name='BFE' OR Name='Schedule'" -ErrorAction Stop | ForEach-Object {
            [ordered]@{name=[string]$_.Name; state=[string]$_.State; process_id=[int]$_.ProcessId}
        })
        $serviceIds=@($services | Where-Object { $_.name -in @('SstpSvc','RasMan') -and $_.process_id -gt 0 } | ForEach-Object { $_.process_id })
        $expectedPort=443
        if ($null -ne $profile -and $null -ne $profile.server.port) { $expectedPort=[int]$profile.server.port }
        $outerCandidates=@(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $serviceIds -contains [int]$_.OwningProcess -and [int]$_.RemotePort -eq $expectedPort -and ([string]$_.State -in @('Established','SynSent','CloseWait')) } | Select-Object -First 32 | ForEach-Object {
            $matches=$false
            if ($null -ne $serverResolution) { $matches=(@($serverResolution.addresses) -contains [string]$_.RemoteAddress) }
            [ordered]@{remote_address=[string]$_.RemoteAddress; remote_port=[int]$_.RemotePort; owning_process_id=[int]$_.OwningProcess; state=[string]$_.State; matches_server_dns_snapshot=$matches; exact_profile_binding_proven=$false}
        })
    } catch { QueryError 'services_or_sstp_tcp' $_ }
    $killSwitch=[ordered]@{group='SSTP Kill Switch'; saved_state_file_present=$false; saved_state_contents_read=$false; enabled_outbound_group_rules=@(); filter_queries_complete=$true}
    try { $killSwitch.saved_state_file_present=(Test-Path -LiteralPath (Join-Path $env:ProgramData 'SstpKillSwitch\firewall-state.json')) } catch { QueryError 'kill_switch_state_presence' $_ }
    if ($null -ne $ruleCounts) {
        $knownNames=@('SSTP Allow VPN tunnel traffic','SSTP Allow server TCP 443','SSTP Allow DNS UDP','SSTP Allow DNS TCP','SSTP Allow DHCPv4','SSTP Allow DHCPv6')
        foreach ($rule in @($rules | Where-Object { [string](Field $_ 'Group' '') -eq 'SSTP Kill Switch' })) {
            try {
                $label='other_group_rule_name_omitted'
                $display=[string](Field $rule 'DisplayName' '')
                if ($knownNames -contains $display) { $label=$display }
                $af=@($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
                $pf=@($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
                $it=@($rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop)
                $apps=@($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
                $addresses=@($af | ForEach-Object { @(Field $_ 'RemoteAddress' @()) })
                $types=@($it | ForEach-Object { [string](Field $_ 'InterfaceType' 'Unknown') } | ForEach-Object { if ($_ -in @('Any','RemoteAccess','Lan','Wireless')) { $_ } else { 'Other' } })
                $ports=@($pf | ForEach-Object { @(Field $_ 'RemotePort' @()) } | ForEach-Object { $x=[string]$_; if ($x -in @('Any','443','53','67','68','546','547')) { $x } else { 'OtherPortOrRange' } })
                $protocols=@($pf | ForEach-Object { [string](Field $_ 'Protocol' 'Unknown') } | ForEach-Object { if ($_ -in @('Any','TCP','UDP','6','17','256')) { $_ } else { 'Other' } })
                $appAny=(@($apps | Where-Object { [string](Field $_ 'Program' '') -eq 'Any' }).Count -gt 0)
                $killSwitch.enabled_outbound_group_rules+=,[ordered]@{kind=$label; action=[string](Field $rule 'Action' 'Unknown'); interface_types=$types;
                    protocols=$protocols; remote_ports=$ports; remote_address_any=($addresses -contains 'Any'); remote_address_filter_items=$addresses.Count; application_any=$appAny}
            } catch { $killSwitch.filter_queries_complete=$false; QueryError 'kill_switch_rule_filters' $_ }
        }
    }
    $blockers=New-Object System.Collections.ArrayList
    if ($profileState -ne 'one_exact_match') { [void]$blockers.Add('vpn_profile_not_unambiguous') }
    if ($null -ne $profile) {
        if ($profile.connection_status -ne 'Connected') { [void]$blockers.Add('vpn_not_reported_connected') }
        if ($profile.tunnel_type -ne 'Sstp') { [void]$blockers.Add('profile_type_not_explicit_sstp') }
        if ($profile.server.state -ne 'parsed') { [void]$blockers.Add('server_address_not_recognized') }
    }
    if ($vpnIndices.Count -ne 1) { [void]$blockers.Add('exact_vpn_interface_not_unambiguous') }
    if ($null -eq $serverResolution -or $serverResolution.state -ne 'resolved') { [void]$blockers.Add('vpn_server_addresses_not_resolved') }
    if ($cdnResolution.state -ne 'resolved') { [void]$blockers.Add('level3_addresses_not_resolved') }
    if ($firewallProfiles.Count -eq 0 -or $null -eq $ruleCounts) { [void]$blockers.Add('active_firewall_policy_not_read') }
    if (@($firewallProfiles | Where-Object { $_.allow_local_firewall_rules -eq 'False' }).Count -gt 0) { [void]$blockers.Add('local_firewall_rules_may_be_disallowed_by_policy') }
    if ($script:QueryErrors.Count -gt 0) { [void]$blockers.Add('one_or_more_read_queries_incomplete') }
    $result=[ordered]@{schema='sstp-isolation-preflight-s1'; started_utc=$started; ended_utc=[DateTime]::UtcNow.ToString('o'); requested_scope='whole_windows'; requested_profile=$VpnProfileName;
        profile_lookup=$lookups; profile_state=$profileState; profile_candidates=@($candidates.ToArray()); profile=$profile;
        vpn_interfaces=$interfaces; vpn_server_resolution=$serverResolution; level3_resolution=$cdnResolution; default_routes=$defaultRoutes; route_checks=$routeChecks;
        existing_kill_switch=$killSwitch; active_firewall_profiles=$firewallProfiles; enabled_outbound_rule_summary=$ruleCounts; service_states=$services; sstp_outer_tcp_candidates=$outerCandidates;
        query_errors=@($script:QueryErrors.ToArray()); review_blockers=@($blockers.ToArray()); ready_to_apply_isolation=$false; independent_local_rollback_prepared=$false;
        limits=[ordered]@{firewall_hosts_routes_vpn_or_security_settings_changed=$false; vpn_connected_or_disconnected_by_tool=$false; scheduled_task_created=$false; resume_requested=$false;
            automatic_upload=$false; credentials_certificate_keys_or_rasphone_contents_read=$false; account_usernames_full_paths_mac_ssid_or_unrelated_firewall_rules_exported=$false;
            only_dns_lookups_requested=$true; dns_snapshots_are_permanent_endpoint_allowlist=$false; sstp_certificate_revocation_dependencies_fully_known=$false;
            system_wide_isolation_will_allow_chat_browser=$false; zero_hardware_upload_or_file_fingerprinting_proven=$false}}
    $folder=Join-Path $PSScriptRoot 'output'
    if (Test-Path -LiteralPath $folder) { if (((Get-Item -LiteralPath $folder).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'output_reparse_point_refused' } }
    else { [void](New-Item -ItemType Directory -Path $folder) }
    $reportPath=Join-Path $folder ('sstp-preflight-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N') + '.json')
    $json=$result | ConvertTo-Json -Depth 12
    if ($json.Length -gt 1048576) { throw 'report_size_limit' }
    [IO.File]::WriteAllText($reportPath, $json, (New-Object Text.UTF8Encoding($false)))
    Write-Host ('Saved output/' + [IO.Path]::GetFileName($reportPath))
    Write-Host ('Review blockers: ' + $blockers.Count)
    Write-Host 'No isolation was applied. Keep update PAUSED. Send only the report JSON.'
}
if ($SelfTest) { RunSelfTest | ConvertTo-Json -Depth 8; exit 0 }
try { RunPreflight } catch {
    $known=@('run_preflight_as_administrator','output_reparse_point_refused','report_size_limit')
    $code='preflight_failed_no_network_settings_changed'
    if ($known -contains $_.Exception.Message) { $code=$_.Exception.Message }
    Write-Host ('STOP: ' + $code); exit 1
}
