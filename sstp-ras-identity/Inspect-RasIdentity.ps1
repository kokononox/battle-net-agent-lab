# Diagnostic only: reads OS state, compiles the bundled helper, writes a bounded local report, then exits.
param([string]$OutputPath=(Join-Path $PSScriptRoot 'SstpRasIdentityReport.json'))
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. "$PSScriptRoot/Policy.ps1"
$o=NewRasIdentityObservation;$apiError=$null;$stage='profile_inventory';$success=$false
function ReadRasProfiles {
 $all=@()
 foreach($scope in @('current_user','all_users')) {
  if($scope -eq 'current_user') { $raw=@(Get-VpnConnection -ErrorAction Stop) } else { $raw=@(Get-VpnConnection -AllUserConnection -ErrorAction Stop) }
  foreach($p in $raw) {
   $guid=[guid]::Empty
   if ($p.PSObject.Properties.Name -contains 'Guid') { try { $guid=[guid]$p.Guid } catch {} }
   $all+=,[pscustomobject]@{name=[string]$p.Name;scope=$scope;connected=([string]$p.ConnectionStatus -eq 'Connected');sstp=([string]$p.TunnelType -ieq 'Sstp');guid=$guid}
  }
 }
 return $all
}
try {
 $profiles=@(ReadRasProfiles);$o.profile_inventory_complete=$true
 $active=@($profiles | Where-Object {$_.sstp -eq $true -and $_.connected -eq $true});$o.active_sstp_count=$active.Count
 if($active.Count -ne 1) { throw 'binding_no_unique_active_sstp' };$selected=$active[0]
 $o.profile_guid_unique=($selected.guid -ne [guid]::Empty -and @($profiles | Where-Object {$_.guid -eq $selected.guid}).Count -eq 1)
 if(-not $o.profile_guid_unique) { throw 'binding_profile_guid_ambiguous' }
 $stage='native_helper'
 Add-Type -Path "$PSScriptRoot/RasIdentity.cs" -ErrorAction Stop
 $stage='ras_inventory'
 $ras=@([SstpIdentityV1.Native]::Enumerate());$o.ras_inventory_available=$true
 $matches=@($ras | Where-Object {$_.EntryGuid -eq $selected.guid});$o.ras_profile_guid_match_count=$matches.Count
 if($matches.Count -ne 1) { throw 'binding_ras_guid_not_unique' };$r=$matches[0]
 $o.ras_name_matches=($r.EntryName -ieq $selected.name)
 $o.ras_scope_matches=($r.AllUsers -eq ($selected.scope -eq 'all_users'))
 $o.ras_device_is_vpn=($r.DeviceType -ieq 'vpn')
 $o.ras_session_marker_available=($r.Handle -ne [IntPtr]::Zero -and $r.CorrelationGuid -ne [guid]::Empty)
 if(-not $o.ras_name_matches -or -not $o.ras_scope_matches -or -not $o.ras_device_is_vpn -or -not $o.ras_session_marker_available) { throw 'binding_ras_metadata_conflict' }
 $stage='projection_ipv4'
 $ip=[SstpIdentityV1.Native]::ProjectionIPv4($r.Handle);$o.projection_ipv4_available=$true
 $stage='network_interface'
 $nics=@([SstpIdentityV1.Native]::Adapters())
 $mapped=@($nics | Where-Object {$ip -cin $_.IPv4});$o.projection_ip_matching_interfaces=$mapped.Count
 if($mapped.Count -ne 1) { throw 'binding_projection_not_unique' };$nic=$mapped[0]
 $o.candidate_is_ppp=($nic.Type -eq [SstpIdentityV1.Native]::PppIfType);$o.candidate_operational_up=$nic.Up
 $o.alias_equal_to_profile_name=($nic.Name -ieq $selected.name)
 $o.candidate_alias_literal_safe=(-not [string]::IsNullOrWhiteSpace($nic.Name) -and $nic.Name.Length -le 128 -and $nic.Name -cne 'Any' -and $nic.Name -notmatch '[*?\[\]`\r\n]' -and $nic.Name -ceq $nic.Name.Trim())
 if(-not $o.candidate_is_ppp -or -not $o.candidate_operational_up) { throw 'binding_candidate_not_up_ppp' }
 $stage='interface_identifiers'
 $id=[SstpIdentityV1.Native]::InterfaceFromIndex($nic.Index)
 $o.interface_index_luid_guid_roundtrip=($id.Guid -eq $nic.Guid)
 if(-not $o.interface_index_luid_guid_roundtrip) { throw 'binding_interface_guid_mismatch' }
 # A second full inventory and projection are independent reads, not evidence of persistence across reconnect/reboot.
 $stage='stable_recheck'
 $againProfiles=@(ReadRasProfiles)
 $againActive=@($againProfiles | Where-Object {$_.sstp -eq $true -and $_.connected -eq $true})
 $againRas=@([SstpIdentityV1.Native]::Enumerate() | Where-Object {$_.EntryGuid -eq $selected.guid})
 $same=$false
 if($againActive.Count -eq 1 -and $againActive[0].guid -eq $selected.guid -and $againActive[0].scope -ceq $selected.scope -and $againActive[0].name -ieq $selected.name -and $againRas.Count -eq 1) {
  $r2=$againRas[0]
  if($r2.Handle -eq $r.Handle -and $r2.CorrelationGuid -eq $r.CorrelationGuid -and $r2.AllUsers -eq $r.AllUsers -and $r2.DeviceType -ieq 'vpn' -and $r2.EntryName -ieq $selected.name) {
   $ip2=[SstpIdentityV1.Native]::ProjectionIPv4($r2.Handle)
   $nic2s=@([SstpIdentityV1.Native]::Adapters() | Where-Object {$ip2 -cin $_.IPv4})
   if($ip2 -ceq $ip -and $nic2s.Count -eq 1 -and $nic2s[0].Guid -eq $nic.Guid -and $nic2s[0].Index -eq $nic.Index -and $nic2s[0].Type -eq [SstpIdentityV1.Native]::PppIfType -and $nic2s[0].Up) {
    $id2=[SstpIdentityV1.Native]::InterfaceFromIndex($nic2s[0].Index)
    $same=($id2.Guid -eq $id.Guid -and $id2.NetLuid -eq $id.NetLuid)
   }
  }
 }
 $o.connection_stable_on_recheck=$same
 $success=((GetRasIdentityDecision $o) -eq 'identity_chain_observed')
} catch {
 $message=$_.Exception.GetBaseException().Message
 if($message -match '^(ras|binding)_[a-z_0-9]+$') { $apiError=$message } else { $apiError='binding_inspection_unavailable' }
 if($stage -eq 'ras_inventory' -and $null -eq $o.ras_inventory_available) { $o.ras_inventory_available=$false }
 if($stage -eq 'projection_ipv4' -and $null -eq $o.projection_ipv4_available) { $o.projection_ipv4_available=$false }
}
$report=[ordered]@{schema='sstp-ras-identity-report-1';created_utc=[DateTime]::UtcNow.ToString('o');os_build=[Environment]::OSVersion.Version.Build;process_bits=([IntPtr]::Size*8);status=(GetRasIdentityDecision $o);identity_chain_observed=$success;last_stage=$stage;error_code=$apiError;observation=$o;logon_luid_used_as_network_luid=$false;projection_is_client_ppp_not_vpn_server=$true;raw_names_ips_guids_handles_exported=$false;network_policy_changed=$false;dns_queried=$false;credentials_read=$false;uploaded=$false;firewall_filter_binding_qualified=$false;reconnect_persistence_tested=$false;enforcement_tested=$false;ready_for_user_apply=$false}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),($report | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
Write-Output 'Read-only RAS identity inspection finished: SstpRasIdentityReport.json'
exit 0
