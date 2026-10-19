# Read-only prerequisites. This does NOT certify the existing kill switch.
Set-StrictMode -Version 2.0
function TestOverlayPrerequisites {
 if($env:OS -cne 'Windows_NT'){throw 'overlay_windows_required'}
 $id=[Security.Principal.WindowsIdentity]::GetCurrent();$p=New-Object Security.Principal.WindowsPrincipal($id)
 if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'overlay_admin_required'}
 $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
 if($profiles.Count -ne 3){throw 'overlay_profile_coverage'}
 foreach($f in $profiles){if([string]$f.AllowLocalFirewallRules -ceq 'False'){throw 'overlay_local_policy_disallowed'};if(@($f.DisabledInterfaceAliases|Where-Object{$_ -and [string]$_ -cne 'NotConfigured'}).Count -gt 0){throw 'overlay_profile_interface_exclusions'};if([string]$f.Enabled -cne 'True' -or [string]$f.DefaultOutboundAction -cne 'Block'){throw 'overlay_enable_existing_kill_switch_first'}}
 $vpns=@();$vpns+=@(Get-VpnConnection -ErrorAction Stop);$vpns+=@(Get-VpnConnection -AllUserConnection -ErrorAction Stop)
 $connected=@($vpns|Where-Object{[string]$_.ConnectionStatus -ceq 'Connected'})
 if($connected.Count -ne 1 -or [string]$connected[0].TunnelType -cne 'Sstp'){throw 'overlay_one_connected_sstp_required'}
 $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop|Where-Object{[string]$_.Group -ceq 'SSTP Kill Switch' -and [string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow'})
 $tunnel=0
 foreach($r in $rules){
  $f=@(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $r -ErrorAction Stop)
  if($f.Count -eq 1 -and [string]$f[0].InterfaceType -ceq 'RemoteAccess'){$tunnel++}
 }
 if($tunnel -ne 1){throw 'overlay_existing_tunnel_allow_not_unique'}
 [pscustomobject]@{schema='sstp-overlay-preflight-1';one_connected_sstp=$true;effective_profiles_enabled_and_default_block=$true;legacy_tunnel_allow_present=$true;legacy_rules_not_changed=$true;outside_vpn_protection_certified=$false;scope='all_RemoteAccess_interfaces_not_pinned_profile';network_changed=$false}
}
function NewOverlaySnapshot([string]$ConfigPath){
 $null=TestOverlayPrerequisites
 $c=ReadAllowlistConfig $ConfigPath;$ips=@();$resolved=@()
 foreach($ip in $c.ip_addresses){$ips+=,(AssertPublicTarget $ip)}
 foreach($domain in $c.domains){
  # Deliberate user-triggered setup lookup through Windows' CURRENT resolver.
  # NOT a DNS leak prevention mechanism; no DNS allow is added by this tool.
  $found=@([Net.Dns]::GetHostAddresses($domain)|ForEach-Object{AssertPublicTarget $_.ToString()}|Sort-Object -Unique)
  if($found.Count -lt 1 -or $found.Count -gt 64){throw 'overlay_domain_snapshot_size'}
  $ips+=@($found);$resolved+=,[pscustomobject]@{domain=$domain;addresses=@($found)}
 }
 $ips=@($ips|Sort-Object -Unique)
 if($ips.Count -lt 1 -or $ips.Count -gt 512){throw 'overlay_allow_size'}
 [pscustomobject]@{schema='sstp-overlay-snapshot-1';config_sha256=(OverlayHash $c);allowed_ips=$ips;resolved=$resolved;dns_queried=($c.domains.Count -gt 0);dns_path_pinned_to_vpn=$false;domain_exclusive=$false}
}
