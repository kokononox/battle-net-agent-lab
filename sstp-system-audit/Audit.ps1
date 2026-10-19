# Collects bounded local metadata only. No DNS lookup, connection or mutation.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'AuditReadCore.ps1')
. (Join-Path $PSScriptRoot 'KnownHosts.ps1')
function AuditSection([scriptblock]$Read){
 try{[pscustomobject]@{status='ok';data=(& $Read)}}catch{[pscustomobject]@{status='unavailable';error_type=$_.Exception.GetType().Name}}
}
function AuditHosts([string[]]$Lines){
 $depth=0;$bad=$false;$starts=0;$ends=0;$known=0;$outside=0;$entries=0;$target=$false;$marked=0
 foreach($line in $Lines){
  $trim=$line.Trim()
  if($trim -ceq '# --- BLIZZARD-BLOCK START ---'){$starts++;if($depth -ne 0){$bad=$true};$depth++;continue}
  if($trim -ceq '# --- BLIZZARD-BLOCK END ---'){$ends++;if($depth -le 0){$bad=$true}else{$depth--};continue}
  $body=($line -split '#',2)[0].Trim();if(-not $body){continue};$parts=@($body -split '\s+');if($parts.Count -lt 2){continue};$entries++
  if($depth -gt 0){$marked++}
  for($i=1;$i -lt $parts.Count;$i++){
   $name=$parts[$i].ToLowerInvariant()
   if($script:AuditKnownHosts -contains $name){$known++;if($depth -eq 0){$outside++}}
   if($name -ceq 'level3.blizzard.com' -and $parts[0] -cin @('0.0.0.0','127.0.0.1','::','::1')){$target=$true}
  }
 }
 [pscustomobject]@{noncomment_entry_lines=$entries;marker_starts=$starts;marker_ends=$ends;markers_balanced=(-not $bad -and $depth -eq 0);lines_inside_markers=$marked;known_list_aliases=$known;known_aliases_outside_markers=$outside;level3_blizzard_sinkholed=$target}
}
function AuditOverlay([string]$Root){
 if(-not [IO.Directory]::Exists($Root)){return [pscustomobject]@{status='absent';observation_only=$true}}
 $null=AssertJournalPath $Root;AssertJournalAcl $Root
 $path=Join-Path $Root 'journal.json';$backup=Join-Path $Root 'journal.bak'
 if(-not [IO.File]::Exists($path)){return [pscustomobject]@{status='primary_missing';backup_present=[IO.File]::Exists($backup);observation_only=$true}}
 $before=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
 $rec=ReadJournalFile $path;AssertOverlayState $rec.state
 $rows=@()
 foreach($o in $rec.state.objects){
  $actual=OverlayRead $o.spec.name;$match=$false;$semantic=$false;$enabled=$null
  if($null -ne $actual){
   $enabled=[string]$actual.rule.Enabled
   if($null -ne $o.original){$match=(OverlayHash $actual.image) -ceq (OverlayHash (OverlayExpected $o $o.enabled));try{AssertOverlaySemantic $o.spec $actual $o.enabled;$semantic=$true}catch{}}
  }
  $rows+=,[pscustomobject]@{kind=[string]$o.spec.kind;saved_original=($null -ne $o.original);saved_exists=[bool]$o.exists;saved_enabled=[bool]$o.enabled;actual_exists=($null -ne $actual);actual_enabled=$enabled;matches_saved_image=$match;matches_semantics=$semantic;remote_entry_count=@($o.spec.remote).Count}
 }
 $after=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
 $changed=$before -cne $after
 [pscustomobject]@{status='observed';phase=[string]$rec.state.phase;scope=[string]$rec.state.scope;pending=($null -ne $rec.state.pending);journal_changed_during_read=$changed;rows=$rows;all_three_disabled_exact=(-not $changed -and $rows.Count -eq 3 -and @($rows|Where-Object{-not $_.actual_exists -or $_.actual_enabled -cne 'False' -or -not $_.matches_saved_image -or -not $_.matches_semantics}).Count -eq 0);observation_only=$true;lock_files_created=$false}
}
function GetSystemAudit {
 $sections=[ordered]@{}
 $sections.os=AuditSection {
  $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  [pscustomobject]@{version=[string]$os.Version;build=[string]$os.BuildNumber;product_type=[int]$os.ProductType;os_architecture=[string]$os.OSArchitecture;powershell=$PSVersionTable.PSVersion.ToString();process_bits=([IntPtr]::Size*8)}
 }
 $sections.firewall_profiles=AuditSection {
  $rows=@();foreach($store in @('PersistentStore','ActiveStore')){foreach($p in @(Get-NetFirewallProfile -PolicyStore $store -ErrorAction Stop)){
   $rows+=,[pscustomobject]@{store=$store;name=[string]$p.Name;enabled=[string]$p.Enabled;default_outbound=[string]$p.DefaultOutboundAction;default_inbound=[string]$p.DefaultInboundAction;allow_local_rules=[string]$p.AllowLocalFirewallRules;excluded_interface_count=@($p.DisabledInterfaceAliases|Where-Object{$_ -and [string]$_ -cne 'NotConfigured'}).Count}
  }};return ,$rows
 }
 $sections.firewall_rules=AuditSection {
  $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
  $legacy=@($rules|Where-Object{[string]$_.Group -ceq 'SSTP Kill Switch'});$overlay=@($rules|Where-Object{[string]$_.Name -cmatch '^SstpDestinationOverlay-[a-f0-9]{32}-(guard|v4|v6)$'})
  [pscustomobject]@{persistent_total=$rules.Count;legacy_group_total=$legacy.Count;legacy_enabled_outbound_allows=@($legacy|Where-Object{[string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow'}).Count;overlay_named_total=$overlay.Count;overlay_named_enabled=@($overlay|Where-Object{[string]$_.Enabled -ceq 'True'}).Count;other_enabled_outbound_allows=@($rules|Where-Object{[string]$_.Group -cne 'SSTP Kill Switch' -and [string]$_.Name -cnotmatch '^SstpDestinationOverlay-[a-f0-9]{32}-(guard|v4|v6)$' -and [string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow'}).Count;other_rules_fully_reviewed=$false;name_match_is_not_ownership=$true}
 }
 $sections.overlay=AuditSection {AuditOverlay (Join-Path $env:ProgramData 'SstpDestinationOverlayTest')}
 $sections.legacy_saved_state=AuditSection {
  $path=Join-Path $env:ProgramData 'SstpKillSwitch\firewall-state.json'
  if(-not [IO.File]::Exists($path)){return [pscustomobject]@{present=$false}}
  if((Get-Item -LiteralPath $path -ErrorAction Stop).Length -gt 1048576){throw 'audit_legacy_size'}
  $s=[IO.File]::ReadAllText($path)|ConvertFrom-Json
  if([string]$s.Version -cne '1.2'){throw 'audit_legacy_version'}
  $rows=@($s.FirewallProfiles|ForEach-Object{if([string]$_.Name -cnotin @('Domain','Private','Public') -or [string]$_.DefaultOutboundAction -cnotin @('Allow','Block','NotConfigured')){throw 'audit_legacy_profile'};[pscustomobject]@{name=[string]$_.Name;default_outbound=[string]$_.DefaultOutboundAction}})
  [pscustomobject]@{present=$true;version=[string]$s.Version;profile_count=$rows.Count;saved_profiles=$rows;restore_authorized=$false;machine_provenance_verified=$false}
 }
 $sections.hosts=AuditSection {
  $path=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
  if((Get-Item -LiteralPath $path -ErrorAction Stop).Length -gt 1048576){throw 'audit_hosts_size'}
  $before=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
  $summary=AuditHosts ([IO.File]::ReadAllLines($path))
  $after=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
  [pscustomobject]@{summary=$summary;sha256=$after;changed_during_read=($before -cne $after);blizzard_backup_count=@(Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($path)) -Filter 'hosts.blizzard-backup-*' -File -ErrorAction Stop).Count;raw_contents_exported=$false}
 }
 $sections.ipv6_registry=AuditSection {
  $key='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
  $p=Get-ItemProperty -LiteralPath $key -ErrorAction Stop
  $prop=$p.PSObject.Properties['DisabledComponents']
  if($null -eq $prop){return [pscustomobject]@{value_present=$false;disabled_components_hex=$null;restart_state_known=$false}}
  $value=[Convert]::ToUInt32(([int64]$prop.Value -band 4294967295))
  [pscustomobject]@{value_present=$true;disabled_components_hex=('0x{0:X8}' -f $value);restart_state_known=$false}
 }
 $sections.ipv6_bindings=AuditSection {
  $b=@(Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop)
  [pscustomobject]@{visible_adapter_bindings=$b.Count;enabled=@($b|Where-Object{$_.Enabled}).Count;disabled=@($b|Where-Object{-not $_.Enabled}).Count;hidden_adapters_reviewed=$false;adapter_names_exported=$false}
 }
 $sections.vpn=AuditSection {
  $all=@(Get-VpnConnection -ErrorAction Stop)+@(Get-VpnConnection -AllUserConnection -ErrorAction Stop);$connected=@($all|Where-Object{[string]$_.ConnectionStatus -ceq 'Connected'})
  [pscustomobject]@{scope='elevated_user_and_all_user_windows_vpn';configured_count=$all.Count;connected_count=$connected.Count;connected_sstp_count=@($connected|Where-Object{[string]$_.TunnelType -ceq 'Sstp'}).Count;names_credentials_servers_exported=$false;external_vpn_clients_reviewed=$false}
 }
 $sections.dns=AuditSection {
  $d=@(Get-DnsClientServerAddress -ErrorAction Stop)
  [pscustomobject]@{rows=$d.Count;ipv4_rows_with_servers=@($d|Where-Object{[int]$_.AddressFamily -eq 2 -and @($_.ServerAddresses).Count -gt 0}).Count;ipv6_rows_with_servers=@($d|Where-Object{[int]$_.AddressFamily -eq 23 -and @($_.ServerAddresses).Count -gt 0}).Count;addresses_exported=$false;leak_protection_verified=$false}
 }
 $sections.nrpt=AuditSection {$n=@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop);[pscustomobject]@{effective_entry_count=$n.Count;policy_contents_exported=$false}}
 $sections.routes=AuditSection {
  $r=@(Get-NetRoute -ErrorAction Stop)
  [pscustomobject]@{route_count=$r.Count;ipv4_default_count=@($r|Where-Object{[string]$_.DestinationPrefix -ceq '0.0.0.0/0'}).Count;ipv6_default_count=@($r|Where-Object{[string]$_.DestinationPrefix -ceq '::/0'}).Count;addresses_and_interfaces_exported=$false;route_safety_verified=$false}
 }
 $sections.proxy=AuditSection {
  $p=Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
  $enabled=$p.PSObject.Properties['ProxyEnable'];$pac=$p.PSObject.Properties['AutoConfigURL']
  [pscustomobject]@{scope='elevated_account_wininet_only';proxy_enable_value_present=($null -ne $enabled);proxy_enabled=($null -ne $enabled -and [int]$enabled.Value -ne 0);pac_url_present=($null -ne $pac -and -not [string]::IsNullOrWhiteSpace([string]$pac.Value));winhttp_and_application_proxies_reviewed=$false;urls_exported=$false}
 }
 $sections.services=AuditSection {return ,@(foreach($name in @('BFE','MpsSvc')){$s=Get-Service -Name $name -ErrorAction Stop;[pscustomobject]@{name=$name;status=[string]$s.Status}})}
 $unavailable=@($sections.Keys|Where-Object{$sections[$_].status -cne 'ok'})
 [pscustomobject][ordered]@{schema='sstp-system-audit-1';network_settings_changed_by_tool=$false;automatic_enable=$false;activation_approved=$false;outside_vpn_protection_certified=$false;complete_security_audit=$false;drivers_tasks_third_party_wfp_reviewed=$false;snapshot_not_transaction=$true;unavailable_sections=$unavailable;sections=[pscustomobject]$sections}
}
