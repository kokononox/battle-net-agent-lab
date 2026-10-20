# One-shot manager. VPN-only scope is deliberate and always disclosed.
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'ConfigCore.ps1')
. (Join-Path $PSScriptRoot 'Overlay.ps1')
. (Join-Path $PSScriptRoot 'Identity.ps1')
. (Join-Path $PSScriptRoot 'Restore.ps1')
function AppRoot {Join-Path $env:ProgramData 'SstpWhitelistManager1'}
function AppLock([string]$Root){
 $null=InitializeJournalRoot $Root
 [IO.File]::Open((AssertJournalPath (Join-Path $Root 'app-operation.lock')),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
}
function AppConfigPath([string]$Root){AssertJournalPath (Join-Path $Root 'allowlist.json')}
function InitializeAppConfig([string]$Root){
 $file=AppConfigPath $Root
 if(-not [IO.File]::Exists($file)){
  $seed=ReadAllowlistConfig (Join-Path $PSScriptRoot 'seed.json')
  $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($seed|ConvertTo-Json -Depth 5))
  $h=[IO.File]::Open($file,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$h.Write($bytes,0,$bytes.Length);$h.Flush($true)}finally{$h.Dispose()}
 }
 ReadAllowlistConfig $file
}
function ConfigFromLines([string[]]$Lines){
 $domains=@();$ips=@()
 foreach($line in $Lines){$v=$line.Trim();if(-not $v){continue};$ip=$null;if([Net.IPAddress]::TryParse($v,[ref]$ip)){$ips+=,(AssertPublicTarget $v)}else{$domains+=,(PolicyDomain $v)}}
 PolicyConfig ([pscustomobject]@{schema='sstp-allowlist-config-1';domains=$domains;ip_addresses=$ips})
}
function SaveAppConfig([string]$Root,[string[]]$Lines){
 $lock=AppLock $Root;$tmp=$null
 try{
  $config=ConfigFromLines $Lines;$path=AppConfigPath $Root
  $tmp=AssertJournalPath (Join-Path $Root ('config.next-'+[guid]::NewGuid().ToString('N')))
  $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($config|ConvertTo-Json -Depth 5))
  $h=[IO.File]::Open($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$h.Write($bytes,0,$bytes.Length);$h.Flush($true)}finally{$h.Dispose()}
  [IO.File]::Replace($tmp,$path,[Management.Automation.Language.NullString]::Value);$tmp=$null
  return $config
 }finally{if($tmp -and [IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)};$lock.Dispose()}
}
function ReadDomainAnswers($Rows,[bool]$CacheOnly){
 $ips=@()
 foreach($row in @($Rows)){
  if($null -eq $row){continue}
  $fields=@($row.PSObject.Properties.Name)
  if($fields -cnotcontains 'Section' -or $fields -cnotcontains 'Type'){continue}
  if([string]$row.Section -cne 'Answer' -or [string]$row.Type -cnotin @('A','AAAA')){continue}
  if($fields -cnotcontains 'IPAddress' -or $fields -cnotcontains 'TTL'){throw 'app_domain_answer_invalid'}
  $ttl=0L;if(-not [long]::TryParse([string]$row.TTL,[ref]$ttl) -or $ttl -lt 0){throw 'app_domain_answer_invalid'}
  if($CacheOnly -and $ttl -eq 0){continue}
  try{$ips+=,(AssertPublicTarget ([string]$row.IPAddress))}catch{throw 'app_domain_address_rejected'}
 }
 $ips=@($ips|Sort-Object -Unique)
 if($ips.Count -lt 1){if($CacheOnly){throw 'app_domain_not_cached'};throw 'app_domain_no_usable_addresses'}
 if($ips.Count -gt 32){throw 'app_domain_too_many_addresses'}
 return ,$ips
}
function ReadCachedDomain([string]$Domain){
 try{$rows=@(Resolve-DnsName -Name ($Domain+'.') -Type A_AAAA -CacheOnly -DnsOnly -NoHostsFile -ErrorAction Stop)}catch{throw 'app_domain_cache_lookup_failed'}
 ReadDomainAnswers $rows $true
}
function ReadNetworkDomain([string]$Domain,[bool]$Confirmed){
 if(-not $Confirmed){throw 'app_dns_network_confirmation_required'}
 # Explicit opt-in only. Uses Windows resolver policy, not a hard-coded DNS provider.
 # A connected VPN does NOT prove that the DNS request stays inside its tunnel.
 try{$rows=@(Resolve-DnsName -Name ($Domain+'.') -Type A_AAAA -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)}catch{throw 'app_domain_network_lookup_failed'}
 ReadDomainAnswers $rows $false
}
function ReadAppDnsBinding {
 $binding=$null;$check=InvokeReadOnlyIdentityInspection -Binding ([ref]$binding)
 if(-not $check.passed -or $null -eq $binding){throw 'app_dns_connected_sstp_required'}
 return $binding
}
function BuildAppSnapshot {
 param($Config,[ValidateSet('CacheOnly','WindowsDns')][string]$DnsMode='CacheOnly',[bool]$NetworkDnsConfirmed=$false)
 $c=PolicyConfig $Config;$ips=@($c.ip_addresses);$resolved=@();$binding=$null
 $network=$DnsMode -ceq 'WindowsDns'
 if($network -and -not $NetworkDnsConfirmed){throw 'app_dns_network_confirmation_required'}
 if($network -and $c.domains.Count -gt 0){$binding=ReadAppDnsBinding}
 foreach($domain in $c.domains){
  try{
   if($network){$found=ReadNetworkDomain $domain $NetworkDnsConfirmed}else{$found=ReadCachedDomain $domain}
  }catch{
   # Keep the real failure category; the old version incorrectly called every failure a cache miss.
   $_.Exception.Data['domain']=$domain;throw
  }
  foreach($ip in $found){$ips+=,(AssertPublicTarget $ip)}
  $resolved+=,[pscustomobject]@{domain=$domain;addresses=@($found)}
 }
 if($null -ne $binding){$again=ReadAppDnsBinding;if((OverlayHash $binding) -cne (OverlayHash $again)){throw 'app_dns_sstp_changed'}}
 $ips=@($ips|Sort-Object -Unique)
 if($ips.Count -lt 1 -or $ips.Count -gt 64){throw 'app_snapshot_size'}
 $null=IntervalsToCidrs (ComplementAddresses $ips 32)
 $null=IntervalsToCidrs (ComplementAddresses $ips 128)
 $mode='CacheOnly';$identity='cached_ip_snapshot_not_hostname_identity'
 if($network){$mode='WindowsDns';$identity='windows_dns_ip_snapshot_not_hostname_identity'}
 return [pscustomobject]@{schema='sstp-whitelist-app-snapshot-2';config_sha256=(OverlayHash $c);allowed_ips=$ips;resolved=$resolved;created_utc=[DateTime]::UtcNow.ToString('o');dns_queried=($network -and $c.domains.Count -gt 0);dns_mode=$mode;network_dns_confirmed=($network -and $NetworkDnsConfirmed);domain_identity=$identity}
}
function AssertAppSnapshot($Snapshot,$Config){
 if($null -eq $Snapshot -or $Snapshot.schema -cne 'sstp-whitelist-app-snapshot-2' -or $Snapshot.config_sha256 -cne (OverlayHash (PolicyConfig $Config)) -or $Snapshot.allowed_ips -isnot [array] -or $Snapshot.allowed_ips.Count -lt 1 -or $Snapshot.allowed_ips.Count -gt 64){throw 'app_snapshot_changed'}
 $age=([DateTime]::UtcNow-[DateTime]::Parse($Snapshot.created_utc).ToUniversalTime()).TotalSeconds
 if($age -lt 0 -or $age -gt 600){throw 'app_snapshot_expired'}
 foreach($ip in $Snapshot.allowed_ips){if((AssertPublicTarget $ip) -cne $ip){throw 'app_snapshot_address'}}
 $expected=@($Config.ip_addresses);$seen=@{}
 if($Snapshot.resolved -isnot [array] -or $Snapshot.resolved.Count -ne $Config.domains.Count -or $Snapshot.dns_mode -cnotin @('CacheOnly','WindowsDns') -or $Snapshot.dns_queried -isnot [bool] -or $Snapshot.network_dns_confirmed -isnot [bool]){throw 'app_snapshot_origins'}
 if($Snapshot.dns_mode -ceq 'CacheOnly'){
  if($Snapshot.dns_queried -or $Snapshot.network_dns_confirmed -or $Snapshot.domain_identity -cne 'cached_ip_snapshot_not_hostname_identity'){throw 'app_snapshot_origins'}
 }else{
  if(-not $Snapshot.network_dns_confirmed -or $Snapshot.dns_queried -ne ($Config.domains.Count -gt 0) -or $Snapshot.domain_identity -cne 'windows_dns_ip_snapshot_not_hostname_identity'){throw 'app_snapshot_origins'}
 }
 foreach($r in $Snapshot.resolved){
  if($r.domain -cnotin $Config.domains -or $seen.ContainsKey($r.domain) -or $r.addresses -isnot [array] -or $r.addresses.Count -lt 1 -or $r.addresses.Count -gt 32){throw 'app_snapshot_origins'}
  $seen[$r.domain]=$true;foreach($ip in $r.addresses){$expected+=,(AssertPublicTarget $ip)}
 }
 $expected=@($expected|Sort-Object -Unique)
 if(($expected -join ',') -cne (@($Snapshot.allowed_ips|Sort-Object -Unique)-join ',')){throw 'app_snapshot_origins'}
}
function ReadAppSlots([string]$Root){
 $out=@()
 foreach($slot in @('slot-a','slot-b')){
  $dir=AssertJournalPath (Join-Path $Root $slot)
  if(-not [IO.Directory]::Exists($dir)){$out+=,[pscustomobject]@{slot=$slot;root=$dir;record=$null;phase='absent'};continue}
  AssertJournalAcl $dir;$j=ReadJournal $dir
  if($j.status -ceq 'absent'){$out+=,[pscustomobject]@{slot=$slot;root=$dir;record=$null;phase='absent'};continue}
  if($j.status -cne 'valid'){throw 'app_slot_journal_unusable'}
  AssertOverlayState $j.record.state
  $out+=,[pscustomobject]@{slot=$slot;root=$dir;record=$j.record;phase=$j.record.state.phase}
 }
 return ,$out
}
function AssertAppExact($Record,[bool]$Active){
 if($null -eq $Record){throw 'app_record_required'}
 AssertOverlayState $Record.state
 if($null -ne $Record.state.pending){throw 'app_pending_requires_restore'}
 foreach($o in $Record.state.objects){
  $want=$Active -and $o.spec.kind -cne 'guard'
  if(-not $o.exists -or $o.enabled -ne $want){throw 'app_not_exact'}
  $read=OverlayRead $o.spec.name
  if($null -eq $read -or -not (OverlayImageEqual $read.image (OverlayExpected $o $want))){throw 'app_owned_image_conflict'}
  AssertOverlaySemantic $o.spec $read $want
 }
 AssertOverlayActiveRules $Record
}
function AppOwnedNames($Slots){return ,@($Slots|Where-Object{$null -ne $_.record}|ForEach-Object{$_.record.state.objects}|ForEach-Object{$_.spec.name})}
function AppForeignInventory([string[]]$Names){$x=ReadPolicyInventory;$x.rules=@($x.rules|Where-Object{$_.name -cnotin $Names});return $x}
function AssertAppPreflight {
 foreach($service in @('BFE','MpsSvc')){if([string](Get-Service -Name $service -ErrorAction Stop).Status -cne 'Running'){throw 'app_firewall_service_required'}}
 $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
 if($profiles.Count -ne 3){throw 'app_profile_count'}
 foreach($p in $profiles){
  if([string]$p.Enabled -cne 'True' -or [string]$p.DefaultOutboundAction -cne 'Block' -or [string]$p.AllowLocalFirewallRules -ceq 'False'){throw 'app_existing_default_block_required'}
  if(@($p.DisabledInterfaceAliases|Where-Object{$_ -and [string]$_ -cne 'NotConfigured'}).Count -gt 0){throw 'app_interface_exclusion'}
 }
 $binding=$null;$check=InvokeReadOnlyIdentityInspection -Binding ([ref]$binding)
 if(-not $check.passed -or $null -eq $binding){throw 'app_verified_connected_sstp_required'}
 # Only checks for usable existing tunnel access. Does NOT assert outside protection.
 $allows=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop|Where-Object{[string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow'})
 $found=$false
 foreach($rule in $allows){$types=@(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop);if($types.Count -eq 1 -and [string]$types[0].InterfaceType -ceq 'RemoteAccess'){$found=$true}}
 if(-not $found){throw 'app_existing_tunnel_allow_required'}
 return $binding
}
function NewAppReport([string]$Action){
 [pscustomobject][ordered]@{schema='sstp-whitelist-app-operation-1';version='0.1.2';action=$Action;passed=$false;stage='starting';code=$null;scope='all_programs_all_RemoteAccess_interfaces_only';outside_vpn_guard_installed=$false;full_requested_protection_ready=$false;no_leak_certified=$false;resident_component_installed=$false;vpn_dial_or_hangup_called=$false;profile_setters_used=$false;allow_rules_created=$false;dns_queried=$false;dns_lookup_mode='not_used';dns_tunnel_only_certified=$false;ip_count=0;unrelated_strict_equal=$null;rules_persistent=$false;cleanup_completed=$false;recovery_required=$false;slot_errors=@()}
}
function AppSafeCode($Err){if($Err.Exception.Message -cmatch '^(app|overlay|journal|inventory|policy|tool)_[a-z_0-9]{1,90}$'){return $Err.Exception.Message};return 'app_operation_failed'}
function ApplyApp([string]$Root,$Snapshot,[bool]$VpnOnlyAcknowledged){
 if(-not $VpnOnlyAcknowledged){throw 'app_scope_acknowledgement_required'}
 $lock=AppLock $Root;$report=NewAppReport 'apply';$before=$null
 try{
  $report.stage='preflight';$null=AssertAppPreflight
  $config=ReadAllowlistConfig (AppConfigPath $Root);AssertAppSnapshot $Snapshot $config
  $report.dns_queried=$Snapshot.dns_queried;$report.dns_lookup_mode=$Snapshot.dns_mode
  $slots=ReadAppSlots $Root;$names=AppOwnedNames $slots;$before=AppForeignInventory $names
  $busy=@($slots|Where-Object{$_.phase -cnotin @('absent','removed','active')})
  $active=@($slots|Where-Object{$_.phase -ceq 'active'})
  if($busy.Count -gt 0 -or $active.Count -gt 1){throw 'app_restore_required'}
  foreach($s in $active){AssertAppExact $s.record $true}
  $same=$active.Count -eq 1 -and $active[0].record.state.config_sha256 -ceq $Snapshot.config_sha256 -and (IntervalSignature $active[0].record.state.allowed_ips) -ceq (IntervalSignature $Snapshot.allowed_ips)
  if(-not $same){
   $next=@($slots|Where-Object{$_.phase -cin @('absent','removed')})[0]
   $report.stage='prepare_disabled'
   NewOverlay -Root $next.root -Allowed $Snapshot.allowed_ips -ConfigSha256 $Snapshot.config_sha256|Out-Null
   $prepared=OverlayLoad $next.root;AssertAppExact $prepared $false
   $report.stage='activate_new';InvokeOverlay $next.root Enable|Out-Null
   $new=OverlayLoad $next.root;AssertAppExact $new $true
   # Old remains restrictive until the new set is exact and enforced.
   $report.stage='retire_old';foreach($s in $active){RemoveAppOverlay $s.root}
  }
  $final=ReadAppSlots $Root;$active=@($final|Where-Object{$_.phase -ceq 'active'})
  if($active.Count -ne 1){throw 'app_active_slot_count'}
  AssertAppExact $active[0].record $true
  $finalNames=AppOwnedNames $final;$allNames=@($names+$finalNames|Sort-Object -Unique)
  $comparison=ComparePolicyInventory $before (AppForeignInventory $allNames)
  $report.unrelated_strict_equal=[bool]$comparison.strict_equal
  if(-not $comparison.strict_equal){throw 'app_unrelated_policy_changed'}
  $report.ip_count=$Snapshot.allowed_ips.Count;$report.rules_persistent=$true;$report.stage='completed';$report.passed=$true
 }catch{$report.code=AppSafeCode $_;$report.recovery_required=$true}
 finally{$lock.Dispose()}
 return $report
}
function RestoreApp([string]$Root){
 $lock=AppLock $Root;$report=NewAppReport 'restore'
 try{
  $slots=ReadAppSlots $Root;$names=AppOwnedNames $slots;$before=AppForeignInventory $names
  foreach($s in $slots){if($null -ne $s.record){try{RemoveAppOverlay $s.root}catch{$report.slot_errors+=,[pscustomobject]@{slot=$s.slot;code=(AppSafeCode $_)}}}}
  if($report.slot_errors.Count -gt 0){throw 'app_restore_conflict'}
  $comparison=ComparePolicyInventory $before (AppForeignInventory $names)
  $report.unrelated_strict_equal=[bool]$comparison.strict_equal
  $report.cleanup_completed=$true
  if(-not $comparison.strict_equal){throw 'app_unrelated_policy_changed'}
  $report.stage='completed';$report.passed=$true
 }catch{$report.code=AppSafeCode $_;$report.recovery_required=$true}
 finally{$lock.Dispose()}
 return $report
}
