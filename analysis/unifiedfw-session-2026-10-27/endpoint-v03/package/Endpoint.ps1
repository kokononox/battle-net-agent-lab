# Read-only correlation, not service-tag attribution or policy authorization.
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'Observer.ps1')
function ConvertTo-EndpointIP($Value){
 $ip=$null
 if($Value -isnot [string] -or $Value.Contains('%') -or -not [Net.IPAddress]::TryParse($Value,[ref]$ip)){throw 'endpoint_ip_invalid'}
 if([Net.IPAddress]::IsLoopback($ip) -or $ip.Equals([Net.IPAddress]::Any) -or $ip.Equals([Net.IPAddress]::IPv6Any)){throw 'endpoint_ip_invalid'}
 return $ip.ToString()
}
function ConvertTo-EndpointHost($Value){
 if($Value -isnot [string] -or $Value -ne $Value.Trim() -or $Value.Length -gt 254){throw 'endpoint_hostname_invalid'}
 $s=$Value.TrimEnd('.').ToLowerInvariant()
 if($s.Length -gt 253 -or $s -notmatch '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$'){throw 'endpoint_hostname_invalid'}
 foreach($label in $s.Split('.')){if($label.Length -gt 63 -or $label -notmatch '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'){throw 'endpoint_hostname_invalid'}}
 return $s
}
function Get-EndpointCacheAddresses($Server,$Records){
 $ip=$null
 if([Net.IPAddress]::TryParse($Server,[ref]$ip)){return [pscustomobject]@{source='configured_literal';addresses=@(ConvertTo-EndpointIP $Server)}}
 $node=ConvertTo-EndpointHost $Server;$seen=@{}
 for($hop=0;$hop -lt 8;$hop++){
  if($seen.ContainsKey($node)){throw 'endpoint_cache_cname_loop'};$seen[$node]=$true
  $addresses=@();$aliases=@()
  foreach($row in @($Records)){
   $owner=$row.PSObject.Properties['Name'];if($null -eq $owner -or [string]::IsNullOrEmpty([string]$owner.Value)){$owner=$row.PSObject.Properties['Entry']}
   if($null -eq $owner){throw 'endpoint_cache_shape_unknown'}
   try{$name=ConvertTo-EndpointHost ([string]$owner.Value)}catch{continue}
   if($name -cne $node){continue}
   foreach($key in @('Status','TimeToLive','Type','Data')){if($null -eq $row.PSObject.Properties[$key]){throw 'endpoint_cache_shape_unknown'}}
   $ttl=0L;if(-not [long]::TryParse([string]$row.TimeToLive,[ref]$ttl)){throw 'endpoint_cache_shape_unknown'}
   if(([string]$row.Status -ne '0' -and [string]$row.Status -cne 'Success') -or $ttl -le 0){continue}
   switch([string]$row.Type){
    {$_ -in @('1','A','28','AAAA')} {
     $v=ConvertTo-EndpointIP ([string]$row.Data);$parsed=[Net.IPAddress]::Parse($v)
     if((([string]$row.Type -in @('1','A')) -and $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) -or (([string]$row.Type -in @('28','AAAA')) -and $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6)){throw 'endpoint_cache_address_family_mismatch'}
     $addresses+=,$v
    }
    {$_ -in @('5','CNAME')} {$aliases+=,(ConvertTo-EndpointHost ([string]$row.Data))}
   }
  }
  $aliases=@($aliases|Sort-Object -Unique);$addresses=@($addresses|Sort-Object -Unique)
  if($aliases.Count -gt 1 -or ($aliases.Count -and $addresses.Count)){throw 'endpoint_cache_cname_conflict'}
  if($addresses.Count){return [pscustomobject]@{source='local_cache_not_trusted_pin';addresses=$addresses}}
  if(-not $aliases.Count){return [pscustomobject]@{source='local_cache_unresolved';addresses=@()}}
  $node=$aliases[0]
 }
 throw 'endpoint_cache_cname_limit'
}
function Read-EndpointImageIdentity($proc){
 $expectedPath=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) 'svchost.exe'
 if(-not [string]::Equals([string]$proc.ExecutablePath,$expectedPath,[StringComparison]::OrdinalIgnoreCase)){throw 'endpoint_process_identity_unavailable'}
 if(([IO.File]::GetAttributes($expectedPath) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'endpoint_process_file_reparse'}
 # No Authenticode call: chain/revocation validation can cause implicit network retrieval.
 # Signature trust is intentionally unverified in this strictly offline observer.
 return (Get-FileHash -LiteralPath $expectedPath -Algorithm SHA256 -ErrorAction Stop).Hash
}
function Read-EndpointNativeSnapshot($Server){
 $services=@(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
 $sstp=@($services|Where-Object{$_.Name -ceq 'SstpSvc'})
 if($sstp.Count -ne 1 -or $sstp[0].State -cne 'Running' -or [uint32]$sstp[0].ProcessId -eq 0){throw 'endpoint_service_not_running'}
 $ownerPid=[uint32]$sstp[0].ProcessId
 $members=@($services|Where-Object{[uint32]$_.ProcessId -eq $ownerPid}|ForEach-Object{[string]$_.Name}|Sort-Object -Unique)
 if($members -notcontains 'SstpSvc'){throw 'endpoint_service_membership_unknown'}
 $processes=@(Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = '+$ownerPid) -ErrorAction Stop)
 if($processes.Count -ne 1){throw 'endpoint_process_unavailable'};$proc=$processes[0]
 if($proc.CreationDate -isnot [datetime]){throw 'endpoint_process_identity_unavailable'}
 $imageHash=Read-EndpointImageIdentity $proc
 $literal=$null;$cache=@();if(-not [Net.IPAddress]::TryParse($Server,[ref]$literal)){$cache=@(Get-DnsClientCache -ErrorAction Stop)}
 $mapping=Get-EndpointCacheAddresses $Server $cache
 $flows=@(Get-NetTCPConnection -State Established -ErrorAction Stop|Where-Object{[uint32]$_.OwningProcess -eq $ownerPid -and $_.RemotePort -eq 443})
 $keys=@();$matches=@()
 foreach($flow in $flows){
  if($flow.CreationTime -isnot [datetime] -or $flow.CreationTime -eq [datetime]::MinValue){throw 'endpoint_flow_creation_unknown'}
  $remote=ConvertTo-EndpointIP ([string]$flow.RemoteAddress)
  $key=(@([string]$flow.LocalAddress,[string]$flow.LocalPort,$remote,'443',[string]$ownerPid,$flow.CreationTime.ToUniversalTime().Ticks)-join '|')
  $keys+=,$key;if($mapping.addresses -contains $remote){$matches+=,$key}
 }
 return [pscustomobject]@{pid=$ownerPid;creation=$proc.CreationDate.ToUniversalTime().Ticks;image_hash=$imageHash;members=$members;flow_keys=@($keys|Sort-Object -Unique);matches=@($matches|Sort-Object -Unique);mapping_source=$mapping.source;address_count=@($mapping.addresses).Count;signature_valid=$false}
}
function Invoke-SstpEndpointObservation($Expected){
 $r=[ordered]@{schema='sstp-endpoint-observation-03';completed=$false;code='';stage='identity_before';vpn_state='unknown';identity_stable_within_run=$false;service_host_stable=$false;service_host_signature_valid=$false;signature_check_mode='not_attempted_avoid_implicit_network';process_path_and_hash_read=$false;service_host_sharing='unknown';hosted_service_count=0;host_TCP443_count=0;configured_address_source='unknown';configured_address_count=0;stable_candidate_count=0;endpoint_correlation_observed=$false;flow_attribution='none';service_tag_attribution_verified=$false;configured_endpoint_pin_approved=$false;DNS_bootstrap_verified=$false;TLS_bootstrap_verified=$false;firewall_approval_granted=$false;ready_for_apply=$false;no_leak_certified=$false;snapshots_atomic=$false;raw_identity_exported=$false;physical_adapter_bound=$false;network_policy_changed=$false;DNS_query_generated=$false;VPN_change_requested=$false}
 $before=$null;$after=$null;$a=$null;$b=$null
 try{
  $first=Invoke-SstpLifecycleObservation $Expected ([ref]$before)
  $r.vpn_state=$first.vpn_state
  if(-not $first.completed -or -not $first.identity_chain_verified -or $null -eq $before){throw 'endpoint_connected_identity_required'}
  $r.stage='endpoint_before';$a=Read-EndpointNativeSnapshot $Expected.server
  $r.stage='identity_after';$last=Invoke-SstpLifecycleObservation $Expected ([ref]$after) $before
  if(-not $last.completed -or -not $last.identity_chain_verified -or -not $last.binding_compared_to_previous -or $last.binding_changed_since_previous -or $null -eq $after){throw 'endpoint_live_binding_changed_or_unknown'}
  $r.identity_stable_within_run=$true
  $r.stage='endpoint_after';$b=Read-EndpointNativeSnapshot $Expected.server
  foreach($key in @('pid','creation','image_hash')){if([string]$a.$key -cne [string]$b.$key){throw 'endpoint_service_host_changed'}}
  if(($a.members -join '|') -cne ($b.members -join '|')){throw 'endpoint_service_membership_changed'}
  $r.service_host_stable=$true;$r.process_path_and_hash_read=$true;$r.hosted_service_count=@($b.members).Count
  $r.service_host_sharing=if($r.hosted_service_count -eq 1){'unshared'}else{'shared'}
  $r.host_TCP443_count=@($b.flow_keys).Count;$r.configured_address_source=$b.mapping_source;$r.configured_address_count=$b.address_count
  $stable=@($a.matches|Where-Object{$b.matches -contains $_}|Sort-Object -Unique);$r.stable_candidate_count=$stable.Count
  $r.completed=$true;$r.stage='completed'
  if(-not $a.address_count -or -not $b.address_count){$r.code='endpoint_local_cache_unresolved'}
  elseif($stable.Count -eq 0){$r.code='endpoint_no_stable_candidate'}
  elseif($stable.Count -gt 1){$r.code='endpoint_multiple_stable_candidates'}
  else{
   $r.endpoint_correlation_observed=$true
   if($r.service_host_sharing -ceq 'shared'){$r.code='endpoint_shared_host_process_only';$r.flow_attribution='shared_host_process_only'}
   else{$r.code='endpoint_unshared_service_host_correlated';$r.flow_attribution='unshared_service_host_endpoint_correlated'}
  }
 }catch{
  $message=[string]$_.Exception.GetBaseException().Message
  if($message -cmatch '^endpoint_[a-z_0-9]{1,90}$'){$r.code=$message}else{$r.code='endpoint_observation_unavailable'}
 }finally{$before=$null;$after=$null;$a=$null;$b=$null}
 return [pscustomobject]$r
}
