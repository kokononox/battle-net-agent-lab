# Strict data admission; never executes request content.
function UValidateRequest($q){
 if($q.schema -cne 'unified-lab-request-1' -or $q.mode -cnotin @('blacklist_only','vpn_allowlist') -or $q.legacy_imports -isnot [array] -or $q.legacy_acknowledged -isnot [bool] -or ($q.legacy_imports.Count -gt 0 -and -not $q.legacy_acknowledged)){throw 'unsupported_mode_or_unresolved_legacy_import'}
 $plan=$q.plan
 if($plan.schema -cne 'unified-firewall-plan-1' -or $plan.owner -cnotmatch '^[a-f0-9]{32}$' -or $plan.rules -isnot [array] -or $plan.rules.Count -lt 1 -or $plan.rules.Count -gt 1024 -or $q.programs -isnot [array] -or $q.programs.Count -gt 32){throw 'lab_plan_schema'}
 $programs=@{};foreach($p in $q.programs){
  if($p.path -isnot [string] -or $p.path -cnotmatch '^[A-Za-z]:\\' -or $p.path -match '[\x00-\x1f*?"<>|]' -or $p.path.Substring(2).Contains(':') -or $p.path -match '\\(?:\.|\.\.)(?:\\|$)' -or -not $p.path.EndsWith('.exe',[StringComparison]::OrdinalIgnoreCase) -or $p.sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'lab_program_identity'}
  UAssertPath $p.path
  if(-not [IO.File]::Exists($p.path) -or (Get-FileHash -LiteralPath $p.path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $p.sha256){throw 'program_binary_changed_before_apply'}
  if($programs.ContainsKey($p.id)){throw 'duplicate_program'};$programs[$p.id]=$p
 }
 $seen=@{}
 foreach($r in $plan.rules){
  if($r.owner -cne $plan.owner -or $r.component -cnotin @('blacklist','whitelist') -or $r.name -cnotmatch ('^UnifiedFW-'+$plan.owner+'-'+$r.component+'-[a-f0-9]{24}$') -or $seen.ContainsKey($r.name)){throw 'lab_rule_identity'};$seen[$r.name]=$true
  $s=$r.spec
  if((@($s.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'action,authentication,direction,edge_traversal,encryption,interface_alias,interface_type,local_addresses,local_port,override_block_rules,port,profile,program,program_id,protocol,remote_addresses,service'){throw 'lab_spec_schema'}
  foreach($pair in @(@($s.action,'Block'),@($s.direction,'Outbound'),@($s.profile,'Any'),@($s.service,'Any'),@($s.interface_alias,'Any'),@($s.local_port,'Any'),@($s.authentication,'NotRequired'),@($s.encryption,'NotRequired'),@($s.edge_traversal,'Block'))){if($pair[0] -cne $pair[1]){throw 'lab_fixed_spec_required'}}
  if($s.override_block_rules -isnot [bool] -or $s.override_block_rules -or @($s.local_addresses).Count -ne 1 -or $s.local_addresses[0] -cne 'Any'){throw 'lab_fixed_filters'}
  if($s.remote_addresses -isnot [array] -or $s.remote_addresses.Count -lt 1 -or $s.remote_addresses.Count -gt 2048){throw 'lab_address_limit'}
  foreach($text in $s.remote_addresses){
   if($text -isnot [string] -or $text -cnotmatch '^([0-9a-fA-F:.]+)/([0-9]{1,3})$'){throw 'lab_cidr_required'}
   $address=[Net.IPAddress]::Parse($Matches[1]);$prefix=[int]$Matches[2];$bits=32;if($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){$bits=128};if($prefix -lt 1 -or $prefix -gt $bits){throw 'lab_prefix'}
  }
  if($r.component -ceq 'blacklist'){
   if($s.program_id -isnot [string] -or -not $programs.ContainsKey($s.program_id) -or $s.program -cne $programs[$s.program_id].path -or $s.interface_type -cne 'Any' -or $s.protocol -cnotin @('TCP','UDP') -or ($s.port -isnot [int] -and $s.port -isnot [long]) -or $s.port -lt 1 -or $s.port -gt 65535){throw 'lab_blacklist_scope'}
  }else{
   if($q.mode -cne 'vpn_allowlist' -or $null -ne $s.program_id -or $s.program -cne 'Any' -or $s.interface_type -cne 'RemoteAccess' -or $s.protocol -cne 'Any' -or $s.port -cne 'Any'){throw 'lab_whitelist_scope'}
  }
 }
}
