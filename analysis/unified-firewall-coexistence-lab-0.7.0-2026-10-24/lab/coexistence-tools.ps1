# Route observations are not packet captures or no-leak guarantees.
function CProperty($Object,[string]$Name){$p=$Object.PSObject.Properties[$Name];if($null -eq $p -or $null -eq $p.Value){throw ('route_property_missing:'+ $Name)};return $p.Value}
function CReadRoute([string]$Address){
 TAssertPublicIPv4 $Address
 $selected=@(Find-NetRoute -RemoteIPAddress $Address -ErrorAction Stop)
 $routes=@($selected|Where-Object{$null -ne $_.PSObject.Properties['DestinationPrefix']})
 $sources=@($selected|Where-Object{$null -ne $_.PSObject.Properties['IPAddress'] -and $null -eq $_.PSObject.Properties['DestinationPrefix']})
 if($routes.Count -ne 1 -or $sources.Count -ne 1){throw 'route_selection_ambiguous'}
 $route=$routes[0];$source=$sources[0];$index=CProperty $route 'InterfaceIndex'
 if([int](CProperty $source 'InterfaceIndex') -ne [int]$index){throw 'route_source_interface_mismatch'}
 $ipif=@(Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop)
 if($ipif.Count -ne 1 -or [string](CProperty $ipif[0] 'ConnectionState') -cne 'Connected'){throw 'route_interface_not_connected'}
 $alias=[string](CProperty $ipif[0] 'InterfaceAlias');$vpns=@()
 foreach($scope in @('current_user','all_users')){
  $args=@{ErrorAction='Stop'};if($scope -ceq 'all_users'){$args.AllUserConnection=$true}
  # Incomplete inventory is a blocker, not an assumed absence.
  foreach($v in @(Get-VpnConnection @args)){if([string]$v.Name -ceq $alias -and [string]$v.ConnectionStatus -ceq 'Connected' -and [string]$v.TunnelType -ceq 'Sstp'){$vpns+=,[pscustomobject]@{scope=$scope;name=[string]$v.Name;server=[string]$v.ServerAddress}}}
 }
 if($vpns.Count -ne 1){throw 'endpoint_not_on_unique_connected_sstp_route; use_an_authorized_endpoint_other_than_vpn_server_IP'}
 if($vpns[0].server -ceq $Address){throw 'vpn_server_IP_cannot_be_coexistence_endpoint'}
 $local=[Net.IPAddress]::Parse([string](CProperty $source 'IPAddress'));if($local.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){throw 'route_source_not_ipv4'}
 return [pscustomobject][ordered]@{schema='unifiedfw-route-observation-1';address=$Address;interface_index=[int]$index;interface_alias=$alias;source_ipv4=$local.ToString();destination_prefix=[string](CProperty $route 'DestinationPrefix');next_hop=[string](CProperty $route 'NextHop');route_metric=[int](CProperty $route 'RouteMetric');interface_metric=[int](CProperty $ipif[0] 'InterfaceMetric');vpn_scope=$vpns[0].scope;vpn_name=$vpns[0].name;vpn_server=$vpns[0].server;selected_route_matches_connected_sstp=$true;packet_path_proven=$false}
}
function CAssertRoute([string]$Address,$Expected){$now=CReadRoute $Address;if(-not (UEqual $Expected $now)){throw 'sstp_route_changed_abort_and_restore'};return $now}
function CValidateRequest($RequestData,[string]$Root){
 if((@($RequestData.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'address,phases,port,programs,schema,scope' -or $RequestData.schema -cne 'unifiedfw-coexistence-request-1' -or $RequestData.scope -cne 'two_bundled_images_one_ipv4_one_tcp_port_RemoteAccess_whitelist_projection'){throw 'coexistence_schema'}
 TAssertPublicIPv4 ([string]$RequestData.address)
 if(($RequestData.port -isnot [int] -and $RequestData.port -isnot [long]) -or $RequestData.port -lt 1024 -or $RequestData.port -gt 65535 -or $RequestData.programs -isnot [array] -or $RequestData.programs.Count -ne 2 -or $RequestData.phases -isnot [array] -or $RequestData.phases.Count -ne 6){throw 'coexistence_endpoint_or_array_schema'}
 $programs=@{};$programIDs=@{};$j=0
 foreach($program in $RequestData.programs){
  $role=@('A','B')[$j];$name=@('python.exe','pythonw.exe')[$j];$j++
  if((@($program.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'enabled,id,path,role,sha256' -or $program.role -cne $role -or $program.enabled -isnot [bool] -or -not $program.enabled -or $program.id -cnotmatch '^[a-f0-9]{24}$' -or $programIDs.ContainsKey($program.id) -or -not (UStringEqual $program.path (Join-Path $Root ('runtime/'+$name)))){throw 'coexistence_only_bundled_enabled_images'}
  $programs[$role]=$program;$programIDs[$program.id]=$true
 }
 $names=@('wl_allows','wl_denies','wl_allows_bl_A','wl_allows_bl_B','wl_allows_bl_both','wl_denies_bl_A');$counts=@(0,2,1,1,2,3)
 $blRoles=@(@(),@(),@('A'),@('B'),@('A','B'),@('A'));$wlNeeded=@($false,$true,$false,$false,$false,$true);$owner=$null
 for($phaseIndex=0;$phaseIndex -lt 6;$phaseIndex++){
  $phase=$RequestData.phases[$phaseIndex];$phaseRequest=$phase.request;$plan=$phaseRequest.plan
  if($phase.name -cne $names[$phaseIndex] -or $phaseRequest.schema -cne 'unified-lab-request-1' -or $phaseRequest.mode -cne 'vpn_allowlist' -or $phaseRequest.legacy_imports -isnot [array] -or $phaseRequest.legacy_imports.Count -ne 0 -or $phaseRequest.legacy_acknowledged -isnot [bool] -or $phaseRequest.legacy_acknowledged -or $phaseRequest.programs -isnot [array] -or $phaseRequest.programs.Count -ne 2 -or $plan.schema -cne 'unified-firewall-plan-1' -or $plan.owner -cnotmatch '^[a-f0-9]{32}$' -or $plan.rules -isnot [array] -or $plan.rules.Count -ne $counts[$phaseIndex] -or $plan.lab_scope -cne $RequestData.scope -or $plan.activation_allowed -isnot [bool] -or $plan.activation_allowed -or $plan.no_leak_certified -isnot [bool] -or $plan.no_leak_certified){throw 'coexistence_phase_schema'}
  if($null -eq $owner){$owner=$plan.owner};if($plan.owner -cne $owner){throw 'coexistence_owner_changed'}
  $seenPrograms=@{}
  foreach($program in $phaseRequest.programs){$same=@($RequestData.programs|Where-Object{$_.id -ceq $program.id -and $_.path -ceq $program.path -and $_.sha256 -ceq $program.sha256 -and $_.enabled -ceq $program.enabled});if($same.Count -ne 1 -or $seenPrograms.ContainsKey($program.id)){throw 'coexistence_phase_program_mismatch'};$seenPrograms[$program.id]=$true}
  $seen=@{}
  foreach($rule in $plan.rules){
   $spec=$rule.spec;$role=$null;foreach($key in @('A','B')){if($spec.program_id -ceq $programs[$key].id){$role=$key}}
   if($null -eq $role -or $rule.owner -cne $owner -or $rule.component -cnotin @('blacklist','whitelist') -or $rule.name -cnotmatch ('^UnifiedFW-'+$owner+'-'+$rule.component+'-[a-f0-9]{24}$') -or $spec.program -cne $programs[$role].path -or $spec.protocol -cne 'TCP' -or $spec.port -ne $RequestData.port -or $spec.remote_addresses -isnot [array] -or $spec.remote_addresses.Count -ne 1 -or $spec.remote_addresses[0] -cne ($RequestData.address+'/32')){throw 'coexistence_fixed_endpoint_and_images_only'}
   $key=$rule.component+':'+$role;if($seen.ContainsKey($key)){throw 'coexistence_duplicate_rule'};$seen[$key]=$true
   if($rule.component -ceq 'whitelist'){if(-not $wlNeeded[$phaseIndex] -or $spec.interface_type -cne 'RemoteAccess'){throw 'coexistence_whitelist_scope'}}
   elseif($role -cnotin $blRoles[$phaseIndex] -or $spec.interface_type -cne 'Any'){throw 'coexistence_blacklist_scope'}
  }
  foreach($role in @('A','B')){if($wlNeeded[$phaseIndex] -and -not $seen.ContainsKey('whitelist:'+$role)){throw 'coexistence_missing_whitelist_projection'}}
  foreach($role in $blRoles[$phaseIndex]){if(-not $seen.ContainsKey('blacklist:'+$role)){throw 'coexistence_missing_blacklist'}}
  # Reuse unchanged fixed-filter/file-hash admission on a COPY. Normalizing
  # tags/interface ONLY for admission never changes the original/apply plan.
  $admission=ConvertFrom-Json -InputObject (UJson $phaseRequest);$admission.mode='blacklist_only'
  foreach($rule in $admission.plan.rules){$rule.component='blacklist';$rule.name='UnifiedFW-'+$owner+'-blacklist-'+([guid]::NewGuid().ToString('N').Substring(0,24));$rule.spec.interface_type='Any'}
  if($admission.plan.rules.Count -gt 0){UValidateRequest $admission}
  else{
   # Zero-rule allowed phase still verifies BOTH real on-disk files; feed a
   # fixed validation-only block into the existing validator, never apply it.
   $sample=ConvertFrom-Json -InputObject (UJson $RequestData.phases[2].request.plan.rules[0]);$sample.component='blacklist';$sample.name='UnifiedFW-'+$owner+'-blacklist-'+([guid]::NewGuid().ToString('N').Substring(0,24));$sample.spec.interface_type='Any';$admission.plan.rules=@($sample);UValidateRequest $admission
  }
 }
}
