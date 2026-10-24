param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
foreach($file in @('session-core.ps1','native.ps1','traffic-tools.ps1','https-tools.ps1','coexistence-tools.ps1')){. (Join-Path $Root ('lab/'+$file))}
$script:checks=0;$script:admissions=0
function Check([bool]$OK,[string]$Why){$script:checks++;if(-not $OK){throw ('coexistence_assertion:'+ $Why)}}
function Throws([scriptblock]$Body){$caught=$false;try{& $Body|Out-Null}catch{$caught=$true};Check $caught 'expected_rejection'}
function Clone($v){ConvertFrom-Json -InputObject (UJson $v)}
# Existing fixed-filter and real-file validator is independently covered in
# Test-NativeAdapter. Here only that boundary is a double (no Windows disk).
function UValidateRequest($Data){
 $script:admissions++;if($Data.mode -cne 'blacklist_only' -or $Data.plan.rules.Count -lt 1){throw 'normalized_admission_schema'}
 foreach($rule in $Data.plan.rules){if($rule.component -cne 'blacklist' -or $rule.spec.interface_type -cne 'Any'){throw 'normalized_admission_scope'}}
}
function Join-Path {param($Path,$ChildPath)
 if($Path -ceq 'C:\Fixture'){return ('C:\Fixture\'+$ChildPath.Replace('/','\'))}
 Microsoft.PowerShell.Management\Join-Path $Path $ChildPath
}
$wire=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $Root 'tests/coexistence-request.json')));$before=UJson $wire
CValidateRequest $wire 'C:\Fixture';Check ($script:admissions -eq 6) 'all_phases_admitted';Check ((UJson $wire) -ceq $before) 'original_plans_unchanged'
foreach($kind in @('port','address','global_program','global_interface','whitelist_as_blacklist','blacklist_as_whitelist','missing_program','wrong_hash','duplicate_program','wrong_order','foreign_owner','enable_activation','duplicate_role','unbounded_port','scope','zero_phase_rules')){
 $bad=Clone $wire
 switch($kind){
  'port' {$bad.phases[1].request.plan.rules[0].spec.port=39444}
  'address' {$bad.phases[1].request.plan.rules[0].spec.remote_addresses=@('8.8.8.8/32')}
  'global_program' {$bad.phases[1].request.plan.rules[0].spec.program='Any'}
  'global_interface' {$bad.phases[1].request.plan.rules[0].spec.interface_type='Any'}
  'whitelist_as_blacklist' {$bad.phases[1].request.plan.rules[0].component='blacklist'}
  'blacklist_as_whitelist' {$bad.phases[2].request.plan.rules[0].component='whitelist'}
  'missing_program' {$bad.phases[2].request.programs=@($bad.phases[2].request.programs[0])}
  'wrong_hash' {$bad.phases[1].request.programs[0].sha256='b'*64}
  'duplicate_program' {$bad.phases[1].request.programs[1]=Clone $bad.phases[1].request.programs[0]}
  'wrong_order' {$bad.phases[2].name='wl_allows'}
  'foreign_owner' {$bad.phases[2].request.plan.owner='f'*32}
  'enable_activation' {$bad.phases[2].request.plan.activation_allowed=$true}
  'duplicate_role' {$bad.programs[1].role='A'}
  'unbounded_port' {$bad.port=443}
  'scope' {$bad.scope='global'}
  'zero_phase_rules' {$bad.phases[0].request.plan.rules=@($bad.phases[2].request.plan.rules[0])}
 }
 Throws {CValidateRequest $bad 'C:\Fixture'}
}
$httpsWire=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $Root 'tests/https-coexistence-request.json')))
$beforeHttps=UJson $httpsWire;CValidateRequest $httpsWire 'C:\Fixture';Check ((UJson $httpsWire) -ceq $beforeHttps) 'HTTPS_admission_preserves_plan'
foreach($kind in @('port','host','path','url','transport','rule_port')){
 $bad=Clone $httpsWire
 switch($kind){
  'port' {$bad.port=4443}
  'host' {$bad.https_host='other.example'}
  'path' {$bad.https_path='/other.php'}
  'url' {$bad.https_url='http://ufw-test.example/probe.php'}
  'transport' {$bad.transport='http'}
  'rule_port' {$bad.phases[1].request.plan.rules[0].spec.port=80}
 }
 Throws {CValidateRequest $bad 'C:\Fixture'}
}
# Route doubles: captures selected route/source, not actual RAS packets.
$script:routeCase='good'
function Find-NetRoute{param($RemoteIPAddress,$ErrorAction)
 $index=42;if($script:routeCase -ceq 'physical'){$index=7}
 $route=[pscustomobject]@{DestinationPrefix='9.9.9.9/32';InterfaceIndex=$index;NextHop='0.0.0.0';RouteMetric=5}
 $sourceIndex=$index;if($script:routeCase -ceq 'mismatch'){$sourceIndex=88}
 $source=[pscustomobject]@{IPAddress='10.20.30.40';InterfaceIndex=$sourceIndex}
 if($script:routeCase -ceq 'missing_source'){return $route};if($script:routeCase -ceq 'ambiguous'){return @($route,$route,$source)}
 return @($route,$source)
}
function Get-NetIPInterface{param($InterfaceIndex,$AddressFamily,$ErrorAction)
 $alias='VPN Fixture';if($InterfaceIndex -eq 7){$alias='Ethernet'};$state='Connected';if($script:routeCase -ceq 'disconnected'){$state='Disconnected'}
 [pscustomobject]@{InterfaceAlias=$alias;ConnectionState=$state;InterfaceMetric=10}
}
function Get-VpnConnection{param([switch]$AllUserConnection,$ErrorAction)
 if($script:routeCase -ceq 'inventory_error'){throw 'fixture_inventory_error'}
 if($AllUserConnection){return}
 $server='vpn.fixture.invalid';$tunnel='Sstp';$status='Connected'
 if($script:routeCase -ceq 'server_ip'){$server='9.9.9.9'}
 if($script:routeCase -ceq 'other_tunnel'){$tunnel='Ikev2'}
 if($script:routeCase -ceq 'vpn_down'){$status='Disconnected'}
 [pscustomobject]@{Name='VPN Fixture';ServerAddress=$server;TunnelType=$tunnel;ConnectionStatus=$status}
}
$good=CReadRoute '9.9.9.9';Check ($good.interface_index -eq 42 -and $good.selected_route_matches_connected_sstp -and -not $good.packet_path_proven) 'route_snapshot_only'
$null=CAssertRoute '9.9.9.9' $good;Check $true 'stable_route_snapshot'
foreach($kind in @('physical','mismatch','missing_source','ambiguous','disconnected','inventory_error','server_ip','other_tunnel','vpn_down')){$script:routeCase=$kind;Throws {CReadRoute '9.9.9.9'}}
$script:routeCase='good';$changed=Clone $good;$changed.source_ipv4='10.20.30.41';Throws {CAssertRoute '9.9.9.9' $changed}
$report=[ordered]@{passed=$true;assertions=$script:checks;windows_executed=$false;backend='request admission boundary and route test doubles';native_rule_creation_tested=$false;packet_path_proven=$false}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/coexistence-tests.json'),(UJson $report));$report|ConvertTo-Json -Compress
