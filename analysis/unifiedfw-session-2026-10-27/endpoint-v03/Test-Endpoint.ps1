param([string]$Root='/data/sstp-endpoint-v03/package/SSTP-ENDPOINT-OBSERVER-03')
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. (Join-Path $Root 'Endpoint.ps1')
$script:checks=0
function Check($b,$m){$script:checks++;if(-not $b){throw $m}}
function Reject($f,$code){try{& $f;throw 'TEST_EXPECTED_REJECTION'}catch{Check ($_.Exception.Message -ceq $code) ('wrong rejection: '+$_.Exception.Message)}}
function CacheRow($name,$type,$data,$ttl=30,$status=0){[pscustomobject]@{Name=$name;Entry='query.invalid';Type=$type;Data=$data;TimeToLive=$ttl;Status=$status}}
$rows=@((CacheRow 'vpn.fixture.invalid' 5 'edge.fixture.invalid.'),(CacheRow 'edge.fixture.invalid' 1 '192.0.2.10'),(CacheRow 'edge.fixture.invalid' 28 '2001:db8::1'))
$m=Get-EndpointCacheAddresses 'VPN.fixture.invalid.' $rows
Check ($m.addresses.Count -eq 2 -and $m.addresses -contains '192.0.2.10') 'cache chain'
Check ($m.source -ceq 'local_cache_not_trusted_pin') 'not trusted pin'
Check ((Get-EndpointCacheAddresses '192.0.2.8' @()).source -ceq 'configured_literal') 'literal'
Check (@((Get-EndpointCacheAddresses 'vpn.fixture.invalid' @()).addresses).Count -eq 0) 'cold cache'
foreach($r in @((CacheRow 'vpn.fixture.invalid' 1 '192.0.2.1' 0),(CacheRow 'vpn.fixture.invalid' 1 '192.0.2.1' 30 9003))){Check (@((Get-EndpointCacheAddresses 'vpn.fixture.invalid' @($r)).addresses).Count -eq 0) 'negative expired'}
Reject {Get-EndpointCacheAddresses 'vpn.fixture.invalid' @((CacheRow 'vpn.fixture.invalid' 5 'vpn.fixture.invalid'))} 'endpoint_cache_cname_loop'
Reject {Get-EndpointCacheAddresses 'vpn.fixture.invalid' @((CacheRow 'vpn.fixture.invalid' 5 'a.invalid'),(CacheRow 'vpn.fixture.invalid' 5 'b.invalid'))} 'endpoint_cache_cname_conflict'
Reject {Get-EndpointCacheAddresses 'vpn.fixture.invalid' @((CacheRow 'vpn.fixture.invalid' 5 'a.invalid'),(CacheRow 'vpn.fixture.invalid' 1 '192.0.2.1'))} 'endpoint_cache_cname_conflict'
Reject {Get-EndpointCacheAddresses 'vpn.fixture.invalid' @((CacheRow 'vpn.fixture.invalid' 28 '192.0.2.1'))} 'endpoint_cache_address_family_mismatch'
foreach($bad in @('https://vpn.invalid','*.invalid','x..invalid','a.invalid:443',' a.invalid','a`b.invalid')){Reject {ConvertTo-EndpointHost $bad} 'endpoint_hostname_invalid'}
Reject {Get-EndpointCacheAddresses 'vpn.fixture.invalid' @([pscustomobject]@{Name='vpn.fixture.invalid';Type=1})} 'endpoint_cache_shape_unknown'
Reject {ConvertTo-EndpointIP '127.0.0.1'} 'endpoint_ip_invalid'
# Exercise actual native adapter orchestration with fixture cmdlets (no Windows APIs).
$script:services=@([pscustomobject]@{Name='SstpSvc';State='Running';ProcessId=123},[pscustomobject]@{Name='Other';State='Running';ProcessId=123})
$script:flows=@([pscustomobject]@{OwningProcess=123;RemotePort=443;LocalAddress='192.0.2.50';LocalPort=50001;RemoteAddress='192.0.2.10';CreationTime=[datetime]'2026-01-01Z'},[pscustomobject]@{OwningProcess=456;RemotePort=443;LocalAddress='192.0.2.50';LocalPort=50002;RemoteAddress='192.0.2.10';CreationTime=[datetime]'2026-01-01Z'})
$script:dnsCalls=0;$script:imageCalls=0
function Get-CimInstance{param($ClassName,$Filter,$ErrorAction)if($ClassName -ceq 'Win32_Service'){return $script:services};Check ($Filter -ceq 'ProcessId = 123') 'pid exact';return [pscustomobject]@{CreationDate=[datetime]'2025-01-01Z';ExecutablePath='fixture'}}
function Read-EndpointImageIdentity($proc){$script:imageCalls++;return 'fixture-hash'}
function Get-DnsClientCache{param($ErrorAction)$script:dnsCalls++;return $rows}
function Get-NetTCPConnection{param($State,$ErrorAction)Check ($State -ceq 'Established') 'established filter';return $script:flows}
$a=Read-EndpointNativeSnapshot 'vpn.fixture.invalid'
Check ($a.members.Count -eq 2 -and $a.matches.Count -eq 1 -and $a.flow_keys.Count -eq 1) 'pid and endpoint matching'
Check ($script:dnsCalls -eq 1 -and $script:imageCalls -eq 1) 'native read adapters called'
$b=Read-EndpointNativeSnapshot '192.0.2.10';Check ($script:dnsCalls -eq 1 -and $b.matches.Count -eq 1) 'literal no dns cache call'
$script:services[0].State='Stopped';Reject {Read-EndpointNativeSnapshot '192.0.2.10'} 'endpoint_service_not_running';$script:services[0].State='Running'
$script:flows[0].CreationTime=$null;Reject {Read-EndpointNativeSnapshot '192.0.2.10'} 'endpoint_flow_creation_unknown';$script:flows[0].CreationTime=[datetime]'2026-01-01Z'
# Exercise real endpoint decision/orchestration; lifecycle/native snapshots are modeled here.
function Reset-Fixture{
 $script:n=0;$script:mode='normal';$script:lifeCalls=0
 $script:snapshot=[pscustomobject]@{pid=123;creation=1;image_hash='hash';members=@('Other','SstpSvc');flow_keys=@('tuple1');matches=@('tuple1');mapping_source='local_cache_not_trusted_pin';address_count=1;signature_valid=$true}
}
function Invoke-SstpLifecycleObservation{param($Expected,[ref]$PrivateBinding,$PreviousBinding=$null)
 $script:lifeCalls++;$PrivateBinding.Value=[pscustomobject]@{private='not exported'}
 [pscustomobject]@{completed=($script:mode -cne 'identity_failure');identity_chain_verified=($script:mode -cne 'identity_failure');vpn_state='connected';binding_compared_to_previous=($null -ne $PreviousBinding);binding_changed_since_previous=($script:mode -ceq 'binding_change' -and $script:lifeCalls -eq 2)}
}
function Read-EndpointNativeSnapshot($Server){
 $script:n++;$x=$script:snapshot|ConvertTo-Json -Depth 10|ConvertFrom-Json
 if($script:n -eq 2){switch($script:mode){'pid_change'{$x.pid=124};'creation_change'{$x.creation=2};'hash_change'{$x.image_hash='new'};'members_change'{$x.members=@('SstpSvc')};'flow_change'{$x.matches=@('tuple2')};'cache_cold'{$x.address_count=0;$x.matches=@();$x.mapping_source='local_cache_unresolved'}}}
 if($script:mode -ceq 'raw_error'){throw 'PRIVATE_SERVER_AND_PATH'}
 return $x
}
$expected=[pscustomobject]@{server='private.fixture.invalid'}
Reset-Fixture;$r=Invoke-SstpEndpointObservation $expected
Check ($r.completed -and $r.endpoint_correlation_observed -and $r.code -ceq 'endpoint_shared_host_process_only') 'shared host not service claim'
Check ($r.identity_stable_within_run -and $r.service_host_stable) 'stable guards'
foreach($key in @('service_host_signature_valid','service_tag_attribution_verified','configured_endpoint_pin_approved','DNS_bootstrap_verified','TLS_bootstrap_verified','firewall_approval_granted','ready_for_apply','no_leak_certified','raw_identity_exported','physical_adapter_bound','network_policy_changed','DNS_query_generated','VPN_change_requested','snapshots_atomic')){Check ($r.$key -ceq $false) ('false boundary '+$key)}
Check ($r.signature_check_mode -ceq 'not_attempted_avoid_implicit_network' -and $r.process_path_and_hash_read) 'offline signature boundary'
Check (($r|ConvertTo-Json -Depth 10) -notmatch 'private.fixture|tuple1|fixture-hash') 'privacy'
Reset-Fixture;$script:snapshot.members=@('SstpSvc');$r=Invoke-SstpEndpointObservation $expected;Check ($r.code -ceq 'endpoint_unshared_service_host_correlated' -and -not $r.service_tag_attribution_verified) 'unshared limited claim'
foreach($case in @('pid_change','creation_change','hash_change','members_change','binding_change','identity_failure','raw_error')){
 Reset-Fixture;$script:mode=$case;$r=Invoke-SstpEndpointObservation $expected
 Check (-not $r.completed -and -not $r.endpoint_correlation_observed -and -not $r.ready_for_apply) ('fail closed '+$case)
}
foreach($case in @('flow_change','cache_cold')){Reset-Fixture;$script:mode=$case;$r=Invoke-SstpEndpointObservation $expected;Check ($r.completed -and -not $r.endpoint_correlation_observed) $case}
Reset-Fixture;$script:snapshot.matches=@('tuple1','tuple2');$r=Invoke-SstpEndpointObservation $expected;Check ($r.code -ceq 'endpoint_multiple_stable_candidates' -and -not $r.endpoint_correlation_observed) 'ambiguity'
[pscustomobject]@{schema='sstp-endpoint-model-tests-03';assertions=$script:checks;passed=$true;native_Windows_API_executed=$false;network_or_firewall_changed=$false;ready_for_apply=$false}|ConvertTo-Json|Set-Content -LiteralPath '/data/sstp-endpoint-v03/model-results.json' -Encoding UTF8
Write-Host ('PASS '+$script:checks+' assertions')
