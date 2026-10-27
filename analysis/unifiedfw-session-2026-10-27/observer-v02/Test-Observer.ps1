param([string]$Root='/data/sstp-observer-v02/package/SSTP-READONLY-OBSERVER-02')
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. (Join-Path $Root 'Observer.ps1')
# Compile real helper and inspect ABI only. Never invoke its Windows native APIs in Linux.
ImportIdentityNativeHelper
if([SstpIdentityV1.Native]::RasSize -ne 1388 -or [SstpIdentityV1.Native]::ProjectionSize -ne 80){throw 'model_host_ABI_unexpected'}
$script:checks=0
function Check($b,$m){$script:checks++;if(-not $b){throw $m}}
function Clone($x){ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $x -Depth 24)}
function Reset-Fixture{
 $script:guid=[guid]'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';$script:correlation=[guid]'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';$script:nicGuid=[guid]'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
 $script:name='SSTP fixture';$script:server='vpn.fixture.invalid';$script:status='Connected';$script:scope='current_user';$script:split=$false;$script:tunnel='Sstp';$script:sid='S-1-5-21-111-222-333-1001'
 $script:alias=$script:name;$script:index=42;$script:luid=[uint64]123456789;$script:handle=[IntPtr]1234;$script:client='192.0.2.50'
 $script:rasGuid=$script:guid;$script:rasName=$script:name;$script:rasAllUsers=$false;$script:rasDevice='vpn';$script:nicUp=$true;$script:nicType=23;$script:roundtripGuid=$script:nicGuid
 $script:failScope='';$script:duplicates=$false;$script:otherVpn=$false;$script:rasDuplicate=$false;$script:projectionDuplicate=$false;$script:forceRasOffline=$false;$script:hook='';$script:nativeCalls=0;$script:omitProperty='';$script:splitUnknown=$false
 $script:expected=[pscustomobject][ordered]@{schema='sstp-observer-selection-1';profile_guid=$script:guid.ToString('D');profile_scope=$script:scope;profile_name=$script:name;server=$script:server;owner_sid=$script:sid}
}
function Read-SstpObserverCallerSid{$script:sid}
function Get-VpnConnection{
 param([switch]$AllUserConnection,$ErrorAction)
 $scope=if($AllUserConnection){'all_users'}else{'current_user'}
 if($scope -ceq $script:failScope){throw 'RAW_PRIVATE_PATH_AND_SERVER_ERROR'}
 if($scope -cne $script:scope){return @()}
 $p=[pscustomobject]@{Guid=$script:guid;Name=$script:name;ServerAddress=$script:server;TunnelType=$script:tunnel;ConnectionStatus=$script:status;SplitTunneling=$script:split}
 if($script:omitProperty){$p.PSObject.Properties.Remove($script:omitProperty)}
 if($script:splitUnknown){$p.SplitTunneling=$null}
 $rows=@($p);if($script:duplicates){$rows+=,$p}
 if($script:otherVpn){$rows+=,[pscustomobject]@{Guid=[guid]'dddddddd-dddd-4ddd-8ddd-dddddddddddd';Name='Other fixture';ServerAddress='other.invalid';TunnelType='Ikev2';ConnectionStatus='Connected';SplitTunneling=$false}}
 return $rows
}
function ReadNativeRasRecords{
 $script:nativeCalls++
 if($script:status -cne 'Connected' -and -not $script:forceRasOffline){return @()}
 $r=[pscustomobject]@{EntryGuid=$script:rasGuid;EntryName=$script:rasName;DeviceType=$script:rasDevice;AllUsers=$script:rasAllUsers;Handle=$script:handle;CorrelationGuid=$script:correlation}
 if($script:rasDuplicate){return @($r,$r)};return @($r)
}
function ReadNativeProjectionIPv4{param($h)$script:client}
function ReadNativeIdentityAdapters{
 $n=[pscustomobject]@{Guid=$script:nicGuid;Index=$script:index;Name=$script:alias;Type=$script:nicType;Up=$script:nicUp;IPv4=@($script:client)}
 if($script:projectionDuplicate){return @($n,$n)};return @($n)
}
function ReadNativeInterfaceIdentity{param($Index)[pscustomobject]@{Guid=$script:roundtripGuid;NetLuid=$script:luid;Index=$Index}}
function WaitIdentityRecheck{
 switch($script:hook){
 'server_change'{$script:server='changed.private.invalid'}
 'disconnect'{$script:status='Disconnected'}
 'correlation_change'{$script:correlation=[guid]'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'}
 'sid_change'{$script:sid='S-1-5-18'}
 };$script:hook=''
}
function Observe($Previous=$null){$private=$null;$r=Invoke-SstpLifecycleObservation $script:expected ([ref]$private) $Previous;return [pscustomobject]@{report=$r;private=$private}}
Reset-Fixture;$x=Observe
Check ($x.report.completed -and $x.report.identity_chain_verified -and $x.report.vpn_state -ceq 'connected') 'connected native chain through production observer'
Check ($null -ne $x.private -and $x.private.interface_index -eq 42) 'private binding passed only by ref'
Check (-not $x.report.endpoint_verified -and -not $x.report.DNS_bootstrap_verified -and -not $x.report.TLS_bootstrap_verified -and -not $x.report.ready_for_apply) 'identity is not transport or bootstrap approval'
$text=$x.report|ConvertTo-Json -Depth 10
Check (-not ($text -match 'fixture|192\.0\.2|aaaaaaaa|123456789|S-1-5-21')) 'no raw private binding in report'
foreach($state in @('Disconnected','Connecting')){
 Reset-Fixture;$script:status=$state;$x=Observe
 Check ($x.report.completed -and $x.report.selected_profile_matched -and -not $x.report.identity_chain_verified) ('saved profile recognized while '+$state)
 Check ($null -eq $x.private) 'no live binding invented offline'
}
foreach($case in @('current_context','scope','server','name','guid','split','tunnel','duplicates','other_vpn','missing_property','unknown_split','inventory_fail','ras_guid','ras_name','ras_scope','ras_device','zero_handle','zero_correlation','ras_duplicate','projection_duplicate','wrong_type','nic_down','roundtrip','unsafe_alias','server_during_chain','disconnect_during_chain','correlation_during_chain','context_during_chain','offline_ras_conflict','state_unknown')){
 Reset-Fixture
 switch($case){
 'current_context'{$script:sid='S-1-5-18'}
 'scope'{$script:scope='all_users'}
 'server'{$script:server='different.invalid'}
 'name'{$script:name='Another fixture'}
 'guid'{$script:guid=[guid]'ffffffff-ffff-4fff-8fff-ffffffffffff'}
 'split'{$script:split=$true}
 'tunnel'{$script:tunnel='Ikev2'}
 'duplicates'{$script:duplicates=$true}
 'other_vpn'{$script:otherVpn=$true}
 'missing_property'{$script:omitProperty='Guid'}
 'unknown_split'{$script:splitUnknown=$true}
 'inventory_fail'{$script:failScope='all_users'}
 'ras_guid'{$script:rasGuid=[guid]'ffffffff-ffff-4fff-8fff-ffffffffffff'}
 'ras_name'{$script:rasName='wrong'}
 'ras_scope'{$script:rasAllUsers=$true}
 'ras_device'{$script:rasDevice='modem'}
 'zero_handle'{$script:handle=[IntPtr]::Zero}
 'zero_correlation'{$script:correlation=[guid]::Empty}
 'ras_duplicate'{$script:rasDuplicate=$true}
 'projection_duplicate'{$script:projectionDuplicate=$true}
 'wrong_type'{$script:nicType=6}
 'nic_down'{$script:nicUp=$false}
 'roundtrip'{$script:roundtripGuid=[guid]'ffffffff-ffff-4fff-8fff-ffffffffffff'}
 'unsafe_alias'{$script:alias='Any'}
 'server_during_chain'{$script:hook='server_change'}
 'disconnect_during_chain'{$script:hook='disconnect'}
 'correlation_during_chain'{$script:hook='correlation_change'}
 'context_during_chain'{$script:hook='sid_change'}
 'offline_ras_conflict'{$script:status='Disconnected';$script:forceRasOffline=$true}
 'state_unknown'{$script:status='Unknown'}
 }
 $x=Observe;Check (-not $x.report.completed -and -not $x.report.identity_chain_verified) ('reject '+$case)
 Check ($null -eq $x.private) ('clear private on '+$case)
}
# Native alias need not equal display/profile name; strong GUID/RAS/projection chain governs.
Reset-Fixture;$script:alias='Literal PPP interface';$x=Observe;Check ($x.report.completed -and $x.private.interface_alias -ceq 'Literal PPP interface') 'strong mapped alias instead of name-only lookup'
# A new network index is detected as a new binding, never accepted as previous identity.
Reset-Fixture;$old=(Observe).private;$script:index=57;$script:luid=987654321;$script:correlation=[guid]'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';$x=Observe $old
Check ($x.report.completed -and $x.report.binding_changed_since_previous) 'reconnection markers differ but new chain verified'
$x=Observe $x.private;Check ($x.report.completed -and -not $x.report.binding_changed_since_previous) 'same observed binding compared'
$old.profile_guid='ffffffff-ffff-4fff-8fff-ffffffffffff';$x=Observe $old;Check (-not $x.report.completed) 'previous profile mismatch not adopted'
# Machine/global profiles can be observed by SYSTEM, but a current-user profile cannot.
Reset-Fixture;$script:scope='all_users';$script:rasAllUsers=$true;$script:expected.profile_scope='all_users';$script:sid='S-1-5-18';$x=Observe
Check ($x.report.completed -and $x.report.identity_chain_verified) 'all-user profile valid from machine context'
# Strict contract rejects missing/extra/coerced approval fields.
foreach($case in @('missing','extra','bad_guid','empty_guid','bad_sid','wildcard','any','bad_scope','nonstring')){
 Reset-Fixture
 switch($case){'missing'{$script:expected.PSObject.Properties.Remove('server')};'extra'{$script:expected|Add-Member NoteProperty untrusted_approved $true};'bad_guid'{$script:expected.profile_guid='bad'};'empty_guid'{$script:expected.profile_guid=[guid]::Empty.ToString('D')};'bad_sid'{$script:expected.owner_sid='bad'};'wildcard'{$script:expected.profile_name='*'};'any'{$script:expected.profile_name='Any'};'bad_scope'{$script:expected.profile_scope='unknown'};'nonstring'{$script:expected.owner_sid=$true}}
 $x=Observe;Check (-not $x.report.completed -and $x.report.code -ceq 'observer_selection_schema') ('selection contract '+$case)
}
# Failure must clear an input ref that previously held a trusted binding.
Reset-Fixture;$secret=(Observe).private;$script:split=$true;$r=Invoke-SstpLifecycleObservation $script:expected ([ref]$secret)
Check ($null -eq $secret -and -not $r.completed) 'stale ref cleared'
# Inventory error is sanitized rather than leaking exception paths or hostnames.
Reset-Fixture;$script:failScope='current_user';$x=Observe
Check (-not (($x.report|ConvertTo-Json) -match 'PRIVATE|SERVER_ERROR|fixture')) 'exception privacy'
@{suite='sstp-native-lifecycle-observer-model-v02';passed=$true;assertions=$script:checks;actual_CSharp_helper_compiled=$true;ABI_layout_checked_on_Linux_x64=$true;Windows_native_APIs_invoked=$false;real_reconnect_tested=$false;firewall_changed=$false}|ConvertTo-Json|Set-Content '/data/sstp-observer-v02/model-results.json'
Write-Host ('Passed '+$script:checks+' observer checks; Windows DLL APIs not invoked.')
