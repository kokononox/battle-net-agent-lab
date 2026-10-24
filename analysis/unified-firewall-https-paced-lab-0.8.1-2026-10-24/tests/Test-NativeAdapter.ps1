param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $Root 'lab/session-core.ps1')
. (Join-Path $Root 'lab/native.ps1')
. (Join-Path $Root 'lab/request.ps1')
$script:checks=0;$script:rows=@{};$script:filters=@{};$script:createdParams=$null
function Check([bool]$ok,[string]$why){$script:checks++;if(-not $ok){throw ('assertion:'+ $why)}}
function Throws([scriptblock]$body,[string]$pattern){$caught=$false;try{& $body|Out-Null}catch{$caught=$true;Check ($_.Exception.Message -like $pattern) ('error:'+ $_.Exception.Message)};Check $caught 'expected_throw'}
function Clone($v){ConvertFrom-Json -InputObject (UJson $v)}
function FakeCim($properties,$rawOverrides=@{}){
 $raw=@();foreach($k in $properties.Keys){$value=$properties[$k];if($rawOverrides.ContainsKey($k)){$value=$rawOverrides[$k]};$raw+=,[pscustomobject]@{Name=$k;Value=$value}}
 $obj=[pscustomobject]$properties;Add-Member -InputObject $obj -NotePropertyName CimInstanceProperties -NotePropertyValue $raw;return $obj
}
# These functions are TEST DOUBLES. No NetSecurity module is imported or invoked.
function Get-NetFirewallRule{param($PolicyStore,$ErrorAction) foreach($row in $script:rows.Values){$row}}
function New-NetFirewallRule{
 param($PolicyStore,$Name,$DisplayName,$Group,$Description,$Enabled,$Direction,$Action,$Profile,$Program,$Service,$InterfaceAlias,$InterfaceType,$LocalAddress,$RemoteAddress,$Protocol,$LocalPort,$RemotePort,$EdgeTraversalPolicy,$Authentication,$Encryption,$OverrideBlockRules,$LooseSourceMapping,$LocalOnlyMapping,$ErrorAction)
 $script:createdParams=@{}+ $PSBoundParameters
 $script:rows[$Name]=FakeCim ([ordered]@{Name=$Name;InstanceID=$Name;DisplayName=$DisplayName;Group=$Group;Description=$Description;Enabled=$Enabled;Direction=$Direction;Action=$Action;Profile=$Profile;EdgeTraversalPolicy=$EdgeTraversalPolicy;LooseSourceMapping=$LooseSourceMapping;LocalOnlyMapping=$LocalOnlyMapping;PolicyStoreSourceType='Local'}) @{Enabled='2'}
 $script:filters[$Name]=@{
  address=(FakeCim ([ordered]@{InstanceID=$Name;LocalAddress=@($LocalAddress);RemoteAddress=@($RemoteAddress)}))
  application=(FakeCim ([ordered]@{InstanceID=$Name;Program=$Program;Package=$null}))
  interface=(FakeCim ([ordered]@{InstanceID=$Name;InterfaceAlias=@($InterfaceAlias)}))
  interface_type=(FakeCim ([ordered]@{InstanceID=$Name;InterfaceType=$InterfaceType}))
  port=(FakeCim ([ordered]@{InstanceID=$Name;Protocol=$Protocol;LocalPort=@($LocalPort);RemotePort=@($RemotePort)}))
  security=(FakeCim ([ordered]@{InstanceID=$Name;Authentication=$Authentication;Encryption=$Encryption;OverrideBlockRules=$OverrideBlockRules}))
  service=(FakeCim ([ordered]@{InstanceID=$Name;Service=$Service}))
 }
}
function Get-NetFirewallAddressFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$script:filters[$InputObject.Name].address}}
function Get-NetFirewallApplicationFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$script:filters[$InputObject.Name].application}}
function Get-NetFirewallInterfaceFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$script:filters[$InputObject.Name].interface}}
function Get-NetFirewallInterfaceTypeFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$script:filters[$InputObject.Name].interface_type}}
function Get-NetFirewallPortFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$script:filters[$InputObject.Name].port}}
function Get-NetFirewallSecurityFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$script:filters[$InputObject.Name].security}}
function Get-NetFirewallServiceFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$script:filters[$InputObject.Name].service}}
function Set-NetFirewallRule{param([Parameter(ValueFromPipeline=$true)]$InputObject,$Enabled) process{$InputObject.Enabled='True';foreach($p in $InputObject.CimInstanceProperties){if($p.Name -ceq 'Enabled'){$p.Value='1'}}}}
function Remove-NetFirewallRule{param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$script:rows.Remove($InputObject.Name);$script:filters.Remove($InputObject.Name)}}
try{
 Check ((UAddressSignature @('1.1.1.1/32')) -ceq (UAddressSignature @('1.1.1.1'))) 'provider_single_host_normalization'
 Check ((UAddressSignature @('8.8.8.0/25','8.8.8.128/25')) -ceq (UAddressSignature @('8.8.8.0-8.8.8.255'))) 'provider_coalesced_range'
 Check ((UAddressSignature @('2001:4860::/33','2001:4860:8000::/33')) -ceq (UAddressSignature @('2001:4860:0000::/32'))) 'provider_ipv6_coalescence'
 Check ((UAddressSignature @('0.0.0.0/1','128.0.0.0/1')) -ceq (UAddressSignature @('0.0.0.0/0'))) 'full_space_exact'
 Check ((UAddressSignature @('8.8.8.8')) -cne (UAddressSignature @('8.8.8.9'))) 'different_address_not_equal'
 $oracle=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $Root 'tests/address-oracle.json')))
 foreach($vector in $oracle){Check ((UAddressSignature $vector.values) -ceq $vector.expected) 'independent_python_ipaddress_oracle'}
 $fixture=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $Root 'tests/lab-request.json')))
 UValidateRequest $fixture;Check $true 'valid_request'
 $r=$fixture.plan.rules[0];$id='1'*32
 UCreateNative $r $id;$image=UReadNative $r.name;UValidateNative $image $r $id
 Check ($image.rule.Enabled -ceq '2') 'provider_disabled_encoding'
 Check ($script:createdParams.PolicyStore -ceq 'PersistentStore' -and $script:createdParams.Action -ceq 'Block' -and $script:createdParams.Enabled -ceq 'False') 'disabled_block_only'
 Check ($script:createdParams.InterfaceType -ceq 'RemoteAccess' -and $script:createdParams.Program -ceq 'Any') 'whitelist_scope'
 Check ($image.PSObject.Properties.Name.Count -eq 8) 'all_seven_filters'
 $expected=UEnabledNative $image;UEnableNative $r.name;Check (UEqual (UReadNative $r.name) $expected) 'enable_full_image_readback'
 UValidateNative (UReadNative $r.name 'ActiveStore') $r $id 'ActiveStore' 'True';Check $true 'active_filter_validation'
 URemoveNative $r.name;Check ($null -eq (UReadNative $r.name)) 'exact_remove'
 # Regression: unrestricted is a PRESENT null property or explicit Any, never missing/SID/array/empty.
 Check (UPackageUnrestricted ([pscustomobject]@{Package=$null})) 'real_windows_null_package'
 Check (UPackageUnrestricted ([pscustomobject]@{Package='Any'})) 'explicit_any_package'
 Check (-not (UPackageUnrestricted ([pscustomobject]@{}))) 'missing_package_refused'
 foreach($bad in @('','S-1-15-2-123',256,@('Any'))){Check (-not (UPackageUnrestricted ([pscustomobject]@{Package=$bad}))) 'non_unrestricted_package_refused'}
 UCreateNative $r $id;$script:filters[$r.name].application.Package='S-1-15-2-123'
 Throws {UValidateNative (UReadNative $r.name) $r $id} 'created_filter_behavior_mismatch:application.Package'
 URemoveNative $r.name
 # Request data cannot inject Allow, bypass, service changes, interfaces, ports, paths or scripts.
 foreach($case in @('mode','imports','allow','direction','profile','service','interface_alias','authentication','bypass','local_addresses','remote_address','protocol','extra','component')){
  $q=Clone $fixture;$spec=$q.plan.rules[0].spec
  switch($case){
   mode{$q.mode='full_isolation'}
   imports{$q.legacy_imports=@([pscustomobject]@{kind='blacklist';rules_may_still_be_active=$true})}
   allow{$spec.action='Allow'}
   direction{$spec.direction='Inbound'}
   profile{$spec.profile='Public'}
   service{$spec.service='RasMan'}
   interface_alias{$spec.interface_alias='*'}
   authentication{$spec.authentication='Required'}
   bypass{$spec.override_block_rules=$true}
   local_addresses{$spec.local_addresses=@('8.8.8.8')}
   remote_address{$spec.remote_addresses=@('Any')}
   protocol{$spec.protocol='TCP'}
   extra{Add-Member -InputObject $spec -NotePropertyName script -NotePropertyValue 'bad'}
   component{$q.plan.rules[0].component='unknown'}
  }
  Throws {UValidateRequest $q} '*'
 }
 foreach($case in @('enabled','action','program','port','address','security','service','interface')){
  UCreateNative $r $id;$before=UReadNative $r.name
  switch($case){
   enabled{$script:rows[$r.name].Enabled='True'}
   action{$script:rows[$r.name].Action='Allow'}
   program{$script:filters[$r.name].application.Program='C:\Other.exe'}
   port{$script:filters[$r.name].port.RemotePort=@('443')}
   address{$script:filters[$r.name].address.RemoteAddress=@('8.8.8.8')}
   security{$script:filters[$r.name].security.OverrideBlockRules=$true}
   service{$script:filters[$r.name].service.Service='RasMan'}
   interface{$script:filters[$r.name].interface_type.InterfaceType='Any'}
  }
  Throws {UValidateNative $before $r $id} '*'
  URemoveNative $r.name
 }
 # Scoped coexistence projections through the full native adapter test doubles.
 $coex=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $Root 'tests/coexistence-request.json')))
 foreach($phase in $coex.phases){foreach($projectedRule in $phase.request.plan.rules){
  UCreateNative $projectedRule $id;$projectedImage=UReadNative $projectedRule.name
  UValidateCaptureNative $projectedImage $projectedRule $id
  UValidateNative $projectedImage $projectedRule $id
  Check (UStringEqual $script:createdParams.Program $projectedRule.spec.program) 'scoped_image_not_global'
  Check ($script:createdParams.InterfaceType -ceq $projectedRule.spec.interface_type) 'scoped_interface_preserved'
  Check ($script:createdParams.Protocol -ceq 'TCP' -and $script:createdParams.RemotePort -ceq '39443') 'scoped_transport_preserved'
  UEnableNative $projectedRule.name
  UValidateNative (UReadNative $projectedRule.name 'ActiveStore') $projectedRule $id 'ActiveStore' 'True'
  URemoveNative $projectedRule.name;Check ($null -eq (UReadNative $projectedRule.name)) 'scoped_exact_restore'
 }}
 $httpsCoex=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $Root 'tests/https-coexistence-request.json')))
 foreach($phase in $httpsCoex.phases){foreach($projectedRule in $phase.request.plan.rules){
  UCreateNative $projectedRule $id;$projectedImage=UReadNative $projectedRule.name;UValidateCaptureNative $projectedImage $projectedRule $id;UValidateNative $projectedImage $projectedRule $id
  Check ($script:createdParams.Protocol -ceq 'TCP' -and $script:createdParams.RemotePort -ceq '443' -and $script:createdParams.Program -cne 'Any') 'HTTPS_scoped_443_only'
  UEnableNative $projectedRule.name;UValidateNative (UReadNative $projectedRule.name 'ActiveStore') $projectedRule $id 'ActiveStore' 'True';URemoveNative $projectedRule.name
  Check ($null -eq (UReadNative $projectedRule.name)) 'HTTPS_exact_adapter_restore'
 }}
 UAssertStandaloneActivation ([pscustomobject]@{mode='blacklist_only'});Check $true 'blacklist_standalone_kept'
 Throws {UAssertStandaloneActivation ([pscustomobject]@{mode='vpn_allowlist'})} 'global_whitelist_activation_pending*'
 Throws {UAssertStandaloneActivation ([pscustomobject]@{mode='full_isolation'})} 'global_whitelist_activation_pending*'
 # Environment guard is evaluated without assuming effective Allow/Block defaults.
 $env=[pscustomobject]@{profiles=@('Domain','Private','Public'|ForEach-Object{[pscustomobject]@{name=$_;enabled='True';allow_local_rules='NotConfigured';default_outbound='Allow'}});vpn=@([pscustomobject]@{tunnel='Sstp';status='Connected';name='not-hardcoded';server='dynamic.example'});vpn_query_errors=@();legacy_enabled_rule_names=@();authenticated_bypass_filter_ids=@()}
 UAssertEnvironment $env 'vpn_allowlist';Check $true 'sstp_dynamic_inventory'
 foreach($case in @('disabled','merge','bypass','legacy','disconnected','wrong_tunnel','query_error')){
  $e=Clone $env
  switch($case){disabled{$e.profiles[0].enabled='False'};merge{$e.profiles[0].allow_local_rules='False'};bypass{$e.authenticated_bypass_filter_ids=@('x')};legacy{$e.legacy_enabled_rule_names=@('x')};disconnected{$e.vpn[0].status='Disconnected'};wrong_tunnel{$e.vpn[0].tunnel='Ikev2'};query_error{$e.vpn_query_errors=@('current_user')}}
  Throws {UAssertEnvironment $e 'vpn_allowlist'} '*'
 }
 $report=[ordered]@{passed=$true;assertions=$script:checks;provider='PowerShell_test_doubles_NOT_Windows_CIM';windows_executed=$false;windows_acl_constructors_executed=$false;independent_address_oracle_cases=$oracle.Count}
 [IO.File]::WriteAllText((Join-Path $Root 'evidence/native-adapter-tests.json'),(UJson $report));$report|ConvertTo-Json -Compress
}catch{$_.ScriptStackTrace|Write-Host;throw}
