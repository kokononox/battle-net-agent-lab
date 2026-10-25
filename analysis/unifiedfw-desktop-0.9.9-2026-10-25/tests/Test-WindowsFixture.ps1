param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $Root 'lab/session-core.ps1')
. (Join-Path $Root 'lab/native.ps1')
$fixture=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $Root 'tests/windows-provider-fixture.json')))
$script:fixtureRows=@{};$script:fixtureFilters=@{};$script:checks=0
function Check([bool]$ok,[string]$why){$script:checks++;if(-not $ok){throw ('fixture_assertion:'+ $why)}}
function FromObserved($Node){
 $props=[ordered]@{};foreach($p in $Node.friendly.PSObject.Properties){$v=$p.Value
  if(-not $v.present){continue}
  if($v.is_null){$props[$p.Name]=$null}elseif($v.type.EndsWith('[]')){$props[$p.Name]=@($v.items)}elseif($v.type -ceq 'System.Boolean'){$props[$p.Name]=[bool]::Parse($v.text)}else{$props[$p.Name]=[string]$v.text}
 }
 $raw=@();foreach($p in $Node.raw.PSObject.Properties){$v=$p.Value;$value=$null
  if(-not $v.is_null){$type=[type]$v.type;if($type.IsArray){$value=[Management.Automation.LanguagePrimitives]::ConvertTo($v.items,$type)}else{$value=[Management.Automation.LanguagePrimitives]::ConvertTo($v.items[0],$type)}}
  $raw+=,[pscustomobject]@{Name=$p.Name;Value=$value}
 }
 $obj=[pscustomobject]$props;Add-Member -InputObject $obj -NotePropertyName CimInstanceProperties -NotePropertyValue $raw;return $obj
}
function Get-NetFirewallRule{param($PolicyStore,$ErrorAction) foreach($r in $script:fixtureRows.Values){$r}}
function Get-NetFirewallApplicationFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$script:fixtureFilters.application}}
function Get-NetFirewallAddressFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$script:fixtureFilters.address}}
function Get-NetFirewallPortFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$script:fixtureFilters.port}}
function Get-NetFirewallInterfaceFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$script:fixtureFilters.interface}}
function Get-NetFirewallInterfaceTypeFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$script:fixtureFilters.interface_type}}
function Get-NetFirewallSecurityFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$script:fixtureFilters.security}}
function Get-NetFirewallServiceFilter{param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$script:fixtureFilters.service}}
$rule=$fixture.expected_rule;$id=$fixture.session_id;$name=$rule.name
$script:fixtureRows[$name]=FromObserved $fixture.row.rule
foreach($p in $fixture.row.filters.PSObject.Properties){$script:fixtureFilters[$p.Name]=FromObserved $p.Value}
$image=UReadNative $name
Check ($null -eq $script:fixtureFilters.application.Package) 'actual_reported_package_null_preserved'
Check ($image.rule.Enabled -ceq '2') 'reported_raw_enum_preserved'
Check ($image.application.AppPath -ceq $rule.spec.program) 'reported_app_path_alias'
Check ($image.port.Protocol -ceq $fixture.row.filters.port.raw.Protocol.items[0]) 'reported_protocol_preserved'
UValidateCaptureNative $image $rule $id;Check $true 'captured_ownership_passes'
UValidateNative $image $rule $id;Check $true 'complete_disabled_validation_passes_real_shape'
$enabled=UEnabledNative $image
$script:fixtureRows[$name].Enabled='True';foreach($p in $script:fixtureRows[$name].CimInstanceProperties){if($p.Name -ceq 'Enabled'){$p.Value=[uint16]1}}
Check (UEqual (UReadNative $name) $enabled) 'real_shape_enabled_readback'
UValidateNative (UReadNative $name 'ActiveStore') $rule $id 'ActiveStore' 'True';Check $true 'active_semantics_real_shape'
$report=[ordered]@{passed=$true;assertions=$script:checks;source='anonymized Windows 5.1 report replay';executed_on='Linux PowerShell 7.4.6';windows_live_execution=$false;preserved_provider_property_shapes=$true;anonymized_fields=@('owner','session','rule_names','executable_path','version_marker')}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/windows-fixture-tests.json'),(UJson $report));$report|ConvertTo-Json -Compress
