param([string]$Root='/data/ufw-minimal-readonly-v01')
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$module=Import-Module (Join-Path $Root 'source/Ufw.ProfileReader.psm1') -Force -PassThru
$script:checks=0
function Check($b,$label){$script:checks++;if(-not $b){throw $label}}
function Fixture([string]$Outbound='Allow'){
 return @(foreach($name in @('Domain','Private','Public')){[pscustomobject]@{Name=$name;DefaultOutboundAction=$Outbound;Enabled='True';AllowLocalFirewallRules='True';DisabledInterfaceAliases=@()}})
}
function Pair($l,$e){& $module {param($l,$e)[pscustomobject]@{local=@(ConvertTo-UfwProfileRows $l 'PersistentStore');effective=@(ConvertTo-UfwProfileRows $e 'ActiveStore')}} $l $e}
function Assess($p){& $module {param($p)Get-UfwProfileAssessment $p} $p}
function Reject($l,$e,$code){$caught='';try{Pair $l $e|Out-Null}catch{$caught=$_.Exception.GetBaseException().Message};Check ($caught -ceq $code) $code}
$a=Assess (Pair (Fixture) (Fixture));Check ($a.all_outbound_allow -and $a.explicit_local_outbound_baseline_present -and $a.profile_fields_compatible_for_later_review) 'explicit Allow'
$b=Assess (Pair (Fixture 'Block') (Fixture 'Block'));Check (-not $b.all_outbound_allow -and $b.explicit_local_outbound_baseline_present -and $b.profile_fields_compatible_for_later_review) 'Block observed without coercion or permission'
foreach($field in @('ready_for_apply','normal_mode_record_authorized','original_restore_verified','no_leak_certified')){Check ($b.$field -ceq $false) $field}
$l=Fixture 'NotConfigured';$e=Fixture;$a=Assess (Pair $l $e);Check (-not $a.explicit_local_outbound_baseline_present -and -not $a.profile_fields_compatible_for_later_review -and $a.profiles[0].local_outbound -ceq 'NotConfigured') 'NotConfigured never coerced'
$a=Assess (Pair (Fixture) (Fixture 'Block'));Check (-not $a.profile_fields_compatible_for_later_review -and $a.reasons.Count -eq 3) 'mismatch explicit'
foreach($value in @('False','NotConfigured')){$e=Fixture;$e[0].Enabled=$value;$a=Assess (Pair (Fixture) $e);Check (-not $a.profile_fields_compatible_for_later_review -and $a.reasons -contains 'Domain:effective_firewall_not_enabled') 'effective disabled/unknown'}
foreach($value in @('False','NotConfigured')){$e=Fixture;$e[1].AllowLocalFirewallRules=$value;$a=Assess (Pair (Fixture) $e);Check (-not $a.profile_fields_compatible_for_later_review -and $a.reasons -contains 'Private:effective_local_rules_not_true') 'effective rules disabled/unknown'}
$l=Fixture;$l[0].Enabled='NotConfigured';$l[0].AllowLocalFirewallRules='NotConfigured';$a=Assess (Pair $l (Fixture));Check ($a.profiles[0].local_enabled -ceq 'NotConfigured' -and $a.profiles[0].effective_enabled -ceq 'True') 'local and effective never hybridized'
foreach($field in @('Name','DefaultOutboundAction','Enabled','AllowLocalFirewallRules','DisabledInterfaceAliases')){$l=Fixture;$l[0].PSObject.Properties.Remove($field);Reject $l (Fixture) 'ufw_read_profile_field_missing'}
$l=Fixture;$l[1].Name='Domain';Reject $l (Fixture) 'ufw_read_profile_identity'
$l=Fixture;$l[1].Name='Other';Reject $l (Fixture) 'ufw_read_profile_identity'
Reject @((Fixture)[0]) (Fixture) 'ufw_read_profile_coverage'
foreach($field in @('DefaultOutboundAction','Enabled','AllowLocalFirewallRules')){$l=Fixture;$l[0].$field=$null;Reject $l (Fixture) 'ufw_read_profile_value_missing';$l=Fixture;$l[0].$field='UNKNOWN';Reject $l (Fixture) 'ufw_read_profile_encoding'}
$l=Fixture;$l[0].DisabledInterfaceAliases=$null;Reject $l (Fixture) 'ufw_read_exclusions_unknown'
$l=Fixture;$l[0].DisabledInterfaceAliases=@('Ethernet-PRIVATE');Reject $l (Fixture) 'ufw_read_excluded_interface_present'
$l=Fixture;$l[0].DisabledInterfaceAliases=@('');Reject $l (Fixture) 'ufw_read_exclusions_unknown'
$l=Fixture;$l[0].DisabledInterfaceAliases=42;Reject $l (Fixture) 'ufw_read_exclusions_encoding'
$l=Fixture;$l[0].DisabledInterfaceAliases=$null;$l[0]|Add-Member NoteProperty CimInstanceProperties @{DisabledInterfaceAliases=[pscustomobject]@{CimType='StringArray';Value=$null}};$a=Assess (Pair $l (Fixture));Check ($a.all_outbound_allow) 'typed null accepted'
$l[0].CimInstanceProperties.DisabledInterfaceAliases.CimType='String';Reject $l (Fixture) 'ufw_read_exclusions_unknown'
$l=Fixture;$l[0].DisabledInterfaceAliases=@('NotConfigured');$a=Assess (Pair $l (Fixture));Check $a.all_outbound_allow 'NotConfigured exclusion marker'
# Native adapter mocks remain module-private; public entry exposes no injectable callbacks.
& $module {function script:Assert-UfwReadPlatform {}; $script:testRows=$null;$script:testCalls=@();$script:testMode='';function script:Get-NetFirewallProfile {param($PolicyStore,$ErrorAction)$script:testCalls+=,$PolicyStore;if($script:testMode -ceq 'raw_error'){throw 'PRIVATE_PATH_AND_USER'};$rows=foreach($name in @('Domain','Private','Public')){[pscustomobject]@{Name=$name;DefaultOutboundAction='Block';Enabled='True';AllowLocalFirewallRules='True';DisabledInterfaceAliases=@()}};if($script:testMode -ceq 'drift' -and $script:testCalls.Count -eq 4){$rows[0].DefaultOutboundAction='Allow'};return $rows}}
$r=Invoke-UfwProfilePreflightReadOnly
Check ($r.completed -and $r.two_observations_match -and -not $r.assessment.all_outbound_allow) 'entry current Block not error or normal'
$calls=& $module {$script:testCalls -join ','};Check ($calls -ceq 'PersistentStore,ActiveStore,PersistentStore,ActiveStore' -and $r.native_store_reads_attempted -eq 4) 'four total native reads'
foreach($k in @('snapshot_is_atomic','legacy_runtime_imported','legacy_journal_read','file_write_requested','firewall_change_requested','VPN_change_requested','DNS_query_generated','ready_for_apply','no_leak_certified')){Check ($r.$k -ceq $false) ('entry boundary '+$k)}
& $module {$script:testCalls=@();$script:testMode='drift'};$r=Invoke-UfwProfilePreflightReadOnly;Check (-not $r.completed -and $null -eq $r.assessment -and $r.code -ceq 'ufw_read_profile_drift_between_observations') 'drift does not produce approved assessment'
& $module {$script:testCalls=@();$script:testMode='raw_error'};$r=Invoke-UfwProfilePreflightReadOnly;Check (-not $r.completed -and $r.code -ceq 'ufw_read_native_unavailable' -and ($r|ConvertTo-Json -Depth 10) -notmatch 'PRIVATE_PATH_AND_USER') 'native error redacted'
Check ($r.native_store_reads_attempted -eq 1) 'failed first native call counted once'
Remove-Module $module.Name -Force;Import-Module (Join-Path $Root 'source/Ufw.ProfileReader.psm1') -Force
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){$r=Invoke-UfwProfilePreflightReadOnly;Check (-not $r.completed -and $r.code -ceq 'ufw_read_windows_required' -and $r.native_store_reads_attempted -eq 0) 'real Linux guard no native calls'}
$exports=@(Get-Command -Module Ufw.ProfileReader);Check ($exports.Count -eq 1 -and $exports[0].Name -ceq 'Invoke-UfwProfilePreflightReadOnly') 'only read entry exported'
# Allowlist executable cmdlets: no legacy import, shell/eval, file I/O or setters.
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'source/Ufw.ProfileReader.psm1'),[ref]$t,[ref]$e);Check ($e.Count -eq 0) 'PS parse'
$allowed=@('Set-StrictMode','Sort-Object','Where-Object','Get-NetFirewallProfile','ConvertTo-Json','Export-ModuleMember','Assert-UfwReadPlatform','ConvertTo-UfwProfileRows','Read-UfwProfilePair','Get-UfwProfileAssessment')
foreach($cmd in $ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){if($cmd.GetCommandName() -cnotin $allowed){throw ('unexpected command '+$cmd.GetCommandName())}}
Check $true 'strict command allowlist'
foreach($cmd in $ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){
 $p=$cmd.Parent;$inside=$false;while($p){if($p -is [Management.Automation.Language.FunctionDefinitionAst]){$inside=$true;break};$p=$p.Parent}
 if(-not $inside -and $cmd.GetCommandName() -cnotin @('Set-StrictMode','Export-ModuleMember')){throw 'unexpected import-time command'}
}
Check $true 'module import has no native or file calls'
$types=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.TypeExpressionAst]},$true)|ForEach-Object{$_.TypeName.FullName}|Sort-Object -Unique)
foreach($type in $types){if($type -cnotin @('Environment','PlatformID','string','array','datetime','pscustomobject')){throw ('unexpected static API type '+$type)}}
Check $true 'static API type allowlist'
$result=[ordered]@{suite='minimal-readonly-profile-foundation-01';passed=$true;assertions=$script:checks;native_Windows_executed=$false;native_reader_mocked=$true;real_Linux_platform_guard_tested=$true;only_read_entry_exported=$true;no_legacy_imports=$true;ready_for_apply=$false}
$result|ConvertTo-Json|Set-Content (Join-Path $Root 'evidence/model-tests.json') -Encoding UTF8
$result|ConvertTo-Json -Compress
