param([Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. "$PSScriptRoot/Firewall.ps1"
$script:checks=0;$passed=$false;$errorCode=$null;$remaining=-1;$profilesUnchanged=$false;$rulesUnchanged=$false
$session=[guid]::NewGuid().ToString('N');$prefix='SstpAllowlist-'+$session+'-';$group='SstpAllowlist-'+$session
function Check([bool]$Ok) { if (-not $Ok) { throw 'adapter_test_assertion' };$script:checks++ }
function Reject([scriptblock]$Body,[string]$Expected) {
 $caught=$false
 try { & $Body | Out-Null } catch { if ($_.Exception.Message -ne $Expected) { throw };$caught=$true }
 Check $caught
}
function ProfileImage {
 $out=@()
 foreach($store in @('PersistentStore','ActiveStore')) {
  $out+=@(Get-NetFirewallProfile -PolicyStore $store -ErrorAction Stop | Sort-Object Name | Select-Object @{N='store';E={$store}},Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowLocalFirewallRules,AllowLocalIPsecRules)
 }
 $out | ConvertTo-Json -Depth 4 -Compress
}
function ExistingRuleImage {
 # This baseline covers rule-level properties only; own test rules additionally have all seven filters hashed.
 $images=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.Name -notlike ($prefix+'*') } | Sort-Object Name | ForEach-Object { ConvertAdapterCim $_ })
 ConvertTo-Json -InputObject $images -Depth 5 -Compress
}
$beforeProfiles=ProfileImage;$beforeRules=ExistingRuleImage
try {
 # An existing interface is used only to test stored filters. It is NOT an SSTP interface qualification.
 $aliases=@(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceAlias -notmatch '[*?\[\]`\r\n]' -and $_.InterfaceIndex -ne 1 } | Select-Object -ExpandProperty InterfaceAlias -Unique)
 if ($aliases.Count -eq 0) { throw 'adapter_fixture_interface_missing' };$alias=$aliases[0]
 $spec=NewStagedRuleSpec $session 'target' 'target' $alias @('192.0.2.44','2001:db8::44','192.0.2.44')
 Check ($spec.addresses.Count -eq 2 -and $spec.interface_type -eq 'RemoteAccess')
 Check ((AssertStagedRuleSpec $spec).schema -eq 'sstp-staged-rule-1')
 Reject { NewStagedRuleSpec $session 'x' 'target' '*' @('192.0.2.44') } 'adapter_alias'
 Reject { NewStagedRuleSpec $session 'x' 'target' '[abc]' @('192.0.2.44') } 'adapter_alias'
 Reject { NewStagedRuleSpec $session 'x' 'target' 'Any' @('192.0.2.44') } 'adapter_alias'
 Reject { NewStagedRuleSpec $session 'x' 'target' $alias @('Any') } 'policy_ip'
 Reject { NewStagedRuleSpec $session 'x' 'target' $alias @('192.0.2.0/24') } 'policy_ip'
 Reject { NewStagedRuleSpec $session 'x' 'target' $alias @('level3.blizzard.com') } 'policy_ip'
 Reject { NewStagedRuleSpec 'bad' 'x' 'target' $alias @('192.0.2.44') } 'adapter_identity'
 Reject { NewStagedRuleSpec $session 'x' 'other' $alias @('192.0.2.44') } 'adapter_kind'
 $changed=$spec | ConvertTo-Json -Depth 4 | ConvertFrom-Json;$changed | Add-Member extra $true
 Reject { AssertStagedRuleSpec $changed } 'adapter_spec_schema'
 $changed=$spec | ConvertTo-Json -Depth 4 | ConvertFrom-Json;$changed.interface_type='Any'
 Reject { AssertStagedRuleSpec $changed } 'adapter_spec_noncanonical'
 Check ($null -eq (ReadStagedRule (StagedRuleName $spec)))
 $snapshot=NewDisabledStagedRule $spec
 Check ($snapshot.image.view.enabled -eq 'False' -and $snapshot.image.view.action -eq 'Allow')
 Check (AssertStagedRuleReadback $spec $snapshot)
 Reject { NewDisabledStagedRule $spec } 'adapter_name_exists'
 Reject { RemoveDisabledStagedRule $spec ('0'*64) } 'adapter_external_change'
 # Controlled external-edit simulation on our DISABLED fixture, never an existing rule.
 Set-NetFirewallRule -PolicyStore PersistentStore -Name $snapshot.name -Description 'fixture external edit' -ErrorAction Stop
 Reject { RemoveDisabledStagedRule $spec $snapshot.sha256 } 'adapter_external_change'
 Check ($null -ne (GetExactLocalRule $snapshot.name))
 Set-NetFirewallRule -PolicyStore PersistentStore -Name $snapshot.name -Description 'SSTP allowlist P3 staging only; never enabled' -ErrorAction Stop
 Check ((ReadStagedRule $snapshot.name).sha256 -ceq $snapshot.sha256)
 Check ((RemoveDisabledStagedRule $spec $snapshot.sha256) -eq 'removed')
 Check ((RemoveDisabledStagedRule $spec $snapshot.sha256) -eq 'already_absent')
 foreach($kind in @('dns-tcp','dns-udp','transport')) {
  $s=NewStagedRuleSpec $session $kind $kind $alias @('192.0.2.45')
  $r=NewDisabledStagedRule $s
  Check (AssertStagedRuleReadback $s $r)
  Check ((RemoveDisabledStagedRule $s $r.sha256) -eq 'removed')
 }
 Check ($script:checks -eq 28)
 $passed=$true
} catch { $errorCode='adapter_native_failure';Write-Host ('Adapter check failed after '+$script:checks+' checks.');if ($_.Exception.Message -match '^(adapter|policy)_[a-z_]+$') { Write-Host $_.Exception.Message } else { Write-Host 'adapter_provider_failure' } }
finally {
 # CI cleanup: only this invocation's GUID-named DISABLED fixtures with exact group.
 $left=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.Name -like ($prefix+'*') })
 foreach($r in $left) {
  if ($r.Group -cne $group -or [string]$r.Enabled -ne 'False') { $passed=$false;continue }
  Remove-NetFirewallRule -PolicyStore PersistentStore -Name $r.Name -ErrorAction Stop
 }
 $remaining=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.Name -like ($prefix+'*') }).Count
 $profilesUnchanged=((ProfileImage) -ceq $beforeProfiles);$rulesUnchanged=((ExistingRuleImage) -ceq $beforeRules)
 if ($remaining -ne 0 -or -not $profilesUnchanged -or -not $rulesUnchanged) { $passed=$false;$errorCode='adapter_baseline_mismatch' }
 $receipt=[ordered]@{schema='sstp-adapter-test-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;passed=$passed;checks=$script:checks;error_code=$errorCode;disabled_rules_created=$true;remaining_test_rules=$remaining;profiles_unchanged=$profilesUnchanged;existing_rule_properties_unchanged=$rulesUnchanged;effective_network_policy_changed=$false;dns_queried=$false;resident_program_created=$false;enforcement_tested=$false;sstp_binding_tested=$false;user_device_tested=$false;ready_for_user_apply=$false}
 [IO.File]::WriteAllText($OutputPath,($receipt | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
}
if (-not $passed) { exit 1 }
