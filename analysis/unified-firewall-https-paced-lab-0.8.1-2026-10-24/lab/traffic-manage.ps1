param([Parameter(Mandatory=$true)][string]$Request,[Parameter(Mandatory=$true)][string]$Output)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'session-core.ps1')
. (Join-Path $PSScriptRoot 'native.ps1')
. (Join-Path $PSScriptRoot 'request.ps1')
. (Join-Path $PSScriptRoot 'inventory.ps1')
. (Join-Path $PSScriptRoot 'traffic-tools.ps1')
$root=Split-Path $PSScriptRoot -Parent;$job=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Output));$lock=$null;$activeID=$null;$journalRoot=$null;$baseline=$null;$exitCode=0
# Validate output scope BEFORE any error-path write or Windows mutation.
$jobsRoot=[IO.Path]::GetFullPath((Join-Path $root 'private-state/traffic-jobs')).TrimEnd('\')+'\'
 foreach($path in @($Request,$Output)){UAssertPath $path;if(-not [IO.Path]::GetFullPath($path).StartsWith($jobsRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'traffic_job_path_escape'}}
 if([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Request)) -cne $job -or (Get-Item -LiteralPath $Request).Length -gt 4194304){throw 'traffic_request_scope_or_size'}

$report=[ordered]@{schema='unifiedfw-traffic-result-1';action='direct_ipv4_tcp_two_image_test';completed=$false;restore_verified=$false;classification=[pscustomobject]@{outcome='running_not_verified'};phases=@();errors=@();cleanup='not_needed';environment=$null;endpoint=$null;firewall_mutation_attempted=$false;whitelist_tested=$false;vpn_route_verified=$false;outside_vpn_guard_installed=$false;udp_tested=$false;packet_capture_performed=$false;protection_verified=$false}
try{
 UAdmin;Import-Module NetSecurity -ErrorAction Stop
 if([string]$env:SESSIONNAME -like 'RDP*'){throw 'local_console_required_not_RDP'}
 $q=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Request));TValidateRequest $q $root
 $report.endpoint=[pscustomobject]@{address=$q.address;port=$q.port;protocol='TCP';literal_ipv4_no_dns=$true}
 TSave $Output $report
 $journalRoot=USecureRoot $true;$lock=UOpenPrivateFile (Join-Path $journalRoot 'session.lock') ([IO.FileMode]::OpenOrCreate)
 $prior=ULoad $journalRoot;if($null -ne $prior -and $prior.phase -cne 'restored'){throw 'restore_existing_session_before_traffic_test'}
 $environment=UReadEnvironment;UAssertEnvironment $environment 'blacklist_only';$report.environment=$environment
 $read={param($name) UReadNative $name};$remove={param($name) URemoveNative $name}
 $baseline=ReadPolicyInventory
 $baselinePhase=[pscustomobject][ordered]@{name='baseline';during=@();after_restore=@();restored=$true;baseline_strict_equal=$false;comparison=$null}
 $report.phases+=,$baselinePhase;TSave $Output $report
 $baselinePhase.during=TMatrix $q $job $root
 if(-not (TBaselineGood $baselinePhase.during)){throw 'baseline_unreachable_or_invalid_echo; no_rules_applied'}
 $baselinePhase.after_restore=TMatrix $q $job $root
 if(-not (TBaselineGood $baselinePhase.after_restore)){throw 'baseline_not_stable; no_rules_applied'}
 $cmp=ComparePolicyInventory $baseline (ReadPolicyInventory);$baselinePhase.baseline_strict_equal=$cmp.strict_equal;$baselinePhase.comparison=$cmp
 if(-not $cmp.strict_equal){throw 'baseline_changed_externally_before_test'}
 TSave $Output $report
 foreach($phaseSpec in $q.phases){
  $phase=[pscustomobject][ordered]@{name=$phaseSpec.name;session_id=$null;during=@();after_restore=@();restored=$false;baseline_strict_equal=$false;comparison=$null}
  $report.phases+=,$phase;TSave $Output $report
  # NewUSession checks every desired name absent. Keep ONE protected file lock for the entire test.
  $session=NewUSession $journalRoot $phaseSpec.request.plan $read;$activeID=$session.id;$phase.session_id=$activeID
  UWritePrivateBytes (Join-Path $journalRoot ('traffic-baseline-'+$session.id+'.json')) ([Text.Encoding]::UTF8.GetBytes((UJson $baseline)))
  $report.firewall_mutation_attempted=$true;TSave $Output $report
  try{
   $null=InvokeUSession $journalRoot $read {param($rule,$id) UCreateNative $rule $id} {param($image,$rule,$id) UValidateNative $image $rule $id} {param($image) UEnabledNative $image} {param($name) UEnableNative $name} -ValidateCapture {param($image,$rule,$id) UValidateCaptureNative $image $rule $id}
   $session=ULoad $journalRoot
   foreach($entry in $session.entries){UValidateNative (UReadNative $entry.name 'ActiveStore') $entry.rule $session.id 'ActiveStore' 'True'}
   $phase.during=TMatrix $q $job $root
   # Confirm tested rules did not drift during network probes.
   foreach($entry in $session.entries){if(-not (UEqual (UReadNative $entry.name) $entry.enabled_image)){throw 'owned_rule_drift_during_traffic'}}
  }finally{
   $current=ULoad $journalRoot;if($null -eq $current -or $current.id -cne $activeID){throw 'traffic_cleanup_session_identity_conflict'}
   $restored=RestoreUSession $journalRoot $read $remove
   if($restored.phase -cne 'restored'){throw 'traffic_restore_not_completed'}
   $phase.restored=$true;$activeID=$null;TSave $Output $report
  }
  $cmp=ComparePolicyInventory $baseline (ReadPolicyInventory);$phase.baseline_strict_equal=$cmp.strict_equal;$phase.comparison=$cmp
  if(-not $cmp.strict_equal){throw 'traffic_post_restore_baseline_drift'}
  $phase.after_restore=TMatrix $q $job $root;TSave $Output $report
  if(-not (TBaselineGood $phase.after_restore)){throw 'traffic_connectivity_did_not_recover_after_restore'}
 }
 $last=ComparePolicyInventory $baseline (ReadPolicyInventory);$report.restore_verified=$last.strict_equal
 if(-not $last.strict_equal){throw 'traffic_final_baseline_drift'}
 $classificationInput=Join-Path $job 'classification-input.json';$classificationOutput=Join-Path $job 'classification.json';TSave $classificationInput $report
 $classification=TRunProcess (Join-Path $root 'runtime/python.exe') (Join-Path $root 'lab/traffic-classify.py') $classificationInput $classificationOutput
 $report.classification=$classification;$report.completed=$true;$report.cleanup='all_three_sessions_restored_and_baseline_equal'
 if($classification.outcome -cne 'passed'){$exitCode=1}
}catch{
 $exitCode=1;$report.errors+=,$_.Exception.Message;$report.classification=[pscustomobject]@{outcome='inconclusive';reason='execution_or_restore_error'}
 if($null -ne $activeID -and $null -ne $lock){
  try{
   $s=ULoad $journalRoot;if($null -eq $s -or $s.id -cne $activeID){throw 'cleanup_session_identity_conflict'}
   $s=RestoreUSession $journalRoot {param($name) UReadNative $name} {param($name) URemoveNative $name}
   $report.cleanup='owned_session_restored_after_error';$activeID=$null
  }catch{$report.cleanup='restore_failed; retain_journal_and_use_RESTORE';$report.errors+=,$_.Exception.Message}
 }
 if($null -ne $baseline -and $null -eq $activeID){try{$report.restore_verified=(ComparePolicyInventory $baseline (ReadPolicyInventory)).strict_equal}catch{$report.errors+=,$_.Exception.Message}}
}finally{if($null -ne $lock){$lock.Dispose()}}
TSave $Output $report
Write-Host ('Traffic result: '+$Output)
exit $exitCode
