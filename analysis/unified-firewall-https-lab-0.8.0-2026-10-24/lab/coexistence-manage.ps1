param([Parameter(Mandatory=$true)][string]$Request,[Parameter(Mandatory=$true)][string]$Output,[switch]$ReadOnly)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
foreach($file in @('session-core.ps1','native.ps1','request.ps1','inventory.ps1','traffic-tools.ps1','https-tools.ps1','coexistence-tools.ps1')){. (Join-Path $PSScriptRoot $file)}
$root=Split-Path $PSScriptRoot -Parent;$job=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Output));$lock=$null;$activeID=$null;$journalRoot=$null;$baseline=$null;$exitCode=0
$jobsRoot=[IO.Path]::GetFullPath((Join-Path $root 'private-state/coexistence-jobs')).TrimEnd([char]92)+[char]92
foreach($path in @($Request,$Output)){UAssertPath $path;if(-not [IO.Path]::GetFullPath($path).StartsWith($jobsRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'coexistence_job_path_escape'}}
if([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Request)) -cne $job -or (Get-Item -LiteralPath $Request).Length -gt 4194304){throw 'coexistence_request_scope_or_size'}
$report=[ordered]@{schema='unifiedfw-coexistence-result-1';action='scoped_coexistence_traffic_test';scope='two_bundled_images_one_ipv4_one_tcp_port_RemoteAccess_whitelist_projection';read_only=[bool]$ReadOnly;completed=$false;progress='validating_request';classification=[pscustomobject]@{outcome='running_not_verified'};restore_verified=$false;phases=@();errors=@();cleanup='not_needed';environment=$null;endpoint=$null;selected_route=$null;route_checks_ok=$false;route_check_count=0;firewall_mutation_attempted=$false;global_whitelist_tested=$false;vpn_route_verified=$false;outside_vpn_guard_installed=$false;udp_tested=$false;ipv6_tested=$false;packet_capture_performed=$false;protection_verified=$false}
try{
 UAdmin;Import-Module NetSecurity -ErrorAction Stop
 if([string]$env:SESSIONNAME -like 'RDP*'){throw 'local_console_required_not_RDP'}
 $coexistenceRequest=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Request));CValidateRequest $coexistenceRequest $root
 if($null -ne $coexistenceRequest.PSObject.Properties['transport']){$report.transport=$coexistenceRequest.transport}
 $report.endpoint=[pscustomobject]@{address=$coexistenceRequest.address;port=$coexistenceRequest.port;protocol='TCP';literal_ipv4_no_dns=$true}
 if($report.Contains('transport')){Add-Member -InputObject $report.endpoint -NotePropertyName https_url -NotePropertyValue $coexistenceRequest.https_url;Add-Member -InputObject $report.endpoint -NotePropertyName certificate_hostname -NotePropertyValue $coexistenceRequest.https_host}
 TSave $Output $report
 $environment=UReadEnvironment;UAssertEnvironment $environment 'vpn_allowlist';$report.environment=$environment
 $routeBaseline=CReadRoute $coexistenceRequest.address;$report.selected_route=$routeBaseline;$report.route_check_count=1
 $journalRoot=USecureRoot (-not $ReadOnly)
 if(-not $ReadOnly){$lock=UOpenPrivateFile (Join-Path $journalRoot 'session.lock') ([IO.FileMode]::OpenOrCreate)}
 $prior=ULoad $journalRoot;if($null -ne $prior -and $prior.phase -cne 'restored'){throw 'restore_existing_session_before_coexistence_test'}
 if($ReadOnly){
  $report.completed=$true;$report.progress='preflight_complete_no_connections_no_rules';$report.classification=[pscustomobject]@{outcome='ready_for_scoped_test';endpoint_reachability_tested=$false;route_observation_only=$true};TSave $Output $report
 }else{
  $routeGuard={CAssertRoute $coexistenceRequest.address $routeBaseline|Out-Null;$report.route_check_count++}
  $read={param($name) UReadNative $name};$remove={param($name) URemoveNative $name};$baseline=ReadPolicyInventory
  $phase=[pscustomobject][ordered]@{name='baseline';session_id=$null;during=@();after_restore=@();restored=$true;baseline_strict_equal=$false;comparison=$null};$report.phases+=,$phase
  $report.progress='baseline:probe';TSave $Output $report
  $phase.during=TMatrix $coexistenceRequest $job $root $routeGuard
  if(-not (TBaselineGood $phase.during)){throw 'baseline_unreachable_or_invalid_echo; no_rules_applied'}
  $phase.after_restore=TMatrix $coexistenceRequest $job $root $routeGuard
  if(-not (TBaselineGood $phase.after_restore)){throw 'baseline_not_stable; no_rules_applied'}
  $cmp=ComparePolicyInventory $baseline (ReadPolicyInventory);$phase.comparison=$cmp;$phase.baseline_strict_equal=$cmp.strict_equal
  if(-not $cmp.strict_equal){throw 'baseline_changed_externally_before_test'};TSave $Output $report
  foreach($phaseSpec in $coexistenceRequest.phases){
   & $routeGuard|Out-Null
   $phase=[pscustomobject][ordered]@{name=$phaseSpec.name;session_id=$null;during=@();after_restore=@();restored=$false;baseline_strict_equal=$false;comparison=$null};$report.phases+=,$phase
   $report.progress=$phase.name+':prepare';TSave $Output $report
   if($phaseSpec.request.plan.rules.Count -eq 0){
    $phase.during=TMatrix $coexistenceRequest $job $root $routeGuard;$phase.restored=$true
   }else{
    $session=NewUSession $journalRoot $phaseSpec.request.plan $read;$activeID=$session.id;$phase.session_id=$activeID
    UWritePrivateBytes (Join-Path $journalRoot ('coexistence-baseline-'+$session.id+'.json')) ([Text.Encoding]::UTF8.GetBytes((UJson $baseline)))
    $report.firewall_mutation_attempted=$true;$report.progress=$phase.name+':apply';TSave $Output $report
    try{
     $null=InvokeUSession $journalRoot $read {param($rule,$id) UCreateNative $rule $id} {param($image,$rule,$id) UValidateNative $image $rule $id} {param($image) UEnabledNative $image} {param($name) UEnableNative $name} -ValidateCapture {param($image,$rule,$id) UValidateCaptureNative $image $rule $id}
     $session=ULoad $journalRoot;foreach($entry in $session.entries){UValidateNative (UReadNative $entry.name 'ActiveStore') $entry.rule $session.id 'ActiveStore' 'True'}
     $report.progress=$phase.name+':probe';TSave $Output $report
     $phase.during=TMatrix $coexistenceRequest $job $root $routeGuard
     foreach($entry in $session.entries){if(-not (UEqual (UReadNative $entry.name) $entry.enabled_image)){throw 'owned_rule_drift_during_coexistence'}}
    }finally{
     $report.progress=$phase.name+':restore';TSave $Output $report
     $current=ULoad $journalRoot;if($null -eq $current -or $current.id -cne $activeID){throw 'coexistence_cleanup_session_identity_conflict'}
     $restored=RestoreUSession $journalRoot $read $remove;if($restored.phase -cne 'restored'){throw 'coexistence_restore_not_completed'}
     $phase.restored=$true;$activeID=$null;TSave $Output $report
    }
   }
   $cmp=ComparePolicyInventory $baseline (ReadPolicyInventory);$phase.comparison=$cmp;$phase.baseline_strict_equal=$cmp.strict_equal
   if(-not $cmp.strict_equal){throw 'coexistence_post_restore_baseline_drift'}
   $report.progress=$phase.name+':post_restore_probe';TSave $Output $report
   $phase.after_restore=TMatrix $coexistenceRequest $job $root $routeGuard
   if(-not (TBaselineGood $phase.after_restore)){throw 'coexistence_connectivity_did_not_recover_after_restore'};TSave $Output $report
  }
  & $routeGuard|Out-Null;$report.route_checks_ok=$true
  $report.restore_verified=(ComparePolicyInventory $baseline (ReadPolicyInventory)).strict_equal
  if(-not $report.restore_verified){throw 'coexistence_final_baseline_drift'}
  $inputFile=Join-Path $job 'classification-input.json';$outputFile=Join-Path $job 'classification.json';TSave $inputFile $report
  $report.classification=TRunProcess (Join-Path $root 'runtime/python.exe') (Join-Path $root 'lab/coexistence-classify.py') $inputFile $outputFile
  $report.completed=$true;$report.progress='complete';$report.cleanup='all_owned_sessions_restored_and_baseline_equal'
  if($report.classification.outcome -cne 'passed'){$exitCode=1}
 }
}catch{
 $exitCode=1;$report.errors+=,$_.Exception.Message;$report.route_checks_ok=$false;$report.progress='stopped_with_error';$report.classification=[pscustomobject]@{outcome='inconclusive';reason='preflight_route_execution_or_restore_error'}
 if($null -ne $activeID -and $null -ne $lock){try{
  $current=ULoad $journalRoot;if($null -eq $current -or $current.id -cne $activeID){throw 'cleanup_session_identity_conflict'}
  $restored=RestoreUSession $journalRoot {param($name) UReadNative $name} {param($name) URemoveNative $name};if($restored.phase -cne 'restored'){throw 'restore_not_completed'}
  $report.cleanup='owned_session_restored_after_error';$activeID=$null
 }catch{$report.cleanup='restore_failed; retain_journal_and_use_RESTORE';$report.errors+=,$_.Exception.Message}}
 if($null -ne $baseline -and $null -eq $activeID){try{$report.restore_verified=(ComparePolicyInventory $baseline (ReadPolicyInventory)).strict_equal}catch{$report.errors+=,$_.Exception.Message}}
}finally{if($null -ne $lock){$lock.Dispose()}}
TSave $Output $report
Write-Host ('Coexistence result: '+$Output)
exit $exitCode
