param([Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. "$PSScriptRoot/Quarantine.ps1"
$script:checks=0;$script:roots=@();$script:snapshots=@();$script:counter=0;$script:faults=0;$script:recoveries=0;$script:partialRestores=0
$passed=$false;$errorCode=$null;$remaining=-1;$profilesUnchanged=$false;$rulesUnchanged=$false
$session=[guid]::NewGuid().ToString('N');$prefix='SstpQuarantineTest-'+$session+'-';$group='SstpQuarantineTest-'+$session
$program=Join-Path $env:windir ('System32\sstp-quarantine-fixture-'+$session+'.exe')
function Check([bool]$Ok) { if (-not $Ok) { throw 'quarantine_test_assertion' };$script:checks++ }
function Reject([scriptblock]$Body,[string]$Expected) { $caught=$false;try { & $Body | Out-Null } catch { if ($_.Exception.Message -ne $Expected) { throw };$caught=$true };Check $caught }
function ProfileImage {
 $out=@();foreach($store in @('PersistentStore','ActiveStore')) { $out+=@(Get-NetFirewallProfile -PolicyStore $store -ErrorAction Stop | Sort-Object Name | Select-Object @{N='store';E={$store}},Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowLocalFirewallRules,AllowLocalIPsecRules) };$out | ConvertTo-Json -Depth 4 -Compress
}
function ExistingRuleImage {
 # Baseline of unrelated rule PROPERTIES, not a claim that all unrelated filters were inspected.
 $items=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.Name -notlike ($prefix+'*') } | Sort-Object Name | ForEach-Object { ConvertAdapterCim $_ });ConvertTo-Json -InputObject $items -Depth 5 -Compress
}
function NewFixture([int]$Count=2) {
 $root=InitializeJournalRoot (Join-Path $env:RUNNER_TEMP ('sstp-quarantine-'+[guid]::NewGuid().ToString('N')));$script:roots+=,$root;$snaps=@()
 for($i=0;$i -lt $Count;$i++) {
  $script:counter++;$name=$prefix+$script:counter.ToString('000')
  # Only synthetic rules: nonexistent executable, documentation-only addresses and one high TCP port.
  New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Group $group -Description 'P7 controlled fixture' -Enabled True -Direction Outbound -Action Allow -Profile Any -Program $program -Protocol TCP -RemotePort 65534 -RemoteAddress @('192.0.2.44','2001:db8::44') -EdgeTraversalPolicy Block -ErrorAction Stop | Out-Null
  $s=ReadStagedRule $name;AssertQSnapshot $s;$snaps+=,$s;$script:snapshots+=,$s
 }
 [pscustomobject]@{root=$root;snapshots=$snaps}
}
function Prepare($Fixture) {
 $state=[pscustomobject][ordered]@{schema='sstp-native-quarantine-1';phase='quarantine';cursor=0;pending=$false;rules=@($Fixture.snapshots | Sort-Object name)}
 AssertQState $state;AssertQFrontier $state | Out-Null;WriteJournal $Fixture.root -1 $state | Out-Null
}
function Worker([string]$Root,[string]$Action,[string]$Fault='None',[int]$Index=0) {
 $out=@(& (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PSScriptRoot/Worker.ps1" -Root $Root -Action $Action -Fault $Fault -FaultIndex $Index 2>&1);$code=$LASTEXITCODE
 if ($code -notin @(0,73)) { foreach($line in $out) { if ([string]$line -match '^(quarantine|adapter|journal|policy)_[a-z_0-9]+$') { Write-Host ([string]$line) } } };return $code
}
function AssertOriginal($Fixture) { foreach($s in $Fixture.snapshots) { Check ((ReadStagedRule $s.name).sha256 -ceq $s.sha256) } }
$beforeProfiles=ProfileImage;$beforeRules=ExistingRuleImage
try {
 Check (-not (Test-Path -LiteralPath $program))
 $f=NewFixture 2
 Check ((QExpected $f.snapshots[0] $false).sha256 -ceq $f.snapshots[0].sha256)
 Check ((QExpected $f.snapshots[0] $true).sha256 -cne $f.snapshots[0].sha256)
 $r=InvokeNativeQuarantine -Root $f.root -Action Quarantine -Snapshots $f.snapshots
 Check ($r.phase -eq 'quarantined')
 foreach($s in $f.snapshots) { Check ((ReadStagedRule $s.name).sha256 -ceq (QExpected $s $true).sha256) }
 $rev=(ReadJournal $f.root).record.revision;InvokeNativeQuarantine $f.root Quarantine | Out-Null
 Check ((ReadJournal $f.root).record.revision -eq $rev)
 InvokeNativeQuarantine $f.root Restore | Out-Null;AssertOriginal $f
 $rev=(ReadJournal $f.root).record.revision;InvokeNativeQuarantine $f.root Restore | Out-Null
 Check ((ReadJournal $f.root).record.revision -eq $rev)
 Reject { InvokeNativeQuarantine $f.root Quarantine } 'quarantine_restore_started'
 # Real process termination before/after each of two rule mutations, in both directions.
 foreach($action in @('Quarantine','Restore')) { foreach($index in @(0,1)) { foreach($point in @('BeforeMutation','AfterMutation')) {
  $f=NewFixture 2;Prepare $f
  if ($action -eq 'Restore') { InvokeNativeQuarantine $f.root Quarantine | Out-Null }
  Check ((Worker $f.root $action $point $index) -eq 73);$script:faults++
  Check ((ReadJournal $f.root).record.state.pending)
  Check ((Worker $f.root $action) -eq 0);$script:recoveries++
  Check ((ReadJournal $f.root).record.state.phase -eq $(if ($action -eq 'Quarantine') {'quarantined'} else {'restored'}))
  if ($action -eq 'Quarantine') { InvokeNativeQuarantine $f.root Restore | Out-Null }
  AssertOriginal $f
 } } }
 # Restore directly from an interrupted quarantine, including the uncertain completed mutation.
 foreach($point in @('BeforeMutation','AfterMutation')) {
  $f=NewFixture 2;Prepare $f
  Check ((Worker $f.root Quarantine $point 1) -eq 73);$script:faults++
  Check ((Worker $f.root Restore) -eq 0);$script:recoveries++;$script:partialRestores++
  AssertOriginal $f
 }
 # Full filter snapshots, not only Enabled or display names, protect against external changes.
 $f=NewFixture 2;InvokeNativeQuarantine -Root $f.root -Action Quarantine -Snapshots $f.snapshots | Out-Null
 $s=$f.snapshots[0];$rule=GetExactLocalRule $s.name
 Set-NetFirewallRule -InputObject $rule -RemoteAddress '192.0.2.45' -ErrorAction Stop | Out-Null
 $changed=ReadStagedRule $s.name;$rev=(ReadJournal $f.root).record.revision
 Reject { InvokeNativeQuarantine $f.root Restore } 'quarantine_external_change'
 Check ((ReadStagedRule $s.name).sha256 -ceq $changed.sha256 -and (ReadJournal $f.root).record.revision -eq $rev)
 Set-NetFirewallRule -InputObject (GetExactLocalRule $s.name) -RemoteAddress @('192.0.2.44','2001:db8::44') -ErrorAction Stop | Out-Null
 InvokeNativeQuarantine $f.root Restore | Out-Null;AssertOriginal $f
 # A conflict in a later frontier resource prevents even the first mutation.
 $f=NewFixture 2;Prepare $f;$s=$f.snapshots[1]
 Set-NetFirewallRule -InputObject (GetExactLocalRule $s.name) -Description 'P7 external edit' -ErrorAction Stop | Out-Null
 Reject { InvokeNativeQuarantine $f.root Quarantine } 'quarantine_external_change'
 Check ((ReadStagedRule $f.snapshots[0].name).sha256 -ceq $f.snapshots[0].sha256)
 Set-NetFirewallRule -InputObject (GetExactLocalRule $s.name) -Description 'P7 controlled fixture' -ErrorAction Stop | Out-Null
 InvokeNativeQuarantine $f.root Restore | Out-Null;AssertOriginal $f
 # No journal means no restoration authority; no fallback reset or EnableAll.
 $f=NewFixture 1;Reject { InvokeNativeQuarantine $f.root Restore } 'quarantine_missing_journal';AssertOriginal $f
 # Duplicate and altered snapshots stop before mutation/journal creation.
 Reject { InvokeNativeQuarantine -Root $f.root -Action Quarantine -Snapshots @($f.snapshots[0],$f.snapshots[0]) } 'quarantine_duplicate_or_unsorted'
 $bad=$f.snapshots[0] | ConvertTo-Json -Depth 12 | ConvertFrom-Json;$bad.image.view.action='Block'
 Reject { InvokeNativeQuarantine -Root $f.root -Action Quarantine -Snapshots @($bad) } 'quarantine_snapshot_integrity'
 Check ((ReadJournal $f.root).status -eq 'absent');AssertOriginal $f
 # A retained backup does not silently authorize replay of a damaged primary.
 $f=NewFixture 1;InvokeNativeQuarantine -Root $f.root -Action Quarantine -Snapshots $f.snapshots | Out-Null
 $disabled=ReadStagedRule $f.snapshots[0].name;[IO.File]::WriteAllText((Join-Path $f.root 'journal.json'),'broken')
 Reject { InvokeNativeQuarantine $f.root Restore } 'quarantine_journal_recovery_required'
 Check ((ReadStagedRule $disabled.name).sha256 -ceq $disabled.sha256)
 # Lock contention does not mutate the real fixture.
 $f=NewFixture 1;$lock=OpenQLock $f.root
 try { $busy=$false;try { InvokeNativeQuarantine -Root $f.root -Action Quarantine -Snapshots $f.snapshots | Out-Null } catch { $busy=$true };Check $busy } finally { $lock.Dispose() }
 Check ((ReadJournal $f.root).status -eq 'absent');AssertOriginal $f
 Check ($script:faults -eq 10 -and $script:recoveries -eq 10 -and $script:partialRestores -eq 2)
 $passed=$true
} catch {
 $errorCode='quarantine_native_failure';Write-Host ('Quarantine checks completed before failure: '+$script:checks)
 if ($_.Exception.Message -match '^(quarantine|adapter|journal|policy)_[a-z_0-9]+$') { Write-Host $_.Exception.Message } else { Write-Host ('quarantine_provider_failure_'+$_.Exception.GetType().Name.ToLowerInvariant()) }
} finally {
 # Explicit CI-only cleanup: exact GUID identity AND full known before/after filter hash.
 foreach($s in $script:snapshots) {
  try {
   $a=ReadStagedRule $s.name;if ($null -eq $a) { continue }
   if ($a.sha256 -cnotin @($s.sha256,(QExpected $s $true).sha256) -or $a.image.view.group -cne $group) { throw 'quarantine_cleanup_conflict' }
   Remove-NetFirewallRule -InputObject (GetExactLocalRule $s.name) -ErrorAction Stop
  } catch { $passed=$false;$errorCode='quarantine_cleanup_failure' }
 }
 $remaining=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.Name -like ($prefix+'*') }).Count
 $profilesUnchanged=((ProfileImage) -ceq $beforeProfiles);$rulesUnchanged=((ExistingRuleImage) -ceq $beforeRules)
 if ($remaining -ne 0 -or -not $profilesUnchanged -or -not $rulesUnchanged) { $passed=$false;$errorCode='quarantine_baseline_mismatch' }
 foreach($root in $script:roots) { if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force } }
 $receipt=[ordered]@{schema='sstp-quarantine-test-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;passed=$passed;checks=$script:checks;fault_cases=$script:faults;fresh_process_recoveries=$script:recoveries;partial_quarantine_restores=$script:partialRestores;error_code=$errorCode;verified_fixture_rules=$script:snapshots.Count;remaining_test_rules=$remaining;profiles_unchanged=$profilesUnchanged;existing_rule_properties_unchanged=$rulesUnchanged;test_rule_enabled_states_changed=($script:snapshots.Count -gt 0);profile_defaults_changed=$false;dns_queried=$false;resident_program_created=$false;real_guard_tested=$false;enforcement_tested=$false;sstp_binding_tested=$false;user_device_tested=$false;ready_for_user_apply=$false}
 [IO.File]::WriteAllText($OutputPath,($receipt | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
}
if (-not $passed) { exit 1 };exit 0
