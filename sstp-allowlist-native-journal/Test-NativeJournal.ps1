param([Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. "$PSScriptRoot/NativeJournal.ps1"
$script:checks=0;$script:roots=@();$script:specs=@();$script:counter=0;$script:faultCases=0;$script:recoveries=0;$script:reviewStops=0
$passed=$false;$errorCode=$null;$remaining=-1;$profilesUnchanged=$false;$rulesUnchanged=$false
$session=[guid]::NewGuid().ToString('N');$prefix='SstpAllowlist-'+$session+'-';$group='SstpAllowlist-'+$session
function Check([bool]$Ok) { if (-not $Ok) { throw 'staging_test_assertion' };$script:checks++ }
function Reject([scriptblock]$Body,[string]$Expected) {
 $caught=$false;try { & $Body | Out-Null } catch { if ($_.Exception.Message -ne $Expected) { throw };$caught=$true };Check $caught
}
function ProfileImage {
 $out=@();foreach($store in @('PersistentStore','ActiveStore')) { $out+=@(Get-NetFirewallProfile -PolicyStore $store -ErrorAction Stop | Sort-Object Name | Select-Object @{N='store';E={$store}},Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowLocalFirewallRules,AllowLocalIPsecRules) };$out | ConvertTo-Json -Depth 4 -Compress
}
function ExistingRuleImage {
 $items=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.Name -notlike ($prefix+'*') } | Sort-Object Name | ForEach-Object { ConvertAdapterCim $_ });ConvertTo-Json -InputObject $items -Depth 5 -Compress
}
function NewFixture {
 $script:counter++;$s=NewStagedRuleSpec $session ('case-'+$script:counter) 'target' $script:alias @('192.0.2.44','2001:db8::44')
 $root=InitializeJournalRoot (Join-Path $env:RUNNER_TEMP ('sstp-native-journal-'+[guid]::NewGuid().ToString('N')))
 [IO.File]::WriteAllText((Join-Path $root 'fixture-spec.json'),($s | ConvertTo-Json -Depth 5 -Compress))
 $script:roots+=,$root;$script:specs+=,$s
 [pscustomobject]@{root=$root;spec=$s}
}
function Worker([string]$Root,[string]$Action,[string]$Fault='None') {
 $out=@(& (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PSScriptRoot/Worker.ps1" -Root $Root -Action $Action -Fault $Fault 2>&1);$code=$LASTEXITCODE
 if ($code -notin @(0,73)) { foreach($line in $out) { if ([string]$line -match '^(staging|adapter|journal|policy)_[a-z_0-9]+$') { Write-Host ([string]$line) } } }
 return $code
}
$beforeProfiles=ProfileImage;$beforeRules=ExistingRuleImage
try {
 $aliases=@(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceIndex -ne 1 -and $_.InterfaceAlias -notmatch '[*?\[\]`\r\n]' } | Select-Object -ExpandProperty InterfaceAlias -Unique)
 if ($aliases.Count -eq 0) { throw 'staging_fixture_interface_missing' };$script:alias=$aliases[0]
 # Durable intent exists, actual rule does not: a fresh worker may create and record it.
 $f=NewFixture
 Check ((Worker $f.root 'Stage' 'BeforeCreate') -eq 73);$script:faultCases++
 Check ((ReadJournal $f.root).record.state.phase -eq 'create_intent' -and $null -eq (ReadStagedRule (StagedRuleName $f.spec)))
 Check ((Worker $f.root 'Stage') -eq 0);$script:recoveries++
 Check ((ReadStagedRule (StagedRuleName $f.spec)).image.view.enabled -eq 'False')
 $rev=(ReadJournal $f.root).record.revision;InvokeNativeStaging $f.root 'Stage' $f.spec | Out-Null
 Check ((ReadJournal $f.root).record.revision -eq $rev)
 InvokeNativeStaging $f.root 'Remove' $f.spec | Out-Null
 Check ($null -eq (ReadStagedRule (StagedRuleName $f.spec)))
 # Real New-NetFirewallRule completed, but its snapshot was never durably recorded. STOP, do not adopt.
 $f=NewFixture
 Check ((Worker $f.root 'Stage' 'AfterCreate') -eq 73);$script:faultCases++
 $snap=ReadStagedRule (StagedRuleName $f.spec);$rev=(ReadJournal $f.root).record.revision
 Check ($snap.image.view.enabled -eq 'False' -and $null -eq (ReadJournal $f.root).record.state.snapshot)
 Check ((Worker $f.root 'Stage') -eq 1);$script:reviewStops++
 Check ((Worker $f.root 'Remove') -eq 1);$script:reviewStops++
 Check ((ReadStagedRule $snap.name).sha256 -ceq $snap.sha256 -and (ReadJournal $f.root).record.revision -eq $rev)
 # A readback fingerprint saved before termination makes later operations attributable.
 $f=NewFixture
 Check ((Worker $f.root 'Stage' 'AfterRecord') -eq 73);$script:faultCases++
 Check ((ReadJournal $f.root).record.state.phase -eq 'staged')
 Check ((Worker $f.root 'Stage') -eq 0);$script:recoveries++
 Check ((ReadStagedRule (StagedRuleName $f.spec)).sha256 -ceq (ReadJournal $f.root).record.state.snapshot.sha256)
 InvokeNativeStaging $f.root 'Remove' $f.spec | Out-Null
 Check ((ReadJournal $f.root).record.state.phase -eq 'removed')
 foreach($point in @('BeforeRemove','AfterRemove')) {
  $f=NewFixture;InvokeNativeStaging $f.root 'Stage' $f.spec | Out-Null
  Check ((Worker $f.root 'Remove' $point) -eq 73);$script:faultCases++
  Check ((ReadJournal $f.root).record.state.phase -eq 'remove_intent')
  Check ((Worker $f.root 'Remove') -eq 0);$script:recoveries++
  Check ($null -eq (ReadStagedRule (StagedRuleName $f.spec)))
  $rev=(ReadJournal $f.root).record.revision;InvokeNativeStaging $f.root 'Remove' $f.spec | Out-Null
  Check ((ReadJournal $f.root).record.revision -eq $rev)
 }
 # A changed disabled rule is preserved; only this fixture's description is edited and restored here.
 $f=NewFixture;InvokeNativeStaging $f.root 'Stage' $f.spec | Out-Null;$name=StagedRuleName $f.spec
 Set-NetFirewallRule -PolicyStore PersistentStore -Name $name -Description 'P5 external edit fixture' -ErrorAction Stop
 $changed=ReadStagedRule $name;$rev=(ReadJournal $f.root).record.revision
 Reject { InvokeNativeStaging $f.root 'Remove' $f.spec } 'staging_external_change'
 Check ((ReadStagedRule $name).sha256 -ceq $changed.sha256 -and (ReadJournal $f.root).record.revision -eq $rev)
 Set-NetFirewallRule -PolicyStore PersistentStore -Name $name -Description 'SSTP allowlist P3 staging only; never enabled' -ErrorAction Stop
 InvokeNativeStaging $f.root 'Remove' $f.spec | Out-Null
 Check ($null -eq (ReadStagedRule $name))
 # A matching name without a journal is not ownership.
 $f=NewFixture;$snap=NewDisabledStagedRule $f.spec
 Reject { InvokeNativeStaging $f.root 'Stage' $f.spec } 'staging_name_exists'
 Reject { InvokeNativeStaging $f.root 'Remove' $f.spec } 'staging_missing_journal'
 Check ((ReadStagedRule $snap.name).sha256 -ceq $snap.sha256 -and (ReadJournal $f.root).status -eq 'absent')
 RemoveDisabledStagedRule $f.spec $snap.sha256 | Out-Null
 # A corrupt primary with backup must never authorize actual rule deletion.
 $f=NewFixture;InvokeNativeStaging $f.root 'Stage' $f.spec | Out-Null;$snap=ReadStagedRule (StagedRuleName $f.spec)
 [IO.File]::WriteAllText((Join-Path $f.root 'journal.json'),'broken')
 Reject { InvokeNativeStaging $f.root 'Remove' $f.spec } 'staging_journal_recovery_required'
 Check ((ReadStagedRule $snap.name).sha256 -ceq $snap.sha256)
 # Reject an altered incoming spec, even when its canonical shape is valid.
 $f=NewFixture;InvokeNativeStaging $f.root 'Stage' $f.spec | Out-Null
 $other=NewStagedRuleSpec $session $f.spec.id 'target' $script:alias @('192.0.2.45')
 Reject { InvokeNativeStaging $f.root 'Remove' $other } 'staging_plan_mismatch'
 $snap=ReadStagedRule (StagedRuleName $f.spec)
 Check ($snap.sha256 -ceq (ReadJournal $f.root).record.state.snapshot.sha256)
 InvokeNativeStaging $f.root 'Remove' $f.spec | Out-Null
 # Lock contention cannot create a rule or a journal.
 $f=NewFixture;$lock=OpenNativeStagingLock $f.root
 try { $busy=$false;try { InvokeNativeStaging $f.root 'Stage' $f.spec | Out-Null } catch { $busy=$true };Check $busy } finally { $lock.Dispose() }
 Check ($null -eq (ReadStagedRule (StagedRuleName $f.spec)) -and (ReadJournal $f.root).status -eq 'absent')
 Check ($script:checks -eq 38 -and $script:faultCases -eq 5 -and $script:recoveries -eq 4 -and $script:reviewStops -eq 2)
 $passed=$true
} catch {
 $errorCode='staging_native_failure';Write-Host ('Native journal check failed after '+$script:checks+' checks.')
 if ($_.Exception.Message -match '^(staging|adapter|journal|policy)_[a-z_0-9]+$') { Write-Host $_.Exception.Message } else { Write-Host ('staging_provider_failure_'+$_.Exception.GetType().Name.ToLowerInvariant()) }
} finally {
 # Explicit CI-fixture cleanup, NOT automatic recovery: inspect each known fixture anew and delete ONLY disabled, exact-spec matches.
 foreach($s in $script:specs) {
  $actual=ReadStagedRule (StagedRuleName $s)
  if ($null -eq $actual) { continue }
  try { AssertStagedRuleReadback $s $actual | Out-Null;RemoveDisabledStagedRule $s $actual.sha256 | Out-Null } catch { $passed=$false;$errorCode='staging_cleanup_failure' }
 }
 $remaining=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.Name -like ($prefix+'*') }).Count
 $profilesUnchanged=((ProfileImage) -ceq $beforeProfiles);$rulesUnchanged=((ExistingRuleImage) -ceq $beforeRules)
 if ($remaining -ne 0 -or -not $profilesUnchanged -or -not $rulesUnchanged) { $passed=$false;$errorCode='staging_baseline_mismatch' }
 foreach($root in $script:roots) { if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force } }
 $receipt=[ordered]@{schema='sstp-native-journal-test-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;passed=$passed;checks=$script:checks;fault_cases=$script:faultCases;fresh_process_recoveries=$script:recoveries;ambiguous_review_stops=$script:reviewStops;error_code=$errorCode;adapter_kind='native_disabled_rules';remaining_test_rules=$remaining;profiles_unchanged=$profilesUnchanged;existing_rule_properties_unchanged=$rulesUnchanged;effective_network_policy_changed=$false;dns_queried=$false;resident_program_created=$false;real_guard_tested=$false;enforcement_tested=$false;sstp_binding_tested=$false;user_device_tested=$false;ready_for_user_apply=$false}
 [IO.File]::WriteAllText($OutputPath,($receipt | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
}
if (-not $passed) { exit 1 };exit 0
