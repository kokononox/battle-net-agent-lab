param([Parameter(Mandatory=$true)][string]$OutputPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Engine.ps1"
$script:checks=0;$script:roots=@();$script:fixtures=@();$script:deleted=@{};$script:counter=0;$script:next=0
$faults=0;$recoveries=0;$partials=0;$conflicts=0;$metadataPreserved=0;$capacityRejects=0;$sealCases=0;$journalMin=10000;$corruptStops=0;$missingStops=0
$nativeChanged=$false;$passed=$false;$errorCode=$null;$remaining=-1;$globalEqual=$false;$displayDrift=-1
$session=[guid]::NewGuid().ToString('N');$prefix='SstpIntegratedTest-'+$session+'-';$group='SstpIntegratedTest-'+$session
$program=Join-Path $env:windir ('System32\sstp-integrated-fixture-'+$session+'.exe')
function Check([bool]$Ok) { if (-not $Ok) { throw 'integrated_test_assertion' };$script:checks++ }
function Reject([scriptblock]$Body,[string]$Code) { $caught=$false;try { & $Body | Out-Null } catch { if ($_.Exception.Message -cne $Code) { throw };$caught=$true };Check $caught }
function Clone($Object) { $Object | ConvertTo-Json -Depth 24 -Compress | ConvertFrom-Json }
function NewRoot { $root=InitializeJournalRoot (Join-Path $env:RUNNER_TEMP ('sstp-integrated-'+[guid]::NewGuid().ToString('N')));$script:roots+=,$root;return $root }
function AddFixture {
 $script:counter++;$name=$prefix+$script:counter.ToString('000')
 New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Description 'P9 fixture' -Group $group -Enabled True -Direction Outbound -Action Allow -Profile Any -Program $program -Protocol TCP -RemotePort 65534 -RemoteAddress @('192.0.2.44','2001:db8::44') -EdgeTraversalPolicy Block -ErrorAction Stop | Out-Null
 $row=ReadIntegratedRow (GetIntegratedRule $name);$script:fixtures+=,$row;return $row
}
function TakeNames([int]$Count=1) { $out=@();for($i=0;$i -lt $Count;$i++) { $out+=,$script:fixtures[$script:next].name;$script:next++ };return ,$out }
function Prepare([string[]]$Names) {
 $root=NewRoot;$state=NewIntegratedState (ReadPolicyInventory) $Names @($script:ownedName);WriteJournal $root -1 $state | Out-Null
 $script:journalMin=[Math]::Min($script:journalMin,$state.baseline.Count)
 return $root
}
function Worker([string]$Root,[string]$Action,[string]$Fault='None',[int]$Index=0) {
 $lines=@(& (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PSScriptRoot/Worker.ps1" -Root $Root -Action $Action -Fault $Fault -FaultIndex $Index 2>&1);$code=$LASTEXITCODE
 if ($code -notin @(0,73)) { foreach($line in $lines) { if ([string]$line -match '^(integrated|inventory|journal)_[a-z_0-9]+$') { Write-Host ([string]$line) } } };return $code
}
function CheckEnabled([string[]]$Names,[string]$Value='1') { foreach($name in $Names) { Check ((InventoryRaw (GetIntegratedRule $name)).Enabled -ceq $Value) } }
function DeleteFixture($Original) {
 $rule=GetIntegratedRule $Original.name;$row=ReadIntegratedRow $rule;$actual=SealIntegratedRow $row $false
 $trueSeal=SealIntegratedRow $Original $false;$falseSeal=SealIntegratedRow (IntegratedExpected $Original $true) $false
 if ($actual.policy_sha256 -cnotin @($trueSeal.policy_sha256,$falseSeal.policy_sha256) -or $row.rule.Group -cne $group) { throw 'integrated_cleanup_conflict' }
 Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
 $script:deleted[$Original.name]=$true
}
$before=ReadPolicyInventory
try {
 Check (-not (Test-Path -LiteralPath $program))
 # All regular fixtures exist BEFORE any transaction baseline; later additions are intentional negative tests.
 for($i=0;$i -lt 20;$i++) { AddFixture | Out-Null }
 $script:foreignName=$script:fixtures[18].name;$script:ownedName=$script:fixtures[19].name
 # Verify that compact policy seals retain every raw property and all seven filters.
 $row=$script:fixtures[0];$seal=SealIntegratedRow $row $false
 foreach($part in @('rule')+$script:InventoryParts) { foreach($p in $row.$part.PSObject.Properties) {
  $copy=Clone $row
  if ($p.Value -is [array]) { $copy.$part.($p.Name)=@($p.Value)+@('fixture') } else { $copy.$part.($p.Name)='fixture-value' }
  $changed=SealIntegratedRow $copy $false
  if ($part -ceq 'rule' -and $p.Name -cin @('Description','DisplayGroup','DisplayName')) {
   Check ($changed.policy_sha256 -ceq $seal.policy_sha256 -and $changed.strict_sha256 -cne $seal.strict_sha256)
   Check ((SealIntegratedRow $copy $true).policy_sha256 -cne (SealIntegratedRow $row $true).policy_sha256)
  } else { Check ($changed.policy_sha256 -cne $seal.policy_sha256) }
  $sealCases++
 } }
 $copy=Clone $row;$copy.rule.PSObject.Properties.Remove('DisplayName');Check ((SealIntegratedRow $copy $false).policy_sha256 -cne $seal.policy_sha256)
 $copy=Clone $row;$copy.rule.DisplayName=@('wrong-type');Check ((SealIntegratedRow $copy $false).policy_sha256 -cne $seal.policy_sha256)
 # Initial capture + real two-rule round trip + idempotency, through the public integrated entry point.
 $names=TakeNames 2;$root=NewRoot
 $r=InvokeIntegratedTransaction -Root $root -Action Quarantine -Names $names -Owned @($script:ownedName)
 Check ($r.phase -ceq 'quarantined');CheckEnabled $names '2';$nativeChanged=$true
 $record=(ReadJournal $root).record;$journalMin=[Math]::Min($journalMin,$record.state.baseline.Count)
 InvokeIntegratedTransaction $root Quarantine | Out-Null;Check ((ReadJournal $root).record.revision -eq $record.revision)
 InvokeIntegratedTransaction $root Restore | Out-Null;CheckEnabled $names
 $rev=(ReadJournal $root).record.revision;InvokeIntegratedTransaction $root Restore | Out-Null;Check ((ReadJournal $root).record.revision -eq $rev)
 Reject { InvokeIntegratedTransaction $root Quarantine } 'integrated_restore_started'
 foreach($action in @('Quarantine','Restore')) { foreach($point in @('BeforeMutation','AfterMutation')) {
  $names=TakeNames;$root=Prepare $names
  if ($action -eq 'Restore') { InvokeIntegratedTransaction $root Quarantine | Out-Null }
  Check ((Worker $root $action $point) -eq 73);$faults++
  Check ((ReadJournal $root).record.state.pending)
  Check ((Worker $root $action) -eq 0);$recoveries++
  if ($action -eq 'Quarantine') { InvokeIntegratedTransaction $root Restore | Out-Null }
  CheckEnabled $names;Check ((ReadJournal $root).record.state.phase -ceq 'restored')
  Write-Host ('integrated_fault_recovered_'+$faults)
 } }
 foreach($point in @('BeforeMutation','AfterMutation')) {
  $names=TakeNames 2;$root=Prepare $names
  Check ((Worker $root Quarantine $point 1) -eq 73);$faults++
  Check ((Worker $root Restore) -eq 0);$recoveries++;$partials++
  CheckEnabled $names;Check ((ReadJournal $root).record.state.phase -ceq 'restored')
 }
 # Foreign display drift is audited across process restart and NEVER overwritten by Restore.
 $names=TakeNames;$root=Prepare $names;InvokeIntegratedTransaction $root Quarantine | Out-Null
 Set-NetFirewallRule -InputObject (GetIntegratedRule $names[0]) -Description 'P9 selected display drift' -ErrorAction Stop | Out-Null
 Set-NetFirewallRule -InputObject (GetIntegratedRule $script:foreignName) -Description 'P9 external display drift' -ErrorAction Stop | Out-Null
 Check ((Worker $root Restore) -eq 0);CheckEnabled $names
 Check ((GetIntegratedRule $names[0]).Description -ceq 'P9 selected display drift' -and (GetIntegratedRule $script:foreignName).Description -ceq 'P9 external display drift');$metadataPreserved++
 Check ((InvokeIntegratedTransaction $root Restore).display_changed_rules -ge 2)
 # Owned display changes and NONSELECTED address-filter changes stop BEFORE cursor/journal advancement.
 $names=TakeNames;$root=Prepare $names;$rev=(ReadJournal $root).record.revision
 Set-NetFirewallRule -InputObject (GetIntegratedRule $script:ownedName) -Description 'P9 owned conflict' -ErrorAction Stop | Out-Null
 Reject { InvokeIntegratedTransaction $root Quarantine } 'integrated_policy_conflict';$conflicts++
 Check ((ReadJournal $root).record.revision -eq $rev);CheckEnabled $names
 Set-NetFirewallRule -InputObject (GetIntegratedRule $script:ownedName) -Description 'P9 fixture' -ErrorAction Stop | Out-Null
 InvokeIntegratedTransaction $root Restore | Out-Null
 $names=TakeNames;$root=Prepare $names;$rev=(ReadJournal $root).record.revision
 Set-NetFirewallRule -InputObject (GetIntegratedRule $script:foreignName) -RemoteAddress '192.0.2.45' -ErrorAction Stop | Out-Null
 Reject { InvokeIntegratedTransaction $root Quarantine } 'integrated_policy_conflict';$conflicts++
 Check ((ReadJournal $root).record.revision -eq $rev);CheckEnabled $names
 Set-NetFirewallRule -InputObject (GetIntegratedRule $script:foreignName) -RemoteAddress @('192.0.2.44','2001:db8::44') -ErrorAction Stop | Out-Null
 InvokeIntegratedTransaction $root Restore | Out-Null
 $names=TakeNames;$root=Prepare $names;$rev=(ReadJournal $root).record.revision;$extra=AddFixture
 Reject { InvokeIntegratedTransaction $root Quarantine } 'integrated_inventory_membership';$conflicts++
 Check ((ReadJournal $root).record.revision -eq $rev);CheckEnabled $names
 DeleteFixture $extra;InvokeIntegratedTransaction $root Restore | Out-Null
 $names=TakeNames;$root=Prepare $names;$rev=(ReadJournal $root).record.revision;DeleteFixture $script:fixtures[17]
 Reject { InvokeIntegratedTransaction $root Quarantine } 'integrated_inventory_membership';$conflicts++
 Check ((ReadJournal $root).record.revision -eq $rev);CheckEnabled $names
 # Primary corruption with a retained backup cannot authorize a mutation or EnableAll fallback.
 $names=TakeNames;$root=Prepare $names;InvokeIntegratedTransaction $root Quarantine | Out-Null
 [IO.File]::WriteAllText((Join-Path $root 'journal.json'),'broken')
 Reject { InvokeIntegratedTransaction $root Restore } 'integrated_journal_recovery_required';$corruptStops++;CheckEnabled $names '2'
 $root=NewRoot;Reject { InvokeIntegratedTransaction $root Restore } 'integrated_missing_journal';$missingStops++
 # Lock and capacity gates are checked before native mutation.
 $names=TakeNames;$root=NewRoot;$lock=OpenIntegratedLock $root
 try { $busy=$false;try { InvokeIntegratedTransaction -Root $root -Action Quarantine -Names $names | Out-Null } catch { $busy=$true };Check $busy } finally { $lock.Dispose() }
 Check ((ReadJournal $root).status -ceq 'absent');CheckEnabled $names
 $inventory=ReadPolicyInventory;$fake=Clone $inventory;$selected=@($fake.rules | Where-Object { $_.name -ceq $names[0] })[0];$selected.rule.Description='x'*1048576
 Reject { NewIntegratedState $fake $names @($script:ownedName) } 'integrated_journal_capacity';$capacityRejects++
 Check ($faults -eq 6 -and $recoveries -eq 6 -and $partials -eq 2 -and $conflicts -eq 4 -and $sealCases -ge 50 -and $metadataPreserved -eq 1 -and $capacityRejects -eq 1)
 $passed=$true
} catch {
 $errorCode='integrated_native_failure';Write-Host ('integrated_checks_before_failure_'+$script:checks)
 if ($_.Exception.Message -match '^(integrated|inventory|journal)_[a-z_0-9]+$') { Write-Host $_.Exception.Message } else { Write-Host ('integrated_provider_failure_'+$_.Exception.GetType().Name.ToLowerInvariant()) }
} finally {
 try {
  $inventory=ReadPolicyInventory;$map=@{};foreach($r in $inventory.rules) { $map[$r.name]=$r }
  foreach($original in $script:fixtures) {
   if (-not $map.ContainsKey($original.name)) { if (-not $script:deleted.ContainsKey($original.name)) { throw 'integrated_cleanup_missing' };continue }
   DeleteFixture $original
  }
  $after=ReadPolicyInventory;$remaining=@($after.rules | Where-Object { $_.name -like ($prefix+'*') }).Count
  $c=ComparePolicyInventory $before $after;$globalEqual=$c.policy_equal;$displayDrift=$c.display_rule_changes
  if ($remaining -ne 0 -or -not $globalEqual) { $passed=$false;$errorCode='integrated_baseline_mismatch' }
 } catch { $passed=$false;$errorCode='integrated_cleanup_failure' }
 foreach($root in $script:roots) { if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force } }
 $receipt=[ordered]@{schema='sstp-integrated-test-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;passed=$passed;error_code=$errorCode;checks=$script:checks;seal_field_cases=$sealCases;fault_cases=$faults;fresh_process_recoveries=$recoveries;partial_quarantine_restores=$partials;external_conflict_stops=$conflicts;metadata_preserved_cases=$metadataPreserved;capacity_rejections=$capacityRejects;corrupt_journal_stops=$corruptStops;missing_journal_stops=$missingStops;verified_fixture_rules=$script:fixtures.Count;remaining_test_rules=$remaining;journal_baseline_seals_min=$journalMin;unrelated_full_policy_equal=$globalEqual;unrelated_display_changes=$displayDrift;verified_native_enabled_changes=$nativeChanged;profile_defaults_changed=$false;real_guard_tested=$false;enforcement_tested=$false;sstp_binding_tested=$false;user_device_tested=$false;ready_for_user_apply=$false}
 [IO.File]::WriteAllText($OutputPath,($receipt | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
}
if (-not $passed) { exit 1 };exit 0
