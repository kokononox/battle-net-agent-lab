param([Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. "$PSScriptRoot/Journal.ps1"
. "$PSScriptRoot/RestorePolicy.ps1"
$script:checks=0;$root=$null;$passed=$false;$errorCode=$null
function Check([bool]$Ok) { if (-not $Ok) { throw 'journal_test_assertion' };$script:checks++ }
function Reject([scriptblock]$Body,[string]$Expected) {
 $caught=$false
 try { & $Body | Out-Null } catch { if ($_.Exception.Message -ne $Expected) { throw };$caught=$true }
 Check $caught
}
try {
 $root=InitializeJournalRoot (Join-Path $env:RUNNER_TEMP ('sstp-journal-test-'+[guid]::NewGuid().ToString('N')))
 Check ((ReadJournal $root).status -eq 'absent')
 AssertJournalAcl $root;Check $true
 $state=[ordered]@{session_id=[guid]::NewGuid().ToString();phase='prepared';before=[ordered]@{Domain='NotConfigured';Private='Allow';Public='Block'};pending_operation=$null;expires_at=$null}
 $r=WriteJournal $root -1 $state
 Check ($r.revision -eq 0 -and $r.state.before.Domain -eq 'NotConfigured')
 Check ((ReadJournal $root).record.state.before.Private -eq 'Allow')
 Reject { WriteJournal $root -1 $state } 'journal_revision_conflict'
 $state.phase='intent_recorded';$state.pending_operation='test-only-no-os-action'
 $r=WriteJournal $root 0 $state
 Check ($r.revision -eq 1 -and $r.state.pending_operation -eq 'test-only-no-os-action')
 Check ((ReadJournalFile (Join-Path $root 'journal.bak')).revision -eq 0)
 $held=OpenJournalLock $root
 try { $busy=$false;try { ReadJournal $root | Out-Null } catch { $busy=$true };Check $busy } finally { $held.Dispose() }
 Check (@(Get-ChildItem -LiteralPath $root -Filter 'journal.next-*').Count -eq 0)
 $primary=Join-Path $root 'journal.json'
 $original=[IO.File]::ReadAllText($primary)
 $e=$original | ConvertFrom-Json;$e.sha256=('0'*64)
 [IO.File]::WriteAllText($primary,($e | ConvertTo-Json -Compress))
 Check ((ReadJournal $root).status -eq 'recovery_required')
 Reject { WriteJournal $root 0 $state } 'journal_recovery_required'
 [IO.File]::WriteAllText($primary,'broken')
 Check ((ReadJournal $root).status -eq 'recovery_required')
 [IO.File]::Delete($primary)
 Check ((ReadJournal $root).status -eq 'recovery_required')
 [IO.File]::WriteAllText($primary,'broken');[IO.File]::WriteAllText((Join-Path $root 'journal.bak'),'broken')
 Reject { ReadJournal $root } 'journal_unrecoverable'
 [IO.File]::WriteAllText($primary,$original)
 Check ((ReadJournal $root).record.revision -eq 1)
 Check ((GetRestoreDecision 'NotConfigured' 'Block' 'Block' $true $true) -eq 'restore_exact_before')
 Check ((GetRestoreDecision 'Allow' 'Block' 'Allow' $true $false) -eq 'already_restored')
 Check ((GetRestoreDecision 'NotConfigured' 'Block' 'Allow' $true $true) -eq 'stop_external_change')
 Check ((GetRestoreDecision 'Allow' 'Block' 'Block' $false $true) -eq 'stop_ownership_unverified')
 Check ((GetRestoreDecision 'Allow' 'Block' 'Block' $true $false) -eq 'stop_guard_unverified')
 Check ((GetGuardReleaseDecision $true $true $false $true) -eq 'release_may_be_planned')
 foreach($flags in @(@($false,$true,$false,$true),@($true,$false,$false,$true),@($true,$true,$true,$true),@($true,$true,$false,$false))) {
  Check ((GetGuardReleaseDecision @flags) -eq 'keep_guard_required')
 }
 Reject { AssertJournalPath '\\server\share\state' } 'journal_path'
 Reject { AssertJournalPath 'relative\state' } 'journal_path'
 Reject { AssertJournalPath 'C:\Windows\..\state' } 'journal_path'
 # Tampering with the directory's inheritance must prevent any further use.
 $acl=Get-Acl -LiteralPath $root;$acl.SetAccessRuleProtection($false,$true);Set-Acl -LiteralPath $root -AclObject $acl
 Reject { ReadJournal $root } 'journal_acl_inheritance'
 Check ($script:checks -eq 29)
 $passed=$true
} catch { $errorCode='journal_native_failure';Write-Host $_.Exception.Message }
finally {
 # Only this invocation's isolated test directory; no user state and no firewall operations.
 if ($root -and (Test-Path -LiteralPath $root)) { Remove-Item -LiteralPath $root -Recurse -Force }
 $receipt=[ordered]@{schema='sstp-journal-test-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;passed=$passed;checks=$script:checks;error_code=$errorCode;network_changed=$false;firewall_changed=$false;dns_queried=$false;resident_program_created=$false;enforcement_tested=$false;user_device_tested=$false;ready_for_user_apply=$false}
 [IO.File]::WriteAllText($OutputPath,($receipt | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
}
if (-not $passed) { exit 1 }
