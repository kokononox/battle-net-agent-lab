param([Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. "$PSScriptRoot/ModelEngine.ps1"
$script:checks=0;$script:faultCases=0;$script:recoveries=0;$passed=$false;$errorCode=$null;$script:roots=@()
function Check([bool]$Ok) { if (-not $Ok) { throw 'transaction_test_assertion' };$script:checks++ }
function Reject([scriptblock]$Body,[string]$Expected) {
 $caught=$false
 try { & $Body | Out-Null } catch { if ($_.Exception.Message -ne $Expected) { throw };$caught=$true }
 Check $caught
}
function SameWorld($A,$B) {
 $a1=[ordered]@{};$b1=[ordered]@{}
 foreach($k in @($A.PSObject.Properties.Name | Sort-Object)) { $a1[$k]=$A.$k }
 foreach($k in @($B.PSObject.Properties.Name | Sort-Object)) { $b1[$k]=$B.$k }
 return (($a1 | ConvertTo-Json -Compress) -ceq ($b1 | ConvertTo-Json -Compress))
}
function NewFixtureResources {
 @(
  [pscustomobject]@{key='guard';before='absent';after='blocked'},
  [pscustomobject]@{key='profile:Domain';before='NotConfigured';after='Block'},
  [pscustomobject]@{key='profile:Private';before='Allow';after='Block'},
  [pscustomobject]@{key='profile:Public';before='Block';after='Block'},
  [pscustomobject]@{key=('local:'+('1'*16));before=('enabled:'+('a'*64));after=('disabled:'+('a'*64))},
  [pscustomobject]@{key=('local:'+('2'*16));before=('enabled:'+('b'*64));after=('disabled:'+('b'*64))},
  [pscustomobject]@{key=('owned:'+('3'*16));before='absent';after=('present:'+('c'*64))}
 )
}
$resources=@(NewFixtureResources)
$prototype=NewModelTransaction $resources
function NewFixture {
 $root=InitializeJournalRoot (Join-Path $env:RUNNER_TEMP ('sstp-transaction-'+[guid]::NewGuid().ToString('N')))
 $script:roots+=,$root
 [IO.File]::WriteAllText((Join-Path $root 'plan.json'),(ConvertTo-Json -InputObject $resources -Depth 5 -Compress))
 [IO.File]::WriteAllText((Join-Path $root 'model.json'),((ModelBaseline $prototype) | ConvertTo-Json -Compress))
 return $root
}
function Worker([string]$Root,[string]$Action,[int]$Before=-1,[int]$After=-1) {
 $exe=Join-Path $PSHOME 'powershell.exe'
 $output=@(& $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PSScriptRoot/Worker.ps1" -Root $Root -Action $Action -FaultBefore $Before -FaultAfter $After 2>&1)
 $code=$LASTEXITCODE
 if ($code -notin @(0,73)) {
  Write-Host ('transaction_worker_exit_'+$code)
  foreach($line in $output) { if ([string]$line -match '^transaction_[a-z_0-9]+$') { Write-Host ([string]$line) } }
 }
 return $code
}
try {
 $opCount=@(GetModelOperations $prototype).Count
 if ($opCount -ne 9) { throw 'transaction_fixture_count' }
 foreach($action in @('Enable','Disable')) {
  foreach($side in @('Before','After')) {
   for($index=0;$index -lt $opCount;$index++) {
    $root=NewFixture
    if ($action -eq 'Disable') { InvokeModelPolicyTransaction $root 'Enable' $resources | Out-Null }
    $before=-1;$after=-1;if ($side -eq 'Before') { $before=$index } else { $after=$index }
    Check ((Worker $root $action $before $after) -eq 73);$script:faultCases++
    $world=ReadModelWorld $root
    Check ($world.guard -eq 'blocked' -or (SameWorld $world (ModelBaseline $prototype)) -or (SameWorld $world (ModelFinal $prototype 'enable')))
    # Recovery runs in a NEW powershell.exe process, with no memory of the terminated worker.
    Check ((Worker $root $action) -eq 0);$script:recoveries++
    $phase=$action.ToLowerInvariant()
    Check (SameWorld (ReadModelWorld $root) (ModelFinal $prototype $phase))
    $j=ReadJournal $root
    Check ($null -eq $j.record.state.pending -and $j.record.state.cursor -eq $opCount -and $j.record.state.phase -eq $phase)
    $revision=$j.record.revision
    InvokeModelPolicyTransaction $root $action $resources | Out-Null
    Check ((ReadJournal $root).record.revision -eq $revision)
   }
  }
 }
 # Disable may safely target the original baseline from a partially applied Enable.
 foreach($side in @('Before','After')) {
  $root=NewFixture;$before=-1;$after=-1
  if ($side -eq 'Before') { $before=3 } else { $after=3 }
  Check ((Worker $root 'Enable' $before $after) -eq 73);$script:faultCases++
  Check ((ReadModelWorld $root).guard -eq 'blocked')
  Check ((Worker $root 'Disable') -eq 0);$script:recoveries++
  Check (SameWorld (ReadModelWorld $root) (ModelBaseline $prototype))
  $j=ReadJournal $root
  Check ($j.record.state.phase -eq 'disable' -and $j.record.state.cursor -eq $opCount -and $null -eq $j.record.state.pending)
  $revision=$j.record.revision
  InvokeModelPolicyTransaction $root 'Disable' $resources | Out-Null
  Check ((ReadJournal $root).record.revision -eq $revision)
 }
 # Missing journal: Disable must not invent a reset or open anything.
 $root=NewFixture;$before=ReadModelWorld $root
 Reject { InvokeModelPolicyTransaction $root 'Disable' } 'transaction_missing_journal'
 Check (SameWorld $before (ReadModelWorld $root))
 # A hash-valid but semantically invalid journal must not authorize a write.
 $root=NewFixture;InvokeModelPolicyTransaction $root 'Enable' $resources | Out-Null
 $j=ReadJournal $root;$j.record.state.cursor=999
 WriteJournal $root $j.record.revision $j.record.state | Out-Null;$before=ReadModelWorld $root
 Reject { InvokeModelPolicyTransaction $root 'Disable' } 'transaction_cursor'
 Check (SameWorld $before (ReadModelWorld $root))
 # Primary corruption with backup available requires inspection, never blind replay.
 $root=NewFixture;InvokeModelPolicyTransaction $root 'Enable' $resources | Out-Null
 [IO.File]::WriteAllText((Join-Path $root 'journal.json'),'broken');$before=ReadModelWorld $root
 Reject { InvokeModelPolicyTransaction $root 'Disable' } 'transaction_journal_recovery_required'
 Check (SameWorld $before (ReadModelWorld $root))
 # An external edit to an acknowledged resource is not overwritten.
 $root=NewFixture;InvokeModelPolicyTransaction $root 'Enable' $resources | Out-Null
 WriteModelResource $root 'profile:Private' 'NotConfigured';$before=ReadModelWorld $root
 Reject { InvokeModelPolicyTransaction $root 'Disable' } 'transaction_state_conflict'
 Check (SameWorld $before (ReadModelWorld $root))
 # Whole-operation lock, separate from per-journal-write locks.
 $root=NewFixture;$before=ReadModelWorld $root;$lock=OpenModelTransactionLock $root
 try { $busy=$false;try { InvokeModelPolicyTransaction $root 'Enable' $resources | Out-Null } catch { $busy=$true };Check $busy } finally { $lock.Dispose() }
 Check (SameWorld $before (ReadModelWorld $root))
 # An unfinished Disable must be completed, not reversed halfway through.
 $root=NewFixture;InvokeModelPolicyTransaction $root 'Enable' $resources | Out-Null
 if ((Worker $root 'Disable' 2 -1) -ne 73) { throw 'transaction_fixture_failure' }
 $before=ReadModelWorld $root
 Reject { InvokeModelPolicyTransaction $root 'Enable' $resources } 'transaction_finish_disable_first'
 Check (SameWorld $before (ReadModelWorld $root))
 $bad=ModelClone $resources;$bad=[object[]]$bad;$bad[1].before='Any'
 Reject { NewModelTransaction $bad } 'transaction_profile_schema'
 $bad=ModelClone $resources;$bad=[object[]]$bad;$bad[1].key=$bad[0].key
 Reject { NewModelTransaction $bad } 'transaction_resource_schema'
 Check ($script:checks -eq 242 -and $script:faultCases -eq 38 -and $script:recoveries -eq 38)
 $passed=$true
} catch {
 $errorCode='transaction_native_failure';Write-Host ('Transaction check failed after '+$script:checks+' checks.')
 if ($_.Exception.Message -match '^transaction_[a-z_]+$') { Write-Host $_.Exception.Message } else { Write-Host ('transaction_provider_failure_'+$_.Exception.GetType().Name) }
} finally {
 foreach($root in $script:roots) { if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force } }
 $receipt=[ordered]@{schema='sstp-transaction-test-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;passed=$passed;checks=$script:checks;fault_cases=$script:faultCases;fresh_process_recoveries=$script:recoveries;error_code=$errorCode;adapter_kind='file_model_only';firewall_changed=$false;dns_queried=$false;resident_program_created=$false;real_guard_tested=$false;enforcement_tested=$false;sstp_binding_tested=$false;user_device_tested=$false;ready_for_user_apply=$false}
 [IO.File]::WriteAllText($OutputPath,($receipt | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
}
if (-not $passed) { exit 1 };exit 0
