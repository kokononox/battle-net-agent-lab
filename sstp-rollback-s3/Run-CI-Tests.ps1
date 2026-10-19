[CmdletBinding()]
param()
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REPOSITORY -ne 'kokononox/battle-net-agent-lab') { throw 's3_github_hosted_ci_only_do_not_run_on_user_pc' }
. (Join-Path $PSScriptRoot 'Core.ps1')
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 's3_ci_not_admin' }
$script:Stage='fixtures';$script:Checks=0
function Check($Condition) { if (-not $Condition) { throw ('s3_assertion_'+($script:Checks+1)) };$script:Checks++ }
function TestFixtures {
    Check ((RollbackDecision 'Block' 'Allow' 'Block' $true) -ceq 'restore')
    Check ((RollbackDecision 'Allow' 'Allow' 'Block' $true) -ceq 'already_before')
    Check ((RollbackDecision 'NotConfigured' 'Allow' 'Block' $true) -ceq 'conflict_value')
    Check ((RollbackDecision 'Block' 'Allow' 'Block' $false) -ceq 'conflict_identity')
    Check ((RollbackDecision 'False' 'True' 'False' $true) -ceq 'restore')
    Check ((RollbackDecision 'True' 'True' 'False' $true) -ceq 'already_before')
    Check ((RollbackDecision 'False' 'False' 'False' $true) -ceq 'already_before')
    Check ((RollbackDecision 'Allow' 'NotConfigured' 'Block' $true) -ceq 'conflict_value')
    $id='0123456789abcdef0123456789abcdef'
    $j=[pscustomobject]@{schema='s3-ci-journal-1';session_id=$id;purpose='github_hosted_ci_fixtures_only';scenario='full';prepared_utc=[DateTime]::UtcNow.ToString('o');profiles=@();rules=@()}
    foreach ($name in @('Domain','Private','Public')) { $j.profiles+=,[pscustomobject]@{name=$name;before='NotConfigured';applied='Block'} }
    foreach ($letter in @('A','B')) { $j.rules+=,[pscustomobject]@{name=('RetailIsolation-S3-'+$id+'-'+$letter);before='True';applied='False';identity_sha256=('a'*64)} }
    AssertJournal $j $id;Check $true
    function Reject($Journal,[string]$Id) { try { AssertJournal $Journal $Id;return $false } catch { return $true } }
    Check (Reject $j ('f'*32))
    $copy=$j | ConvertTo-Json -Depth 8 | ConvertFrom-Json;$copy.rules[0].name='Unrelated-Rule';Check (Reject $copy $id)
    $copy=$j | ConvertTo-Json -Depth 8 | ConvertFrom-Json;$copy.profiles[0].name='Unknown';Check (Reject $copy $id)
    $copy=$j | ConvertTo-Json -Depth 8 | ConvertFrom-Json;$copy.profiles[0].before='Unknown';Check (Reject $copy $id)
    $copy=$j | ConvertTo-Json -Depth 8 | ConvertFrom-Json;$copy.prepared_utc=[DateTime]::UtcNow.AddHours(-1).ToString('o');Check (Reject $copy $id)
    $copy=$j | ConvertTo-Json -Depth 8 | ConvertFrom-Json;$copy.purpose='user_device_apply';Check (Reject $copy $id)
    $copy=$j | ConvertTo-Json -Depth 8 | ConvertFrom-Json;$copy.rules[0].identity_sha256='not_a_hash';Check (Reject $copy $id)
}
function RunScenario([string]$Scenario) {
    $script:Stage=$Scenario+'_setup'
    $baseline=ProfileSnapshot;$effectiveBefore=EffectiveProfileSnapshot
    if (@($baseline).Count -ne 3 -or @($baseline | Where-Object { $_.outbound -ne 'Block' }).Count -eq 0) { throw 's3_no_real_profile_transition_available' }
    $id=[Guid]::NewGuid().ToString('N');$folder=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('RetailIsolation-S3-'+$id)
    $group='RetailIsolation-S3-'+$id;$taskName=$group+'-Timer';$description='CI-only targeted rollback '+$id
    $ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $registered=$false;$journalReady=$false;$timerSucceeded=$false;$cleanupOk=$false;$result=$null
    $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $folder 'Timed-Rollback.ps1')+'" -SessionId '+$id
    CreatePrivateDirectory $folder
    foreach ($name in @('Core.ps1','Timed-Rollback.ps1','Crash-Driver.ps1')) { [IO.File]::WriteAllBytes((Join-Path $folder $name),[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $name))) }
    try {
        foreach ($letter in @('A','B','C')) {
            $action='Allow';if ($letter -eq 'C') { $action='Block' }
            [void](New-NetFirewallRule -Name ($group+'-'+$letter) -DisplayName ($group+'-'+$letter) -Group $group -Description ('baseline-'+$id) -Enabled True -Direction Outbound -Action $action -Protocol TCP -RemoteAddress '198.51.100.17' -RemotePort 9 -Profile Any -PolicyStore PersistentStore -ErrorAction Stop)
        }
        $rules=@()
        foreach ($letter in @('A','B')) { $rule=GetFixtureRule ($group+'-'+$letter);$rules+=,[ordered]@{name=[string]$rule.Name;before=[string]$rule.Enabled;applied='False';identity_sha256=(FixtureIdentity $rule)} }
        $profiles=@($baseline | ForEach-Object { [ordered]@{name=$_.name;before=$_.outbound;applied='Block'} })
        $j=[ordered]@{schema='s3-ci-journal-1';session_id=$id;purpose='github_hosted_ci_fixtures_only';scenario=$Scenario;prepared_utc=[DateTime]::UtcNow.ToString('o');profiles=$profiles;rules=$rules}
        WriteNewJson (Join-Path $folder 'journal.json') $j;$journalReady=$true
        $action=New-ScheduledTaskAction -Execute $ps -Argument $arguments
        $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(75)
        $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew
        $who=New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        $task=New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $who -Description $description
        [void](Register-ScheduledTask -TaskName $taskName -TaskPath '\' -InputObject $task -ErrorAction Stop);$registered=$true
        $verify=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
        if ($verify.Description -cne $description -or @($verify.Actions).Count -ne 1 -or $verify.Actions[0].Arguments -cne $arguments) { throw 's3_task_registration_mismatch' }
        $script:Stage=$Scenario+'_crash_driver'
        $args='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $folder 'Crash-Driver.ps1')+'" -SessionId '+$id
        $driver=Start-Process -FilePath $ps -ArgumentList $args -PassThru -Wait -NoNewWindow
        if ($driver.ExitCode -ne 73) { throw 's3_driver_did_not_reach_injected_exit' }
        $marker=[IO.File]::ReadAllText((Join-Path $folder 'driver-applied.json')) | ConvertFrom-Json
        if ($marker.a_enabled -cne 'False' -or $marker.b_enabled -cne 'False') { throw 's3_rule_mutation_not_observed' }
        if ($Scenario -eq 'full' -and @($marker.profiles | Where-Object { $_.outbound -ne 'Block' }).Count -gt 0) { throw 's3_full_profile_mutation_not_observed' }
        # A separate fixture simulates a concurrent unrelated edit, excluded from the journal.
        Set-NetFirewallRule -Name ($group+'-C') -PolicyStore PersistentStore -Description ('external-unrelated-'+$id) -ErrorAction Stop
        $unrelatedFingerprint=FixtureIdentity (GetFixtureRule ($group+'-C'))
        $script:Stage=$Scenario+'_await_timer'
        $until=[DateTime]::UtcNow.AddSeconds(150);$receiptPath=Join-Path $folder 'rollback-receipt.json';$receipt=$null
        while ([DateTime]::UtcNow -lt $until) {
            if (Test-Path -LiteralPath $receiptPath) { try { $receipt=[IO.File]::ReadAllText($receiptPath) | ConvertFrom-Json;break } catch {} }
            Start-Sleep -Seconds 2
        }
        if ($null -eq $receipt -or $receipt.schema -cne 's3-ci-rollback-receipt-1' -or $receipt.ran_as_system -ne $true) { throw 's3_timer_receipt_missing' }
        $expectedConflicts=0;$expectedExit=0;if ($Scenario -eq 'partial_conflict') { $expectedConflicts=1;$expectedExit=2 }
        if ($receipt.conflicts -ne $expectedConflicts) { throw 's3_conflict_count_mismatch' }
        for ($n=0;$n -lt 12;$n++) { $info=Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\';if ($info.LastTaskResult -eq $expectedExit) { break };Start-Sleep -Seconds 1 }
        if ($info.LastTaskResult -ne $expectedExit) { throw 's3_task_exit_mismatch' }
        $after=ProfileSnapshot
        if (($after | ConvertTo-Json -Compress) -cne ($baseline | ConvertTo-Json -Compress) -or (EffectiveProfileSnapshot) -cne $effectiveBefore) { throw 's3_profile_baseline_not_restored' }
        if ([string](GetFixtureRule ($group+'-A')).Enabled -cne 'True') { throw 's3_rule_a_not_restored' }
        $b=GetFixtureRule ($group+'-B')
        if ($Scenario -eq 'full') { if ([string]$b.Enabled -cne 'True') { throw 's3_rule_b_not_restored' } }
        else { if ([string]$b.Enabled -cne 'False' -or $b.Description -cne ('foreign-change-'+$id)) { throw 's3_foreign_edit_not_preserved' } }
        if ((FixtureIdentity (GetFixtureRule ($group+'-C'))) -cne $unrelatedFingerprint) { throw 's3_unrelated_fixture_changed' }
        $script:Stage=$Scenario+'_idempotence'
        $repeat=InvokeS3Rollback $folder $id
        if ($repeat.conflicts -ne $expectedConflicts -or @($repeat.items | Where-Object { $_.decision -eq 'restore' }).Count -ne 0) { throw 's3_repeat_not_idempotent' }
        $timerSucceeded=$true
        $result=[ordered]@{scenario=$Scenario;driver_abrupt_exit_verified=$true;driver_exit_code=$driver.ExitCode;profile_transition_observed=$true;system_timer_verified=$true;targeted_profile_restore_verified=$true;fixture_a_restore_verified=$true;expected_conflicts=$expectedConflicts;observed_conflicts=[int]$receipt.conflicts;conflict_fixture_preserved=($Scenario -eq 'partial_conflict');unrelated_fixture_edit_preserved=$true;repeat_no_writes_verified=$true;task_last_result=[long]$info.LastTaskResult;task_removed=$false;fixture_rules_removed=$false;emergency_controller_restore_used=$false}
    } finally {
        # Controller fallback prevents leaving CI default policy altered when an assertion fails.
        # A fallback is never counted as proof that the timer worked.
        if ($journalReady -and -not $timerSucceeded) { try { [void](InvokeS3Rollback $folder $id) } catch {} }
        $profilesMatch=(($baseline | ConvertTo-Json -Compress) -ceq ((ProfileSnapshot) | ConvertTo-Json -Compress))
        if ($profilesMatch) {
            if ($registered) {
                $t=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
                if ($t.Description -cne $description -or $t.Actions[0].Arguments -cne $arguments) { throw 's3_cleanup_task_identity_mismatch' }
                Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
                if (@(Get-ScheduledTask -TaskPath '\' | Where-Object { $_.TaskName -ceq $taskName }).Count -ne 0) { throw 's3_task_cleanup_failed' }
                if ($null -ne $result) { $result.task_removed=$true }
            }
            foreach ($letter in @('A','B','C')) {
                $fixture=@(Get-NetFirewallRule -Name ($group+'-'+$letter) -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
                foreach ($rule in $fixture) {
                    if ($rule.Group -cne $group) { throw 's3_cleanup_rule_identity_mismatch' }
                    Remove-NetFirewallRule -Name $rule.Name -PolicyStore PersistentStore -ErrorAction Stop
                }
            }
            if (@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Group -ceq $group }).Count -ne 0) { throw 's3_fixture_cleanup_failed' }
            if ($null -ne $result) { $result.fixture_rules_removed=$true }
        } else { throw 's3_ci_profiles_not_restored_timer_left_armed' }
    }
    return $result
}
$summary=[ordered]@{schema='sstp-targeted-rollback-s3-native-1';passed=$false;fixture_checks=0;scenarios=@();stage=$null;error_code=$null;diagnostic_line=$null;error_id=$null;exception_type=$null;user_device_tested=$false;sstp_or_level3_enforcement_tested=$false;firewall_import_used=$false;concurrent_write_protection_atomic=$false}
try {
    TestFixtures;$summary.fixture_checks=$script:Checks
    foreach ($scenario in @('full','partial_conflict')) { $summary.scenarios+=,(RunScenario $scenario) }
    if ($summary.fixture_checks -ne 16) { throw 's3_fixture_count' }
    $summary.passed=$true;$script:Stage='complete'
} catch {
    $summary.error_code='s3_native_failed'
    if ($_.Exception.Message -cmatch '^s3_[a-z_0-9]{1,100}$') { $summary.error_code=$_.Exception.Message }
    $summary.diagnostic_line=[int]$_.InvocationInfo.ScriptLineNumber
    $summary.error_id=(([string]$_.FullyQualifiedErrorId) -replace '[^a-zA-Z0-9_.,-]','_')
    $summary.exception_type=$_.Exception.GetType().FullName
} finally {
    $summary.stage=$script:Stage
    $path=Join-Path $PSScriptRoot 'native-result.json'
    [IO.File]::WriteAllText($path,($summary | ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($false)))
}
if (-not $summary.passed) { exit 1 }
