[CmdletBinding()]
param()
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REPOSITORY -ne 'kokononox/battle-net-agent-lab' -or -not [Environment]::Is64BitProcess) { throw 's3u_ci_only_not_for_user_pc' }
. (Join-Path $PSScriptRoot 'Core.ps1')
function SetStage([string]$Value) { $script:Stage=$Value;Write-Host ('S3U_STAGE '+$Value+' '+[DateTime]::UtcNow.ToString('o')) }
SetStage 'fixtures';$script:Checks=0
function Check($Ok) { if (-not $Ok) { throw ('s3u_assertion_'+($script:Checks+1)) };$script:Checks++ }
function Fixtures {
    Check ((UnsetDecision 'Block') -ceq 'restore_notconfigured')
    Check ((UnsetDecision 'NotConfigured') -ceq 'already_notconfigured')
    Check ((UnsetDecision 'Allow') -ceq 'conflict')
    Check ((UnsetDecision 'Unknown') -ceq 'conflict')
    $id='0123456789abcdef0123456789abcdef'
    $j=[pscustomobject]@{schema='s3u-ci-journal-1';session_id=$id;purpose='experimental_unset_roundtrip_ci_only';prepared_utc=[DateTime]::UtcNow.ToString('o');profiles=@()}
    foreach ($name in @('Domain','Private','Public')) { $j.profiles+=,[pscustomobject]@{name=$name;before='NotConfigured';applied='Block'} }
    AssertUnsetJournal $j $id;Check $true
    function Reject($J,[string]$Id) { try { AssertUnsetJournal $J $Id;return $false } catch { return $true } }
    Check (Reject $j ('f'*32))
    $copy=$j | ConvertTo-Json -Depth 8 | ConvertFrom-Json;$copy.profiles[0].before='Allow';Check (Reject $copy $id)
    $copy=$j | ConvertTo-Json -Depth 8 | ConvertFrom-Json;$copy.profiles[0].applied='Allow';Check (Reject $copy $id)
    $copy=$j | ConvertTo-Json -Depth 8 | ConvertFrom-Json;$copy.profiles[0].name='Other';Check (Reject $copy $id)
    $copy=$j | ConvertTo-Json -Depth 8 | ConvertFrom-Json;$copy.prepared_utc=[DateTime]::UtcNow.AddHours(-1).ToString('o');Check (Reject $copy $id)
    $copy=$j | ConvertTo-Json -Depth 8 | ConvertFrom-Json;$copy.purpose='user_apply';Check (Reject $copy $id)
    Check ((OutboundPresenceCount @([pscustomobject]@{values=@([pscustomobject]@{name='Other'})})) -eq 0)
    Check ((OutboundPresenceCount @([pscustomobject]@{values=@([pscustomobject]@{name='DefaultOutboundAction'})})) -eq 1)
}
function RunRound([int]$Round) {
    SetStage ('round_'+$Round+'_baseline')
    $before=ProfileSnapshot
    if (@($before).Count -ne 3 -or @($before | Where-Object { $_.outbound -cne 'NotConfigured' }).Count -gt 0) { throw 's3u_baseline_not_all_notconfigured' }
    $effective=EffectiveProfileSnapshot;$com=(ReadComEffective | ConvertTo-Json -Compress);$ruleDigest=RulePropertyDigest
    $registry=ReadRegistryProfiles;$registryBefore=RegistryDigest $registry;$outboundBefore=OutboundRegistryDigest $registry;$presenceBefore=OutboundPresenceCount $registry
    $id=[Guid]::NewGuid().ToString('N');$folder=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('RetailIsolation-S3U-'+$id)
    CreatePrivateDirectory $folder
    foreach ($name in @('Core.ps1','Timer.ps1','Driver.ps1')) { [IO.File]::WriteAllBytes((Join-Path $folder $name),[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $name))) }
    WriteNewJson (Join-Path $folder 'private-registry-before.json') $registry
    $j=[ordered]@{schema='s3u-ci-journal-1';session_id=$id;purpose='experimental_unset_roundtrip_ci_only';prepared_utc=[DateTime]::UtcNow.ToString('o');profiles=@($before | ForEach-Object { [ordered]@{name=$_.name;before=$_.outbound;applied='Block'} })}
    WriteNewJson (Join-Path $folder 'journal.json') $j
    $taskName='RetailIsolation-S3U-'+$id;$description='CI-only unset provider experiment '+$id
    $ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $taskArguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $folder 'Timer.ps1')+'" -SessionId '+$id
    $registered=$false;$timerPassed=$false;$result=$null
    try {
        $action=New-ScheduledTaskAction -Execute $ps -Argument $taskArguments
        $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(75)
        $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew
        $who=New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        $task=New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $who -Description $description
        [void](Register-ScheduledTask -TaskName $taskName -TaskPath '\' -InputObject $task -ErrorAction Stop);$registered=$true
        $verify=Get-ScheduledTask -TaskName $taskName -TaskPath '\'
        if ($verify.Description -cne $description -or @($verify.Actions).Count -ne 1 -or $verify.Actions[0].Arguments -cne $taskArguments) { throw 's3u_task_identity' }
        SetStage ('round_'+$Round+'_driver')
        $driverArgs='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $folder 'Driver.ps1')+'" -SessionId '+$id
        $child=Start-Process -FilePath $ps -ArgumentList $driverArgs -PassThru -Wait -NoNewWindow
        if ($child.ExitCode -ne 73) { throw 's3u_driver_did_not_reach_exit' }
        $applied=[IO.File]::ReadAllText((Join-Path $folder 'applied.json')) | ConvertFrom-Json
        if (@($applied.profiles).Count -ne 3 -or @($applied.profiles | Where-Object { $_.outbound -cne 'Block' }).Count -gt 0 -or $applied.registry_sha256 -ceq $registryBefore -or $applied.outbound_registry_sha256 -ceq $outboundBefore) { throw 's3u_real_mutation_not_observed' }
        SetStage ('round_'+$Round+'_timer')
        $until=[DateTime]::UtcNow.AddSeconds(150);$r=$null;$receiptPath=Join-Path $folder 'timer-receipt.json'
        while ([DateTime]::UtcNow -lt $until) {
            if (Test-Path -LiteralPath $receiptPath) { try { $r=[IO.File]::ReadAllText($receiptPath) | ConvertFrom-Json;break } catch {} }
            Start-Sleep -Seconds 2
        }
        if ($null -eq $r -or $r.schema -cne 's3u-timer-receipt-1' -or $r.ran_as_system -ne $true -or $r.restore_write_calls -ne 3 -or $r.conflicts -ne 0) { throw 's3u_timer_not_success' }
        for ($n=0;$n -lt 10;$n++) { $info=Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\';if ($info.LastTaskResult -eq 0) { break };Start-Sleep -Seconds 1 }
        if ($info.LastTaskResult -ne 0) { throw 's3u_task_exit_not_zero' }
        SetStage ('round_'+$Round+'_exact_state')
        $afterRegistry=ReadRegistryProfiles;$afterDigest=RegistryDigest $afterRegistry
        if (((ProfileSnapshot) | ConvertTo-Json -Compress) -cne ($before | ConvertTo-Json -Compress)) { throw 's3u_stored_state_not_exact' }
        if ($afterDigest -cne $registryBefore) { throw 's3u_registry_profile_values_not_exact' }
        if ((EffectiveProfileSnapshot) -cne $effective -or (ReadComEffective | ConvertTo-Json -Compress) -cne $com) { throw 's3u_effective_state_not_exact' }
        if ((RulePropertyDigest) -cne $ruleDigest) { throw 's3u_rule_properties_changed' }
        $repeat=RestoreUnsetExperiment $folder $id
        if ($repeat.restore_write_calls -ne 0 -or $repeat.conflicts -ne 0) { throw 's3u_repeat_not_noop' }
        $timerPassed=$true
        $result=[ordered]@{round=$Round;baseline_profile_count=3;baseline_notconfigured_count=3;observed_block_count=3;outbound_registry_mutation_observed=$true;driver_abrupt_exit_verified=$true;system_timer_verified=$true;restore_write_calls=3;stored_state_exact=$true;registry_profile_values_exact=$true;effective_cim_exact=$true;effective_com_exact=$true;selected_rule_properties_exact=$true;registry_outbound_values_before=$presenceBefore;registry_outbound_values_during=[int]$applied.registry_outbound_value_count;registry_outbound_values_after=(OutboundPresenceCount $afterRegistry);repeat_restore_write_calls=0;task_last_result=0;task_removed=$false;controller_fallback_used=$false}
    } finally {
        if (-not $timerPassed) { try { [void](RestoreUnsetExperiment $folder $id) } catch {} }
        $storedRestored=(@((ProfileSnapshot) | Where-Object { $_.outbound -cne 'NotConfigured' }).Count -eq 0)
        if ($registered -and $storedRestored) {
            $t=Get-ScheduledTask -TaskName $taskName -TaskPath '\'
            if ($t.Description -cne $description -or $t.Actions[0].Arguments -cne $taskArguments) { throw 's3u_cleanup_identity' }
            Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
            if (@(Get-ScheduledTask -TaskPath '\' | Where-Object { $_.TaskName -ceq $taskName }).Count -ne 0) { throw 's3u_task_not_removed' }
            if ($null -ne $result) { $result.task_removed=$true }
        }
    }
    return $result
}
$result=[ordered]@{schema='sstp-unset-s3u-native-1';passed=$false;fixture_checks=0;rounds=@();stage=$null;error_code=$null;error_id=$null;diagnostic_line=$null;os_version=$null;os_build=$null;ps_version=$PSVersionTable.PSVersion.ToString();user_device_tested=$false;enforcement_tested=$false;registry_written_directly=$false;policy_reset_or_import_used=$false;s3_hardened_guard_changed=$false;ready_for_user_apply=$false}
try {
    $os=Get-CimInstance Win32_OperatingSystem -Property Version,BuildNumber -ErrorAction Stop;$result.os_version=$os.Version;$result.os_build=$os.BuildNumber
    Fixtures;$result.fixture_checks=$script:Checks
    if ($result.fixture_checks -ne 13) { throw 's3u_fixture_count' }
    foreach ($round in @(1,2)) { $result.rounds+=,(RunRound $round) }
    $result.passed=$true;SetStage 'complete'
} catch {
    $result.error_code='s3u_native_failed'
    if ($_.Exception.Message -cmatch '^s3u_[a-z_0-9]{1,100}$') { $result.error_code=$_.Exception.Message }
    $result.error_id=(([string]$_.FullyQualifiedErrorId) -replace '[^a-zA-Z0-9_.,-]','_');$result.diagnostic_line=[int]$_.InvocationInfo.ScriptLineNumber
} finally {
    $result.stage=$script:Stage
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'native-result.json'),($result | ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($false)))
}
if (-not $result.passed) { exit 1 }
