[CmdletBinding()]
param([switch]$SelfTest)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$script:WorkerTextSha256='4016b7c8a7bd06bf54c32f69695ce097c30b2420f48595001a9458536ba81907'
function TextHash([string]$Path) {
    $text=[IO.File]::ReadAllText($Path).Replace("`r`n","`n")
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash((New-Object Text.UTF8Encoding($false)).GetBytes($text)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
}
function ValidId([string]$Id) { return ($Id -cmatch '^[a-f0-9]{32}$') }
function AssertProbeReceipt($R,[string]$Id) {
    if ($null -eq $R) { throw 'missing_probe_receipt' }
    $keys=@($R.PSObject.Properties.Name | Sort-Object)
    $expected=@('schema','session_id','ran_as_system','ended_utc','network_settings_changed','firewall_import_attempted' | Sort-Object)
    if (($keys -join ',') -cne ($expected -join ',')) { throw 'probe_schema' }
    if ($R.schema -cne 's2-system-probe-1' -or $R.session_id -cne $Id -or -not (ValidId $Id)) { throw 'probe_identity' }
    if ($R.ran_as_system -isnot [bool] -or $R.ran_as_system -ne $true -or $R.network_settings_changed -isnot [bool] -or $R.network_settings_changed -ne $false -or $R.firewall_import_attempted -isnot [bool] -or $R.firewall_import_attempted -ne $false) { throw 'probe_scope' }
    $stamp=[DateTimeOffset]::Parse([string]$R.ended_utc)
    if ($stamp -gt [DateTimeOffset]::UtcNow.AddMinutes(1) -or $stamp -lt [DateTimeOffset]::UtcNow.AddMinutes(-10)) { throw 'stale_probe' }
}
function AssertPrivateDirectory([string]$Path) {
    $item=Get-Item -LiteralPath $Path
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'private_directory_invalid' }
    $acl=Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { throw 'private_acl_not_protected' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'untrusted_private_acl' }
    }
}
function CreatePrivateDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw 'private_directory_exists' }
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity=New-Object Security.Principal.SecurityIdentifier($sid)
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($identity,[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    [void][IO.Directory]::CreateDirectory($Path,$acl)
    AssertPrivateDirectory $Path
}
function PolicySummary {
    $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Sort-Object Name | ForEach-Object {
        [ordered]@{name=[string]$_.Name;enabled=[string]$_.Enabled;inbound=[string]$_.DefaultInboundAction;outbound=[string]$_.DefaultOutboundAction}
    })
    if ($profiles.Count -ne 3) { throw 'firewall_profiles_incomplete' }
    return ($profiles | ConvertTo-Json -Compress)
}
function SelfTests {
    $script:Checks=0
    function Check($Condition) { if (-not $Condition) { throw ('fixture_assertion_'+($script:Checks+1)) };$script:Checks++ }
    function Rejected($Value,[string]$Id) { try { AssertProbeReceipt $Value $Id;return $false } catch { return $true } }
    $id='0123456789abcdef0123456789abcdef'
    Check (ValidId $id)
    Check (-not (ValidId '../path'))
    Check (-not (ValidId $id.ToUpperInvariant()))
    Check (-not (ValidId ($id+'a')))
    Check (-not (ValidId ''))
    $r=[pscustomobject]@{schema='s2-system-probe-1';session_id=$id;ran_as_system=$true;ended_utc=[DateTime]::UtcNow.ToString('o');network_settings_changed=$false;firewall_import_attempted=$false}
    AssertProbeReceipt $r $id; Check $true
    Check (Rejected $null $id)
    Check (Rejected $r ('f'*32))
    foreach ($key in @('ran_as_system','network_settings_changed','firewall_import_attempted')) {
        $copy=($r | ConvertTo-Json | ConvertFrom-Json);$copy.$key=(-not $copy.$key);Check (Rejected $copy $id)
    }
    $copy=($r | ConvertTo-Json | ConvertFrom-Json);$copy.ran_as_system='true';Check (Rejected $copy $id)
    $copy=($r | ConvertTo-Json | ConvertFrom-Json);$copy.schema='wrong';Check (Rejected $copy $id)
    $copy=($r | ConvertTo-Json | ConvertFrom-Json);$copy.ended_utc=[DateTime]::UtcNow.AddHours(-1).ToString('o');Check (Rejected $copy $id)
    $copy=($r | ConvertTo-Json | ConvertFrom-Json);$copy.ended_utc=[DateTime]::UtcNow.AddHours(1).ToString('o');Check (Rejected $copy $id)
    $copy=($r | ConvertTo-Json | ConvertFrom-Json);$copy | Add-Member -NotePropertyName unexpected -NotePropertyValue 'PRIVATE';Check (Rejected $copy $id)
    Check ((TextHash (Join-Path $PSScriptRoot 'Rollback-Probe.ps1')) -ceq $script:WorkerTextSha256)
    return [ordered]@{schema='s2-rehearsal-fixture-1';passed=$true;checks=$script:Checks;network_settings_changed=$false;scheduled_task_created=$false;firewall_policy_exported=$false}
}
function Rehearse {
    $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run_as_administrator' }
    Write-Host 'S2 RECOVERY REHEARSAL ONLY - NO INTERNET ISOLATION, NO FIREWALL IMPORT.'
    Write-Host 'Creates a private firewall EXPORT and one scheduled SYSTEM probe, then removes its task.'
    Write-Host 'The probe writes a receipt only. Keep WoW CLOSED and update PAUSED. Do not Resume.'
    $workerSource=Join-Path $PSScriptRoot 'Rollback-Probe.ps1'
    if ((TextHash $workerSource) -cne $script:WorkerTextSha256) { throw 'worker_hash_mismatch' }
    if ((Get-Service -Name Schedule -ErrorAction Stop).Status -ne 'Running') { throw 'scheduler_not_running' }
    $started=[DateTime]::UtcNow.ToString('o');$id=[Guid]::NewGuid().ToString('N')
    $folder=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('RetailIsolation-S2-'+$id)
    $taskName='RetailIsolation-S2-Probe-'+$id
    $description='RetailIsolation S2 receipt-only probe '+$id
    $powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $netsh=Join-Path $env:SystemRoot 'System32\netsh.exe'
    $worker=Join-Path $folder 'Rollback-Probe.ps1'
    $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$worker+'" -SessionId '+$id
    $r=[ordered]@{schema='sstp-recovery-rehearsal-s2';session_id=$id;started_utc=$started;ended_utc=$null;passed=$false;error_code=$null;
        firewall_backup_exported=$false;firewall_backup_nonempty=$false;private_acl_checked=$false;worker_hash_checked=$false;
        task_registered=$false;system_probe_receipt_verified=$false;task_last_result=$null;owned_task_removed=$false;
        firewall_profile_summary_unchanged=$null;firewall_restore_import_tested=$false;independent_network_rollback_proven=$false;ready_to_apply_isolation=$false;
        network_settings_changed_by_tool=$false;vpn_or_game_process_control=$false;game_resume_requested=$false;automatic_upload=$false;
        private_backup_contents_exported_to_report=$false;task_name=$taskName;probe_delay_seconds=45;wait_limit_seconds=120;private_session_id=$id}
    $registered=$false;$before=$null
    try {
        $before=PolicySummary
        CreatePrivateDirectory $folder; $r.private_acl_checked=$true
        [IO.File]::WriteAllBytes($worker,[IO.File]::ReadAllBytes($workerSource))
        if ((TextHash $worker) -cne $script:WorkerTextSha256) { throw 'private_worker_hash_mismatch' };$r.worker_hash_checked=$true
        $backup=Join-Path $folder 'firewall-before.wfw'
        $exportOutput=& $netsh advfirewall export $backup 2>&1
        if ($LASTEXITCODE -ne 0) { throw 'firewall_export_failed' }
        $r.firewall_backup_exported=$true
        if (-not (Test-Path -LiteralPath $backup) -or (Get-Item -LiteralPath $backup).Length -le 0) { throw 'firewall_export_empty' }
        $r.firewall_backup_nonempty=$true
        $action=New-ScheduledTaskAction -Execute $powershell -Argument $arguments
        $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(45)
        $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
        $identity=New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        $definition=New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $identity -Description $description
        # No -Force: never overwrite an existing task.
        $registered=$true
        [void](Register-ScheduledTask -TaskName $taskName -TaskPath '\' -InputObject $definition -ErrorAction Stop)
        $r.task_registered=$true
        $deadline=[DateTime]::UtcNow.AddSeconds(120);$receiptPath=Join-Path $folder 'system-probe.json';$receipt=$null
        Write-Host 'Waiting for the timed SYSTEM probe (up to 120 seconds); network stays unchanged.'
        while ([DateTime]::UtcNow -lt $deadline) {
            if (Test-Path -LiteralPath $receiptPath) {
                try { $receipt=[IO.File]::ReadAllText($receiptPath) | ConvertFrom-Json;AssertProbeReceipt $receipt $id;break } catch { $receipt=$null }
            }
            Start-Sleep -Seconds 2
        }
        if ($null -eq $receipt) { throw 'system_probe_receipt_missing_or_invalid' }
        AssertProbeReceipt $receipt $id; $r.system_probe_receipt_verified=$true
        for ($n=0;$n -lt 10;$n++) {
            $info=Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\' -ErrorAction Stop
            if ($info.LastTaskResult -eq 0) { break };Start-Sleep -Seconds 1
        }
        $r.task_last_result=[long]$info.LastTaskResult
        if ($r.task_last_result -ne 0) { throw 'scheduled_probe_not_success' }
    } catch {
        $known=@('private_directory_exists','private_directory_invalid','private_acl_not_protected','untrusted_private_acl','private_worker_hash_mismatch','firewall_export_failed','firewall_export_empty','system_probe_receipt_missing_or_invalid','scheduled_probe_not_success','firewall_profiles_incomplete')
        $r.error_code='rehearsal_failed_no_network_settings_changed'
        if ($known -contains $_.Exception.Message) { $r.error_code=$_.Exception.Message }
    } finally {
        if ($registered) {
            try {
                $task=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
                if ($task.Description -cne $description -or @($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -cne $powershell -or $task.Actions[0].Arguments -cne $arguments) { throw 'owned_task_identity_changed' }
                Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
                $remaining=@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object { $_.TaskName -ceq $taskName })
                $r.owned_task_removed=($remaining.Count -eq 0)
                if (-not $r.owned_task_removed) { throw 'task_still_present' }
            } catch { $r.error_code='owned_probe_task_cleanup_not_confirmed' }
        }
        if ($null -ne $before) {
            try { $r.firewall_profile_summary_unchanged=((PolicySummary) -ceq $before) } catch { $r.firewall_profile_summary_unchanged=$null }
        }
        $r.ended_utc=[DateTime]::UtcNow.ToString('o')
    }
    $r.passed=($null -eq $r.error_code -and $r.firewall_backup_nonempty -and $r.system_probe_receipt_verified -and $r.owned_task_removed -and $r.firewall_profile_summary_unchanged -eq $true)
    $output=Join-Path $PSScriptRoot 'output'
    if (Test-Path -LiteralPath $output) {
        if (((Get-Item -LiteralPath $output).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'output_reparse_point_refused' }
    } else { [void](New-Item -ItemType Directory -Path $output) }
    $report=Join-Path $output ('s2-rehearsal-to-share-'+$id+'.json')
    [IO.File]::WriteAllText($report,($r | ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)))
    Write-Host ('SHARE ONLY: '+$report)
    Write-Host ('PRIVATE backup folder - do NOT upload: '+$folder)
    Write-Host ('Rehearsal passed: '+$r.passed)
    Write-Host 'This does NOT prove firewall import/recovery and does NOT authorize isolation or Resume.'
    if (-not $r.passed) { exit 1 }
}
if ($SelfTest) { SelfTests | ConvertTo-Json -Depth 8;exit 0 }
try { Rehearse } catch {
    $code='rehearsal_stopped_no_network_settings_changed'
    if ($_.Exception.Message -in @('run_as_administrator','worker_hash_mismatch','scheduler_not_running','output_reparse_point_refused')) { $code=$_.Exception.Message }
    Write-Host ('STOP: '+$code);exit 1
}
