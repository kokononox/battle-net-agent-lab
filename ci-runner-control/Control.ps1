[CmdletBinding()]
param([ValidateSet('Arm','Cleanup','Timer')][string]$Mode='Arm',[string]$PrivateDir)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$isSystem=([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18')
if ($Mode -eq 'Timer') { if (-not $isSystem) { throw 'ci_control_system_required' } }
elseif ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REPOSITORY -ne 'kokononox/battle-net-agent-lab') { throw 'ci_control_hosted_ci_only' }
$core=Join-Path $PSScriptRoot 'Core.ps1'
if (-not (Test-Path -LiteralPath $core)) { $core=Join-Path (Split-Path $PSScriptRoot -Parent) 'sstp-unset-s3u\Core.ps1' }
. $core
function HostAddress([string]$Value) {
    $bits=$Value -split '/';if ($bits.Count -gt 2) { throw 'ci_control_address' }
    $ip=$null;if (-not [Net.IPAddress]::TryParse($bits[0],[ref]$ip)) { throw 'ci_control_address' }
    $v4=($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork)
    if ($bits.Count -eq 2 -and $bits[1] -cne $(if($v4){'32'}else{'128'})) { throw 'ci_control_address' }
    if ([Net.IPAddress]::IsLoopback($ip) -or $ip.Equals([Net.IPAddress]::Any) -or $ip.Equals([Net.IPAddress]::IPv6Any) -or $ip.IsIPv6Multicast -or $ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal) { throw 'ci_control_address' }
    if ($ip.IsIPv4MappedToIPv6) { throw 'ci_control_address' }
    if ($v4) { $b=$ip.GetAddressBytes();if ($b[0] -eq 0 -or $b[0] -ge 224 -or ($b[0] -eq 169 -and $b[1] -eq 254)) { throw 'ci_control_address' } }
    return $ip.ToString()
}
function StableExecutable([string]$Path,[string]$Leaf) {
    $f=Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($f.PSIsContainer -or $f.Name -cne $Leaf -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'ci_control_binary_identity' }
    $parent=$f.Directory
    while ($null -ne $parent) { if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'ci_control_binary_reparse' };$parent=$parent.Parent }
    return [string](Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}
function CheckRule($Rule,$Spec,[string]$Group) {
    if ($Rule.Name -cne $Spec.name -or $Rule.Group -cne $Group -or $Rule.Description -cne $Group -or [string]$Rule.Enabled -cne 'True' -or [string]$Rule.Direction -cne 'Outbound' -or [string]$Rule.Action -cne 'Allow' -or [string]$Rule.Profile -cne 'Any' -or [string]$Rule.EdgeTraversalPolicy -cne 'Block') { throw 'ci_control_rule_identity' }
    $app=$Rule | Get-NetFirewallApplicationFilter
    $port=$Rule | Get-NetFirewallPortFilter
    $addr=$Rule | Get-NetFirewallAddressFilter
    $svc=$Rule | Get-NetFirewallServiceFilter
    if ($app.Program -ine $Spec.program -or [string]$svc.Service -ine 'Any' -or [string]$port.Protocol -notin @('TCP','6') -or (@($port.RemotePort) -join ',') -cne '443' -or (@($port.LocalPort) -join ',') -cne 'Any' -or (@($addr.LocalAddress) -join ',') -cne 'Any') { throw 'ci_control_rule_filters' }
    $actual=@($addr.RemoteAddress | ForEach-Object { HostAddress ([string]$_) } | Sort-Object -Unique)
    if (($actual -join ',') -cne (@($Spec.addresses | Sort-Object -Unique) -join ',')) { throw 'ci_control_rule_addresses' }
}
function EmitReceipt($Receipt) {
    $path=Join-Path (Split-Path $PSScriptRoot -Parent) 'sstp-unset-s3u\ci-control-receipt.json'
    [IO.File]::WriteAllText($path,($Receipt | ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)))
}
function AssertManifest($J,[string]$Dir) {
    AssertPrivateDirectory $Dir
    if ($J.schema -cne 'ci-control-private-1' -or $J.session_id -cnotmatch '^[a-f0-9]{32}$' -or (Split-Path $Dir -Leaf) -cne ('Retail-CI-Control-'+$J.session_id) -or $J.group -cne ('S3U-CI-Control-'+$J.session_id) -or $J.source_commit -cnotmatch '^[a-f0-9]{40}$' -or $J.run_id -cnotmatch '^[0-9]{1,30}$') { throw 'ci_control_manifest_identity' }
    if ([DateTimeOffset]::Parse($J.created_utc) -lt [DateTimeOffset]::UtcNow.AddMinutes(-12)) { throw 'ci_control_manifest_stale' }
    if (@($J.specs).Count -ne 2) { throw 'ci_control_manifest_specs' }
    for ($i=0;$i -lt 2;$i++) {
        $s=$J.specs[$i];$leaf=@('Runner.Listener.exe','Runner.Worker.exe')[$i]
        if ($s.name -cne ($J.group+'-'+$i) -or (StableExecutable $s.program $leaf) -cne $s.sha256 -or @($s.addresses).Count -lt 1 -or @($s.addresses).Count -gt 16) { throw 'ci_control_manifest_specs' }
        foreach ($ip in $s.addresses) { if ((HostAddress $ip) -cne $ip) { throw 'ci_control_address' } }
    }
    if ([string](Get-FileHash -LiteralPath (Join-Path $Dir 'Control.ps1') -Algorithm SHA256).Hash -cne $J.helper_hash -or [string](Get-FileHash -LiteralPath (Join-Path $Dir 'Core.ps1') -Algorithm SHA256).Hash -cne $J.core_hash) { throw 'ci_control_helper_changed' }
}
if ($Mode -eq 'Arm') {
    $r=[ordered]@{schema='sstp-ci-control-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;setup_succeeded=$false;cleanup_attempted=$false;cleanup_succeeded=$false;independent_cleanup_armed=$false;timer_fallback_used=$false;program_count=0;remote_address_count=0;rules_created=0;rules_removed=0;remaining_rules=0;profiles_exact=$false;selected_rules_exact=$false;cleanup_task_removed=$false;fixture_checks=0;error_code=$null;fixture_only=$true;user_device_tested=$false;ready_for_user_apply=$false}
    try {
        if ((HostAddress '192.0.2.1/32') -cne '192.0.2.1') { throw 'ci_control_fixture' };$r.fixture_checks++
        foreach ($bad in @('Any','0.0.0.0','127.0.0.1','192.0.2.1/24','::','fe80::1')) { $rejected=$false;try { [void](HostAddress $bad) } catch { $rejected=$true };if (-not $rejected) { throw 'ci_control_fixture' };$r.fixture_checks++ }
        $before=ProfileSnapshot
        if (@($before).Count -ne 3 -or @($before | Where-Object { $_.outbound -cne 'NotConfigured' }).Count -ne 0) { throw 'ci_control_baseline' }
        $specs=@();$bin=$null;$id=[Guid]::NewGuid().ToString('N');$group='S3U-CI-Control-'+$id
        for ($i=0;$i -lt 2;$i++) {
            $name=@('Runner.Listener','Runner.Worker')[$i];$procs=@(Get-Process -Name $name -ErrorAction Stop)
            if ($procs.Count -ne 1) { throw 'ci_control_process_not_unique' }
            $proc=$procs[0];$exe=$proc.Path;$hash=StableExecutable $exe ($name+'.exe');$dir=Split-Path $exe -Parent
            if ($null -ne $bin -and $dir -ine $bin) { throw 'ci_control_binary_root' };$bin=$dir
            $connections=@()
            for ($attempt=0;$attempt -lt 5;$attempt++) {
                $connections=@(Get-NetTCPConnection -OwningProcess $proc.Id -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemotePort -eq 443 })
                if ($connections.Count -gt 0) { break };Start-Sleep -Seconds 2
            }
            $ips=@($connections | ForEach-Object { HostAddress ([string]$_.RemoteAddress) } | Sort-Object -Unique)
            if ($ips.Count -lt 1 -or $ips.Count -gt 16) { throw 'ci_control_endpoint_count' }
            if ((StableExecutable $exe ($name+'.exe')) -cne $hash -or $proc.HasExited) { throw 'ci_control_binary_changed' }
            $specs+=,[ordered]@{name=($group+'-'+$i);program=$exe;sha256=$hash;addresses=$ips}
        }
        if (@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Group -ceq $group }).Count -ne 0) { throw 'ci_control_group_exists' }
        $r.program_count=2;$r.remote_address_count=@($specs | ForEach-Object { $_.addresses } | Sort-Object -Unique).Count
        $folder=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('Retail-CI-Control-'+$id)
        CreatePrivateDirectory $folder
        [IO.File]::WriteAllBytes((Join-Path $folder 'Control.ps1'),[IO.File]::ReadAllBytes($PSCommandPath))
        [IO.File]::WriteAllBytes((Join-Path $folder 'Core.ps1'),[IO.File]::ReadAllBytes($core))
        $taskName=$group;$ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $taskArgs='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $folder 'Control.ps1')+'" -Mode Timer -PrivateDir "'+$folder+'"'
        $j=[ordered]@{schema='ci-control-private-1';session_id=$id;source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;created_utc=[DateTime]::UtcNow.ToString('o');group=$group;specs=$specs;before_profiles=($before | ConvertTo-Json -Compress);before_effective=(EffectiveProfileSnapshot);before_rules=(RulePropertyDigest);task_name=$taskName;task_args=$taskArgs;task_exe=$ps;helper_hash=[string](Get-FileHash (Join-Path $folder 'Control.ps1') -Algorithm SHA256).Hash;core_hash=[string](Get-FileHash (Join-Path $folder 'Core.ps1') -Algorithm SHA256).Hash}
        WriteNewJson (Join-Path $folder 'manifest.json') $j
        [IO.File]::WriteAllText((Join-Path $env:RUNNER_TEMP 'ci-control-private-pointer.json'),(@{folder=$folder} | ConvertTo-Json -Compress))
        $action=New-ScheduledTaskAction -Execute $ps -Argument $taskArgs
        $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(7)
        $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
        $principal=New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        [void](Register-ScheduledTask -TaskName $taskName -TaskPath '\' -InputObject (New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $group) -ErrorAction Stop)
        $task=Get-ScheduledTask -TaskName $taskName -TaskPath '\'
        if ($task.Description -cne $group -or @($task.Actions).Count -ne 1 -or $task.Actions[0].Arguments -cne $taskArgs -or $task.Actions[0].Execute -ine $ps -or $task.Principal.UserId -notin @('SYSTEM','S-1-5-18')) { throw 'ci_control_task_identity' }
        $r.independent_cleanup_armed=$true
        foreach ($spec in $specs) {
            $rule=New-NetFirewallRule -PolicyStore PersistentStore -Name $spec.name -DisplayName $spec.name -Group $group -Description $group -Direction Outbound -Action Allow -Enabled True -Profile Any -Program $spec.program -Protocol TCP -RemotePort 443 -RemoteAddress $spec.addresses -EdgeTraversalPolicy Block -ErrorAction Stop
            $r.rules_created++;CheckRule $rule $spec $group
        }
        $r.setup_succeeded=$true
    } catch { $r.error_code='ci_control_setup_failed';if ($_.Exception.Message -cmatch '^ci_control_[a-z_]{1,80}$') { $r.error_code=$_.Exception.Message } }
    finally { EmitReceipt $r }
    if (-not $r.setup_succeeded) { exit 1 };exit 0
}
# Cleanup reads only this fixture's protected journal and removes only exact owned rules.
$r=$null;$j=$null;$cleanupLock=$null
try {
    if ($Mode -eq 'Cleanup') {
        $receipt=Join-Path (Split-Path $PSScriptRoot -Parent) 'sstp-unset-s3u\ci-control-receipt.json'
        $r=[IO.File]::ReadAllText($receipt) | ConvertFrom-Json;$r.cleanup_attempted=$true
        $pointer=Join-Path $env:RUNNER_TEMP 'ci-control-private-pointer.json'
        if (-not (Test-Path -LiteralPath $pointer)) { throw 'ci_control_no_mutation_journal' }
        $PrivateDir=([IO.File]::ReadAllText($pointer) | ConvertFrom-Json).folder
    }
    AssertPrivateDirectory $PrivateDir
    $cleanupLock=AcquireSessionLock $PrivateDir
    $mf=Get-Item -LiteralPath (Join-Path $PrivateDir 'manifest.json')
    if ($mf.Length -gt 65536 -or ($mf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'ci_control_manifest_file' }
    $j=[IO.File]::ReadAllText($mf.FullName) | ConvertFrom-Json;AssertManifest $j $PrivateDir
    if ($Mode -eq 'Cleanup' -and ($j.source_commit -cne $env:GITHUB_SHA -or $j.run_id -cne $env:GITHUB_RUN_ID)) { throw 'ci_control_current_identity' }
    $removed=0
    foreach ($spec in $j.specs) {
        $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name $spec.name -ErrorAction SilentlyContinue)
        if ($rules.Count -gt 1) { throw 'ci_control_rule_not_unique' }
        foreach ($rule in $rules) { CheckRule $rule $spec $j.group;Remove-NetFirewallRule -InputObject $rule -Confirm:$false -ErrorAction Stop;$removed++ }
    }
    $remaining=@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Group -ceq $j.group }).Count
    if ($remaining -ne 0) { throw 'ci_control_rules_remaining' }
    $task=@(Get-ScheduledTask -TaskName $j.task_name -TaskPath '\' -ErrorAction SilentlyContinue)
    if ($task.Count -gt 1) { throw 'ci_control_task_identity' }
    foreach ($t in $task) {
        if ($t.Description -cne $j.group -or @($t.Actions).Count -ne 1 -or $t.Actions[0].Arguments -cne $j.task_args -or $t.Actions[0].Execute -ine $j.task_exe -or $t.Principal.UserId -notin @('SYSTEM','S-1-5-18')) { throw 'ci_control_task_identity' }
        Unregister-ScheduledTask -TaskName $j.task_name -TaskPath '\' -Confirm:$false -ErrorAction Stop
    }
    $taskGone=(@(Get-ScheduledTask -TaskName $j.task_name -TaskPath '\' -ErrorAction SilentlyContinue).Count -eq 0)
    $profilesExact=((((ProfileSnapshot) | ConvertTo-Json -Compress) -ceq $j.before_profiles) -and (EffectiveProfileSnapshot) -ceq $j.before_effective)
    $rulesExact=((RulePropertyDigest) -ceq $j.before_rules)
    if ($Mode -eq 'Timer') {
        WriteNewJson (Join-Path $PrivateDir 'timer-cleanup.json') ([ordered]@{removed=$removed;remaining=$remaining;profiles_exact=$profilesExact;selected_rules_exact=$rulesExact;task_removed=$taskGone})
    } else {
        $r.rules_removed=$removed;$r.remaining_rules=$remaining;$r.profiles_exact=$profilesExact;$r.selected_rules_exact=$rulesExact;$r.cleanup_task_removed=$taskGone
        $r.timer_fallback_used=(Test-Path -LiteralPath (Join-Path $PrivateDir 'timer-cleanup.json'))
        $r.cleanup_succeeded=($profilesExact -and $rulesExact -and $taskGone -and -not $r.timer_fallback_used)
        if (-not $r.cleanup_succeeded) { throw 'ci_control_cleanup_not_exact' }
    }
} catch {
    if ($null -ne $r) { $r.error_code='ci_control_cleanup_failed';if ($_.Exception.Message -cmatch '^ci_control_[a-z_]{1,80}$') { $r.error_code=$_.Exception.Message } }
    if ($Mode -eq 'Timer') { exit 2 }
} finally { if ($null -ne $cleanupLock) { $cleanupLock.Dispose() };if ($null -ne $r) { EmitReceipt $r } }
if ($Mode -eq 'Cleanup' -and ($null -eq $r -or -not $r.cleanup_succeeded)) { exit 1 }
