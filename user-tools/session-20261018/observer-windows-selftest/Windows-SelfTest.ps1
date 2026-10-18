# Tests only generated files under this package; never discovers real logs.
[CmdletBinding()]
param([switch]$DeveloperLinuxModel)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT' -and -not $DeveloperLinuxModel) {
    Write-Host 'Windows only. No files were opened or changed.'
    exit 1
}
if ($env:OS -eq 'Windows_NT' -and $DeveloperLinuxModel) {
    Write-Host 'Do not use the Linux model flag on Windows.'
    exit 1
}
$coreFile=Join-Path $PSScriptRoot 'Observer-Core-1.2.ps1'
if ((Get-FileHash -LiteralPath $coreFile -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'acd9d4d562fb193c95de10e204cefeb92720baa2143879c47813b4b34251f6d5') {
    Write-Host 'Core file does not match the tested version. Extract a fresh package. Do NOT update.'
    exit 1
}
. $coreFile -LibraryOnly
# The Linux development model stabilizes CreationTime only. Windows uses real
# discovery, FileInfo, timestamps, handles, decoding and reads without mocks.
if ($DeveloperLinuxModel) {
    $script:originalDiscovery=${function:Get-AllowedLogFiles}
    $script:creationMap=@{}
    function Get-AllowedLogFiles([string[]]$Roots,[hashtable]$Stats) {
        foreach ($f in @(& $script:originalDiscovery $Roots $Stats)) {
            if (-not $script:creationMap.ContainsKey($f.FullName)) { $script:creationMap[$f.FullName]=$f.CreationTimeUtc }
            [pscustomobject]@{FullName=$f.FullName; Length=$f.Length; CreationTimeUtc=$script:creationMap[$f.FullName]}
        }
    }
}

$run=Join-Path $PSScriptRoot ('SelfTest-Results\run-'+[Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $run)
$fixtures=Join-Path $run 'generated-fixtures'
[void](New-Item -ItemType Directory -Path $fixtures)
$script:checks=New-Object System.Collections.ArrayList
$script:phase='initialization'; $errorType=$null
$utf8=New-Object Text.UTF8Encoding($false)
function Check([bool]$Condition,[string]$Name) {
    $status='passed'; if (-not $Condition) { $status='failed' }
    [void]$script:checks.Add([ordered]@{name=$Name;status=$status})
    Write-Host ($status.ToUpper()+': '+$Name)
    if (-not $Condition) { throw 'selftest_assertion_failed' }
}
function New-FixtureRoot([string]$Name) {
    $p=Join-Path $fixtures $Name
    [void](New-Item -ItemType Directory -Path $p)
    $p
}
Write-Host 'Observer self-test: synthetic files only. Do NOT start a game update.'
Write-Host 'No game path is needed. Battle.net can remain paused.'
$stream=$null
try {
    $script:phase='version_fixture'
    $root=New-FixtureRoot 'version'
    $path=Join-Path $root '.build.info'
    [IO.File]::WriteAllText($path,"Product!STRING:0|Version!STRING:0|Account!STRING:0`nwow|12.1.0.69933|FAKE_PRIVATE_MARKER`nwow_classic_era|1.15.9.69722|FAKE_PRIVATE_MARKER`n",$utf8)
    $beforeHash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    $v=Get-VersionSnapshot $root
    Check ($v.retail_versions.Count -eq 1 -and $v.retail_versions[0] -eq '12.1.0.69933') 'synthetic_retail_version'
    Check (($v|ConvertTo-Json -Depth 5) -notmatch 'FAKE_PRIVATE_MARKER|Account') 'version_projection_excludes_unrelated_fields'
    Check ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -eq $beforeHash) 'synthetic_build_info_unchanged'

    $script:phase='appended_log_read'
    $logs=New-FixtureRoot 'live-log'
    $log=Join-Path $logs 'Agent.log'
    [IO.File]::WriteAllText($log,"historical error`n",$utf8)
    $states=@{}; $stats=New-Stats
    Read-Pass @($logs) $states $stats $true
    Check ($stats.files_observed -eq 1 -and $stats.bytes_read -eq 0 -and $stats.keywords.error -eq 0) 'baseline_skips_history'
    [IO.File]::AppendAllText($log,"boundary line`nupdate`ndownload`n",$utf8)
    Read-Pass @($logs) $states $stats $false
    Check ($stats.appended_data_seen -and $stats.bytes_read -gt 0 -and $stats.keywords.update -eq 1 -and $stats.keywords.download -eq 1 -and $stats.keywords.error -eq 0 -and $stats.read_errors -eq 0) 'real_file_appends_counted'
    # This is a known limitation, not a completeness claim: the core deliberately
    # drops the first line after a nonempty baseline.
    Check ($stats.lines_examined -eq 2) 'known_first_baseline_line_skip_accounted_for'

    $script:phase='partial_line'
    [IO.File]::AppendAllText($log,'downlo',$utf8)
    Read-Pass @($logs) $states $stats $false
    Check ($stats.keywords.download -eq 1) 'incomplete_line_held'
    [IO.File]::AppendAllText($log,"ad`n",$utf8)
    Read-Pass @($logs) $states $stats $false
    Check ($stats.keywords.download -eq 2) 'split_line_completed_once'

    $script:phase='writer_handle_sharing'
    $stream=[IO.File]::Open($log,[IO.FileMode]::Open,[IO.FileAccess]::Write,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    [void]$stream.Seek(0,[IO.SeekOrigin]::End)
    $bytes=$utf8.GetBytes("patch`nFAKE_PRIVATE_MARKER auth`n")
    $stream.Write($bytes,0,$bytes.Length); $stream.Flush()
    Read-Pass @($logs) $states $stats $false
    Check ($stats.keywords.patch -eq 1 -and $stats.keywords.auth -eq 1 -and $stats.read_errors -eq 0) 'read_while_writer_handle_open'
    $stream.Dispose(); $stream=$null

    $script:phase='truncation'
    [IO.File]::WriteAllText($log,"repair`n",$utf8)
    Read-Pass @($logs) $states $stats $false
    Check ($stats.resets -ge 1 -and $stats.keywords.repair -eq 1) 'shorter_file_reset'

    $script:phase='utf16'
    $logs16=New-FixtureRoot 'utf16'
    $l16=Join-Path $logs16 'Agent.log'
    [IO.File]::WriteAllText($l16,"verify`nerror`n",[Text.Encoding]::Unicode)
    $s16=New-Stats; $st16=@{}; Read-Pass @($logs16) $st16 $s16 $false
    Check ($s16.keywords.verify -eq 1 -and $s16.keywords.error -eq 1 -and $s16.read_errors -eq 0) 'utf16_bom'

    $script:phase='line_length_limit'
    [IO.File]::AppendAllText($l16,(('x'*4200)+"error`n"),[Text.Encoding]::Unicode)
    Read-Pass @($logs16) $st16 $s16 $false
    Check ($s16.discarded_long_lines -eq 1 -and $s16.keywords.error -eq 1) 'oversized_line_dropped'

    $script:phase='read_budget'
    $s16.bytes_read=33554432
    $oldOffset=$st16[$l16].offset
    [IO.File]::AppendAllText($l16,"patch`n",[Text.Encoding]::Unicode)
    Read-Pass @($logs16) $st16 $s16 $false
    Check ($s16.budget_reached -and $st16[$l16].offset -eq $oldOffset) 'global_read_budget_stops_reads'

    $script:phase='json_roundtrip'
    $projection=[ordered]@{before=$v;log_statistics=$stats}
    $json=$projection|ConvertTo-Json -Depth 12
    Check ($json -notmatch 'FAKE_PRIVATE_MARKER' -and $json -notmatch [regex]::Escape($fixtures)) 'projection_contains_no_fixture_text_or_path'
    $saved=Join-Path $run 'synthetic-projection.json'
    [IO.File]::WriteAllText($saved,$json,$utf8)
    $loaded=[IO.File]::ReadAllText($saved)|ConvertFrom-Json
    Check ($loaded.log_statistics.keywords.patch -eq 1 -and $loaded.before.retail_versions[0] -eq '12.1.0.69933') 'json_saved_and_reloaded'
    Check ($stats.read_errors -eq 0 -and $stats.discovery_errors -eq 0 -and -not $stats.discovery_limited) 'no_unexpected_io_errors_in_generated_fixture'
    $script:phase='complete'
} catch {
    $errorType=$_.Exception.GetType().Name
    if ($errorType -notmatch '^[A-Za-z0-9_]{1,80}$') { $errorType='Exception' }
    Write-Host ('SELF-TEST STOPPED at '+$script:phase+'. No update was requested.')
} finally {
    if ($null -ne $stream) { $stream.Dispose() }
}
$passed=@($script:checks | Where-Object {$_.status -eq 'passed'}).Count
$allPassed=($script:phase -eq 'complete' -and $passed -eq 16)
$platform='Windows'; if ($DeveloperLinuxModel) { $platform='Linux_developer_creationtime_model_NOT_Windows' }
$coreHash=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'Observer-Core-1.2.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()
$report=[ordered]@{
    schema='observer-synthetic-windows-selftest-1'; core_version='1.2'; core_sha256=$coreHash;
    platform=$platform; powershell_version=$PSVersionTable.PSVersion.ToString();
    all_passed=$allPassed; checks_passed=$passed; checks_expected=16; last_phase=$script:phase;
    error_type=$errorType; checks=@($script:checks.ToArray());
    scope='generated_files_only_no_game_or_real_logs';
    real_log_discovery_called=$false; game_path_requested=$false; network_requested=$false;
    update_requested=$false; installation_modified=$false;
    not_proven=@('real_BattleNet_log_writes','all_update_stages_captured','log_rotation_without_loss','complete_update_algorithm','atomic_or_crash_safe_report_save','rollback','real_update_success');
    known_limitations=@('The core skips the first line after a nonempty baseline.',
      'Keyword counters are not raw events, exact patch evidence or operation success.',
      'The main observer saves at normal stop; closing it prematurely can lose the report.',
      'A passed synthetic test is NOT approval to start a real update.')
}
$output=Join-Path $run 'SELFTEST-to-share.json'
[IO.File]::WriteAllText($output,($report|ConvertTo-Json -Depth 12),$utf8)
if ($allPassed) { Write-Host 'SELFTEST PASSED - synthetic IO only. Do NOT start Update yet.' }
else { Write-Host 'SELFTEST NOT PASSED - do NOT start Update.' }
Write-Host ('Report: '+$output)
Write-Host 'Share SELFTEST-to-share.json only. Generated fixtures can remain where they are.'
if (-not $allPassed) { exit 1 }
