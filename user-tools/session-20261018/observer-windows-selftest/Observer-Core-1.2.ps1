# Read-only observer. Compatible with Windows PowerShell 5.1.
[CmdletBinding()]
param([switch]$LibraryOnly)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-VersionSnapshot([string]$Root) {
    $versions = New-Object 'System.Collections.Generic.List[string]'
    $status = 'not_found'
    $candidates = @((Join-Path $Root '.build.info'), (Join-Path $Root '_retail_\.build.info'))
    foreach ($path in $candidates) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        try {
            if ((Get-Item -LiteralPath $path -Force).Length -gt 1048576) { $status = 'too_large'; continue }
            $lines = [IO.File]::ReadAllLines($path)
            if ($lines.Length -lt 2) { $status = 'unrecognized'; continue }
            $header = $lines[0].Split('|'); $vi = -1; $pi = -1
            for ($i=0; $i -lt $header.Length; $i++) {
                if ($header[$i] -match '^Version!') { $vi = $i }
                if ($header[$i] -match '^Product!') { $pi = $i }
            }
            $status = 'read'
            if ($vi -lt 0 -or $pi -lt 0) { $status = 'unrecognized'; continue }
            foreach ($line in $lines[1..($lines.Length-1)]) {
                $cells = $line.Split('|')
                if ($cells.Length -le [Math]::Max($vi,$pi)) { continue }
                # Export only Retail version numbers; never export paths, keys or raw text.
                if ($cells[$pi] -eq 'wow' -and $cells[$vi] -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,10}$') {
                    if (-not $versions.Contains($cells[$vi])) { $versions.Add($cells[$vi]) }
                }
            }
        } catch { $status = 'unreadable' }
    }
    [ordered]@{ build_info_status=$status; retail_versions=@($versions.ToArray()) }
}

function Get-LogRoots([hashtable]$Stats) {
    # Only explicit log directories: do not recurse through app caches/packages.
    $roots = New-Object 'System.Collections.Generic.List[string]'
    foreach ($base in @($env:ProgramData, $env:LOCALAPPDATA, $env:APPDATA)) {
        if ([string]::IsNullOrWhiteSpace($base)) { continue }
        foreach ($sub in @('Battle.net\Logs','Blizzard Entertainment\Logs','Battle.net\Agent\Logs')) {
            $p = Join-Path $base $sub
            if (Test-Path -LiteralPath $p -PathType Container) {
                if (-not $roots.Contains($p)) { $roots.Add($p) }
            }
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
        $agentRoot=Join-Path $env:ProgramData 'Battle.net\Agent'
        if (Test-Path -LiteralPath $agentRoot -PathType Container) {
            try {
                $ri=Get-Item -LiteralPath $agentRoot -Force -ErrorAction Stop
                if (($ri.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    $Stats.discovery_limited=$true; $Stats.discovery_reasons.root_reparse_skipped=$true
                } else {
                    $versions=0
                    foreach ($dir in (Get-ChildItem -LiteralPath $agentRoot -Directory -Filter 'Agent.*' -Force -ErrorAction Stop)) {
                        if ($dir.Name -notmatch '^Agent\.\d+$') { continue }
                        $versions++
                        if ($versions -gt 64) { $Stats.discovery_limited=$true; $Stats.discovery_reasons.agent_version_directory_limit=$true; break }
                        if (($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                            $Stats.discovery_limited=$true; $Stats.discovery_reasons.root_reparse_skipped=$true; continue
                        }
                        $p=Join-Path $dir.FullName 'Logs'
                        if ((Test-Path -LiteralPath $p -PathType Container) -and -not $roots.Contains($p)) { $roots.Add($p) }
                    }
                }
            } catch { $Stats.discovery_errors++ }
        }
    }
    @($roots.ToArray())
}

function Get-AllowedLogFiles([string[]]$Roots, [hashtable]$Stats) {
    $queue = New-Object System.Collections.Queue
    foreach ($r in $Roots) {
        try {
            $ri=Get-Item -LiteralPath $r -Force -ErrorAction Stop
            if (($ri.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $Stats.discovery_limited=$true; $Stats.discovery_reasons.root_reparse_skipped=$true; continue }
            $queue.Enqueue(@($r,0))
        } catch { $Stats.discovery_errors++ }
    }
    $seen=0; $dirs=0; $found=0
    while ($queue.Count -gt 0) {
        $entry = $queue.Dequeue(); $dirs++
        if ($dirs -gt 200) { $Stats.discovery_limited=$true; $Stats.discovery_reasons.directory_limit=$true; break }
        try {
            foreach ($item in (Get-ChildItem -LiteralPath $entry[0] -Force -ErrorAction Stop)) {
                $seen++
                if ($seen -gt 3000) { $Stats.discovery_limited=$true; $Stats.discovery_reasons.entry_limit=$true; return }
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                if ($item.PSIsContainer) {
                    if ($entry[1] -lt 2) { $queue.Enqueue(@($item.FullName,($entry[1]+1))) }
                } elseif ($item.Extension -eq '.log') {
                    $found++; if ($found -gt 256) { $Stats.discovery_limited=$true; $Stats.discovery_reasons.log_file_limit=$true; return }
                    $item
                }
            }
        } catch { $Stats.discovery_errors++ }
    }
}

function New-Stats {
    @{ bytes_read=0L; discovery_limited=$false; discovery_errors=0; read_errors=0;
       resets=0; discarded_long_lines=0; budget_reached=$false; files_observed=0;
       lines_examined=0; lines_with_keywords=0; appended_data_seen=$false; agent_log_files_observed=0; client_log_files_observed=0;
       discovery_reasons=@{ root_reparse_skipped=$false; directory_limit=$false;
           entry_limit=$false; log_file_limit=$false; state_limit=$false; agent_version_directory_limit=$false };
       keywords=@{ update=0; download=0; patch=0; install=0; verify=0; repair=0; error=0; auth=0 } }
}

function Add-LineStats([string]$Text, [hashtable]$Stats) {
    $Stats.lines_examined++
    $matched=$false
    $patterns=@{update='\bupdat(?:e|es|ed|ing)\b';download='\bdownload(?:s|ed|ing)?\b';
        patch='\bpatch(?:es|ed|ing)?\b';install='\binstall(?:s|ed|ing|ation)?\b';
        verify='\bverif(?:y|ied|ying|ication)\b';repair='\brepair(?:s|ed|ing)?\b';
        error='\b(?:error|failed|failure|fatal)\b';auth='\b(?:auth|authentication|login|logon)\b'}
    foreach ($k in $patterns.Keys) {
        if ($Text -match $patterns[$k]) { $Stats.keywords[$k]++; $matched=$true }
    }
    if ($matched) { $Stats.lines_with_keywords++ }
}

function New-TailState($File, [bool]$Baseline) {
    $offset=0L; if ($Baseline) { $offset=[long]$File.Length }
    # Probe only the BOM, not historical log content. Count these bytes in Read-Pass.
    @{ offset=$offset; creation=$File.CreationTimeUtc.Ticks; decoder=$null;
       carry=''; dropping=$false; read=0L; skip_first=$Baseline -and $offset -gt 0 }
}

function Read-Pass([string[]]$Roots, [hashtable]$States, [hashtable]$Stats, [bool]$Baseline) {
    $passBytes=0L
    foreach ($file in @(Get-AllowedLogFiles $Roots $Stats)) {
        $key=$file.FullName
        if (-not $States.ContainsKey($key)) {
            if ($States.Count -ge 256) { $Stats.discovery_limited=$true; $Stats.discovery_reasons.state_limit=$true; continue }
            $States[$key]=New-TailState $file $Baseline
            $Stats.files_observed=$States.Count
            $normalized=$key.Replace('\','/')
            if ($normalized -match '(?i)/Battle\.net/Agent/(?:Agent\.\d+/)?Logs/') { $Stats.agent_log_files_observed++ }
            else { $Stats.client_log_files_observed++ }
        }
        $st=$States[$key]
        if ($file.Length -lt $st.offset -or $file.CreationTimeUtc.Ticks -ne $st.creation) {
            $States[$key]=New-TailState $file $false; $st=$States[$key]; $Stats.resets++
        }
        if ($Baseline) { continue }
        if ($Stats.bytes_read -ge 33554432) { $Stats.budget_reached=$true; break }
        if ($passBytes -ge 1048576) { break }
        if ($st.read -ge 4194304) { $Stats.budget_reached=$true; continue }
        if ($file.Length -le $st.offset) { continue }
        $Stats.appended_data_seen=$true
        $stream=$null
        try {
            $stream=[IO.File]::Open($key,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            if ($null -eq $st.decoder) {
                $bom=New-Object byte[] 3
                $bomLimit=[int][Math]::Min(3,[Math]::Min(33554432-$Stats.bytes_read,[Math]::Min(1048576-$passBytes,4194304-$st.read)))
                if ($bomLimit -le 0) { $Stats.budget_reached=$true; continue }
                $n=$stream.Read($bom,0,$bomLimit)
                $Stats.bytes_read+=$n; $passBytes+=$n; $st.read+=$n
                $encoding=New-Object Text.UTF8Encoding($false,$false); $bomLen=0
                if ($n -ge 2 -and $bom[0] -eq 255 -and $bom[1] -eq 254) { $encoding=[Text.Encoding]::Unicode; $bomLen=2 }
                elseif ($n -ge 2 -and $bom[0] -eq 254 -and $bom[1] -eq 255) { $encoding=[Text.Encoding]::BigEndianUnicode; $bomLen=2 }
                elseif ($n -eq 3 -and $bom[0] -eq 239 -and $bom[1] -eq 187 -and $bom[2] -eq 191) { $bomLen=3 }
                $st.decoder=$encoding.GetDecoder()
                if ($st.offset -eq 0) { $st.offset=$bomLen }
            }
            [void]$stream.Seek($st.offset,[IO.SeekOrigin]::Begin)
            $limit=[int][Math]::Min(65536,[Math]::Min(33554432-$Stats.bytes_read,[Math]::Min(1048576-$passBytes,4194304-$st.read)))
            if ($limit -le 0) { $Stats.budget_reached=$true; continue }
            $buf=New-Object byte[] $limit; $n=$stream.Read($buf,0,$limit)
            $st.offset+=$n; $st.read+=$n; $Stats.bytes_read+=$n; $passBytes+=$n
            $chars=New-Object char[] ($n+2)
            $nc=$st.decoder.GetChars($buf,0,$n,$chars,0,$false)
            $text=New-Object string(,$chars); $text=$text.Substring(0,$nc)
            # Keep only one bounded unfinished line. No log text is exported.
            foreach ($c in $text.ToCharArray()) {
                if ($c -eq "`n") {
                    if (-not $st.skip_first -and -not $st.dropping) { Add-LineStats $st.carry $Stats }
                    $st.carry=''; $st.dropping=$false; $st.skip_first=$false
                } elseif (-not $st.dropping -and -not $st.skip_first) {
                    if ($st.carry.Length -ge 4096) { $st.carry=''; $st.dropping=$true; $Stats.discarded_long_lines++ }
                    else { $st.carry += $c }
                }
            }
        } catch { $Stats.read_errors++ }
        finally { if ($null -ne $stream) { $stream.Dispose() } }
    }
}

function Ask-Choice([string]$Prompt,[string[]]$Choices) {
    do { Write-Host $Prompt; for ($i=0;$i -lt $Choices.Length;$i++) { Write-Host ('  {0}. {1}' -f ($i+1),$Choices[$i]) }; $answer=Read-Host 'Number' }
    until ($answer -match '^\d+$' -and [int]$answer -ge 1 -and [int]$answer -le $Choices.Length)
    $Choices[([int]$answer)-1]
}

function Invoke-Observer {
    if ($env:OS -ne 'Windows_NT') { throw 'This tool is for Windows only.' }
    Write-Host 'Retail Update Observer v1.2 - no admin rights required.'
    Write-Host 'It never starts updates, signs in, changes game files, captures traffic or uploads data.'
    Write-Host 'It writes a local JSON report containing version numbers, your menu answers and keyword counts only.'
    Write-Host 'Keep Battle.net paused until the observer says READY. Close WoW first.'
    do {
        $root=(Read-Host 'WoW installation folder (the folder containing .build.info)').Trim().Trim('"')
        $valid=Test-Path -LiteralPath $root -PathType Container
        if (-not $valid) { Write-Host 'Folder not found. Try again.' }
    } until ($valid)
    $root=[IO.Path]::GetFullPath($root)
    $toolDir=[IO.Path]::GetFullPath($PSScriptRoot)
    if ($toolDir.Equals($root,[StringComparison]::OrdinalIgnoreCase) -or $toolDir.StartsWith(($root.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Extract this tool OUTSIDE the game folder, then run it again.'
    }
    $before=Get-VersionSnapshot $root
    Write-Host ('Retail versions found: '+($before.retail_versions -join ', '))
    if ($before.retail_versions.Count -eq 0) { Write-Host 'No Retail version detected. No files will be changed.'; if ((Ask-Choice 'Continue anyway?' @('No','Yes')) -eq 'No') { return } }
    $login=Ask-Choice 'Battle.net sign-in state (no account details):' @('signed_in','signed_out','unknown')
    $button=Ask-Choice 'Battle.net button before test:' @('Update','Play','Initializing','Other','unknown')
    [void](Read-Host 'Press Enter to start observation BEFORE clicking Update in Battle.net')
    $states=@{}; $stats=New-Stats; $roots=@(Get-LogRoots $stats)
    Read-Pass $roots $states $stats $true
    Write-Host ('Log files found: '+$stats.files_observed)
    if ($stats.discovery_limited) {
        $reasons=@($stats.discovery_reasons.Keys | Where-Object { $stats.discovery_reasons[$_] })
        Write-Host ('Discovery coverage limited: '+($reasons -join ', '))
        Write-Host 'For a diagnostic run, do NOT click Update; use check_only.'
    }
    if ($stats.files_observed -eq 0) {
        Write-Host 'WARNING: no default log files were found. This run may only capture version changes.'
        if ((Ask-Choice 'Continue with this limitation?' @('No','Yes')) -eq 'No') { return }
    }
    Write-Host ('Agent log files found: '+$stats.agent_log_files_observed)
    $preflightReady=($before.retail_versions.Count -gt 0 -and $stats.agent_log_files_observed -gt 0 -and -not $stats.discovery_limited -and $stats.discovery_errors -eq 0 -and $stats.read_errors -eq 0)
    if ($preflightReady) { Write-Host 'PREFLIGHT: READY (file discovery only; live log writes not yet proven)' }
    else { Write-Host 'PREFLIGHT: LIMITED - do NOT click Update. Use check_only and send report.json.' }
    $started=[DateTime]::UtcNow; $stopReason='user_stopped'; $samples=New-Object System.Collections.ArrayList
    if ($preflightReady) { Write-Host 'READY: manual Update is possible now if you choose. Keep sign-in state unchanged.' }
    Write-Host 'When finished (or on error), return here and press Q. Limit: 4 hours.'
    try {
        $nextSample=$started
        while ($true) {
            $roots=@(Get-LogRoots $stats)
            Read-Pass $roots $states $stats $false
            $now=[DateTime]::UtcNow
            if ($now -ge $nextSample) {
                $kw=@{}; foreach ($k in $stats.keywords.Keys) { $kw[$k]=$stats.keywords[$k] }
                [void]$samples.Add([ordered]@{ elapsed_seconds=[int]($now-$started).TotalSeconds; keyword_lines=$kw })
                $nextSample=$now.AddSeconds(30)
            }
            if ([Console]::KeyAvailable) { if ([Console]::ReadKey($true).Key -eq [ConsoleKey]::Q) { break } }
            if (($now-$started).TotalHours -ge 4) { $stopReason='time_limit'; break }
            if ($stats.bytes_read -ge 33554432) { $stopReason='read_budget'; break }
            Start-Sleep -Milliseconds 1000
        }
    } catch { $stopReason='observer_error' }
    $after=Get-VersionSnapshot $root
    $outcome=Ask-Choice 'What did YOU observe in Battle.net?' @('update_completed','error_shown','still_updating','check_only','cancelled','unknown')
    $afterButton=Ask-Choice 'Battle.net button now:' @('Update','Play','Initializing','Other','unknown')
    $report=[ordered]@{
        tool='RetailUpdateObserver'; tool_version='1.2'; schema_version=3; preflight_ready=$preflightReady; started_utc=$started.ToString('o');
        duration_seconds=[int]([DateTime]::UtcNow-$started).TotalSeconds; stop_reason=$stopReason;
        user_reported=[ordered]@{ sign_in=$login; button_before=$button; button_after=$afterButton; outcome=$outcome };
        before=$before; after=$after; log_statistics=$stats; samples=@($samples.ToArray());
        limitations=@('Keyword counts are hints, not proof of update stages or success.',
          'Counts may include other Blizzard products and background activity.',
          'Appended log data only, plus up to 3 BOM-probe bytes per opened log; first baseline line is skipped.',
          'Only .log files in explicit default Logs folders, with a bounded Agent-version lookup, are scanned. Other locations may be missed.',
          'No network capture, actual download-byte measurement, raw logs or account information.',
          'No Windows-native execution test was performed by the author.',
          'duration_seconds includes time answering the final menus; samples mark observation time.')
    }
    $outDir=Join-Path $PSScriptRoot ('reports\run-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,6))
    [void](New-Item -ItemType Directory -Path $outDir -Force)
    $output=Join-Path $outDir 'report.json'
    $json=$report | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText($output,$json,(New-Object Text.UTF8Encoding($false)))
    Write-Host ('Report saved locally: '+$output)
    Write-Host 'Review report.json before sharing. Share that file only, not Battle.net logs.'
}
if (-not $LibraryOnly) { Invoke-Observer }
