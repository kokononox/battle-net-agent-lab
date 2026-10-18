[CmdletBinding()]
param([switch]$LibraryOnly)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Get-WindowStamp([string]$Line,[datetime]$WindowStart,[datetime]$WindowEnd,[TimeZoneInfo]$LocalZone) {
    $prefix=$Line.Substring(0,[Math]::Min(96,$Line.Length))
    $m=[regex]::Match($prefix,'(?<stamp>20\d{2}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,7})?)(?<zone>Z|[+-]\d{2}:?\d{2})?')
    if (-not $m.Success) { return $null }
    try {
        $stamp=$m.Groups['stamp'].Value.Replace(',','.')
        $zone=$m.Groups['zone'].Value
        if ($zone) {
            $dto=[DateTimeOffset]::Parse(($stamp+$zone),[Globalization.CultureInfo]::InvariantCulture)
            $utc=$dto.UtcDateTime
            if ($utc -ge $WindowStart -and $utc -le $WindowEnd) { return @{utc=$utc;basis='explicit_offset'} }
            return $null
        }
        $dt=[datetime]::ParseExact($stamp.Replace('T',' '),[string[]]@('yyyy-MM-dd HH:mm:ss','yyyy-MM-dd HH:mm:ss.FFFFFFF'),[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None)
        $dt=[datetime]::SpecifyKind($dt,[DateTimeKind]::Unspecified)
        $candidates=New-Object System.Collections.ArrayList
        $u=[datetime]::SpecifyKind($dt,[DateTimeKind]::Utc)
        if ($u -ge $WindowStart -and $u -le $WindowEnd) { [void]$candidates.Add(@{utc=$u;basis='UTC_assumed_window_fit'}) }
        if (-not $LocalZone.IsInvalidTime($dt) -and -not $LocalZone.IsAmbiguousTime($dt)) {
            $u=[TimeZoneInfo]::ConvertTimeToUtc($dt,$LocalZone)
            if ($u -ge $WindowStart -and $u -le $WindowEnd) {
                if (@($candidates|Where-Object {$_.utc.Ticks -eq $u.Ticks}).Count -eq 0) { [void]$candidates.Add(@{utc=$u;basis='OS_local_assumed_window_fit'}) }
            }
        }
        if ($candidates.Count -eq 1) { return $candidates[0] }
    } catch { return $null }
    $null
}

function Get-FixedMarkers([string]$Line) {
    # Fixed hints only, not a vendor state machine or proof of a game stage.
    $patterns=@{initialization_keyword='(?i)\binitializ\w*';
        download_keyword='(?i)\bdownload\w*'; patch_keyword='(?i)\bpatch\w*';
        update_keyword='(?i)\bupdat(?:e|es|ed|ing)\b';
        install_keyword='(?i)\binstall\w*'; verify_keyword='(?i)\bverif\w*';
        pause_keyword='(?i)\b(?:paus\w*|resum\w*|cancel\w*)';
        error_keyword='(?i)\b(?:error|failed|failure|fatal)\b'}
    foreach ($k in $patterns.Keys) { if ($Line -match $patterns[$k]) { $k } }
}

function Invoke-PausedReview {
    if ($env:OS -ne 'Windows_NT') { throw 'Windows is required. No logs were read.' }
    Write-Host 'Paused-run log review: keep the game update PAUSED. No Update/Resume/Repair is requested.'
    Write-Host 'Only bounded existing .log tails are read. No game path, login, raw-log export or upload.'
    $core=Join-Path $PSScriptRoot 'Observer-Core-1.2.ps1'
    $expected='acd9d4d562fb193c95de10e204cefeb92720baa2143879c47813b4b34251f6d5'
    if ((Get-FileHash -LiteralPath $core -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Core hash mismatch. Extract a fresh package.' }
    . $core -LibraryOnly
    $start=[datetime]::Parse('2026-10-18T17:44:36.1659425Z',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
    $finish=[datetime]::Parse('2026-10-18T17:52:27.1659425Z',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
    $discovery=New-Stats
    $stats=@{candidate_files=0;files_scanned=0;bytes_read=0L;tail_truncated_files=0;
        read_errors=0;long_lines_skipped=0;lines_examined=0;timestamp_window_matches=0;
        unmatched_keyword_lines=0;budget_reached=$false;short_reads=0}
    $summaries=@{}; $files=New-Object System.Collections.ArrayList
    $roles=@{agent=0;client_or_other=0}
    try {
        $roots=@(Get-LogRoots $discovery)
        $candidates=@(Get-AllowedLogFiles $roots $discovery | Where-Object { $_.LastWriteTimeUtc -ge $start.AddMinutes(-2) } | Sort-Object LastWriteTimeUtc -Descending)
        $stats.candidate_files=$candidates.Count
        foreach ($file in $candidates) {
            if ($stats.files_scanned -ge 32 -or $stats.bytes_read -ge 8388608-4) { $stats.budget_reached=$true; break }
            $stream=$null
            try {
                $stream=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
                $length=$stream.Length
                $bom=New-Object byte[] 3; $bn=$stream.Read($bom,0,3); $stats.bytes_read+=$bn
                $encoding=New-Object Text.UTF8Encoding($false,$false); $unit=1
                if ($bn -ge 2 -and $bom[0] -eq 255 -and $bom[1] -eq 254) { $encoding=[Text.Encoding]::Unicode; $unit=2 }
                elseif ($bn -ge 2 -and $bom[0] -eq 254 -and $bom[1] -eq 255) { $encoding=[Text.Encoding]::BigEndianUnicode; $unit=2 }
                $take=[long][Math]::Min(1048576,[Math]::Min($length,8388608-$stats.bytes_read))
                $offset=[Math]::Max(0,$length-$take)
                if ($unit -eq 2 -and $offset%2 -ne 0) { $offset++; $take-- }
                if ($offset -gt 0) { $stats.tail_truncated_files++ }
                [void]$stream.Seek($offset,[IO.SeekOrigin]::Begin)
                $buffer=New-Object byte[] ([int]$take); $used=0
                while ($used -lt $take) {
                    $n=$stream.Read($buffer,$used,([int]$take-$used)); if ($n -le 0) { break }; $used+=$n
                }
                $stats.bytes_read+=$used
                if ($used -lt $take) { $stats.short_reads++ }
                $text=$encoding.GetString($buffer,0,$used)
                if ($offset -gt 0) {
                    $nl=$text.IndexOf("`n")
                    if ($nl -lt 0) { $text='' } else { $text=$text.Substring($nl+1) }
                }
                $stats.files_scanned++
                $role='client_or_other'
                if ($file.FullName.Replace('\','/') -match '(?i)/Battle\.net/Agent/(?:Agent\.\d+/)?Logs/') { $role='agent' }
                $roles[$role]++
                $alias='log_'+$stats.files_scanned.ToString('D2')
                $matched=0
                foreach ($line in $text.Split("`n")) {
                    $stats.lines_examined++
                    if ($line.Length -gt 8192) { $stats.long_lines_skipped++; continue }
                    $markers=@(Get-FixedMarkers $line)
                    if ($markers.Count -eq 0) { continue }
                    $ts=Get-WindowStamp $line $start $finish ([TimeZoneInfo]::Local)
                    if ($null -eq $ts) { $stats.unmatched_keyword_lines++; continue }
                    $matched++; $stats.timestamp_window_matches++
                    $wow=($line -match '(?i)(?<![A-Za-z0-9_])wow(?![A-Za-z0-9_])')
                    foreach ($marker in $markers) {
                        if (-not $summaries.ContainsKey($marker)) {
                            $summaries[$marker]=@{matching_lines=0;wow_literal_lines=0;first_utc=$null;last_utc=$null;
                                explicit_offset_lines=0;assumed_timezone_lines=0;first_examples=(New-Object System.Collections.ArrayList)}
                        }
                        $sum=$summaries[$marker]; $sum.matching_lines++
                        if ($wow) { $sum.wow_literal_lines++ }
                        $iso=$ts.utc.ToString('o')
                        if ($null -eq $sum.first_utc -or $iso -lt $sum.first_utc) { $sum.first_utc=$iso }
                        if ($null -eq $sum.last_utc -or $iso -gt $sum.last_utc) { $sum.last_utc=$iso }
                        if ($ts.basis -eq 'explicit_offset') { $sum.explicit_offset_lines++ } else { $sum.assumed_timezone_lines++ }
                        if ($sum.first_examples.Count -lt 6) {
                            $codes=@([regex]::Matches($line,'\bBLZBNT(?:AGT|BNA|BGS)[0-9A-F]{8}\b') | Select-Object -First 3 | ForEach-Object {$_.Value})
                            [void]$sum.first_examples.Add([ordered]@{utc=$iso;time_basis=$ts.basis;log_alias=$alias;
                                role=$role;wow_literal=$wow;blizzard_code_hints=$codes})
                        }
                    }
                }
                [void]$files.Add([ordered]@{alias=$alias;role=$role;source_bytes_observed=$length;
                    tail_bytes_read=$used;tail_truncated=($offset -gt 0);window_keyword_lines=$matched})
            } catch { $stats.read_errors++ }
            finally { if ($null -ne $stream) { $stream.Dispose() } }
        }
    } catch { $stats.read_errors++ }
    $report=[ordered]@{
        schema='paused-run-log-review-1'; source_observer_version='1.2';
        requested_window_utc=[ordered]@{from=$start.ToString('o');to=$finish.ToString('o');source='previous_user_report_start_plus_duration_including_menus'};
        user_observation='Initializing passed; download near 3 percent; now Paused';
        statistics=$stats;discovery_limited=$discovery.discovery_limited;discovery_reasons=$discovery.discovery_reasons;
        discovery_errors=$discovery.discovery_errors;roles_scanned=$roles;files=@($files.ToArray());keyword_time_hints=$summaries;
        raw_log_exported=$false;game_files_read=$false;network_requested=$false;update_or_resume_requested=$false;
        limits=[ordered]@{total_read_bytes=8388608;per_file_tail_bytes=1048576;files=32;max_line_characters=8192};
        limitations=@('Keyword/time hints are NOT vendor stages, game attribution, operation success or full algorithm proof.',
            'wow_literal is only a word match; other Blizzard products and background events can be included.',
            'Timestamps must contain an ISO-like full date within the first 96 characters. Unsupported or ambiguous time lines are not attributed.',
            'Without an explicit offset, UTC and OS-local interpretations are tried; a unique window fit is an assumption, not proof of timezone.',
            'Historical tails are bounded and may exclude Initializing; zero matches does NOT prove absence.',
            'File modification time selects candidates only. It does not prove when their contents were written.',
            'Report duration included menu time. No exact Update-click or Pause-click timestamp was recorded.',
            'No raw text, filenames, paths, account values, hashes from logs, tokens or cookies are exported.',
            'No source snapshot is taken; concurrent writes/rotation can cause missed lines.',
            'The author has not executed this retrospective reader on native Windows.')
    }
    $dir=Join-Path $PSScriptRoot ('Results\run-'+[Guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $dir)
    $output=Join-Path $dir 'PAUSED-REVIEW-to-share.json'
    [IO.File]::WriteAllText($output,($report|ConvertTo-Json -Depth 15),(New-Object Text.UTF8Encoding($false)))
    Write-Host ('Read bytes: '+$stats.bytes_read+'; matching timestamped keyword lines: '+$stats.timestamp_window_matches)
    Write-Host ('Report: '+$output)
    Write-Host 'Keep the update PAUSED; share this JSON only, not the source logs.'
}
if (-not $LibraryOnly) { Invoke-PausedReview }
