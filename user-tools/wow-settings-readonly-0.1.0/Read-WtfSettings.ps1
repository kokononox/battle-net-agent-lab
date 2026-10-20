param([switch]$FunctionsOnly)
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
function Get-ScopedWtfSettings {
    param([AllowEmptyString()][string]$Text)
    $keys = @('engineSurvey','engineSurveyPatch','telemetryWowPackage','telemetryWowlabsPackage','shop2ClientErrorTelemetryAllowed','shop2TelemetryAllowed','optOutIngameSurveys')
    $found = @{}
    foreach ($k in $keys) { $found[$k] = New-Object 'System.Collections.Generic.List[object]' }
    $reader = New-Object System.IO.StringReader($Text)
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            $line = $line.TrimStart([char]0xfeff)
            if ($line -notmatch '^\s*SET\s+(?:"(?<key>[^"\r\n]+)"|(?<key>[^\s"]+))\s+"(?<value>[^"\r\n]*)"\s*$') { continue }
            $key = $Matches['key']; $value = $Matches['value']
            if (-not $found.ContainsKey($key)) { continue }
            $safe = $false
            if ($key -in @('engineSurvey','engineSurveyPatch')) { $safe = $value -match '^\d{1,20}$' }
            elseif ($key -in @('telemetryWowPackage','telemetryWowlabsPackage')) { $safe = $value -eq '' -or $value -match '^(?:Blizzard\.Telemetry\.)?Wow[_A-Za-z0-9.-]{0,100}$' }
            else { $safe = $value -match '^[01]$' }
            if ($safe) { $found[$key].Add([pscustomobject]@{value=$value; redacted=$false}) }
            else { $found[$key].Add([pscustomobject]@{value=$null; redacted=$true}) }
        }
    } finally { $reader.Dispose() }
    foreach ($k in $keys) {
        [pscustomobject]@{name=$k; present=($found[$k].Count -gt 0); occurrences=$found[$k].Count; explicit_values=@($found[$k].ToArray()); runtime_effective_value_proven=$false; absent_means_disabled=$false}
    }
}
function Read-BoundedWtfText {
    param([string]$Path)
    $max = 1048576
    $fs = [System.IO.File]::Open($Path,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
    try {
        if ($fs.Length -gt $max) { throw 'Config file exceeds the 1 MiB read limit.' }
        $buffer = New-Object byte[] ($max + 1); $total = 0
        while ($total -lt $buffer.Length) {
            $n = $fs.Read($buffer,$total,$buffer.Length - $total)
            if ($n -eq 0) { break }; $total += $n
        }
        if ($total -gt $max) { throw 'Config file changed beyond the 1 MiB read limit.' }
        if ($total -ge 2 -and $buffer[0] -eq 255 -and $buffer[1] -eq 254) { return [System.Text.Encoding]::Unicode.GetString($buffer,2,$total-2) }
        if ($total -ge 2 -and $buffer[0] -eq 254 -and $buffer[1] -eq 255) { return [System.Text.Encoding]::BigEndianUnicode.GetString($buffer,2,$total-2) }
        return (New-Object System.Text.UTF8Encoding($false,$true)).GetString($buffer,0,$total)
    } finally { $fs.Dispose() }
}
if ($FunctionsOnly) { return }
try {
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = 'Select the Retail WTF\Config.wtf file (read only)'
    $dialog.Filter = 'Config.wtf|Config.wtf'
    $dialog.CheckFileExists = $true
    try {
        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { Write-Host 'Cancelled. Nothing changed.'; exit 0 }
        $path = $dialog.FileName
    } finally { $dialog.Dispose() }
    if ([System.IO.Path]::GetFileName($path) -ine 'Config.wtf') { throw 'Select a file named Config.wtf.' }
    $text = Read-BoundedWtfText -Path $path
    $rows = @(Get-ScopedWtfSettings -Text $text)
    $result = [ordered]@{schema='wow-scoped-wtf-settings-1'; selected_config_context_verified=$false; atomic_snapshot_proven=$false; read_only=$true; network_used=$false; account_or_hardware_values_collected=$false; file_name='Config.wtf'; settings=$rows; limits=@('Explicit text settings only; not live runtime values.','Missing setting is not disabled or zero.','No default value or upload behavior is inferred.','Duplicate values are retained; precedence is not inferred.','Source path and unrelated config lines are omitted.')}
    $json = $result | ConvertTo-Json -Depth 8
    $output = Join-Path $PSScriptRoot ('settings-result-' + [guid]::NewGuid().ToString('N') + '.json')
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
    $out = [System.IO.File]::Open($output,[System.IO.FileMode]::CreateNew,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
    try { $out.Write($bytes,0,$bytes.Length) } finally { $out.Dispose() }
    Write-Host 'Read-only report saved next to this script:' -ForegroundColor Green
    Write-Host ([System.IO.Path]::GetFileName($output))
    $rows | Select-Object name,present,occurrences | Format-Table -AutoSize
    Write-Host 'No setting, firewall rule, certificate, or game file was changed.'
} catch {
    Write-Host 'The read-only check did not complete. No setting was changed.' -ForegroundColor Red
    Write-Host $_.Exception.Message
    exit 1
}
