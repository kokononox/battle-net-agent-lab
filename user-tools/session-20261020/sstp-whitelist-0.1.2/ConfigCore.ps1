# Configuration and read-only compatibility planning. NO firewall mutation entry point.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')

function AssertConfigPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'tool_config_path' }
    $full = [IO.Path]::GetFullPath($Path)
    if ([IO.Path]::GetExtension($full) -ine '.json') { throw 'tool_config_extension' }
    $cursor = $full
    while ($cursor) {
        if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
            if (([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'tool_config_link' }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -ceq $cursor) { break }; $cursor = $parent
    }
    return $full
}
function ReadAllowlistConfig([string]$Path) {
    $full = AssertConfigPath $Path
    $f = New-Object IO.FileInfo($full)
    if (-not $f.Exists -or $f.Length -gt 65536) { throw 'tool_config_missing_or_large' }
    $text = [IO.File]::ReadAllText($full)
    return (PolicyConfig (ConvertFrom-Json -InputObject $text -ErrorAction Stop))
}
