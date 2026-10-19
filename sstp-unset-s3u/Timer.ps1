[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$SessionId)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 's3u_system_required' }
. (Join-Path $PSScriptRoot 'Core.ps1')
try {
    $r=RestoreUnsetExperiment $PSScriptRoot $SessionId
    WriteNewJson (Join-Path $PSScriptRoot 'timer-receipt.json') $r
    if ($r.conflicts -ne 0) { exit 2 };exit 0
} catch { exit 3 }
