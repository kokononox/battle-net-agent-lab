[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$SessionId)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 's3_worker_not_system' }
. (Join-Path $PSScriptRoot 'Core.ps1')
try {
    $r=InvokeS3Rollback $PSScriptRoot $SessionId
    WriteNewJson (Join-Path $PSScriptRoot 'rollback-receipt.json') $r
    if ($r.conflicts -gt 0) { exit 2 };exit 0
} catch { exit 3 }
