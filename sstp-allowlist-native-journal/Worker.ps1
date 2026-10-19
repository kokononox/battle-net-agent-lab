param([string]$Root,[ValidateSet('Stage','Remove')][string]$Action,[string]$Fault='None')
$ErrorActionPreference='Stop'
. "$PSScriptRoot/NativeJournal.ps1"
try {
 $spec=[IO.File]::ReadAllText((Join-Path $Root 'fixture-spec.json')) | ConvertFrom-Json
 InvokeNativeStaging -Root $Root -Action $Action -Spec $spec -Fault $Fault | Out-Null
 exit 0
} catch {
 if ($_.Exception.Message -match '^(staging|adapter|journal|policy)_[a-z_0-9]+$') { Write-Host $_.Exception.Message } else { Write-Host ('staging_worker_failure_'+$_.Exception.GetType().Name.ToLowerInvariant()) }
 exit 1
}
