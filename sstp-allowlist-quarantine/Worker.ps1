param([string]$Root,[ValidateSet('Quarantine','Restore')][string]$Action,[string]$Fault='None',[int]$FaultIndex=0)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Quarantine.ps1"
try { InvokeNativeQuarantine -Root $Root -Action $Action -Fault $Fault -FaultIndex $FaultIndex | Out-Null;exit 0 }
catch {
 if ($_.Exception.Message -match '^(quarantine|adapter|journal|policy)_[a-z_0-9]+$') { Write-Host $_.Exception.Message } else { Write-Host ('quarantine_worker_failure_'+$_.Exception.GetType().Name.ToLowerInvariant()) }
 exit 1
}
