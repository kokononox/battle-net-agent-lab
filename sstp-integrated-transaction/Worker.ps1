param([string]$Root,[ValidateSet('Quarantine','Restore')][string]$Action,[string]$Fault='None',[int]$FaultIndex=0)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Engine.ps1"
try { InvokeIntegratedTransaction -Root $Root -Action $Action -Fault $Fault -FaultIndex $FaultIndex | Out-Null;exit 0 }
catch {
 if ($_.Exception.Message -match '^(integrated|inventory|journal)_[a-z_0-9]+$') { Write-Host $_.Exception.Message } else { Write-Host ('integrated_worker_failure_'+$_.Exception.GetType().Name.ToLowerInvariant()) }
 exit 1
}
