param([string]$Root,[ValidateSet('Enable','Disable')][string]$Action,[int]$FaultBefore=-1,[int]$FaultAfter=-1)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/ModelEngine.ps1"
try {
 $decoded=[IO.File]::ReadAllText((Join-Path $Root 'plan.json')) | ConvertFrom-Json
 $resources=[object[]]$decoded
 InvokeModelPolicyTransaction -Root $Root -Action $Action -Resources $resources -FaultBefore $FaultBefore -FaultAfter $FaultAfter | Out-Null
 exit 0
} catch {
 if ($_.Exception.Message -match '^transaction_[a-z_]+$') { Write-Host $_.Exception.Message } else { Write-Host ('transaction_worker_failure_'+$_.Exception.GetType().Name.ToLowerInvariant()) }
 Write-Host ('transaction_worker_line_'+$_.InvocationInfo.ScriptLineNumber)
 foreach($frame in ($_.ScriptStackTrace -split "`n")) { if ($frame -match '^at ([A-Za-z0-9-]+),.*: line ([0-9]+)') { Write-Host ('transaction_frame_'+$Matches[1].ToLowerInvariant().Replace('-','_')+'_'+$Matches[2]) } }
 exit 1
}
