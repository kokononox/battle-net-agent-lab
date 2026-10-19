param([string]$Root,[ValidateSet('Enable','Disable')][string]$Action,[int]$FaultBefore=-1,[int]$FaultAfter=-1)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/ModelEngine.ps1"
try {
 $resources=@([IO.File]::ReadAllText((Join-Path $Root 'plan.json')) | ConvertFrom-Json)
 InvokeModelPolicyTransaction -Root $Root -Action $Action -Resources $resources -FaultBefore $FaultBefore -FaultAfter $FaultAfter | Out-Null
 exit 0
} catch {
 if ($_.Exception.Message -match '^transaction_[a-z_]+$') { Write-Host $_.Exception.Message } else { Write-Host 'transaction_worker_failure' }
 exit 1
}
