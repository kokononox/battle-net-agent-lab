param([Parameter(Mandatory=$true)][string]$Config)
. (Join-Path $PSScriptRoot 'Common.ps1');. (Join-Path $PSScriptRoot 'Inventory.ps1')
$c=Read-Context $Config
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'system_snapshot_required'}
$phase=Get-Content -Raw (Join-Path $c.root 'snapshot-phase.json') | ConvertFrom-Json
if($phase.value -eq 'baseline'){
 Save-Private (Join-Path $c.root 'registrations-before.json') (Get-RegistrationSnapshot)
 Save-Private (Join-Path $c.root 'system-baseline-receipt.json') @{system_identity=$true;captured=$true}
}elseif($phase.value -eq 'prelaunch'){
 $changes=Registration-Changes $c
 Save-Private (Join-Path $c.root 'system-prelaunch-receipt.json') @{system_identity=$true;registration_changes=$changes;captured=$true}
}else{throw 'snapshot_phase_refused'}
