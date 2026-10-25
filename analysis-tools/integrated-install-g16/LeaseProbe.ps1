param([Parameter(Mandatory=$true)][string]$Config,[ValidateSet('runner_created','system_created')][string]$Mode)
. (Join-Path $PSScriptRoot 'Common.ps1')
$c=Read-Context $Config;$c.mutex_name=$c.mutex_name+'_'+$Mode;$mutex=$null
try{
 $mutex=Enter-Lease $c
 Save-Private (Join-Path $c.root ('lease-probe-'+$Mode+'.json')) @{system_identity=([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18');acquired=$true}
 Start-Sleep -Seconds 3
}finally{if($mutex){$mutex.ReleaseMutex();$mutex.Dispose()}}
