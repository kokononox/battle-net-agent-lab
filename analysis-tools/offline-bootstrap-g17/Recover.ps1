param([Parameter(Mandatory=$true)][string]$Config,[ValidateSet('deadline','explicit','fallback')][string]$Origin='fallback')
. (Join-Path $PSScriptRoot 'Common.ps1');. (Join-Path $PSScriptRoot 'Inventory.ps1')
$c=Read-Context $Config;$mutex=$null;$job=[IntPtr]::Zero
$r=[ordered]@{status='stopped';origin=$Origin;system_identity=([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18');owned_job_ended=$false;registration_changes=0;outside_job_target_candidates=0;restore_refused=$false;firewall_restored=$false;iis_restored=$false;error_code=$null;stage='enter_lease'}
try{
 $mutex=Enter-Lease $c;$lease=Get-Content -Raw (Join-Path $c.root 'lease.json') | ConvertFrom-Json
 if($lease.phase -eq 'released'){exit 0};Save-Private (Join-Path $c.root 'lease.json') @{phase='releasing'}
 $r.stage='owned_job_exit';$null=[Reflection.Assembly]::LoadFrom($c.helper)
 $job=[OfflineLauncher]::OpenOwnedJob($c.job_name)
 if($job -ne [IntPtr]::Zero){$r.owned_job_ended=[OfflineLauncher]::EndJob($job)}
 elseif(Test-Path (Join-Path $c.root 'owner-result.json')){$proof=Get-Content -Raw (Join-Path $c.root 'owner-result.json') | ConvertFrom-Json;$r.owned_job_ended=($proof.job_active_zero_before_close -and $proof.root_exited)}
 elseif(Test-Path (Join-Path $c.root 'owner-failure.json')){$proof=Get-Content -Raw (Join-Path $c.root 'owner-failure.json') | ConvertFrom-Json;$r.owned_job_ended=($proof.job_active_zero_before_close -and $proof.root_exited)}
 elseif(-not (Test-Path (Join-Path $c.root 'launch-attempted.json'))){$r.owned_job_ended=$true}
 if(-not $r.owned_job_ended){throw 'owned_exit_not_verified'}
 $r.stage='registration_inventory';$r.registration_changes=Registration-Changes $c;$outside=@()
 foreach($p in @(Get-CimInstance Win32_Process)){
  $image=[string]$p.ExecutablePath;if(-not $image){continue}
  if($image -in @($c.helper,(Join-Path $c.root 'NativeUI.exe'))){continue}
  $candidate=([IO.Path]::GetFileName($image) -in @('Battle.net-Setup.exe','Agent.exe','Battle.net.exe','Battle.net Launcher.exe','BlizzardError.exe'))
  foreach($root in @($c.target_roots)){if($image.StartsWith(([string]$root+'\'),[StringComparison]::OrdinalIgnoreCase)){$candidate=$true}}
  if($candidate){$r.outside_job_target_candidates++;$outside+=@{image=$image;pid=[int]$p.ProcessId;created='unattributed'}}
 }
 Save-Private (Join-Path $c.root 'outside-candidates.json') @{items=$outside}
 $r.stage='external_component_check';if($r.registration_changes -gt 0 -or $r.outside_job_target_candidates -gt 0){$r.restore_refused=$true;throw 'unclassified_external_component_blocks_restore'}
 $r.stage='firewall_restore';Save-Private (Join-Path $c.root 'ended-proof.json') @{verified=$true}
 if(Test-Path (Join-Path $c.root 'before.wfw')){$r.firewall_restored=(Invoke-Gate $c 'Restore').restored}else{$r.firewall_restored=$true}
 if(-not $r.firewall_restored){throw 'restore_fingerprint_mismatch'}
 $r.stage='iis_restore';if($c.iis_original -eq 'Running'){Start-Service W3SVC;$svc=Get-Service W3SVC;try{$svc.WaitForStatus('Running',[TimeSpan]::FromSeconds(15))}finally{$svc.Dispose()}}
 $r.iis_restored=([string](Get-Service W3SVC).Status -eq $c.iis_original);if(-not $r.iis_restored){throw 'iis_restore_failed'}
 Save-Private (Join-Path $c.root 'lease.json') @{phase='released'};$r.status='restored_after_scoped_exit_checks';Save-Private (Join-Path $c.root 'recovery-result.json') $r
 Unregister-ScheduledTask $c.watchdog_name -Confirm:$false -ErrorAction SilentlyContinue
 Unregister-ScheduledTask $c.snapshot_task_name -Confirm:$false -ErrorAction SilentlyContinue
}catch{
 $r.error_shape=Error-Shape $_;$m=$_.Exception.Message;$r.error_code=if($m -match '^[a-z_]{1,100}$'){$m}else{'recovery_operation_failed'}
 $priorPath=Join-Path $c.root 'recovery-result.json'
 if(-not (Test-Path $priorPath)){Save-Private $priorPath $r}
 Write-Output ($r | ConvertTo-Json -Compress -Depth 5);throw 'offline_recovery_stopped_no_unconditional_restore'
}finally{if($job -ne [IntPtr]::Zero){[OfflineLauncher]::CloseJob($job)};if($mutex){$mutex.ReleaseMutex();$mutex.Dispose()}}
