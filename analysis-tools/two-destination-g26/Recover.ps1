param([Parameter(Mandatory=$true)][string]$Config,[ValidateSet('deadline','explicit','fallback')][string]$Origin='fallback')
. (Join-Path $PSScriptRoot 'Common.ps1');. (Join-Path $PSScriptRoot 'Inventory.ps1')
$c=Read-Context $Config;$mutex=$null;$job=[IntPtr]::Zero
$r=[ordered]@{status='stopped';origin=$Origin;system_identity=([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18');owned_job_ended=$false;registration_changes=0;raw_registration_changes=0;classified_reschedules=0;outside_job_target_candidates=0;restore_refused=$false;firewall_restored=$false;iis_restored=$false;bits_new_or_modified=0;bits_snapshot_complete=$false;error_code=$null;stage='enter_lease'}
try{
 $mutex=Enter-Lease $c;$lease=Get-Content -Raw (Join-Path $c.root 'lease.json') | ConvertFrom-Json
 if($lease.phase -eq 'released'){exit 0};if(Test-Path (Join-Path $c.root 'quarantine-latch.json')){throw 'quarantine_latched'};Save-Private (Join-Path $c.root 'lease.json') @{phase='releasing'}
 $r.stage='proxy_exit'
 foreach($process in @(Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq $c.proxy_exe})){try{if(-not $process.WaitForExit(25000)){$r.proxy_force_terminated=$true;$process.Kill();if(-not $process.WaitForExit(10000)){throw 'proxy_exit_timeout'}}}finally{$process.Dispose()}}
 if(@(Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq $c.proxy_exe}).Count -gt 0){throw 'proxy_still_alive'}
 $r.proxy_closed=$true;$r.proxy_drain_complete=$false
 if(Test-Path (Join-Path $c.root 'proxy-drain.json')){$drain=Get-Content -Raw (Join-Path $c.root 'proxy-drain.json') | ConvertFrom-Json;$r.proxy_drain_complete=($drain.complete -eq $true -and $drain.active_handlers -eq 0)}
 $r.stage='owned_job_exit';$null=[Reflection.Assembly]::LoadFrom($c.helper)
 $job=[OfflineLauncher]::OpenOwnedJob($c.job_name)
 if($job -ne [IntPtr]::Zero){$r.owned_job_ended=[OfflineLauncher]::EndJob($job)}
 elseif(Test-Path (Join-Path $c.root 'owner-result.json')){$proof=Get-Content -Raw (Join-Path $c.root 'owner-result.json') | ConvertFrom-Json;$r.owned_job_ended=($proof.job_active_zero_before_close -and $proof.root_exited)}
 elseif(Test-Path (Join-Path $c.root 'owner-failure.json')){$proof=Get-Content -Raw (Join-Path $c.root 'owner-failure.json') | ConvertFrom-Json;$r.owned_job_ended=($proof.job_active_zero_before_close -and $proof.root_exited)}
 elseif(-not (Test-Path (Join-Path $c.root 'launch-attempted.json'))){$r.owned_job_ended=$true}
 if(-not $r.owned_job_ended){throw 'owned_exit_not_verified'}
 $r.stage='bits_inventory';$bitsNow=Get-BitsSnapshot;Save-Private (Join-Path $c.root 'bits-after.json') $bitsNow
 $bitsBefore=Get-Content -Raw (Join-Path $c.root 'bits-before.json') | ConvertFrom-Json;$bitsDelta=Compare-Bits $bitsBefore $bitsNow
 $watchPath=Join-Path $c.root 'bits-watch.json';$watchedAdded=0;$watchedModified=0;$watchComplete=$false
 if(Test-Path $watchPath){$watch=Get-Content -Raw $watchPath | ConvertFrom-Json;$watchComplete=($watch.complete -and $watch.system_identity -and $watch.samples -gt 0);$watchedAdded=[int]$watch.ever_added;$watchedModified=[int]$watch.ever_modified}
 $r.bits_new_or_modified=[Math]::Max(($bitsDelta.added+$bitsDelta.modified),($watchedAdded+$watchedModified))
 $r.bits_snapshot_complete=($bitsNow.complete -and $bitsBefore.complete -and ($watchComplete -or -not (Test-Path (Join-Path $c.root 'system-prelaunch-receipt.json'))))
 $r.stage='registration_inventory';$r.registration_changes=Registration-Changes $c;$cl=Get-Content -Raw (Join-Path $c.root 'classification.json') | ConvertFrom-Json;$r.raw_registration_changes=$cl.raw_changes;$r.classified_reschedules=$cl.classified_reschedules;$outside=@()
 foreach($p in @(Get-CimInstance Win32_Process)){
  $image=[string]$p.ExecutablePath;if(-not $image){continue}
  if($image -in @($c.helper,$c.proxy_exe,(Join-Path $c.root 'NativeUI.exe'))){continue}
  $candidate=([IO.Path]::GetFileName($image) -in @('Battle.net-Setup.exe','Agent.exe','Battle.net.exe','Battle.net Launcher.exe','BlizzardError.exe'))
  foreach($root in @($c.target_roots)){if($image.StartsWith(([string]$root+'\'),[StringComparison]::OrdinalIgnoreCase)){$candidate=$true}}
  if($candidate){$r.outside_job_target_candidates++;$outside+=@{image=$image;pid=[int]$p.ProcessId;created='unattributed'}}
 }
 Save-Private (Join-Path $c.root 'outside-candidates.json') @{items=$outside}
 $r.stage='external_component_check';if(Test-RecoveryRefusal $r.registration_changes $r.outside_job_target_candidates $r.bits_new_or_modified $r.bits_snapshot_complete){$r.restore_refused=$true;Save-Private (Join-Path $c.root 'quarantine-latch.json') @{latched=$true;registration_changes=$r.registration_changes;bits_new_or_modified=$r.bits_new_or_modified};throw 'unclassified_external_component_blocks_restore'}
 $r.stage='hosts_restore'
 if(Test-Path (Join-Path $c.root 'hosts-before.bin')){Copy-Item (Join-Path $c.root 'hosts-before.bin') (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -Force;$null=& "$env:SystemRoot\System32\ipconfig.exe" /flushdns}
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
