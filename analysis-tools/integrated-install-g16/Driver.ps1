$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REF -ne 'refs/heads/research/battlenet-minimal-install-isolation-2026-10-25' -or $env:GITHUB_EVENT_NAME -ne 'push' -or $env:GITHUB_RUN_ATTEMPT -ne '1' -or $env:BNET_INTEGRATED_G16 -ne 'lab: approved peer firewall integration G16a 20261025' -or $env:BNET_G16_SCENARIO -notin @('normal_release','supervisor_crash')){throw 'fresh_hosted_integration_required'}
. (Join-Path $PSScriptRoot 'Common.ps1')
New-Item -ItemType Directory -Force output | Out-Null
$r=[ordered]@{schema='bnet-peer-firewall-g16a-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;scenario=$env:BNET_G16_SCENARIO;status='stopped';installer_launched=$false;baseline_direct_ok=$false;cross_identity_mutex_preflight=$false;gate_ready=$false;component_probes=@();system_service_verified=$false;system_task_verified=$false;unknown_same_exe_no_dial=$false;service_revoked_no_dial=$false;forged_service_creation_no_dial=$false;service_reenrolled_ok=$false;forged_controller_no_dial=$false;controller_restored_ok=$false;supervisor_crashed=$false;controller_death_no_dial=$false;fixtures_alive_after_crash=$false;direct_still_denied_after_crash=$false;recovery_system=$false;recovery_origin=$null;peer_ledger_revoked_before_restore=$false;proxy_closed_before_restore=$false;components_exited_before_restore=$false;hosts_restored=$false;firewall_restored=$false;iis_restored=$false;post_restore_direct_ok=$false;full_install_boundary_proven=$false;socket_duplication_proven_safe=$false;https_payload_classified=$false;live_inventory_monitor_tested=$false;stage='prepare';error_code=$null;failure_stage=$null;supervisor_diagnostic=$null;recovery_error_code=$null;recovery_error_shape=$null}
$guid=[guid]::NewGuid().ToString('N');$root=Join-Path (Join-Path $env:ProgramData 'BNetIntegratedG16') $guid;$config=Join-Path $root 'config.json';$c=$null;$supervisor=$null;$probeLease=$null
function Save-Report{$r | ConvertTo-Json -Depth 8 | Set-Content ('output/integrated-g16-'+$env:BNET_G16_SCENARIO+'.json') -Encoding UTF8;Write-Output ($r | ConvertTo-Json -Depth 8 -Compress)}
try{
 $null=New-Item -ItemType Directory -Force $root;$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){$identity=[Security.Principal.SecurityIdentifier]::new($sid);$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity,[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))}
 Set-Acl $root $acl
 foreach($name in @('Common.ps1','Supervisor.ps1','Recover.ps1','FirewallGate.ps1','LeaseProbe.ps1','Inventory.ps1')){Copy-Item (Join-Path $PSScriptRoot $name) (Join-Path $root $name)}
 Copy-Item "$env:RUNNER_TEMP\bnet-g16-bin\ExternalProbe.exe" (Join-Path $root 'ExternalProbe.exe')
 Copy-Item (Join-Path $PSScriptRoot 'dist\TwoHostProxy.exe') (Join-Path $root 'TwoHostProxy.exe')
 $pinsText=& python -c "import socket,ipaddress,json; h=('level3.blizzard.com','us.version.battle.net'); d={n:sorted({x[4][0] for x in socket.getaddrinfo(n,80,type=socket.SOCK_STREAM) if ipaddress.ip_address(x[4][0]).is_global},key=lambda a:(':' in a,a)) for n in h}; assert all(1<=len(v)<=32 for v in d.values()); print(json.dumps(d))"
 if($LASTEXITCODE -ne 0){throw 'pins_resolution_failed'};$pins=$pinsText | ConvertFrom-Json
 $v4=@($pins.'us.version.battle.net' | Where-Object {$_ -notmatch ':'});if($v4.Count -eq 0){throw 'ipvfour_fixture_missing'}
 $exe=Join-Path $root 'ExternalProbe.exe';$token=[guid]::NewGuid().ToString('N');$ps="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
 $c=[ordered]@{root=$root;token=$token;exe=$exe;proxy_exe=(Join-Path $root 'TwoHostProxy.exe');service_name=('BNetLabG16_'+$guid+'_svc');task_name=('BNetLabG16_'+$guid+'_task');watchdog_name=('BNetLabG16_'+$guid+'_recovery');job_name=('Global\BNetLabG16_'+$guid);mutex_name=('Global\BNetG16Lease_'+$guid);expires_ticks=[DateTime]::UtcNow.AddMinutes(8).Ticks;canary_ip=$v4[0];service_command=('"'+$exe+'" service "'+$config+'" '+$token);task_arguments=('task "'+$config+'" '+$token);source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;iis_original=[string](Get-Service W3SVC).Status;supervisor_script=(Join-Path $root 'Supervisor.ps1');watchdog_script=(Join-Path $root 'Recover.ps1')}
 $c.fixture_sha256=(Get-FileHash $c.exe -Algorithm SHA256).Hash;$c.peer_expires_unix=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+420;$c.resolution_task_name=$c.watchdog_name+'_resolution'
 if($c.iis_original -notin @('Running','Stopped')){throw 'iis_transitional_state'}
 Save-Private $config $c;Save-Private (Join-Path $root 'lease.json') @{phase='prepared'}
 Save-Private (Join-Path $root 'proxy.json') @{hosts=$pins;port=18731;seconds=600;log=(Join-Path $root 'proxy-private.jsonl');transparent=$true;peer_policy=(Join-Path $root 'peers.json')}
 Save-Private output/g16-private-recovery-pointer.json @{config=$config}
 $before=Invoke-Canary $c 'canary';$r.baseline_direct_ok=($before.connected -and $before.http200);if(-not $r.baseline_direct_ok){throw 'baseline_not_healthy'}
 # Verify both creators before changing firewall or hosts: runner -> SYSTEM, SYSTEM -> runner.
 foreach($mode in @('runner_created','system_created')){
  $probeName=$c.watchdog_name+'_leaseprobe';$held=$null;$probeMutex=$null
  try{
   $probeContext=@{mutex_name=($c.mutex_name+'_'+$mode)}
   if($mode -eq 'runner_created'){$held=Enter-Lease $probeContext;$held.ReleaseMutex()}
   $probeAction=New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $root 'LeaseProbe.ps1')+'" -Config "'+$config+'" -Mode '+$mode)
   $probePrincipal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
   $null=Register-ScheduledTask -TaskName $probeName -Action $probeAction -Principal $probePrincipal
   Start-ScheduledTask $probeName;$receipt=Join-Path $root ('lease-probe-'+$mode+'.json');Wait-File $receipt 20
   $proof=Get-Content -Raw $receipt | ConvertFrom-Json;if($proof.system_identity -ne $true -or $proof.acquired -ne $true){throw 'system_lease_probe_failed'}
   $probeMutex=Enter-Lease $probeContext;$probeMutex.ReleaseMutex();$probeMutex.Dispose();$probeMutex=$null
  }finally{
   if($held){$held.Dispose()};if($probeMutex){$probeMutex.Dispose()}
   Stop-ScheduledTask $probeName -ErrorAction SilentlyContinue;Unregister-ScheduledTask $probeName -Confirm:$false -ErrorAction SilentlyContinue
  }
 }
 $r.cross_identity_mutex_preflight=$true
 $action=New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$c.watchdog_script+'" -Config "'+$config+'" -Origin deadline')
 $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(120);$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $watchdogSettings=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds 90)
 $null=Register-ScheduledTask -TaskName $c.watchdog_name -Action $action -Trigger $trigger -Principal $principal -Settings $watchdogSettings
 if(-not (Get-ScheduledTask -TaskName $c.watchdog_name)){throw 'independent_watchdog_missing'}
 $r.stage='supervisor_start'
 $supervisor=Start-Process $ps -ArgumentList ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$c.supervisor_script+'" -Config "'+$config+'"') -PassThru -WindowStyle Hidden
 Record-Process $supervisor (Join-Path $root 'supervisor-process.json')
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while(-not (Test-Path (Join-Path $root 'supervisor-ready.json')) -and $watch.Elapsed.TotalSeconds -lt 150){
  if(Test-Path (Join-Path $root 'supervisor-error.json')){$e=Get-Content -Raw (Join-Path $root 'supervisor-error.json') | ConvertFrom-Json;$r.supervisor_diagnostic=$e;throw $e.error_code}
  if($supervisor.HasExited){throw 'supervisor_exited_before_ready'};Start-Sleep -Milliseconds 250
 }
 Wait-File (Join-Path $root 'supervisor-ready.json') 1
 $ready=Get-Content -Raw (Join-Path $root 'supervisor-ready.json') | ConvertFrom-Json;$r.gate_ready=$ready.gate_verified;$r.root_and_leaf_in_job=$ready.root_and_leaf_member;$r.external_service_task_outside=$ready.service_and_task_outside
 $resolveAction=New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$c.watchdog_script+'" -Config "'+$config+'" -Origin resolution')
 $null=Register-ScheduledTask -TaskName $c.resolution_task_name -Action $resolveAction -Principal $principal
 . (Join-Path $root 'Inventory.ps1')
 Save-Private (Join-Path $root 'registration-baseline.json') (Get-RegistrationSnapshot)
 $probeLease=Enter-Lease $c
 $r.stage='component_admission'
 foreach($kind in @('root','leaf','service','task')){
  $direct=Invoke-Component $c $kind 2 'direct';$via=Invoke-Component $c $kind 3 'via_gate'
  $r.component_probes+=@{kind=$kind;direct_denied=(-not $direct.connected);via_http200=$via.http200;system_identity=$via.system_identity}
 }
 $r.system_service_verified=(@($r.component_probes | Where-Object {$_.kind -eq 'service' -and $_.system_identity}).Count -eq 1)
 $r.system_task_verified=(@($r.component_probes | Where-Object {$_.kind -eq 'task' -and $_.system_identity}).Count -eq 1)
 $before=Upstream-Counts $c;$unknown=Invoke-Canary $c 'via_gate';$after=Upstream-Counts $c
 $r.unknown_same_exe_no_dial=($unknown.connected -and -not $unknown.http200 -and $before.attempts -eq $after.attempts -and $before.connections -eq $after.connections -and $after.denials -gt $before.denials)
 $r.stage='service_identity_revocation'
 $serviceId=Get-Content -Raw (Join-Path $root 'service.json') | ConvertFrom-Json
 $peers=Get-Content -Raw (Join-Path $root 'peers.json') | ConvertFrom-Json
 Write-Peers $c @($peers.peers | Where-Object {[int]$_.pid -ne [int]$serviceId.pid})
 function Denied-Service([int]$Sequence){
  $before=Upstream-Counts $c;$v=Invoke-Component $c 'service' $Sequence 'via_gate';$after=Upstream-Counts $c
  return ($v.system_identity -and $v.connected -and -not $v.http200 -and $before.attempts -eq $after.attempts -and $before.connections -eq $after.connections -and $after.denials -gt $before.denials)
 }
 $r.service_revoked_no_dial=Denied-Service 4
 $forged=@($peers.peers);foreach($entry in $forged){if([int]$entry.pid -eq [int]$serviceId.pid){$entry.created=[long]$entry.created+1}}
 Write-Peers $c $forged;$r.forged_service_creation_no_dial=Denied-Service 5
 Enroll-KnownPeers $c;$r.service_reenrolled_ok=(Invoke-Component $c 'service' 6 'via_gate').http200
 $r.stage='controller_identity'
 $policy=Get-Content -Raw (Join-Path $root 'peers.json') | ConvertFrom-Json;$policy.controller.created=[long]$policy.controller.created+1
 Save-Private (Join-Path $root 'peers.json') $policy;$r.forged_controller_no_dial=Denied-Service 7
 Enroll-KnownPeers $c;$r.controller_restored_ok=(Invoke-Component $c 'service' 8 'via_gate').http200
 $null=Invoke-Gate $c 'Verify'
 if($env:BNET_G16_SCENARIO -eq 'supervisor_crash'){
  $r.stage='supervisor_crash';Write-Host 'G16_STAGE:before_supervisor_kill';$supervisor.Kill();$r.supervisor_crashed=$supervisor.WaitForExit(5000)
  Write-Host 'G16_STAGE:supervisor_kill_acknowledged';$r.controller_death_no_dial=Denied-Service 9;Write-Host ('G16_CONTROLLER_DEATH_DENIED:'+ $r.controller_death_no_dial)
  $r.fixtures_alive_after_crash=$true
  foreach($kind in @('root','leaf','service','task','owner')){
   $id=Get-Content -Raw (Join-Path $root ($kind+'.json')) | ConvertFrom-Json;$id | Add-Member -NotePropertyName image -NotePropertyValue $c.exe -Force
   $proc=Open-Verified $id;if($proc){$proc.Dispose()}else{$r.fixtures_alive_after_crash=$false}
  }
  $r.direct_still_denied_after_crash=(-not (Invoke-Component $c 'root' 4 'direct').connected)
 }else{Start-ScheduledTask $c.resolution_task_name}
 $probeLease.ReleaseMutex();$probeLease.Dispose();$probeLease=$null
 $r.stage='await_system_recovery';Write-Host 'G16_STAGE:await_system_recovery'
 $wait=[Diagnostics.Stopwatch]::StartNew()
 while(-not (Test-Path (Join-Path $root 'recovery-result.json')) -and $wait.Elapsed.TotalSeconds -lt 180){
  $progressPath=Join-Path $root 'recovery-progress.json'
  $stage='not_started';if(Test-Path $progressPath){$stage=[string](Get-Content -Raw $progressPath | ConvertFrom-Json).stage}
  if($stage -notmatch '^[a-z_]{1,60}$'){$stage='unclassified'}
  $state=[string](Get-ScheduledTask -TaskName $c.watchdog_name -ErrorAction SilentlyContinue).State
  if($state -notin @('Ready','Running','Disabled','Queued')){$state='unavailable'}
  Write-Host ('G16_RECOVERY_PROGRESS:'+ $stage+';task='+$state)
  Start-Sleep -Seconds 10
 }
 Wait-File (Join-Path $root 'recovery-result.json') 1
 $recovery=Get-Content -Raw (Join-Path $root 'recovery-result.json') | ConvertFrom-Json
 $r.recovery_error_code=$recovery.error_code;$r.recovery_error_shape=$recovery.error_shape
 $expectedOrigin=if($env:BNET_G16_SCENARIO -eq 'supervisor_crash'){'deadline'}else{'resolution'}
 $r.recovery_origin=$recovery.origin;$r.recovery_system=($recovery.system_identity -and $recovery.origin -eq $expectedOrigin -and $recovery.status -eq 'recovered_after_verified_component_exit')
 $r.peer_ledger_revoked_before_restore=$recovery.peer_ledger_revoked;$r.proxy_closed_before_restore=$recovery.gate_proxy_closed
 $r.components_exited_before_restore=($recovery.supervisor_exited -and $recovery.job_active_zero -and $recovery.all_observed_members_exited -and $recovery.service_removed -and $recovery.task_removed -and $recovery.fixture_images_gone)
 $r.hosts_restored=$recovery.hosts_restored;$r.firewall_restored=$recovery.firewall_restored;$r.iis_restored=$recovery.iis_restored
 if($r.recovery_system){$post=Invoke-Canary $c 'canary';$r.post_restore_direct_ok=($post.connected -and $post.http200)}
 Unregister-ScheduledTask $c.resolution_task_name -Confirm:$false
 $componentsGood=(@($r.component_probes | Where-Object {-not $_.direct_denied -or -not $_.via_http200}).Count -eq 0 -and $r.component_probes.Count -eq 4)
 $crashGood=($env:BNET_G16_SCENARIO -ne 'supervisor_crash' -or ($r.supervisor_crashed -and $r.controller_death_no_dial -and $r.fixtures_alive_after_crash -and $r.direct_still_denied_after_crash))
 if($r.gate_ready -and $r.cross_identity_mutex_preflight -and $componentsGood -and $r.system_service_verified -and $r.system_task_verified -and $r.unknown_same_exe_no_dial -and $r.service_revoked_no_dial -and $r.forged_service_creation_no_dial -and $r.service_reenrolled_ok -and $r.forged_controller_no_dial -and $r.controller_restored_ok -and $crashGood -and $r.recovery_system -and $r.peer_ledger_revoked_before_restore -and $r.proxy_closed_before_restore -and $r.components_exited_before_restore -and $r.hosts_restored -and $r.firewall_restored -and $r.iis_restored -and $r.post_restore_direct_ok){$r.status='qualified_peer_firewall_system_recovery_integration'}else{$r.error_code='peer_firewall_integration_probes_failed'}
}catch{$r.failure_stage=$r.stage;$message=$_.Exception.Message;$r.error_code=if($message -match '^[a-z_]{1,80}$'){$message}else{'integration_operation_failed'}}
finally{
 if($probeLease){$probeLease.ReleaseMutex();$probeLease.Dispose()};if($supervisor){$supervisor.Dispose()};$r.stage='complete';Write-Host ('G16_STAGE:'+$r.stage);Save-Report
}
if($r.status -eq 'stopped'){throw 'integrated_recovery_qualification_stopped'}
