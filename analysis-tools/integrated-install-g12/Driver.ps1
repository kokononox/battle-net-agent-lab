$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REF -ne 'refs/heads/research/battlenet-minimal-install-isolation-2026-10-25' -or $env:GITHUB_EVENT_NAME -ne 'push' -or $env:GITHUB_RUN_ATTEMPT -ne '1' -or $env:BNET_INTEGRATED_G12 -ne 'lab: approved integrated-recovery qualification G12 20261025' -or $env:BNET_G12_SCENARIO -notin @('supervisor_crash','supervisor_timeout')){throw 'fresh_hosted_integration_required'}
. (Join-Path $PSScriptRoot 'Common.ps1')
New-Item -ItemType Directory -Force output | Out-Null
$r=[ordered]@{schema='bnet-integrated-g12-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;scenario=$env:BNET_G12_SCENARIO;status='stopped';installer_launched=$false;baseline_direct_ok=$false;gate_ready=$false;root_and_leaf_in_job=$false;external_service_task_outside=$false;supervisor_crashed_as_requested=$false;supervisor_alive_for_timeout=$false;fixtures_alive_at_failure=$false;fixtures_alive_after_failure=$false;post_scenario_direct_denied=$false;no_observed_direct_release_before_recovery=$true;independent_deadline_system_recovery=$false;components_exited_before_restore=$false;hosts_restored=$false;firewall_restored=$false;iis_restored=$false;post_restore_direct_ok=$false;full_install_boundary_proven=$false;arbitrary_service_discovery_proven=$false;mid_startup_crash_tested=$false;stage='prepare';error_code=$null}
$guid=[guid]::NewGuid().ToString('N');$root=Join-Path (Join-Path $env:ProgramData 'BNetIntegratedG12') $guid;$config=Join-Path $root 'config.json';$c=$null;$supervisor=$null
function Save-Report{$r | ConvertTo-Json -Depth 8 | Set-Content ('output/integrated-g12-'+$env:BNET_G12_SCENARIO+'.json') -Encoding UTF8;Write-Output ($r | ConvertTo-Json -Depth 8 -Compress)}
try{
 $null=New-Item -ItemType Directory -Force $root;$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){$identity=[Security.Principal.SecurityIdentifier]::new($sid);$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity,[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))}
 Set-Acl $root $acl
 foreach($name in @('Common.ps1','Supervisor.ps1','Recover.ps1','FirewallGate.ps1')){Copy-Item (Join-Path $PSScriptRoot $name) (Join-Path $root $name)}
 Copy-Item "$env:RUNNER_TEMP\bnet-g12-bin\ExternalProbe.exe" (Join-Path $root 'ExternalProbe.exe')
 Copy-Item (Join-Path $PSScriptRoot 'dist\TwoHostProxy.exe') (Join-Path $root 'TwoHostProxy.exe')
 $pinsText=& python -c "import socket,ipaddress,json; h=('level3.blizzard.com','us.version.battle.net'); d={n:sorted({x[4][0] for x in socket.getaddrinfo(n,80,type=socket.SOCK_STREAM) if ipaddress.ip_address(x[4][0]).is_global},key=lambda a:(':' in a,a)) for n in h}; assert all(1<=len(v)<=32 for v in d.values()); print(json.dumps(d))"
 if($LASTEXITCODE -ne 0){throw 'pins_resolution_failed'};$pins=$pinsText | ConvertFrom-Json
 $v4=@($pins.'us.version.battle.net' | Where-Object {$_ -notmatch ':'});if($v4.Count -eq 0){throw 'ipvfour_fixture_missing'}
 $exe=Join-Path $root 'ExternalProbe.exe';$token=[guid]::NewGuid().ToString('N');$ps="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
 $c=[ordered]@{root=$root;token=$token;exe=$exe;proxy_exe=(Join-Path $root 'TwoHostProxy.exe');service_name=('BNetLabG12_'+$guid+'_svc');task_name=('BNetLabG12_'+$guid+'_task');watchdog_name=('BNetLabG12_'+$guid+'_recovery');job_name=('Global\BNetLabG12_'+$guid);mutex_name=('Global\BNetG12Lease_'+$guid);expires_ticks=[DateTime]::UtcNow.AddMinutes(8).Ticks;canary_ip=$v4[0];service_command=('"'+$exe+'" service "'+$config+'" '+$token);task_arguments=('task "'+$config+'" '+$token);source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;iis_original=[string](Get-Service W3SVC).Status;supervisor_script=(Join-Path $root 'Supervisor.ps1');watchdog_script=(Join-Path $root 'Recover.ps1')}
 if($c.iis_original -notin @('Running','Stopped')){throw 'iis_transitional_state'}
 Save-Private $config $c;Save-Private (Join-Path $root 'lease.json') @{phase='prepared'}
 Save-Private (Join-Path $root 'proxy.json') @{hosts=$pins;port=18731;seconds=600;log=(Join-Path $root 'proxy-private.jsonl');transparent=$true}
 Save-Private output/g12-private-recovery-pointer.json @{config=$config}
 $before=Invoke-Canary $c 'canary';$r.baseline_direct_ok=($before.connected -and $before.http200);if(-not $r.baseline_direct_ok){throw 'baseline_not_healthy'}
 $action=New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$c.watchdog_script+'" -Config "'+$config+'" -Origin deadline')
 $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(180);$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $null=Register-ScheduledTask -TaskName $c.watchdog_name -Action $action -Trigger $trigger -Principal $principal
 if(-not (Get-ScheduledTask -TaskName $c.watchdog_name)){throw 'independent_watchdog_missing'}
 $r.stage='supervisor_start'
 $supervisor=Start-Process $ps -ArgumentList ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$c.supervisor_script+'" -Config "'+$config+'"') -PassThru -WindowStyle Hidden
 Record-Process $supervisor (Join-Path $root 'supervisor-process.json')
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while(-not (Test-Path (Join-Path $root 'supervisor-ready.json')) -and $watch.Elapsed.TotalSeconds -lt 150){
  if(Test-Path (Join-Path $root 'supervisor-error.json')){$e=Get-Content -Raw (Join-Path $root 'supervisor-error.json') | ConvertFrom-Json;throw $e.error_code}
  if($supervisor.HasExited){throw 'supervisor_exited_before_ready'};Start-Sleep -Milliseconds 250
 }
 Wait-File (Join-Path $root 'supervisor-ready.json') 1
 $ready=Get-Content -Raw (Join-Path $root 'supervisor-ready.json') | ConvertFrom-Json;$r.gate_ready=$ready.gate_verified;$r.root_and_leaf_in_job=$ready.root_and_leaf_member;$r.external_service_task_outside=$ready.service_and_task_outside
 $alive=$true
 foreach($kind in @('root','leaf','service','task','owner')){
  $id=Get-Content -Raw (Join-Path $root ($kind+'.json')) | ConvertFrom-Json;$id | Add-Member -NotePropertyName image -NotePropertyValue $c.exe -Force
  $proc=Open-Verified $id;if($proc){$proc.Dispose()}else{$alive=$false}
 }
 $r.fixtures_alive_at_failure=$alive;if(-not $alive){throw 'fixture_ended_before_failure'}
 $r.stage='inject_failure'
 if($env:BNET_G12_SCENARIO -eq 'supervisor_crash'){$supervisor.Kill();$r.supervisor_crashed_as_requested=$supervisor.WaitForExit(5000)}else{$r.supervisor_alive_for_timeout=(-not $supervisor.HasExited)}
 $aliveAfter=$true
 foreach($kind in @('root','leaf','service','task','owner')){
  $id=Get-Content -Raw (Join-Path $root ($kind+'.json')) | ConvertFrom-Json;$id | Add-Member -NotePropertyName image -NotePropertyValue $c.exe -Force
  $proc=Open-Verified $id;if($proc){$proc.Dispose()}else{$aliveAfter=$false}
 }
 $r.fixtures_alive_after_failure=$aliveAfter
 $r.stage='await_independent_recovery';$watch.Restart()
 while(-not (Test-Path (Join-Path $root 'recovery-result.json')) -and $watch.Elapsed.TotalSeconds -lt 300){
  $mutex=Enter-Lease $c
  try{
   $lease=Get-Content -Raw (Join-Path $root 'lease.json') | ConvertFrom-Json
   if($lease.phase -eq 'active'){$probe=Invoke-Canary $c 'canary';if($probe.connected){$r.no_observed_direct_release_before_recovery=$false}else{$r.post_scenario_direct_denied=$true}}
  }finally{$mutex.ReleaseMutex();$mutex.Dispose()}
  Start-Sleep -Seconds 5
 }
 Wait-File (Join-Path $root 'recovery-result.json') 1
 $recovery=Get-Content -Raw (Join-Path $root 'recovery-result.json') | ConvertFrom-Json
 $r.independent_deadline_system_recovery=($recovery.origin -eq 'deadline' -and $recovery.system_identity -eq $true -and $recovery.status -eq 'recovered_after_verified_component_exit')
 $r.components_exited_before_restore=($recovery.supervisor_exited -and $recovery.job_active_zero -and $recovery.all_observed_members_exited -and $recovery.service_removed -and $recovery.task_removed -and $recovery.fixture_images_gone)
 $r.hosts_restored=$recovery.hosts_restored;$r.firewall_restored=$recovery.firewall_restored;$r.iis_restored=$recovery.iis_restored
 if($r.independent_deadline_system_recovery){$after=Invoke-Canary $c 'canary';$r.post_restore_direct_ok=($after.connected -and $after.http200)}
 $expected=if($env:BNET_G12_SCENARIO -eq 'supervisor_crash'){$r.supervisor_crashed_as_requested}else{$r.supervisor_alive_for_timeout}
 if($r.gate_ready -and $r.fixtures_alive_after_failure -and $r.root_and_leaf_in_job -and $r.external_service_task_outside -and $expected -and $r.post_scenario_direct_denied -and $r.no_observed_direct_release_before_recovery -and $r.independent_deadline_system_recovery -and $r.components_exited_before_restore -and $r.hosts_restored -and $r.firewall_restored -and $r.iis_restored -and $r.post_restore_direct_ok){$r.status='qualified_post_ready_integrated_deadline_recovery'}else{$r.error_code='integrated_recovery_probes_failed'}
}catch{$message=$_.Exception.Message;$r.error_code=if($message -match '^[a-z_]{1,80}$'){$message}else{'integration_operation_failed'}}
finally{
 if($supervisor){$supervisor.Dispose()};$r.stage='complete';Save-Report
}
if($r.status -eq 'stopped'){throw 'integrated_recovery_qualification_stopped'}
