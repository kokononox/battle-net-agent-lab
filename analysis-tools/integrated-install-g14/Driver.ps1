$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REF -ne 'refs/heads/research/battlenet-minimal-install-isolation-2026-10-25' -or $env:GITHUB_EVENT_NAME -ne 'push' -or $env:GITHUB_RUN_ATTEMPT -ne '1' -or $env:BNET_INTEGRATED_G14 -ne 'lab: approved inventory quarantine qualification G14 20261025' -or $env:BNET_G14_SCENARIO -notin @('outside_service','outside_task','foreign_job_child')){throw 'fresh_hosted_integration_required'}
. (Join-Path $PSScriptRoot 'Common.ps1')
New-Item -ItemType Directory -Force output | Out-Null
$r=[ordered]@{schema='bnet-inventory-g14-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;scenario=$env:BNET_G14_SCENARIO;status='stopped';installer_launched=$false;baseline_direct_ok=$false;cross_identity_mutex_preflight=$false;gate_ready=$false;global_baseline_clean=$false;monitor_system=$false;monitor_detected=$false;quarantine_elapsed_seconds=$null;quarantine_refusal_verified=$false;unknown_alive_while_quarantined=$false;direct_denied=$false;proxy_connection_denied=$false;default_block_retained=$false;unknown_explicitly_removed=$false;resolution_system=$false;components_exited_before_restore=$false;hosts_restored=$false;firewall_restored=$false;iis_restored=$false;post_restore_direct_ok=$false;full_install_boundary_proven=$false;all_process_creation_intercepted=$false;https_payload_classified=$false;stage='prepare';error_code=$null;failure_stage=$null;supervisor_diagnostic=$null;recovery_error_code=$null;recovery_error_shape=$null}
$guid=[guid]::NewGuid().ToString('N');$root=Join-Path (Join-Path $env:ProgramData 'BNetIntegratedG14') $guid;$config=Join-Path $root 'config.json';$c=$null;$supervisor=$null;$leaseAnchor=$null
function Save-Report{$r | ConvertTo-Json -Depth 8 | Set-Content ('output/inventory-g14-'+$env:BNET_G14_SCENARIO+'.json') -Encoding UTF8;Write-Output ($r | ConvertTo-Json -Depth 8 -Compress)}
try{
 $null=New-Item -ItemType Directory -Force $root;$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){$identity=[Security.Principal.SecurityIdentifier]::new($sid);$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity,[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))}
 Set-Acl $root $acl
 foreach($name in @('Common.ps1','Supervisor.ps1','Recover.ps1','FirewallGate.ps1','LeaseProbe.ps1','Inventory.ps1','Monitor.ps1')){Copy-Item (Join-Path $PSScriptRoot $name) (Join-Path $root $name)}
 Copy-Item "$env:RUNNER_TEMP\bnet-g14-bin\ExternalProbe.exe" (Join-Path $root 'ExternalProbe.exe')
 Copy-Item (Join-Path $PSScriptRoot 'dist\TwoHostProxy.exe') (Join-Path $root 'TwoHostProxy.exe')
 $pinsText=& python -c "import socket,ipaddress,json; h=('level3.blizzard.com','us.version.battle.net'); d={n:sorted({x[4][0] for x in socket.getaddrinfo(n,80,type=socket.SOCK_STREAM) if ipaddress.ip_address(x[4][0]).is_global},key=lambda a:(':' in a,a)) for n in h}; assert all(1<=len(v)<=32 for v in d.values()); print(json.dumps(d))"
 if($LASTEXITCODE -ne 0){throw 'pins_resolution_failed'};$pins=$pinsText | ConvertFrom-Json
 $v4=@($pins.'us.version.battle.net' | Where-Object {$_ -notmatch ':'});if($v4.Count -eq 0){throw 'ipvfour_fixture_missing'}
 $exe=Join-Path $root 'ExternalProbe.exe';$token=[guid]::NewGuid().ToString('N');$ps="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
 $c=[ordered]@{scenario=$env:BNET_G14_SCENARIO;pause_owner_receipt=($env:BNET_G14_SCENARIO -eq 'mid_owner_receipt');root=$root;token=$token;exe=$exe;proxy_exe=(Join-Path $root 'TwoHostProxy.exe');service_name=('BNetLabG14_'+$guid+'_svc');task_name=('BNetLabG14_'+$guid+'_task');watchdog_name=('BNetLabG14_'+$guid+'_recovery');job_name=('Global\BNetLabG14_'+$guid);mutex_name=('Global\BNetG14Lease_'+$guid);expires_ticks=[DateTime]::UtcNow.AddMinutes(8).Ticks;canary_ip=$v4[0];service_command=('"'+$exe+'" service "'+$config+'" '+$token);task_arguments=('task "'+$config+'" '+$token);source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;iis_original=[string](Get-Service W3SVC).Status;supervisor_script=(Join-Path $root 'Supervisor.ps1');watchdog_script=(Join-Path $root 'Recover.ps1')}
 $outside=Join-Path (Join-Path $env:ProgramData 'BNetOutsideG14') $guid;$null=New-Item -ItemType Directory -Force $outside;Set-Acl $outside $acl
 Copy-Item "$env:RUNNER_TEMP\bnet-g14-bin\OutsideProbe.exe" (Join-Path $outside 'OutsideProbe.exe')
 $c.outside_exe=Join-Path $outside 'OutsideProbe.exe';$c.outside_receipt=Join-Path $outside 'outside-ready.json';$c.outside_hash=(Get-FileHash $c.outside_exe -Algorithm SHA256).Hash
 $c.outside_service_name='BNetOutsideG14_'+$guid+'_svc';$c.outside_task_name='BNetOutsideG14_'+$guid+'_task';$c.outside_service_command='"'+$c.outside_exe+'" service '+$c.outside_service_name+' "'+$c.outside_receipt+'"';$c.outside_task_arguments='task "'+$c.outside_receipt+'"'
 $c.monitor_task_name=$c.watchdog_name+'_monitor'
 $c.unlisted_task_name='BNetLabG14_'+$guid+'_unlisted';$c.unlisted_task_arguments='unlisted "'+$config+'" '+$token;$c.resolution_task_name=$c.watchdog_name+'_resolution'
 if($c.iis_original -notin @('Running','Stopped')){throw 'iis_transitional_state'}
 Save-Private $config $c;Save-Private (Join-Path $root 'lease.json') @{phase='prepared'}
 Save-Private (Join-Path $root 'proxy.json') @{hosts=$pins;port=18731;seconds=600;log=(Join-Path $root 'proxy-private.jsonl');transparent=$true}
 Save-Private output/g14-private-recovery-pointer.json @{config=$config}
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
 $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(240);$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $null=Register-ScheduledTask -TaskName $c.watchdog_name -Action $action -Trigger $trigger -Principal $principal
 if(-not (Get-ScheduledTask -TaskName $c.watchdog_name)){throw 'independent_watchdog_missing'}
 $leaseAnchor=Enter-Lease $c;$leaseAnchor.ReleaseMutex()
 $r.stage='supervisor_start'
 $supervisor=Start-Process $ps -ArgumentList ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$c.supervisor_script+'" -Config "'+$config+'"') -PassThru -WindowStyle Hidden
 Record-Process $supervisor (Join-Path $root 'supervisor-process.json')
 $r.stage='wait_ready';$receiptPath=Join-Path $root 'supervisor-ready.json';$watch=[Diagnostics.Stopwatch]::StartNew()
 while(-not (Test-Path $receiptPath) -and $watch.Elapsed.TotalSeconds -lt 140){
  if(Test-Path (Join-Path $root 'supervisor-error.json')){$e=Get-Content -Raw (Join-Path $root 'supervisor-error.json') | ConvertFrom-Json;$r.supervisor_diagnostic=$e;throw $e.error_code}
  if($supervisor.HasExited){throw 'supervisor_exited_before_ready'};Start-Sleep -Milliseconds 250
 }
 Wait-File $receiptPath 1;$ready=Get-Content -Raw $receiptPath | ConvertFrom-Json
 $r.gate_ready=($ready.gate_verified -and $ready.direct_denied -and $ready.via_gate_ok -and $ready.root_and_leaf_member -and $ready.service_and_task_outside)
 $r.stage='baseline_and_monitor'
 $monitorAction=New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $root 'Monitor.ps1')+'" -Config "'+$config+'"')
 $resolveAction=New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$c.watchdog_script+'" -Config "'+$config+'" -Origin resolution')
 $null=Register-ScheduledTask -TaskName $c.monitor_task_name -Action $monitorAction -Principal $principal
 $null=Register-ScheduledTask -TaskName $c.resolution_task_name -Action $resolveAction -Principal $principal
 . (Join-Path $root 'Inventory.ps1');$null=[Reflection.Assembly]::LoadFrom($c.exe)
 Save-Private (Join-Path $root 'registration-baseline.json') (Get-RegistrationSnapshot)
 Start-ScheduledTask $c.monitor_task_name;Wait-File (Join-Path $root 'monitor-ready.json') 15;Wait-File (Join-Path $root 'monitor-baseline-checked.json') 45
 $r.monitor_system=((Get-Content -Raw (Join-Path $root 'monitor-ready.json') | ConvertFrom-Json).system_identity -eq $true)
 $r.global_baseline_clean=((Get-Content -Raw (Join-Path $root 'monitor-baseline-checked.json') | ConvertFrom-Json).clean -eq $true)
 $injectionWatch=[Diagnostics.Stopwatch]::StartNew();$r.stage='inject_external_component';$m=Enter-Lease $c
 try{
  if((Get-FileHash $c.outside_exe -Algorithm SHA256).Hash -ne $c.outside_hash){throw 'outside_fixture_hash_changed'}
  if($c.scenario -eq 'outside_service'){
   $null=New-Service -Name $c.outside_service_name -BinaryPathName $c.outside_service_command -StartupType Manual;Start-Service $c.outside_service_name
  }elseif($c.scenario -eq 'outside_task'){
   $oa=New-ScheduledTaskAction -Execute $c.outside_exe -Argument $c.outside_task_arguments
   $null=Register-ScheduledTask -TaskName $c.outside_task_name -Action $oa -Principal $principal;Start-ScheduledTask $c.outside_task_name
  }else{$null=New-Item -ItemType File (Join-Path $root 'inject-foreign-child')}
  Wait-File $c.outside_receipt 15
  $outsideIdentity=Get-Content -Raw $c.outside_receipt | ConvertFrom-Json
  if(-not [string]::Equals($outsideIdentity.image,$c.outside_exe,[StringComparison]::OrdinalIgnoreCase)){throw 'outside_fixture_identity_changed'}
  $op=Open-Verified $outsideIdentity;if(-not $op){throw 'outside_fixture_not_alive'};$op.Dispose()
 }finally{$m.ReleaseMutex();$m.Dispose()}
 $r.stage='await_live_quarantine';Wait-File (Join-Path $root 'monitor-alert.json') 50;Wait-File (Join-Path $root 'recovery-result.json') 50;Wait-File (Join-Path $root 'monitor-result.json') 10
 $r.quarantine_elapsed_seconds=[Math]::Round($injectionWatch.Elapsed.TotalSeconds,2)
 $alert=Get-Content -Raw (Join-Path $root 'monitor-alert.json') | ConvertFrom-Json
 $recovery=Get-Content -Raw (Join-Path $root 'recovery-result.json') | ConvertFrom-Json
 $expected=if($c.scenario -eq 'outside_service'){$alert.service_change_count -gt 0 -and $recovery.unknown_service_detected}elseif($c.scenario -eq 'outside_task'){$alert.task_change_count -gt 0 -and $recovery.unknown_task_detected}else{$alert.foreign_job_member -and $recovery.foreign_job_member}
 $r.monitor_detected=($alert.system_identity -and $alert.status -eq 'unclassified_change_detected' -and $expected)
 $op=Open-Verified $outsideIdentity;$r.unknown_alive_while_quarantined=($null -ne $op);if($op){$op.Dispose()}
 $direct=Invoke-Canary $c 'canary';$via=Invoke-Canary $c 'via_gate';$r.direct_denied=(-not $direct.connected);$r.proxy_connection_denied=(-not $via.connected)
 $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore)
 $r.default_block_retained=($profiles.Count -eq 3 -and @($profiles | Where-Object {-not $_.Enabled -or [string]$_.DefaultOutboundAction -ne 'Block'}).Count -eq 0)
 $r.quarantine_refusal_verified=($recovery.origin -eq 'monitor' -and $recovery.system_identity -and $recovery.restore_refused_for_unknown -and $recovery.gate_proxy_closed -and $recovery.status -eq 'stopped' -and -not $recovery.hosts_restored -and -not $recovery.firewall_restored -and $r.unknown_alive_while_quarantined -and $r.direct_denied -and $r.proxy_connection_denied -and $r.default_block_retained)
 if(-not ($r.monitor_detected -and $r.quarantine_refusal_verified)){throw 'live_quarantine_not_verified'}
 Copy-Item (Join-Path $root 'recovery-result.json') ('output/recovery-denied-g14-'+$c.scenario+'.json')
 Copy-Item (Join-Path $root 'monitor-alert.json') ('output/monitor-g14-'+$c.scenario+'.json')
 $r.stage='explicit_test_resolution';$m=Enter-Lease $c
 try{
  if((Get-FileHash $c.outside_exe -Algorithm SHA256).Hash -ne $c.outside_hash){throw 'outside_fixture_hash_changed'}
  $op=Open-Verified $outsideIdentity;if(-not $op){throw 'outside_identity_missing_before_resolution'}
  try{
   if($c.scenario -eq 'outside_service'){
    $svc=Get-CimInstance Win32_Service -Filter ("Name='"+$c.outside_service_name+"'")
    if($svc.PathName -ne $c.outside_service_command){throw 'outside_service_definition_changed'}
    Stop-Service $c.outside_service_name
    $ctl=Get-Service $c.outside_service_name;try{$ctl.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(10))}finally{$ctl.Dispose()}
    $null=& "$env:SystemRoot\System32\sc.exe" delete $c.outside_service_name;if($LASTEXITCODE -ne 0){throw 'outside_service_delete_failed'}
   }elseif($c.scenario -eq 'outside_task'){
    $ot=Get-ScheduledTask -TaskName $c.outside_task_name -TaskPath '\'
    if(@($ot.Actions).Count -ne 1 -or $ot.Actions[0].Execute -ne $c.outside_exe -or $ot.Actions[0].Arguments -ne $c.outside_task_arguments){throw 'outside_task_definition_changed'}
    $null=Disable-ScheduledTask $c.outside_task_name;Stop-ScheduledTask $c.outside_task_name;Unregister-ScheduledTask $c.outside_task_name -Confirm:$false
   }else{$op.Kill()}
   if(-not $op.WaitForExit(5000)){throw 'outside_fixture_survived_resolution'}
  }finally{$op.Dispose()}
  $r.unknown_explicitly_removed=$true
  Move-Item (Join-Path $root 'recovery-result.json') (Join-Path $root 'recovery-denied.json')
  Start-ScheduledTask $c.resolution_task_name
 }finally{$m.ReleaseMutex();$m.Dispose()}
 Wait-File (Join-Path $root 'recovery-result.json') 90;$recovery=Get-Content -Raw (Join-Path $root 'recovery-result.json') | ConvertFrom-Json
 $r.resolution_system=($recovery.origin -eq 'resolution' -and $recovery.system_identity -eq $true -and $recovery.status -eq 'recovered_after_verified_component_exit')
 $r.components_exited_before_restore=($recovery.supervisor_exited -and $recovery.job_active_zero -and $recovery.all_observed_members_exited -and $recovery.service_removed -and $recovery.task_removed -and $recovery.fixture_images_gone)
 $r.hosts_restored=$recovery.hosts_restored;$r.firewall_restored=$recovery.firewall_restored;$r.iis_restored=$recovery.iis_restored
 $r.recovery_error_code=$recovery.error_code;$r.recovery_error_shape=$recovery.error_shape
 if($r.resolution_system){$after=Invoke-Canary $c 'canary';$r.post_restore_direct_ok=($after.connected -and $after.http200)}
 foreach($name in @($c.monitor_task_name,$c.resolution_task_name)){Unregister-ScheduledTask $name -Confirm:$false}
 if($r.gate_ready -and $r.cross_identity_mutex_preflight -and $r.global_baseline_clean -and $r.monitor_system -and $r.monitor_detected -and $r.quarantine_refusal_verified -and $r.unknown_explicitly_removed -and $r.resolution_system -and $r.components_exited_before_restore -and $r.hosts_restored -and $r.firewall_restored -and $r.iis_restored -and $r.post_restore_direct_ok){$r.status='qualified_live_inventory_quarantine_and_controlled_resolution'}else{$r.error_code='inventory_quarantine_probes_failed'}
}catch{$r.failure_stage=$r.stage;$message=$_.Exception.Message;$r.error_code=if($message -match '^[a-z_]{1,80}$'){$message}else{'integration_operation_failed'}}
finally{
 if($supervisor){$supervisor.Dispose()};if($leaseAnchor){$leaseAnchor.Dispose()};$r.stage='complete';Save-Report
}
if($r.status -eq 'stopped'){throw 'integrated_recovery_qualification_stopped'}
