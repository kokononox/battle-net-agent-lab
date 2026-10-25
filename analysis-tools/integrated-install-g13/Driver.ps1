$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REF -ne 'refs/heads/research/battlenet-minimal-install-isolation-2026-10-25' -or $env:GITHUB_EVENT_NAME -ne 'push' -or $env:GITHUB_RUN_ATTEMPT -ne '1' -or $env:BNET_INTEGRATED_G13 -ne 'lab: approved startup-refusal qualification G13 20261025' -or $env:BNET_G13_SCENARIO -notin @('mid_owner_receipt','mid_service_before_task','unknown_fixture')){throw 'fresh_hosted_integration_required'}
. (Join-Path $PSScriptRoot 'Common.ps1')
New-Item -ItemType Directory -Force output | Out-Null
$r=[ordered]@{schema='bnet-integrated-g13-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;scenario=$env:BNET_G13_SCENARIO;status='stopped';installer_launched=$false;baseline_direct_ok=$false;cross_identity_mutex_preflight=$false;gate_ready=$false;root_and_leaf_in_job=$false;external_service_task_outside=$false;supervisor_crashed_as_requested=$false;abandoned_mutex_reclaimed=$false;unknown_refusal_verified=$false;unknown_resolution_system=$false;partial_checkpoint_verified=$false;fixtures_alive_at_failure=$false;fixtures_alive_after_failure=$false;post_scenario_direct_denied=$false;no_observed_direct_release_before_recovery=$true;independent_deadline_system_recovery=$false;components_exited_before_restore=$false;hosts_restored=$false;firewall_restored=$false;iis_restored=$false;post_restore_direct_ok=$false;full_install_boundary_proven=$false;arbitrary_service_discovery_proven=$false;mid_startup_crash_tested=$false;stage='prepare';error_code=$null;failure_stage=$null;supervisor_diagnostic=$null;recovery_error_code=$null;recovery_error_shape=$null}
$guid=[guid]::NewGuid().ToString('N');$root=Join-Path (Join-Path $env:ProgramData 'BNetIntegratedG13') $guid;$config=Join-Path $root 'config.json';$c=$null;$supervisor=$null;$leaseAnchor=$null
function Save-Report{$r | ConvertTo-Json -Depth 8 | Set-Content ('output/integrated-g13-'+$env:BNET_G13_SCENARIO+'.json') -Encoding UTF8;Write-Output ($r | ConvertTo-Json -Depth 8 -Compress)}
try{
 $null=New-Item -ItemType Directory -Force $root;$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){$identity=[Security.Principal.SecurityIdentifier]::new($sid);$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity,[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))}
 Set-Acl $root $acl
 foreach($name in @('Common.ps1','Supervisor.ps1','Recover.ps1','FirewallGate.ps1','LeaseProbe.ps1')){Copy-Item (Join-Path $PSScriptRoot $name) (Join-Path $root $name)}
 Copy-Item "$env:RUNNER_TEMP\bnet-g13-bin\ExternalProbe.exe" (Join-Path $root 'ExternalProbe.exe')
 Copy-Item (Join-Path $PSScriptRoot 'dist\TwoHostProxy.exe') (Join-Path $root 'TwoHostProxy.exe')
 $pinsText=& python -c "import socket,ipaddress,json; h=('level3.blizzard.com','us.version.battle.net'); d={n:sorted({x[4][0] for x in socket.getaddrinfo(n,80,type=socket.SOCK_STREAM) if ipaddress.ip_address(x[4][0]).is_global},key=lambda a:(':' in a,a)) for n in h}; assert all(1<=len(v)<=32 for v in d.values()); print(json.dumps(d))"
 if($LASTEXITCODE -ne 0){throw 'pins_resolution_failed'};$pins=$pinsText | ConvertFrom-Json
 $v4=@($pins.'us.version.battle.net' | Where-Object {$_ -notmatch ':'});if($v4.Count -eq 0){throw 'ipvfour_fixture_missing'}
 $exe=Join-Path $root 'ExternalProbe.exe';$token=[guid]::NewGuid().ToString('N');$ps="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
 $c=[ordered]@{scenario=$env:BNET_G13_SCENARIO;pause_owner_receipt=($env:BNET_G13_SCENARIO -eq 'mid_owner_receipt');root=$root;token=$token;exe=$exe;proxy_exe=(Join-Path $root 'TwoHostProxy.exe');service_name=('BNetLabG13_'+$guid+'_svc');task_name=('BNetLabG13_'+$guid+'_task');watchdog_name=('BNetLabG13_'+$guid+'_recovery');job_name=('Global\BNetLabG13_'+$guid);mutex_name=('Global\BNetG13Lease_'+$guid);expires_ticks=[DateTime]::UtcNow.AddMinutes(8).Ticks;canary_ip=$v4[0];service_command=('"'+$exe+'" service "'+$config+'" '+$token);task_arguments=('task "'+$config+'" '+$token);source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;iis_original=[string](Get-Service W3SVC).Status;supervisor_script=(Join-Path $root 'Supervisor.ps1');watchdog_script=(Join-Path $root 'Recover.ps1')}
 $c.unlisted_task_name='BNetLabG13_'+$guid+'_unlisted';$c.unlisted_task_arguments='unlisted "'+$config+'" '+$token;$c.resolution_task_name=$c.watchdog_name+'_resolution'
 if($c.iis_original -notin @('Running','Stopped')){throw 'iis_transitional_state'}
 Save-Private $config $c;Save-Private (Join-Path $root 'lease.json') @{phase='prepared'}
 Save-Private (Join-Path $root 'proxy.json') @{hosts=$pins;port=18731;seconds=600;log=(Join-Path $root 'proxy-private.jsonl');transparent=$true}
 Save-Private output/g13-private-recovery-pointer.json @{config=$config}
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
 $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(180);$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $null=Register-ScheduledTask -TaskName $c.watchdog_name -Action $action -Trigger $trigger -Principal $principal
 if(-not (Get-ScheduledTask -TaskName $c.watchdog_name)){throw 'independent_watchdog_missing'}
 $leaseAnchor=Enter-Lease $c;$leaseAnchor.ReleaseMutex()
 $r.stage='supervisor_start'
 $supervisor=Start-Process $ps -ArgumentList ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$c.supervisor_script+'" -Config "'+$config+'"') -PassThru -WindowStyle Hidden
 Record-Process $supervisor (Join-Path $root 'supervisor-process.json')
 $partial=($c.scenario -ne 'unknown_fixture')
 $receiptName=if($partial){'startup-checkpoint.json'}else{'supervisor-ready.json'}
 $receiptPath=Join-Path $root $receiptName;$watch=[Diagnostics.Stopwatch]::StartNew()
 while(-not (Test-Path $receiptPath) -and $watch.Elapsed.TotalSeconds -lt 140){
  if(Test-Path (Join-Path $root 'supervisor-error.json')){$e=Get-Content -Raw (Join-Path $root 'supervisor-error.json') | ConvertFrom-Json;$r.supervisor_diagnostic=$e;throw $e.error_code}
  if($supervisor.HasExited){throw 'supervisor_exited_before_checkpoint'};Start-Sleep -Milliseconds 250
 }
 Wait-File $receiptPath 1
 $ready=Get-Content -Raw $receiptPath | ConvertFrom-Json;$r.gate_ready=($ready.gate_verified -and $ready.direct_denied -and $ready.via_gate_ok)
 $rootState=Get-Content -Raw (Join-Path $root 'root.json') | ConvertFrom-Json;$leafState=Get-Content -Raw (Join-Path $root 'leaf.json') | ConvertFrom-Json
 $r.root_and_leaf_in_job=($rootState.job_member -eq $true -and $leafState.job_member -eq $true)
 $kinds=@('root','leaf','owner-process')
 if($c.scenario -eq 'mid_owner_receipt'){
  $r.partial_checkpoint_verified=($ready.phase -eq 'owner_before_ready_receipt' -and -not (Test-Path (Join-Path $root 'owner.json')) -and -not (Get-Service $c.service_name -ErrorAction SilentlyContinue) -and -not (Get-ScheduledTask $c.task_name -ErrorAction SilentlyContinue))
 }elseif($c.scenario -eq 'mid_service_before_task'){
  $kinds+=@('service');$serviceState=Get-Content -Raw (Join-Path $root 'service.json') | ConvertFrom-Json
  $r.external_service_task_outside=($serviceState.job_member -eq $false)
  $r.partial_checkpoint_verified=($ready.phase -eq 'service_started_task_not_registered' -and (Test-Path (Join-Path $root 'owner.json')) -and -not (Get-ScheduledTask $c.task_name -ErrorAction SilentlyContinue))
 }else{
  $kinds+=@('service','task');$r.external_service_task_outside=$ready.service_and_task_outside
  # Inject exactly one controlled unexpected fixture. It is intentionally absent from the authorized ledger.
  $m=Enter-Lease $c
  try{
   $uAction=New-ScheduledTaskAction -Execute $c.exe -Argument $c.unlisted_task_arguments
   $null=Register-ScheduledTask -TaskName $c.unlisted_task_name -Action $uAction -Principal $principal
   Start-ScheduledTask $c.unlisted_task_name;Wait-File (Join-Path $root 'unlisted.json') 15
   $unlisted=Get-Content -Raw (Join-Path $root 'unlisted.json') | ConvertFrom-Json
   if($unlisted.job_member -ne $false){throw 'unknown_fixture_not_external'}
   $unlisted | Add-Member -NotePropertyName image -NotePropertyValue $c.exe -Force
   $up=Open-Verified $unlisted;if(-not $up){throw 'unknown_fixture_not_alive'};$up.Dispose()
  }finally{$m.ReleaseMutex();$m.Dispose()}
 }
 function Test-KnownAlive {
  foreach($kind in $kinds){
   $id=Get-Content -Raw (Join-Path $root ($kind+'.json')) | ConvertFrom-Json;$id | Add-Member -NotePropertyName image -NotePropertyValue $c.exe -Force
   $proc=Open-Verified $id;if(-not $proc){return $false};$proc.Dispose()
  };return $true
 }
 $r.fixtures_alive_at_failure=Test-KnownAlive;if(-not $r.fixtures_alive_at_failure){throw 'fixture_ended_before_failure'}
 $r.stage='inject_failure';$supervisor.Kill();$r.supervisor_crashed_as_requested=$supervisor.WaitForExit(5000)
 $r.fixtures_alive_after_failure=Test-KnownAlive
 # Do NOT acquire the abandoned mutex here: only SYSTEM recovery may first reclaim it.
 # One bounded probe well before the fixed deadline; no process launches while recovery runs.
 $probe=Invoke-Canary $c 'canary';$r.post_scenario_direct_denied=(-not $probe.connected)
 $r.no_observed_direct_release_before_recovery=$r.post_scenario_direct_denied
 $r.stage='await_independent_recovery';Wait-File (Join-Path $root 'recovery-result.json') 240
 $recovery=Get-Content -Raw (Join-Path $root 'recovery-result.json') | ConvertFrom-Json
 $r.independent_deadline_system_recovery=($recovery.origin -eq 'deadline' -and $recovery.system_identity -eq $true)
 $r.abandoned_mutex_reclaimed=$recovery.abandoned_mutex_reclaimed
 if($c.scenario -eq 'unknown_fixture'){
  $r.stage='verify_unknown_refusal'
  $up=Open-Verified $unlisted;$unknownAlive=($null -ne $up);if($up){$up.Dispose()}
  $deny=Invoke-Canary $c 'canary';$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore)
  $blocked=(@($profiles | Where-Object { -not $_.Enabled -or [string]$_.DefaultOutboundAction -ne 'Block'}).Count -eq 0 -and $profiles.Count -eq 3)
  $r.unknown_refusal_verified=($r.independent_deadline_system_recovery -and $recovery.status -eq 'stopped' -and $recovery.error_code -eq 'unclassified_fixture_component_blocks_restore' -and $recovery.unknown_task_detected -and $recovery.unknown_process_detected -and $recovery.restore_refused_for_unknown -and -not $recovery.firewall_restored -and -not $recovery.hosts_restored -and $unknownAlive -and -not $deny.connected -and $blocked)
  if(-not $r.unknown_refusal_verified){throw 'unknown_refusal_not_verified'}
  # Explicit test-harness resolution, never automatic recovery of an unknown component.
  $r.stage='controlled_unknown_resolution';$m=Enter-Lease $c
  try{
   $ut=Get-ScheduledTask -TaskName $c.unlisted_task_name -TaskPath '\'
   if(@($ut.Actions).Count -ne 1 -or $ut.Actions[0].Execute -ne $c.exe -or $ut.Actions[0].Arguments -ne $c.unlisted_task_arguments){throw 'unlisted_task_identity_changed'}
   $up=Open-Verified $unlisted;if(-not $up){throw 'unlisted_process_identity_missing'}
   try{
    $null=Disable-ScheduledTask $c.unlisted_task_name;Stop-ScheduledTask $c.unlisted_task_name;Unregister-ScheduledTask $c.unlisted_task_name -Confirm:$false
    if(-not $up.WaitForExit(5000)){throw 'unlisted_process_survived'}
   }finally{$up.Dispose()}
   Copy-Item (Join-Path $root 'recovery-result.json') ('output/recovery-denied-g13-'+$c.scenario+'.json')
   Move-Item (Join-Path $root 'recovery-result.json') (Join-Path $root 'recovery-denied.json')
   $resolveAction=New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$c.watchdog_script+'" -Config "'+$config+'" -Origin resolution')
   $null=Register-ScheduledTask -TaskName $c.resolution_task_name -Action $resolveAction -Principal $principal
   Start-ScheduledTask $c.resolution_task_name
  }finally{$m.ReleaseMutex();$m.Dispose()}
  Wait-File (Join-Path $root 'recovery-result.json') 90
  $recovery=Get-Content -Raw (Join-Path $root 'recovery-result.json') | ConvertFrom-Json
  $r.unknown_resolution_system=($recovery.origin -eq 'resolution' -and $recovery.system_identity -eq $true)
  Unregister-ScheduledTask $c.resolution_task_name -Confirm:$false
 }
 $r.recovery_error_code=$recovery.error_code;$r.recovery_error_shape=$recovery.error_shape
 $r.components_exited_before_restore=($recovery.supervisor_exited -and $recovery.job_active_zero -and $recovery.all_observed_members_exited -and $recovery.service_removed -and $recovery.task_removed -and $recovery.fixture_images_gone)
 $r.hosts_restored=$recovery.hosts_restored;$r.firewall_restored=$recovery.firewall_restored;$r.iis_restored=$recovery.iis_restored
 if($recovery.status -eq 'recovered_after_verified_component_exit'){$after=Invoke-Canary $c 'canary';$r.post_restore_direct_ok=($after.connected -and $after.http200)}
 $expected=if($partial){$r.partial_checkpoint_verified -and $r.abandoned_mutex_reclaimed}else{$r.unknown_refusal_verified -and $r.unknown_resolution_system}
 if($r.gate_ready -and $r.cross_identity_mutex_preflight -and $r.fixtures_alive_after_failure -and $r.root_and_leaf_in_job -and $r.supervisor_crashed_as_requested -and $expected -and $r.post_scenario_direct_denied -and $r.independent_deadline_system_recovery -and $r.components_exited_before_restore -and $r.hosts_restored -and $r.firewall_restored -and $r.iis_restored -and $r.post_restore_direct_ok){
  $r.status=if($partial){'qualified_partial_startup_deadline_recovery'}else{'qualified_unknown_refusal_then_controlled_resolution'}
  $r.mid_startup_crash_tested=$partial
 }else{$r.error_code='startup_refusal_probes_failed'}
}catch{$r.failure_stage=$r.stage;$message=$_.Exception.Message;$r.error_code=if($message -match '^[a-z_]{1,80}$'){$message}else{'integration_operation_failed'}}
finally{
 if($supervisor){$supervisor.Dispose()};if($leaseAnchor){$leaseAnchor.Dispose()};$r.stage='complete';Save-Report
}
if($r.status -eq 'stopped'){throw 'integrated_recovery_qualification_stopped'}
