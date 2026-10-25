$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REF -ne 'refs/heads/research/battlenet-minimal-install-isolation-2026-10-25' -or $env:GITHUB_EVENT_NAME -ne 'push' -or $env:GITHUB_RUN_ATTEMPT -ne '1' -or $env:BNET_EXTERNAL_G10 -ne 'lab: approved external-components qualification G10 20261025'){throw 'fresh_hosted_approval_required'}
New-Item -ItemType Directory -Force output | Out-Null
$r=[ordered]@{schema='bnet-external-components-g10-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;status='stopped';stage='prepare';installer_launched=$false;network_policy_changed=$false;actual_network_release_tested=$false;arbitrary_service_discovery_proven=$false;service_outside_job=$false;task_outside_job=$false;service_survived_owner_crash=$false;task_survived_owner_crash=$false;service_stopped=$false;task_stopped=$false;release_denied_while_both_alive=$false;release_denied_while_task_alive=$false;release_denied_for_unknown=$false;release_denied_for_unhealthy_coverage=$false;release_allowed_after_known_exits=$false;cleanup_verified=$false;error_code=$null}
$id=[guid]::NewGuid().ToString('N');$root=Join-Path (Join-Path $env:ProgramData 'BNetExternalG10') $id;$config=Join-Path $root 'config.json';$script:owner=$null;$serviceProcess=$null;$taskProcess=$null
function Save-Report{$r | ConvertTo-Json -Depth 5 | Set-Content output/external-components-g10.json -Encoding UTF8}
function Release-Allowed([bool]$ownerGone,[bool]$serviceGone,[bool]$taskGone,[bool]$unknown,[bool]$coverageHealthy){return $ownerGone -and $serviceGone -and $taskGone -and (-not $unknown) -and $coverageHealthy}
function Wait-Ready([string]$kind){
 $path=Join-Path $root ($kind+'.json');$watch=[Diagnostics.Stopwatch]::StartNew()
 while(-not (Test-Path $path) -and $watch.Elapsed.TotalSeconds -lt 15){Start-Sleep -Milliseconds 100}
 if(-not (Test-Path $path)){throw ('ready_missing_'+$kind)}
 $v=Get-Content -Raw $path | ConvertFrom-Json
 $p=Get-Process -Id $v.pid -ErrorAction Stop;$null=$p.Handle
 if($p.StartTime.ToFileTimeUtc() -ne [long]$v.created -or -not [string]::Equals($p.MainModule.FileName,$c.exe,[StringComparison]::OrdinalIgnoreCase)){throw 'fixture_process_identity_mismatch'}
 return @{process=$p;state=$v}
}
try{
 if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'administrator_required'}
 $null=New-Item -ItemType Directory -Force $root
 # No inherited user-write access. Only SYSTEM and Administrators own lab inputs.
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  $identity=[Security.Principal.SecurityIdentifier]::new($sid)
  $rule=[Security.AccessControl.FileSystemAccessRule]::new($identity,[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
  $acl.AddAccessRule($rule)
 }
 Set-Acl -Path $root -AclObject $acl
 $exe=Join-Path $root 'ExternalProbe.exe';Copy-Item "$env:RUNNER_TEMP\bnet-g10-bin\ExternalProbe.exe" $exe
 Copy-Item analysis-tools/external-install/cleanup.ps1 (Join-Path $root 'cleanup.ps1')
 $token=[guid]::NewGuid().ToString('N');$taskArgs='task "'+$config+'" '+$token
 $serviceCommand='"'+$exe+'" service "'+$config+'" '+$token
 $c=[ordered]@{root=$root;token=$token;service_name=('BNetLabG10_'+$id+'_svc');task_name=('BNetLabG10_'+$id+'_task');watchdog_name=('BNetLabG10_'+$id+'_recovery');job_name=('Global\BNetLabG10_'+$id);exe=$exe;service_command=$serviceCommand;task_arguments=$taskArgs;source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;expires_ticks=[DateTime]::UtcNow.AddMinutes(8).Ticks}
 $c | ConvertTo-Json | Set-Content $config -Encoding UTF8
 # Recovery intent is recorded before service/task creation.
 @{config=$config} | ConvertTo-Json | Set-Content output/g10-private-recovery-pointer.json -Encoding UTF8
 $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $root 'cleanup.ps1')+'" -Config "'+$config+'"')
 $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(3)
 $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $null=Register-ScheduledTask -TaskName $c.watchdog_name -Action $action -Trigger $trigger -Principal $principal
 if(-not (Get-ScheduledTask -TaskName $c.watchdog_name)){throw 'recovery_task_missing'}
 $r.stage='start_owner';$script:owner=Start-Process -FilePath $exe -ArgumentList ('owner "'+$config+'" '+$token) -PassThru -WindowStyle Hidden
 $ownerReady=Wait-Ready 'owner'
 $r.stage='start_service';$null=New-Service -Name $c.service_name -BinaryPathName $c.service_command -StartupType Manual
 Start-Service $c.service_name;$svc=Wait-Ready 'service';$serviceProcess=$svc.process;$r.service_outside_job=($svc.state.job_member -eq $false)
 $r.stage='start_task';$taskAction=New-ScheduledTaskAction -Execute $exe -Argument $taskArgs
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
 $null=Register-ScheduledTask -TaskName $c.task_name -Action $taskAction -Principal $principal -Settings $settings
 Start-ScheduledTask $c.task_name;$task=Wait-Ready 'task';$taskProcess=$task.process;$r.task_outside_job=($task.state.job_member -eq $false)
 $r.stage='owner_crash';$script:owner.Kill();if(-not $script:owner.WaitForExit(5000)){throw 'owner_survived'}
 $r.service_survived_owner_crash=(-not $serviceProcess.WaitForExit(500));$r.task_survived_owner_crash=(-not $taskProcess.WaitForExit(500))
 $r.release_denied_while_both_alive=(-not (Release-Allowed $true $false $false $false $true))
 $r.release_denied_for_unknown=(-not (Release-Allowed $true $true $true $true $true))
 $r.release_denied_for_unhealthy_coverage=(-not (Release-Allowed $true $true $true $false $false))
 $r.stage='stop_service';$service=Get-CimInstance Win32_Service -Filter ("Name='"+$c.service_name+"'")
 if($service.PathName -ne $c.service_command){throw 'service_identity_changed'}
 Set-Service $c.service_name -StartupType Disabled;Stop-Service $c.service_name
 $controller=Get-Service $c.service_name;try{$controller.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(10))}finally{$controller.Dispose()};$r.service_stopped=$serviceProcess.WaitForExit(5000)
 $r.release_denied_while_task_alive=(-not (Release-Allowed $true $r.service_stopped $false $false $true)) -and (-not $taskProcess.HasExited)
 $r.stage='stop_task';$definition=Get-ScheduledTask -TaskName $c.task_name
 if(@($definition.Actions).Count -ne 1 -or $definition.Actions[0].Execute -ne $c.exe -or $definition.Actions[0].Arguments -ne $taskArgs){throw 'task_identity_changed'}
 $null=Disable-ScheduledTask -TaskName $c.task_name
 $null=New-Item -ItemType File -Force (Join-Path $root 'stop-task');Stop-ScheduledTask -TaskName $c.task_name
 $r.task_stopped=$taskProcess.WaitForExit(5000)
 $r.release_allowed_after_known_exits=Release-Allowed $script:owner.HasExited $r.service_stopped $r.task_stopped $false $true
 if($r.service_outside_job -and $r.task_outside_job -and $r.service_survived_owner_crash -and $r.task_survived_owner_crash -and $r.service_stopped -and $r.task_stopped -and $r.release_denied_while_both_alive -and $r.release_denied_while_task_alive -and $r.release_denied_for_unknown -and $r.release_denied_for_unhealthy_coverage -and $r.release_allowed_after_known_exits){$r.status='qualified_known_external_fixture_lifecycle_and_release_logic'}else{$r.error_code='fixture_probe_failed'}
}catch{
 $text=$_.Exception.Message;$r.error_code=if($text -match '^[a-z_]{1,80}$'){$text}else{'fixture_operation_failed'}
}finally{
 $r.stage='cleanup'
 foreach($p in @($ownerReady.process,$serviceProcess,$taskProcess,$script:owner)){if($p){try{$p.Dispose()}catch{}}}
 try{
  if(Test-Path $config){& (Join-Path $root 'cleanup.ps1') -Config $config;$cleanup=Get-Content -Raw (Join-Path $root 'cleanup-result.json') | ConvertFrom-Json;$r.cleanup_verified=($cleanup.verified -eq $true)}
 }catch{$r.cleanup_verified=$false}
 if(-not $r.cleanup_verified){$r.status='stopped';$r.error_code='cleanup_not_verified'}
 $r.stage='complete';Save-Report
}
if($r.status -eq 'stopped'){throw 'external_fixture_qualification_stopped'}
