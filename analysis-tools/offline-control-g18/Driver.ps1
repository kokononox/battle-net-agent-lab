$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REF -ne 'refs/heads/research/battlenet-minimal-install-isolation-2026-10-25' -or $env:GITHUB_EVENT_NAME -ne 'push' -or $env:GITHUB_RUN_ATTEMPT -ne '1' -or $env:BNET_OFFLINE_G18 -ne 'lab: approved matched offline BITS G18 20261025'){throw 'fresh_hosted_required'}
$scenario=$env:BNET_G18_SCENARIO;if($scenario -notin @('no_setup','real_setup')){throw 'scenario_refused'}
. (Join-Path $PSScriptRoot 'Common.ps1');. (Join-Path $PSScriptRoot 'Inventory.ps1')
New-Item -ItemType Directory -Force output | Out-Null
$guid=[guid]::NewGuid().ToString('N');$root=Join-Path (Join-Path $env:ProgramData 'BNetOfflineG18') $guid;$config=Join-Path $root 'config.json';$c=$null;$owner=$null;$ui=$null
$r=[ordered]@{scenario=$scenario;observation_seconds=90;stage='prepare';gate_verified_before_launch=$false;gate_verified_after_observation=$false;baseline_canary_connected=$false;blocked_canary_connected=$null;post_restore_canary_connected=$null;target_launch_attempted=$false;target_launched=$null;owner_exit_confirmed=$false;error_code=$null;failure_stage=$null}
try{
 $null=New-Item -ItemType Directory -Force $root;$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){$s=[Security.Principal.SecurityIdentifier]::new($sid);$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($s,[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))};Set-Acl $root $acl
 Save-Private output/g18-private-pointer.json @{root=$root}
 foreach($name in @('Common.ps1','FirewallGate.ps1','Inventory.ps1','Recover.ps1','Snapshot.ps1')){Copy-Item (Join-Path $PSScriptRoot $name) (Join-Path $root $name)}
 Copy-Item "$env:RUNNER_TEMP\bnet-g18-bin\OfflineLauncher.exe" (Join-Path $root 'OfflineLauncher.exe')
 $stageTemp=Join-Path $root 'stage-temp';$null=New-Item -ItemType Directory $stageTemp
 $envChild=@{};foreach($key in @('SystemRoot','windir','SystemDrive','ProgramFiles','ProgramFiles(x86)','ProgramW6432','ProgramData','LOCALAPPDATA','APPDATA','USERPROFILE','COMSPEC')){$v=[Environment]::GetEnvironmentVariable($key);if($v){$envChild[$key]=$v}}
 $envChild['TEMP']=$stageTemp;$envChild['TMP']=$stageTemp;$envChild['PATH']="$env:SystemRoot\System32;$env:SystemRoot"
 $ip=& python -c "import socket,ipaddress; a=sorted({x[4][0] for x in socket.getaddrinfo('us.version.battle.net',1119,socket.AF_INET,socket.SOCK_STREAM) if ipaddress.ip_address(x[4][0]).is_global}); assert a; print(a[0])"
 if($LASTEXITCODE -ne 0){throw 'canary_resolution_failed'}
 $c=@{scenario=$scenario;root=$root;setup=(Join-Path $root 'Battle.net-Setup.exe');helper=(Join-Path $root 'OfflineLauncher.exe');job_name=('Global\BNetOfflineG18_'+$guid);watchdog_name=('BNetOfflineG18_'+$guid+'_recovery');cleanup_task_name=('BNetOfflineG18_'+$guid+'_cleanup');snapshot_task_name=('BNetOfflineG18_'+$guid+'_snapshot');mutex_name=('Global\BNetOfflineG18Lease_'+$guid);canary_ip=[string]$ip;signature_accepted=$false;child_environment=$envChild;iis_original=[string](Get-Service W3SVC).Status;target_roots=@((Join-Path ${env:ProgramFiles(x86)} 'Battle.net'),(Join-Path $env:ProgramData 'Battle.net'),(Join-Path $env:ProgramData 'Blizzard Entertainment'),(Join-Path $env:LOCALAPPDATA 'Battle.net'),$root)}
 foreach($path in @($c.target_roots | Where-Object {$_ -ne $root})){if(Test-Path $path){throw 'preexisting_battlenet_directory'}}
 if(@(Get-Process -Name 'Battle.net-Setup','Battle.net','Agent','BlizzardError' -ErrorAction SilentlyContinue).Count -gt 0){throw 'preexisting_target_process'}
 Save-Private $config $c;Save-Private (Join-Path $root 'lease.json') @{phase='prepared'}
 $r.stage='identity';Write-Host 'G18_STAGE:identity'
 & python (Join-Path $PSScriptRoot 'Prepare.py') $root
 if($LASTEXITCODE -ne 0){$r.target_launched=$false;throw 'setup_preflight_stopped'}
 $meta=Get-Content -Raw (Join-Path $root 'preflight.json') | ConvertFrom-Json;if(-not ($meta.matches_pin -and $meta.signature_accepted -and $meta.ui_helper_ready)){throw 'identity_not_accepted'}
 $c.signature_accepted=$true;Save-Private $config $c
 $before=(& $c.helper canary $config | ConvertFrom-Json);$r.baseline_canary_connected=$before.connected;if(-not $before.connected){throw 'baseline_canary_not_healthy'}
 $ps="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe";$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds 90)
 foreach($origin in @('deadline','explicit','snapshot')){
  $name=if($origin -eq 'deadline'){$c.watchdog_name}elseif($origin -eq 'snapshot'){$c.snapshot_task_name}else{$c.cleanup_task_name}
  $action=New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $root 'Recover.ps1')+'" -Config "'+$config+'" -Origin '+$origin)
  if($origin -eq 'snapshot'){$action=New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $root 'Snapshot.ps1')+'" -Config "'+$config+'"')}
  if($origin -eq 'deadline'){$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(210);$null=Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Trigger $trigger -Settings $settings}else{$taskSettings=if($origin -eq 'snapshot'){New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds 180)}else{$settings};$null=Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $taskSettings}
 }
 Save-Private (Join-Path $root 'snapshot-phase.json') @{value='baseline'};Start-ScheduledTask $c.snapshot_task_name;Wait-File (Join-Path $root 'system-baseline-receipt.json') 40
 $baseReceipt=Get-Content -Raw (Join-Path $root 'system-baseline-receipt.json') | ConvertFrom-Json;if(-not $baseReceipt.system_identity -or -not $baseReceipt.captured){throw 'system_baseline_not_verified'}
 $r.stage='offline_gate';Write-Host 'G18_STAGE:offline_gate';$null=Invoke-Gate $c 'Prepare'
 if($c.iis_original -eq 'Running'){Stop-Service W3SVC}
 $gate=Invoke-Gate $c 'Apply';$r.gate_verified_before_launch=($gate.verified -and $gate.target_allow_rules -eq 0)
 Save-Private (Join-Path $root 'lease.json') @{phase='active'}
 $blocked=(& $c.helper canary $config | ConvertFrom-Json);$r.blocked_canary_connected=$blocked.connected
 if(-not $r.gate_verified_before_launch -or $blocked.connected){throw 'offline_gate_not_verified'}
 Save-Private (Join-Path $root 'snapshot-phase.json') @{value='prelaunch'};Start-ScheduledTask $c.snapshot_task_name;Wait-File (Join-Path $root 'system-prelaunch-receipt.json') 40
 $preReceipt=Get-Content -Raw (Join-Path $root 'system-prelaunch-receipt.json') | ConvertFrom-Json;if(-not $preReceipt.system_identity -or $preReceipt.registration_changes -ne 0 -or $preReceipt.bits_added -ne 0 -or $preReceipt.bits_modified -ne 0){$r.target_launched=$false;throw 'registration_drift_before_target'}
 if($scenario -eq 'no_setup'){
  $r.stage='observe_no_setup_control';$r.target_launched=$false;Write-Host 'G18_STAGE:observe_no_setup_control';Start-Sleep -Seconds 90
 }else{
 $r.stage='real_setup_launch';Write-Host 'G18_STAGE:real_setup_launch';$r.target_launch_attempted=$true;Save-Private (Join-Path $root 'launch-attempted.json') @{attempted=$true}
 $owner=Start-Process $c.helper -ArgumentList ('run "'+$config+'"') -PassThru -RedirectStandardOutput (Join-Path $root 'owner-stdout.private.txt') -RedirectStandardError (Join-Path $root 'owner-stderr.private.txt')
 Record-Process $owner (Join-Path $root 'owner-process.json')
 Wait-File (Join-Path $root 'launch-state.json') 20;$launch=Get-Content -Raw (Join-Path $root 'launch-state.json') | ConvertFrom-Json;$r.target_launched=$launch.target_launched
 $r.stage='observe_bootstrap';Write-Host 'G18_STAGE:observe_bootstrap'
 $python=(Get-Command python).Source;$ui=Start-Process $python -ArgumentList ('"'+(Join-Path $PSScriptRoot 'ObserveUI.py')+'" "'+$root+'"') -PassThru -RedirectStandardOutput (Join-Path $root 'ui-stdout.private.txt') -RedirectStandardError (Join-Path $root 'ui-stderr.private.txt')
 Wait-File (Join-Path $root 'owner-result.json') 120;$r.owner_exit_confirmed=$owner.WaitForExit(10000)
 if($ui -and -not $ui.WaitForExit(15000)){$ui.Kill();throw 'ui_observer_timeout'}
 }
 Save-Private (Join-Path $root 'bits-stop.json') @{requested=$true};Wait-File (Join-Path $root 'bits-watch-done.json') 20
 $bitsDone=Get-Content -Raw (Join-Path $root 'bits-watch-done.json') | ConvertFrom-Json;if(-not $bitsDone.complete){throw 'bits_observation_incomplete'}
 $r.gate_verified_after_observation=(Invoke-Gate $c 'Verify').verified
 $r.stage='scoped_cleanup';Write-Host 'G18_STAGE:scoped_cleanup';Start-ScheduledTask $c.cleanup_task_name
 Wait-File (Join-Path $root 'recovery-result.json') 100
 $recovery=Get-Content -Raw (Join-Path $root 'recovery-result.json') | ConvertFrom-Json
 if($recovery.status -ne 'restored_after_scoped_exit_checks'){throw 'cleanup_not_verified'}
 $post=(& $c.helper canary $config | ConvertFrom-Json);$r.post_restore_canary_connected=$post.connected
 Unregister-ScheduledTask $c.cleanup_task_name -Confirm:$false
}catch{$r.failure_stage=$r.stage;$m=$_.Exception.Message;$r.error_code=if($m -match '^[a-z_]{1,100}$'){$m}else{'offline_observation_operation_failed'}}
finally{if(Test-Path $root){Save-Private (Join-Path $root 'bits-stop.json') @{requested=$true}};if($owner){$owner.Dispose()};if($ui){$ui.Dispose()};$r.stage='complete';if(Test-Path $root){Save-Private (Join-Path $root 'driver-result.json') $r};Write-Output ($r | ConvertTo-Json -Compress -Depth 5);& python (Join-Path $PSScriptRoot 'Reporter.py')}
if($r.error_code){throw 'offline_real_setup_observation_stopped'}
