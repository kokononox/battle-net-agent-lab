$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REF -ne 'refs/heads/research/battlenet-minimal-install-isolation-2026-10-25' -or $env:GITHUB_EVENT_NAME -ne 'push' -or $env:GITHUB_RUN_ATTEMPT -ne '1' -or $env:BNET_ONLINE_G33 -ne 'lab: approved ambient no Setup control G33 20261025'){throw 'fresh_hosted_required'}
$scenario=$env:BNET_G33_SCENARIO;if($scenario -ne 'ambient_no_setup'){throw 'scenario_refused'}
. (Join-Path $PSScriptRoot 'Common.ps1');. (Join-Path $PSScriptRoot 'Inventory.ps1');. (Join-Path $PSScriptRoot 'FocusTasks.ps1')
New-Item -ItemType Directory -Force output | Out-Null
$guid=[guid]::NewGuid().ToString('N');$root=Join-Path (Join-Path $env:ProgramData 'BNetOnlineG33') $guid;$config=Join-Path $root 'config.json';$c=$null;$owner=$null;$ui=$null;$completion=$null
$r=[ordered]@{scenario=$scenario;observation_seconds=270;stage='prepare';gate_verified_before_launch=$false;gate_verified_after_observation=$false;baseline_canary_connected=$false;blocked_canary_connected=$null;post_restore_canary_connected=$null;target_launch_attempted=$false;target_launched=$null;owner_exit_confirmed=$false;error_code=$null;failure_stage=$null}
try{
 $null=New-Item -ItemType Directory -Force $root;$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){$s=[Security.Principal.SecurityIdentifier]::new($sid);$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($s,[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))};Set-Acl $root $acl
 Save-Private output/g33-private-pointer.json @{root=$root}
 if(Test-Path output/g33-log-probe.json){Copy-Item output/g33-log-probe.json (Join-Path $root 'log-probe.json')}
 foreach($name in @('Common.ps1','FirewallGate.ps1','Inventory.ps1','Recover.ps1','Snapshot.ps1','TaskTrust.ps1','FocusTasks.ps1','TaskAudit.ps1','DiagnosticLog.ps1','Classify.py','TaskXml.py','NarrowTimeRules.py','ShadowSchedule.py','TestClassifier.py','TestEnforcedTimeRules.py')){Copy-Item (Join-Path $PSScriptRoot $name) (Join-Path $root $name)}
 Copy-Item "$env:RUNNER_TEMP\bnet-g33-bin\OfflineLauncher.exe" (Join-Path $root 'OfflineLauncher.exe')
 Copy-Item (Join-Path $PSScriptRoot 'dist\TwoHostProxy') (Join-Path $root 'proxy-bin') -Recurse
 $stageTemp=Join-Path $root 'stage-temp';$null=New-Item -ItemType Directory $stageTemp
 $envChild=@{};foreach($key in @('SystemRoot','windir','SystemDrive','ProgramFiles','ProgramFiles(x86)','ProgramW6432','ProgramData','LOCALAPPDATA','APPDATA','USERPROFILE','COMSPEC')){$v=[Environment]::GetEnvironmentVariable($key);if($v){$envChild[$key]=$v}}
 $envChild['TEMP']=$stageTemp;$envChild['TMP']=$stageTemp;$envChild['PATH']="$env:SystemRoot\System32;$env:SystemRoot"
 $pinsText=& python -c "import socket,ipaddress,json; h=('level3.blizzard.com','us.version.battle.net');d={n:sorted({x[4][0] for x in socket.getaddrinfo(n,80,type=socket.SOCK_STREAM) if ipaddress.ip_address(x[4][0]).is_global}) for n in h};assert all(1<=len(v)<=32 for v in d.values());print(json.dumps(d))"
 if($LASTEXITCODE -ne 0){throw 'pins_resolution_failed'};$pins=$pinsText | ConvertFrom-Json
 $ip=& python -c "import socket,ipaddress; a=sorted({x[4][0] for x in socket.getaddrinfo('us.version.battle.net',1119,socket.AF_INET,socket.SOCK_STREAM) if ipaddress.ip_address(x[4][0]).is_global}); assert a; print(a[0])"
 if($LASTEXITCODE -ne 0){throw 'canary_resolution_failed'}
 $c=@{python=(Get-Command python).Source;scenario=$scenario;root=$root;setup=(Join-Path $root 'Battle.net-Setup.exe');helper=(Join-Path $root 'OfflineLauncher.exe');job_name=('Global\BNetOnlineG33_'+$guid);watchdog_name=('BNetOnlineG33_'+$guid+'_recovery');cleanup_task_name=('BNetOnlineG33_'+$guid+'_cleanup');snapshot_task_name=('BNetOnlineG33_'+$guid+'_snapshot');mutex_name=('Global\BNetOnlineG33Lease_'+$guid);canary_ip=[string]$ip;signature_accepted=$false;child_environment=$envChild;iis_original=[string](Get-Service W3SVC).Status;target_roots=@((Join-Path ${env:ProgramFiles(x86)} 'Battle.net'),(Join-Path $env:ProgramData 'Battle.net'),(Join-Path $env:ProgramData 'Blizzard Entertainment'),(Join-Path $env:LOCALAPPDATA 'Battle.net'),$root)}
 $c.hosts=$pins;$c.proxy_exe=Join-Path $root 'proxy-bin\TwoHostProxy.exe'
 foreach($path in @($c.target_roots | Where-Object {$_ -ne $root})){if(Test-Path $path){throw 'preexisting_battlenet_directory'}}
 if(@(Get-Process -Name 'Battle.net-Setup','Battle.net','Agent','BlizzardError' -ErrorAction SilentlyContinue).Count -gt 0){throw 'preexisting_target_process'}
 Save-Private $config $c;Save-Private (Join-Path $root 'lease.json') @{phase='prepared'}
 $r.stage='identity';Write-Host 'G33_STAGE:identity'
 & python (Join-Path $PSScriptRoot 'Prepare.py') $root
 if($LASTEXITCODE -ne 0){$r.target_launched=$false;throw 'setup_preflight_stopped'}
 $meta=Get-Content -Raw (Join-Path $root 'preflight.json') | ConvertFrom-Json;if(-not ($meta.matches_pin -and $meta.signature_accepted -and $meta.ui_helper_ready)){throw 'identity_not_accepted'}
 $c.signature_accepted=$true;Save-Private $config $c
 $refusalText=& $c.helper run $config;$refusalExit=$LASTEXITCODE;$refusal=$refusalText | ConvertFrom-Json
 if($refusalExit -ne 2 -or $refusal.error_code -ne 'installer_execution_disabled_in_control'){throw 'native_no_launch_refusal_not_verified'}
 $r.stage='certificate_cache_preparation';Write-Host 'G33_STAGE:certificate_cache_preparation'
 & python (Join-Path $PSScriptRoot 'WarmCertificates.py') $root
 if($LASTEXITCODE -ne 0){$r.target_launched=$false;throw 'certificate_preparation_not_verified'}

 $before=(& $c.helper canary $config | ConvertFrom-Json);$r.baseline_canary_connected=$before.connected;if(-not $before.connected){throw 'baseline_canary_not_healthy'}
 $ps="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe";$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds 90)
 foreach($origin in @('deadline','explicit','snapshot')){
  $name=if($origin -eq 'deadline'){$c.watchdog_name}elseif($origin -eq 'snapshot'){$c.snapshot_task_name}else{$c.cleanup_task_name}
  $action=New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $root 'Recover.ps1')+'" -Config "'+$config+'" -Origin '+$origin)
  if($origin -eq 'snapshot'){$action=New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $root 'Snapshot.ps1')+'" -Config "'+$config+'"')}
  if($origin -eq 'deadline'){$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(480);$null=Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Trigger $trigger -Settings $settings}else{$taskSettings=if($origin -eq 'snapshot'){New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds 350)}else{$settings};$null=Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $taskSettings}
 }
 Save-Private (Join-Path $root 'snapshot-phase.json') @{value='baseline'};Start-ScheduledTask $c.snapshot_task_name;Wait-File (Join-Path $root 'system-baseline-receipt.json') 40
 $baseReceipt=Get-Content -Raw (Join-Path $root 'system-baseline-receipt.json') | ConvertFrom-Json;if(-not $baseReceipt.system_identity -or -not $baseReceipt.captured){throw 'system_baseline_not_verified'}
 $r.stage='two_host_gate';Write-Host 'G33_STAGE:two_host_gate';$null=Invoke-Gate $c 'Prepare'
 if($c.iis_original -eq 'Running'){Stop-Service W3SVC}
 $hostPath=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts';Copy-Item $hostPath (Join-Path $root 'hosts-before.bin')
 Add-Content -Path $hostPath -Encoding ASCII -Value "`r`n127.0.0.1 level3.blizzard.com us.version.battle.net`r`n::1 level3.blizzard.com us.version.battle.net`r`n"
 $null=& "$env:SystemRoot\System32\ipconfig.exe" /flushdns
 foreach($h in @('level3.blizzard.com','us.version.battle.net')){$resolved=@([Net.Dns]::GetHostAddresses($h));if($resolved.Count -eq 0 -or @($resolved | Where-Object {-not [Net.IPAddress]::IsLoopback($_)}).Count -gt 0){throw 'hosts_not_loopback'}}
 Save-Private (Join-Path $root 'proxy.json') @{hosts=$pins;port=18731;seconds=350;log=(Join-Path $root 'proxy-private.jsonl');transparent=$true;peer_policy=(Join-Path $root 'peers.json')}
 $proxy=Start-Process $c.proxy_exe -ArgumentList ('"'+(Join-Path $root 'proxy.json')+'"') -PassThru -RedirectStandardOutput (Join-Path $root 'proxy-stdout.private.txt') -RedirectStandardError (Join-Path $root 'proxy-stderr.private.txt');Record-Process $proxy (Join-Path $root 'proxy-process.json')
 $pw=[Diagnostics.Stopwatch]::StartNew();do{Start-Sleep -Milliseconds 200;$ready=(Test-Path (Join-Path $root 'proxy-private.jsonl')) -and [bool](Select-String -Path (Join-Path $root 'proxy-private.jsonl') -Pattern 'proxy_ready' -Quiet)}while(-not $ready -and $pw.Elapsed.TotalSeconds -lt 15 -and -not $proxy.HasExited)
 if(-not $ready){throw 'proxy_not_ready'}

 $gate=Invoke-Gate $c 'Apply';$r.gate_verified_before_launch=($gate.verified -and $gate.target_allow_rules -eq 0)
 Save-Private (Join-Path $root 'lease.json') @{phase='active'}
 $blocked=(& $c.helper canary $config | ConvertFrom-Json);$r.blocked_canary_connected=$blocked.connected
 if(-not $r.gate_verified_before_launch -or $blocked.connected){throw 'offline_gate_not_verified'}
 Save-Private (Join-Path $root 'snapshot-phase.json') @{value='prelaunch'};Start-ScheduledTask $c.snapshot_task_name;Wait-File (Join-Path $root 'system-prelaunch-receipt.json') 40
 $preReceipt=Get-Content -Raw (Join-Path $root 'system-prelaunch-receipt.json') | ConvertFrom-Json;if(-not $preReceipt.system_identity -or -not $preReceipt.captured -or $preReceipt.bits_added -ne 0 -or $preReceipt.bits_modified -ne 0){$r.target_launched=$false;throw 'registration_drift_before_target'}
 $deny=& python -c "import socket;s=socket.create_connection(('127.0.0.1',1119),3);s.sendall(b'GET /agent/versions HTTP/1.1\r\nHost: us.version.battle.net:1119\r\n\r\n');r=s.recv(256);s.close();assert r.startswith(b'HTTP/1.1 403');print('denied')"
 if($LASTEXITCODE -ne 0 -or $deny -ne 'denied'){throw 'outside_proxy_probe_failed'}
 if(Select-String -Path (Join-Path $root 'proxy-private.jsonl') -Pattern 'upstream_dial_started' -Quiet){throw 'outside_proxy_dial_detected'}
 Save-Private (Join-Path $root 'online-preflight.json') @{outside_job_denied_no_dial=$true;exact_hosts_loopback=$true;proxy_ready=$true;ambient_registration_changes=[int]$preReceipt.registration_changes;ambient_changes_not_waived_for_recovery=$true}
 $c.observation_start_utc=(Get-Date).ToUniversalTime().ToString('o');Save-Private $config $c
 $r.stage='observe_ambient_no_setup';$r.target_launched=$false;Write-Host 'G33_STAGE:observe_ambient_no_setup'
 Save-Private (Join-Path $root 'no-setup-control.json') @{scenario='ambient_no_setup';installer_execution_disabled_in_native_helper=$true;native_run_refusal_verified=$true;installer_execute_requested=$false;setup_download_and_signature_preparation_matched=$true;observation_seconds=270}
 Start-Sleep -Seconds 270
 Save-Private (Join-Path $root 'bits-stop.json') @{requested=$true};Wait-File (Join-Path $root 'bits-watch-done.json') 20
 $bitsDone=Get-Content -Raw (Join-Path $root 'bits-watch-done.json') | ConvertFrom-Json;if(-not $bitsDone.complete){throw 'bits_observation_incomplete'}
 Save-Private (Join-Path $root 'focus-observation-end.json') (Get-FocusTasks $c 'observation_end' 270 -Deep)
 $r.gate_verified_after_observation=(Invoke-Gate $c 'Verify').verified
 & python (Join-Path $PSScriptRoot 'FocusSummary.py') $root
 if($LASTEXITCODE -ne 0){throw 'focus_summary_failed'}
 & python (Join-Path $PSScriptRoot 'Capture.py') $root
 & python (Join-Path $PSScriptRoot 'LogErrors.py') $root
 if($LASTEXITCODE -ne 0){throw 'log_error_collection_failed'}
 & (Join-Path $PSScriptRoot 'WindowsTLS.ps1') -Config $config
 Save-Private (Join-Path $root 'driver-result.json') $r
 & python (Join-Path $PSScriptRoot 'Reporter.py')
 $r.stage='scoped_cleanup';Write-Host 'G33_STAGE:scoped_cleanup';Start-ScheduledTask $c.cleanup_task_name
 Wait-File (Join-Path $root 'recovery-result.json') 100
 $recovery=Get-Content -Raw (Join-Path $root 'recovery-result.json') | ConvertFrom-Json
 if($recovery.status -ne 'restored_after_scoped_exit_checks'){throw 'cleanup_not_verified'}
 $post=(& $c.helper canary $config | ConvertFrom-Json);$r.post_restore_canary_connected=$post.connected
 Unregister-ScheduledTask $c.cleanup_task_name -Confirm:$false
}catch{$r.failure_stage=$r.stage;$m=$_.Exception.Message;$r.error_code=if($m -match '^[a-z_]{1,100}$'){$m}else{'offline_observation_operation_failed'}}
finally{if(Test-Path $root){Save-Private (Join-Path $root 'bits-stop.json') @{requested=$true}};if($owner){$owner.Dispose()};if($ui){$ui.Dispose()};if($completion){$completion.Dispose()};$r.stage='complete';if(Test-Path $root){Save-Private (Join-Path $root 'driver-result.json') $r};Write-Output ($r | ConvertTo-Json -Compress -Depth 5);& python (Join-Path $PSScriptRoot 'FocusSummary.py') $root;& python (Join-Path $PSScriptRoot 'Reporter.py')}
if($r.error_code){throw 'two_host_observation_or_cleanup_stopped'}
