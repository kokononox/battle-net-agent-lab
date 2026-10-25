param([Parameter(Mandatory=$true)][string]$Config)
. (Join-Path $PSScriptRoot 'Common.ps1')
$c=Read-Context $Config;$mutex=$null;$phase='lease'
try{
 if($env:BNET_INTEGRATED_G12 -ne 'lab: approved integrated-recovery qualification G12b 20261025' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_RUN_ATTEMPT -ne '1'){throw 'fresh_hosted_supervisor_required'}
 $mutex=Enter-Lease $c;$lease=Get-Content -Raw (Join-Path $c.root 'lease.json') | ConvertFrom-Json
 if($lease.phase -ne 'prepared'){throw 'launch_lease_not_prepared'}
 $phase='lease_write';Save-Private (Join-Path $c.root 'lease.json') @{phase='active'}
 $phase='gate_prepare';$null=Invoke-Gate $c 'Prepare'
 if($c.iis_original -eq 'Running'){Stop-Service W3SVC;$ctl=Get-Service W3SVC;try{$ctl.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))}finally{$ctl.Dispose()}}
 $phase='proxy_start';$proxy=Start-Process -FilePath $c.proxy_exe -ArgumentList ('"'+(Join-Path $c.root 'proxy.json')+'"') -PassThru -WindowStyle Hidden
 Record-Process $proxy (Join-Path $c.root 'proxy-process.json');$proxy.Dispose()
 $w=[Diagnostics.Stopwatch]::StartNew();$log=Join-Path $c.root 'proxy-private.jsonl'
 while($w.Elapsed.TotalSeconds -lt 25){if((Test-Path $log) -and (Get-Content -Raw $log).Contains('proxy_ready')){break};Start-Sleep -Milliseconds 200}
 if(-not (Test-Path $log) -or -not (Get-Content -Raw $log).Contains('proxy_ready')){throw 'proxy_ready_timeout'}
 $before=Invoke-Canary $c 'via_gate';if(-not $before.http200){throw 'proxy_fixture_not_healthy'}
 $phase='hosts_steer';$hosts="$env:SystemRoot\System32\drivers\etc\hosts";$old=[IO.File]::ReadAllBytes($hosts)
 if($old.Length -gt 262144 -or [Text.Encoding]::UTF8.GetString($old) -match '(?im)^\s*[^#\r\n]+\s+(?:level3\.blizzard\.com|us\.version\.battle\.net)(?:\s|$)'){throw 'hosts_preexisting_or_format_refused'}
 $extra=[Text.Encoding]::ASCII.GetBytes("`r`n# BNET G12 temporary exact loopback`r`n127.0.0.1 level3.blizzard.com`r`n::1 level3.blizzard.com`r`n127.0.0.1 us.version.battle.net`r`n::1 us.version.battle.net`r`n")
 [byte[]]$new=$old+$extra;[IO.File]::WriteAllBytes((Join-Path $c.root 'hosts-before.bak'),$old);[IO.File]::WriteAllBytes((Join-Path $c.root 'hosts-after.expected'),$new)
 [IO.File]::WriteAllBytes($hosts,$new);$null=& "$env:SystemRoot\System32\ipconfig.exe" /flushdns
 if($LASTEXITCODE -ne 0){throw 'hosts_flush_failed'}
 $phase='gate_apply';$applied=Invoke-Gate $c 'Apply';if($applied.verified -ne $true){throw 'gate_not_applied'}
 $direct=Invoke-Canary $c 'canary';$via=Invoke-Canary $c 'via_gate'
 if($direct.connected -or -not $via.http200){throw 'integrated_gate_probe_failed'}
 $phase='fixture_start';$owner=Start-Process $c.exe -ArgumentList ('owner "'+$Config+'" '+$c.token) -PassThru -WindowStyle Hidden
 Record-Process $owner (Join-Path $c.root 'owner-process.json');$owner.Dispose();Wait-File (Join-Path $c.root 'owner.json') 20
 $null=New-Service -Name $c.service_name -BinaryPathName $c.service_command -StartupType Manual;Start-Service $c.service_name;Wait-File (Join-Path $c.root 'service.json') 15
 $action=New-ScheduledTaskAction -Execute $c.exe -Argument $c.task_arguments
 $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 8)
 $null=Register-ScheduledTask -TaskName $c.task_name -Action $action -Principal $principal -Settings $settings
 Start-ScheduledTask $c.task_name;Wait-File (Join-Path $c.root 'task.json') 15
 $service=Get-Content -Raw (Join-Path $c.root 'service.json') | ConvertFrom-Json;$task=Get-Content -Raw (Join-Path $c.root 'task.json') | ConvertFrom-Json
 $root=Get-Content -Raw (Join-Path $c.root 'root.json') | ConvertFrom-Json;$leaf=Get-Content -Raw (Join-Path $c.root 'leaf.json') | ConvertFrom-Json
 $own=Get-Content -Raw (Join-Path $c.root 'owner.json') | ConvertFrom-Json
 if($service.job_member -ne $false -or $task.job_member -ne $false -or $root.job_member -ne $true -or $leaf.job_member -ne $true -or $own.assigned_before_resume -ne $true){throw 'membership_proof_failed'}
 $null=Invoke-Gate $c 'Verify'
 Save-Private (Join-Path $c.root 'supervisor-ready.json') @{gate_verified=$true;direct_denied=$true;via_gate_ok=$true;root_and_leaf_member=$true;service_and_task_outside=$true}
}catch{
 $text=$_.Exception.Message;Save-Private (Join-Path $c.root 'supervisor-error.json') @{error_code=$(if($text -match '^[a-z_]{1,80}$'){$text}else{'supervisor_operation_failed'});phase=$phase;shape=(Error-Shape $_)}
 throw 'supervisor_stopped'
}finally{if($mutex){$mutex.ReleaseMutex();$mutex.Dispose()}}
# Intentionally no finally-based rollback. Crash/timeout recovery is an independent SYSTEM task.
Start-Sleep -Seconds 450
