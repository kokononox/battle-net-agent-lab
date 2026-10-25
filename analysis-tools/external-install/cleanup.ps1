param([Parameter(Mandatory=$true)][string]$Config)
$ErrorActionPreference='Stop'
# Self-contained recovery: may run as SYSTEM without inheriting runner environment.
$prefix=Join-Path $env:ProgramData 'BNetExternalG10'
$Config=[IO.Path]::GetFullPath($Config)
if(-not $Config.StartsWith($prefix+'\',[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($Config) -ne 'config.json'){throw 'cleanup_config_scope_refused'}
$c=Get-Content -Raw $Config | ConvertFrom-Json
if($c.root -ne (Split-Path $Config) -or $c.service_name -notmatch '^BNetLabG10_[0-9a-f]{32}_svc$' -or $c.task_name -notmatch '^BNetLabG10_[0-9a-f]{32}_task$' -or $c.watchdog_name -notmatch '^BNetLabG10_[0-9a-f]{32}_recovery$'){throw 'cleanup_identity_refused'}
function Verified-Process($kind){
 $file=Join-Path $c.root ($kind+'.json');if(-not (Test-Path $file)){return $null}
 $id=Get-Content -Raw $file | ConvertFrom-Json
 $proc=Get-Process -Id $id.pid -ErrorAction SilentlyContinue
 if(-not $proc){return $null};$null=$proc.Handle
 if($proc.StartTime.ToFileTimeUtc() -ne [long]$id.created){$proc.Dispose();return $null}
 if(-not [string]::Equals($proc.MainModule.FileName,$c.exe,[StringComparison]::OrdinalIgnoreCase)){throw 'cleanup_process_identity_mismatch'}
 return $proc
}
# Disable scheduled starts first, then stop only this exact registered fixture.
$task=Get-ScheduledTask -TaskName $c.task_name -ErrorAction SilentlyContinue
if($task){
 if(@($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -ne $c.exe -or $task.Actions[0].Arguments -ne $c.task_arguments){throw 'cleanup_task_identity_mismatch'}
 $null=Disable-ScheduledTask -TaskName $c.task_name
 $null=New-Item -ItemType File -Force (Join-Path $c.root 'stop-task')
 Stop-ScheduledTask -TaskName $c.task_name -ErrorAction SilentlyContinue
 Unregister-ScheduledTask -TaskName $c.task_name -Confirm:$false
}
$svc=Get-CimInstance Win32_Service -Filter ("Name='"+$c.service_name+"'")
if($svc){
 if($svc.PathName -ne $c.service_command){throw 'cleanup_service_identity_mismatch'}
 Set-Service -Name $c.service_name -StartupType Disabled
 Stop-Service -Name $c.service_name -ErrorAction Stop
 $controller=Get-Service $c.service_name
 try{$controller.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(10))}finally{$controller.Dispose()}
 $null=& "$env:SystemRoot\System32\sc.exe" delete $c.service_name
 if($LASTEXITCODE -ne 0){throw 'cleanup_service_delete_failed'}
}
foreach($kind in @('task','service','owner')){
 $proc=Verified-Process $kind
 if($proc){
  try{if(-not $proc.WaitForExit(5000)){$proc.Kill();if(-not $proc.WaitForExit(5000)){throw 'cleanup_owned_process_survived'}}}finally{$proc.Dispose()}
 }
}
Start-Sleep -Milliseconds 500
$serviceGone=-not (Get-CimInstance Win32_Service -Filter ("Name='"+$c.service_name+"'"))
$taskGone=-not (Get-ScheduledTask -TaskName $c.task_name -ErrorAction SilentlyContinue)
$processesGone=$true
foreach($kind in @('task','service','owner')){$proc=Verified-Process $kind;if($proc){$processesGone=$false;$proc.Dispose()}}
$verified=$serviceGone -and $taskGone -and $processesGone
@{schema='bnet-external-cleanup-g10-1';service_removed=$serviceGone;task_removed=$taskGone;known_processes_exited=$processesGone;verified=$verified} | ConvertTo-Json | Set-Content (Join-Path $c.root 'cleanup-result.json') -Encoding UTF8
if($verified){Unregister-ScheduledTask -TaskName $c.watchdog_name -Confirm:$false -ErrorAction SilentlyContinue}else{throw 'cleanup_not_verified'}
