$ErrorActionPreference='Stop'
if($env:GITHUB_REPOSITORY -ne 'kokononox/battle-net-agent-lab' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'hosted_lab_required'}
$root=Join-Path $env:ProgramData ('BNetTaskReadOnlyG30\'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Force $root | Out-Null
$acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @('S-1-5-18','S-1-5-32-544')){$rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($rule)}
Set-Acl -LiteralPath $root -AclObject $acl
Copy-Item (Join-Path $PSScriptRoot 'Observe.ps1'),(Join-Path $PSScriptRoot 'TaskTrust.ps1') $root
# SYSTEM task does not inherit the runner's environment; inject only public run identity into a trusted wrapper.
$sha=$env:GITHUB_SHA;$run=$env:GITHUB_RUN_ID
if($sha -notmatch '^[a-f0-9]{40}$' -or $run -notmatch '^\d+$'){throw 'identity_refused'}
$output=Join-Path $root 'report.json'
$wrapper="`$env:GITHUB_SHA='$sha';`$env:GITHUB_RUN_ID='$run';& '$root\Observe.ps1' -Output '$output'"
Set-Content -LiteralPath (Join-Path $root 'Wrapper.ps1') -Value $wrapper -Encoding UTF8
$name='BNetReadOnlyG30-'+[guid]::NewGuid().ToString('N')
try{
 $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -File "'+(Join-Path $root 'Wrapper.ps1')+'"')
 $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
 Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings | Out-Null
 Start-ScheduledTask -TaskName $name
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while(-not (Test-Path $output) -and $watch.Elapsed.TotalSeconds -lt 300){Start-Sleep -Seconds 2}
 if(-not (Test-Path $output)){throw 'read_only_capture_missing'}
 New-Item -ItemType Directory -Force output | Out-Null;Copy-Item $output output/task-security-g30.json
 python (Join-Path $PSScriptRoot 'Receipt.py') output/task-security-g30.json
 if($LASTEXITCODE -ne 0){throw 'receipt_failed'}
}finally{Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue;Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue}
