param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){throw 'Fixture uses fake WinForms; run on Linux, not a Windows GUI acceptance test.'}
function Check([bool]$Value,[string]$Name){if(-not $Value){throw ('test_failed: '+$Name)};$script:checks++}
function ExpectError([scriptblock]$Body){$caught=$false;try{& $Body|Out-Null}catch{$caught=$true};Check $caught 'expected-error'}
Add-Type -TypeDefinition 'namespace System.Windows.Forms { public static class MessageBox { public static string Next="Yes"; public static string Last=""; public static string Show(string text,string title,string buttons,string icon){Last=text;return Next;} } }'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/ui-transfer.ps1'),[ref]$tokens,[ref]$errors)
foreach($name in @('Get-ObservedProgramPaths','Set-ProcessTransferControls','Start-ProcessTransfer','Transfer-ObservedPrograms','Complete-PendingProcessTransfer')){
 $f=$ast.Find({param($a)$a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -ceq $name},$true);Check ($null -ne $f) ('production-function-'+$name);Invoke-Expression $f.Extent.Text
}
function Row([string]$Path){return [pscustomobject]@{Tag=[pscustomobject]@{program_path=$Path}}}
$known=@([pscustomobject]@{path='C:\Old\Known.exe';sha256=('a'*64)})
$rows=@((Row 'C:\Games\Game.exe'),(Row 'c:\games\GAME.exe'),(Row 'C:\Helper\Game.exe'),(Row 'C:\Old\Known.exe'))
$x=@(Get-ObservedProgramPaths $rows $known);Check ($x.Count -eq 2) 'case-insensitive-dedup-and-known-skipped';Check ($x[0] -ceq 'C:\Games\Game.exe' -and $x[1] -ceq 'C:\Helper\Game.exe') 'same-name-different-paths-preserved'
Check (@(Get-ObservedProgramPaths @((Row 'C:\Old\Known.exe')) $known).Count -eq 0) 'existing-program-not-rehashed-or-replaced'
ExpectError {Get-ObservedProgramPaths @((Row 'C:\bad.txt')) @()}
ExpectError {Get-ObservedProgramPaths @((Row '\\server\remote.exe')) @()}
ExpectError {Get-ObservedProgramPaths @([pscustomobject]@{Tag=$null}) @()}
$many=@(1..33|ForEach-Object{Row ('C:\Apps\'+$_+'.exe')});ExpectError {Get-ObservedProgramPaths $many @()}
$existing=@(1..31|ForEach-Object{[pscustomobject]@{path=('C:\Old\'+$_+'.exe')}});ExpectError {Get-ObservedProgramPaths $rows[0..2] $existing}
$script:state=[pscustomobject]@{config=[pscustomobject]@{programs=$known}};$script:closing=$false;$script:ptrJob=$null;$script:job=$null;$script:pendingProcessTransfer=$null
$transferPrograms=[pscustomobject]@{Enabled=$false};$popupTransferPrograms=[pscustomobject]@{Enabled=$false}
$livePopup=[pscustomobject]@{hidden=$false};$livePopup|Add-Member ScriptMethod Hide {$this.hidden=$true}
$script:submitted=New-Object Collections.Generic.List[object];$script:stopCalls=0;$script:stopFails=$false
function BeginOp([string]$Action,$Payload){$script:submitted.Add([pscustomobject]@{action=$Action;payload=$Payload});$script:job=@{action=$Action;folder='new-register-job'}}
function Generation {return 7}
function Request-MonitorStop {$script:stopCalls++;if($script:stopFails){throw 'fake_stop_failure'}}
$filter=[pscustomobject]@{Text=''};$tabs=[pscustomobject]@{SelectedTab=$null};$programTab=[pscustomobject]@{name='programs'};$status=[pscustomobject]@{Text=''};$form=[pscustomobject]@{calls=0};$form|Add-Member ScriptMethod BringToFront {$this.calls++}
$grid=[pscustomobject]@{SelectedRows=@($rows[0],$rows[1],$rows[2])}
[System.Windows.Forms.MessageBox]::Next='No';Transfer-ObservedPrograms $grid
Check ($script:submitted.Count -eq 0 -and $script:stopCalls -eq 0 -and $null -eq $script:pendingProcessTransfer) 'cancel-does-nothing'
[System.Windows.Forms.MessageBox]::Next='Yes';Transfer-ObservedPrograms $grid
Check ($script:submitted.Count -eq 1 -and $script:submitted[0].action -ceq 'register') 'idle-explicit-register-only'
Check ($script:submitted[0].payload.paths.Count -eq 2 -and $script:submitted[0].payload.generation -eq 7) 'batch-paths-and-generation'
Check ($script:job.process_transfer -eq $true) 'job-marked-for-program-page'
$script:job=@{action='baseline_record';folder='recording-1'};Transfer-ObservedPrograms $grid
Check ($script:stopCalls -eq 1 -and $script:submitted.Count -eq 1) 'recording-stops-first-no-register-yet'
Check ($script:pendingProcessTransfer.recording_folder -ceq 'recording-1') 'pending-bound-to-exact-job'
Check (-not $transferPrograms.Enabled -and -not $popupTransferPrograms.Enabled) 'pending-disables-double-click'
Check ([System.Windows.Forms.MessageBox]::Last.Contains('ابتدا همین ثبت رصد')) 'recording-stop-disclosed-in-consent'
ExpectError {Transfer-ObservedPrograms $grid}
Check (-not (Complete-PendingProcessTransfer @{folder='other-job'} $true)) 'unrelated-job-cannot-trigger-queue'
Check ($null -ne $script:pendingProcessTransfer -and $script:submitted.Count -eq 1) 'unrelated-job-leaves-pending'
$script:job=$null;Check (Complete-PendingProcessTransfer @{folder='recording-1'} $true) 'successful-finish-consumes-pending'
Check ($null -eq $script:pendingProcessTransfer -and $script:submitted.Count -eq 2 -and $script:submitted[1].action -ceq 'register') 'one-registration-after-normal-stop'
Check (-not (Complete-PendingProcessTransfer @{folder='recording-1'} $true)) 'queue-cannot-replay'
$script:job=$null;$script:pendingProcessTransfer=@{recording_folder='failed';paths=@('C:\Apps\A.exe');generation=7}
Check (Complete-PendingProcessTransfer @{folder='failed'} $false) 'failed-recording-consumes-without-register'
Check ($null -eq $script:pendingProcessTransfer -and $script:submitted.Count -eq 2) 'failed-recording-no-registration'
$script:pendingProcessTransfer=@{recording_folder='closing';paths=@('C:\Apps\A.exe');generation=7};$script:closing=$true
Check (Complete-PendingProcessTransfer @{folder='closing'} $true) 'closing-cancels-pending';Check ($script:submitted.Count -eq 2) 'closing-no-registration'
$script:closing=$false;$script:job=@{action='native_restore';folder='native'};ExpectError {Transfer-ObservedPrograms $grid}
$script:job=$null;$script:ptrJob=@{running=$true};ExpectError {Transfer-ObservedPrograms $grid};$script:ptrJob=$null
$script:job=@{action='monitor_record';folder='stop-error'};$script:stopFails=$true;ExpectError {Transfer-ObservedPrograms $grid}
Check ($null -eq $script:pendingProcessTransfer -and $script:submitted.Count -eq 2) 'stop-error-clears-pending-without-save'
$script:job=$null;$script:stopFails=$false;$grid.SelectedRows=@($rows[3]);Transfer-ObservedPrograms $grid
Check ($script:submitted.Count -eq 2 -and $tabs.SelectedTab -eq $programTab) 'already-registered-navigate-only'
$result=@{suite='explicit-observed-process-registration';passed=$true;assertions=$script:checks;environment='PowerShell 7 Linux; AST-extracted production functions, fake dialogs/jobs/controls';Windows_GUI_executed=$false;Windows_EXE_inspector_executed=$false;firewall_or_hosts_changed=$false;IP_domain_prefill_unchanged=$true}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/process-transfer-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
