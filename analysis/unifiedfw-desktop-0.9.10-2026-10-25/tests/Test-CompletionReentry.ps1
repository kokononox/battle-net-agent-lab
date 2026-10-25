param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:assertions=0
function Check([bool]$b,[string]$n){if(-not $b){throw ('test_failed: '+$n)};$script:assertions++}
function Load-Functions($File,$Names){
 $t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $File),[ref]$t,[ref]$e)
 foreach($name in $Names){$node=$a.Find({param($x)$x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -ceq $name},$true);if($null -eq $node){throw 'missing_function'};. ([scriptblock]::Create('function script:'+ $name + $node.Extent.Text.Substring(('function '+$name).Length)))}
}
Load-Functions 'app/ui.ps1' @('Invoke-DesktopTickCore','Invoke-DesktopTick','SetBusy','Update-PolicyModeControls')
Load-Functions 'app/ui-workspace.ps1' @('Set-WorkspaceBusy')
Load-Functions 'app/ui-hosts-reset.ps1' @('Set-HostsResetControls')
# Exercise production busy helper across actual variable names, including blacklist toolbar.
$names=@('hostRead','hostSink','hostRemove','hostDomains','hostFilter','historyReload','historyOpen','historyExport','stageObserved','baselineStart','baselineHistory','dnsTrace','add','remove','observe','reload','save','preview','importBlack','importWhite','addEntry','deleteEntry','mode','connectionMode','whitelist','programGrid','blackGrid','filter','selectVisible','clearVisible','clearAll','target','proto','port','duration','apply','restore','nativeStatus','copyPath','stop','monitorStop','popupStop','hostsResetDefault','hostsDnsFlush','hostsResetReload','hostsResetRestore','hostsResetFolder','hostsResetGrid','ipNew','ipEdit','ipBind','ipDelete','rangeAdd','ipSave','ipRevert','ipCheckNative','ipRestore')
foreach($n in $names){Set-Variable -Name $n -Value ([pscustomobject]@{Enabled=$true})}
$mode|Add-Member NoteProperty SelectedIndex 0;$connectionMode|Add-Member NoteProperty SelectedIndex 1;$modeHint=[pscustomobject]@{Text=''}
$script:workspaceButtons=@($ipNew,$ipEdit,$ipBind,$ipDelete,$rangeAdd,$ipSave,$ipRevert,$ipCheckNative,$ipRestore)
function Set-EvidenceControls {};function Set-ProcessTransferControls {};function Set-DenialControls {}
$script:state=[pscustomobject]@{config=[pscustomobject]@{mode='blacklist_only'}};$script:liveFrame=$null;$script:job=@{action='hosts_reset_apply'}
SetBusy $true
foreach($b in $script:workspaceButtons){Check (-not $b.Enabled) 'blacklist-disabled-while-writing'}
Check (-not $hostsDnsFlush.Enabled) 'dns-disabled-while-writing'
$script:job=$null;SetBusy $false
foreach($b in $script:workspaceButtons){Check $b.Enabled 'blacklist-reenabled-after-completion'}
Check ($apply.Enabled -and $restore.Enabled -and $hostsDnsFlush.Enabled) 'apply-restore-dns-enabled'
# Drive the actual completion handler with a fake completed process and a valid response.
# A nested callback simulates ShowDialog/MessageBox pumping WM_TIMER on WinForms.
function Update-LiveView {};function Expire-LivePulses {};function Update-Ptr {}
$script:resultCalls=0;$script:disposeCalls=0;$script:busyCalls=@();$script:throwResult=$false;$script:throwDispose=$false
function Accept-HostsResetResult($Result){$script:resultCalls++;if($script:throwResult){throw 'result-render-failure'};Invoke-DesktopTick}
function SetBusy([bool]$Busy){$script:busyCalls+=,$Busy;Set-WorkspaceBusy $Busy}
$status=[pscustomobject]@{Text=''};$output=[pscustomobject]@{Text=''};$tabs=[pscustomobject]@{SelectedTab=$null};$detailTab='details';$detailHint=[pscustomobject]@{Text=''}
$script:closing=$false;$script:pendingProcessTransfer=$null;$script:ptrJob=$null;$script:tickActive=$false
$tmp=Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N')+'.json')
function New-FakeJob {
 $process=[pscustomobject]@{HasExited=$true};$process|Add-Member ScriptMethod Dispose {$script:disposeCalls++;if($script:throwDispose){throw 'dispose-fault'}}
 $script:job=@{action='hosts_reset_apply';process=$process;response=$tmp;folder='fake'}
 foreach($button in $script:workspaceButtons){$button.Enabled=$false}
}
try{
 [IO.File]::WriteAllText($tmp,'{"ok":true,"hosts_reset_result":{}}')
 New-FakeJob;Invoke-DesktopTick
 Check ($script:resultCalls -eq 1) 'modal-reentry-does-not-reconsume-result'
 Check ($script:disposeCalls -eq 1) 'process-disposed-once'
 Check ($null -eq $script:job -and -not $script:tickActive) 'job-and-guard-released'
 foreach($b in $script:workspaceButtons){Check $b.Enabled 'blacklist-buttons-work-after-result'}
 Invoke-DesktopTick;Check ($script:resultCalls -eq 1) 'later-tick-does-not-replay'
 $script:throwResult=$true;New-FakeJob;Invoke-DesktopTick
 Check ($null -eq $script:job -and -not $script:tickActive) 'render-failure-releases-job-and-guard'
 Check ($script:disposeCalls -eq 2) 'failure-disposes-once'
 foreach($b in $script:workspaceButtons){Check $b.Enabled 'render-failure-reenables-blacklist'}
 $script:throwResult=$false;$script:throwDispose=$true;New-FakeJob;Invoke-DesktopTick
 Check ($null -eq $script:job -and -not $script:tickActive) 'dispose-failure-still-unlocks'
 Check ($ipNew.Enabled -and $ipSave.Enabled -and $ipBind.Enabled) 'dispose-failure-buttons-reenabled'
 $script:throwDispose=$false
 [IO.File]::WriteAllText($tmp,'not-json');New-FakeJob;Invoke-DesktopTick
 Check ($null -eq $script:job -and -not $script:tickActive -and $ipSave.Enabled) 'malformed-response-unlocks'
 [IO.File]::WriteAllText($tmp,'{"ok":false,"error":"backend-fixture-error"}');New-FakeJob;Invoke-DesktopTick
 Check ($null -eq $script:job -and $status.Text.Contains('backend-fixture-error')) 'backend-error-reported-and-unlocked'
 function Update-LiveView {throw 'live-view-fixture-error'}
 [IO.File]::WriteAllText($tmp,'{"ok":true,"hosts_reset_result":{}}');New-FakeJob;Invoke-DesktopTick
 Check ($null -eq $script:job -and $ipSave.Enabled) 'live-display-error-does-not-block-job-completion'
 New-FakeJob;$script:job.completion_claimed=$true;$before=$script:disposeCalls;Invoke-DesktopTick
 Check ($script:disposeCalls -eq $before) 'claimed-job-never-disposed-twice';$script:job=$null
 $source=[IO.File]::ReadAllText((Join-Path $Root 'app/ui-hosts-reset.ps1'))
 Check (-not $source.Contains("MessageBox]::Show($"+'message')) 'hosts-result-is-nonmodal'
 $result=@{passed=$true;assertions=$script:assertions;suite='completion-reentry-and-blacklist-unlock';production_tick_and_busy_helpers_executed=$true;Windows_GUI_executed=$false}
 [IO.File]::WriteAllText((Join-Path $Root 'evidence/completion-reentry-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
}finally{if(Test-Path $tmp){Remove-Item $tmp}}
