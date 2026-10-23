$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
function Notice($s){[void][Windows.Forms.MessageBox]::Show($s,'WLab APIProbe')}
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(!$admin){[IO.File]::WriteAllText((Join-Path $WLabLogDir 'elevation-handoff.txt'),'Requesting administrator launch');try{Start-Process -FilePath $WLabExe -Verb RunAs}catch{Notice 'Administrator approval was not granted.'};return}
$form=New-Object Windows.Forms.Form;$form.Text='WLab APIProbe 0.1.1 - One 8-byte slot read only'
$form.ClientSize=New-Object Drawing.Size(790,500);$form.StartPosition='CenterScreen';$form.FormBorderStyle='FixedDialog';$form.MaximizeBox=$false;$form.ShowInTaskbar=$true;$form.Font=New-Object Drawing.Font('Segoe UI',10)
$form.Add_Shown({[IO.File]::WriteAllText((Join-Path $WLabLogDir 'ui-ready.txt'),'Shown event; not proof of visibility');$form.Activate()})
function Control($type,$text,$x,$y,$w,$h){$c=New-Object ('Windows.Forms.'+$type);$c.Text=$text;$c.SetBounds($x,$y,$w,$h);$form.Controls.Add($c);return $c}
[void](Control Label 'Read one 8-byte API slot only. No code pages, full dump, debugger or target writes.' 15 15 760 28)
$list=Control ComboBox '' 15 52 545 30;$list.DropDownStyle='DropDownList'
$refresh=Control Button 'Refresh' 575 50 195 32
[void](Control Label 'Current game screen (your report, not detected):' 15 95 450 27)
$stage=Control ComboBox '' 480 91 290 30;$stage.DropDownStyle='DropDownList';[void]$stage.Items.Add('Character selection');[void]$stage.Items.Add('In world');$stage.SelectedIndex=0
$agree=Control CheckBox 'Make one read-only attempt against the selected test game; stop if access is denied.' 15 132 760 30
$start=Control Button 'Identify API once' 15 175 245 40
$cancel=Control Button 'Cancel helper only' 280 175 235 40;$cancel.Enabled=$false
$open=Control Button 'Open results' 535 175 235 40;$open.Enabled=$false
$log=Control TextBox '' 15 235 755 245;$log.Multiline=$true;$log.ReadOnly=$true;$log.ScrollBars='Vertical'
$script:busy=$false;$script:cancel=$false;$script:r=$null;$script:out='';$script:run='';$script:helper=$null;$script:captureLock=$null
function Log($s){$log.AppendText(([DateTime]::Now.ToString('HH:mm:ss'))+'  '+$s+"`r`n");[Windows.Forms.Application]::DoEvents()}
function Pump{[Windows.Forms.Application]::DoEvents();Start-Sleep -Milliseconds 50}
function WriteRun{[IO.File]::WriteAllText((Join-Path $script:out 'run.json'),($script:r|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))}
function RefreshList{
$list.Items.Clear();$script:ts=@()
foreach($p in @(Get-Process -Name Wow -ErrorAction SilentlyContinue)){try{
$entry=[pscustomobject]@{Id=$p.Id;StartFileTime=$p.StartTime.ToUniversalTime().ToFileTimeUtc();Path=$p.Path};$script:ts+=$entry;[void]$list.Items.Add(('Wow.exe PID '+$p.Id+'  '+$p.Path))
}catch{}}
if($list.Items.Count){$list.SelectedIndex=0}else{Log 'No accessible Wow.exe found. Open the supported test game, then Refresh.'}
}
function Alive{
try{$p=Get-Process -Id $script:t.Id -ErrorAction Stop;return ($p.StartTime.ToUniversalTime().ToFileTimeUtc() -eq $script:t.StartFileTime)}catch{return $false}
}
function StopHelperOnly{
if($null -ne $script:helper){try{if(!(Test-WLabChildExited $script:helper)){$script:helper.Process.Kill();[void]$script:helper.Process.WaitForExit(3000)}}catch{}}
}
$refresh.Add_Click({RefreshList})
$cancel.Add_Click({$script:cancel=$true;$cancel.Enabled=$false})
$open.Add_Click({Start-Process explorer.exe -ArgumentList ('"'+$script:run+'"')})
$form.Add_FormClosing({param($s,$e)if($script:busy){$e.Cancel=$true;Notice 'Use Cancel helper only and wait. The game is never terminated by this tool.'}})
$start.Add_Click({
if($script:busy){return};if(!$agree.Checked){Notice 'Tick acceptance for one bounded read-only attempt first.';return};if($list.SelectedIndex -lt 0){Notice 'Select the running supported test game first.';return}
$start.Enabled=$false;$refresh.Enabled=$false;$list.Enabled=$false;$stage.Enabled=$false;$script:busy=$true
try{
$script:t=$script:ts[$list.SelectedIndex]
if($script:t.Path -notmatch '^([A-Za-z]):[\\/]'){throw 'Selected game path must use a local drive letter; no fallback to C is used'}
$outputRoot=$Matches[1].ToUpperInvariant()+':\WLabAPIProbe'
$cache=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'WLabSnapshot'
$script:captureLock=Acquire-WLabCaptureLock $cache
$script:run=Join-Path $outputRoot ((Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8));$script:out=Join-Path $script:run 'report'
[void](New-Item -ItemType Directory -Force -Path $script:out)
$script:r=[ordered]@{tool='WLab APIProbe 0.1.1';state='preparing';started_utc=[DateTime]::UtcNow.ToString('o');expected_pid=$script:t.Id;expected_creation_filetime=$script:t.StartFileTime;game_screen_user_reported=[string]$stage.SelectedItem;output_directory=$script:run;read_helper_requested=$false;game_stability='not established; ask user';network_sending='unresolved';observations=@()}
WriteRun;Log ('Small report output: '+$script:run)
if(@(Get-Process -Name procdump,procdump64,procdump64a -ErrorAction SilentlyContinue).Count -gt 0){throw 'A ProcDump is still running; no read started'}
$script:r.child_runner_self_test=@(Invoke-WLabChildSelfTest $WLabExe $script:out)
if(!(Alive)){throw 'Selected process changed or exited; no memory read started'}
Log 'Checking signatures of three fixed Windows DLL files (local disk only).'
$trustEntries=@()
foreach($dll in @('kernel32.dll','KernelBase.dll','ntdll.dll')){
$dp=Join-Path ([Environment]::SystemDirectory) $dll
try{
$h1=(Get-FileHash -LiteralPath $dp -Algorithm SHA256).Hash.ToLowerInvariant()
$sg=Get-AuthenticodeSignature -LiteralPath $dp
$h2=(Get-FileHash -LiteralPath $dp -Algorithm SHA256).Hash.ToLowerInvariant()
if($h1 -ne $h2){throw 'DLL file changed during signature validation'}
$subject='';if($null -ne $sg.SignerCertificate){$subject=[string]$sg.SignerCertificate.Subject}
$trustEntries+=[ordered]@{path=$dp;sha256=$h2;status=[string]$sg.Status;subject=$subject}
}catch{$trustEntries+=[ordered]@{path=$dp;sha256='';status='CheckFailed';subject=''}}
Pump
}
$tm=[ordered]@{source='PowerShell Get-AuthenticodeSignature + Get-FileHash';entries=@($trustEntries)}
[IO.File]::WriteAllText((Join-Path $script:out 'trust.json'),($tm|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
if($script:cancel -or !(Alive)){throw 'Cancelled or selected process changed before the slot read'}
$script:r.state='reading';$script:r.read_helper_requested=$true;WriteRun
Log 'Checking slot geometry and mapped-file NT paths against the pinned DLL; only then one exact 8-byte read. No protection changes.'
$script:helper=Start-WLabChild $WLabExe @('--read-once',([string]$script:t.Id),([string]$script:t.StartFileTime),('"'+$script:out+'"')) (Join-Path $script:out 'read')
$cancel.Enabled=$true;$until=[DateTime]::UtcNow.AddSeconds(45)
while(!(Test-WLabChildExited $script:helper)){
if($script:cancel -or [DateTime]::UtcNow -gt $until){StopHelperOnly;$script:r.wrapper_timeout_or_cancel=$true;break};Pump
}
if(!(Test-WLabChildExited $script:helper)){throw 'Owned read helper exit not confirmed; do not repeat'}
$script:r.read_helper_result=Complete-WLabChild $script:helper
$analysisPath=Join-Path $script:out 'analysis.json'
if(Test-Path -LiteralPath $analysisPath){$analysis=[IO.File]::ReadAllText($analysisPath)|ConvertFrom-Json;$script:r.analysis_status=$analysis.status
if($analysis.status -eq 'api_slot_sample_complete'){$script:r.state='api_slot_sample_complete';Log ('Sample validated; resolution: '+$analysis.resolution.status);foreach($entry in @($analysis.resolution.matching_exports)){if($null -ne $entry){Log ('Matching disk export: '+$entry.name)}};Log 'A match is not proof of execution or page decryption.'}else{$script:r.state='read_stopped';Log ('Read stopped: '+$analysis.error)}
}else{$script:r.state='read_helper_no_analysis';Log 'No analysis report was produced; send the small wrapper report without retrying.'}
$cancel.Enabled=$false
# Metadata-only observation of the same game process; no more memory reads.
$obs=New-Object 'Collections.Generic.List[object]'
foreach($i in 0..2){
$a=Alive;$responding=$null;if($a){try{$responding=(Get-Process -Id $script:t.Id).Responding}catch{}}
$obs.Add([pscustomobject]@{utc=[DateTime]::UtcNow.ToString('o');same_process_alive=$a;responding=$responding})
if($i -lt 2 -and !$script:cancel){$wait=[DateTime]::UtcNow.AddSeconds(5);while([DateTime]::UtcNow -lt $wait -and !$script:cancel){Pump}}
}
$script:r.observations=$obs.ToArray()
}catch{Log $_.Exception.Message;if($null -ne $script:r){$script:r.state='wrapper_stopped';$script:r.error=$_.Exception.Message}}
finally{
StopHelperOnly
if($null -ne $script:r){
$script:r.finished_utc=[DateTime]::UtcNow.ToString('o');$script:r.cancel_requested=$script:cancel;WriteRun
try{
$z=Join-Path $script:run 'READY-TO-SEND.zip';$pack=Start-WLabChild $WLabExe @('--bundle',('"'+$script:out+'"'),('"'+$z+'"')) (Join-Path $script:out 'bundle')
if($pack.Process.WaitForExit(15000)){$pr=Complete-WLabChild $pack;if($pr.status -eq 'succeeded'){Log 'READY-TO-SEND.zip is ready. Send this report and say whether the game stayed usable.'}else{Log 'Packing did not succeed; local report files remain.'}}else{Log 'Packing still running; local report files remain.'}
}catch{Log ('Packing error: '+$_.Exception.Message)}
$open.Enabled=$true;try{Start-Process explorer.exe -ArgumentList ('"'+$script:run+'"')}catch{}
}
Release-WLabCaptureLock $script:captureLock;$script:captureLock=$null;$script:busy=$false;$cancel.Enabled=$false
Log 'One attempt ended. No automatic retry and no proof of CPU/BIOS network sending.'
}
})
Log 'One fixed 8-byte API slot. No code-page capture, dump, debugger, target writes or downloads.'
Log ('Startup logs: '+$WLabLogDir)
RefreshList
try{[void]$form.ShowDialog()}finally{Release-WLabCaptureLock $script:captureLock}
