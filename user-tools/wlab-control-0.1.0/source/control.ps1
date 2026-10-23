$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
function Notice($s){[void][Windows.Forms.MessageBox]::Show($s,'WLab Control')}
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(!$admin){[IO.File]::WriteAllText((Join-Path $WLabLogDir 'elevation-handoff.txt'),'Requesting administrator launch');try{Start-Process -FilePath $WLabExe -Verb RunAs}catch{Notice 'Administrator approval was not granted.'};return}
$form=New-Object Windows.Forms.Form;$form.Text='WLab Control 0.1.0 - Own process tests only'
$form.ClientSize=New-Object Drawing.Size(790,500);$form.StartPosition='CenterScreen';$form.FormBorderStyle='FixedDialog';$form.MaximizeBox=$false;$form.ShowInTaskbar=$true
$form.Font=New-Object Drawing.Font('Segoe UI',10)
$form.Add_Shown({[IO.File]::WriteAllText((Join-Path $WLabLogDir 'ui-ready.txt'),'Shown event; not proof of visibility');$form.Activate()})
function Control($type,$text,$x,$y,$w,$h){$c=New-Object ('Windows.Forms.'+$type);$c.Text=$text;$c.SetBounds($x,$y,$w,$h);$form.Controls.Add($c);return $c}
[void](Control Label 'Two diagnostic dumps of a NEW WLab test worker only. No Wow/game access.' 15 15 760 28)
[void](Control Label 'Output folder (use G: for this test):' 15 55 280 28)
$path=Control TextBox 'G:\WLabControl' 295 52 345 30
$browse=Control Button 'Browse' 655 50 115 32
$agree=Control CheckBox 'I accept the Microsoft Sysinternals EULA for these two owned-process tests.' 15 95 750 30
$view=Control Button 'View EULA' 15 135 150 35
$start=Control Button 'Run control tests once' 185 135 270 40
$stop=Control Button 'Stop tests' 475 135 135 40;$stop.Enabled=$false
$open=Control Button 'Open results' 630 135 140 40;$open.Enabled=$false
$log=Control TextBox '' 15 195 755 285;$log.Multiline=$true;$log.ReadOnly=$true;$log.ScrollBars='Vertical'
$script:busy=$false;$script:cancel=$false;$script:run='';$script:out='';$script:worker=$null;$script:activeCapture=$null;$script:captureLock=$null;$script:r=$null
function Log($s){$log.AppendText(([DateTime]::Now.ToString('HH:mm:ss'))+'  '+$s+"`r`n");[Windows.Forms.Application]::DoEvents()}
function WriteRun{[IO.File]::WriteAllText((Join-Path $script:out 'run.json'),($script:r|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))}
function Pump{[Windows.Forms.Application]::DoEvents();Start-Sleep -Milliseconds 50}
function WaitOwned($job,[int]$seconds){
$until=[DateTime]::UtcNow.AddSeconds($seconds)
while(!(Test-WLabChildExited $job)){
if($script:cancel -or [DateTime]::UtcNow -gt $until){return $false};Pump
}
return $true
}
function WaitExitUninterruptible($job,[int]$seconds){
$until=[DateTime]::UtcNow.AddSeconds($seconds)
while(!(Test-WLabChildExited $job)) {if([DateTime]::UtcNow -gt $until){return $false};Pump}
return $true
}
function StopOwnedChild($job){
if($null -eq $job){return}
try{if(!(Test-WLabChildExited $job)){$job.Process.Kill();[void]$job.Process.WaitForExit(3000)};if(Test-WLabChildExited $job){[void](Complete-WLabChild $job)}}catch{}
}
function RunCase([string]$name,[bool]$clone){
# PID is only from the Process.Start object created for --control-worker below.
if($null -eq $script:worker -or (Test-WLabChildExited $script:worker)){throw 'Owned test worker exited; no capture attempted'}
$pidText=[string]$script:worker.Pid
$dump=Join-Path $script:run ($name+'.dmp')
$argsList=@('-accepteula','-ma');if($clone){$argsList+=@('-r','1')}
$argsList+=@('-n','1','-at','30',$pidText,('"'+$dump+'"'))
$c=[ordered]@{name=$name;target='owned WLab control worker only';target_pid=$script:worker.Pid;clone=$clone;arguments=($argsList -join ' ');started_utc=[DateTime]::UtcNow.ToString('o');timed_out_or_cancelled=$false;result=$null;dump_header=$null;worker_alive_after=$null}
$script:r.cases.Add($c);WriteRun
Log ('Running '+$name+' against owned WLab worker PID '+$pidText+'; NOT the game.')
$job=Start-WLabChild $script:pd $argsList (Join-Path $script:out $name);$script:activeCapture=$job
if(!(WaitOwned $job 45)){
$c.timed_out_or_cancelled=$true
Log 'Requesting documented cancellation for the OWNED worker target only.'
$cancelName=if($clone){'cancel-clone'}else{'cancel-direct'}
$cj=Start-WLabChild $script:pd @('-accepteula','-cancel',$pidText) (Join-Path $script:out $cancelName)
if(WaitExitUninterruptible $cj 5){$c.cancel_result=Complete-WLabChild $cj}else{StopOwnedChild $cj}
if(!(WaitExitUninterruptible $job 15)){
# Both this ProcDump and its target were created by this control test.
StopOwnedChild $job
$c.owned_capture_forced_stop=$true
}
}
if(Test-WLabChildExited $job){$c.result=Complete-WLabChild $job}else{throw 'Owned capture worker still running; stop further tests'}
Convert-WLabProcDumpLog $job.Stdout (Join-Path $script:out ($name+'.decoded.txt'))
$c.dump_header=Read-WLabDumpHeader $dump
$c.worker_alive_after=!(Test-WLabChildExited $script:worker)
$script:activeCapture=$null;$c.finished_utc=[DateTime]::UtcNow.ToString('o');WriteRun
Log ($name+': exit status '+$c.result.status+', exit code '+$c.result.exit_code+', dump bytes '+$c.dump_header.size_bytes)
}
$browse.Add_Click({$d=New-Object Windows.Forms.FolderBrowserDialog;$d.Description='Choose an output folder on a drive with space for two small test-worker dumps.';if($d.ShowDialog() -eq 'OK'){$path.Text=Join-Path $d.SelectedPath 'WLabControl'};$d.Dispose()})
$view.Add_Click({Start-Process 'https://learn.microsoft.com/en-us/sysinternals/license-terms'})
$stop.Add_Click({$script:cancel=$true;$stop.Enabled=$false})
$open.Add_Click({Start-Process explorer.exe -ArgumentList ('"'+$script:run+'"')})
$form.Add_FormClosing({param($s,$e)if($script:busy){$e.Cancel=$true;Notice 'Use Stop tests and wait. Only owned diagnostic children will be stopped.'}})
$start.Add_Click({
if($script:busy){return};if(!$agree.Checked){Notice 'Read the EULA and tick acceptance first.';return}
$root=$path.Text.Trim();if($root -notmatch '^[A-Za-z]:[\\/]'){Notice 'Choose an absolute local drive path, such as G:\WLabControl.';return}
$start.Enabled=$false;$browse.Enabled=$false;$path.Enabled=$false;$stop.Enabled=$true;$script:busy=$true
try{
$cache=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'WLabSnapshot'
$script:captureLock=Acquire-WLabCaptureLock $cache
if(@(Get-Process -Name procdump,procdump64,procdump64a -ErrorAction SilentlyContinue).Count -gt 0){throw 'Another ProcDump is running; no tests started'}
$script:run=Join-Path $root ((Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8));$script:out=Join-Path $script:run 'report'
[void](New-Item -ItemType Directory -Force -Path $script:out)
$script:r=[ordered]@{tool='WLab Control 0.1.0';state='preparing';started_utc=[DateTime]::UtcNow.ToString('o');game_access_requested=$false;game_capture_requested=$false;output_directory=$script:run;network_sending='unresolved';cases=(New-Object 'Collections.Generic.List[object]')}
WriteRun;Log ('Control output: '+$script:run)
$script:r.space_before=Get-WLabOutputSpace $script:run
if((Get-WLabSpaceGate $script:r.space_before 1GB) -ne 'sufficient'){throw 'Need a successful native query and at least 1 GiB for owned-process diagnostics; no game capture involved'}
$script:r.write_probe=Invoke-WLabWriteProbe $script:run
$script:r.child_runner_self_test=@(Invoke-WLabChildSelfTest $WLabExe $script:out)
$tools=Join-Path $cache 'tools-22c2a2b0'
$prep=Start-WLabChild $WLabExe @('--prepare',('"'+$tools+'"')) (Join-Path $script:out 'preparation')
if(!(WaitOwned $prep 90)){StopOwnedChild $prep;throw 'Preparation cancelled or timed out'}
$script:r.preparation_result=Complete-WLabChild $prep
if($script:r.preparation_result.status -ne 'succeeded'){throw 'Preparation did not succeed'}
$script:pd=Join-Path $tools 'procdump64.exe'
$sha=(Get-FileHash -LiteralPath $script:pd -Algorithm SHA256).Hash.ToLowerInvariant()
$sig=Get-AuthenticodeSignature -LiteralPath $script:pd
$script:r.procdump_sha256=$sha;$script:r.signature_status=[string]$sig.Status
if($sha -ne '22c2a2b09ade73a342a18dab838354385f73fc98e324b9903fd61fff949c5124' -or $sig.Status -ne 'Valid' -or !$sig.SignerCertificate -or $sig.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)'){throw 'Microsoft tool hash/signature gate failed'}
if($script:cancel){throw 'Cancelled before worker start'}
$ready=Join-Path $script:out 'control-worker-ready.json'
$script:worker=Start-WLabChild $WLabExe @('--control-worker',('"'+$ready+'"')) (Join-Path $script:out 'control-worker')
$until=[DateTime]::UtcNow.AddSeconds(10)
$readyData=$null
while($null -eq $readyData){
if(Test-Path -LiteralPath $ready){try{$candidate=[IO.File]::ReadAllText($ready)|ConvertFrom-Json;if($null -ne $candidate -and $candidate.pid -gt 0){$readyData=$candidate}}catch{}}
if($null -eq $readyData){if($script:cancel -or [DateTime]::UtcNow -gt $until -or (Test-WLabChildExited $script:worker)){throw 'Owned worker readiness not confirmed'};Pump}
}
if($readyData.pid -ne $script:worker.Pid){throw 'Owned worker PID mismatch'}
$script:r.owned_worker_pid=$script:worker.Pid;$script:r.state='running_controls';WriteRun
RunCase 'control-clone' $true
if($script:cancel){throw 'Cancelled; direct test not started'}
RunCase 'control-direct' $false
$script:r.state='control_tests_complete';$script:r.space_after=Get-WLabOutputSpace $script:run
}catch{Log $_.Exception.Message;if($null -ne $script:r){$script:r.state='control_tests_stopped';$script:r.error=$_.Exception.Message}}
finally{
# Never enumerate or terminate game processes. The only worker object is owned.
StopOwnedChild $script:activeCapture
StopOwnedChild $script:worker
if($null -ne $script:r){
$script:r.finished_utc=[DateTime]::UtcNow.ToString('o');$script:r.cancel_requested=$script:cancel;WriteRun
try{
$z=Join-Path $script:run 'READY-TO-SEND.zip'
$pack=Start-WLabChild $WLabExe @('--bundle',('"'+$script:out+'"'),('"'+$z+'"')) (Join-Path $script:out 'bundle')
if(WaitExitUninterruptible $pack 15){$pr=Complete-WLabChild $pack;if($pr.status -eq 'succeeded'){Log 'READY-TO-SEND.zip is ready; send this small report only.'}else{Log 'Packing did not succeed; report files remain local.'}}else{Log 'Packing still running; report files remain local.'}
}catch{Log ('Packing error: '+$_.Exception.Message)}
$open.Enabled=$true;try{Start-Process explorer.exe -ArgumentList ('"'+$script:run+'"')}catch{}
}
Release-WLabCaptureLock $script:captureLock;$script:captureLock=$null;$script:busy=$false;$stop.Enabled=$false
Log 'Control test ended. No game capture was attempted; this does not establish game capture support or network behavior.'
}
})
Log 'Own-process control test only. You may close the game; it is not needed.'
Log ('Startup logs: '+$WLabLogDir)
try{[void]$form.ShowDialog()}finally{Release-WLabCaptureLock $script:captureLock}
