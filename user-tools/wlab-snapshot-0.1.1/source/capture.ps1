$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
function Notice($s){[void][Windows.Forms.MessageBox]::Show($s,'WLab Snapshot')}
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(!$admin){[IO.File]::WriteAllText((Join-Path $WLabLogDir 'elevation-handoff.txt'),'Requesting administrator launch');try{Start-Process -FilePath $WLabExe -Verb RunAs}catch{Notice 'Administrator approval was not granted.'};return}
$form=New-Object Windows.Forms.Form
$form.Text='WLab Snapshot 0.1.1 - One capture only'
$form.ShowInTaskbar=$true
$form.Add_Shown({[IO.File]::WriteAllText((Join-Path $WLabLogDir 'ui-ready.txt'),'UI shown');$form.Activate()})
$form.ClientSize=New-Object Drawing.Size(790,490)
$form.StartPosition='CenterScreen';$form.FormBorderStyle='FixedDialog';$form.MaximizeBox=$false
$form.Font=New-Object Drawing.Font('Segoe UI',10)
function Control($type,$text,$x,$y,$w,$h){$c=New-Object ('Windows.Forms.'+$type);$c.Text=$text;$c.SetBounds($x,$y,$w,$h);$form.Controls.Add($c);return $c}
[void](Control Label 'Open the test game first. Select it, choose your current screen, then capture once.' 15 15 760 28)
$list=Control ComboBox '' 15 52 545 30;$list.DropDownStyle='DropDownList'
$refresh=Control Button 'Refresh' 575 50 195 32
[void](Control Label 'Current game screen (your report, not automatically detected):' 15 95 460 27)
$stage=Control ComboBox '' 480 91 290 30;$stage.DropDownStyle='DropDownList'
[void]$stage.Items.Add('Character selection');[void]$stage.Items.Add('In world');$stage.SelectedIndex=0
$agree=Control CheckBox 'I accept the Microsoft Sysinternals EULA for this capture.' 15 135 580 28
$view=Control Button 'View EULA' 615 132 155 32
$cap=Control Button 'Capture once' 15 177 240 40
$cancel=Control Button 'Cancel capture' 275 177 240 40;$cancel.Enabled=$false
$folder=Control Button 'Open results' 535 177 235 40;$folder.Enabled=$false
$log=Control TextBox '' 15 235 755 235;$log.Multiline=$true;$log.ReadOnly=$true;$log.ScrollBars='Vertical'
$script:captureLock=$null
$script:busy=$false;$script:used=$false;$script:run='';$script:stt='idle';$script:cs=$false
function Log($s){$log.AppendText(([DateTime]::Now.ToString('HH:mm:ss'))+'  '+$s+"`r`n")}
function RefreshList{
$list.Items.Clear();$script:ts=@()
foreach($p in @(Get-Process -Name Wow -ErrorAction SilentlyContinue)){try{$o=[pscustomobject]@{Id=$p.Id;Start=$p.StartTime.ToUniversalTime().Ticks;Path=$p.Path};$script:ts+= $o;[void]$list.Items.Add(('Wow.exe  PID '+$p.Id))}catch{}}
if($list.Items.Count){$list.SelectedIndex=0}else{Log 'No accessible Wow.exe found. Open the game and refresh.'}
}
function Alive{
try{$p=Get-Process -Id $script:t.Id -ErrorAction Stop;return ($p.StartTime.ToUniversalTime().Ticks -eq $script:t.Start)}catch{return $false}
}
function WriteRun{
$script:r.state=$script:stt;$script:r.cancel_requested=$script:cs
$script:r.observations=@($script:obs.ToArray());$script:r.updated_utc=[DateTime]::UtcNow.ToString('o')
$j=$script:r | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText((Join-Path $script:out 'run.json'),$j,[Text.UTF8Encoding]::new($false))
}
function Helper($argsList){Start-Process -FilePath $WLabExe -ArgumentList $argsList -WindowStyle Hidden -PassThru}
function Finish($s){
$timer.Stop();$script:stt=$s;$script:r.finished_utc=[DateTime]::UtcNow.ToString('o');WriteRun
try{$z=Join-Path $script:run 'READY-TO-SEND.zip';$h=Helper @('--bundle',('"'+$script:out+'"'),('"'+$z+'"'));if(!$h.WaitForExit(15000)){Log 'Report packing is still running; output files remain in the results folder.'}elseif($h.ExitCode -ne 0){Log 'Packing failed; output files remain in the results folder.'}else{Log 'READY-TO-SEND.zip is ready.'}}catch{Log $_.Exception.Message}
if($s -ne 'capture_still_running_cancel_unconfirmed'){Release-WLabCaptureLock $script:captureLock;$script:captureLock=$null}
$script:busy=$false;$cancel.Enabled=$false;$folder.Enabled=$true
Log ('Result: '+$s+'. This does NOT establish game stability or network sending.')
Log 'Keep snapshot.dmp locally. Send READY-TO-SEND.zip and say whether the game stayed usable.'
try{Start-Process explorer.exe -ArgumentList ('"'+$script:run+'"')}catch{}
}
function RequestCancel($reason){
if($script:stt -eq 'preparing'){try{if(!$script:job.HasExited){$script:job.Kill();[void]$script:job.WaitForExit(3000)}}catch{};Finish 'preparation_cancelled';return}
if($script:stt -ne 'capturing' -or $script:cs){return};$script:cs=$true;$script:r.cancel_reason=$reason;$script:ct=[DateTime]::UtcNow
Log ('Requesting documented graceful ProcDump cancellation: '+$reason)
try{$script:cj=Start-Process -FilePath $script:pd -ArgumentList @('-accepteula','-cancel',([string]$script:t.Id)) -WindowStyle Hidden -PassThru}catch{Log ('Cancel request failed: '+$_.Exception.Message)}
}
$timer=New-Object Windows.Forms.Timer;$timer.Interval=1000
$timer.Add_Tick({try{
if($script:stt -eq 'preparing'){
$script:job.Refresh()
if($script:job.HasExited){$script:job.WaitForExit();$script:r.prepare_exit_code=$script:job.ExitCode
if($script:job.ExitCode -ne 0){$script:r.prepare_error=Get-Content -LiteralPath (Join-Path $script:out 'preparation-error.txt') -Raw;Finish 'preparation_failed';return}
$script:stt='preflight';$cancel.Enabled=$false;WriteRun;BeginCapture
}elseif(([DateTime]::UtcNow-$script:prepStart).TotalSeconds -gt 90){RequestCancel 'preparation timeout'}
}elseif($script:stt -eq 'capturing'){
$script:job.Refresh()
if($script:job.HasExited){
$script:job.WaitForExit();$script:r.procdump_exit_code=$script:job.ExitCode
$dump=Join-Path $script:run 'snapshot.dmp'
if($script:job.ExitCode -ne 0 -or !(Test-Path -LiteralPath $dump) -or (Get-Item -LiteralPath $dump).Length -lt 32){Finish 'capture_failed';return}
$script:r.dump_bytes=(Get-Item -LiteralPath $dump).Length
Log 'Capture returned a dump. Validating module identity and extracting three code windows...'
$script:stt='extracting';$cancel.Enabled=$false
$script:hp=Helper @('--extract',('"'+$dump+'"'),('"'+$script:t.Path+'"'),('"'+$script:out+'"'));$script:est=[DateTime]::UtcNow
}else{
if((Get-PSDrive -Name ([IO.Path]::GetPathRoot($script:run).Substring(0,1))).Free -lt 1GB){RequestCancel 'less than 1 GiB free space'}
if(([DateTime]::UtcNow-$script:st).TotalSeconds -gt 180){RequestCancel '180-second wrapper timeout'}
if($script:cs -and ([DateTime]::UtcNow-$script:ct).TotalSeconds -gt 30){Finish 'capture_still_running_cancel_unconfirmed';return}
}
}elseif($script:stt -eq 'extracting'){
$script:hp.Refresh()
if($script:hp.HasExited){$script:hp.WaitForExit();$script:r.extract_exit_code=$script:hp.ExitCode
if($script:hp.ExitCode -ne 0){Finish 'dump_received_extraction_failed';return}
$script:stt='observing';$script:ost=[DateTime]::UtcNow;$script:no=[DateTime]::UtcNow
Log 'Extraction finished. Observing process for 60 seconds; continued playability needs your confirmation.'
}elseif(([DateTime]::UtcNow-$script:est).TotalSeconds -gt 120){Finish 'extraction_still_running';return}
}elseif($script:stt -eq 'observing'){
if([DateTime]::UtcNow -ge $script:no){$a=Alive;$responding=$null;if($a){try{$responding=(Get-Process -Id $script:t.Id).Responding}catch{}}
$script:obs.Add([pscustomobject]@{utc=[DateTime]::UtcNow.ToString('o');same_process_alive=$a;window_responding=$responding});$script:no=[DateTime]::UtcNow.AddSeconds(5)
if(!$a){Finish 'snapshot_extracted_target_exited';return}}
if(([DateTime]::UtcNow-$script:ost).TotalSeconds -ge 60){Finish 'snapshot_extracted_observation_complete';return}
}
}catch{Log $_.Exception.Message;if($script:stt -eq 'capturing'){RequestCancel 'wrapper error'}else{Finish 'wrapper_error'}}})
$refresh.Add_Click({RefreshList})
$view.Add_Click({Start-Process 'https://learn.microsoft.com/en-us/sysinternals/license-terms'})
$folder.Add_Click({Start-Process explorer.exe -ArgumentList ('"'+$script:run+'"')})
$cancel.Add_Click({RequestCancel 'user clicked cancel'})
function BeginCapture{
try{
$os=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if(($os.InstallationType -eq 'Client' -and [int]$os.CurrentBuildNumber -lt 22000) -or [int]$os.CurrentBuildNumber -lt 14393){throw 'This ProcDump package requires Windows 11 or Server 2016+.'}
$script:t=$script:ts[$list.SelectedIndex];if(!(Alive)){throw 'Selected process changed or exited. Refresh the list.'}
$script:pd=Join-Path $script:tools 'procdump64.exe'
Log 'Checking Microsoft tool signature and pinned hashes...';[Windows.Forms.Application]::DoEvents()
$script:r.procdump_sha256=(Get-FileHash -LiteralPath $script:pd -Algorithm SHA256).Hash.ToLower()
if($script:r.procdump_sha256 -ne '22c2a2b09ade73a342a18dab838354385f73fc98e324b9903fd61fff949c5124'){throw 'ProcDump hash mismatch.'}
$sig=Get-AuthenticodeSignature -LiteralPath $script:pd
if($sig.Status -ne 'Valid' -or !$sig.SignerCertificate -or $sig.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)'){throw 'ProcDump needs a valid Microsoft Authenticode signature.'}
$script:r.actual_wow_sha256=(Get-FileHash -LiteralPath $script:t.Path -Algorithm SHA256).Hash.ToLower()
if($script:r.actual_wow_sha256 -ne '1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a'){throw 'Wow.exe differs from build 12.1.5.70448. No capture was started.'}
if(@(Get-Process -Name procdump,procdump64,procdump64a -ErrorAction SilentlyContinue).Count -gt 0){throw 'Another ProcDump instance is running. No capture was started.'}
$script:r.signature_status=[string]$sig.Status
$script:r.windows_build=[string]$os.CurrentBuildNumber
if((Get-PSDrive -Name ([IO.Path]::GetPathRoot($script:run).Substring(0,1))).Free -lt 8GB){throw 'Need at least 8 GiB free; a full dump may need more.'}
if(!(Alive)){throw 'Selected process exited before capture.'}
$script:st=[DateTime]::UtcNow;$script:used=$true;$script:busy=$true;$script:stt='capturing';WriteRun
$dump=Join-Path $script:run 'snapshot.dmp'
$script:job=Start-Process -FilePath $script:pd -ArgumentList @('-accepteula','-ma','-r','1','-n','1','-at','120',([string]$script:t.Id),('"'+$dump+'"')) -RedirectStandardOutput (Join-Path $script:out 'procdump.stdout.txt') -RedirectStandardError (Join-Path $script:out 'procdump.stderr.txt') -WindowStyle Hidden -PassThru
$script:r.capture_started=$true;$script:r.capture_process_pid=$script:job.Id;WriteRun
$cancel.Enabled=$true;Log 'One clone-based capture started. No debugger/exception monitoring, retry or game launch is requested.';$timer.Start()
}catch{Log $_.Exception.Message;Finish 'capture_preflight_or_start_failed'}
}
$cap.Add_Click({
if($script:busy -or $script:used){return}
if(!$agree.Checked){Notice 'Read the EULA and tick acceptance first.';return}
if($list.SelectedIndex -lt 0){Notice 'Select the running test game first.';return}
$cap.Enabled=$false;$refresh.Enabled=$false;$list.Enabled=$false;$stage.Enabled=$false
try{
$script:t=$script:ts[$list.SelectedIndex]
$root=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'WLabSnapshot'
try{$script:captureLock=Acquire-WLabCaptureLock $root}catch{throw ('Capture lock unavailable; no capture was started. '+$_.Exception.Message)}
$script:tools=Join-Path $root 'tools-22c2a2b0'
$script:run=Join-Path $root ((Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8));$script:out=Join-Path $script:run 'report'
[void](New-Item -ItemType Directory -Force -Path $script:out)
$script:obs=New-Object 'Collections.Generic.List[object]'
$script:r=[ordered]@{tool='WLab Snapshot 0.1.1';started_utc=[DateTime]::UtcNow.ToString('o');target_pid=$script:t.Id;target_start_ticks=$script:t.Start;game_screen_user_reported=[string]$stage.SelectedItem;expected_wow_sha256='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a';capture_started=$false;capture_arguments_planned='-accepteula -ma -r 1 -n 1 -at 120 PID snapshot.dmp';stability='not established; ask user';network_sending='unresolved'}
$script:busy=$true;$script:used=$true;$script:stt='preparing';$script:prepStart=[DateTime]::UtcNow;WriteRun
Log 'Preparing ProcDump directly from Microsoft (first run needs Internet)...'
$script:job=Start-Process -FilePath $WLabExe -ArgumentList @('--prepare',('"'+$script:tools+'"')) -RedirectStandardError (Join-Path $script:out 'preparation-error.txt') -WindowStyle Hidden -PassThru
$cancel.Enabled=$true;$timer.Start()
}catch{Log $_.Exception.Message;if($script:busy){Finish 'preparation_start_failed'}else{Release-WLabCaptureLock $script:captureLock;$script:captureLock=$null;$cap.Enabled=$true;$refresh.Enabled=$true;$list.Enabled=$true;$stage.Enabled=$true}}
})
$form.Add_FormClosing({param($s,$e)if($script:busy){$e.Cancel=$true;Notice 'Use Cancel capture and wait for its result before closing. No game termination is performed.'}})
Log ('Startup log folder: '+$WLabLogDir)
Log 'Extract this package first. Windows approval may be required. No Python or debugger installation is needed.'
Log 'A full dump stays local; READY-TO-SEND.zip contains only a small code report. No automatic upload.'
RefreshList
try{[void]$form.ShowDialog()}finally{$timer.Stop();Release-WLabCaptureLock $script:captureLock;$script:captureLock=$null}
