$ErrorActionPreference='Stop'
$base=$PSScriptRoot
$run=$null;$owned=@();$watch=$null;$state=$null;$manifest=$null;$mutex=$null;$mutexHeld=$false
$report=[ordered]@{schema='game-tls-test-result-1';version='0.1.0';status='preflight';setup_stage='preflight';error_code=$null;exe_name=$null;exe_sha256=$null;proxy_version='12.2.3';temporary_root_installed=$false;cleanup=$null;content=$null;limits=@{process_scope_is_exe_basename_not_exclusive_path=$true;native_windows_tested_by_builder=$false;no_protection_bypass=$true;not_prevention_of_first_disclosure=$true}}
function Write-State {
 $tmp=Join-Path $run 'cleanup-state.tmp'
 $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding UTF8
 Move-Item -LiteralPath $tmp -Destination (Join-Path $run 'cleanup-state.json') -Force
}
function Launch-Proxy([string]$Phase,[string]$Folder,[string]$Mode) {
 $stop=Join-Path $Folder 'stop.flag';Remove-Item -LiteralPath $stop -Force -ErrorAction SilentlyContinue
 $oldRun=$env:INGEST_PROBE_RUN;$oldPhase=$env:INGEST_PROBE_PHASE;$oldKeys=$env:SSLKEYLOGFILE
 try {
  $env:INGEST_PROBE_RUN=$Folder;$env:INGEST_PROBE_PHASE=$Phase;$env:SSLKEYLOGFILE=$null
  $addon=Join-Path $base 'app\ingest_probe.py';$conf=Join-Path $run 'ca'
  $args=@('--mode',$Mode,'--listen-host','127.0.0.1','--listen-port','0','--set',('confdir="'+$conf+'"'),'-s',('"'+$addon+'"'),
   '--set','ssl_insecure=false',
   '--set','strip_ech=false','--set','flow_detail=0','--set','termlog_verbosity=error',
   '--set','stream_large_bodies=256k','--set','store_streamed_bodies=false','--set','connection_strategy=lazy')
  $p=Start-Process -FilePath $binary -ArgumentList $args -PassThru -WorkingDirectory $base -WindowStyle Hidden -RedirectStandardOutput (Join-Path $Folder 'private-stdout.log') -RedirectStandardError (Join-Path $Folder 'private-stderr.log')
  $script:owned+=,$p
  $script:state.processes+=@{pid=$p.Id;start_ticks=$p.StartTime.ToUniversalTime().Ticks.ToString()};Write-State
  return $p
 } finally { $env:INGEST_PROBE_RUN=$oldRun;$env:INGEST_PROBE_PHASE=$oldPhase;$env:SSLKEYLOGFILE=$oldKeys }
}
function Wait-Ready($Process,[string]$Folder) {
 $until=[DateTime]::UtcNow.AddSeconds(35)
 while([DateTime]::UtcNow -lt $until) {
  if ($Process.HasExited) { throw 'proxy_exited_before_ready' }
  if (Test-Path -LiteralPath (Join-Path $Folder 'addon-ready.flag')) { return }
  Start-Sleep -Milliseconds 200
 }
 throw 'proxy_ready_timeout'
}
function Stop-Owned($Process,[string]$Folder) {
 'stop' | Set-Content -LiteralPath (Join-Path $Folder 'stop.flag') -Encoding ASCII
 if (!$Process.WaitForExit(8000)) { throw 'proxy_graceful_stop_timeout_cleanup_required' }
}
try {
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 $principal=New-Object Security.Principal.WindowsPrincipal($id)
 if (![Environment]::Is64BitProcess -or ![Environment]::Is64BitOperatingSystem) { throw 'windows_x64_required' }
 if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run_as_administrator_with_same_windows_user' }
 $mutex=[Threading.Mutex]::new($false,('Global\WowIngestTLS-'+$id.User.Value))
 try { $mutexHeld=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $mutexHeld=$true }
 if (!$mutexHeld) { throw 'another_tls_test_is_running' }
 # Reject reparse locations before reading package code or trusting any certificate.
 $walk=Get-Item -LiteralPath $base
 while($null -ne $walk) { if ($walk.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_package_path_refused' };$walk=$walk.Parent }
 $manifest=Get-Content -LiteralPath (Join-Path $base 'SHA256.json') -Raw | ConvertFrom-Json
 foreach($prop in $manifest.PSObject.Properties) {
  if ($prop.Name -notmatch '^[A-Za-z0-9_./-]+$' -or $prop.Name.Split('/') -contains '..') { throw 'manifest_invalid_path' }
  $f=Join-Path $base $prop.Name
  if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ne $prop.Value) { throw 'package_integrity_failed' }
 }
 $binary=Join-Path $base 'bin\mitmdump.exe'
 $report.setup_stage='exe_selection'
 Add-Type -AssemblyName System.Windows.Forms
 $picker=New-Object System.Windows.Forms.OpenFileDialog
 $picker.Filter='Windows executable (*.exe)|*.exe';$picker.Title='Select Wow.exe (game must be closed)'
 if ($picker.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { $report.status='cancelled';return }
 $game=$picker.FileName;$name=[IO.Path]::GetFileName($game)
 if ($name -notmatch '^[A-Za-z0-9_.-]{1,60}\.exe$') { throw 'simple_exe_name_required' }
 if ($game.StartsWith('\\')) { throw 'network_executable_refused' }
 $item=Get-Item -LiteralPath $game
 if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_executable_refused' }
 $report.exe_name=$name;$report.exe_sha256=(Get-FileHash -LiteralPath $game -Algorithm SHA256).Hash.ToLowerInvariant()
 if (@(Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($name)) -ErrorAction SilentlyContinue).Count -gt 0) { throw 'close_selected_game_then_retry' }
 Write-Host 'This test changes CurrentUser trusted roots TEMPORARILY. It is not a per-domain root.' -ForegroundColor Yellow
 Write-Host 'TLS interception applies to connections of the selected executable NAME, not just one domain.'
 Write-Host 'Account and OAuth traffic, cached tokens, and hardware identifiers may be visible locally.'
 Write-Host ('Local interception targets processes named '+$name+'. Keep other instances closed.')
 Write-Host 'Do not enter login credentials. Close unrelated apps. No anti-cheat bypass is performed.'
 if ((Read-Host 'Type TLS to consent and start') -cne 'TLS') { $report.status='cancelled';return }
 $report.setup_stage='private_directory'
 $root=Join-Path $env:LOCALAPPDATA 'WowIngestTLS'
 if (!(Test-Path -LiteralPath $root)) { New-Item -Path $root -ItemType Directory | Out-Null }
 $walk=Get-Item -LiteralPath $root
 while($null -ne $walk) { if ($walk.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_private_path_refused' };$walk=$walk.Parent }
 $run=Join-Path $root ('run-'+[Guid]::NewGuid().ToString('N'))
 New-Item -Path $run -ItemType Directory | Out-Null
 # Private directory: only this Windows account, SYSTEM, and Administrators.
 $acl=Get-Acl -LiteralPath $run;$acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @($id.User.Value,'S-1-5-18','S-1-5-32-544')) {
  $who=New-Object Security.Principal.SecurityIdentifier($sid)
  $rule=New-Object Security.AccessControl.FileSystemAccessRule($who,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
  $acl.AddAccessRule($rule)
 }
 Set-Acl -LiteralPath $run -AclObject $acl
 $state=[ordered]@{schema='ingest-cleanup-1';user_sid=$id.User.Value;remove_root=$false;thumbprint=$null;processes=@()};Write-State
 $boot=Join-Path $run 'bootstrap';New-Item -Path $boot -ItemType Directory | Out-Null
 $report.setup_stage='proxy_bootstrap'
 $p=Launch-Proxy 'bootstrap' $boot 'regular';Wait-Ready $p $boot;Stop-Owned $p $boot
 $report.setup_stage='temporary_root_install'
 $pem=Get-Content -LiteralPath (Join-Path $run 'ca\mitmproxy-ca-cert.pem') -Raw
 $der=[Convert]::FromBase64String(($pem -replace '-----BEGIN CERTIFICATE-----','' -replace '-----END CERTIFICATE-----','' -replace '\s',''))
 $cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
 $store=New-Object Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
 try {
  $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  if ($store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$cert.Thumbprint,$false).Count -gt 0) { throw 'unexpected_preexisting_generated_root_do_not_remove' }
  # Persist removal intent BEFORE adding trust; finite worker is armed first.
  $state.thumbprint=$cert.Thumbprint;$state.remove_root=$true;Write-State
  $cleaner=Join-Path $base 'Cleanup.ps1';$powershell=Join-Path $PSHOME 'powershell.exe'
  $watchArgs=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$cleaner+'"'),'-RunDir',('"'+$run+'"'),'-Watch')
  $watch=Start-Process -FilePath $powershell -ArgumentList $watchArgs -WindowStyle Hidden -PassThru
  Start-Sleep -Milliseconds 300
  if ($watch.HasExited) { throw 'cleanup_watchdog_did_not_start' }
  # Make emergency rollback available before the trust store is changed.
  ('@echo off'+"`r`n"+'"'+$powershell+'" -NoProfile -ExecutionPolicy Bypass -File "'+$cleaner+'" -RunDir "'+$run+'"'+"`r`n"+'pause'+"`r`n") | Set-Content -LiteralPath (Join-Path $run 'Restore.cmd') -Encoding ASCII
  $store.Add($cert)
  if ($store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$cert.Thumbprint,$false).Count -ne 1) { throw 'temporary_root_install_not_verified' }
  $report.temporary_root_installed=$true
 } finally { $store.Close() }
 $report.setup_stage='local_capture_start'
 $proxy=Launch-Proxy 'capture' $run ('local:'+$name);Wait-Ready $proxy $run
 Write-Host 'TLS READY. Open the selected game yourself NOW; stop at the login screen.' -ForegroundColor Green
 Write-Host 'Do not enter credentials. Q ends early. Maximum test time: 90 seconds.'
 Write-Host ('Emergency cleanup: '+(Join-Path $run 'Restore.cmd'))
 $report.setup_stage='capturing'
 $report.status='observing';$until=[DateTime]::UtcNow.AddSeconds(90)
 while([DateTime]::UtcNow -lt $until) {
  if ($proxy.HasExited) { $report.status='proxy_exited';break }
  if (Test-Path -LiteralPath (Join-Path $run 'tls-failed.flag')) { $report.status='tls_failed_stopped_no_bypass';break }
  if ([Console]::KeyAvailable -and [Console]::ReadKey($true).Key -eq [ConsoleKey]::Q) { $report.status='user_stopped';break }
  Start-Sleep -Milliseconds 250
 }
 if ($report.status -eq 'observing') { $report.status='observation_ended' }
 $report.setup_stage='normal_stop'
 Stop-Owned $proxy $run
} catch {
 $report.status='stopped'
 $msg=$_.Exception.Message
 $report.error_code=if ($msg -cmatch '^[a-z0-9_]{1,100}$') { $msg } else { 'local_setup_or_proxy_failed' }
 $report.exception_type=$_.Exception.GetType().Name
 $report.exception_hresult=$_.Exception.HResult
 Write-Host ('STOP: '+$report.error_code) -ForegroundColor Red
} finally {
 if ($null -ne $run) {
  try {
   'cleanup' | Set-Content -LiteralPath (Join-Path $run 'cleanup-now.flag') -Encoding ASCII
   & (Join-Path $base 'Cleanup.ps1') -RunDir $run
   if (Test-Path -LiteralPath (Join-Path $run 'cleanup-result.json')) { $report.cleanup=Get-Content -LiteralPath (Join-Path $run 'cleanup-result.json') -Raw | ConvertFrom-Json }
  } catch { $report.cleanup=@{root_absence_verified=$false;manual_restore_required=$true};Write-Host 'ATTENTION: temporary root cleanup not verified. Run Restore.cmd for this test.' -ForegroundColor Red }
  if (Test-Path -LiteralPath (Join-Path $run 'ingest-content.json')) { try { $report.content=Get-Content -LiteralPath (Join-Path $run 'ingest-content.json') -Raw | ConvertFrom-Json } catch {} }
 }
 # Fallback for a process launched just before state persistence failed.
 foreach($p in $owned) { try { if (!$p.HasExited) { $p.Kill();$p.WaitForExit(5000) | Out-Null } } catch {} }
 $out=Join-Path $base 'output';if (!(Test-Path -LiteralPath $out)) { New-Item -Path $out -ItemType Directory | Out-Null }
 $dest=Join-Path $out ('game-tls-test-'+[DateTime]::UtcNow.Ticks+'.json')
 $report | ConvertTo-Json -Depth 24 | Set-Content -LiteralPath $dest -Encoding UTF8
 Write-Host ('SEND ONLY THIS JSON: '+$dest) -ForegroundColor Cyan
 if ($null -ne $run) { Write-Host ('PRIVATE local samples and CA keys (DO NOT SEND): '+$run) }
 Write-Host 'No game process was launched, killed, patched or paused. No automatic upload occurred.'
 if ($mutexHeld) { $mutex.ReleaseMutex() }
 if ($null -ne $mutex) { $mutex.Dispose() }
}
