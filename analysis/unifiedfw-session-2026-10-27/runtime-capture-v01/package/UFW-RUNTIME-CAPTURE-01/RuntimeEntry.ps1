Set-StrictMode -Version 2.0
function Get-UfwRuntimeRoot {
 [void](Get-UfwProgramCandidateNativeRoot)
 return Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'UnifiedFW-RuntimeCapture-01'
}
function Assert-UfwRuntimeJournal($Data){
 if($null -eq $Data -or (@($Data.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'actor_sid,audit_plan,created_utc,schema,session_id' -or $Data.schema -isnot [string] -or $Data.schema -cne 'ufw-runtime-audit-journal-01' -or $Data.actor_sid -isnot [string] -or $Data.actor_sid -cnotmatch '^S-1-[0-9]+(-[0-9]+)+$' -or $Data.session_id -isnot [string] -or $Data.session_id -cnotmatch '^[a-f0-9]{32}$' -or $Data.created_utc -isnot [string]){throw 'ufw_runtime_journal_shape'}
 $time=[datetime]::MinValue;if(-not [datetime]::TryParseExact($Data.created_utc,'yyyy-MM-dd HH:mm:ss.fffffff \U\T\C',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$time)){throw 'ufw_runtime_journal_shape'}
 Assert-UfwRuntimeAuditPlan $Data.audit_plan
}
function Read-UfwRuntimePending {
 $root=Get-UfwRuntimeRoot;if(-not [IO.Directory]::Exists($root)){return $null};Assert-UfwJournalAcl $root $true
 $path=Join-Path $root 'audit-pending.json';if(-not [IO.File]::Exists($path)){return $null};Assert-UfwJournalAcl $path $false
 $f=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{if($f.Length -lt 2 -or $f.Length -gt 16384){throw 'ufw_runtime_journal_size'};$reader=New-Object IO.StreamReader($f,[Text.Encoding]::UTF8,$true,4096,$true);try{$text=$reader.ReadToEnd()}finally{$reader.Dispose()}}finally{$f.Dispose()}
 $en=ConvertFrom-Json $text
 if((@($en.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'payload,sha256' -or $en.payload -isnot [string] -or $en.sha256 -isnot [string] -or $en.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $en.sha256 -cne (Get-UfwJournalHash $en.payload)){throw 'ufw_runtime_journal_checksum'}
 $data=ConvertFrom-Json $en.payload;Assert-UfwRuntimeJournal $data
 return [pscustomobject]@{data=$data;head=$en.sha256;readback_verified=$true}
}
function Write-UfwRuntimePending($Data){
 Assert-UfwRuntimeJournal $Data;$root=Get-UfwRuntimeRoot
 if([IO.Directory]::Exists($root)){Assert-UfwJournalAcl $root $true}else{New-UfwPrivateJournalDirectory $root}
 $payload=Get-UfwCandidateJson $Data;$head=Get-UfwJournalHash $payload
 $bytes=[Text.Encoding]::UTF8.GetBytes((Get-UfwCandidateJson ([pscustomobject][ordered]@{payload=$payload;sha256=$head})))
 $f=Open-UfwPrivateJournalFile (Join-Path $root 'audit-pending.json') ([IO.FileMode]::CreateNew)
 try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
 $back=Read-UfwRuntimePending;if($back.head -cne $head){throw 'ufw_runtime_journal_readback'};return $back
}
function Archive-UfwRuntimePending($Journal){
 $back=Read-UfwRuntimePending
 if($null -eq $back -or $back.head -cne $Journal.head){throw 'ufw_runtime_journal_changed'}
 $root=Get-UfwRuntimeRoot;$from=Join-Path $root 'audit-pending.json';$to=Join-Path $root ('audit-restored-'+$back.data.session_id+'.json')
 if([IO.File]::Exists($to) -or [IO.Directory]::Exists($to)){throw 'ufw_runtime_archive_collision'}
 Assert-UfwJournalAcl $root $true;Assert-UfwJournalAcl $from $false;[IO.File]::Move($from,$to);Assert-UfwJournalAcl $to $false
}
function Get-UfwRuntimeSystemHostPath {return Join-Path ([Environment]::SystemDirectory) 'svchost.exe'}
function Get-UfwRuntimeFirewallGuard {
 $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
 if($profiles.Count -ne 3 -or (@($profiles.Name|Sort-Object)-join ',') -cne 'Domain,Private,Public'){throw 'ufw_runtime_firewall_profiles'}
 foreach($p in $profiles){if([string]$p.Enabled -cne 'True' -or [string]$p.DefaultOutboundAction -cne 'Block'){throw 'ufw_runtime_firewall_not_blocked_no_launch'}}
 $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
 if($rules.Count -gt 32768){throw 'ufw_runtime_firewall_rule_cap'}
 $allows=@($rules|Where-Object{[string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow'})
 $foreign=0;$transport=0
 foreach($rule in $allows){
  # Only already-existing exact SstpSvc/TCP443/literal-unicast transport grants may remain.
  $service=@($rule|Get-NetFirewallServiceFilter -ErrorAction Stop);$app=@($rule|Get-NetFirewallApplicationFilter -ErrorAction Stop);$port=@($rule|Get-NetFirewallPortFilter -ErrorAction Stop);$address=@($rule|Get-NetFirewallAddressFilter -ErrorAction Stop)
  $dynamic=@();if($rule.PSObject.Properties.Name -contains 'RemoteDynamicKeywordAddresses'){$dynamic=@($rule.RemoteDynamicKeywordAddresses|Where-Object{-not [string]::IsNullOrWhiteSpace([string]$_)})}
  $ok=$dynamic.Count -eq 0 -and $service.Count -eq 1 -and $app.Count -eq 1 -and $port.Count -eq 1 -and $address.Count -eq 1
  if($ok){$ok=[string]$service[0].Service -ceq 'SstpSvc' -and [string]::Equals([string]$app[0].Program,(Get-UfwRuntimeSystemHostPath),[StringComparison]::OrdinalIgnoreCase) -and [string]$port[0].Protocol -cin @('TCP','6') -and @($port[0].RemotePort).Count -eq 1 -and [string]$port[0].RemotePort -ceq '443'}
  if($ok){$ips=@($address[0].RemoteAddress);if($ips.Count -lt 1 -or $ips.Count -gt 8){$ok=$false};foreach($text in $ips){$ip=$null;if(-not [Net.IPAddress]::TryParse([string]$text,[ref]$ip) -or $null -eq (Get-UfwRuntimeEndpoint ([string]$text) 443 6)){$ok=$false}}}
  if($ok){$transport++}else{$foreign++}
 }
 if($foreign -gt 0){throw 'ufw_runtime_unreviewed_allow_rules_no_launch'}
 return [pscustomobject]@{profiles_blocked=$true;existing_sstp_transport_rules=$transport;unreviewed_allow_rules=$foreign;isolation_certified=$false}
}
function Get-UfwRuntimeDeviceMap {
 $out=@();foreach($drive in [IO.DriveInfo]::GetDrives()){
  if($drive.DriveType -eq [IO.DriveType]::Fixed){$name=$drive.Name.Substring(0,2);$out+=,[pscustomobject]@{drive=$name;device=[UfwRuntime01.Audit]::Device($name)}}
 };if($out.Count -lt 1){throw 'ufw_runtime_device_mapping_empty'};return ,@($out|Sort-Object drive)
}
function Get-UfwRuntimeLogEdge([bool]$Reverse){
 $query=New-Object Diagnostics.Eventing.Reader.EventLogQuery('Security',[Diagnostics.Eventing.Reader.PathType]::LogName,'*');$query.ReverseDirection=$Reverse
 $reader=New-Object Diagnostics.Eventing.Reader.EventLogReader($query)
 try{$event=$reader.ReadEvent();if($null -eq $event){throw 'ufw_runtime_security_log_empty'};try{return [long]$event.RecordId}finally{$event.Dispose()}}finally{$reader.Dispose()}
}
function Read-UfwRuntimeEvents([long]$Start,[long]$End,$Map){
 $oldest=Get-UfwRuntimeLogEdge $false;$latest=Get-UfwRuntimeLogEdge $true
 if($oldest -gt ($Start+1) -or $latest -lt $Start -or $End -lt $Start){throw 'ufw_runtime_security_log_gap'}
 $xpath='*[System[(EventID=4688 or EventID=4689 or EventID=5156 or EventID=5157 or EventID=1101 or EventID=1102 or EventID=1104 or EventID=4719) and EventRecordID > '+$Start+' and EventRecordID <= '+$End+']]'
 $query=New-Object Diagnostics.Eventing.Reader.EventLogQuery('Security',[Diagnostics.Eventing.Reader.PathType]::LogName,$xpath);$query.ReverseDirection=$false
 $reader=New-Object Diagnostics.Eventing.Reader.EventLogReader($query);$out=@();$parseErrors=0
 try{
  while($null -ne ($e=$reader.ReadEvent())){
   try{
    if($out.Count -ge 50000){throw 'ufw_runtime_event_limit'}
    try{$out+=,(ConvertFrom-UfwRuntimeXml $e.ToXml() $Map)}catch{
     # Unknown/malformed lifecycle event creates a conservative attribution barrier, never a stale PID match.
     $parseErrors++;$out+=,[pscustomobject]@{id=$(if([int]$e.Id -cin @(4688,4689,1101,1102,1104)){0}else{-1});record=[long]$e.RecordId;time=$e.TimeCreated.ToUniversalTime()}
    }
   }finally{$e.Dispose()}
  }
 }finally{$reader.Dispose()}
 if((Get-UfwRuntimeLogEdge $false) -gt ($Start+1)){throw 'ufw_runtime_security_log_gap'}
 return [pscustomobject]@{events=$out;parse_errors=$parseErrors}
}
function Test-UfwRuntimeNativeEvents($Map){
 # Diagnostic child only, NEVER the selected program. No shell, no credentials, no payload.
 $path=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
 $code=@'
$ErrorActionPreference='Stop';$c=New-Object Net.Sockets.TcpClient;try{$task=$c.ConnectAsync([Net.IPAddress]::Parse('192.0.2.1'),9);if(-not $task.Wait(2000)){exit 3};if($c.Connected){exit 4};exit 2}catch{$e=$_.Exception;while($e.InnerException){$e=$e.InnerException};if($e -is [Net.Sockets.SocketException] -and $e.NativeErrorCode -eq 10013){exit 0};exit 2}finally{$c.Close()}
'@
 $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=$path;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.Arguments='-NoLogo -NoProfile -NonInteractive -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
 $start=Get-UfwRuntimeLogEdge $true;$process=New-Object Diagnostics.Process;$process.StartInfo=$info
 try{
  if(-not $process.Start()){throw 'ufw_runtime_selftest_child_start'};$childId=[int]$process.Id
  if(-not $process.WaitForExit(10000)){try{$process.Kill()}catch{};throw 'ufw_runtime_selftest_child_timeout'}
  if($process.ExitCode -ne 0){throw 'ufw_runtime_selftest_not_access_denied_no_launch'}
  $watch=[Diagnostics.Stopwatch]::StartNew()
  try{
   do{
    $batch=Read-UfwRuntimeEvents $start (Get-UfwRuntimeLogEdge $true) $Map
    $starts=@($batch.events|Where-Object{$_.id -eq 4688 -and $_.pid -eq $childId -and [string]::Equals($_.path,$path,[StringComparison]::OrdinalIgnoreCase)})
    $stops=@($batch.events|Where-Object{$_.id -eq 4689 -and $_.pid -eq $childId -and [string]::Equals($_.path,$path,[StringComparison]::OrdinalIgnoreCase)})
    $blocks=@($batch.events|Where-Object{$_.id -eq 5157 -and $_.pid -eq $childId -and $_.direction -ceq '%%14593' -and $_.address -ceq '192.0.2.1' -and $_.port -eq 9 -and $_.protocol -eq 6 -and [string]::Equals($_.path,$path,[StringComparison]::OrdinalIgnoreCase)})
    if($starts.Count -eq 1 -and $stops.Count -ge 1 -and $blocks.Count -ge 1){return $true}
    Start-Sleep -Milliseconds 500
   }while($watch.Elapsed.TotalSeconds -lt 8)
  }finally{$watch.Stop()}
  throw 'ufw_runtime_selftest_events_missing_no_launch'
 }finally{$process.Dispose()}
}
function Confirm-UfwRuntime([string]$Mode,$Programs){
 Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
 $f=New-Object System.Windows.Forms.Form
 try{
  $f.Width=1040;$f.Height=700;$f.StartPosition='CenterScreen';$f.MinimizeBox=$false;$f.Text='Runtime capture - explicit local consent; NOT isolation certification'
  $text=New-Object System.Windows.Forms.TextBox;$text.Multiline=$true;$text.ReadOnly=$true;$text.ScrollBars='Both';$text.Dock='Fill'
  if($Mode -ceq 'recovery'){$text.Text='A protected unfinished audit session exists. Recover restores ONLY its three saved audit subcategory masks if current masks match saved before/during states. No capture, installer launch, firewall, VPN or old baseline changes. Other-policy drift refuses recovery; never delete the pending file to bypass. Windows Security records are NOT erased.';$label='Recover audit settings only'}
  else{
   $lines=@('Review the EXACT saved program(s) below. After consent the collector arms BEFORE you manually launch the installer from normal Explorer. It does NOT launch or kill programs. First close previous instances.','This is an experimental RECORDER, not a sandbox, no-leak/fingerprint guarantee, complete WFP enforcement or protection against administrator/GPO/third-party WFP/existing flows/loopback/IPC. If you require that guarantee before execution, Cancel. No new firewall Allow is added. The existing firewall must pass the conservative read-only gate; otherwise NO READY and do not launch. A running installer (especially elevated) could change policy or install services; this collector does NOT prevent or undo that. Periodic checks are not atomic enforcement. If that risk is unacceptable, Cancel; do not run the installer.','A harmless diagnostic PowerShell child first attempts one TCP connect to documentation address 192.0.2.1:9 with NO data payload. It must be denied by Windows (10013), and matching process-start/blocked-connect/process-stop Security events must be seen, or NO READY is shown. The helper is not the selected installer. Consent temporarily enables system-wide connection success/failure and process start/stop audit, backs up these three masks in protected storage, and restores them on normal exit/error. Windows Security records include paths/IPs and possibly command lines if your existing policy already includes them. These records remain after audit restore; nothing is cleared. Other processes are logged by Windows too. Only relevant proposals are separately saved privately.','READY window lasts at most 90 seconds. Start target yourself ONLY after READY. If you stop/end/timeout, close the installer yourself; the collector never terminates it or undoes installation. Descendants are unreviewed observations, NEVER auto-approved. DNS broker/services may not be attributable; missing data never proves no traffic.','Crash/power loss may leave audit enabled. Re-run THIS SAME package for explicit recovery before a new capture. Do not delete the pending journal. Cancel starts no capture and changes no audit masks. Consent expires after 2 minutes. Do not share screenshot/transcript.','')
   foreach($p in $Programs){$lines+=@($p.program_id,('Path: '+$p.path),('SHA256: '+$p.sha256),'')};$text.Text=$lines -join [Environment]::NewLine;$label='Arm capture (manual launch after READY)'
  }
  $panel=New-Object System.Windows.Forms.FlowLayoutPanel;$panel.Dock='Bottom';$panel.Height=50;$panel.FlowDirection='RightToLeft'
  $cancel=New-Object System.Windows.Forms.Button;$cancel.Text='Cancel';$cancel.Width=120;$cancel.DialogResult='Cancel'
  $yes=New-Object System.Windows.Forms.Button;$yes.Text=$label;$yes.Width=330;$yes.DialogResult='OK'
  $panel.Controls.Add($cancel);$panel.Controls.Add($yes);$f.Controls.Add($text);$f.Controls.Add($panel);$f.CancelButton=$cancel;$f.ActiveControl=$cancel
  return ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK)
 }finally{$f.Dispose()}
}
function Show-UfwRuntimeWindow($Guard){
 $f=New-Object System.Windows.Forms.Form;$timer=New-Object System.Windows.Forms.Timer;$watch=[Diagnostics.Stopwatch]::StartNew()
 $state=[pscustomobject]@{interrupted=$false;guard_code='';timed_out=$false;last_guard=0.0}
 try{
  $f.Text='READY - runtime audit active; launch saved installer yourself';$f.Width=900;$f.Height=360;$f.StartPosition='CenterScreen'
  $label=New-Object System.Windows.Forms.Label;$label.Dock='Fill';$label.Text='READY: Now launch the reviewed installer yourself from normal Explorer. No new network Allow has been opened. This collector does not start/kill the installer. Close the installer before End capture. Do not send screenshots. Maximum 90 seconds.'
  $end=New-Object System.Windows.Forms.Button;$end.Dock='Bottom';$end.Height=50;$end.Text='End capture - installer must be closed by you';$end.DialogResult='OK';$f.Controls.Add($label);$f.Controls.Add($end)
  $timer.Interval=500
  $timer.Add_Tick({
   try{
    $left=[Math]::Max(0,90-[int]$watch.Elapsed.TotalSeconds);$f.Text='READY - capture active; remaining '+$left+' seconds'
    if($watch.Elapsed.TotalSeconds-$state.last_guard -ge 5){& $Guard|Out-Null;$state.last_guard=$watch.Elapsed.TotalSeconds}
    if($watch.Elapsed.TotalSeconds -ge 90){$state.timed_out=$true;$f.Close()}
   }catch{$state.interrupted=$true;$state.guard_code='ufw_runtime_guard_changed_during_capture';$f.Close()}
  }.GetNewClosure())
  $timer.Start();[void]$f.ShowDialog();return $state
 }finally{$timer.Stop();$timer.Dispose();$watch.Stop();$f.Dispose()}
}
function Save-UfwRuntimeProposals($Data){
 $root=Get-UfwRuntimeRoot;Assert-UfwJournalAcl $root $true
 $dir=Join-Path $root ('capture-'+[guid]::NewGuid().ToString('N'));New-UfwPrivateJournalDirectory $dir
 $payload=Get-UfwCandidateJson $Data;$head=Get-UfwJournalHash $payload;$bytes=[Text.Encoding]::UTF8.GetBytes((Get-UfwCandidateJson ([pscustomobject][ordered]@{payload=$payload;sha256=$head})))
 if($bytes.Length -gt 2097152){throw 'ufw_runtime_proposal_size'}
 $path=Join-Path $dir 'runtime-proposals.json';$f=Open-UfwPrivateJournalFile $path ([IO.FileMode]::CreateNew)
 try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
 Assert-UfwJournalAcl $path $false
 $f=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{if($f.Length -ne $bytes.Length){throw 'ufw_runtime_proposal_readback'};$rd=New-Object IO.StreamReader($f,[Text.Encoding]::UTF8,$true,4096,$true);try{$text=$rd.ReadToEnd()}finally{$rd.Dispose()}}finally{$f.Dispose()}
 if($text -cne [Text.Encoding]::UTF8.GetString($bytes)){throw 'ufw_runtime_proposal_readback'}
 return [pscustomobject]@{head=$head;readback_verified=$true}
}
function Invoke-UfwRuntimeCallbacks($Ops){
 $r=[ordered]@{schema='ufw-runtime-capture-result-01';completed=$false;stage='pending_recovery_check';code='';mode='capture';candidate_read_verified=$false;file_observation_passes=0;consent_received=$false;firewall_preflight_passed=$false;audit_journal_write_attempted=$false;audit_change_requested=$false;audit_during_verified=$false;selftest_requested=$false;selftest_verified=$false;audit_restore_verified=$false;audit_recovery_required=$false;ready_displayed=$false;capture_window_completed=$false;capture_interrupted=$false;root_start_events=0;descendant_start_events=0;blocked_events=0;permitted_events=0;suggestion_count=0;unattributed_network_events=0;excluded_network_events=0;integrity_warning_events=0;parse_error_events=0;selected_file_revalidation_failed=$false;private_proposals_saved=$false;private_write_status='not_requested';raw_identity_exported=$false;target_launched_by_tool=$false;target_terminated_by_tool=$false;candidate_write_requested=$false;baseline_journal_access_requested=$false;firewall_change_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;packet_capture_requested=$false;security_log_cleared=$false;destinations_approved=$false;complete_coverage=$false;isolation_certified=$false;ready_for_apply=$false;no_leak_certified=$false;fingerprint_prevention_certified=$false}
 $transaction=$false;$journal=$null;$private=$null
 try{
  foreach($k in @('Pending','Confirm','Actor','AuditQuery','AuditSet','Archive','Select','Load','Observe','Clock','FirewallGuard','ExistingProcesses','DeviceMap','WriteJournal','LogEdge','SelfTest','Window','ReadEvents','Save')){if(-not $Ops.ContainsKey($k) -or $Ops[$k] -isnot [scriptblock]){throw 'ufw_runtime_adapter_missing'}}
  $pending=& $Ops.Pending
  if($null -ne $pending){
   $r.mode='audit_recovery';$r.audit_recovery_required=$true;Assert-UfwRuntimeJournal $pending.data
   if($pending.readback_verified -isnot [bool] -or -not $pending.readback_verified -or $pending.head -cne (Get-UfwJournalHash (Get-UfwCandidateJson $pending.data)) -or (& $Ops.Actor) -cne $pending.data.actor_sid){throw 'ufw_runtime_pending_unverified_or_actor'}
   $answer=& $Ops.Confirm 'recovery' @();if($answer -isnot [bool] -or -not $answer){$r.completed=$true;$r.code='ufw_runtime_recovery_cancelled_pending';return [pscustomobject]$r}
   $r.consent_received=$true;$r.stage='explicit_audit_recovery';$r.audit_restore_verified=Restore-UfwRuntimeAuditPlan $pending.data.audit_plan $Ops.AuditQuery $Ops.AuditSet
   & $Ops.Archive $pending;$r.audit_recovery_required=$false;$r.completed=$true;$r.stage='completed';$r.code='ufw_runtime_audit_recovered_no_capture';return [pscustomobject]$r
  }
  $r.stage='select_existing_candidate';$s=& $Ops.Select
  if($null -eq $s -or $s.cancelled -isnot [bool] -or $s.path -isnot [string]){throw 'ufw_runtime_selection_shape'}
  if($s.cancelled){$r.completed=$true;$r.code='ufw_runtime_cancelled_no_capture';return [pscustomobject]$r}
  $record=& $Ops.Load $s.path;Assert-UfwObserverRecord $record;$data=$record.data;$head=$record.head;$digest=Get-UfwCandidateProgramDigest $data.programs
  $actor=& $Ops.Actor;if($actor -isnot [string] -or $actor -cne $data.receipt.actor_sid){throw 'ufw_runtime_same_actor_required'};$r.candidate_read_verified=$true
  $paths=@($data.programs|ForEach-Object{$_.path});$fresh=ConvertTo-UfwCandidatePrograms $paths $Ops.Observe;$r.file_observation_passes=1
  if((Get-UfwCandidateProgramDigest $fresh) -cne $digest){throw 'ufw_runtime_selected_file_changed'}
  $r.stage='read_only_firewall_gate';$gate=& $Ops.FirewallGuard
  if($gate.profiles_blocked -isnot [bool] -or -not $gate.profiles_blocked -or $gate.unreviewed_allow_rules -ne 0){throw 'ufw_runtime_firewall_gate_no_launch'};$r.firewall_preflight_passed=$true
  $running=& $Ops.ExistingProcesses $data.programs;if($running -isnot [array] -or $running.Count -gt 0){throw 'ufw_runtime_target_already_running_no_launch'}
  $plan=Get-UfwRuntimeAuditPlan $Ops.AuditQuery;$start=& $Ops.Clock
  if($start -isnot [datetime] -or $start.Kind -ne [DateTimeKind]::Utc){throw 'ufw_runtime_clock'}
  $r.stage='explicit_local_capture_consent';$answer=& $Ops.Confirm 'capture' $data.programs
  if($answer -isnot [bool] -or -not $answer){$r.completed=$true;$r.code='ufw_runtime_cancelled_no_capture';return [pscustomobject]$r};$r.consent_received=$true
  $now=& $Ops.Clock;if($now -isnot [datetime] -or $now.Kind -ne [DateTimeKind]::Utc -or $now -lt $start -or $now -gt $start.AddSeconds(120) -or (& $Ops.Actor) -cne $actor){throw 'ufw_runtime_consent_expired_or_actor_changed'}
  $again=& $Ops.Load $s.path;Assert-UfwObserverRecord $again;if($again.head -cne $head){throw 'ufw_runtime_candidate_changed'}
  $fresh=ConvertTo-UfwCandidatePrograms $paths $Ops.Observe;$r.file_observation_passes=2;if((Get-UfwCandidateProgramDigest $fresh) -cne $digest){throw 'ufw_runtime_selected_file_changed'}
  if((Get-UfwCandidateJson (Get-UfwRuntimeAuditPlan $Ops.AuditQuery)) -cne (Get-UfwCandidateJson $plan)){throw 'ufw_runtime_audit_changed_before_arm'}
  $map=& $Ops.DeviceMap;$mapHead=Get-UfwCandidateJson $map
  $journalData=[pscustomobject][ordered]@{schema='ufw-runtime-audit-journal-01';session_id=[guid]::NewGuid().ToString('N');actor_sid=$actor;created_utc=($now.ToString('yyyy-MM-dd HH:mm:ss.fffffff',[Globalization.CultureInfo]::InvariantCulture)+' UTC');audit_plan=$plan};Assert-UfwRuntimeJournal $journalData
  $r.stage='protected_audit_backup';$r.audit_journal_write_attempted=$true;$r.audit_recovery_required=$true;$journal=& $Ops.WriteJournal $journalData
  if($journal.readback_verified -isnot [bool] -or -not $journal.readback_verified -or $journal.head -cne (Get-UfwJournalHash (Get-UfwCandidateJson $journalData))){throw 'ufw_runtime_journal_unverified'}
  $transaction=$true;$r.stage='arm_scoped_audit'
  foreach($p in $plan){
   if((& $Ops.AuditQuery $p.id) -ne $p.before){throw 'ufw_runtime_audit_drift_before_set'}
   if($p.before -ne $p.during){$r.audit_change_requested=$true;& $Ops.AuditSet $p.id $p.during}
   if((& $Ops.AuditQuery $p.id) -ne $p.during){throw 'ufw_runtime_audit_arm_unverified'}
  }
  $r.audit_during_verified=$true
  # Re-check immediately before showing READY. No launch is performed by this code.
  $guard={
   $g=& $Ops.FirewallGuard;if(-not $g.profiles_blocked -or $g.unreviewed_allow_rules -ne 0){throw 'ufw_runtime_firewall_gate_no_launch'}
   foreach($p in $plan){if((& $Ops.AuditQuery $p.id) -ne $p.during){throw 'ufw_runtime_audit_drift_during_capture'}}
  }.GetNewClosure()
  & $guard|Out-Null;$r.stage='native_runtime_blocked_selftest';$r.selftest_requested=$true;$test=& $Ops.SelfTest $map
  if($test -isnot [bool] -or -not $test){throw 'ufw_runtime_selftest_failed_no_launch'};$r.selftest_verified=$true
  & $guard|Out-Null;$running=& $Ops.ExistingProcesses $data.programs;if($running.Count -gt 0){throw 'ufw_runtime_target_started_before_ready'}
  $startRecord=& $Ops.LogEdge $true;$begin=& $Ops.Clock;$r.stage='runtime_capture_manual_launch_window'
  $window=& $Ops.Window $guard;$r.ready_displayed=$true;$r.capture_window_completed=$true;$r.capture_interrupted=[bool]$window.interrupted
  $end=& $Ops.Clock;$endRecord=& $Ops.LogEdge $true
  if($end -isnot [datetime] -or $end.Kind -ne [DateTimeKind]::Utc -or $end -lt $begin -or $end -gt $begin.AddSeconds(180)){throw 'ufw_runtime_capture_clock_window'}
  if((Get-UfwCandidateJson (& $Ops.DeviceMap)) -cne $mapHead){throw 'ufw_runtime_device_mapping_changed'}
  $r.stage='read_security_event_window';$batch=& $Ops.ReadEvents $startRecord $endRecord $map;$r.parse_error_events=$batch.parse_errors
  $proposals=Get-UfwRuntimeProposals $batch.events $data.programs $actor $begin $end
  foreach($k in @('root_start_events','descendant_start_events','blocked_events','permitted_events','unattributed_network_events','excluded_network_events','integrity_warning_events')){$r[$k]=$proposals.$k}
  $r.suggestion_count=$proposals.endpoints.Count
  $post=& $Ops.Load $s.path;Assert-UfwObserverRecord $post;if($post.head -cne $head){throw 'ufw_runtime_candidate_changed'}
  # A real installer may update/remove itself. Do not bless such changes or silently replace the saved candidate.
  try{$fresh=ConvertTo-UfwCandidatePrograms $paths $Ops.Observe;$r.file_observation_passes=3;if((Get-UfwCandidateProgramDigest $fresh) -cne $digest){$r.selected_file_revalidation_failed=$true}}catch{$r.selected_file_revalidation_failed=$true}
  $private=[pscustomobject][ordered]@{schema='ufw-runtime-proposals-01';candidate_id=$data.candidate_id;candidate_head=$head;created_utc=$end.ToString('o');source='Windows_Security_4688_4689_5156_5157';programs=$proposals.programs;endpoints=$proposals.endpoints;interrupted=$r.capture_interrupted;selected_file_revalidation_failed=$r.selected_file_revalidation_failed;integrity_warning_events=$proposals.integrity_warning_events;parse_errors=$batch.parse_errors;complete_coverage=$false;destinations_approved=$false;ready_for_apply=$false;execution_authorized=$false}
  $r.code='ufw_runtime_events_collected_restore_pending'
 }catch{
  $msg=[string]$_.Exception.GetBaseException().Message
  if($msg -cmatch '^(ufw_runtime|ufw_observer|ufw_candidate|ufw_program|ufw_journal)_[a-z_0-9]{1,100}$'){$r.code=$msg}else{$r.code='ufw_runtime_unavailable'}
 }finally{
  if($transaction){
   try{
    $r.stage='restore_scoped_audit';$r.audit_restore_verified=Restore-UfwRuntimeAuditPlan $journal.data.audit_plan $Ops.AuditQuery $Ops.AuditSet
    & $Ops.Archive $journal;$r.audit_recovery_required=$false
   }catch{$r.code='ufw_runtime_audit_recovery_required';$r.audit_recovery_required=$true}
  }
 }
 # Persist only after audit restore has been verified. Never overwrite a candidate or baseline journal.
 if($null -ne $private -and $r.audit_restore_verified -and -not $r.audit_recovery_required){
  try{
   $r.stage='private_proposal_write';$r.private_write_status='attempted_may_exist_inspect_if_failed';$saved=& $Ops.Save $private
   if($saved.readback_verified -isnot [bool] -or -not $saved.readback_verified -or $saved.head -cne (Get-UfwJournalHash (Get-UfwCandidateJson $private))){throw 'ufw_runtime_proposal_unverified'}
   $r.private_proposals_saved=$true;$r.private_write_status='saved_unapproved_runtime_proposals';$r.completed=$true;$r.stage='completed'
   if($r.selected_file_revalidation_failed -or $r.capture_interrupted -or $r.integrity_warning_events -gt 0 -or $r.parse_error_events -gt 0){$r.code='ufw_runtime_partial_events_not_coverage_proof'}
   elseif($r.root_start_events -eq 0){$r.code='ufw_runtime_no_selected_start_not_safety_proof'}
   elseif($r.suggestion_count -eq 0){$r.code='ufw_runtime_selected_started_zero_endpoints_not_safety_proof'}else{$r.code='ufw_runtime_proposals_pending_review'}
  }catch{$r.completed=$false;$r.code='ufw_runtime_private_proposal_write_unverified'}
 }
 return [pscustomobject]$r
}
function Invoke-UfwRuntimeNative {
 $ops=@{Pending={Read-UfwRuntimePending};Confirm={param($mode,$p)Confirm-UfwRuntime $mode $p};Actor={[Security.Principal.WindowsIdentity]::GetCurrent().User.Value};AuditQuery={param($id)[UfwRuntime01.Audit]::Query($id)};AuditSet={param($id,$value)[UfwRuntime01.Audit]::Set($id,[uint32]$value)};Archive={param($j)Archive-UfwRuntimePending $j};Select={Select-UfwObserverCandidate};Load={param($p)Read-UfwObserverCandidate $p};Observe={param($p)Read-UfwProgramNativeObservation $p};Clock={[datetime]::UtcNow};FirewallGuard={Get-UfwRuntimeFirewallGuard};ExistingProcesses={param($p)Get-UfwObserverProcesses $p};DeviceMap={Get-UfwRuntimeDeviceMap};WriteJournal={param($d)Write-UfwRuntimePending $d};LogEdge={param($reverse)Get-UfwRuntimeLogEdge $reverse};SelfTest={param($map)Test-UfwRuntimeNativeEvents $map};Window={param($guard)Show-UfwRuntimeWindow $guard};ReadEvents={param($start,$end,$map)Read-UfwRuntimeEvents $start $end $map};Save={param($d)Save-UfwRuntimeProposals $d}}
 return Invoke-UfwRuntimeCallbacks $ops
}
