# Passive TCP-table suggestions only. Not a recorder of denied traffic, packets or TLS content.
Set-StrictMode -Version 2.0
function Select-UfwObserverCandidate {
 Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
 $root=Get-UfwProgramCandidateNativeRoot
 Assert-UfwJournalAcl $root $true
 $d=New-Object System.Windows.Forms.OpenFileDialog
 try{
  $d.Title='Select EXISTING protected candidate.json - do not select an EXE'
  $d.Filter='Existing program candidate (candidate.json)|candidate.json';$d.InitialDirectory=$root
  $d.Multiselect=$false;$d.CheckFileExists=$true;$d.CheckPathExists=$true;$d.ValidateNames=$true
  $d.DereferenceLinks=$false;$d.RestoreDirectory=$true;$d.AutoUpgradeEnabled=$false;$d.AddExtension=$false
  if($d.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK){return [pscustomobject]@{cancelled=$true;path=''}}
  return [pscustomobject]@{cancelled=$false;path=[string]$d.FileName}
 }finally{$d.Dispose()}
}
function Read-UfwObserverCandidate([string]$Path){
 $root=Get-UfwProgramCandidateNativeRoot;Assert-UfwJournalAcl $root $true
 $full=[IO.Path]::GetFullPath($Path);$dir=[IO.Path]::GetDirectoryName($full)
 if([IO.Path]::GetFileName($full) -cne 'candidate.json' -or -not [string]::Equals([IO.Path]::GetDirectoryName($dir),$root,[StringComparison]::OrdinalIgnoreCase)){throw 'ufw_observer_candidate_location'}
 $name=[IO.Path]::GetFileName($dir)
 if($name -cnotmatch '^UfwProgramCandidate-([a-f0-9]{32})$'){throw 'ufw_observer_candidate_location'}
 $id=$Matches[1];return Read-UfwProgramCandidateRecord $dir $id
}
function Assert-UfwObserverRecord($Record){
 if($null -eq $Record -or $Record.readback_verified -isnot [bool] -or -not $Record.readback_verified -or $Record.head -isnot [string] -or $Record.head -cnotmatch '^[a-f0-9]{64}$'){throw 'ufw_observer_candidate_unverified'}
 Assert-UfwProgramCandidateData $Record.data $Record.data.candidate_id
 if((Get-UfwJournalHash (Get-UfwCandidateJson $Record.data)) -cne $Record.head){throw 'ufw_observer_candidate_head'}
}
function Confirm-UfwObserver($Programs){
 Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
 $f=New-Object System.Windows.Forms.Form
 try{
  $f.Text='Observe existing processes ONLY - no execution or firewall changes';$f.Width=1000;$f.Height=640;$f.StartPosition='CenterScreen';$f.MinimizeBox=$false
  $l=New-Object System.Windows.Forms.Label;$l.Dock='Top';$l.Height=115
  $l.Text='Review the saved programs below. Observe takes 15 passive TCP-table samples (~30 seconds) and saves private IP/port suggestions locally. The tool does NOT launch these programs or open the firewall. If they are not running, zero observations are expected. No DNS lookups, packet capture or audit enable. UDP, short and blocked connections can be missed. Nothing is approved. Cancel changes no candidate. Consent expires after 2 minutes. Do not share screenshots.'
  $t=New-Object System.Windows.Forms.TextBox;$t.Multiline=$true;$t.ReadOnly=$true;$t.WordWrap=$false;$t.ScrollBars='Both';$t.Dock='Fill'
  $lines=@();foreach($p in $Programs){$lines+=@($p.program_id,('Path: '+$p.path),('SHA256: '+$p.sha256),('Local file: '+$p.volume_id+':'+$p.file_id),('Header: '+$p.architecture),'')};$t.Text=$lines -join [Environment]::NewLine
  $panel=New-Object System.Windows.Forms.FlowLayoutPanel;$panel.Dock='Bottom';$panel.Height=50;$panel.FlowDirection='RightToLeft'
  $cancel=New-Object System.Windows.Forms.Button;$cancel.Text='Cancel';$cancel.Width=120;$cancel.DialogResult='Cancel'
  $ok=New-Object System.Windows.Forms.Button;$ok.Text='Observe and save suggestions';$ok.Width=250;$ok.DialogResult='OK'
  $panel.Controls.Add($cancel);$panel.Controls.Add($ok);$f.Controls.Add($t);$f.Controls.Add($panel);$f.Controls.Add($l);$f.CancelButton=$cancel;$f.ActiveControl=$cancel
  return ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK)
 }finally{$f.Dispose()}
}
function Get-UfwObserverProcesses($Programs){
 $out=@()
 foreach($p in @(Get-Process -ErrorAction Stop)){
  try{
   # Read only image path, PID, start time. No command line, memory or environment.
   $path=[string]$p.Path;$id=[int]$p.Id;$ticks=[long]$p.StartTime.ToUniversalTime().Ticks
   if($id -le 0 -or $ticks -le 0 -or $p.HasExited){continue}
   foreach($program in $Programs){if([string]::Equals($path,$program.path,[StringComparison]::OrdinalIgnoreCase)){$out+=,[pscustomobject]@{pid=$id;start_ticks=$ticks;path=$path};break}}
  }catch{
   # Inaccessible/exited processes cannot be attributed. This is not complete coverage.
  }finally{$p.Dispose()}
 }
 return ,$out
}
function Get-UfwObserverTcp {
 $out=@()
 foreach($r in @(Get-NetTCPConnection -ErrorAction Stop)){
  $out+=,[pscustomobject]@{pid=[int]$r.OwningProcess;remote_address=[string]$r.RemoteAddress;remote_port=[int]$r.RemotePort;state=[string]$r.State}
  if($out.Count -gt 65536){throw 'ufw_observer_tcp_table_limit'}
 }
 return ,$out
}
function Get-UfwObserverProcessMap($Rows,$Programs){
 if($Rows -isnot [array] -or $Rows.Count -gt 65536){throw 'ufw_observer_process_rows'}
 $out=@{}
 foreach($r in $Rows){
  if($null -eq $r -or $r.pid -isnot [int] -or $r.pid -le 0 -or $r.start_ticks -isnot [long] -or $r.start_ticks -le 0 -or $r.path -isnot [string]){throw 'ufw_observer_process_shape'}
  if($out.ContainsKey($r.pid)){throw 'ufw_observer_duplicate_pid'}
  foreach($p in $Programs){if([string]::Equals($r.path,$p.path,[StringComparison]::OrdinalIgnoreCase)){$out[$r.pid]=[pscustomobject]@{start_ticks=$r.start_ticks;path=$r.path;program_id=$p.program_id};break}}
 }
 return ,$out
}
function Add-UfwObserverSample($Before,$Rows,$After,$Programs,$Items){
 $b=Get-UfwObserverProcessMap $Before $Programs;$a=Get-UfwObserverProcessMap $After $Programs
 if($Rows -isnot [array] -or $Rows.Count -gt 65536){throw 'ufw_observer_tcp_rows'}
 $matched=0;$unstable=0;$excluded=0
 foreach($r in $Rows){
  if($null -eq $r -or $r.pid -isnot [int] -or $r.remote_address -isnot [string] -or $r.remote_port -isnot [int] -or $r.state -isnot [string]){throw 'ufw_observer_tcp_shape'}
  if(-not $b.ContainsKey($r.pid)){continue}
  if(-not $a.ContainsKey($r.pid) -or $a[$r.pid].start_ticks -ne $b[$r.pid].start_ticks -or -not [string]::Equals($a[$r.pid].path,$b[$r.pid].path,[StringComparison]::OrdinalIgnoreCase)){$unstable++;continue}
  if($r.state -cnotin @('Established','SynSent') -or $r.remote_port -lt 1 -or $r.remote_port -gt 65535){$excluded++;continue}
  $ip=$null
  if(-not [Net.IPAddress]::TryParse($r.remote_address,[ref]$ip)){throw 'ufw_observer_ip_invalid'}
  if($ip.IsIPv4MappedToIPv6){$ip=$ip.MapToIPv4()}
  $v4=$ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
  if(-not $v4 -and $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6){throw 'ufw_observer_ip_family'}
  $bytes=$ip.GetAddressBytes()
  if([Net.IPAddress]::IsLoopback($ip) -or $ip.Equals([Net.IPAddress]::Any) -or $ip.Equals([Net.IPAddress]::IPv6Any) -or ($v4 -and ($bytes[0] -eq 0 -or $bytes[0] -ge 224)) -or (-not $v4 -and ($ip.IsIPv6Multicast -or $ip.IsIPv6LinkLocal -or $ip.ScopeId -ne 0)) -or ($v4 -and $bytes[0] -eq 169 -and $bytes[1] -eq 254)){$excluded++;continue}
  $address=$ip.ToString();$program=$b[$r.pid].program_id;$key=$program+'|'+$address+'|'+$r.remote_port
  if(-not $Items.ContainsKey($key)){
   if($Items.Count -ge 256){throw 'ufw_observer_endpoint_limit'}
   $Items[$key]=[pscustomobject][ordered]@{program_id=$program;address=$address;port=$r.remote_port;protocol='TCP';direction='unknown_tcp_table';approval='not_reviewed';observations=0}
  }
  $Items[$key].observations++;$matched++
 }
 return [pscustomobject]@{matched=$matched;unstable=$unstable;excluded=$excluded;stable_processes=@($b.Keys|Where-Object{$a.ContainsKey($_) -and $a[$_].start_ticks -eq $b[$_].start_ticks -and [string]::Equals($a[$_].path,$b[$_].path,[StringComparison]::OrdinalIgnoreCase)}).Count}
}
function Get-UfwObserverStorageRoot {
 [void](Get-UfwProgramCandidateNativeRoot)
 return Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'UnifiedFW-ProgramObservations-01'
}
function Save-UfwObserverSuggestions($Data){
 # Independent append-new storage. Never write into candidate or baseline roots.
 $root=Get-UfwObserverStorageRoot
 if([IO.Directory]::Exists($root)){Assert-UfwJournalAcl $root $true}else{New-UfwPrivateJournalDirectory $root}
 $dir=Join-Path $root ('UfwProgramObservation-'+[guid]::NewGuid().ToString('N'));New-UfwPrivateJournalDirectory $dir
 $payload=Get-UfwCandidateJson $Data;$head=Get-UfwJournalHash $payload
 $bytes=[Text.Encoding]::UTF8.GetBytes((Get-UfwCandidateJson ([pscustomobject][ordered]@{payload=$payload;sha256=$head})))
 if($bytes.Length -gt 262144){throw 'ufw_observer_store_size'}
 $path=Join-Path $dir 'suggestions.json';$stream=Open-UfwPrivateJournalFile $path ([IO.FileMode]::CreateNew)
 try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 Assert-UfwJournalAcl $dir $true;Assert-UfwJournalAcl $path $false
 $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{
  if($stream.Length -ne $bytes.Length){throw 'ufw_observer_store_readback'}
  $reader=New-Object IO.StreamReader($stream,[Text.Encoding]::UTF8,$true,4096,$true)
  try{$back=$reader.ReadToEnd()}finally{$reader.Dispose()}
 }finally{$stream.Dispose()}
 if($back -cne [Text.Encoding]::UTF8.GetString($bytes)){throw 'ufw_observer_store_readback'}
 return [pscustomobject]@{readback_verified=$true;head=$head}
}
function Invoke-UfwObserverCallbacks($Ops){
 $r=[ordered]@{schema='ufw-program-observer-result-01';completed=$false;stage='selection';code='';candidate_read_verified=$false;program_count=0;file_observation_passes=0;review_displayed=$false;consent_received=$false;samples_completed=0;samples_with_stable_process=0;matched_tcp_observations=0;unstable_tcp_rows=0;excluded_tcp_rows=0;suggestion_count=0;private_write_status='not_requested';private_suggestions_saved=$false;raw_identity_exported=$false;candidate_write_requested=$false;baseline_journal_access_requested=$false;program_execution_requested=$false;firewall_change_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;audit_change_requested=$false;packet_capture_requested=$false;udp_observed=$false;blocked_connections_covered=$false;complete_coverage=$false;destinations_approved=$false;ready_for_apply=$false;no_leak_certified=$false;fingerprint_prevention_certified=$false}
 $items=@{}
 try{
  foreach($k in @('Select','Load','Observe','Confirm','Actor','Clock','Processes','Tcp','Sleep','Save')){if(-not $Ops.ContainsKey($k) -or $Ops[$k] -isnot [scriptblock]){throw 'ufw_observer_adapter_missing'}}
  $s=& $Ops.Select
  if($null -eq $s -or $s.cancelled -isnot [bool] -or $s.path -isnot [string]){throw 'ufw_observer_selection_shape'}
  if($s.cancelled){if($s.path -cne ''){throw 'ufw_observer_selection_shape'};$r.completed=$true;$r.code='ufw_observer_cancelled_no_observation';return [pscustomobject]$r}
  $r.stage='candidate_validation';$record=& $Ops.Load $s.path;Assert-UfwObserverRecord $record
  $data=$record.data;$head=$record.head;$digest=Get-UfwCandidateProgramDigest $data.programs
  $actor=& $Ops.Actor;if($actor -isnot [string] -or $actor -cne $data.receipt.actor_sid){throw 'ufw_observer_same_actor_required'}
  $r.candidate_read_verified=$true;$r.program_count=$data.programs.Count
  $paths=@($data.programs|ForEach-Object{$_.path})
  $r.stage='file_reobservation';$fresh=ConvertTo-UfwCandidatePrograms $paths $Ops.Observe;$r.file_observation_passes=1
  if((Get-UfwCandidateProgramDigest $fresh) -cne $digest){throw 'ufw_observer_program_changed'}
  $start=& $Ops.Clock;if($start -isnot [datetime] -or $start.Kind -ne [DateTimeKind]::Utc){throw 'ufw_observer_clock'}
  $r.stage='local_review';$answer=& $Ops.Confirm $data.programs;$r.review_displayed=$true
  if($answer -isnot [bool] -or -not $answer){$r.completed=$true;$r.code='ufw_observer_cancelled_no_observation';return [pscustomobject]$r}
  $r.consent_received=$true;$now=& $Ops.Clock
  if($now -isnot [datetime] -or $now.Kind -ne [DateTimeKind]::Utc -or $now -lt $start -or $now -gt $start.AddSeconds(120) -or (& $Ops.Actor) -cne $actor){throw 'ufw_observer_review_expired_or_actor_changed'}
  $again=& $Ops.Load $s.path;Assert-UfwObserverRecord $again;if($again.head -cne $head){throw 'ufw_observer_candidate_changed'}
  $fresh=ConvertTo-UfwCandidatePrograms $paths $Ops.Observe;$r.file_observation_passes=2
  if((Get-UfwCandidateProgramDigest $fresh) -cne $digest){throw 'ufw_observer_program_changed'}
  $r.stage='passive_tcp_sampling'
  for($i=0;$i -lt 15;$i++){
   $time=& $Ops.Clock;if($time -isnot [datetime] -or $time.Kind -ne [DateTimeKind]::Utc -or $time -lt $now -or $time -gt $now.AddSeconds(300)){throw 'ufw_observer_sampling_deadline'}
   $before=& $Ops.Processes $data.programs;$rows=& $Ops.Tcp;$after=& $Ops.Processes $data.programs
   $summary=Add-UfwObserverSample $before $rows $after $data.programs $items
   $r.samples_completed++;if($summary.stable_processes -gt 0){$r.samples_with_stable_process++}
   $r.matched_tcp_observations+=$summary.matched;$r.unstable_tcp_rows+=$summary.unstable;$r.excluded_tcp_rows+=$summary.excluded
   if($i -lt 14){& $Ops.Sleep}
  }
  $r.stage='post_sample_validation';$post=& $Ops.Load $s.path;Assert-UfwObserverRecord $post;if($post.head -cne $head){throw 'ufw_observer_candidate_changed'}
  $fresh=ConvertTo-UfwCandidatePrograms $paths $Ops.Observe;$r.file_observation_passes=3
  if((Get-UfwCandidateProgramDigest $fresh) -cne $digest){throw 'ufw_observer_program_changed'}
  $end=& $Ops.Clock;if($end -isnot [datetime] -or $end.Kind -ne [DateTimeKind]::Utc -or $end -lt $now -or $end -gt $now.AddSeconds(300) -or (& $Ops.Actor) -cne $actor){throw 'ufw_observer_sampling_deadline'}
  $r.suggestion_count=$items.Count
  $private=[pscustomobject][ordered]@{schema='ufw-program-endpoint-suggestions-01';candidate_id=$data.candidate_id;candidate_head=$head;source='sampled_TCP_table_path_PID_start_time_before_after';created_utc=$end.ToString('o');sample_count=$r.samples_completed;suggestions=@($items.Values|Sort-Object program_id,address,port);direction_known=$false;destinations_approved=$false;complete_coverage=$false;ready_for_apply=$false;execution_authorized=$false}
  $r.stage='private_suggestion_write';$r.private_write_status='attempted_may_exist_inspect_if_failed';$save=& $Ops.Save $private
  if($save.readback_verified -isnot [bool] -or -not $save.readback_verified -or $save.head -cne (Get-UfwJournalHash (Get-UfwCandidateJson $private))){throw 'ufw_observer_save_unverified'}
  $r.private_write_status='saved_unapproved_suggestions_only';$r.private_suggestions_saved=$true;$r.completed=$true;$r.stage='completed'
  if($r.suggestion_count -eq 0){$r.code='ufw_observer_completed_zero_suggestions_not_safety_proof'}else{$r.code='ufw_observer_completed_suggestions_pending_review'}
 }catch{
  $msg=[string]$_.Exception.GetBaseException().Message
  if($msg -cmatch '^(ufw_observer|ufw_candidate|ufw_program|ufw_journal)_[a-z_0-9]{1,100}$'){$r.code=$msg}else{$r.code='ufw_observer_unavailable'}
 }finally{$items=@{}}
 return [pscustomobject]$r
}
function Invoke-UfwObserverNative {
 $ops=@{Select={Select-UfwObserverCandidate};Load={param($p)Read-UfwObserverCandidate $p};Observe={param($p)Read-UfwProgramNativeObservation $p};Confirm={param($p)Confirm-UfwObserver $p};Actor={[Security.Principal.WindowsIdentity]::GetCurrent().User.Value};Clock={[datetime]::UtcNow};Processes={param($p)Get-UfwObserverProcesses $p};Tcp={Get-UfwObserverTcp};Sleep={Start-Sleep -Seconds 2};Save={param($d)Save-UfwObserverSuggestions $d}}
 return Invoke-UfwObserverCallbacks $ops
}
