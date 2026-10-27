# Dedicated program-candidate storage only. No policy or execution authority.
Set-StrictMode -Version 2.0
function Get-UfwCandidateJson($Value){return ConvertTo-Json -InputObject $Value -Depth 24 -Compress}
function Get-UfwCandidateProgramDigest($Programs){return Get-UfwJournalHash (Get-UfwCandidateJson @($Programs|Sort-Object program_id))}
function Assert-UfwCandidatePrograms($Programs){
 if($Programs -isnot [array] -or $Programs.Count -lt 1 -or $Programs.Count -gt 16){throw 'ufw_candidate_program_count'}
 $paths=@{};$ids=@{};$files=@{};$i=0
 foreach($p in $Programs){
  $i++;if($null -eq $p -or (@($p.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'architecture,file_id,length,path,program_id,sha256,volume_id'){throw 'ufw_candidate_program_shape'}
  if($p.program_id -isnot [string] -or $p.architecture -isnot [string] -or $p.program_id -cne ('program'+$i.ToString('D2')) -or $p.path -isnot [string]){throw 'ufw_candidate_program_shape'}
  [void][UfwProgramReview01.Reader]::ValidatePathText($p.path)
  if($p.sha256 -isnot [string] -or $p.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $p.file_id -isnot [string] -or $p.file_id -cnotmatch '^[a-f0-9]{16}$' -or $p.volume_id -isnot [string] -or $p.volume_id -cnotmatch '^[a-f0-9]{8}$' -or $p.architecture -cnotin @('x86','x64') -or ($p.length -isnot [long] -and $p.length -isnot [int]) -or $p.length -lt 96 -or $p.length -gt 536870912){throw 'ufw_candidate_program_shape'}
  $key=$p.volume_id+':'+$p.file_id
  if($paths.ContainsKey($p.path.ToLowerInvariant()) -or $files.ContainsKey($key)){throw 'ufw_candidate_duplicate_program'}
  $paths[$p.path.ToLowerInvariant()]=$true;$files[$key]=$true
 }
}
function ConvertTo-UfwCandidatePrograms($Paths,$Observe){
 if($Paths -isnot [array] -or $Paths.Count -lt 1 -or $Paths.Count -gt 16){throw 'ufw_candidate_program_count'}
 $seen=@{}
 foreach($p in $Paths){if($p -isnot [string]){throw 'ufw_candidate_path_shape'};[void][UfwProgramReview01.Reader]::ValidatePathText($p);if($seen.ContainsKey($p.ToLowerInvariant())){throw 'ufw_candidate_duplicate_program'};$seen[$p.ToLowerInvariant()]=$true}
 $i=0;$out=@()
 foreach($path in $Paths){
  $i++;Write-Host ('Observing EXE '+$i+' of '+$Paths.Count+' (not executing it).')
  $o=& $Observe $path
  if($o.NativeIdentityObserved -isnot [bool] -or -not $o.NativeIdentityObserved -or $o.SameHandleDoubleHashMatched -isnot [bool] -or -not $o.SameHandleDoubleHashMatched -or $o.ExecutionAuthorized -isnot [bool] -or $o.ExecutionAuthorized -ne $false -or $o.ProgramTrusted -isnot [bool] -or $o.ProgramTrusted -ne $false -or $o.AuthenticodeVerified -isnot [bool] -or $o.AuthenticodeVerified -ne $false -or -not [string]::Equals($path,$o.Path,[StringComparison]::OrdinalIgnoreCase)){throw 'ufw_candidate_native_observation_required'}
  $out+=,[pscustomobject][ordered]@{program_id=('program'+$i.ToString('D2'));path=$o.Path;sha256=$o.Sha256;file_id=$o.FileId;volume_id=$o.VolumeId;length=$o.Length;architecture=$o.Architecture}
 }
 Assert-UfwCandidatePrograms $out
 return ,$out
}
function Assert-UfwProgramCandidateData($Data,[string]$Id){
 if($Id -cnotmatch '^[a-f0-9]{32}$' -or $null -eq $Data -or (@($Data.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'candidate_id,destinations,execution_authorized,generation,phase,profile_kind,programs,ready_for_apply,receipt,schema'){throw 'ufw_candidate_data_shape'}
 foreach($k in @('schema','candidate_id','profile_kind','phase')){if($Data.$k -isnot [string]){throw 'ufw_candidate_data_invalid'}}
 if($Data.schema -cne 'ufw-program-candidate-01' -or $Data.candidate_id -cne $Id -or $Data.profile_kind -cne 'installer' -or $Data.phase -cne 'programs_reviewed_destinations_pending' -or ($Data.generation -isnot [int] -and $Data.generation -isnot [long]) -or $Data.generation -ne 1 -or $Data.destinations -isnot [array] -or $Data.destinations.Count -ne 0 -or $Data.execution_authorized -isnot [bool] -or $Data.execution_authorized -ne $false -or $Data.ready_for_apply -isnot [bool] -or $Data.ready_for_apply -ne $false){throw 'ufw_candidate_data_invalid'}
 Assert-UfwCandidatePrograms $Data.programs
 $p=$Data.receipt
 if($null -eq $p -or (@($p.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'actor_sid,authorizes_firewall_change,authorizes_program_execution,candidate_id,created_utc,nonce_sha256,programs_sha256,purpose,schema'){throw 'ufw_candidate_receipt_shape'}
 foreach($k in @('schema','purpose','candidate_id','actor_sid','created_utc','nonce_sha256','programs_sha256')){if($p.$k -isnot [string]){throw 'ufw_candidate_receipt_invalid'}}
 if($p.schema -cne 'ufw-program-candidate-consent-01' -or $p.purpose -cne 'record_installer_program_selection_only' -or $p.candidate_id -cne $Id -or $p.actor_sid -cnotmatch '^S-1-[0-9]+(-[0-9]+)+$' -or $p.nonce_sha256 -cnotmatch '^[a-f0-9]{64}$' -or $p.programs_sha256 -cne (Get-UfwCandidateProgramDigest $Data.programs) -or $p.authorizes_firewall_change -isnot [bool] -or $p.authorizes_firewall_change -ne $false -or $p.authorizes_program_execution -isnot [bool] -or $p.authorizes_program_execution -ne $false){throw 'ufw_candidate_receipt_invalid'}
 $parsed=[datetime]::MinValue;if(-not [datetime]::TryParseExact($p.created_utc,'yyyy-MM-dd HH:mm:ss.fffffff UTC',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$parsed)){throw 'ufw_candidate_receipt_invalid'}
}
function Read-UfwProgramCandidateRecord([string]$Root,[string]$Id){
 Assert-UfwJournalAcl $Root $true
 if([IO.Path]::GetFileName($Root) -cne ('UfwProgramCandidate-'+$Id)){throw 'ufw_candidate_root_identity'}
 $children=@(Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop)
 if($children.Count -ne 1 -or $children[0].PSIsContainer -or $children[0].Name -cne 'candidate.json'){throw 'ufw_candidate_exact_record_required'}
 $path=$children[0].FullName;Assert-UfwJournalAcl $path $false
 $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{if($stream.Length -lt 2 -or $stream.Length -gt 262144){throw 'ufw_candidate_record_size'};$reader=New-Object IO.StreamReader($stream,[Text.Encoding]::UTF8,$true,4096,$true);try{$text=$reader.ReadToEnd()}finally{$reader.Dispose()}}finally{$stream.Dispose()}
 $en=ConvertFrom-Json -InputObject $text
 if((@($en.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'payload,sha256' -or $en.payload -isnot [string] -or $en.sha256 -isnot [string] -or $en.sha256 -cne (Get-UfwJournalHash $en.payload)){throw 'ufw_candidate_record_checksum'}
 $data=ConvertFrom-Json -InputObject $en.payload;Assert-UfwProgramCandidateData $data $Id
 return [pscustomobject]@{data=$data;head=$en.sha256;readback_verified=$true}
}
function Get-UfwProgramCandidateNativeRoot {
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'ufw_candidate_windows_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or -not [Environment]::Is64BitProcess){throw 'ufw_candidate_ps51_x64_required'}
 $who=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ufw_candidate_admin_required'}
 return Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'UnifiedFW-ProgramCandidates-01'
}
function Save-UfwProgramCandidateNative($Data){
 Assert-UfwProgramCandidateData $Data $Data.candidate_id
 $root=Get-UfwProgramCandidateNativeRoot;Assert-UfwJournalPath $root
 if([IO.Directory]::Exists($root)){Assert-UfwJournalAcl $root $true}else{New-UfwPrivateJournalDirectory $root}
 $dir=Join-Path $root ('UfwProgramCandidate-'+$Data.candidate_id);New-UfwPrivateJournalDirectory $dir
 $payload=Get-UfwCandidateJson $Data;$hash=Get-UfwJournalHash $payload
 $bytes=[Text.Encoding]::UTF8.GetBytes((Get-UfwCandidateJson ([pscustomobject][ordered]@{payload=$payload;sha256=$hash})))
 if($bytes.Length -gt 262144){throw 'ufw_candidate_record_size'}
 $f=Open-UfwPrivateJournalFile (Join-Path $dir 'candidate.json') ([IO.FileMode]::CreateNew)
 try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
 $read=Read-UfwProgramCandidateRecord $dir $Data.candidate_id
 if($read.head -cne $hash){throw 'ufw_candidate_readback_mismatch'}
 return [pscustomobject]@{readback_verified=$true;head=$hash}
}
function Confirm-UfwProgramCandidate($Programs){
 Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
 $form=New-Object System.Windows.Forms.Form
 try{
  $form.Text='Save installer program candidate ONLY - no execution or firewall change';$form.Width=980;$form.Height=650;$form.StartPosition='CenterScreen';$form.MinimizeBox=$false
  $label=New-Object System.Windows.Forms.Label;$label.Dock='Top';$label.Height=80;$label.Text='Review the EXACT files below. Save writes a protected LOCAL installer candidate only. No destinations, program execution, trust or firewall Apply is approved. Cancel writes no candidate. Review expires after 2 minutes. Do not share a screenshot.'
  $text=New-Object System.Windows.Forms.TextBox;$text.Multiline=$true;$text.ReadOnly=$true;$text.WordWrap=$false;$text.ScrollBars='Both';$text.Dock='Fill'
  $lines=@();foreach($p in $Programs){$lines+=@($p.program_id,('Path: '+$p.path),('SHA256: '+$p.sha256),('Local identity: '+$p.volume_id+':'+$p.file_id),('Header: '+$p.architecture+'; bytes: '+$p.length),'')};$text.Text=$lines -join [Environment]::NewLine
  $panel=New-Object System.Windows.Forms.FlowLayoutPanel;$panel.Dock='Bottom';$panel.Height=48;$panel.FlowDirection='RightToLeft'
  $cancel=New-Object System.Windows.Forms.Button;$cancel.Text='Cancel';$cancel.Width=120;$cancel.DialogResult='Cancel'
  $save=New-Object System.Windows.Forms.Button;$save.Text='Save candidate';$save.Width=180;$save.DialogResult='OK'
  $panel.Controls.Add($cancel);$panel.Controls.Add($save);$form.Controls.Add($text);$form.Controls.Add($panel);$form.Controls.Add($label)
  $form.CancelButton=$cancel;$form.ActiveControl=$cancel
  return ($form.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK)
 }finally{$form.Dispose()}
}
function Invoke-UfwProgramCandidateCallbacks($Ops){
 $r=[ordered]@{schema='ufw-program-candidate-result-01';completed=$false;stage='selection';code='';selected_count=0;observation_passes=0;review_displayed=$false;consent_received=$false;candidate_write_attempted=$false;candidate_recorded=$false;write_status='not_requested';candidate_phase='not_recorded';destination_count=0;architectures=@();program_config_saved=$false;raw_identity_exported=$false;program_trusted=$false;program_execution_requested=$false;firewall_change_requested=$false;baseline_journal_access_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;baseline_linked=$false;ready_for_apply=$false;no_leak_certified=$false}
 try{
  foreach($k in @('Select','Observe','Confirm','Clock','Actor','Save')){if(-not $Ops.ContainsKey($k) -or $Ops[$k] -isnot [scriptblock]){throw 'ufw_candidate_adapter_missing'}}
  $selection=& $Ops.Select
  if($null -eq $selection -or $selection.cancelled -isnot [bool] -or $selection.paths -isnot [array]){throw 'ufw_candidate_selection_shape'}
  if($selection.cancelled){if($selection.paths.Count -ne 0){throw 'ufw_candidate_selection_shape'};$r.completed=$true;$r.code='ufw_candidate_cancelled_no_write';return [pscustomobject]$r}
  $r.selected_count=$selection.paths.Count;$r.stage='initial_observation';$programs=ConvertTo-UfwCandidatePrograms $selection.paths $Ops.Observe;$r.observation_passes=1
  $r.architectures=@($programs|ForEach-Object{$_.architecture});$digest=Get-UfwCandidateProgramDigest $programs
  $start=& $Ops.Clock;$actor=& $Ops.Actor
  if($start -isnot [datetime] -or $start.Kind -ne [DateTimeKind]::Utc -or $actor -isnot [string] -or $actor -cnotmatch '^S-1-[0-9]+(-[0-9]+)+$'){throw 'ufw_candidate_clock_or_actor_required'}
  $id=[guid]::NewGuid().ToString('N');$nonce=[guid]::NewGuid().ToString('N');$r.stage='local_review'
  $answer=& $Ops.Confirm $programs;$r.review_displayed=$true
  if($answer -isnot [bool] -or -not $answer){$r.completed=$true;$r.code='ufw_candidate_cancelled_no_write';return [pscustomobject]$r}
  $r.consent_received=$true;$r.stage='prewrite_reobservation';$fresh=ConvertTo-UfwCandidatePrograms $selection.paths $Ops.Observe;$r.observation_passes=2
  if((Get-UfwCandidateProgramDigest $fresh) -cne $digest){throw 'ufw_candidate_program_changed_after_review'}
  $now=& $Ops.Clock;$freshActor=& $Ops.Actor;if($now -isnot [datetime] -or $now.Kind -ne [DateTimeKind]::Utc -or $now -lt $start -or $now -gt $start.AddSeconds(120) -or $freshActor -isnot [string] -or $freshActor -cne $actor){throw 'ufw_candidate_review_expired_or_actor_changed'}
  $receipt=[pscustomobject][ordered]@{schema='ufw-program-candidate-consent-01';purpose='record_installer_program_selection_only';candidate_id=$id;actor_sid=$actor;created_utc=$now.ToString('yyyy-MM-dd HH:mm:ss.fffffff',[Globalization.CultureInfo]::InvariantCulture)+' UTC';nonce_sha256=(Get-UfwJournalHash $nonce);programs_sha256=$digest;authorizes_firewall_change=$false;authorizes_program_execution=$false}
  $data=[pscustomobject][ordered]@{schema='ufw-program-candidate-01';candidate_id=$id;generation=1;profile_kind='installer';phase='programs_reviewed_destinations_pending';programs=$fresh;destinations=@();receipt=$receipt;execution_authorized=$false;ready_for_apply=$false};Assert-UfwProgramCandidateData $data $id
  $r.stage='protected_candidate_write';$r.candidate_write_attempted=$true;$r.write_status='attempted_may_exist_inspect_if_failed';$saved=& $Ops.Save $data
  if($saved.readback_verified -isnot [bool] -or -not $saved.readback_verified -or $saved.head -isnot [string] -or $saved.head -cnotmatch '^[a-f0-9]{64}$' -or $saved.head -cne (Get-UfwJournalHash (Get-UfwCandidateJson $data))){throw 'ufw_candidate_save_unverified'}
  $r.stage='postwrite_reobservation';$post=ConvertTo-UfwCandidatePrograms $selection.paths $Ops.Observe;$r.observation_passes=3
  if((Get-UfwCandidateProgramDigest $post) -cne $digest){throw 'ufw_candidate_program_changed_after_write'}
  $end=& $Ops.Clock;$endActor=& $Ops.Actor;if($end -isnot [datetime] -or $end.Kind -ne [DateTimeKind]::Utc -or $end -lt $now -or $end -gt $start.AddSeconds(120) -or $endActor -isnot [string] -or $endActor -cne $actor){throw 'ufw_candidate_review_expired_after_write'}
  $r.candidate_recorded=$true;$r.program_config_saved=$true;$r.write_status='recorded_revalidated_no_authority';$r.candidate_phase='programs_reviewed_destinations_pending';$r.completed=$true;$r.stage='completed';$r.code='ufw_candidate_recorded_destinations_pending_no_authority'
 }catch{
  $msg=[string]$_.Exception.GetBaseException().Message
  if($msg -cmatch '^(ufw_candidate|ufw_program|ufw_journal)_[a-z_0-9]{1,100}$'){$r.code=$msg}else{$r.code='ufw_candidate_unavailable'}
 }
 return [pscustomobject]$r
}
function Invoke-UfwProgramCandidateNative {
 $ops=@{Select={Select-UfwProgramFiles};Observe={param($p)Read-UfwProgramNativeObservation $p};Confirm={param($programs)Confirm-UfwProgramCandidate $programs};Clock={[datetime]::UtcNow};Actor={[Security.Principal.WindowsIdentity]::GetCurrent().User.Value};Save={param($data)Save-UfwProgramCandidateNative $data}}
 return Invoke-UfwProgramCandidateCallbacks $ops
}
