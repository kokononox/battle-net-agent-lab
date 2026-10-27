# Load inside the unchanged journal module. This entry never creates/repairs journal files.
Set-StrictMode -Version 2.0
function Get-UfwReopenNativeRoot {
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'ufw_reopen_windows_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or -not [Environment]::Is64BitProcess){throw 'ufw_reopen_ps51_x64_required'}
 $who=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ufw_reopen_admin_required'}
 return Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'UnifiedFW-InstallerSessions-01'
}
function Get-UfwReopenSingleSession([string]$Root){
 Assert-UfwJournalPath $Root
 if(-not [IO.Directory]::Exists($Root)){throw 'ufw_reopen_root_missing_no_create'}
 Assert-UfwJournalAcl $Root $true
 $children=@(Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop)
 if($children.Count -eq 0){throw 'ufw_reopen_no_session'}
 foreach($child in $children){if(-not $child.PSIsContainer -or $child.Name -cnotmatch '^UfwInstaller-Session-[a-f0-9]{32}$'){throw 'ufw_reopen_unexpected_root_child'};Assert-UfwJournalAcl $child.FullName $true}
 if($children.Count -ne 1){throw 'ufw_reopen_multiple_sessions_no_selection'}
 return $children[0]
}
function Read-UfwReopenPrepared([string]$Root,[string]$Id){
 $names=@(Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop|ForEach-Object{$_.Name}|Sort-Object)
 if(($names -join ',') -cne '00000001.json,operation.lock'){throw 'ufw_reopen_exact_prepared_files_required'}
 $read=Read-UfwPreparationJournal $Root $Id
 if($read.sequence -ne 1 -or $null -eq $read.last -or $read.last.kind -cne 'prepared' -or $read.last.data.draft.phase -cne 'prepared' -or $read.last.data.draft.execution_authorized -ne $false -or @($read.last.data.draft.entries|Where-Object{$_.intent -or $_.restored}).Count -ne 0){throw 'ufw_reopen_prepared_only'}
 $path=Join-Path $Root '00000001.json';$bytes=[IO.File]::ReadAllBytes($path)
 if($bytes.Length -gt 262144){throw 'ufw_reopen_record_size'}
 $sha=[Security.Cryptography.SHA256]::Create();try{$fileHash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
 return [pscustomobject]@{read=$read;file_hash=$fileHash;length=$bytes.Length;receipt_json=(Get-UfwCanonicalReceiptJson $read.last.data.receipt)}
}
function Get-UfwReopenProfile($Result){
 $p=Invoke-UfwInstallerPreflightReadOnly
 $summary=[ordered]@{core_completed=$p.completed;core_code=$p.code;baseline_draft_constructible=$p.baseline_draft_constructible;reader_completed=$false;reader_code='not_available';native_profile_reads_attempted=0;two_observations_match=$false;profiles=@();reasons=@()}
 if($null -ne $p.profile_observation){
  $o=$p.profile_observation;$summary.reader_completed=$o.completed;$summary.reader_code=$o.code;$summary.native_profile_reads_attempted=$o.native_store_reads_attempted;$summary.two_observations_match=$o.two_observations_match
  if($null -ne $o.assessment){$summary.profiles=@($o.assessment.profiles|ForEach-Object{[pscustomobject][ordered]@{name=$_.name;local_outbound=$_.local_outbound;effective_outbound=$_.effective_outbound;local_enabled=$_.local_enabled;effective_enabled=$_.effective_enabled;local_allow_local_rules=$_.local_allow_local_rules;effective_allow_local_rules=$_.effective_allow_local_rules}});$summary.reasons=@($o.assessment.reasons)}
 }
 $Result.profile_observations+=,[pscustomobject]$summary
 if(-not $p.completed){throw 'ufw_reopen_profile_preflight_incomplete'}
 return & $script:Core {param($o)New-UfwProfileRecoveryDraft $o} $p.profile_observation
}
function Invoke-UfwReadOnlyReopen {
 $r=[ordered]@{schema='ufw-readonly-reopen-result-01';completed=$false;stage='platform_and_discovery';code='';single_session_selected=$false;existing_readonly_lock_acquired=$false;record_validated=$false;prepared_checkpoint_count=0;baseline_profiles=@();profile_observations=@();initial_profiles_match_baseline=$false;final_profiles_match_baseline=$false;record_bytes_unchanged_during_observation=$false;session_selection_unchanged=$false;lock_released=$false;journal_write_requested=$false;journal_repair_requested=$false;real_legacy_journal_access_requested=$false;firewall_change_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;normal_mode_restored=$false;original_restore_verified=$false;reboot_qualified=$false;ready_for_apply=$false;no_leak_certified=$false}
 $lock=$null
 try{
  $root=Get-UfwReopenNativeRoot;$session=Get-UfwReopenSingleSession $root;$r.single_session_selected=$true;$id=$session.Name.Substring('UfwInstaller-Session-'.Length)
  $r.stage='existing_readonly_lock';$lockPath=Join-Path $session.FullName 'operation.lock'
  if(-not [IO.File]::Exists($lockPath)){throw 'ufw_reopen_lock_missing_no_create'}
  Assert-UfwJournalAcl $lockPath $false
  try{$lock=[IO.File]::Open($lockPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)}catch{throw 'ufw_reopen_lock_unavailable'}
  $r.existing_readonly_lock_acquired=$true
  if($lock.Length -ne 0){throw 'ufw_reopen_lock_nonempty'}
  $r.stage='initial_record_validation';$before=Read-UfwReopenPrepared $session.FullName $id;$r.record_validated=$true;$r.prepared_checkpoint_count=$before.read.sequence
  $r.baseline_profiles=@($before.read.last.data.draft.entries|ForEach-Object{$_.before})
  $r.stage='initial_profile_comparison';$initial=Get-UfwReopenProfile $r
  if((Get-UfwDraftBaselineHash $initial) -cne $before.read.last.data.receipt.baseline_sha256){throw 'ufw_reopen_current_baseline_mismatch'};$r.initial_profiles_match_baseline=$true
  $r.stage='final_profile_comparison';$final=Get-UfwReopenProfile $r
  if((Get-UfwDraftBaselineHash $final) -cne $before.read.last.data.receipt.baseline_sha256){throw 'ufw_reopen_final_baseline_mismatch'};$r.final_profiles_match_baseline=$true
  $r.stage='final_record_validation';$after=Read-UfwReopenPrepared $session.FullName $id
  if($before.file_hash -cne $after.file_hash -or $before.length -ne $after.length -or $before.read.head -cne $after.read.head -or $before.receipt_json -cne $after.receipt_json){throw 'ufw_reopen_record_changed'}
  $r.record_bytes_unchanged_during_observation=$true
  if($lock.Length -ne 0){throw 'ufw_reopen_lock_nonempty'}
  $r.stage='final_selection_validation';$again=Get-UfwReopenSingleSession $root
  if($again.FullName -cne $session.FullName){throw 'ufw_reopen_selection_changed'};$r.session_selection_unchanged=$true
  $r.code='ufw_reopen_prepared_matches_current_no_authority';$r.completed=$true;$r.stage='completed'
 }catch{
  $msg=[string]$_.Exception.GetBaseException().Message
  if($msg -cmatch '^(ufw_reopen|ufw_journal|ufw_core|ufw_read)_[a-z_0-9]{1,100}$'){$r.code=$msg}else{$r.code='ufw_reopen_unavailable'}
 }finally{
  if($null -ne $lock){try{$lock.Dispose();$r.lock_released=$true}catch{$r.completed=$false;$r.stage='lock_release';$r.code='ufw_reopen_lock_release_failed'}}
 }
 return [pscustomobject]$r
}
