param([string]$Root='/data/ufw-reopen-session-v01/package/UFW-REOPEN-SESSION-01')
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$m=Import-Module (Join-Path $Root 'Ufw.SessionJournal.psm1') -Force -PassThru
$reader=@(& $m {& $script:Core {Get-Module Ufw.ProfileReader}})[0]
$script:checks=0
function Check($b,$label){$script:checks++;if(-not $b){throw $label}}
& $reader {
 function script:Assert-UfwReadPlatform {}
 $script:mode='block';$script:calls=0
 function script:Get-NetFirewallProfile {
  param($PolicyStore,$ErrorAction)$script:calls++
  if($script:mode -ceq 'reader_failure'){throw 'PRIVATE_USER_PATH_OR_SERVER'}
  $out='Block';if($script:mode -ceq 'allow' -or $script:mode -ceq 'mismatch' -or ($script:mode -ceq 'final_mismatch' -and $script:calls -ge 5) -or ($script:mode -ceq 'intra_read_drift' -and $script:calls -ge 3)){$out='Allow'}
  foreach($n in @('Domain','Private','Public')){[pscustomobject]@{Name=$n;DefaultOutboundAction=$out;Enabled='True';AllowLocalFirewallRules=$(if($PolicyStore -ceq 'PersistentStore'){'NotConfigured'}else{'True'});DisabledInterfaceAliases=@()}}
 }
}
function New-Fixture($Base,$id=('a'*32),$out='Block'){
 & $m {
  param($base,$id,$out)
  $rows=@(foreach($n in @('Domain','Private','Public')){[pscustomobject][ordered]@{name=$n;local_outbound=$out;effective_outbound=$out;local_enabled='True';effective_enabled='True';local_allow_local_rules='NotConfigured';effective_allow_local_rules='True'}})
  $obs=[pscustomobject]@{schema='ufw-readonly-profile-preflight-01';completed=$true;two_observations_match=$true;firewall_change_requested=$false;ready_for_apply=$false;assessment=[pscustomobject]@{explicit_local_outbound_baseline_present=$true;profile_fields_compatible_for_later_review=$true;profiles=$rows}}
  $draft=& $script:Core {param($o)New-UfwProfileRecoveryDraft $o} $obs
  $receipt=[pscustomobject][ordered]@{schema='ufw-preparation-consent-01';session_id=$id;baseline_sha256=(Get-UfwDraftBaselineHash $draft);challenge_sha256=('c'*64);purpose='prepare_profile_journal_only';consent_validated=$true;created_utc='2026-10-27 05:00:00.0000000 UTC';authorizes_firewall_change=$false;ready_for_apply=$false}
  if(-not [IO.Directory]::Exists($base)){New-UfwPrivateJournalDirectory $base}
  $dir=Join-Path $base ('UfwInstaller-Session-'+$id);New-UfwPrivateJournalDirectory $dir
  Add-UfwPreparationCheckpoint $dir $id ('0'*64) 'prepared' ([pscustomobject][ordered]@{receipt=$receipt;draft=$draft})|Out-Null
  return $dir
 } $Base $id $out
}
function Fingerprint($Base){
 if(-not [IO.Directory]::Exists($Base)){return 'ABSENT'}
 return (@(Get-ChildItem $Base -Recurse -Force|Sort-Object FullName|ForEach-Object{if($_.PSIsContainer){'D:'+ $_.FullName}else{'F:'+ $_.FullName+':'+(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}})-join '|')
}
function Execute-Reopen($Base,$Mode){
 & $reader {param($mode)$script:mode=$mode;$script:calls=0} $Mode
 return & $m {
  param($path,$base,$mode)
  . $path
  $script:ReopenTest=[pscustomobject]@{root=$base;mode=$mode;read_calls=0;acl_calls=0;select_calls=0}
  $originalRead=${function:Read-UfwPreparationJournal};$originalAcl=${function:Assert-UfwJournalAcl};$originalSelect=${function:Get-UfwReopenSingleSession}
  function Get-UfwReopenNativeRoot {return $script:ReopenTest.root}
  function Assert-UfwJournalAcl {
   param($Path,$Directory)$script:ReopenTest.acl_calls++
   if($script:ReopenTest.mode -ceq 'acl_failure'){throw 'ufw_journal_acl_owner_or_inheritance'}
   & $originalAcl $Path $Directory
  }
  function Get-UfwReopenSingleSession {
   param($Root)$script:ReopenTest.select_calls++
   if($script:ReopenTest.mode -ceq 'second_selection_failure' -and $script:ReopenTest.select_calls -eq 2){throw 'ufw_reopen_multiple_sessions_no_selection'}
   return & $originalSelect $Root
  }
  function Read-UfwPreparationJournal {
   param($Root,$SessionId)$script:ReopenTest.read_calls++
   if($script:ReopenTest.mode -ceq 'changed_valid_record' -and $script:ReopenTest.read_calls -eq 2){
    $file=Join-Path $Root '00000001.json';$en=ConvertFrom-Json ([IO.File]::ReadAllText($file));$body=ConvertFrom-Json $en.payload;$body.data.receipt.created_utc='2026-10-27 05:00:01.0000000 UTC';$en.payload=Get-UfwJournalJson $body;$en.sha256=Get-UfwJournalHash $en.payload;[IO.File]::WriteAllText($file,(Get-UfwJournalJson $en))
   }
   return & $originalRead $Root $SessionId
  }
  Invoke-UfwReadOnlyReopen
 } (Join-Path $Root 'ReopenEntry.ps1') $Base $Mode
}
$baseParent=Join-Path ([IO.Path]::GetTempPath()) ('ufw-reopen-test-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($baseParent)
try{
 foreach($mode in @('block','allow','mismatch','final_mismatch','intra_read_drift','reader_failure','acl_failure','second_selection_failure','changed_valid_record','missing_root','empty_root','multiple','unexpected_root','missing_lock','nonempty_lock','missing_record','extra_record','unexpected_session_file','partial','checksum','bad_receipt','authorized_draft','symlink','locked')){
  $base=Join-Path $baseParent $mode;$session=$null;$held=$null
  if($mode -ceq 'empty_root'){[void][IO.Directory]::CreateDirectory($base)}
  elseif($mode -cne 'missing_root'){$session=New-Fixture $base ('a'*32) $(if($mode -ceq 'allow'){'Allow'}else{'Block'})}
  if($mode -ceq 'multiple'){New-Fixture $base ('b'*32)|Out-Null}
  if($mode -ceq 'unexpected_root'){[IO.File]::WriteAllText((Join-Path $base 'unexpected.txt'),'unknown')}
  if($mode -ceq 'missing_lock'){[IO.File]::Delete((Join-Path $session 'operation.lock'))}
  if($mode -ceq 'nonempty_lock'){[IO.File]::WriteAllText((Join-Path $session 'operation.lock'),'x')}
  if($mode -ceq 'missing_record'){[IO.File]::Delete((Join-Path $session '00000001.json'))}
  if($mode -ceq 'extra_record'){[IO.File]::Copy((Join-Path $session '00000001.json'),(Join-Path $session '00000002.json'))}
  if($mode -ceq 'unexpected_session_file'){[IO.File]::WriteAllText((Join-Path $session 'unexpected.txt'),'unknown')}
  if($mode -ceq 'partial'){[IO.File]::WriteAllText((Join-Path $session '00000001.json'),'{')}
  if($mode -ceq 'checksum'){$file=Join-Path $session '00000001.json';$en=ConvertFrom-Json ([IO.File]::ReadAllText($file));$en.sha256='0'*64;[IO.File]::WriteAllText($file,($en|ConvertTo-Json -Depth 32 -Compress))}
  if($mode -cin @('bad_receipt','authorized_draft')){
   & $m {param($session,$mode)$file=Join-Path $session '00000001.json';$en=ConvertFrom-Json ([IO.File]::ReadAllText($file));$body=ConvertFrom-Json $en.payload;if($mode -ceq 'bad_receipt'){$body.data.receipt.authorizes_firewall_change=$true}else{$body.data.draft.execution_authorized=$true};$en.payload=Get-UfwJournalJson $body;$en.sha256=Get-UfwJournalHash $en.payload;[IO.File]::WriteAllText($file,(Get-UfwJournalJson $en))} $session $mode
  }
  if($mode -ceq 'symlink'){$file=Join-Path $session '00000001.json';$target=Join-Path $baseParent 'private-target.json';[IO.File]::Move($file,$target);[void](New-Item -ItemType SymbolicLink -Path $file -Target $target)}
  $before=Fingerprint $base
  if($mode -ceq 'locked'){$held=[IO.File]::Open((Join-Path $session 'operation.lock'),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)}
  try{$r=Execute-Reopen $base $mode}finally{if($held){$held.Dispose()}}
  $calls=& $reader {$script:calls}
  if($mode -cin @('block','allow')){
   Check ($r.completed -and $r.code -ceq 'ufw_reopen_prepared_matches_current_no_authority') ('success '+$mode)
   Check ($r.record_validated -and $r.existing_readonly_lock_acquired -and $r.lock_released -and $r.prepared_checkpoint_count -eq 1) 'existing file lock and prepared chain'
   Check ($r.initial_profiles_match_baseline -and $r.final_profiles_match_baseline -and $r.record_bytes_unchanged_during_observation -and $r.session_selection_unchanged) 'recheck all success flags'
   Check ($calls -eq 8 -and $r.profile_observations.Count -eq 2 -and @($r.baseline_profiles).Count -eq 3) 'real core reader invoked twice with eight mocked getters'
  }else{
   Check (-not $r.completed) ('refuse '+$mode)
   $expected=@{mismatch='ufw_reopen_current_baseline_mismatch';final_mismatch='ufw_reopen_final_baseline_mismatch';intra_read_drift='ufw_reopen_profile_preflight_incomplete';reader_failure='ufw_reopen_profile_preflight_incomplete';acl_failure='ufw_journal_acl_owner_or_inheritance';second_selection_failure='ufw_reopen_multiple_sessions_no_selection';changed_valid_record='ufw_reopen_record_changed';missing_root='ufw_reopen_root_missing_no_create';empty_root='ufw_reopen_no_session';multiple='ufw_reopen_multiple_sessions_no_selection';unexpected_root='ufw_reopen_unexpected_root_child';missing_lock='ufw_reopen_lock_missing_no_create';nonempty_lock='ufw_reopen_lock_nonempty';missing_record='ufw_reopen_exact_prepared_files_required';extra_record='ufw_reopen_exact_prepared_files_required';unexpected_session_file='ufw_reopen_exact_prepared_files_required';partial='ufw_reopen_unavailable';checksum='ufw_journal_checksum';bad_receipt='ufw_journal_receipt_invalid';authorized_draft='ufw_core_recovery_session_shape';symlink='ufw_journal_reparse_path';locked='ufw_reopen_lock_unavailable'}
   Check ($r.code -ceq $expected[$mode]) ('code '+$mode+' got '+$r.code)
  }
  if($mode -cne 'changed_valid_record'){Check ((Fingerprint $base) -ceq $before) ('no journal creation/mutation/repair '+$mode)}
  if($r.existing_readonly_lock_acquired){Check $r.lock_released ('release on '+$mode)}
  foreach($key in @('journal_write_requested','journal_repair_requested','real_legacy_journal_access_requested','firewall_change_requested','VPN_change_requested','DNS_query_generated','normal_mode_restored','original_restore_verified','reboot_qualified','ready_for_apply','no_leak_certified')){Check ($r.$key -ceq $false) ('boundary '+$mode+' '+$key)}
  $json=$r|ConvertTo-Json -Depth 24;Check ($json -notmatch 'ufw-reopen-test-|PRIVATE_USER_PATH_OR_SERVER|UfwInstaller-Session-|a{32}|b{32}|c{64}|baseline_sha256|challenge_sha256|session_id') ('private data not exported '+$mode)
 }
 # A genuinely new Linux pwsh process reopens the existing disk record; only Windows guards/getters are mocked.
 $base=Join-Path $baseParent 'separate-process';New-Fixture $base|Out-Null;$before=Fingerprint $base
 $childOutput=& '/data/ufd-isolation-hf1/pwsh/pwsh' -NoProfile -File '/data/ufw-reopen-session-v01/Test-ReopenChild.ps1' -PackageRoot $Root -FixtureRoot $base
 Check ($LASTEXITCODE -eq 0) 'fresh child process success'
 $child=ConvertFrom-Json ($childOutput -join "`n")
 Check ($child.completed -and $child.record_validated -and $child.record_bytes_unchanged_during_observation -and $child.lock_released) 'child independently validates stored receipt/checkpoint'
 Check ((Fingerprint $base) -ceq $before) 'fresh process leaves files and directory inventory byte unchanged'
 # WinPS5.1 top-level JSON array contract is simulated, not a Windows runtime.
 function global:ConvertFrom-Json {param([Parameter(ValueFromPipeline=$true)]$InputObject)process{$v=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject;if([string]$InputObject -match '^\s*\['){Write-Output -NoEnumerate @($v)}else{$v}}}
 try{$base=Join-Path $baseParent 'ps51-array';New-Fixture $base|Out-Null;$r=Execute-Reopen $base 'block';Check $r.completed 'PS51 JSON array contract does not nest profile rows'}finally{Remove-Item Function:\global:ConvertFrom-Json}
 foreach($n in @('ReopenEntry.ps1','Run-Reopen.ps1')){
  $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $n),[ref]$t,[ref]$e);Check ($e.Count -eq 0) ('parse '+$n)
  $cmds=@($ast.FindAll({param($a)$a -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
  Check (@($cmds|Where-Object{$_ -match '^(Set-Net|New-Net|Remove-Net|Add-Ufw|Save-Ufw|New-UfwPrivate|Open-UfwPrivate|Read-Host|Set-Acl|rasdial|netsh)'}).Count -eq 0) ('no mutation or consent commands '+$n)
 }
 $r=[ordered]@{suite='readonly-separate-process-reopen-entry-01';passed=$true;assertions=$script:checks;real_Linux_file_IO_and_existing_exclusive_read_lock_tested=$true;fresh_Linux_child_process_reopen_tested=$true;Windows_profile_getters_mocked=$true;real_Windows_ACL_executed=$false;real_Windows_reopen_executed=$false;PS51_JSON_array_contract_shim_tested=$true;firewall_writer_present=$false;journal_writer_called_by_entry=$false;ready_for_apply=$false}
 $r|ConvertTo-Json|Set-Content '/data/ufw-reopen-session-v01/MODEL-RESULTS.json' -Encoding UTF8;$r|ConvertTo-Json -Compress
}finally{if([IO.Directory]::Exists($baseParent)){Remove-Item -LiteralPath $baseParent -Recurse -Force}}
