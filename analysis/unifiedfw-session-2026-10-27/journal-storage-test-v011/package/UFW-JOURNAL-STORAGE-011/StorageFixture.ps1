# Synthetic fixture only. NEVER invokes real profile readers, consent, or native session storage.
Set-StrictMode -Version 2.0
function Assert-UfwStorageFixturePlatform {
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'ufw_fixture_windows_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or -not [Environment]::Is64BitProcess){throw 'ufw_fixture_ps51_x64_required'}
 $who=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ufw_fixture_admin_required'}
}
function Get-UfwStorageFixtureBase {return [Environment]::GetFolderPath('CommonApplicationData')}
function New-UfwStorageFixtureData([string]$Id){
 # All profiles here are invented, not observations of Windows.
 $rows=@(foreach($n in @('Domain','Private','Public')){[pscustomobject][ordered]@{name=$n;local_outbound='Allow';effective_outbound='Allow';local_enabled='True';effective_enabled='True';local_allow_local_rules='NotConfigured';effective_allow_local_rules='True'}})
 $entries=@(foreach($row in $rows){[pscustomobject][ordered]@{name=$row.name;before=$row;intent=$false;restored=$false}})
 $draft=[pscustomobject][ordered]@{schema='ufw-profile-recovery-draft-01';scope='profile_outbound_only';phase='prepared';entries=$entries;execution_authorized=$false}
 $receipt=[pscustomobject][ordered]@{schema='ufw-preparation-consent-01';session_id=$Id;baseline_sha256='';challenge_sha256=('c'*64);purpose='prepare_profile_journal_only';consent_validated=$true;created_utc='2000-01-01 00:00:00.0000000 UTC';authorizes_firewall_change=$false;ready_for_apply=$false}
 return [pscustomobject][ordered]@{receipt=$receipt;draft=$draft}
}
function Remove-UfwStorageFixtureTree([string]$Root,[string]$Base,[array]$SessionIds,$Module){
 if([IO.Path]::GetDirectoryName($Root) -cne $Base -or [IO.Path]::GetFileName($Root) -cnotmatch '^UnifiedFW-JournalQualification-[a-f0-9]{32}$'){throw 'ufw_fixture_cleanup_root_invalid'}
 & $Module {param($p)Assert-UfwJournalAcl $p $true} $Root
 $children=@(Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop);$allowed=@($SessionIds|ForEach-Object{'UfwInstaller-Session-'+$_});$files=@();$dirs=@()
 # Validate the entire tree before deleting anything; no recursion or unknown files.
 foreach($child in $children){
  if(-not $child.PSIsContainer -or $child.Name -cnotin $allowed){throw 'ufw_fixture_cleanup_unexpected_child'}
  & $Module {param($p)Assert-UfwJournalAcl $p $true} $child.FullName;$dirs+=,$child.FullName
  foreach($leaf in @(Get-ChildItem -LiteralPath $child.FullName -Force -ErrorAction Stop)){
   if($leaf.PSIsContainer -or ($leaf.Name -cne 'operation.lock' -and $leaf.Name -cnotmatch '^000000(0[1-9]|1[01])\.json$')){throw 'ufw_fixture_cleanup_unexpected_leaf'}
   & $Module {param($p)Assert-UfwJournalAcl $p $false} $leaf.FullName;$files+=,$leaf.FullName
  }
 }
 foreach($file in $files){[IO.File]::Delete($file)}
 foreach($dir in $dirs){[IO.Directory]::Delete($dir,$false)}
 [IO.Directory]::Delete($Root,$false)
}
function Invoke-UfwJournalStorageFixture($Module){
 $native=([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
 $r=[ordered]@{completed=$false;stage='platform_guard';code='';native_Windows_file_API_executed=$false;synthetic_data_only=$true;root_acl_verified=$false;session_acl_verified=$false;record_acl_verified=$false;lock_acl_verified=$false;initial_roundtrip_verified=$false;CreateNew_collision_refused=$false;existing_record_preserved=$false;stale_head_refused=$false;exclusive_lock_verified=$false;append_chain_verified=$false;baseline_change_refused=$false;checksum_corruption_refused=$false;partial_record_refused=$false;memory_profile_recovery_with_file_checkpoints_verified=$false;checkpoint_count=0;no_execution_authority=$false;cleanup_completed=$false;real_legacy_journal_access_requested=$false;real_preparation_record_created=$false;profile_query_requested=$false;firewall_change_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;ready_for_apply=$false;no_leak_certified=$false}
 $base=$null;$root=$null;$ids=@();$cleanupSafe=$false;$held=$null
 try{
  Assert-UfwStorageFixturePlatform
  $r.native_Windows_file_API_executed=$native;$base=Get-UfwStorageFixtureBase
  $root=Join-Path $base ('UnifiedFW-JournalQualification-'+[guid]::NewGuid().ToString('N'))
  $r.stage='new_private_fixture_root';& $Module {param($p)New-UfwPrivateJournalDirectory $p} $root
  & $Module {param($p)Assert-UfwJournalAcl $p $true} $root;$cleanupSafe=$true;$r.root_acl_verified=$native
  $id=[guid]::NewGuid().ToString('N');$ids+=,$id;$session=Join-Path $root ('UfwInstaller-Session-'+$id)
  & $Module {param($p)New-UfwPrivateJournalDirectory $p} $session;& $Module {param($p)Assert-UfwJournalAcl $p $true} $session;$r.session_acl_verified=$native
  $data=New-UfwStorageFixtureData $id;$data.receipt.baseline_sha256=& $Module {param($d)Get-UfwDraftBaselineHash $d} $data.draft
  $r.stage='initial_checkpoint';$one=& $Module {param($p,$id,$d)Add-UfwPreparationCheckpoint $p $id ('0'*64) 'prepared' $d} $session $id $data
  $read=& $Module {param($p,$id)Read-UfwPreparationJournal $p $id} $session $id
  if(-not $one.readback_verified -or $read.sequence -ne 1 -or $read.head -cne $one.head){throw 'ufw_fixture_roundtrip_failed'};$r.initial_roundtrip_verified=$true
  $record=Join-Path $session '00000001.json';$before=(Get-FileHash -LiteralPath $record -Algorithm SHA256).Hash
  & $Module {param($p)Assert-UfwJournalAcl $p $false} $record;$r.record_acl_verified=$native
  $r.stage='CreateNew_collision';$refused=$false
  try{$f=& $Module {param($p)Open-UfwPrivateJournalFile $p ([IO.FileMode]::CreateNew)} $record;$f.Dispose()}catch{if($_.Exception.GetBaseException() -is [IO.IOException]){$refused=$true}else{throw}}
  if(-not $refused){throw 'ufw_fixture_collision_not_refused'};$r.CreateNew_collision_refused=$true
  if((Get-FileHash -LiteralPath $record -Algorithm SHA256).Hash -cne $before){throw 'ufw_fixture_existing_record_changed'};$r.existing_record_preserved=$true
  $r.stage='stale_head';$refused=$false
  try{& $Module {param($p,$id,$d)Add-UfwPreparationCheckpoint $p $id ('0'*64) 'prepared' $d} $session $id $data|Out-Null}catch{if($_.Exception.GetBaseException().Message -ceq 'ufw_journal_stale_head'){$refused=$true}else{throw}}
  if(-not $refused){throw 'ufw_fixture_stale_head_not_refused'};$r.stale_head_refused=$true
  $r.stage='exclusive_lock';$lock=Join-Path $session 'operation.lock';$held=& $Module {param($p)Open-UfwPrivateJournalFile $p ([IO.FileMode]::OpenOrCreate)} $lock;$refused=$false
  try{& $Module {param($p,$id,$d,$h)Add-UfwPreparationCheckpoint $p $id $h 'model_checkpoint' $d} $session $id $data $one.head|Out-Null}catch{if($_.Exception.GetBaseException() -is [IO.IOException]){$refused=$true}else{throw}}finally{$held.Dispose();$held=$null}
  if(-not $refused){throw 'ufw_fixture_lock_not_exclusive'};$r.exclusive_lock_verified=$true
  & $Module {param($p)Assert-UfwJournalAcl $p $false} $lock;$r.lock_acl_verified=$native
  $r.stage='append_and_memory_recovery'
  $data.draft.phase='arming';foreach($e in $data.draft.entries){$e.intent=$true}
  $two=& $Module {param($p,$id,$d,$h)Add-UfwPreparationCheckpoint $p $id $h 'model_checkpoint' $d} $session $id $data $one.head
  $data.draft.phase='armed';$three=& $Module {param($p,$id,$d,$h)Add-UfwPreparationCheckpoint $p $id $h 'model_checkpoint' $d} $session $id $data $two.head
  $recovery=& $Module {
   param($p,$id,$d,$h)
   $script:StorageFixture=[pscustomobject]@{root=$p;id=$id;data=$d;head=$h;writes=0;rows=@(foreach($e in $d.draft.entries){$row=ConvertFrom-Json (ConvertTo-Json $e.before -Compress);$row.local_outbound='Block';$row.effective_outbound='Block';$row})}
   $ops=@{
    ReadProfiles={foreach($row in $script:StorageFixture.rows){ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $row -Depth 16 -Compress)}}
    Save={param($draft)$ctx=$script:StorageFixture;$entry=[pscustomobject][ordered]@{receipt=$ctx.data.receipt;draft=$draft};$saved=Add-UfwPreparationCheckpoint $ctx.root $ctx.id $ctx.head 'model_checkpoint' $entry;$ctx.head=$saved.head}
    WriteOutbound={param($name,$value)$ctx=$script:StorageFixture;if($name -cnotin @('Domain','Private','Public') -or $value -cne 'Allow'){throw 'ufw_fixture_memory_write_invalid'};$ctx.writes++;$row=@($ctx.rows|Where-Object{$_.name -ceq $name})[0];$row.local_outbound=$value;$row.effective_outbound=$value}
   }
   $result=& $script:Core {param($d,$ops)Invoke-UfwProfileRecoveryCallbacks $d $ops} $d.draft $ops
   return [pscustomobject]@{model_completed=$result.model_recovery_completed;memory_writes=$script:StorageFixture.writes;head=$script:StorageFixture.head}
  } $session $id $data $three.head
  $final=& $Module {param($p,$id)Read-UfwPreparationJournal $p $id} $session $id
  if(-not $recovery.model_completed -or $recovery.memory_writes -ne 3 -or $final.sequence -ne 11 -or $final.head -cne $recovery.head -or $final.last.data.draft.phase -cne 'restored'){throw 'ufw_fixture_recovery_checkpoints_failed'}
  $r.append_chain_verified=$true;$r.memory_profile_recovery_with_file_checkpoints_verified=$true;$r.checkpoint_count=$final.sequence
  if($final.last.data.receipt.authorizes_firewall_change -isnot [bool] -or $final.last.data.receipt.authorizes_firewall_change -ne $false -or $final.last.data.draft.execution_authorized -isnot [bool] -or $final.last.data.draft.execution_authorized -ne $false){throw 'ufw_fixture_unexpected_authority'};$r.no_execution_authority=$true
  $r.stage='changed_baseline';$bad=ConvertFrom-Json (ConvertTo-Json $final.last.data -Depth 32);$bad.draft.entries[0].before.local_outbound='Block';$bad.draft.entries[0].before.effective_outbound='Block';$refused=$false
  try{& $Module {param($p,$id,$d,$h)Add-UfwPreparationCheckpoint $p $id $h 'model_checkpoint' $d} $session $id $bad $final.head|Out-Null}catch{if($_.Exception.GetBaseException().Message -ceq 'ufw_journal_baseline_changed'){$refused=$true}else{throw}}
  if(-not $refused){throw 'ufw_fixture_changed_baseline_not_refused'};$r.baseline_change_refused=$true
  foreach($case in @('checksum','partial')){
   $r.stage=$case+'_corrupt_fixture';$caseId=[guid]::NewGuid().ToString('N');$ids+=,$caseId;$caseRoot=Join-Path $root ('UfwInstaller-Session-'+$caseId)
   & $Module {param($p)New-UfwPrivateJournalDirectory $p} $caseRoot;$caseFile=Join-Path $caseRoot '00000001.json'
   $text=if($case -ceq 'checksum'){'{"payload":"fixture","sha256":"invalid"}'}else{'{'};$bytes=[Text.Encoding]::UTF8.GetBytes($text)
   $f=& $Module {param($p)Open-UfwPrivateJournalFile $p ([IO.FileMode]::CreateNew)} $caseFile
   try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
   & $Module {param($p)Assert-UfwJournalAcl $p $false} $caseFile;$refused=$false
   try{& $Module {param($p,$id)Read-UfwPreparationJournal $p $id} $caseRoot $caseId|Out-Null}catch{
    if(($case -ceq 'checksum' -and $_.Exception.GetBaseException().Message -ceq 'ufw_journal_checksum') -or ($case -ceq 'partial' -and $_.FullyQualifiedErrorId -match 'ConvertFromJson')){$refused=$true}else{throw}
   }
   if(-not $refused){throw 'ufw_fixture_corrupt_record_not_refused'}
   if([IO.File]::ReadAllText($caseFile) -cne $text){throw 'ufw_fixture_corrupt_record_modified'}
   if($case -ceq 'checksum'){$r.checksum_corruption_refused=$true}else{$r.partial_record_refused=$true}
  }
  if((Get-FileHash -LiteralPath $record -Algorithm SHA256).Hash -cne $before){throw 'ufw_fixture_existing_record_changed'}
  $r.completed=$true;$r.stage='completed';$r.code='ufw_fixture_storage_tests_passed'
 }catch{
  $msg=[string]$_.Exception.GetBaseException().Message
  if($msg -cmatch '^(ufw_fixture|ufw_journal|ufw_core|ufw_read)_[a-z_0-9]{1,100}$'){$r.code=$msg}else{$r.code='ufw_fixture_storage_unavailable'}
 }finally{
  if($null -ne $held){$held.Dispose()}
  & $Module {Remove-Variable StorageFixture -Scope Script -ErrorAction SilentlyContinue}
  if($null -ne $root -and [IO.Directory]::Exists($root)){
   try{if(-not $cleanupSafe){throw 'ufw_fixture_cleanup_unverified_root'};Remove-UfwStorageFixtureTree $root $base $ids $Module;$r.cleanup_completed=$true}catch{$r.completed=$false;if($r.code -ceq 'ufw_fixture_storage_tests_passed' -or -not $r.code){$r.code='ufw_fixture_cleanup_requires_review'}}
  }
 }
 return [pscustomobject]$r
}
