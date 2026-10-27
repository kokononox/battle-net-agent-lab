# Preparation-only consent and append-only journal. No firewall/VPN writer.
Set-StrictMode -Version 2.0
$path=Join-Path $PSScriptRoot 'Ufw.InstallerCore.psm1'
$check=[IO.Path]::GetFullPath($path);if($check.StartsWith('\')){throw 'ufw_journal_local_path_required'}
while($check){if(([IO.File]::GetAttributes($check) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ufw_journal_reparse_path'};$parent=[IO.Path]::GetDirectoryName($check);if($parent -eq $check){break};$check=$parent}
if((Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash -cne 'C072F580E20864053870F32C2560BBA9FC973B7A28FFCA76423AF618D7D575CB'){throw 'ufw_journal_core_hash'}
$script:Core=Import-Module $path -Scope Local -PassThru -ErrorAction Stop
function Get-UfwJournalHash([string]$Text){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function Get-UfwJournalJson($Value){ConvertTo-Json -InputObject $Value -Depth 32 -Compress}
function Get-UfwDraftBaselineHash($Draft){
 & $script:Core {param($d)Assert-UfwRecoveryDraft $d} $Draft
 $text=& $script:Core {param($d)Get-UfwCoreJson @($d.entries|ForEach-Object{$_.before})} $Draft
 return Get-UfwJournalHash $text
}
function Assert-UfwJournalPath([string]$Path){
 $p=[IO.Path]::GetFullPath($Path)
 if($p.StartsWith('\')){throw 'ufw_journal_local_path_required'}
 while($p){if([IO.File]::Exists($p) -or [IO.Directory]::Exists($p)){if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ufw_journal_reparse_path'}};$q=[IO.Path]::GetDirectoryName($p);if($q -eq $p){break};$p=$q}
}
function Test-UfwJournalWindows {return ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)}
function Assert-UfwJournalAcl([string]$Path,[bool]$Directory){
 Assert-UfwJournalPath $Path
 if(-not (Test-UfwJournalWindows)){return} # Test filesystem only; not a Linux production permission adapter.
 $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
 if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544'){throw 'ufw_journal_acl_owner_or_inheritance'}
 $seen=@{}
 foreach($r in @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))){
  $sid=$r.IdentityReference.Value;$inherit=if($Directory){'ContainerInherit, ObjectInherit'}else{'None'}
  if($sid -cnotin @('S-1-5-32-544','S-1-5-18') -or $seen.ContainsKey($sid) -or $r.IsInherited -or $r.AccessControlType -ne 'Allow' -or $r.FileSystemRights -ne 'FullControl' -or [string]$r.PropagationFlags -cne 'None' -or [string]$r.InheritanceFlags -cne $inherit){throw 'ufw_journal_acl_rule'}
  $seen[$sid]=$true
 }
 if($seen.Count -ne 2){throw 'ufw_journal_acl_incomplete'}
}
function New-UfwPrivateJournalDirectory([string]$Path){
 Assert-UfwJournalPath $Path
 if([IO.File]::Exists($Path) -or [IO.Directory]::Exists($Path)){throw 'ufw_journal_directory_collision'}
 if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
  $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false)
  $owner=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544');$acl.SetOwner($owner)
  foreach($text in @('S-1-5-32-544','S-1-5-18')){$sid=New-Object Security.Principal.SecurityIdentifier($text);$r=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($r)}
  $dir=New-Object IO.DirectoryInfo($Path);$dir.Create($acl)
 }else{[void][IO.Directory]::CreateDirectory($Path)}
 Assert-UfwJournalAcl $Path $true
}
function Open-UfwPrivateJournalFile([string]$Path,[IO.FileMode]$Mode){
 Assert-UfwJournalPath $Path
 if([IO.File]::Exists($Path)){Assert-UfwJournalAcl $Path $false}
 if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
  $acl=New-Object Security.AccessControl.FileSecurity;$acl.SetAccessRuleProtection($true,$false);$owner=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544');$acl.SetOwner($owner)
  foreach($text in @('S-1-5-32-544','S-1-5-18')){$sid=New-Object Security.Principal.SecurityIdentifier($text);$r=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow');$acl.AddAccessRule($r)}
  return (New-Object IO.FileStream($Path,$Mode,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$acl))
 }
 return [IO.File]::Open($Path,$Mode,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
}
function Assert-UfwPreparationData($Data,[string]$SessionId){
 if($SessionId -cnotmatch '^[a-f0-9]{32}$' -or $null -eq $Data){throw 'ufw_journal_data_shape'}
 if((@($Data.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'draft,receipt'){throw 'ufw_journal_data_shape'}
 if((@($Data.draft.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'entries,execution_authorized,phase,schema,scope'){throw 'ufw_journal_draft_shape'}
 foreach($entry in @($Data.draft.entries)){if((@($entry.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'before,intent,name,restored'){throw 'ufw_journal_draft_shape'}}
 $r=$Data.receipt
 if((@($r.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'authorizes_firewall_change,baseline_sha256,challenge_sha256,consent_validated,created_utc,purpose,ready_for_apply,schema,session_id'){throw 'ufw_journal_receipt_shape'}
 foreach($key in @('schema','purpose','session_id','baseline_sha256','challenge_sha256','created_utc')){if($r.$key -isnot [string]){throw 'ufw_journal_receipt_invalid'}}
 if($r.schema -cne 'ufw-preparation-consent-01' -or $r.purpose -cne 'prepare_profile_journal_only' -or $r.session_id -cne $SessionId -or $r.baseline_sha256 -cnotmatch '^[a-f0-9]{64}$' -or $r.challenge_sha256 -cnotmatch '^[a-f0-9]{64}$' -or $r.created_utc -isnot [string] -or $r.created_utc -cnotmatch '^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{7} UTC$' -or $r.consent_validated -isnot [bool] -or -not $r.consent_validated -or $r.authorizes_firewall_change -isnot [bool] -or $r.authorizes_firewall_change -ne $false -or $r.ready_for_apply -isnot [bool] -or $r.ready_for_apply -ne $false){throw 'ufw_journal_receipt_invalid'}
 $parsed=[datetime]::MinValue;if(-not [datetime]::TryParseExact($r.created_utc.Substring(0,27),'yyyy-MM-dd HH:mm:ss.fffffff',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$parsed)){throw 'ufw_journal_receipt_invalid'}
 if((Get-UfwDraftBaselineHash $Data.draft) -cne $r.baseline_sha256){throw 'ufw_journal_baseline_changed'}
}
function Get-UfwCanonicalReceiptJson($Receipt){$value=[ordered]@{};foreach($key in @($Receipt.PSObject.Properties.Name|Sort-Object)){$value[$key]=$Receipt.$key};return Get-UfwJournalJson $value}
function Assert-UfwCheckpointProgress($Before,$After){
 if((Get-UfwCanonicalReceiptJson $Before.receipt) -cne (Get-UfwCanonicalReceiptJson $After.receipt)){throw 'ufw_journal_receipt_changed'}
 $transitions=@{prepared=@('prepared','arming','restoring');arming=@('arming','armed','restoring');armed=@('restoring');restoring=@('restoring','restored');restored=@('restored')}
 if($After.draft.phase -cnotin $transitions[$Before.draft.phase]){throw 'ufw_journal_phase_regression'}
 foreach($old in $Before.draft.entries){
  $new=@($After.draft.entries|Where-Object{$_.name -ceq $old.name})[0]
  if(($old.intent -and -not $new.intent) -or ($old.restored -and -not $new.restored)){throw 'ufw_journal_flag_regression'}
  if(-not $old.intent -and $new.intent -and $After.draft.phase -cne 'arming'){throw 'ufw_journal_intent_without_arming'}
 }
}
function Read-UfwPreparationJournal([string]$Root,[string]$SessionId){
 Assert-UfwJournalAcl $Root $true
 if([IO.Path]::GetFileName($Root) -cne ('UfwInstaller-Session-'+$SessionId)){throw 'ufw_journal_root_identity'}
 $files=@(Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop);$records=@()
 foreach($f in $files){
  if($f.PSIsContainer){throw 'ufw_journal_unexpected_child'};Assert-UfwJournalAcl $f.FullName $false
  if($f.Name -ceq 'operation.lock'){continue}
  if($f.Name -cnotmatch '^\d{8}\.json$'){throw 'ufw_journal_unexpected_child'};$records+=,$f
 }
 if($records.Count -gt 128){throw 'ufw_journal_record_limit'}
 $seq=0;$head='0'*64;$last=$null
 foreach($f in @($records|Sort-Object Name)){
  $seq++;if($f.Name -cne ($seq.ToString('D8')+'.json') -or $f.Length -gt 262144){throw 'ufw_journal_sequence_or_size'}
  $envelope=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($f.FullName))
  if((@($envelope.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'payload,sha256' -or $envelope.payload -isnot [string] -or $envelope.sha256 -cne (Get-UfwJournalHash $envelope.payload)){throw 'ufw_journal_checksum'}
  $body=ConvertFrom-Json -InputObject $envelope.payload
  if((@($body.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'data,kind,previous_sha256,schema,sequence,session_id' -or $body.schema -cne 'ufw-preparation-checkpoint-01' -or ($body.sequence -isnot [int] -and $body.sequence -isnot [long]) -or $body.sequence -ne $seq -or $body.previous_sha256 -cne $head -or $body.session_id -cne $SessionId){throw 'ufw_journal_chain'}
  Assert-UfwPreparationData $body.data $SessionId
  if($seq -eq 1){if($body.kind -cne 'prepared' -or $body.data.draft.phase -cne 'prepared' -or @($body.data.draft.entries|Where-Object{$_.intent -or $_.restored}).Count -ne 0){throw 'ufw_journal_initial_state'}}
  else{if($body.kind -cne 'model_checkpoint'){throw 'ufw_journal_checkpoint_kind'};Assert-UfwCheckpointProgress $last.data $body.data}
  $head=$envelope.sha256;$last=$body
 }
 return [pscustomobject]@{sequence=$seq;head=$head;last=$last}
}
function Add-UfwPreparationCheckpoint([string]$Root,[string]$SessionId,[string]$ExpectedHead,[string]$Kind,$Data){
 Assert-UfwPreparationData $Data $SessionId
 if($ExpectedHead -cnotmatch '^[a-f0-9]{64}$'){throw 'ufw_journal_expected_head'}
 Assert-UfwJournalAcl $Root $true
 $lock=Open-UfwPrivateJournalFile (Join-Path $Root 'operation.lock') ([IO.FileMode]::OpenOrCreate)
 try{
  $before=Read-UfwPreparationJournal $Root $SessionId
  if($before.head -cne $ExpectedHead){throw 'ufw_journal_stale_head'}
  if($before.sequence -ge 128){throw 'ufw_journal_record_limit'}
  if($before.sequence -eq 0){if($Kind -cne 'prepared' -or $Data.draft.phase -cne 'prepared' -or @($Data.draft.entries|Where-Object{$_.intent -or $_.restored}).Count){throw 'ufw_journal_initial_state'}}else{if($Kind -cne 'model_checkpoint'){throw 'ufw_journal_checkpoint_kind'};Assert-UfwCheckpointProgress $before.last.data $Data}
  $seq=$before.sequence+1;$body=[pscustomobject][ordered]@{schema='ufw-preparation-checkpoint-01';session_id=$SessionId;sequence=$seq;previous_sha256=$before.head;kind=$Kind;data=$Data}
  $payload=Get-UfwJournalJson $body;$hash=Get-UfwJournalHash $payload;$bytes=[Text.Encoding]::UTF8.GetBytes((Get-UfwJournalJson ([ordered]@{payload=$payload;sha256=$hash})))
  if($bytes.Length -gt 262144){throw 'ufw_journal_sequence_or_size'}
  $file=Join-Path $Root ($seq.ToString('D8')+'.json');$stream=Open-UfwPrivateJournalFile $file ([IO.FileMode]::CreateNew)
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  $after=Read-UfwPreparationJournal $Root $SessionId
  if($after.sequence -ne $seq -or $after.head -cne $hash){throw 'ufw_journal_readback'}
  return [pscustomobject]@{sequence=$seq;head=$hash;readback_verified=$true}
 }finally{$lock.Dispose()}
}
function Save-UfwNativePreparation($Receipt,$Draft){
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'ufw_journal_windows_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or -not [Environment]::Is64BitProcess){throw 'ufw_journal_ps51_x64_required'}
 $who=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ufw_journal_admin_required'}
 $data=[pscustomobject][ordered]@{receipt=$Receipt;draft=$Draft};Assert-UfwPreparationData $data $Receipt.session_id
 $root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'UnifiedFW-InstallerSessions-01';Assert-UfwJournalPath $root
 if(-not [IO.Directory]::Exists($root)){New-UfwPrivateJournalDirectory $root}else{Assert-UfwJournalAcl $root $true}
 $session=Join-Path $root ('UfwInstaller-Session-'+$Receipt.session_id);New-UfwPrivateJournalDirectory $session
 return Add-UfwPreparationCheckpoint $session $Receipt.session_id ('0'*64) 'prepared' $data
}
function Invoke-UfwPreparationConsentCallbacks($Ops){
 $r=[ordered]@{schema='ufw-preparation-review-result-01';completed=$false;code='';consent_received=$false;journal_write_attempted=$false;journal_preparation_recorded=$false;firewall_change_requested=$false;ready_for_apply=$false;no_leak_certified=$false}
 try{
  foreach($key in @('ReadObservation','ShowReview','ReadAnswer','UtcNow','SavePreparation')){if(-not $Ops.ContainsKey($key) -or $Ops[$key] -isnot [scriptblock]){throw 'ufw_journal_consent_adapter_missing'}}
  $draft=& $script:Core {param($o)New-UfwProfileRecoveryDraft $o} (& $Ops.ReadObservation)
  $hash=Get-UfwDraftBaselineHash $draft;$id=[guid]::NewGuid().ToString('N');$challenge='PREPARE JOURNAL '+$id+' '+[guid]::NewGuid().ToString('N')
  $start=& $Ops.UtcNow;if($start -isnot [datetime] -or $start.Kind -ne [DateTimeKind]::Utc){throw 'ufw_journal_utc_clock_required'}
  & $Ops.ShowReview $draft $challenge|Out-Null;$answer=& $Ops.ReadAnswer $challenge
  if($answer -isnot [string] -or $answer -cne $challenge){$r.completed=$true;$r.code='ufw_journal_cancelled_no_write';return [pscustomobject]$r}
  $r.consent_received=$true
  $fresh=& $script:Core {param($o)New-UfwProfileRecoveryDraft $o} (& $Ops.ReadObservation)
  if((Get-UfwDraftBaselineHash $fresh) -cne $hash){throw 'ufw_journal_baseline_changed_after_prompt'}
  $now=& $Ops.UtcNow;if($now -isnot [datetime] -or $now.Kind -ne [DateTimeKind]::Utc -or $now -lt $start -or $now -gt $start.AddSeconds(120)){throw 'ufw_journal_consent_expired_or_clock_changed'}
  $receipt=[pscustomobject][ordered]@{schema='ufw-preparation-consent-01';session_id=$id;baseline_sha256=$hash;challenge_sha256=(Get-UfwJournalHash $challenge);purpose='prepare_profile_journal_only';consent_validated=$true;created_utc=$now.ToString('yyyy-MM-dd HH:mm:ss.fffffff',[Globalization.CultureInfo]::InvariantCulture)+' UTC';authorizes_firewall_change=$false;ready_for_apply=$false}
  $r.journal_write_attempted=$true;$saved=& $Ops.SavePreparation $receipt $fresh
  if($saved.readback_verified -isnot [bool] -or -not $saved.readback_verified -or $saved.sequence -ne 1 -or $saved.head -cnotmatch '^[a-f0-9]{64}$'){throw 'ufw_journal_preparation_unverified'}
  $post=& $script:Core {param($o)New-UfwProfileRecoveryDraft $o} (& $Ops.ReadObservation)
  if((Get-UfwDraftBaselineHash $post) -cne $hash){throw 'ufw_journal_baseline_changed_after_write'}
  $end=& $Ops.UtcNow;if($end -isnot [datetime] -or $end.Kind -ne [DateTimeKind]::Utc -or $end -lt $now -or $end -gt $start.AddSeconds(120)){throw 'ufw_journal_consent_expired_after_write'}
  $r.journal_preparation_recorded=$true;$r.completed=$true;$r.code='ufw_journal_prepared_no_firewall_authority'
 }catch{
  $m=[string]$_.Exception.GetBaseException().Message
  if($m -cmatch '^(ufw_journal|ufw_core|ufw_read)_[a-z_0-9]{1,100}$'){$r.code=$m}else{$r.code='ufw_journal_preparation_unavailable'}
 }
 return [pscustomobject]$r
}
function New-UfwNativePreparationOps {
 return @{
  ReadObservation={$result=Invoke-UfwInstallerPreflightReadOnly;if(-not $result.completed){throw 'ufw_journal_native_preflight_incomplete'};return $result.profile_observation}
  ShowReview={param($draft,$challenge)Write-Host 'Preparation journal ONLY. No firewall, VPN or route change is authorized.';$draft.entries|ForEach-Object{$_.before}|Format-Table name,local_outbound,effective_outbound -AutoSize|Out-Host;Write-Host 'Enter cancels. This is not consent to isolation.'}
  ReadAnswer={param($challenge)Read-Host ('Type exactly: '+$challenge)}
  UtcNow={[datetime]::UtcNow}
  SavePreparation={param($receipt,$draft)Save-UfwNativePreparation $receipt $draft}
 }
}
function Get-UfwPreparationCapabilities {return [pscustomobject]@{schema='ufw-preparation-capabilities-01';scope='prepare_profile_journal_only';public_preparation_execution_enabled=$false;native_firewall_writer_present=$false;native_storage_Windows_qualified=$false;ready_for_apply=$false}}
Export-ModuleMember -Function Get-UfwPreparationCapabilities
