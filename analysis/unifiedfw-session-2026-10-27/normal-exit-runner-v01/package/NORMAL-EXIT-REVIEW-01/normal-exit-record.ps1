# Library only. Requires existing session-core/native/isolation-core/isolation-native.
# Records a separately acknowledged NORMAL networking baseline, never a historical Restore.
Set-StrictMode -Version 2.0
function IsoExitBuildPreview($S,$Ops){
 if($null -eq $S -or $S.schema -cne 'unified-isolation-session-1' -or $S.phase -cne 'restored' -or $S.id -cnotmatch '^[a-f0-9]{32}$' -or $S.owner -cnotmatch '^[a-f0-9]{32}$'){throw 'normal_exit_legacy_session_review_required'}
 if($S.entries -isnot [array] -or $S.entries.Count -gt 1024 -or $S.foreign -isnot [array] -or $S.foreign.Count -gt 4096 -or @($S.profiles).Count -ne 3 -or ((@($S.profiles|ForEach-Object{$_.name}|Sort-Object))-join ',') -cne 'Domain,Private,Public'){throw 'normal_exit_legacy_shape'}
 $journalBefore=& $Ops.JournalDigest $S
 if($journalBefore -isnot [string] -or $journalBefore -cnotmatch '^[a-f0-9]{64}$'){throw 'normal_exit_journal_digest_invalid'}
 $controllerCount=& $Ops.ControllerCount
 if($controllerCount -isnot [int] -or $controllerCount -ne 0){throw 'normal_exit_controller_task_present_or_unknown'}
 $seen=@{};$ownedCount=0;$foreignProof=@();$profiles=@()
 foreach($e in @($S.entries)){
  if($e.intent -isnot [bool] -or $e.removed -isnot [bool] -or $e.name -cnotmatch ('^UnifiedFW-ISO-'+$S.owner+'-[a-f0-9]{24}$') -or $seen.ContainsKey($e.name)){throw 'normal_exit_owned_identity_invalid'}
  $seen[$e.name]=$true
  if($e.intent){if(-not $e.removed -or $null -ne (& $Ops.Read $e.name)){throw 'normal_exit_owned_rule_not_removed'};$ownedCount++}
 }
 $seen=@{}
 foreach($f in @($S.foreign)){
  if($f.intent -isnot [bool] -or $f.restored -isnot [bool] -or $f.name -isnot [string] -or [string]::IsNullOrWhiteSpace($f.name) -or $seen.ContainsKey($f.name)){throw 'normal_exit_foreign_identity_invalid'}
  $seen[$f.name]=$true
  if($f.intent){if(-not $f.restored -or -not (UEqual (& $Ops.Read $f.name) $f.before)){throw 'normal_exit_foreign_before_image_mismatch'};$foreignProof+=,[pscustomobject][ordered]@{name=$f.name;before_digest=(UHash (UJson $f.before))}}
 }
 foreach($p in @($S.profiles|Sort-Object name)){
  if($p.intent -isnot [bool] -or -not $p.intent -or $p.restored -isnot [bool] -or -not $p.restored -or $p.before.default_outbound -isnot [string] -or $p.before.default_outbound -cnotin @('Allow','Block','NotConfigured')){throw 'normal_exit_legacy_profile_review_required'}
  $local=& $Ops.ProfileRead $p.name;$effective=& $Ops.ProfileEffectiveRead $p.name
  foreach($image in @($local,$effective)){
   if($image.name -cne $p.name -or $image.default_outbound -cne 'Allow' -or $image.enabled -cne 'True' -or $image.allow_local_rules -cnotin @('True','NotConfigured')){throw 'normal_exit_current_profile_not_normal_allow'}
  }
  $profiles+=,[pscustomobject][ordered]@{name=$p.name;legacy_outbound=$p.before.default_outbound;local=$local;effective=$effective}
 }
 if((& $Ops.JournalDigest $S) -cne $journalBefore){throw 'normal_exit_journal_changed_during_review'}
 $lastControllerCount=& $Ops.ControllerCount
 if($lastControllerCount -isnot [int] -or $lastControllerCount -ne 0){throw 'normal_exit_controller_appeared'}
 $evidence=[pscustomobject][ordered]@{schema='unified-normal-mode-exit-evidence-1';legacy_session_id=$S.id;legacy_owner=$S.owner;legacy_journal_sha256=$journalBefore;owned_rules_absent=$ownedCount;foreign_images_digest=(UHash (UJson @($foreignProof|Sort-Object name)));foreign_images_matched=$foreignProof.Count;profiles=$profiles;known_isolation_controller_count=0;scope='explicit_new_normal_mode_not_original_baseline_restore'}
 $digest=UHash (UJson $evidence)
 return [pscustomobject]@{digest=$digest;evidence=$evidence;review=[pscustomobject][ordered]@{scope='acknowledge_existing_normal_mode_only';owned_rules_absent=$ownedCount;foreign_images_matched=$foreignProof.Count;profiles=@($profiles|ForEach-Object{[pscustomobject]@{name=$_.name;legacy_outbound=$_.legacy_outbound;current_local_outbound=$_.local.default_outbound;current_effective_outbound=$_.effective.default_outbound;firewall_enabled=$_.effective.enabled}});legacy_journal_will_be_rewritten=$false;network_policy_will_be_changed=$false;may_start_isolation=$false;reboot_qualified=$false}}
}
function IsoExitRecordNormalMode($S,$Ops,[string]$Confirmation,[string]$ReviewDigest){
 if($Confirmation -cne 'ACKNOWLEDGE EXISTING NORMAL NETWORK MODE'){throw 'normal_exit_explicit_consent_required'}
 if($ReviewDigest -cnotmatch '^[a-f0-9]{64}$'){throw 'normal_exit_review_digest_required'}
 $fresh=IsoExitBuildPreview $S $Ops
 if($fresh.digest -cne $ReviewDigest){throw 'normal_exit_review_stale'}
 $existing=& $Ops.ReadRecord $S
 $created=$false
 if($null -ne $existing){
  if(((@($existing.PSObject.Properties.Name|Sort-Object))-join ',') -cne 'authorizes_isolation,consent,created_utc,evidence,original_restore_verified,reboot_qualified,review_digest,schema' -or $existing.consent -cne 'ACKNOWLEDGE EXISTING NORMAL NETWORK MODE' -or $existing.reboot_qualified -isnot [bool] -or $existing.reboot_qualified -ne $false -or $existing.schema -cne 'unified-normal-mode-exit-record-1' -or $existing.review_digest -cne $fresh.digest -or -not (UEqual $existing.evidence $fresh.evidence) -or $existing.authorizes_isolation -isnot [bool] -or $existing.authorizes_isolation -ne $false -or $existing.original_restore_verified -isnot [bool] -or $existing.original_restore_verified -ne $false){throw 'normal_exit_existing_record_conflict'}
 }else{
  $record=[pscustomobject][ordered]@{schema='unified-normal-mode-exit-record-1';created_utc=([datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss.fffffff',[Globalization.CultureInfo]::InvariantCulture)+' UTC');consent='ACKNOWLEDGE EXISTING NORMAL NETWORK MODE';review_digest=$fresh.digest;evidence=$fresh.evidence;authorizes_isolation=$false;original_restore_verified=$false;reboot_qualified=$false}
  & $Ops.WriteRecord $S $record
  $created=$true;$existing=& $Ops.ReadRecord $S
  if(-not (UEqual $record $existing)){throw 'normal_exit_record_readback_failed'}
 }
 $after=IsoExitBuildPreview $S $Ops
 if($after.digest -cne $fresh.digest){throw 'normal_exit_state_changed_after_record'}
 return [pscustomobject][ordered]@{schema='unified-normal-mode-exit-result-1';normal_mode_acknowledgment_recorded=$true;created_this_call=$created;record_matches_current_snapshot=$true;scope='explicit_new_normal_mode_not_original_baseline_restore';legacy_journal_rewritten=$false;firewall_changed=$false;rules_changed=$false;controller_installed_or_removed=$false;authorizes_isolation=$false;original_restore_verified=$false;reboot_qualified=$false;ready_for_apply=$false;no_leak_certified=$false}
}
function IsoExitJournalDigest($S){
 $path=Join-Path $script:IsoRoot 'session.json';UAssertPath $path
 $before=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
 $live=IsoLoad
 $after=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
 if($before -cne $after -or -not (UEqual $live $S)){throw 'normal_exit_legacy_journal_changed'}
 return $after
}
function IsoExitRecordPath($S){
 if($S.id -cnotmatch '^[a-f0-9]{32}$'){throw 'normal_exit_record_identity'}
 return Join-Path $script:IsoRoot ('normal-mode-exit-'+$S.id+'.json')
}
function IsoExitReadRecord($S){
 $path=IsoExitRecordPath $S;UAssertPath $path
 if(-not [IO.File]::Exists($path)){return $null}
 if((Get-Item -LiteralPath $path).Length -gt 65536){throw 'normal_exit_record_size'}
 $envelope=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($path))
 if(((@($envelope.PSObject.Properties.Name|Sort-Object))-join ',') -cne 'payload,sha256' -or $envelope.payload -isnot [string] -or (UHash $envelope.payload) -cne $envelope.sha256){throw 'normal_exit_record_checksum'}
 return ConvertFrom-Json -InputObject $envelope.payload
}
function IsoExitWriteRecord($S,$Record){
 $payload=UJson $Record
 if([Text.Encoding]::UTF8.GetByteCount($payload) -gt 60000){throw 'normal_exit_record_size'}
 $envelope=UJson ([ordered]@{payload=$payload;sha256=(UHash $payload)})
 # Existing helper uses CreateNew and supplies admin/SYSTEM DACL at creation on Windows.
 UWritePrivateBytes (IsoExitRecordPath $S) ([Text.Encoding]::UTF8.GetBytes($envelope))
}
function IsoExitControllerCount{
 # Known isolation tasks only. This is not an inventory of all possible policy writers.
 return [int]@(Get-ScheduledTask -ErrorAction Stop|Where-Object{$_.TaskName -like 'UnifiedFW-Isolation-*'}).Count
}
function IsoExitNativeOps{
 return @{JournalDigest={param($s)IsoExitJournalDigest $s};ControllerCount={IsoExitControllerCount};Read={param($n)UReadNative $n};ProfileRead={param($n)IsoProfileRead $n};ProfileEffectiveRead={param($n)IsoProfileRead $n 'ActiveStore'};ReadRecord={param($s)IsoExitReadRecord $s};WriteRecord={param($s,$r)IsoExitWriteRecord $s $r}}
}
function Invoke-IsoNormalExitOperation{
 param([ValidateSet('Review','Record')][string]$Operation='Review',[string]$Confirmation='',[string]$ReviewDigest='')
 $lock=$null;$previousRoot=$null;$hadRoot=$false;$rootTouched=$false
 try{
  UAdmin
  $old=Get-Variable IsoRoot -Scope Script -ErrorAction SilentlyContinue
  if($null -ne $old){$previousRoot=$old.Value;$hadRoot=$true}
  $script:IsoRoot=IsoSecureRoot $false;$rootTouched=$true
  if(-not [IO.Directory]::Exists($script:IsoRoot)){throw 'normal_exit_existing_protected_journal_required'}
  # Same exclusive operation lock as guardian/Restore; do not touch a busy controller.
  $lock=UOpenPrivateFile (Join-Path $script:IsoRoot 'operation.lock') ([IO.FileMode]::OpenOrCreate)
  $s=IsoLoad;$ops=IsoExitNativeOps
  if($Operation -ceq 'Review'){
   $preview=IsoExitBuildPreview $s $ops
   return [pscustomobject]@{schema='unified-normal-mode-exit-review-1';review_digest=$preview.digest;review=$preview.review;record_created=$false;legacy_journal_rewritten=$false;ready_for_apply=$false}
  }
  return IsoExitRecordNormalMode $s $ops $Confirmation $ReviewDigest
 }finally{
  if($null -ne $lock){$lock.Dispose()}
  if($rootTouched){if($hadRoot){$script:IsoRoot=$previousRoot}else{Remove-Variable IsoRoot -Scope Script -ErrorAction SilentlyContinue}}
 }
}
