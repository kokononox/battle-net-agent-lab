# Explicit evidence-based cleanup for ONE observed disabled orphan. No general Force Restore.
function AssertKnownSession($Session,$Expected){
 if($null -eq $Session -or $Session.owner -cne $Expected.owner -or $Session.id -cne $Expected.session_id -or $Session.phase -cnotin @('restoring','restored') -or $Session.entries.Count -ne 2){throw 'recovery_session_identity_or_phase'}
 $a=$Session.entries[0];$b=$Session.entries[1]
 if($a.name -cne $Expected.target_name -or $b.name -cne $Expected.never_created_name -or -not $a.intent -or $b.intent -or $null -ne $a.disabled_image -or $null -ne $a.enabled_image -or $null -ne $b.disabled_image -or $null -ne $b.enabled_image -or $b.removed){throw 'recovery_session_entry_drift'}
 if($Session.phase -ceq 'restored' -and -not $a.removed){throw 'recovery_restored_flags'}
 if($Session.plan.owner -cne $Expected.owner -or $Session.plan.rules.Count -ne 2 -or $Session.plan.rules[0].name -cne $Expected.target_name -or $Session.plan.rules[1].name -cne $Expected.never_created_name){throw 'recovery_plan_identity'}
}
function AssertKnownDisabledImages($Expected,[scriptblock]$Read,[bool]$AllowAbsent){
 $present=@()
 foreach($store in @('PersistentStore','ActiveStore')){
  if($null -ne (& $Read $Expected.never_created_name $store)){throw 'recovery_unexpected_second_rule'}
  $image=& $Read $Expected.target_name $store
  $present+=,($null -ne $image)
  if($null -eq $image){if(-not $AllowAbsent){throw 'recovery_target_missing_without_intent'};continue}
  if($image.rule.Enabled -cne '2' -or -not (UEqual $image $Expected.images.$store)){throw ('recovery_full_image_drift:'+ $store)}
 }
 if($present[0] -ne $present[1]){throw 'recovery_store_presence_mismatch'}
 return $present[0]
}
function InvokeKnownDisabledRecovery([string]$Root,$Expected,[scriptblock]$Read,[scriptblock]$Remove,[scriptblock]$Hook=$null){
 $session=ULoad $Root;AssertKnownSession $session $Expected
 if($Expected.target_name -cnotmatch ('^UnifiedFW-'+$Expected.owner+'-blacklist-[a-f0-9]{24}$') -or $Expected.session_id -cnotmatch '^[a-f0-9]{32}$'){throw 'recovery_expected_identity'}
 $intentPath=Join-Path $Root ('known-recovery-'+$Expected.session_id+'.json');UAssertPath $intentPath
 $backupPath=Join-Path $Root ('known-recovery-'+$Expected.session_id+'-before.json');UAssertPath $backupPath
 $expectedHash=UHash (UJson $Expected);$hasIntent=[IO.File]::Exists($intentPath)
 if($hasIntent){
  if((Get-Item -LiteralPath $intentPath).Length -gt 65536){throw 'recovery_intent_size'}
  $record=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($intentPath))
  if($record.schema -cne 'known-disabled-recovery-intent-1' -or $record.session_id -cne $Expected.session_id -or $record.owner -cne $Expected.owner -or $record.expected_hash -cne $expectedHash){throw 'recovery_intent_drift'}
  if(-not [IO.File]::Exists($backupPath) -or (UHash ([IO.File]::ReadAllText($backupPath))) -cne $record.backup_hash){throw 'recovery_backup_integrity'}
 }
 if($session.phase -ceq 'restored'){
  if(-not $hasIntent){throw 'recovery_restored_without_intent'}
  if(AssertKnownDisabledImages $Expected $Read $true){throw 'recovery_rule_reappeared_after_completion'}
  return [pscustomobject]@{ok=$true;already_completed=$true;owned_session_restored=$true;rule_deleted_this_run=$false}
 }
 $present=AssertKnownDisabledImages $Expected $Read $hasIntent
 if(-not $hasIntent){
  $original=[IO.File]::ReadAllText((Join-Path $Root 'session.json'))
  if([IO.File]::Exists($backupPath)){if([IO.File]::ReadAllText($backupPath) -cne $original){throw 'recovery_backup_collision'}}else{UWritePrivateBytes $backupPath ([Text.Encoding]::UTF8.GetBytes($original))}
  $record=[ordered]@{schema='known-disabled-recovery-intent-1';session_id=$Expected.session_id;owner=$Expected.owner;expected_hash=$expectedHash;backup_hash=(UHash $original);created_utc=[datetime]::UtcNow.ToString('o')}
  UWritePrivateBytes $intentPath ([Text.Encoding]::UTF8.GetBytes((UJson $record)))
 }
 UCheckpoint $Hook 'recovery_intent_saved'
 if($present){
  # Two complete stores, both names, all seven filters, and disabled state rechecked.
  $null=AssertKnownDisabledImages $Expected $Read $false
  UCheckpoint $Hook 'recovery_before_remove'
  $null=AssertKnownDisabledImages $Expected $Read $false
  & $Remove $Expected.target_name|Out-Null
  UCheckpoint $Hook 'recovery_after_remove'
 }
 if(AssertKnownDisabledImages $Expected $Read $true){throw 'recovery_rule_still_present'}
 UCheckpoint $Hook 'recovery_before_journal_restore'
 # Do not adopt or seal an unknown image. Only absent names can reach journal Restore.
 $originalRecoveryRead=$Read
 $absentRead={param($name) $value=& $originalRecoveryRead $name 'PersistentStore';if($null -ne $value){throw 'recovery_rule_appeared_before_journal_restore'};return $null}.GetNewClosure()
 $neverRemove={param($name) throw 'recovery_no_additional_deletion_permitted'}
 $restored=RestoreUSession $Root $absentRead $neverRemove
 if($restored.phase -cne 'restored'){throw 'recovery_journal_not_restored'}
 if(AssertKnownDisabledImages $Expected $Read $true){throw 'recovery_rule_reappeared'}
 return [pscustomobject]@{ok=$true;already_completed=$false;owned_session_restored=$true;rule_deleted_this_run=$present;only_target_name=$Expected.target_name;profiles_modified=$false;other_rules_modified=$false;rule_activated=$false}
}
