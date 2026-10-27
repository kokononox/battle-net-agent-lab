# Callback-driven, owner-scoped isolation transaction. No automatic rollback to Allow.
function IsoCopy($Value){ConvertFrom-Json -InputObject (UJson $Value)}
function IsoDisabled($Image){$x=IsoCopy $Image;if($x.rule.Enabled -cne '1'){throw 'iso_foreign_enabled_encoding'};$x.rule.Enabled='2';return $x}
function IsoCheckpoint($Ops,$S,[string]$Point){& $Ops.Save $S;if($Ops.ContainsKey('Hook')){& $Ops.Hook $Point}}
function IsoAddRules($S,$Rules,$Ops){
 foreach($spec in @($Rules)){
  if(@($S.entries|Where-Object{$_.name -ceq $spec.name -and -not $_.removed}).Count){continue}
  if($null -ne (& $Ops.Read $spec.name)){throw 'iso_rule_collision_no_adoption'}
  $e=[pscustomobject]@{name=$spec.name;spec=$spec;intent=$true;disabled=$null;enabled=$null;removed=$false}
  $S.entries+=,$e;IsoCheckpoint $Ops $S ('create_intent:'+ $e.name)
  & $Ops.Create $spec $S.id
  $image=& $Ops.Read $e.name;& $Ops.Validate $image $spec $S.id 'False'
  $e.disabled=$image;$e.enabled=UEnabledNative $image;IsoCheckpoint $Ops $S ('sealed:'+ $e.name)
 }
}
function IsoQuarantine($S,$Items,$Ops){
 foreach($item in @($Items)){
  $known=@($S.foreign|Where-Object{$_.name -ceq $item.name})
  if($known.Count){
   if(-not (UEqual $known[0].before $item.image)){throw 'iso_foreign_changed_since_backup'};$r=$known[0]
  }else{
   $r=[pscustomobject]@{name=$item.name;before=$item.image;after=(IsoDisabled $item.image);intent=$false;restored=$false};$S.foreign+=,$r
  }
  if(-not (UEqual (& $Ops.Read $r.name) $r.before)){throw 'iso_foreign_drift_before_disable'}
  $r.intent=$true;$r.restored=$false;IsoCheckpoint $Ops $S ('foreign_intent:'+ $r.name)
  & $Ops.Disable $r.name
  if(-not (UEqual (& $Ops.Read $r.name) $r.after)){throw 'iso_foreign_disable_readback'}
  IsoCheckpoint $Ops $S ('foreign_disabled:'+ $r.name)
 }
}
function IsoEnableRules($S,$Names,$Ops){
 foreach($e in @($S.entries|Where-Object{$Names -ccontains $_.name -and -not $_.removed})){
  $now=& $Ops.Read $e.name
  if(UEqual $now $e.enabled){& $Ops.Validate $now $e.spec $S.id 'True';continue}
  if($null -eq $e.disabled -or -not (UEqual $now $e.disabled)){throw 'iso_owned_drift_before_enable'}
  & $Ops.Enable $e.name
  if(-not (UEqual (& $Ops.Read $e.name) $e.enabled)){throw 'iso_owned_enable_readback'}
  & $Ops.Validate (& $Ops.Read $e.name) $e.spec $S.id 'True'
  IsoCheckpoint $Ops $S ('enabled:'+ $e.name)
 }
}
function Invoke-IsoArm($S,$Plan,$Ops){
 if($S.phase -cne 'prepared'){throw 'iso_not_prepared'}
 $S.phase='arming';IsoCheckpoint $Ops $S 'arming'
 try{
  # Compiler-generated transport names only. Full strict enable/readback remains unchanged.
  $early=@();if($Plan.PSObject.Properties.Name -contains 'pre_block_rule_names'){$early=@($Plan.pre_block_rule_names)}
  foreach($n in $early){if(@($Plan.rules|Where-Object{$_.name -ceq $n}).Count -ne 1){throw 'iso_invalid_pre_block_rule_identity'}}
  IsoAddRules $S $Plan.rules $Ops
  IsoEnableRules $S $early $Ops
  foreach($p in $S.profiles){
   if(-not (UEqual (& $Ops.ProfileRead $p.name) $p.before)){throw 'iso_profile_drift_before_block'}
   $p.intent=$true;IsoCheckpoint $Ops $S ('profile_intent:'+ $p.name)
   & $Ops.ProfileSet $p.name 'Block'
   $now=& $Ops.ProfileRead $p.name
   if($now.default_outbound -cne 'Block' -or $now.enabled -cne 'True'){throw 'iso_profile_block_readback'}
   $p.after=$now;IsoCheckpoint $Ops $S ('profile_blocked:'+ $p.name)
  }
  IsoQuarantine $S $Plan.foreign $Ops
  IsoEnableRules $S @($Plan.rules|ForEach-Object{$_.name}) $Ops
  & $Ops.Verify $S
  $S.phase='armed';$S.plan=$Plan;IsoCheckpoint $Ops $S 'armed';return $S
 }catch{$S.phase='arming_failed_no_automatic_allow';$S.health='critical_changes_partial_inspect_journal';& $Ops.Save $S;throw}
}
function Invoke-IsoUpdate($S,$Plan,$Ops){
 if($S.phase -cne 'armed'){throw 'iso_update_requires_armed_review_otherwise'}
 $S.phase='updating';IsoCheckpoint $Ops $S 'updating'
 try{
  & $Ops.Verify $S
  IsoAddRules $S $Plan.rules $Ops;IsoQuarantine $S $Plan.foreign $Ops
  $names=@($Plan.rules|ForEach-Object{$_.name});IsoEnableRules $S $names $Ops
  foreach($e in @($S.entries|Where-Object{-not $_.removed -and $names -cnotcontains $_.name})){
   $now=& $Ops.Read $e.name
   if($null -ne $now -and -not (UEqual $now $e.enabled) -and -not (UEqual $now $e.disabled)){throw 'iso_old_rule_drift'}
   if($null -ne $now){& $Ops.Remove $e.name};if($null -ne (& $Ops.Read $e.name)){throw 'iso_old_rule_remove_readback'}
   $e.removed=$true;IsoCheckpoint $Ops $S ('old_removed:'+ $e.name)
  }
  & $Ops.Verify $S;$S.plan=$Plan;$S.phase='armed';IsoCheckpoint $Ops $S 'updated';return $S
 }catch{$S.phase='update_failed_no_automatic_allow';$S.health='critical_changes_partial_inspect_journal';& $Ops.Save $S;throw}
}
function Restore-IsoSession($S,$Ops){
 if($S.phase -ceq 'restored'){return $S}
 # Preflight every restorable image BEFORE the first destructive/restorative write.
 foreach($e in @($S.entries|Where-Object{$_.intent})){
  $now=& $Ops.Read $e.name
  if($e.removed -and $null -ne $now){throw 'iso_rule_reappeared'}
  if($null -ne $now -and ($null -eq $e.disabled -or $null -eq $e.enabled)){throw 'iso_unsealed_rule_requires_inspection'}
  if($null -ne $now -and -not (UEqual $now $e.disabled) -and -not (UEqual $now $e.enabled)){
   if(-not $Ops.ContainsKey('ValidateDisabledRemoval')){throw 'iso_restore_owned_rule_drift'}
   & $Ops.ValidateDisabledRemoval $now $e $S
  }
 }
 foreach($r in @($S.foreign|Where-Object{$_.intent})){if(-not (UEqual (& $Ops.Read $r.name) $r.before) -and -not (UEqual (& $Ops.Read $r.name) $r.after)){throw 'iso_restore_foreign_drift'}}
 foreach($p in @($S.profiles|Where-Object{$_.intent})){$now=& $Ops.ProfileRead $p.name;if($now.default_outbound -cne 'Block' -and $now.default_outbound -cne $p.before.default_outbound){throw 'iso_restore_profile_drift'}}
 $S.phase='restoring';IsoCheckpoint $Ops $S 'restoring'
 foreach($e in @($S.entries|Where-Object{$_.intent -and -not $_.removed})){
  $now=& $Ops.Read $e.name
  if($null -ne $now){if(-not (UEqual $now $e.disabled) -and -not (UEqual $now $e.enabled)){
   if(-not $Ops.ContainsKey('ValidateDisabledRemoval')){throw 'iso_restore_concurrent_owned_change'}
   & $Ops.ValidateDisabledRemoval $now $e $S
  };& $Ops.Remove $e.name}
  if($null -ne (& $Ops.Read $e.name)){throw 'iso_restore_remove_failed'};$e.removed=$true;IsoCheckpoint $Ops $S ('removed:'+ $e.name)
 }
 foreach($r in @($S.foreign|Where-Object{$_.intent})){
  $now=& $Ops.Read $r.name
  if(UEqual $now $r.after){& $Ops.Enable $r.name}elseif(-not (UEqual $now $r.before)){throw 'iso_restore_concurrent_foreign_change'}
  if(-not (UEqual (& $Ops.Read $r.name) $r.before)){throw 'iso_restore_foreign_readback'};$r.restored=$true;IsoCheckpoint $Ops $S ('foreign_restored:'+ $r.name)
 }
 foreach($p in @($S.profiles|Where-Object{$_.intent})){
  $now=& $Ops.ProfileRead $p.name
  if($now.default_outbound -ceq 'Block'){& $Ops.ProfileSet $p.name $p.before.default_outbound}elseif($now.default_outbound -cne $p.before.default_outbound){throw 'iso_restore_concurrent_profile_change'}
  if((& $Ops.ProfileRead $p.name).default_outbound -cne $p.before.default_outbound){throw 'iso_restore_profile_readback'};$p.restored=$true;IsoCheckpoint $Ops $S ('profile_restored:'+ $p.name)
 }
 $S.phase='restored';$S.health='disabled_explicitly_original_fields_restored';IsoCheckpoint $Ops $S 'restored';return $S
}
