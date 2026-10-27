# Minimal installer foundation. Only a read-only preflight entry is public.
Set-StrictMode -Version 2.0
$dependency=Join-Path $PSScriptRoot 'Ufw.ProfileReader.psm1'
$p=[IO.Path]::GetFullPath($dependency)
while($p){if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ufw_core_dependency_reparse'};$q=[IO.Path]::GetDirectoryName($p);if($q -eq $p){break};$p=$q}
if((Get-FileHash -LiteralPath $dependency -Algorithm SHA256 -ErrorAction Stop).Hash -cne 'DDD2575DDC177E6E4EEDD67C14A1AA7B1BFE17723CEA973D6648F7582F788BCC'){throw 'ufw_core_dependency_hash'}
Import-Module $dependency -Scope Local -ErrorAction Stop
function Get-UfwCoreJson($Value){
 # Canonical field/name order avoids treating enumeration order as policy drift.
 $list=@(foreach($row in @($Value|Sort-Object name)){$o=[ordered]@{};foreach($key in @($row.PSObject.Properties.Name|Sort-Object)){$o[$key]=$row.$key};[pscustomobject]$o})
 if($Value -is [array]){return ConvertTo-Json -InputObject $list -Depth 16 -Compress}
 return ConvertTo-Json -InputObject $list[0] -Depth 16 -Compress
}
function Assert-UfwCoreProfileRows($Rows){
 if($Rows -isnot [array] -or $Rows.Count -ne 3){throw 'ufw_core_profile_coverage'}
 $seen=@{}
 foreach($row in $Rows){
  if($null -eq $row){throw 'ufw_core_profile_shape'}
  $keys=@($row.PSObject.Properties.Name|Sort-Object)
  if(($keys -join ',') -cne 'effective_allow_local_rules,effective_enabled,effective_outbound,local_allow_local_rules,local_enabled,local_outbound,name'){throw 'ufw_core_profile_shape'}
  if($row.name -isnot [string] -or $row.name -cnotin @('Domain','Private','Public') -or $seen.ContainsKey($row.name)){throw 'ufw_core_profile_identity'};$seen[$row.name]=$true
  foreach($key in @('local_outbound','effective_outbound')){if($row.$key -isnot [string] -or $row.$key -cnotin @('Allow','Block')){throw 'ufw_core_explicit_outbound_required'}}
  foreach($key in @('local_enabled','local_allow_local_rules')){if($row.$key -isnot [string] -or $row.$key -cnotin @('True','False','NotConfigured')){throw 'ufw_core_local_field_encoding'}}
  if($row.effective_enabled -isnot [string] -or $row.effective_allow_local_rules -isnot [string] -or $row.effective_enabled -cne 'True' -or $row.effective_allow_local_rules -cne 'True'){throw 'ufw_core_effective_profile_policy'}
 }
}
function New-UfwProfileRecoveryDraft($Observation){
 if($Observation.schema -cne 'ufw-readonly-profile-preflight-01' -or $Observation.completed -isnot [bool] -or -not $Observation.completed -or $Observation.two_observations_match -isnot [bool] -or -not $Observation.two_observations_match -or $Observation.firewall_change_requested -isnot [bool] -or $Observation.firewall_change_requested -ne $false -or $Observation.ready_for_apply -isnot [bool] -or $Observation.ready_for_apply -ne $false){throw 'ufw_core_fresh_read_required'}
 if($Observation.assessment.explicit_local_outbound_baseline_present -isnot [bool] -or -not $Observation.assessment.explicit_local_outbound_baseline_present -or $Observation.assessment.profile_fields_compatible_for_later_review -isnot [bool] -or -not $Observation.assessment.profile_fields_compatible_for_later_review){throw 'ufw_core_profile_review_required'}
 $rows=$Observation.assessment.profiles;Assert-UfwCoreProfileRows $rows
 foreach($row in $rows){if($row.local_outbound -cne $row.effective_outbound){throw 'ufw_core_baseline_policy_mismatch'}}
 # Copy data; never hold mutable references to a caller's snapshot.
 $entries=@(foreach($row in @($rows|Sort-Object name)){[pscustomobject][ordered]@{name=$row.name;before=(ConvertFrom-Json -InputObject (Get-UfwCoreJson $row));intent=$false;restored=$false}})
 return [pscustomobject][ordered]@{schema='ufw-profile-recovery-draft-01';scope='profile_outbound_only';phase='prepared';entries=$entries;execution_authorized=$false}
}
function Invoke-UfwInstallerPreflightReadOnly {
 $r=[ordered]@{schema='ufw-minimal-installer-preflight-01';completed=$false;code='';profile_observation=$null;baseline_draft_constructible=$false;pending_components=@('explicit_session_consent','protected_transaction_journal','rule_ownership_and_effective_policy','SSTP_transport_and_reconnect','native_recovery_executor');profile_write_requested=$false;legacy_journal_imported=$false;ready_for_apply=$false;no_leak_certified=$false}
 try{
  $r.profile_observation=Invoke-UfwProfilePreflightReadOnly
  if(-not $r.profile_observation.completed){$r.code='ufw_core_reader_not_completed';return [pscustomobject]$r}
  $draft=New-UfwProfileRecoveryDraft $r.profile_observation
  $r.baseline_draft_constructible=$true;$r.completed=$true;$r.code='ufw_core_profile_stage_only_no_apply';$draft=$null
 }catch{
  $m=[string]$_.Exception.GetBaseException().Message
  if($m -cmatch '^ufw_core_[a-z_0-9]{1,100}$'){$r.code=$m}else{$r.code='ufw_core_profile_stage_unavailable'}
 }
 return [pscustomobject]$r
}
function Assert-UfwRecoveryDraft($Session){
 if($Session.schema -cne 'ufw-profile-recovery-draft-01' -or $Session.scope -cne 'profile_outbound_only' -or $Session.phase -cnotin @('prepared','arming','armed','restoring','restored') -or $Session.execution_authorized -isnot [bool] -or $Session.execution_authorized -ne $false){throw 'ufw_core_recovery_session_shape'}
 if($Session.entries -isnot [array] -or $Session.entries.Count -ne 3){throw 'ufw_core_recovery_entry_coverage'}
 $rows=@();$seen=@{}
 foreach($entry in $Session.entries){
  if($entry.name -isnot [string] -or $seen.ContainsKey($entry.name) -or $entry.name -cne $entry.before.name -or $entry.intent -isnot [bool] -or $entry.restored -isnot [bool]){throw 'ufw_core_recovery_entry_shape'}
  if(($entry.restored -and -not $entry.intent) -or ($Session.phase -ceq 'restored' -and $entry.intent -and -not $entry.restored)){throw 'ufw_core_recovery_entry_shape'}
  $seen[$entry.name]=$true;$rows+=,$entry.before
 }
 Assert-UfwCoreProfileRows $rows
 foreach($row in $rows){if($row.local_outbound -cne $row.effective_outbound){throw 'ufw_core_baseline_policy_mismatch'}}
}
function Get-UfwExpectedBlockedImage($Before){
 $copy=ConvertFrom-Json -InputObject (Get-UfwCoreJson $Before);$copy.local_outbound='Block';$copy.effective_outbound='Block';return $copy
}
function Assert-UfwRecoveryImages($Session,$Rows){
 Assert-UfwCoreProfileRows $Rows
 foreach($entry in $Session.entries){
  $current=@($Rows|Where-Object{$_.name -ceq $entry.name})[0]
  $isBaseline=(Get-UfwCoreJson $current) -ceq (Get-UfwCoreJson $entry.before)
  if(-not $entry.intent -or $entry.restored -or $Session.phase -ceq 'restored'){
   if(-not $isBaseline){throw 'ufw_core_untouched_or_restored_profile_drift'}
  }elseif(-not $isBaseline -and (Get-UfwCoreJson $current) -cne (Get-UfwCoreJson (Get-UfwExpectedBlockedImage $entry.before))){throw 'ufw_core_profile_image_drift'}
 }
}
function Invoke-UfwProfileRecoveryCallbacks($Session,$Ops){
 # PRIVATE callback engine: tests use memory-only adapters. NO native writer provided.
 # A draft is NOT execution consent; this function is not exposed by the public entry.
 Assert-UfwRecoveryDraft $Session
 foreach($key in @('ReadProfiles','Save','WriteOutbound')){if(-not $Ops.ContainsKey($key) -or $Ops[$key] -isnot [scriptblock]){throw 'ufw_core_recovery_adapter_missing'}}
 $rows=@(& $Ops.ReadProfiles);Assert-UfwRecoveryImages $Session $rows
 if($Session.phase -ceq 'restored'){return [pscustomobject]@{model_recovery_completed=$true;current_profile_images_match=$true;profile_writes=0;original_restore_verified=$false;reboot_qualified=$false;ready_for_apply=$false}}
 $Session.phase='restoring';& $Ops.Save $Session|Out-Null;$writes=0
 for($i=$Session.entries.Count-1;$i -ge 0;$i--){
  $entry=$Session.entries[$i];if(-not $entry.intent){continue}
  $rows=@(& $Ops.ReadProfiles);Assert-UfwRecoveryImages $Session $rows
  $current=@($rows|Where-Object{$_.name -ceq $entry.name})[0]
  if((Get-UfwCoreJson $current) -cne (Get-UfwCoreJson $entry.before)){
   # Save acknowledgement of recovery phase before the next write; reread narrows races.
   & $Ops.Save $Session|Out-Null
   $again=@(& $Ops.ReadProfiles);Assert-UfwRecoveryImages $Session $again
   if((Get-UfwCoreJson $again) -cne (Get-UfwCoreJson $rows)){throw 'ufw_core_concurrent_profile_change'}
   & $Ops.WriteOutbound $entry.name $entry.before.local_outbound|Out-Null;$writes++
   $after=@(& $Ops.ReadProfiles);Assert-UfwRecoveryImages $Session $after
   $actual=@($after|Where-Object{$_.name -ceq $entry.name})[0]
   if((Get-UfwCoreJson $actual) -cne (Get-UfwCoreJson $entry.before)){throw 'ufw_core_profile_restore_readback'}
  }
  $entry.restored=$true;& $Ops.Save $Session|Out-Null
 }
 $final=@(& $Ops.ReadProfiles);Assert-UfwCoreProfileRows $final
 foreach($entry in $Session.entries){$actual=@($final|Where-Object{$_.name -ceq $entry.name})[0];if((Get-UfwCoreJson $actual) -cne (Get-UfwCoreJson $entry.before)){throw 'ufw_core_final_profile_mismatch'}}
 $Session.phase='restored';& $Ops.Save $Session|Out-Null
 return [pscustomobject]@{model_recovery_completed=$true;current_profile_images_match=$true;profile_writes=$writes;original_restore_verified=$false;reboot_qualified=$false;ready_for_apply=$false}
}
Export-ModuleMember -Function Invoke-UfwInstallerPreflightReadOnly
