# P11 qualification-only adapter: Domain INACTIVE, original stored NotConfigured.
# Cannot target an active profile or any other profile; NOT a production coordinator.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../sstp-integrated-transaction/Engine.ps1')
function ProfileClone($Object){$Object|ConvertTo-Json -Depth 24 -Compress|ConvertFrom-Json}
function AssertInactiveDomain {
 $fw=New-Object -ComObject HNetCfg.FwPolicy2
 try{$mask=[int]$fw.CurrentProfileTypes}finally{if([Runtime.InteropServices.Marshal]::IsComObject($fw)){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($fw)}}
 if($mask -lt 1 -or $mask -gt 7 -or ($mask -band 1) -ne 0){throw 'profile_domain_active_or_unknown'}
 $net=@(Get-NetConnectionProfile -ErrorAction Stop)
 if($net.Count -lt 1 -or @($net|Where-Object{[string]$_.NetworkCategory -cnotin @('Public','Private')}).Count -ne 0){throw 'profile_network_category_unknown'}
}
function ReadProfileImages {
 $out=@();foreach($store in @('PersistentStore','ActiveStore')){
  $rows=@(Get-NetFirewallProfile -PolicyStore $store -ErrorAction Stop|Sort-Object Name)
  if($rows.Count -ne 3){throw 'profile_inventory_count'}
  foreach($p in $rows){$out+=,[pscustomobject][ordered]@{store=$store;name=[string]$p.Name;image=(InventoryRaw $p)}}
 };return ,$out
}
function AssertProfileImages($Images){
 if($Images -isnot [array] -or $Images.Count -ne 6){throw 'profile_images_schema'}
 $seen=@{};foreach($p in $Images){
  if((($p.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'image,name,store' -or $p.store -cnotin @('PersistentStore','ActiveStore') -or $p.name -cnotin @('Domain','Private','Public')){throw 'profile_images_schema'}
  $key=$p.store+'/'+$p.name;if($seen.ContainsKey($key)){throw 'profile_images_schema'};$seen[$key]=$true;AssertInventoryRaw $p.image
  if($null -eq $p.image.PSObject.Properties['DefaultOutboundAction']){throw 'profile_action_field'}
 }
}
function TestProfileImagesEqual($Before,$After){
 AssertProfileImages $Before;AssertProfileImages $After
 foreach($p in $Before){
  $other=@($After|Where-Object{$_.store -ceq $p.store -and $_.name -ceq $p.name})
  if($other.Count -ne 1 -or (RawDifferenceFields $p.image $other[0].image).Count -ne 0){return $false}
 };return $true
}
function ProfileExpected($Original,[bool]$Blocked){
 AssertProfileImages $Original;$out=@()
 # Clone EACH raw image, never a root array through the PowerShell pipeline.
 foreach($p in $Original){
  $image=ProfileClone $p.image
  if($Blocked -and $p.name -ceq 'Domain'){$image.DefaultOutboundAction='4'}
  $out+=,[pscustomobject][ordered]@{store=$p.store;name=$p.name;image=$image}
 };AssertProfileImages $out;return ,$out
}
function AssertProfileState($S){
 if($null -eq $S -or (($S.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'blocked,original,pending,phase,restore_probe,schema,target' -or $S.schema -cne 'sstp-profile-roundtrip-1' -or $S.phase -cnotin @('prepared','blocking','blocked','restoring','restored') -or $S.blocked -isnot [bool] -or $S.pending -isnot [bool] -or $S.target -isnot [bool] -or $S.restore_probe -isnot [bool]){throw 'profile_state_schema'}
 AssertProfileImages $S.original
 $stored=@($S.original|Where-Object{$_.name -ceq 'Domain' -and $_.store -ceq 'PersistentStore'})
 if($stored[0].image.DefaultOutboundAction -cne '0'){throw 'profile_original_not_notconfigured'}
 foreach($p in $S.original){if($p.name -ceq 'Domain' -and ($p.image.Enabled -cne '1' -or $p.image.DefaultOutboundAction -cnotin @('0','2'))){throw 'profile_original_effective_policy'}}
 if(($S.phase -ceq 'prepared' -and ($S.blocked -or $S.pending -or $S.target)) -or ($S.phase -ceq 'blocked' -and (-not $S.blocked -or $S.pending -or -not $S.target)) -or ($S.phase -ceq 'restored' -and ($S.blocked -or $S.pending -or $S.target)) -or ($S.phase -ceq 'blocking' -and -not $S.target) -or ($S.phase -ceq 'restoring' -and $S.target) -or ($S.phase -cne 'prepared' -and -not $S.restore_probe)){throw 'profile_state_frontier'}
}
function ReadProfileRecord([string]$Root){$j=ReadJournal $Root;if($j.status -cne 'valid'){throw 'profile_journal_required'};AssertProfileState $j.record.state;return $j.record}
function CompareProfileObserved($S,$Actual){
 AssertProfileState $S;AssertProfileImages $Actual
 $normal=ProfileExpected $S.original $S.blocked
 if((TestProfileImagesEqual $Actual $normal)){return [pscustomobject]@{settled=$true;blocked=$S.blocked}}
 if(-not $S.pending){
  $deltaCount=0
  foreach($p in $Actual){
   $matches=@($normal|Where-Object{$_.name -ceq $p.name -and $_.store -ceq $p.store})
   if($matches.Count -eq 1){foreach($f in (RawDifferenceFields $matches[0].image $p.image)){
    if($f -cmatch '^[A-Za-z][A-Za-z0-9_]{0,80}$'){Write-Host ('profile_delta_'+$p.store+'_'+$p.name+'_'+$f);$deltaCount++}
   }}
  }
  if($deltaCount -eq 0){Write-Host 'profile_serialization_shape_mismatch'}
  throw 'profile_external_conflict'
 }
 $next=ProfileExpected $S.original $S.target
 if((TestProfileImagesEqual $Actual $next)){return [pscustomobject]@{settled=$true;blocked=$S.target}}
 # Only known before/after values in the TWO Domain action fields may be temporarily mixed.
 foreach($p in $Actual){
  $b=@($normal|Where-Object{$_.name -ceq $p.name -and $_.store -ceq $p.store})[0]
  $a=@($next|Where-Object{$_.name -ceq $p.name -and $_.store -ceq $p.store})[0]
  if((RawDifferenceFields $p.image $b.image).Count -ne 0 -and (RawDifferenceFields $p.image $a.image).Count -ne 0){throw 'profile_external_conflict'}
 };return [pscustomobject]@{settled=$false;blocked=$false}
}
function ReadProfileFrontier($S,[ValidateSet('Either','Blocked','Original')][string]$Require='Either'){
 for($i=0;$i -lt 12;$i++){
  AssertInactiveDomain;$v=CompareProfileObserved $S (ReadProfileImages)
  if($v.settled -and ($Require -ceq 'Either' -or ($Require -ceq 'Blocked' -and $v.blocked) -or ($Require -ceq 'Original' -and -not $v.blocked))){return $v}
  Start-Sleep -Milliseconds 250
 };throw 'profile_effective_not_settled'
}
function GetStoredDomain {
 $p=@(Get-NetFirewallProfile -PolicyStore PersistentStore -Name Domain -ErrorAction Stop)
 if($p.Count -ne 1 -or [string]$p[0].Name -cne 'Domain'){throw 'profile_target_identity'};return $p[0]
}
function InitializeProfileRoundtrip([string]$Root){
 $lock=OpenIntegratedLock $Root
 try{
  $j=ReadJournal $Root;if($j.status -cne 'absent'){throw 'profile_existing_journal'}
  AssertInactiveDomain;$one=ReadProfileImages;$two=ReadProfileImages
  if(-not (TestProfileImagesEqual $one $two)){throw 'profile_unstable_original'}
  $s=[pscustomobject][ordered]@{schema='sstp-profile-roundtrip-1';phase='prepared';blocked=$false;pending=$false;target=$false;restore_probe=$false;original=$two}
  AssertProfileState $s;$record=WriteJournal $Root -1 $s
  $p=GetStoredDomain
  # Native no-op FIRST. If exact NotConfigured cannot be set/read back, never write Block.
  if([string]$p.DefaultOutboundAction -cne 'NotConfigured' -or [int]$p.DefaultOutboundAction -ne 0){throw 'profile_enum_contract'}
  ReadProfileFrontier $s|Out-Null;Write-Host 'profile_probe_before_noop_verified';AssertInactiveDomain
  Set-NetFirewallProfile -InputObject $p -DefaultOutboundAction NotConfigured -ErrorAction Stop|Out-Null
  Write-Host 'profile_probe_noop_setter_returned';ReadProfileFrontier $s Original|Out-Null
  $s.restore_probe=$true;WriteJournal $Root $record.revision $s|Out-Null
  return [pscustomobject]@{phase='prepared';native_notconfigured_noop=$true}
 }finally{$lock.Dispose()}
}
function InvokeProfileRoundtrip {
 param([string]$Root,[ValidateSet('Block','Restore')][string]$Action,[ValidateSet('None','BeforeMutation','AfterMutation')][string]$Fault='None')
 $lock=OpenIntegratedLock $Root
 try{
  $record=ReadProfileRecord $Root;$s=$record.state
  if(-not $s.restore_probe){throw 'profile_restore_probe_required'}
  $v=ReadProfileFrontier $s
  if($Action -ceq 'Block' -and $s.phase -cin @('restoring','restored')){throw 'profile_restore_started'}
  if($s.pending){$s.blocked=$v.blocked;$s.pending=$false;$record=WriteJournal $Root $record.revision $s;$s=$record.state}
  $want=$Action -ceq 'Block'
  if(($want -and $s.phase -ceq 'blocked') -or (-not $want -and $s.phase -ceq 'restored')){return [pscustomobject]@{phase=$s.phase}}
  $s.target=$want;$s.phase='restoring';if($want){$s.phase='blocking'}
  if($s.blocked -ne $want){
   $s.pending=$true;$record=WriteJournal $Root $record.revision $s;$s=$record.state
   if($Fault -ceq 'BeforeMutation'){[Environment]::Exit(73)}
   $v=ReadProfileFrontier $s
   if($v.blocked -ne $s.blocked){throw 'profile_external_conflict'}
   $p=GetStoredDomain;AssertInactiveDomain
   $value='NotConfigured';if($want){$value='Block'}
   # This adapter writes ONE property of ONE freshly acquired PersistentStore profile.
   Set-NetFirewallProfile -InputObject $p -DefaultOutboundAction $value -ErrorAction Stop|Out-Null
   if($Fault -ceq 'AfterMutation'){[Environment]::Exit(73)}
   $require='Original';if($want){$require='Blocked'}
   ReadProfileFrontier $s $require|Out-Null
   $s.blocked=$want;$s.pending=$false
  }
  $s.phase='restored';if($want){$s.phase='blocked'}
  WriteJournal $Root $record.revision $s|Out-Null
  return [pscustomobject]@{phase=$s.phase}
 }finally{$lock.Dispose()}
}
