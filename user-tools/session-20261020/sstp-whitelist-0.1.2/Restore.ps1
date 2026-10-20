# Monotonic exact cleanup. Never creates/enables/adopts rules, including on recovery.
Set-StrictMode -Version 2.0
function AppCleanupRecord([string]$Root){
 $r=OverlayLoad $Root;$s=$r.state;$p=$s.pending
 if($null -ne $p -and $p.operation -ceq 'create'){throw 'app_uncaptured_create_stop'}
 for($i=0;$i -lt 3;$i++){
  $o=$s.objects[$i];$read=OverlayRead $o.spec.name
  if(-not $o.exists -and $o.enabled){throw 'app_absent_enabled'}
  if($null -ne $p -and $p.index -eq $i){
   if($p.operation -ceq 'delete' -and -not $o.enabled -and $null -eq $read){$o.exists=$false;continue}
   if($p.operation -ceq 'set' -and $null -ne $read -and (OverlayImageEqual $read.image (OverlayExpected $o ([bool]$p.target)))){$o.enabled=[bool]$p.target;$null=AssertOverlayActiveImage $o ([bool]$o.enabled);continue}
  }
  if(-not $o.exists){if($null -ne $read){throw 'app_rule_collision'};continue}
  if($null -eq $read -or -not (OverlayImageEqual $read.image (OverlayExpected $o ([bool]$o.enabled)))){throw 'app_owned_image_conflict'}
  $null=AssertOverlayActiveImage $o ([bool]$o.enabled)
 }
 $s.pending=$null;return $r
}
function RemoveAppOverlay([string]$Root){
 $lock=OverlayOperationLock $Root
 try{
  $one=AppCleanupRecord $Root;Start-Sleep -Milliseconds 400;$r=AppCleanupRecord $Root
  if($one.revision -ne $r.revision -or (OverlayHash $one.state) -cne (OverlayHash $r.state)){throw 'app_cleanup_unstable'}
  $r.state.phase='disabling';$r=OverlaySave $Root $r
  for($i=0;$i -lt 3;$i++){if($r.state.objects[$i].exists){$r=SetOverlayObject $Root $r $i $false}}
  $r.state.phase='removing';$r=OverlaySave $Root $r
  for($i=0;$i -lt 3;$i++){
   $o=$r.state.objects[$i];if(-not $o.exists){continue}
   $r.state.pending=[pscustomobject]@{index=$i;operation='delete';target=$false};$r=OverlaySave $Root $r;$o=$r.state.objects[$i]
   $read=OverlayRead $o.spec.name
   if($null -eq $read -or -not (OverlayImageEqual $read.image (OverlayExpected $o $false))){throw 'app_owned_image_conflict'}
   $null=AssertOverlayActiveImage $o $false
   Remove-NetFirewallRule -InputObject $read.rule -ErrorAction Stop
   if($null -ne (OverlayRead $o.spec.name)){throw 'app_delete_readback'}
   $o.exists=$false;$r.state.pending=$null;$r=OverlaySave $Root $r
  }
  foreach($o in $r.state.objects){foreach($store in @('PersistentStore','ActiveStore')){if($null -ne (OverlayRead $o.spec.name $store)){throw 'app_rule_remains'}}}
  $r.state.phase='removed';$null=OverlaySave $Root $r
 }finally{$lock.Dispose()}
}
