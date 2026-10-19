# Narrow recovery: no adoption, removal, activation, DNS, profile changes or reset.
Set-StrictMode -Version 2.0
$script:ResumeNativeError=$null
function ResumeOverlayPreparation {
 param([string]$Root,[ValidateSet('None','BeforeCreate','AfterCapture')][string]$Fault='None')
 $lock=OverlayOperationLock $Root
 try{
  $rec=OverlayLoad $Root;$s=$rec.state
  $alreadyPrepared=$s.phase -ceq 'prepared'
  if($s.phase -cnotin @('staging','prepared')){throw 'resume_requires_staging'}
  if($alreadyPrepared -and $null -ne $s.pending){throw 'resume_prepared_pending_conflict'}
  if($Fault -cne 'None' -and $s.scope -cne 'Fixture'){throw 'resume_fault_scope'}
  $complete=$null -eq $s.pending
  if(-not $complete){
   if($s.pending.index -ne 2 -or $s.pending.operation -cne 'create' -or $s.pending.target -ne $false){throw 'resume_pending_not_supported'}
  }
  # Bind all destination conditions to the originally recorded allowlist.
  $want4=ComplementAddresses @($s.allowed_ips) 32
  $want6=ComplementAddresses @($s.allowed_ips) 128
  if((IntervalSignature $s.objects[1].spec.remote) -cne (IntervalSignature $want4) -or (IntervalSignature $s.objects[2].spec.remote) -cne (IntervalSignature $want6)){throw 'resume_coverage_conflict'}
  $before=@()
  for($n=0;$n -lt 3;$n++){
   $o=$s.objects[$n];$actual=OverlayRead $o.spec.name
   if($n -eq 2 -and -not $complete){
    if($o.exists -or $o.enabled -or $null -ne $o.original){throw 'resume_v6_record_conflict'}
    if($null -ne $actual){throw 'resume_v6_exists_no_adoption'}
    continue
   }
   if(-not $o.exists -or $o.enabled -or $null -eq $o.original){throw 'resume_saved_state_conflict'}
   if($null -eq $actual -or (OverlayHash $actual.image) -cne (OverlayHash (OverlayExpected $o $false))){throw 'resume_owned_conflict'}
   AssertOverlaySemantic $o.spec $actual $false
   $before+=,(OverlayHash $actual.image)
  }
  if(-not $complete){
   $cidrs=IntervalsToCidrs @($s.objects[2].spec.remote)
   $s.objects[2].spec.remote=@($cidrs)
   # Preserve pending=create and its original index; durable before the new create.
   $rec=OverlaySave $Root $rec;$o=$rec.state.objects[2]
   if($Fault -ceq 'BeforeCreate'){[Environment]::Exit(73)}
   if($null -ne (OverlayRead $o.spec.name)){throw 'resume_v6_exists_no_adoption'}
   try{
    New-NetFirewallRule -PolicyStore PersistentStore -Name $o.spec.name -DisplayName $o.spec.name -Description 'Destination overlay test build; not an independent kill switch' -Group $o.spec.group -Direction Outbound -Action Block -Profile Any -Enabled False -Program $o.spec.program -Service Any -Protocol Any -LocalAddress Any -RemoteAddress $o.spec.remote -InterfaceAlias Any -InterfaceType $o.spec.interface_type -EdgeTraversalPolicy Block -ErrorAction Stop|Out-Null
   }catch{
    $codes=@();$ex=$_.Exception
    while($null -ne $ex){
     $row=[ordered]@{type=$ex.GetType().Name;hresult=[int]$ex.HResult}
     foreach($field in @('StatusCode','NativeErrorCode')){if($null -ne $ex.PSObject.Properties[$field]){try{$row[$field]=[int]$ex.$field}catch{}}}
     $codes+=,[pscustomobject]$row;$ex=$ex.InnerException
    }
    $script:ResumeNativeError=@($codes)
    throw 'resume_v6_create_failed'
   }
   $read=OverlayRead $o.spec.name;AssertOverlaySemantic $o.spec $read $false
   if($read.image.rule.Enabled -cne '2'){throw 'resume_v6_not_disabled'}
   $o.original=$read.image;$o.exists=$true;$rec.state.pending=$null
   $rec=OverlaySave $Root $rec
   if($Fault -ceq 'AfterCapture'){[Environment]::Exit(73)}
  }
  # Recheck every recorded raw field/filter before declaring preparation complete.
  for($n=0;$n -lt 3;$n++){
   $o=$rec.state.objects[$n];$r=OverlayRead $o.spec.name
   if(-not $o.exists -or $o.enabled -or $null -eq $r -or (OverlayHash $r.image) -cne (OverlayHash (OverlayExpected $o $false))){throw 'resume_final_audit_failed'}
   AssertOverlaySemantic $o.spec $r $false
   if($n -lt 2 -and (OverlayHash $r.image) -cne $before[$n]){throw 'resume_prior_rule_changed'}
  }
  if(-not $alreadyPrepared){$rec.state.phase='prepared';$rec=OverlaySave $Root $rec}
  [pscustomobject]@{schema='sstp-v6-resume-result-1';phase='prepared';rules=3;all_rules_disabled=$true;guard_and_v4_unchanged=$true;coverage_unchanged=$true;automatic_enable=$false;existing_kill_switch_changed=$false}
 }finally{$lock.Dispose()}
}
