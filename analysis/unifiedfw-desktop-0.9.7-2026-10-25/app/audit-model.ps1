# Fixed audit-policy transaction. Callbacks are mockable; no automatic disable/restore or timeout.
function Audit-Flags([int]$Value){if($Value -eq 0){return 4};if($Value -notin @(1,2,3,4)){throw 'unsupported_audit_flags'};return $Value}
function Read-AuditReceipt([string]$Root){
 $p=Join-Path $Root 'audit-state.json';UAssertPath $p;if(-not [IO.File]::Exists($p)){return $null}
 if((Get-Item -LiteralPath $p).Length -gt 16384){throw 'audit_receipt_size'}
 $v=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($p))
 if((@($v.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'after,before,created_utc,id,phase,schema' -or $v.schema -cne 'unified-wfp-audit-096' -or $v.id -cnotmatch '^[a-f0-9]{32}$' -or $v.phase -cnotin @('prepared','enabled','restoring','restored')){throw 'audit_receipt_invalid'}
 if($v.before -isnot [int] -and $v.before -isnot [long]){throw 'audit_receipt_flags'}
 if($v.after -isnot [int] -and $v.after -isnot [long]){throw 'audit_receipt_flags'}
 if($v.before -notin @(1,4) -or $v.after -ne (($v.before -band 1) -bor 2)){throw 'audit_receipt_scope'}
 $t=[DateTimeOffset]::Parse([string]$v.created_utc);return $v
}
function Save-AuditReceipt([string]$Root,$Value){
 $p=Join-Path $Root 'audit-state.json';UAssertPath $p;$tmp=Join-Path $Root ('next-'+[guid]::NewGuid().ToString('N')+'.tmp')
 try{UWritePrivateBytes $tmp ([Text.Encoding]::UTF8.GetBytes((UJson $Value)));if([IO.File]::Exists($p)){[IO.File]::Replace($tmp,$p,[Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($tmp,$p)}}finally{if([IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
}
function Invoke-AuditPolicy([string]$Root,[string]$Action,[string]$Confirmation,[scriptblock]$Read,[scriptblock]$Write){
 if($Action -cnotin @('status','enable','restore')){throw 'audit_action'}
 if($Action -ceq 'enable' -and $Confirmation -cne 'ENABLE BLOCKED CONNECTION LOGGING'){throw 'audit_enable_consent_required'}
 if($Action -ceq 'restore' -and $Confirmation -cne 'RESTORE PREVIOUS AUDIT POLICY'){throw 'audit_restore_consent_required'}
 $receipt=Read-AuditReceipt $Root;$now=Audit-Flags (& $Read);$changed=$false
 if($Action -ceq 'enable'){
  if($null -ne $receipt -and $receipt.phase -cne 'restored'){throw 'audit_existing_receipt_use_status_and_restore_no_blind_retry'}
  if(($now -band 2) -eq 0){
   if($null -ne $receipt){UWritePrivateBytes (Join-Path $Root ('restored-'+$receipt.id+'.json')) ([IO.File]::ReadAllBytes((Join-Path $Root 'audit-state.json')))}
   $receipt=[pscustomobject][ordered]@{schema='unified-wfp-audit-096';id=[guid]::NewGuid().ToString('N');before=$now;after=(($now -band 1) -bor 2);phase='prepared';created_utc=[DateTime]::UtcNow.ToString('o')};Save-AuditReceipt $Root $receipt
   if((Audit-Flags (& $Read)) -ne $now){throw 'audit_changed_before_enable'}
   & $Write ([int]$receipt.after)|Out-Null;$changed=$true;$now=Audit-Flags (& $Read)
   if($now -ne $receipt.after){throw 'audit_enable_readback_conflict_no_retry'}
   $receipt.phase='enabled';Save-AuditReceipt $Root $receipt
  }
 }elseif($Action -ceq 'restore'){
  if($null -eq $receipt){throw 'audit_no_owned_receipt_nothing_disabled'}
  if($receipt.phase -cne 'restored'){
   if($now -ne $receipt.before -and $now -ne $receipt.after){throw 'audit_policy_drift_restore_refused'}
   if($now -ne $receipt.before){
    $receipt.phase='restoring';Save-AuditReceipt $Root $receipt
    if((Audit-Flags (& $Read)) -ne $receipt.after){throw 'audit_changed_before_restore'}
    & $Write ([int]$receipt.before)|Out-Null;$changed=$true;$now=Audit-Flags (& $Read)
    if($now -ne $receipt.before){throw 'audit_restore_readback_conflict'}
   }
   $receipt.phase='restored';Save-AuditReceipt $Root $receipt
  }
 }
 return [pscustomobject]@{schema='unified-audit-status-096';failure_enabled=(($now -band 2) -ne 0);success_enabled=(($now -band 1) -ne 0);current_flags=$now;changed=$changed;receipt=$receipt;checked_utc=[DateTime]::UtcNow.ToString('o');system_wide=$true;automatic_restore=$false;coverage_verified=$false;firewall_changed=$false;hosts_changed=$false;note='Subcategory only; persistent until explicitly restored. GPO/per-user policy/log limits may affect coverage. External same-value changes/races cannot be detected.'}
}
