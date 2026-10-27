# Windows-only storage qualification. Fixtures NEVER use the legacy journal root.
Set-StrictMode -Version 2.0
function Assert-ExitPrivateAcl([string]$Path,[bool]$Directory){
 UAssertPath $Path
 $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
 if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544'){throw 'exit_qualification_private_owner_or_inheritance'}
 $seen=@{}
 foreach($rule in @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))){
  $sid=$rule.IdentityReference.Value
  if($sid -cnotin @('S-1-5-32-544','S-1-5-18') -or $seen.ContainsKey($sid) -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl' -or $rule.IsInherited -or [string]$rule.PropagationFlags -cne 'None'){throw 'exit_qualification_private_access_rule'}
  $inherit=if($Directory){'ContainerInherit, ObjectInherit'}else{'None'}
  if([string]$rule.InheritanceFlags -cne $inherit){throw 'exit_qualification_private_inheritance_flags'}
  $seen[$sid]=$true
 }
 if($seen.Count -ne 2){throw 'exit_qualification_private_access_incomplete'}
}
function New-ExitQualificationDirectory{
 $parent=[Environment]::GetFolderPath('CommonApplicationData');UAssertPath $parent
 $path=Join-Path $parent ('UnifiedFW-ExitQualification-'+[guid]::NewGuid().ToString('N'));UAssertPath $path
 if([IO.Directory]::Exists($path) -or [IO.File]::Exists($path)){throw 'exit_qualification_path_collision'}
 $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false)
 $admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544');$acl.SetOwner($admins)
 foreach($sidText in @('S-1-5-32-544','S-1-5-18')){$sid=New-Object Security.Principal.SecurityIdentifier($sidText);$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($rule)}
 $dir=New-Object IO.DirectoryInfo($path);$dir.Create($acl)
 return $path
}
function New-ExitQualificationFixture{
 return [pscustomobject][ordered]@{schema='unified-isolation-session-1';id=('b'*32);owner=('a'*32);phase='restored';entries=@();foreign=@();profiles=@(foreach($n in @('Domain','Private','Public')){[pscustomobject]@{name=$n;intent=$true;restored=$true;before=[pscustomobject]@{name=$n;default_outbound='NotConfigured'}}})}
}
function Get-ExitQualificationOps{
 return @{JournalDigest={param($s)IsoExitJournalDigest $s};ControllerCount={return [int]0};Read={param($n)throw 'exit_qualification_fixture_has_no_rules'};ProfileRead={param($n)[pscustomobject][ordered]@{name=$n;default_outbound='Allow';enabled='True';allow_local_rules='True'}};ProfileEffectiveRead={param($n)[pscustomobject][ordered]@{name=$n;default_outbound='Allow';enabled='True';allow_local_rules='True'}};ReadRecord={param($s)IsoExitReadRecord $s};WriteRecord={param($s,$r)IsoExitWriteRecord $s $r}}
}
function Invoke-ExitStorageQualification{
 $r=[ordered]@{completed=$false;code='';directory_acl_verified=$false;fixture_journal_acl_verified=$false;fixture_record_acl_verified=$false;exclusive_lock_verified=$false;create_new_no_overwrite_verified=$false;record_roundtrip_verified=$false;fixture_journal_preserved=$false;fixture_record_has_no_isolation_authority=$false;cleanup_completed=$false;scope='separate_disposable_ProgramData_fixture_only_not_live_firewall_evidence'}
 $testRoot=$null;$priorRoot=$null;$hadRoot=$false;$held=$null
 $old=Get-Variable IsoRoot -Scope Script -ErrorAction SilentlyContinue;if($null -ne $old){$priorRoot=$old.Value;$hadRoot=$true}
 try{
  if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'exit_qualification_windows_required'}
  $testRoot=New-ExitQualificationDirectory
  Assert-ExitPrivateAcl $testRoot $true;$r.directory_acl_verified=$true
  $script:IsoRoot=$testRoot;$fixture=New-ExitQualificationFixture
  # Only this synthetic fixture is passed to USave; real session.json is never a target.
  USave $testRoot $fixture
  $fixturePath=Join-Path $testRoot 'session.json';Assert-ExitPrivateAcl $fixturePath $false;$r.fixture_journal_acl_verified=$true
  $before=(Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash
  $ops=Get-ExitQualificationOps;$preview=IsoExitBuildPreview $fixture $ops
  $recordResult=IsoExitRecordNormalMode $fixture $ops 'ACKNOWLEDGE EXISTING NORMAL NETWORK MODE' $preview.digest
  $recordPath=IsoExitRecordPath $fixture;Assert-ExitPrivateAcl $recordPath $false;$r.fixture_record_acl_verified=$true
  $record=IsoExitReadRecord $fixture
  if(-not $recordResult.normal_mode_acknowledgment_recorded -or $record.review_digest -cne $preview.digest){throw 'exit_qualification_record_roundtrip'}
  $r.record_roundtrip_verified=$true
  if($record.authorizes_isolation -isnot [bool] -or $record.authorizes_isolation -ne $false -or $record.original_restore_verified -isnot [bool] -or $record.original_restore_verified -ne $false){throw 'exit_qualification_unexpected_authority'}
  $r.fixture_record_has_no_isolation_authority=$true
  $recordHash=(Get-FileHash -LiteralPath $recordPath -Algorithm SHA256).Hash;$refused=$false
  try{IsoExitWriteRecord $fixture $record}catch{if($_.Exception.GetBaseException() -is [IO.IOException]){$refused=$true}else{throw}}
  if(-not $refused -or (Get-FileHash -LiteralPath $recordPath -Algorithm SHA256).Hash -cne $recordHash){throw 'exit_qualification_overwrite_not_refused'}
  $r.create_new_no_overwrite_verified=$true
  $lockPath=Join-Path $testRoot 'operation.lock';$held=UOpenPrivateFile $lockPath ([IO.FileMode]::OpenOrCreate);$other=$null;$refused=$false
  try{$other=UOpenPrivateFile $lockPath ([IO.FileMode]::OpenOrCreate)}catch{if($_.Exception.GetBaseException() -is [IO.IOException]){$refused=$true}else{throw}}finally{if($null -ne $other){$other.Dispose()}}
  if(-not $refused){throw 'exit_qualification_exclusive_lock_not_enforced'}
  $held.Dispose();$held=$null;Assert-ExitPrivateAcl $lockPath $false;$r.exclusive_lock_verified=$true
  if((Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash -cne $before){throw 'exit_qualification_fixture_journal_changed'}
  $r.fixture_journal_preserved=$true;$r.completed=$true;$r.code='exit_storage_qualification_passed'
 }catch{
  $m=[string]$_.Exception.GetBaseException().Message
  if($m -cmatch '^(exit_qualification|normal_exit|session)_[a-z_0-9]{1,100}$'){$r.code=$m}else{$r.code='exit_qualification_failed'}
 }finally{
  if($null -ne $held){$held.Dispose()}
  if($null -ne $testRoot){
   try{
    # No recursive deletion: delete ONLY known fixture leaf names under this unique root.
    $base=[Environment]::GetFolderPath('CommonApplicationData')
    if([IO.Path]::GetDirectoryName($testRoot) -cne $base -or [IO.Path]::GetFileName($testRoot) -cnotmatch '^UnifiedFW-ExitQualification-[a-f0-9]{32}$'){throw 'cleanup_root_invalid'}
    if(-not $r.directory_acl_verified){throw 'cleanup_unverified_root'}
    UAssertPath $testRoot
    $allowed=@('session.json','operation.lock',('normal-mode-exit-'+('b'*32)+'.json'))
    $children=@(Get-ChildItem -LiteralPath $testRoot -Force -ErrorAction Stop)
    foreach($child in $children){if($child.PSIsContainer -or $child.Name -cnotin $allowed){throw 'cleanup_unexpected_child'};UAssertPath $child.FullName}
    foreach($child in $children){[IO.File]::Delete($child.FullName)}
    [IO.Directory]::Delete($testRoot,$false);$r.cleanup_completed=$true
   }catch{$r.completed=$false;if(-not $r.code -or $r.code -ceq 'exit_storage_qualification_passed'){$r.code='exit_qualification_cleanup_requires_review'}}
  }
  if($hadRoot){$script:IsoRoot=$priorRoot}else{Remove-Variable IsoRoot -Scope Script -ErrorAction SilentlyContinue}
 }
 return [pscustomobject]$r
}
function Read-ExitConsentAnswer($Challenge){Read-Host ('Type exactly "'+$Challenge+'" to create ONLY the separate normal-mode record, or Enter to cancel')}
function Invoke-ExitReviewAndConsent{
 $r=[ordered]@{completed=$false;stage='live_review';code='';live_review_passed=$false;known_owned_rules_absent_count=0;known_foreign_images_matched_count=0;profile_count=0;confirmation_received=$false;record_operation_attempted=$false;normal_mode_acknowledgment_recorded=$false;record_created_this_call=$false;record_matches_current_snapshot=$false;legacy_journal_rewritten=$false;firewall_changed=$false;ready_for_apply=$false;original_restore_verified=$false;reboot_qualified=$false;no_leak_certified=$false}
 $preview=$null;$answer=$null;$challenge=$null
 try{
  $preview=Invoke-IsoNormalExitOperation -Operation Review
  $r.live_review_passed=$true;$r.known_owned_rules_absent_count=$preview.review.owned_rules_absent;$r.known_foreign_images_matched_count=$preview.review.foreign_images_matched;$r.profile_count=@($preview.review.profiles).Count
  Write-Host 'Current local/effective outbound profiles must already be Allow, with firewall enabled.'
  $preview.review.profiles|Format-Table name,legacy_outbound,current_local_outbound,current_effective_outbound,firewall_enabled -AutoSize|Out-Host
  Write-Host 'This records your existing normal networking choice. It does NOT restore the original baseline or authorize isolation.'
  Write-Host 'No firewall, VPN, DNS, route, rule or task changes will be requested. The old journal remains unchanged.'
  Write-Host 'Only a separate admin/SYSTEM-protected record will be created if confirmation and fresh checks succeed.'
  $r.stage='manual_consent';$challenge='RECORD NORMAL '+[guid]::NewGuid().ToString('N').Substring(0,12);$answer=Read-ExitConsentAnswer $challenge
  if($answer -isnot [string] -or $answer -cne $challenge){$r.completed=$true;$r.stage='completed';$r.code='exit_record_cancelled_no_live_record_write';return [pscustomobject]$r}
  $r.confirmation_received=$true;$r.stage='record_and_revalidation';$r.record_operation_attempted=$true
  $result=Invoke-IsoNormalExitOperation -Operation Record -Confirmation 'ACKNOWLEDGE EXISTING NORMAL NETWORK MODE' -ReviewDigest $preview.review_digest
  if(-not $result.normal_mode_acknowledgment_recorded -or -not $result.record_matches_current_snapshot -or $result.authorizes_isolation -or $result.original_restore_verified -or $result.ready_for_apply){throw 'exit_record_result_unexpected'}
  $r.normal_mode_acknowledgment_recorded=$true;$r.record_created_this_call=$result.created_this_call;$r.record_matches_current_snapshot=$true;$r.completed=$true;$r.stage='completed';$r.code='exit_record_acknowledged_no_isolation_authority'
 }catch{
  $m=[string]$_.Exception.GetBaseException().Message
  if($m -cmatch '^(normal_exit|iso|unsafe_journal|session|exit_record)_[a-z_0-9]{1,100}$'){$r.code=$m}else{$r.code='exit_record_review_unavailable'}
 }finally{$preview=$null;$answer=$null;$challenge=$null}
 return [pscustomobject]$r
}
