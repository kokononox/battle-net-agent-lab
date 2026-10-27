param([string]$Root='/data/ufd-normal-exit-runner-v01/package/NORMAL-EXIT-REVIEW-01')
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
foreach($n in @('session-core.ps1','native.ps1','isolation-core.ps1','isolation-native.ps1','normal-exit-record.ps1','Qualification.ps1')){. (Join-Path $Root $n)}
$script:checks=0
function CheckRunner($b,$m){$script:checks++;if(-not $b){throw $m}}
function Reset-RunnerFixture{$script:mode='';$script:calls=@();$script:answers=0}
function Invoke-IsoNormalExitOperation{
 param($Operation,$Confirmation,$ReviewDigest)
 $script:calls+=,$Operation
 if($script:mode -ceq 'review_fail' -and $Operation -ceq 'Review'){throw 'normal_exit_foreign_before_image_mismatch'}
 if($Operation -ceq 'Review'){
  return [pscustomobject]@{review_digest=('a'*64);review=[pscustomobject]@{owned_rules_absent=4;foreign_images_matched=100;profiles=@(foreach($n in @('Domain','Private','Public')){[pscustomobject]@{name=$n;legacy_outbound='NotConfigured';current_local_outbound='Allow';current_effective_outbound='Allow';firewall_enabled='True'}})}}
 }
 CheckRunner ($Confirmation -ceq 'ACKNOWLEDGE EXISTING NORMAL NETWORK MODE' -and $ReviewDigest -ceq ('a'*64)) 'fixed consent only after human challenge'
 if($script:mode -ceq 'record_fail'){throw 'normal_exit_review_stale'}
 if($script:mode -ceq 'record_raw_error'){throw 'PRIVATE_PATH_AND_RULE_NAME'}
 return [pscustomobject]@{normal_mode_acknowledgment_recorded=$true;record_matches_current_snapshot=$true;created_this_call=$true;authorizes_isolation=($script:mode -ceq 'bad_authority');original_restore_verified=$false;ready_for_apply=$false}
}
function Read-ExitConsentAnswer($Challenge){$script:answers++;CheckRunner ($Challenge -cmatch '^RECORD NORMAL [a-f0-9]{12}$') 'challenge shape';switch($script:mode){'cancel'{return ''};'wrong'{return 'YES'};'lowercase'{return $Challenge.ToLowerInvariant()};default{return $Challenge}}}
Reset-RunnerFixture;$r=Invoke-ExitReviewAndConsent
CheckRunner ($r.completed -and $r.normal_mode_acknowledgment_recorded -and $r.record_matches_current_snapshot) 'successful reviewed record'
CheckRunner (($script:calls -join ',') -ceq 'Review,Record' -and $script:answers -eq 1) 'review then prompt then record'
foreach($k in @('legacy_journal_rewritten','firewall_changed','ready_for_apply','original_restore_verified','reboot_qualified','no_leak_certified')){CheckRunner ($r.$k -ceq $false) ('boundary '+$k)}
CheckRunner (($r|ConvertTo-Json -Depth 12) -notmatch 'a{64}|PRIVATE_PATH|RECORD NORMAL') 'no digest/challenge/private error export'
foreach($case in @('cancel','wrong','lowercase')){Reset-RunnerFixture;$script:mode=$case;$r=Invoke-ExitReviewAndConsent;CheckRunner ($r.completed -and $r.code -ceq 'exit_record_cancelled_no_live_record_write' -and -not $r.record_operation_attempted -and ($script:calls -join ',') -ceq 'Review') 'cancel no native Record'}
Reset-RunnerFixture;$script:mode='review_fail';$r=Invoke-ExitReviewAndConsent
CheckRunner (-not $r.completed -and $script:answers -eq 0 -and -not $r.record_operation_attempted -and $r.code -ceq 'normal_exit_foreign_before_image_mismatch') 'preflight error before prompt'
foreach($case in @('record_fail','record_raw_error','bad_authority')){Reset-RunnerFixture;$script:mode=$case;$r=Invoke-ExitReviewAndConsent;CheckRunner (-not $r.completed -and $r.record_operation_attempted -and -not $r.normal_mode_acknowledgment_recorded) ('failed write not claimed '+$case)}
Reset-RunnerFixture;$script:mode='record_raw_error';$r=Invoke-ExitReviewAndConsent;CheckRunner (($r|ConvertTo-Json) -notmatch 'PRIVATE_PATH_AND_RULE_NAME') 'raw error redacted'
# Platform refusal for actual qualification function; no synthetic root created on Linux.
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){$q=Invoke-ExitStorageQualification;CheckRunner (-not $q.completed -and $q.code -ceq 'exit_qualification_windows_required') 'storage guard before filesystem ACL calls'}
# Exercise the real ACL validator with metadata fixtures, not Windows access checks.
$script:aclFixture=$null
function Get-Acl{param($LiteralPath,$ErrorAction)return $script:aclFixture}
function New-AclFixture([bool]$Directory){
 $inherit=if($Directory){'ContainerInherit, ObjectInherit'}else{'None'}
 $a=[pscustomobject]@{AreAccessRulesProtected=$true;OwnerValue='S-1-5-32-544';Rules=@(foreach($sid in @('S-1-5-32-544','S-1-5-18')){[pscustomobject]@{IdentityReference=[pscustomobject]@{Value=$sid};AccessControlType=[Security.AccessControl.AccessControlType]::Allow;FileSystemRights=[Security.AccessControl.FileSystemRights]::FullControl;IsInherited=$false;PropagationFlags='None';InheritanceFlags=$inherit}})}
 $a|Add-Member ScriptMethod GetOwner {param($Type)[pscustomobject]@{Value=$this.OwnerValue}}
 $a|Add-Member ScriptMethod GetAccessRules {param($Explicit,$Inherited,$Type)return $this.Rules}
 return $a
}
foreach($directory in @($true,$false)){$script:aclFixture=New-AclFixture $directory;Assert-ExitPrivateAcl $Root $directory;CheckRunner $true 'expected ACL metadata accepted'}
foreach($case in @('owner','unprotected','extra_sid','duplicate','inherited','limited_rights','deny','inheritance','propagation','missing_system')){
 $script:aclFixture=New-AclFixture $false
 switch($case){'owner'{$script:aclFixture.OwnerValue='S-1-5-21-1-2-3-1001'};'unprotected'{$script:aclFixture.AreAccessRulesProtected=$false};'extra_sid'{$script:aclFixture.Rules[1].IdentityReference.Value='S-1-1-0'};'duplicate'{$script:aclFixture.Rules[1].IdentityReference.Value='S-1-5-32-544'};'inherited'{$script:aclFixture.Rules[1].IsInherited=$true};'limited_rights'{$script:aclFixture.Rules[1].FileSystemRights=[Security.AccessControl.FileSystemRights]::Read};'deny'{$script:aclFixture.Rules[1].AccessControlType=[Security.AccessControl.AccessControlType]::Deny};'inheritance'{$script:aclFixture.Rules[1].InheritanceFlags='ObjectInherit'};'propagation'{$script:aclFixture.Rules[1].PropagationFlags='InheritOnly'};'missing_system'{$script:aclFixture.Rules=@($script:aclFixture.Rules[0])}}
 $caught=$false;try{Assert-ExitPrivateAcl $Root $false}catch{$caught=$true};CheckRunner $caught ('unsafe ACL metadata refused '+$case)
}
# Parse and bound executable call sites; helper files containing mutators are only definitions.
foreach($file in @('Qualification.ps1','Run-Exit.ps1')){
 $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $file),[ref]$t,[ref]$e);CheckRunner ($e.Count -eq 0) ('parse '+$file)
 foreach($node in $ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){
  $name=$node.GetCommandName()
  if($name -match '^(Set-Net.*|New-Net.*|Remove-Net.*|Enable-Net.*|Disable-Net.*|Set-ExecutionPolicy|Resolve-DnsName|Invoke-WebRequest|Invoke-RestMethod|Start-Service|Stop-Service|Register-ScheduledTask|Unregister-ScheduledTask|Stop-ScheduledTask|Start-ScheduledTask|Restore-IsoSession|Invoke-IsoArm|Invoke-IsoUpdate|IsoSave)$'){throw ('unexpected executed mutator '+$name)}
 }
}
$source=[IO.File]::ReadAllText((Join-Path $Root 'Qualification.ps1'))
CheckRunner ($source.Contains('USave $testRoot $fixture') -and -not $source.Contains('USave $script:IsoRoot')) 'fixture USave bound to disposable root'
CheckRunner (-not $source.Contains('Remove-Item') -and $source.Contains('[IO.Directory]::Delete($testRoot,$false)')) 'no recursive cleanup'
$result=[ordered]@{suite='normal-exit-runner-consent-and-boundaries';assertions=$script:checks;passed=$true;Windows_storage_qualification_executed=$false;real_human_prompt_tested=$false;live_record_created=$false;firewall_changed=$false;ready_for_apply=$false}
$result|ConvertTo-Json|Set-Content '/data/ufd-normal-exit-runner-v01/MODEL-RESULTS.json' -Encoding UTF8
$result|ConvertTo-Json -Compress
