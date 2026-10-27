param([string]$Root='/data/ufw-prepare-session-v01/package/UFW-PREPARE-SESSION-01')
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. (Join-Path $Root 'PreparationEntry.ps1')
$m=Import-Module (Join-Path $Root 'Ufw.SessionJournal.psm1') -Force -PassThru
$script:checks=0
function Check-Prep($b,$label){$script:checks++;if(-not $b){throw $label}}
& $m {
 $script:TestState=$null;$script:OriginalOps=${function:New-UfwNativePreparationOps}
 function script:Invoke-UfwInstallerPreflightReadOnly {
  $s=$script:TestState;$s.reads++;$default='Block'
  if($s.mode -ceq 'allow' -or ($s.mode -ceq 'before_change' -and $s.reads -eq 2) -or ($s.mode -ceq 'after_change' -and $s.reads -eq 3)){$default='Allow'}
  $rows=@(foreach($n in @('Domain','Private','Public')){[pscustomobject][ordered]@{name=$n;local_outbound=$default;effective_outbound=$default;local_enabled='True';effective_enabled='True';local_allow_local_rules='NotConfigured';effective_allow_local_rules='True'}})
  $assessment=[pscustomobject]@{profiles=$rows;explicit_local_outbound_baseline_present=$true;profile_fields_compatible_for_later_review=$true;all_outbound_allow=($default -ceq 'Allow');reasons=@()}
  $obs=[pscustomobject]@{schema='ufw-readonly-profile-preflight-01';completed=$true;code='ufw_read_observed_profiles_only';assessment=$assessment;two_observations_match=$true;native_store_reads_attempted=4;firewall_change_requested=$false;ready_for_apply=$false}
  $p=[pscustomobject]@{completed=$true;code='ufw_core_profile_stage_only_no_apply';baseline_draft_constructible=$true;profile_observation=$obs}
  if($s.mode -ceq 'reader_failure'){$p.completed=$false;$p.code='ufw_core_reader_not_completed';$p.baseline_draft_constructible=$false;$obs.completed=$false;$obs.code='ufw_read_excluded_interface_present';$obs.assessment=$null}
  if($s.mode -ceq 'policy_failure'){$p.completed=$false;$p.code='ufw_core_profile_review_required';$p.baseline_draft_constructible=$false;$obs.assessment.profiles[0].effective_allow_local_rules='False';$obs.assessment.reasons=@('Domain:effective_local_rules_not_true')}
  return $p
 }
 function script:Read-Host {
  param($Prompt)$s=$script:TestState;$s.prompts++
  if(-not $script:PreparationEntryContext.review_shown){throw 'fixture_prompt_before_review'}
  if(-not $Prompt.StartsWith('Type exactly: PREPARE JOURNAL ')){throw 'fixture_wrong_prompt'}
  $answer=$Prompt.Substring('Type exactly: '.Length);$s.challenge=$answer
  switch($s.mode){cancel{return ''};wrong{return 'YES'};lower{return $answer.ToLowerInvariant()};default{return $answer}}
 }
 function script:Save-UfwNativePreparation {
  param($Receipt,$Draft)$s=$script:TestState;$s.saves++;$s.captured=[pscustomobject]@{receipt=$Receipt;draft=$Draft}
  if($s.mode -ceq 'save_error'){throw 'PRIVATE_PATH_AND_USER'}
  return [pscustomobject]@{sequence=1;head=('f'*64);readback_verified=($s.mode -cne 'unverified')}
 }
 function script:New-UfwNativePreparationOps {
  $ops=& $script:OriginalOps
  $ops.UtcNow={
   $s=$script:TestState;$s.clock++;$t=[datetime]::Parse('2026-10-27T05:00:00Z').ToUniversalTime()
   if($s.mode -ceq 'expired' -and $s.clock -ge 2){return $t.AddSeconds(121)}
   if($s.mode -ceq 'post_expired' -and $s.clock -ge 3){return $t.AddSeconds(121)}
   return $t
  }
  return $ops
 }
}
function Run-PrepCase($Mode){
 & $m {param($mode)$script:TestState=[pscustomobject]@{mode=$mode;reads=0;prompts=0;saves=0;clock=0;challenge='';captured=$null}} $Mode
 return Invoke-UfwPreparationEntry $m
}
foreach($mode in @('block','allow')){
 $r=Run-PrepCase $mode;$s=& $m {$script:TestState}
 Check-Prep ($r.completed -and $r.journal_preparation_recorded -and $r.consent_received -and $s.saves -eq 1 -and $s.prompts -eq 1 -and $s.reads -eq 3) ('success '+$mode)
 Check-Prep ($r.journal_write_status -ceq 'prepared_and_revalidated_no_firewall_authority') 'success status explicit'
 Check-Prep ($r.profile_observations.Count -eq 3 -and @($r.profile_observations|Where-Object{$_.profiles.Count -ne 3}).Count -eq 0) 'three safe three-profile snapshots'
 Check-Prep (($r.profile_observations.native_profile_reads_attempted|Measure-Object -Sum).Sum -eq 12) 'reader query counters preserved'
 Check-Prep ($s.captured.receipt.purpose -ceq 'prepare_profile_journal_only' -and $s.captured.receipt.authorizes_firewall_change -ceq $false -and $s.captured.draft.execution_authorized -ceq $false) 'file consent not execution'
 Check-Prep (($s.captured.draft.entries.before.local_outbound|Sort-Object -Unique) -ceq $(if($mode -ceq 'block'){'Block'}else{'Allow'})) 'baseline not coerced'
 foreach($key in @('real_legacy_journal_access_requested','firewall_change_requested','VPN_change_requested','DNS_query_generated','normal_mode_restored','original_restore_verified','ready_for_apply','no_leak_certified')){Check-Prep ($r.$key -ceq $false) ('boundary '+$key)}
 $json=$r|ConvertTo-Json -Depth 24;Check-Prep ($json -notmatch 'PREPARE JOURNAL|f{64}|[a-f0-9]{32}|PRIVATE_PATH_AND_USER') 'no challenge, identity, digest or raw error in public report'
 $ctx=& $m {Get-Variable PreparationEntryContext -Scope Script -ErrorAction SilentlyContinue};Check-Prep ($null -eq $ctx) 'entry context cleared'
}
foreach($mode in @('cancel','wrong','lower')){
 $r=Run-PrepCase $mode;$s=& $m {$script:TestState}
 Check-Prep ($r.completed -and $r.code -ceq 'ufw_journal_cancelled_no_write' -and -not $r.journal_write_attempted -and -not $r.journal_preparation_recorded -and $s.saves -eq 0 -and $s.reads -eq 1) ('no record on '+$mode)
 Check-Prep ($r.journal_write_status -ceq 'not_requested') 'cancellation not write failure'
}
foreach($mode in @('reader_failure','policy_failure')){
 $r=Run-PrepCase $mode;$s=& $m {$script:TestState}
 Check-Prep (-not $r.completed -and -not $r.review_shown -and $s.prompts -eq 0 -and $s.saves -eq 0 -and $r.profile_observations.Count -eq 1) ('preflight refuses before prompt '+$mode)
 if($mode -ceq 'reader_failure'){Check-Prep ($r.profile_observations[0].reader_code -ceq 'ufw_read_excluded_interface_present') 'specific reader code retained'}else{Check-Prep ($r.profile_observations[0].reasons -contains 'Domain:effective_local_rules_not_true' -and $r.profile_observations[0].profiles[0].effective_allow_local_rules -ceq 'False') 'policy reason and field retained'}
}
foreach($case in @(@('before_change','ufw_journal_baseline_changed_after_prompt'),@('expired','ufw_journal_consent_expired_or_clock_changed'))){
 $r=Run-PrepCase $case[0];$s=& $m {$script:TestState};Check-Prep (-not $r.completed -and $r.code -ceq $case[1] -and $s.saves -eq 0 -and -not $r.journal_write_attempted) ('prewrite refusal '+$case[0])
}
foreach($case in @(@('after_change','ufw_journal_baseline_changed_after_write'),@('save_error','ufw_journal_preparation_unavailable'),@('unverified','ufw_journal_preparation_unverified'),@('post_expired','ufw_journal_consent_expired_after_write'))){
 $r=Run-PrepCase $case[0];$s=& $m {$script:TestState};Check-Prep (-not $r.completed -and $r.code -ceq $case[1] -and $s.saves -eq 1 -and $r.journal_write_attempted -and -not $r.journal_preparation_recorded -and $r.journal_write_status -ceq 'attempted_may_exist_inspect_if_failed') ('uncertain write never no-write '+$case[0])
}
# Entry must also survive the array-output convention that broke the old fixture.
function global:ConvertFrom-Json {
 [CmdletBinding()]param([Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)][string]$InputObject)
 process{if($InputObject.TrimStart().StartsWith('[')){$v=@(Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject);Write-Output -NoEnumerate $v}else{Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject}}
}
try{$r=Run-PrepCase 'block';Check-Prep ($r.completed -and $r.profile_observations.Count -eq 3) 'PS51 JSON array contract does not change wrapper result'}finally{Remove-Item Function:\ConvertFrom-Json}
foreach($file in @('PreparationEntry.ps1','Run-Prepare.ps1')){
 $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $file),[ref]$t,[ref]$e);Check-Prep ($e.Count -eq 0) ('parse '+$file)
 foreach($cmd in $ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){
  if($cmd.GetCommandName() -match '^(Set-Net.*|New-Net.*|Remove-Net.*|Enable-Net.*|Disable-Net.*|Get-Vpn.*|Set-Vpn.*|Get-NetRoute|Resolve-DnsName|Get-ScheduledTask|Register-ScheduledTask|Unregister-ScheduledTask|Set-ExecutionPolicy|Start-Process|Invoke-Expression|IsoLoad|ULoad|USave|IsoSave|Restore-IsoSession|Invoke-IsoArm)$'){throw 'unexpected policy/legacy call'}
 }
 Check-Prep $true ('no native firewall/VPN or legacy calls '+$file)
}
# Full entry -> actual core -> actual reader with getter mocks -> actual file journal.
Remove-Module $m.Name -Force
$m=Import-Module (Join-Path $Root 'Ufw.SessionJournal.psm1') -Force -PassThru
$reader=@(& $m {& $script:Core {Get-Module Ufw.ProfileReader}})
Check-Prep ($reader.Count -eq 1) 'real nested reader found'
& $reader[0] {
 function script:Assert-UfwReadPlatform {}
 $script:getterCalls=0
 function script:Get-NetFirewallProfile {
  param($PolicyStore,$ErrorAction)$script:getterCalls++
  foreach($n in @('Domain','Private','Public')){[pscustomobject]@{Name=$n;DefaultOutboundAction='Block';Enabled='True';AllowLocalFirewallRules=$(if($PolicyStore -ceq 'PersistentStore'){'NotConfigured'}else{'True'});DisabledInterfaceAliases=@()}}
 }
}
$base=Join-Path ([IO.Path]::GetTempPath()) ('ufw-prep-integration-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($base)
try{
 & $m {
  param($base)$script:Integration=[pscustomobject]@{base=$base;path=$null;receipt=$null;draft=$null}
  function script:Read-Host {param($Prompt)return $Prompt.Substring('Type exactly: '.Length)}
  function script:Save-UfwNativePreparation {
   param($Receipt,$Draft)$ctx=$script:Integration;$ctx.receipt=$Receipt;$ctx.draft=$Draft
   $data=[pscustomobject][ordered]@{receipt=$Receipt;draft=$Draft};Assert-UfwPreparationData $data $Receipt.session_id
   $ctx.path=Join-Path $ctx.base ('UfwInstaller-Session-'+$Receipt.session_id);New-UfwPrivateJournalDirectory $ctx.path
   return Add-UfwPreparationCheckpoint $ctx.path $Receipt.session_id ('0'*64) 'prepared' $data
  }
 } $base
 $r=Invoke-UfwPreparationEntry $m
 Check-Prep ($r.completed -and $r.journal_preparation_recorded -and $r.profile_observations.Count -eq 3) 'full integration with real file store'
 $count=& $reader[0] {$script:getterCalls};Check-Prep ($count -eq 12) 'full integration issues twelve getter mock calls'
 $saved=& $m {$ctx=$script:Integration;Read-UfwPreparationJournal $ctx.path $ctx.receipt.session_id}
 Check-Prep ($saved.sequence -eq 1 -and $saved.last.data.draft.phase -ceq 'prepared' -and @($saved.last.data.draft.entries|Where-Object{$_.intent -or $_.restored}).Count -eq 0) 'only one preparation checkpoint, no arming intent'
 Check-Prep (-not $saved.last.data.receipt.authorizes_firewall_change -and -not $saved.last.data.draft.execution_authorized -and ($saved.last.data.draft.entries.before.local_outbound|Sort-Object -Unique) -ceq 'Block') 'disk record retains Block and no authority'
 $ctx=& $m {$script:Integration};$first=Join-Path $ctx.path '00000001.json';$before=(Get-FileHash $first).Hash;$caught=''
 try{& $m {$ctx=$script:Integration;Save-UfwNativePreparation $ctx.receipt $ctx.draft}|Out-Null}catch{$caught=$_.Exception.GetBaseException().Message}
 Check-Prep ($caught -ceq 'ufw_journal_directory_collision' -and (Get-FileHash $first).Hash -ceq $before) 'same session cannot replay/overwrite'
 Check-Prep (($r|ConvertTo-Json -Depth 24) -notmatch 'ufw-prep-integration-|UfwInstaller-Session-[a-f0-9]{32}') 'real IO path not exported'
}finally{
 if([IO.Directory]::Exists($base)){Remove-Item -LiteralPath $base -Recurse -Force}
}
$result=[ordered]@{suite='preparation-only-real-entry-model-01';passed=$true;assertions=$script:checks;Windows_profile_getters_mocked=$true;real_Linux_preparation_record_IO_executed=$true;real_human_prompt_executed=$false;real_Windows_profile_query_or_record_creation_executed=$false;PS51_JSON_array_contract_shim_tested=$true;firewall_writer_present=$false;ready_for_apply=$false}
$result|ConvertTo-Json|Set-Content '/data/ufw-prepare-session-v01/MODEL-RESULTS.json' -Encoding UTF8;$result|ConvertTo-Json -Compress
