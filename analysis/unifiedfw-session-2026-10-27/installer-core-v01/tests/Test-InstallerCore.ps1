param([string]$Root='/data/ufw-installer-core-v01')
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$m=Import-Module (Join-Path $Root 'source/Ufw.InstallerCore.psm1') -Force -PassThru
$script:checks=0
function Check($b,$s){$script:checks++;if(-not $b){throw $s}}
function Copy-CoreFixture($v){ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $v -Depth 32 -Compress)}
function Rows($Default='Allow'){@(foreach($n in @('Domain','Private','Public')){[pscustomobject]@{name=$n;local_outbound=$Default;effective_outbound=$Default;local_enabled='True';effective_enabled='True';local_allow_local_rules='NotConfigured';effective_allow_local_rules='True'}})}
function Observation($Default='Allow'){[pscustomobject]@{schema='ufw-readonly-profile-preflight-01';completed=$true;two_observations_match=$true;firewall_change_requested=$false;ready_for_apply=$false;assessment=[pscustomobject]@{explicit_local_outbound_baseline_present=$true;profile_fields_compatible_for_later_review=$true;profiles=(Rows $Default)}}}
function Draft($o){& $m {param($o)New-UfwProfileRecoveryDraft $o} $o}
function RejectDraft($o,$code){$caught='';try{Draft $o|Out-Null}catch{$caught=$_.Exception.GetBaseException().Message};Check ($caught -ceq $code) ('draft '+$code)}
function Recover($s){& $m {param($s,$ops)Invoke-UfwProfileRecoveryCallbacks $s $ops} $s $script:ops}
function Reset($Default='Allow'){
 $script:s=Draft (Observation $Default);$script:s.phase='armed';foreach($e in $script:s.entries){$e.intent=$true}
 $script:current=Rows 'Block';$script:durable=Copy-CoreFixture $script:s;$script:writes=@();$script:saves=0;$script:reads=0;$script:failSave=0;$script:failWrite=0;$script:failAfterWrite=0;$script:driftAt=0;$script:ignoreWrite=$false;$script:metadataWriteDrift=$false;$script:rawError=$false
 $script:ops=@{
  ReadProfiles={$script:reads++;if($script:driftAt -eq $script:reads){$script:current[0].local_enabled='False'};if($script:rawError){throw 'PRIVATE_PATH_AND_USER'};return @(Copy-CoreFixture $script:current)}
  Save={param($s)$script:saves++;if($script:saves -eq $script:failSave){throw 'fixture_save_failed'};$script:durable=Copy-CoreFixture $s}
  WriteOutbound={param($n,$v)if($n -cnotin @('Domain','Private','Public') -or $v -cnotin @('Allow','Block')){throw 'unsafe_fixture_write'};if(($script:writes.Count+1) -eq $script:failWrite){throw 'fixture_write_failed'};$script:writes+=,[pscustomobject]@{name=$n;outbound=$v};if(-not $script:ignoreWrite){$row=@($script:current|Where-Object{$_.name -ceq $n})[0];$row.local_outbound=$v;$row.effective_outbound=$v;if($script:metadataWriteDrift){$row.local_enabled='False'}};if($script:writes.Count -eq $script:failAfterWrite){throw 'fixture_crash_after_write'}}
 }
}
$d=Draft (Observation);Check ($d.entries.Count -eq 3 -and $d.execution_authorized -ceq $false -and $d.phase -ceq 'prepared') 'draft not consent'
$o=Observation;$d=Draft $o;$o.assessment.profiles[0].local_outbound='Block';Check ($d.entries[0].before.local_outbound -ceq 'Allow') 'snapshot cloned'
foreach($f in @('completed','two_observations_match')){$o=Observation;$o.$f=$false;RejectDraft $o 'ufw_core_fresh_read_required';$o=Observation;$o.$f='True';RejectDraft $o 'ufw_core_fresh_read_required'}
foreach($f in @('firewall_change_requested','ready_for_apply')){$o=Observation;$o.$f=$true;RejectDraft $o 'ufw_core_fresh_read_required'}
$o=Observation;$o.schema='unified-isolation-session-1';RejectDraft $o 'ufw_core_fresh_read_required'
$o=Observation;$o.assessment.profile_fields_compatible_for_later_review=$false;RejectDraft $o 'ufw_core_profile_review_required'
$o=Observation;$o.assessment.profiles[0].local_outbound='NotConfigured';RejectDraft $o 'ufw_core_explicit_outbound_required'
$o=Observation;$o.assessment.profiles[0].effective_outbound='Block';RejectDraft $o 'ufw_core_baseline_policy_mismatch'
$o=Observation;$o.assessment.profiles[0].effective_allow_local_rules='NotConfigured';RejectDraft $o 'ufw_core_effective_profile_policy'
$o=Observation;$o.assessment.profiles[0].name='Other';RejectDraft $o 'ufw_core_profile_identity'
$o=Observation;$o.assessment.profiles[0]|Add-Member NoteProperty Extra 'x';RejectDraft $o 'ufw_core_profile_shape'
$o=Observation;$o.assessment.profiles[0].effective_enabled=$true;RejectDraft $o 'ufw_core_effective_profile_policy'
# The PUBLIC entry really calls the nested reader; Linux guard stops before getters.
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){$r=Invoke-UfwInstallerPreflightReadOnly;Check (-not $r.completed -and $r.code -ceq 'ufw_core_reader_not_completed' -and $r.profile_observation.code -ceq 'ufw_read_windows_required') 'real integration Linux guard'}
# Mock only reader result at the module boundary for core logic cases.
& $m {function script:Invoke-UfwProfilePreflightReadOnly {if($script:obs -is [Exception]){throw $script:obs};return $script:obs}}
foreach($default in @('Allow','Block')){$o=Observation $default;& $m {param($o)$script:obs=$o} $o;$r=Invoke-UfwInstallerPreflightReadOnly;Check ($r.completed -and $r.baseline_draft_constructible -and -not $r.ready_for_apply -and -not $r.profile_write_requested) 'public preflight no execution';Check ($r.pending_components.Count -eq 5) 'missing live components explicit'}
$o=Observation;$o.assessment.profile_fields_compatible_for_later_review=$false;& $m {param($o)$script:obs=$o} $o;$r=Invoke-UfwInstallerPreflightReadOnly;Check (-not $r.completed -and -not $r.baseline_draft_constructible) 'public blocked preflight'
& $m {$script:obs=[Exception]::new('PRIVATE_PATH_AND_USER')};$r=Invoke-UfwInstallerPreflightReadOnly;Check ($r.code -ceq 'ufw_core_profile_stage_unavailable' -and ($r|ConvertTo-Json -Depth 24) -notmatch 'PRIVATE_PATH_AND_USER') 'raw public error redaction'
Reset;$r=Recover $s;Check ($r.model_recovery_completed -and $r.current_profile_images_match -and $r.profile_writes -eq 3 -and $script:durable.phase -ceq 'restored') 'reset-free memory restore';Check (($script:writes.name -join ',') -ceq 'Public,Private,Domain') 'serial reverse order';Check (($script:writes.outbound|Sort-Object -Unique) -ceq 'Allow') 'exact baseline targets'
foreach($f in @('original_restore_verified','reboot_qualified','ready_for_apply')){Check ($r.$f -ceq $false) ('model not certificate '+$f)}
$r=Recover $script:durable;Check ($r.profile_writes -eq 0 -and $script:writes.Count -eq 3) 'restored stamp freshly reread no new writes'
$script:current[0].local_outbound='Block';$script:current[0].effective_outbound='Block';$caught='';try{Recover $script:durable|Out-Null}catch{$caught=$_.Exception.Message};Check ($caught -ceq 'ufw_core_untouched_or_restored_profile_drift' -and $script:writes.Count -eq 3) 'do not trust restored stamp or rewrite outside drift'
Reset 'Block';$r=Recover $s;Check ($r.profile_writes -eq 0 -and $script:writes.Count -eq 0 -and $script:durable.phase -ceq 'restored') 'Block baseline never broadened to Allow'
Reset;$s.entries[0].intent=$false;$script:current[0].local_outbound='Allow';$script:current[0].effective_outbound='Allow';$r=Recover $s;Check ($r.profile_writes -eq 2 -and $script:writes.name -notcontains 'Domain') 'untouched profile not written'
Reset;$s.entries[0].intent=$false;$caught='';try{Recover $s|Out-Null}catch{$caught=$_.Exception.Message};Check ($caught -ceq 'ufw_core_untouched_or_restored_profile_drift' -and $script:writes.Count -eq 0 -and $script:saves -eq 0) 'untouched drift refuses before any save/write'
Reset;$s.entries[0].before.local_outbound='NotConfigured';$caught='';try{Recover $s|Out-Null}catch{$caught=$_.Exception.Message};Check ($caught -ceq 'ufw_core_explicit_outbound_required' -and $script:saves -eq 0 -and $script:writes.Count -eq 0) 'legacy NotConfigured never reinterpreted'
Reset;$s.schema='unified-isolation-session-1';$caught='';try{Recover $s|Out-Null}catch{$caught=$_.Exception.Message};Check ($caught -ceq 'ufw_core_recovery_session_shape' -and $script:saves -eq 0) 'old journal not migrated'
foreach($at in @(1,2,3,4,5,6,7,8)){
 Reset;$script:failSave=$at;$caught='';try{Recover $s|Out-Null}catch{$caught=$_.Exception.Message};Check ($caught -ceq 'fixture_save_failed') ('save failure surfaced '+$at)
 $script:failSave=0;$retry=Copy-CoreFixture $script:durable;$r=Recover $retry;Check ($r.model_recovery_completed -and $script:durable.phase -ceq 'restored' -and $script:writes.Count -eq 3) ('save failure resumable without duplicate write '+$at)
}
foreach($at in @(1,2,3)){
 Reset;$script:failWrite=$at;$caught='';try{Recover $s|Out-Null}catch{$caught=$_.Exception.Message};Check ($caught -ceq 'fixture_write_failed' -and $script:durable.phase -cne 'restored') ('write failure not success '+$at)
 $script:failWrite=0;$r=Recover (Copy-CoreFixture $script:durable);Check ($r.model_recovery_completed -and $script:writes.Count -eq 3) ('partial write resumable '+$at)
}
foreach($at in @(1,2,3)){
 Reset;$script:failAfterWrite=$at;$caught='';try{Recover $s|Out-Null}catch{$caught=$_.Exception.Message};Check ($caught -ceq 'fixture_crash_after_write' -and $script:durable.phase -cne 'restored') ('crash after write not success '+$at)
 $script:failAfterWrite=0;$r=Recover (Copy-CoreFixture $script:durable);Check ($r.model_recovery_completed -and $script:writes.Count -eq 3) ('crash after write resumes without duplicate '+$at)
}
Reset;$script:driftAt=11;$caught='';try{Recover $s|Out-Null}catch{$caught=$_.Exception.Message};Check ($caught -ceq 'ufw_core_final_profile_mismatch' -and $script:durable.phase -cne 'restored') 'final sweep drift no restored stamp'
Reset;$script:driftAt=3;$caught='';try{Recover $s|Out-Null}catch{$caught=$_.Exception.Message};Check ($caught -ceq 'ufw_core_profile_image_drift' -and $script:writes.Count -eq 0) 'metadata concurrent drift before write'
Reset;$script:ignoreWrite=$true;$caught='';try{Recover $s|Out-Null}catch{$caught=$_.Exception.Message};Check ($caught -ceq 'ufw_core_profile_restore_readback' -and $script:durable.phase -cne 'restored') 'no-op write readback failure'
Reset;$script:metadataWriteDrift=$true;$caught='';try{Recover $s|Out-Null}catch{$caught=$_.Exception.Message};Check ($caught -ceq 'ufw_core_profile_image_drift' -and $script:durable.phase -cne 'restored') 'unexpected metadata change after write'
Reset;$script:rawError=$true;$caught='';try{Recover $s|Out-Null}catch{$caught=$_.Exception.Message};Check ($caught -ceq 'PRIVATE_PATH_AND_USER' -and $script:writes.Count -eq 0) 'private callback engine surfaces error to future controller no auto retry'
Reset;$script:current=@($script:current|Sort-Object name -Descending);$r=Recover $s;Check $r.model_recovery_completed 'profile row order irrelevant'
Reset;$script:current=@(foreach($row in $script:current){$x=[ordered]@{};foreach($k in @($row.PSObject.Properties.Name|Sort-Object -Descending)){$x[$k]=$row.$k};[pscustomobject]$x});$r=Recover $s;Check $r.model_recovery_completed 'field order irrelevant'
$exports=@(Get-Command -Module Ufw.InstallerCore);Check ($exports.Count -eq 1 -and $exports[0].Name -ceq 'Invoke-UfwInstallerPreflightReadOnly') 'writer engine not exported'
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'source/Ufw.InstallerCore.psm1'),[ref]$t,[ref]$e);Check ($e.Count -eq 0) 'core parsed'
$bad='^(Set-Net.*|New-Net.*|Remove-Net.*|Enable-Net.*|Disable-Net.*|Set-ExecutionPolicy|Register-ScheduledTask|Unregister-ScheduledTask|Start-Process|Invoke-Expression|Resolve-DnsName|Set-Content|Out-File|USave|IsoSave|Restore-IsoSession|Invoke-IsoArm)$'
foreach($cmd in $ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){if($cmd.GetCommandName() -match $bad){throw ('native mutator '+$cmd.GetCommandName())}}
Check $true 'no native mutation/persistence commands in new module'
# End-to-end core -> pinned reader -> native getter mocks, not a mocked reader result.
Remove-Module $m.Name -Force
$m=Import-Module (Join-Path $Root 'source/Ufw.InstallerCore.psm1') -Force -PassThru
$nested=@(& $m {Get-Module Ufw.ProfileReader})
Check ($nested.Count -eq 1) 'pinned reader imported as local dependency'
& $nested[0] {
 function script:Assert-UfwReadPlatform {}
 $script:calls=@()
 function script:Get-NetFirewallProfile {
  param($PolicyStore,$ErrorAction)$script:calls+=,$PolicyStore
  foreach($n in @('Domain','Private','Public')){[pscustomobject]@{Name=$n;DefaultOutboundAction='Block';Enabled='True';AllowLocalFirewallRules='True';DisabledInterfaceAliases=@()}}
 }
}
$r=Invoke-UfwInstallerPreflightReadOnly
Check ($r.completed -and $r.baseline_draft_constructible -and $r.profile_observation.two_observations_match -and -not $r.profile_observation.assessment.all_outbound_allow -and -not $r.ready_for_apply) 'full read-only integration with Block'
$count=& $nested[0] {$script:calls.Count};Check ($count -eq 4) 'integrated path exactly four getter calls'
# Dependency integrity refusal; test-only temporary files, never a user path.
$tmp=Join-Path ([IO.Path]::GetTempPath()) ('ufw-core-pin-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($tmp)
try{
 foreach($name in @('Ufw.InstallerCore.psm1','Ufw.ProfileReader.psm1')){[IO.File]::Copy((Join-Path $Root ('source/'+$name)),(Join-Path $tmp $name))}
 [IO.File]::AppendAllText((Join-Path $tmp 'Ufw.ProfileReader.psm1'),'# changed fixture')
 $caught='';try{Import-Module (Join-Path $tmp 'Ufw.InstallerCore.psm1') -Force -ErrorAction Stop}catch{$caught=$_.Exception.GetBaseException().Message}
 Check ($caught -match 'ufw_core_dependency_hash') 'changed dependency refused'
}finally{
 foreach($name in @('Ufw.InstallerCore.psm1','Ufw.ProfileReader.psm1')){[IO.File]::Delete((Join-Path $tmp $name))}
 [IO.Directory]::Delete($tmp,$false)
}
$result=[ordered]@{suite='minimal-installer-preflight-and-profile-recovery-callbacks-01';passed=$true;assertions=$script:checks;native_Windows_executed=$false;native_mutation_adapter_implemented=$false;durable_journal_adapter_implemented=$false;profile_recovery_tested_with_memory_callbacks_only=$true;public_entry_read_only=$true;old_journal_migration_implemented=$false;ready_for_apply=$false;no_leak_certified=$false}
$result|ConvertTo-Json|Set-Content (Join-Path $Root 'evidence/model-tests.json') -Encoding UTF8
$result|ConvertTo-Json -Compress
