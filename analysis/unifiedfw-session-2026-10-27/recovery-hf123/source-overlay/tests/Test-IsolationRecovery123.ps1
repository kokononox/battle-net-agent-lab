param([string]$Root=(Join-Path $PSScriptRoot '..'))
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. (Join-Path $Root 'tests/Test-IsolationCore.ps1') -Root $Root
$script:checks=0
function Reject123($Block,$Code){$caught='';try{& $Block|Out-Null}catch{$caught=$_.Exception.Message};Assert ($caught -ceq $Code) ('expected '+$Code+' got '+$caught)}
# Legacy/ambiguous baseline: no firewall writes, even when the old phase says restored.
foreach($bad in @('NotConfigured','', 'Unexpected')){
 Reset-Fake;$s.profiles[0].before.default_outbound=$bad
 Reject123 {Invoke-IsoArm $s $plan $ops} 'iso_local_profile_baseline_requires_explicit_review'
 Assert ($script:writes.Count -eq 0 -and $s.phase -ceq 'prepared') 'arm refuses before side effects'
 Reset-Fake;$s.profiles[0].intent=$true;$s.profiles[0].before.default_outbound=$bad;$s.phase='restored'
 Reject123 {Restore-IsoSession $s $ops} 'iso_local_profile_baseline_requires_explicit_review'
 Assert ($script:writes.Count -eq 0) 'old terminal label cannot authorize repair'
}
Reset-Fake;$ops.Remove('ProfileEffectiveRead')
Reject123 {Invoke-IsoArm $s $plan $ops} 'iso_recovery_effective_reader_required'
Assert ($script:writes.Count -eq 0) 'no adapter fallback'
Reset-Fake;$ops.ProfileEffectiveRead={param($n)$x=IsoCopy $script:profiles[$n];$x.default_outbound='Block';$x}
Reject123 {Invoke-IsoArm $s $plan $ops} 'iso_profile_baseline_local_effective_mismatch'
Assert ($script:writes.Count -eq 0) 'effective mismatch before creating transport'
# Exact Block baseline remains Block: never invent normal-mode Allow during Restore.
Reset-Fake;foreach($p in $s.profiles){$script:profiles[$p.name].default_outbound='Block';$p.before=IsoCopy $script:profiles[$p.name]}
$null=Invoke-IsoArm $s $plan $ops;$null=Restore-IsoSession $s $ops
Assert ($s.phase -ceq 'restored' -and @($script:profiles.Values|Where-Object{$_.default_outbound -cne 'Block'}).Count -eq 0) 'original Block preserved'
# A previously restored session must re-read rules, local and effective profiles.
foreach($kind in @('local','effective','foreign','owned')){
 Reset-Fake;$null=Invoke-IsoArm $s $plan $ops;$null=Restore-IsoSession $s $ops
 switch($kind){
  'local'{$script:profiles.Domain.default_outbound='Block';$code='iso_restored_local_profile_mismatch'}
  'effective'{$ops.ProfileEffectiveRead={param($n)$x=IsoCopy $script:profiles[$n];$x.default_outbound='Block';$x};$code='iso_restored_effective_profile_mismatch'}
  'foreign'{$script:images.foreign.filter='changed';$code='iso_restored_foreign_image_mismatch'}
  'owned'{$script:images.owned=IsoCopy $script:images.foreign;$code='iso_restored_owned_rule_not_absent'}
 }
 $count=$script:writes.Count;Reject123 {Restore-IsoSession $s $ops} $code
 Assert ($script:writes.Count -eq $count) ('read-only terminal recheck '+$kind)
}
Reset-Fake;$null=Invoke-IsoArm $s $plan $ops
$ops.ProfileEffectiveRead={param($n)$x=IsoCopy $script:profiles[$n];$x.default_outbound='Block';$x}
Reject123 {Restore-IsoSession $s $ops} 'iso_restored_effective_profile_mismatch'
Assert ($s.phase -ceq 'restoring') 'effective policy prevents success stamp'
Reset-Fake;$null=Invoke-IsoArm $s $plan $ops
$ops.Hook={param($point)if($point -ceq 'profile_restored:Private'){$script:profiles.Domain.default_outbound='Block'}}
Reject123 {Restore-IsoSession $s $ops} 'iso_restored_local_profile_mismatch'
Assert ($s.phase -ceq 'restoring') 'earlier profile drift caught at final sweep'
Reset-Fake;$null=Invoke-IsoArm $s $plan $ops
$ops.Hook={param($point)if($point -ceq 'profile_restored:Public'){$script:images.foreign.filter='changed'}}
Reject123 {Restore-IsoSession $s $ops} 'iso_restored_foreign_image_mismatch'
Assert ($s.phase -ceq 'restoring') 'earlier rule drift caught at final sweep'
# Real native adapter code, cmdlets mocked: NotConfigured is never sent locally.
. (Join-Path $Root 'app/isolation-native.ps1')
$script:profileSets=@();$script:profileDefault123='NotConfigured'
function Set-NetFirewallProfile{param($PolicyStore,$Name,$DefaultOutboundAction,$ErrorAction)$script:profileSets+=,($Name+':'+$DefaultOutboundAction)}
Reject123 {IsoProfileSet 'Domain' 'NotConfigured'} 'iso_profile_input'
Assert ($script:profileSets.Count -eq 0) 'unsupported local setter not called'
IsoProfileSet 'Domain' 'Allow';IsoProfileSet 'Public' 'Block';Assert ($script:profileSets.Count -eq 2) 'explicit supported values still work'
function Get-NetFirewallProfile{param($PolicyStore,$ErrorAction)foreach($n in @('Domain','Private','Public')){[pscustomobject]@{Name=$n;DefaultOutboundAction=$script:profileDefault123;Enabled='True';AllowLocalFirewallRules='True';DisabledInterfaceAliases=@('NotConfigured')}}}
function IsoAssertNoOtherEngine{param($s)[pscustomobject]@{read_only=$true}}
function IsoPrepareForeignAllows{param($s)return ,@()}
function Get-NetFirewallSecurityFilter{param($PolicyStore,$ErrorAction)return @()}
$policy=[pscustomobject]@{schema='unified-isolation-policy-1';owner=('a'*32);connection='direct';whitelist=@([pscustomobject]@{remote_addresses=@('192.0.2.10');protocol='TCP';remote_port='443'})}
Reject123 {IsoPrepare $policy $null} 'iso_local_profile_baseline_requires_explicit_review'
Assert ($script:profileSets.Count -eq 2) 'Prepare does not repair baseline'
# Extract exact worker Summary definition without executing admin/task entrypoint.
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/isolation-worker.ps1'),[ref]$t,[ref]$e)
Assert ($e.Count -eq 0) 'worker parse'
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'IsoSummary'},$true)
. ([scriptblock]::Create($node.Extent.Text))
function IsoNativeOps{return $script:ops}
$script:taskPresent=$false
function IsoTaskRead{param($s)if($script:taskPresent){return [pscustomobject]@{State='Ready'}};return $null}
$script:IsoRoot=Join-Path ([IO.Path]::GetTempPath()) ('nonexistent-hf123-'+[guid]::NewGuid().ToString('N'))
Reset-Fake;$null=Invoke-IsoArm $s $plan $ops;$null=Restore-IsoSession $s $ops
$s.plan=$null;$r=IsoSummary $s;Assert ($r.restoration_verified_now -and -not $r.restoration_reboot_qualified) 'fresh summary not reboot certificate'
$count=$script:writes.Count;$script:profiles.Domain.default_outbound='Block';$s.plan=$null;$r=IsoSummary $s
Assert (-not $r.restoration_verified_now -and $r.health -ceq 'restoration_unverified:iso_restored_local_profile_mismatch') 'summary invalidates stale restored'
Assert ($script:writes.Count -eq $count) 'summary never auto-repairs'
Reset-Fake;$s.phase='restored';$s.profiles[0].intent=$true;$s.profiles[0].before.default_outbound='NotConfigured';$s.plan=$null;$r=IsoSummary $s
Assert (-not $r.restoration_verified_now -and $r.health -ceq 'restoration_unverified:iso_local_profile_baseline_requires_explicit_review') 'legacy summary explicit review not fabricated Allow'
Reset-Fake;$null=Invoke-IsoArm $s $plan $ops;$null=Restore-IsoSession $s $ops;$script:taskPresent=$true;$s.plan=$null;$r=IsoSummary $s
Assert (-not $r.restoration_verified_now -and $r.health -ceq 'restoration_unverified_controller_task_present') 'stopped but registered task blocks success'
. (Join-Path $Root 'app/policy-mode-model.ps1')
foreach($flag in @($null,'True',$false)){
 $value=[pscustomobject]@{phase='restored';restoration_verified_now=$flag}
 $text=Get-IsolationStatusText $value 'fixture'
 Assert ($text.Contains('تطبیق وضعیت فعلی تأیید نشد')) 'UI never trusts restored label/string flag'
}
$text=Get-IsolationStatusText ([pscustomobject]@{phase='restored';restoration_verified_now=$true}) 'fixture'
Assert ($text.Contains('در بررسی فعلی تأیید شد') -and $text.Contains('راه‌اندازی مجدد هنوز تأیید نشده')) 'UI limits success to current snapshot'
# Post-task-cleanup summary must still gate the worker success result.
$ifs=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst]},$true))
$branches=@(foreach($i in $ifs){foreach($c in $i.Clauses){if($c.Item1.Extent.Text -ceq '$Mode -ceq ''Restore'' -and $null -ne $s'){$c.Item2}}})
Assert ($branches.Count -eq 1 -and $branches[0].Extent.Text.Contains('iso_restore_post_cleanup_verification_failed')) 'worker post-cleanup verification gate exists'
$restoreBlock=[scriptblock]::Create($branches[0].Extent.Text.Trim().Substring(1,$branches[0].Extent.Text.Trim().Length-2))
$script:restoreEvents123=@()
function Restore-IsoSession{param($Session,$Ops)$script:restoreEvents123+=,'restore';$Session.phase='restored';return $Session}
function IsoTaskStop{param($Session)$script:restoreEvents123+=,'stop'}
function IsoSummary{param($Session)[pscustomobject]@{restoration_verified_now=$false}}
$Request=Join-Path ([IO.Path]::GetTempPath()) ('hf123-worker-'+[guid]::NewGuid().ToString('N')+'.json')
try{
 [IO.File]::WriteAllText($Request,'{"confirmation":"RESTORE ISOLATION"}')
 $s=[pscustomobject]@{phase='armed'};$started=$false;$result=$null
 Reject123 {& $restoreBlock} 'iso_restore_post_cleanup_verification_failed'
 Assert (($script:restoreEvents123 -join ',') -ceq 'restore,stop') 'post-cleanup failure never returns worker success'
}finally{Remove-Item -LiteralPath $Request -Force}
$result=[ordered]@{suite='HF123-recovery-contract-and-terminal-revalidation';assertions=$script:checks;passed=$true;Windows_native_API_executed=$false;reboot_qualified=$false;no_leak_certified=$false;ready_for_apply=$false}
$result|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Root 'evidence/isolation-recovery-hf123-tests.json') -Encoding UTF8
$result|ConvertTo-Json -Compress
