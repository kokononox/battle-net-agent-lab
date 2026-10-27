param([string]$Root=(Join-Path $PSScriptRoot '..'))
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. (Join-Path $Root 'lab/session-core.ps1');. (Join-Path $Root 'lab/native.ps1');. (Join-Path $Root 'app/isolation-core.ps1');. (Join-Path $Root 'app/isolation-native.ps1');. (Join-Path $Root 'app/normal-exit-record.ps1')
$script:checks=0
function Check124($v,$m){$script:checks++;if(-not $v){throw $m}}
function Reject124($Block,$Code){$caught='';try{& $Block|Out-Null}catch{$caught=$_.Exception.Message};Check124 ($caught -ceq $Code) ('expected '+$Code+' got '+$caught)}
function Reset124{
 $script:record124=$null;$script:recordWrites124=0;$script:task124=0;$script:taskCalls124=0;$script:journalCalls124=0;$script:mode124='';$script:adminCalls124=0
 $script:owned124='UnifiedFW-ISO-'+('a'*32)+'-'+('c'*24)
 $script:foreign124=[pscustomobject]@{rule=[pscustomobject]@{Name='fixture-foreign';Enabled='1';Action='Allow'};filter='full-before-image'}
 $script:images124=@{'fixture-foreign'=(IsoCopy $script:foreign124)}
 $script:profiles124=@{};foreach($n in @('Domain','Private','Public')){$script:profiles124[$n]=[pscustomobject][ordered]@{name=$n;default_outbound='Allow';enabled='True';allow_local_rules='True'}}
 $script:s124=[pscustomobject][ordered]@{schema='unified-isolation-session-1';id=('b'*32);owner=('a'*32);phase='restored';entries=@([pscustomobject]@{name=$script:owned124;intent=$true;removed=$true});foreign=@([pscustomobject]@{name='fixture-foreign';intent=$true;restored=$true;before=(IsoCopy $script:foreign124)});profiles=@(foreach($n in @('Domain','Private','Public')){[pscustomobject]@{name=$n;intent=$true;restored=$true;before=[pscustomobject]@{name=$n;default_outbound='NotConfigured'}}})}
 $script:ops124=@{
  JournalDigest={param($s)$script:journalCalls124++;if($script:mode124 -ceq 'journal_race' -and $script:journalCalls124 -ge 2){return ('e'*64)};UHash (UJson $s)}
  ControllerCount={$script:taskCalls124++;if($script:mode124 -ceq 'task_appears' -and $script:taskCalls124 -ge 2){return 1};return $script:task124}
  Read={param($n)if($script:images124.ContainsKey($n)){IsoCopy $script:images124[$n]}else{$null}}
  ProfileRead={param($n)IsoCopy $script:profiles124[$n]}
  ProfileEffectiveRead={param($n)$p=IsoCopy $script:profiles124[$n];if($script:mode124 -ceq 'effective_block'){$p.default_outbound='Block'};$p}
  ReadRecord={param($s)if($null -ne $script:record124){return IsoCopy $script:record124};return $null}
  WriteRecord={param($s,$r)$script:recordWrites124++;$script:record124=IsoCopy $r;if($script:mode124 -ceq 'readback_corrupt'){$script:record124.review_digest='wrong'};if($script:mode124 -ceq 'postwrite_drift'){$script:profiles124.Public.default_outbound='Block'}}
 }
}
$consent='ACKNOWLEDGE EXISTING NORMAL NETWORK MODE'
Reset124;$legacy=UJson $s124;$v=IsoExitBuildPreview $s124 $ops124
Check124 ($v.digest -cmatch '^[a-f0-9]{64}$' -and $v.review.owned_rules_absent -eq 1 -and $v.review.foreign_images_matched -eq 1) 'fresh preview'
Check124 ($script:recordWrites124 -eq 0 -and (UJson $s124) -ceq $legacy) 'preview preserves journal'
$r=IsoExitRecordNormalMode $s124 $ops124 $consent $v.digest
Check124 ($r.normal_mode_acknowledgment_recorded -and $r.created_this_call -and $r.record_matches_current_snapshot) 'new record'
foreach($k in @('legacy_journal_rewritten','firewall_changed','rules_changed','controller_installed_or_removed','authorizes_isolation','original_restore_verified','reboot_qualified','ready_for_apply','no_leak_certified')){Check124 ($r.$k -ceq $false) ('boundary '+$k)}
Check124 ((UJson $s124) -ceq $legacy -and $s124.profiles[0].before.default_outbound -ceq 'NotConfigured') 'legacy baseline not normalized'
$r2=IsoExitRecordNormalMode $s124 $ops124 $consent $v.digest
Check124 (-not $r2.created_this_call -and $script:recordWrites124 -eq 1) 'idempotent validated record'
foreach($bad in @('','YES','ACKNOWLEDGE NORMAL NETWORK MODE',$consent.ToLowerInvariant())){Reset124;Reject124 {IsoExitRecordNormalMode $s124 $ops124 $bad ('a'*64)} 'normal_exit_explicit_consent_required';Check124 ($script:recordWrites124 -eq 0) 'no consent no writes'}
Reset124;Reject124 {IsoExitRecordNormalMode $s124 $ops124 $consent 'approved=true'} 'normal_exit_review_digest_required'
foreach($case in @('armed','task','owned','foreign','local_block','effective_block','firewall_off','legacy_flag','duplicate_profile','journal_race','task_appears')){
 Reset124
 switch($case){
  'armed'{$s124.phase='armed';$code='normal_exit_legacy_session_review_required'}
  'task'{$script:task124=1;$code='normal_exit_controller_task_present_or_unknown'}
  'owned'{$script:images124[$script:owned124]=IsoCopy $script:foreign124;$code='normal_exit_owned_rule_not_removed'}
  'foreign'{$script:images124['fixture-foreign'].filter='changed';$code='normal_exit_foreign_before_image_mismatch'}
  'local_block'{$script:profiles124.Private.default_outbound='Block';$code='normal_exit_current_profile_not_normal_allow'}
  'effective_block'{$script:mode124='effective_block';$code='normal_exit_current_profile_not_normal_allow'}
  'firewall_off'{$script:profiles124.Domain.enabled='False';$code='normal_exit_current_profile_not_normal_allow'}
  'legacy_flag'{$s124.profiles[0].restored='True';$code='normal_exit_legacy_profile_review_required'}
  'duplicate_profile'{$s124.profiles[1].name='Domain';$code='normal_exit_legacy_shape'}
  'journal_race'{$script:mode124='journal_race';$code='normal_exit_journal_changed_during_review'}
  'task_appears'{$script:mode124='task_appears';$code='normal_exit_controller_appeared'}
 }
 Reject124 {IsoExitBuildPreview $s124 $ops124} $code
 Check124 ($script:recordWrites124 -eq 0) ('preflight no record '+$case)
}
Reset124;$v=IsoExitBuildPreview $s124 $ops124;$script:profiles124.Domain.allow_local_rules='NotConfigured'
Reject124 {IsoExitRecordNormalMode $s124 $ops124 $consent $v.digest} 'normal_exit_review_stale'
Check124 ($script:recordWrites124 -eq 0) 'stale preview not written'
Reset124;$v=IsoExitBuildPreview $s124 $ops124;$script:mode124='readback_corrupt'
Reject124 {IsoExitRecordNormalMode $s124 $ops124 $consent $v.digest} 'normal_exit_record_readback_failed'
Reset124;$v=IsoExitBuildPreview $s124 $ops124;$script:mode124='postwrite_drift'
Reject124 {IsoExitRecordNormalMode $s124 $ops124 $consent $v.digest} 'normal_exit_current_profile_not_normal_allow'
Check124 ($script:recordWrites124 -eq 1 -and $null -ne $script:record124) 'stale written evidence retained not erased or trusted'
foreach($case in @('authority','consent','extra')){
 Reset124;$v=IsoExitBuildPreview $s124 $ops124;$null=IsoExitRecordNormalMode $s124 $ops124 $consent $v.digest
 switch($case){'authority'{$script:record124.authorizes_isolation=$true};'consent'{$script:record124.consent='YES'};'extra'{$script:record124|Add-Member NoteProperty force_allow $true}}
 Reject124 {IsoExitRecordNormalMode $s124 $ops124 $consent $v.digest} 'normal_exit_existing_record_conflict'
 Check124 ($script:recordWrites124 -eq 1) 'conflicting record not overwritten'
}
Reset124;$script:task124='0';Reject124 {IsoExitBuildPreview $s124 $ops124} 'normal_exit_controller_task_present_or_unknown'
$script:taskFixtures124=@()
function Get-ScheduledTask{param($ErrorAction)return $script:taskFixtures124}
Check124 ((IsoExitControllerCount) -is [int] -and (IsoExitControllerCount) -eq 0) 'native known task counter typed'
$script:taskFixtures124=@([pscustomobject]@{TaskName='UnifiedFW-Isolation-fixture';State='Ready'},[pscustomobject]@{TaskName='Unrelated-fixture';State='Running'})
Check124 ((IsoExitControllerCount) -eq 1) 'native task counter excludes unrelated names but includes stopped known task'
# Real file helpers on Linux: checksum, no overwrite and byte-preserved legacy journal.
Reset124;$script:IsoRoot=Join-Path ([IO.Path]::GetTempPath()) ('normal-exit-124-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($script:IsoRoot)
try{
 USave $script:IsoRoot $s124;$path=Join-Path $script:IsoRoot 'session.json';$before=(Get-FileHash $path).Hash
 Check124 ((IsoExitJournalDigest $s124) -ceq $before.ToLowerInvariant()) 'real legacy digest'
 $v=IsoExitBuildPreview $s124 $ops124;$null=IsoExitRecordNormalMode $s124 $ops124 $consent $v.digest
 IsoExitWriteRecord $s124 $script:record124;$round=IsoExitReadRecord $s124
 Check124 (UEqual $round $script:record124) 'real file roundtrip'
 $caught=$false;try{IsoExitWriteRecord $s124 $script:record124}catch{$caught=$true};Check124 $caught 'CreateNew refuses overwrite'
 Check124 ((Get-FileHash $path).Hash -ceq $before) 'legacy journal unchanged on disk'
 $recordPath=IsoExitRecordPath $s124;$envelope=[IO.File]::ReadAllText($recordPath)|ConvertFrom-Json;$envelope.payload+='tamper';[IO.File]::WriteAllText($recordPath,(UJson $envelope))
 Reject124 {IsoExitReadRecord $s124} 'normal_exit_record_checksum'
}finally{Remove-Item -LiteralPath $script:IsoRoot -Recurse -Force}
# Production wrapper lock/root cleanup with mocked admin/root/native ops; no Windows ACL claim.
Reset124;$temp=Join-Path ([IO.Path]::GetTempPath()) ('normal-exit-lock-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($temp);USave $temp $s124
function UAdmin{$script:adminCalls124++;if($script:mode124 -ceq 'not_admin'){throw 'fixture_admin_required'}}
function IsoSecureRoot{param($Create)Check124 (-not $Create) 'wrapper never creates a new journal root';return $temp}
function IsoExitNativeOps{return $script:ops124}
try{
 $script:IsoRoot='previous-root';$review=Invoke-IsoNormalExitOperation -Operation Review
 Check124 ($review.review_digest -cmatch '^[a-f0-9]{64}$' -and $script:adminCalls124 -eq 1 -and $script:IsoRoot -ceq 'previous-root') 'wrapper requires admin and restores caller root'
 $script:mode124='not_admin';Reject124 {Invoke-IsoNormalExitOperation -Operation Review} 'fixture_admin_required';Check124 ($script:IsoRoot -ceq 'previous-root') 'admin failure does not erase caller root';$script:mode124=''
 $held=UOpenPrivateFile (Join-Path $temp 'operation.lock') ([IO.FileMode]::OpenOrCreate)
 try{$caught=$false;try{Invoke-IsoNormalExitOperation -Operation Review|Out-Null}catch{$caught=$true};Check124 ($caught -and $script:recordWrites124 -eq 0 -and $script:IsoRoot -ceq 'previous-root') 'busy lock rejects without record'}finally{$held.Dispose()}
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
# Static write boundary: no policy/rule/task write commands, no legacy USave, no bypass.
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/normal-exit-record.ps1'),[ref]$t,[ref]$e);Check124 ($e.Count -eq 0) 'parse'
$forbidden='^(Set-Net.*|New-Net.*|Remove-Net.*|Enable-Net.*|Disable-Net.*|Register-ScheduledTask|Unregister-ScheduledTask|Start-ScheduledTask|Stop-ScheduledTask|Set-ExecutionPolicy|Resolve-DnsName|USave|IsoSave|Restore-IsoSession|Invoke-IsoArm|Invoke-IsoUpdate)$'
foreach($n in $ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){if($n.GetCommandName() -match $forbidden){throw ('unexpected mutation '+$n.GetCommandName())}}
Check124 $true 'no firewall/task/legacy-journal writes'
$result=[ordered]@{suite='HF124-separate-normal-mode-exit-record';assertions=$script:checks;passed=$true;Linux_file_IO_tested=$true;Windows_native_API_or_ACL_tested=$false;controller_integration_or_upgrade_tested=$false;original_restore_verified=$false;reboot_qualified=$false;ready_for_apply=$false}
$result|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Root 'evidence/normal-exit-hf124-tests.json') -Encoding UTF8
$result|ConvertTo-Json -Compress
