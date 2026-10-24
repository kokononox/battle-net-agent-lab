param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $Root 'lab/session-core.ps1')
. (Join-Path $Root 'lab/recovery-core.ps1')
$script:checks=0;$script:db=@{};$script:removes=0
function Check([bool]$ok,[string]$why){$script:checks++;if(-not $ok){throw ('assertion:'+ $why)}}
function Throws([scriptblock]$body,[string]$pattern){$caught=$false;try{& $body|Out-Null}catch{$caught=$true;Check ($_.Exception.Message -like $pattern) ('error:'+ $_.Exception.Message)};Check $caught 'expected_throw'}
function Clone($v){ConvertFrom-Json -InputObject (UJson $v)}
$owner='a'*32;$sessionID='b'*32;$name='UnifiedFW-'+$owner+'-blacklist-'+('c'*24);$second='UnifiedFW-'+$owner+'-blacklist-'+('d'*24)
$image=[pscustomobject][ordered]@{rule=[pscustomobject]@{Enabled='2';InstanceID=$name;Description='known-disabled-fixture'};filters=[pscustomobject]@{Package=$null;LocalPort=@('Any');RemotePort=@('9');Protocol='TCP';RemoteAddress=@('1.1.1.1')}}
$expected=[pscustomobject][ordered]@{owner=$owner;session_id=$sessionID;target_name=$name;never_created_name=$second;images=[pscustomobject][ordered]@{PersistentStore=(Clone $image);ActiveStore=(Clone $image)}}
$base=Join-Path ([IO.Path]::GetTempPath()) ('KnownRecovery-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($base)
$read={param($n,$store) if($script:db.ContainsKey($store+'/'+$n)){Clone $script:db[$store+'/'+$n]}else{$null}}
$remove={param($n) $script:removes++;$script:db.Remove('PersistentStore/'+$n);$script:db.Remove('ActiveStore/'+$n)}
function Fresh([string]$label){
 $dir=Join-Path $base $label;$null=[IO.Directory]::CreateDirectory($dir)
 $script:db=@{'foreign'=[pscustomobject]@{unchanged=$true}};$script:db['PersistentStore/'+$name]=Clone $image;$script:db['ActiveStore/'+$name]=Clone $image;$script:removes=0
 $rules=@([pscustomobject]@{name=$name;owner=$owner;component='blacklist'},[pscustomobject]@{name=$second;owner=$owner;component='blacklist'})
 $s=[pscustomobject][ordered]@{schema='unified-owned-session-1';id=$sessionID;owner=$owner;phase='restoring';plan=[pscustomobject]@{owner=$owner;rules=$rules};entries=@([pscustomobject]@{name=$name;intent=$true;removed=$false;disabled_image=$null;enabled_image=$null},[pscustomobject]@{name=$second;intent=$false;removed=$false;disabled_image=$null;enabled_image=$null})}
 USave $dir $s;return $dir
}
try{
 $dir=Fresh 'normal';$before=[IO.File]::ReadAllText((Join-Path $dir 'session.json'))
 $r=InvokeKnownDisabledRecovery $dir $expected $read $remove
 Check ($r.ok -and $r.owned_session_restored -and $script:removes -eq 1) 'single_known_disabled_rule_removed'
 Check ($script:db.Count -eq 1 -and $script:db.ContainsKey('foreign')) 'foreign_preserved'
 Check ((ULoad $dir).phase -ceq 'restored') 'journal_finished_without_sealing_orphan'
 Check ([IO.File]::ReadAllText((Join-Path $dir ('known-recovery-'+$sessionID+'-before.json'))) -ceq $before) 'original_journal_backed_up'
 $r=InvokeKnownDisabledRecovery $dir $expected $read $remove;Check ($r.already_completed -and $script:removes -eq 1) 'repeat_is_idempotent'
 foreach($point in @('recovery_intent_saved','recovery_before_remove','recovery_after_remove','recovery_before_journal_restore')){
  $dir=Fresh $point;$script:fail=$point;$hook={param($at) if($at -ceq $script:fail){throw 'injected'}}
  Throws {InvokeKnownDisabledRecovery $dir $expected $read $remove $hook} 'injected'
  $r=InvokeKnownDisabledRecovery $dir $expected $read $remove
  Check ($r.ok -and (ULoad $dir).phase -ceq 'restored' -and $script:removes -eq 1) 'interrupted_recovery_resumes'
 }
 foreach($case in @('enabled','filter_drift','active_drift','second_appeared','missing_without_intent','session_owner','phase','intent_flag','existing_image')){
  $dir=Fresh ('reject-'+$case);$s=ULoad $dir
  switch($case){
   enabled{$script:db['PersistentStore/'+$name].rule.Enabled='1';$script:db['ActiveStore/'+$name].rule.Enabled='1'}
   filter_drift{$script:db['PersistentStore/'+$name].filters.RemotePort=@('443')}
   active_drift{$script:db['ActiveStore/'+$name].filters.RemotePort=@('443')}
   second_appeared{$script:db['PersistentStore/'+$second]=Clone $image}
   missing_without_intent{$script:db.Remove('PersistentStore/'+$name);$script:db.Remove('ActiveStore/'+$name)}
   session_owner{$s.owner='f'*32;USave $dir $s}
   phase{$s.phase='applied';USave $dir $s}
   intent_flag{$s.entries[0].intent=$false;USave $dir $s}
   existing_image{$s.entries[0].disabled_image=Clone $image;USave $dir $s}
  }
  $before=UJson $script:db;$journal=[IO.File]::ReadAllText((Join-Path $dir 'session.json'))
  Throws {InvokeKnownDisabledRecovery $dir $expected $read $remove} '*'
  Check ($script:removes -eq 0 -and (UJson $script:db) -ceq $before) 'conflict_does_not_delete'
  Check ([IO.File]::ReadAllText((Join-Path $dir 'session.json')) -ceq $journal) 'conflict_does_not_rewrite_session'
 }
 $dir=Fresh 'concurrent';$hook={param($at) if($at -ceq 'recovery_before_remove'){$script:db['ActiveStore/'+$name].rule.Enabled='1'}}
 Throws {InvokeKnownDisabledRecovery $dir $expected $read $remove $hook} 'recovery_full_image_drift:*';Check ($script:removes -eq 0) 'reread_catches_concurrent_enable'
 $dir=Fresh 'reappeared';$null=InvokeKnownDisabledRecovery $dir $expected $read $remove;$script:db['PersistentStore/'+$name]=Clone $image;$script:db['ActiveStore/'+$name]=Clone $image
 Throws {InvokeKnownDisabledRecovery $dir $expected $read $remove} 'recovery_rule_reappeared_after_completion';Check ($script:removes -eq 1) 'completed_repair_never_deletes_reappeared_rule'
 $report=[ordered]@{passed=$true;assertions=$script:checks;recovery_interruption_checkpoints=4;windows_executed=$false;backend='file journal and in-memory two-store test doubles';general_force_restore_added=$false}
 [IO.File]::WriteAllText((Join-Path $Root 'evidence/known-recovery-tests.json'),(UJson $report));$report|ConvertTo-Json -Compress
}finally{if([IO.Directory]::Exists($base)){[IO.Directory]::Delete($base,$true)}}
