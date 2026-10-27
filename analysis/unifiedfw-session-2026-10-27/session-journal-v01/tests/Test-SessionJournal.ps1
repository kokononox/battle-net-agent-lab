param([string]$Root='/data/ufw-session-journal-v01')
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$m=Import-Module (Join-Path $Root 'source/Ufw.SessionJournal.psm1') -Force -PassThru
$script:checks=0
function Check($b,$label){$script:checks++;if(-not $b){throw $label}}
function Clone-JFixture($v){ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $v -Depth 32 -Compress)}
function Rows-JFixture($default='Allow'){@(foreach($n in @('Domain','Private','Public')){[pscustomobject]@{name=$n;local_outbound=$default;effective_outbound=$default;local_enabled='True';effective_enabled='True';local_allow_local_rules='NotConfigured';effective_allow_local_rules='True'}})}
function Observation-JFixture {return [pscustomobject]@{schema='ufw-readonly-profile-preflight-01';completed=$true;two_observations_match=$true;firewall_change_requested=$false;ready_for_apply=$false;assessment=[pscustomobject]@{explicit_local_outbound_baseline_present=$true;profile_fields_compatible_for_later_review=$true;profiles=(Rows-JFixture)}}}
function Draft-JFixture {& $m {param($o)& $script:Core {param($o)New-UfwProfileRecoveryDraft $o} $o} (Observation-JFixture)}
function Hash-JFixture($d){& $m {param($d)Get-UfwDraftBaselineHash $d} $d}
function Data-JFixture($id=('a'*32)){
 $d=Draft-JFixture
 return [pscustomobject][ordered]@{receipt=[pscustomobject][ordered]@{schema='ufw-preparation-consent-01';session_id=$id;baseline_sha256=(Hash-JFixture $d);challenge_sha256=('c'*64);purpose='prepare_profile_journal_only';consent_validated=$true;created_utc='2026-10-27 04:00:00.0000000 UTC';authorizes_firewall_change=$false;ready_for_apply=$false};draft=$d}
}
function New-JFixtureRoot($id=('a'*32)){
 $parent=Join-Path ([IO.Path]::GetTempPath()) ('ufw-journal-test-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($parent)
 $dir=Join-Path $parent ('UfwInstaller-Session-'+$id);& $m {param($p)New-UfwPrivateJournalDirectory $p} $dir
 $script:cleanup+=,$parent;return $dir
}
function Read-JFixture($dir,$id=('a'*32)){& $m {param($p,$id)Read-UfwPreparationJournal $p $id} $dir $id}
function Append-JFixture($dir,$data,$head=('0'*64),$kind='prepared',$id=('a'*32)){& $m {param($p,$id,$h,$k,$d)Add-UfwPreparationCheckpoint $p $id $h $k $d} $dir $id $head $kind $data}
function Reject-JFixture($block,$code){$caught='';try{& $block|Out-Null}catch{$caught=$_.Exception.GetBaseException().Message};Check ($caught -ceq $code) ('expected '+$code+' got '+$caught)}
$script:cleanup=@()
try{
 $dir=New-JFixtureRoot;$data=Data-JFixture;$one=Append-JFixture $dir $data;$read=Read-JFixture $dir
 Check ($one.readback_verified -and $read.sequence -eq 1 -and $read.last.data.draft.phase -ceq 'prepared') 'real filesystem roundtrip'
 Check (-not $read.last.data.receipt.authorizes_firewall_change -and -not $read.last.data.draft.execution_authorized) 'receipt is not execution consent'
 $p=Join-Path $dir '00000001.json';$original=[IO.File]::ReadAllBytes($p)
 Reject-JFixture {Append-JFixture $dir $data} 'ufw_journal_stale_head'
 Check ([Convert]::ToBase64String([IO.File]::ReadAllBytes($p)) -ceq [Convert]::ToBase64String($original)) 'stale head cannot overwrite'
 $held=& $m {param($p)Open-UfwPrivateJournalFile (Join-Path $p 'operation.lock') ([IO.FileMode]::OpenOrCreate)} $dir
 try{$caught=$false;try{Append-JFixture $dir $data $one.head 'model_checkpoint'|Out-Null}catch{$caught=($_.Exception.GetBaseException() -is [IO.IOException])};Check $caught 'real exclusive lock refuses second writer'}finally{$held.Dispose()}
 $changed=Clone-JFixture $data;$changed.draft.phase='arming';foreach($e in $changed.draft.entries){$e.intent=$true}
 $two=Append-JFixture $dir $changed $one.head 'model_checkpoint';Check ((Read-JFixture $dir).sequence -eq 2) 'append not replace'
 $bad=Clone-JFixture $changed;$bad.draft.entries[0].intent=$false;Reject-JFixture {Append-JFixture $dir $bad $two.head 'model_checkpoint'} 'ufw_journal_flag_regression'
 $bad=Clone-JFixture $changed;$bad.draft.phase='prepared';Reject-JFixture {Append-JFixture $dir $bad $two.head 'model_checkpoint'} 'ufw_journal_phase_regression'
 $bad=Clone-JFixture $changed;$bad.draft.entries[0].before.local_outbound='Block';$bad.draft.entries[0].before.effective_outbound='Block';Reject-JFixture {Append-JFixture $dir $bad $two.head 'model_checkpoint'} 'ufw_journal_baseline_changed'
 $bad=Clone-JFixture $changed;$bad.receipt.authorizes_firewall_change=$true;Reject-JFixture {Append-JFixture $dir $bad $two.head 'model_checkpoint'} 'ufw_journal_receipt_invalid'
 $bad=Clone-JFixture $changed;$bad.receipt.consent_validated='True';Reject-JFixture {Append-JFixture $dir $bad $two.head 'model_checkpoint'} 'ufw_journal_receipt_invalid'
 $bad=Clone-JFixture $changed;$bad.receipt.session_id='b'*32;Reject-JFixture {Append-JFixture $dir $bad $two.head 'model_checkpoint'} 'ufw_journal_receipt_invalid'
 $bad=Clone-JFixture $changed;$bad.receipt.challenge_sha256='d'*64;Reject-JFixture {Append-JFixture $dir $bad $two.head 'model_checkpoint'} 'ufw_journal_receipt_changed'
 Reject-JFixture {Append-JFixture $dir $changed $two.head 'prepared'} 'ufw_journal_checkpoint_kind'
 $bad=Clone-JFixture $changed;$bad.draft|Add-Member NoteProperty UnknownAuthority $true;Reject-JFixture {Append-JFixture $dir $bad $two.head 'model_checkpoint'} 'ufw_journal_draft_shape'
 $bad=Clone-JFixture $changed;$bad.draft.entries[0]|Add-Member NoteProperty UnknownFlag $true;Reject-JFixture {Append-JFixture $dir $bad $two.head 'model_checkpoint'} 'ufw_journal_draft_shape'
 $bad=Clone-JFixture $changed;$bad.receipt.created_utc='2026-99-27 04:00:00.0000000 UTC';Reject-JFixture {Append-JFixture $dir $bad $two.head 'model_checkpoint'} 'ufw_journal_receipt_invalid'
 $reordered=Clone-JFixture $changed;$receipt=[ordered]@{};foreach($key in @($reordered.receipt.PSObject.Properties.Name|Sort-Object -Descending)){$receipt[$key]=$reordered.receipt.$key};$reordered.receipt=[pscustomobject]$receipt
 $three=Append-JFixture $dir $reordered $two.head 'model_checkpoint';Check ($three.sequence -eq 3) 'receipt property order is not semantic drift'
 $other=New-JFixtureRoot ('b'*32);[IO.File]::WriteAllBytes((Join-Path $other '00000001.json'),$original);Reject-JFixture {Read-JFixture $other ('b'*32)} 'ufw_journal_chain'
 $corrupt=New-JFixtureRoot;[IO.File]::WriteAllText((Join-Path $corrupt '00000001.json'),'{"payload":"bad","sha256":"bad"}');Reject-JFixture {Read-JFixture $corrupt} 'ufw_journal_checksum'
 $gap=New-JFixtureRoot;[IO.File]::WriteAllBytes((Join-Path $gap '00000002.json'),$original);Reject-JFixture {Read-JFixture $gap} 'ufw_journal_sequence_or_size'
 $unknown=New-JFixtureRoot;[IO.File]::WriteAllText((Join-Path $unknown 'session.json'),'legacy fixture');Reject-JFixture {Read-JFixture $unknown} 'ufw_journal_unexpected_child'
 $partial=New-JFixtureRoot;[IO.File]::WriteAllText((Join-Path $partial '00000001.json'),'{');$caught=$false;try{Read-JFixture $partial|Out-Null}catch{$caught=$true};Check $caught 'partial record fails without fallback'
 Check ([IO.File]::ReadAllText((Join-Path $partial '00000001.json')) -ceq '{') 'partial record retained not overwritten'
 $sized=New-JFixtureRoot;[IO.File]::WriteAllText((Join-Path $sized '00000001.json'),('x'*262145));Reject-JFixture {Read-JFixture $sized} 'ufw_journal_sequence_or_size'
 # Preparation consent with strict challenge, pre/post revalidation, expiry, cancellation.
 $script:mode='';$script:readCount=0;$script:saveCount=0;$script:clockCount=0;$script:shown=0;$script:captured=$null
 $ops=@{
  ReadObservation={$script:readCount++;$o=Observation-JFixture;if(($script:mode -ceq 'stale' -and $script:readCount -eq 2) -or ($script:mode -ceq 'post_stale' -and $script:readCount -eq 3)){$o.assessment.profiles[0].local_outbound='Block';$o.assessment.profiles[0].effective_outbound='Block'};return $o}
  ShowReview={param($d,$c)$script:shown++;if($c -cnotmatch '^PREPARE JOURNAL [a-f0-9]{32} [a-f0-9]{32}$'){throw 'fixture_bad_challenge'}}
  ReadAnswer={param($c)switch($script:mode){cancel{return ''};wrong{return 'YES'};lower{return $c.ToLowerInvariant()};boolean{return $true};default{return $c}}}
  UtcNow={$script:clockCount++;$t=[datetime]::Parse('2026-10-27T04:00:00Z').ToUniversalTime();if($script:clockCount -ge 3 -and $script:mode -ceq 'post_expired'){return $t.AddSeconds(121)};if($script:clockCount -gt 1){if($script:mode -ceq 'expired'){return $t.AddSeconds(121)};if($script:mode -ceq 'backwards'){return $t.AddSeconds(-1)}};return $t}
  SavePreparation={param($r,$d)$script:saveCount++;$script:captured=[pscustomobject]@{receipt=$r;draft=$d};if($script:mode -ceq 'save_error'){throw 'PRIVATE_USER_PATH'};return [pscustomobject]@{sequence=1;head=('f'*64);readback_verified=($script:mode -cne 'unverified')}}
 }
 $invoke={param($ops)& $m {param($ops)Invoke-UfwPreparationConsentCallbacks $ops} $ops}
 $r=& $invoke $ops;Check ($r.completed -and $r.consent_received -and $r.journal_preparation_recorded -and $script:readCount -eq 3 -and $script:saveCount -eq 1) 'consent binds fresh pre/post snapshots'
 Check (-not $r.ready_for_apply -and -not $r.firewall_change_requested) 'preparation not Apply'
 Check (($r|ConvertTo-Json) -notmatch 'PREPARE JOURNAL|f{64}|[a-f0-9]{32}') 'public result omits challenge, identity and digest'
 foreach($mode in @('cancel','wrong','lower','boolean')){
  $script:mode=$mode;$script:readCount=0;$script:saveCount=0;$script:clockCount=0;$r=& $invoke $ops
  Check ($r.completed -and $r.code -ceq 'ufw_journal_cancelled_no_write' -and $script:saveCount -eq 0 -and -not $r.journal_write_attempted) ('cancel/wrong not consent '+$mode)
 }
 foreach($case in @(@('stale','ufw_journal_baseline_changed_after_prompt'),@('expired','ufw_journal_consent_expired_or_clock_changed'),@('backwards','ufw_journal_consent_expired_or_clock_changed'))){
  $script:mode=$case[0];$script:readCount=0;$script:saveCount=0;$script:clockCount=0;$r=& $invoke $ops;Check (-not $r.completed -and $r.code -ceq $case[1] -and $script:saveCount -eq 0) ('before write refusal '+$case[0])
 }
 foreach($case in @(@('save_error','ufw_journal_preparation_unavailable'),@('unverified','ufw_journal_preparation_unverified'),@('post_stale','ufw_journal_baseline_changed_after_write'),@('post_expired','ufw_journal_consent_expired_after_write'))){
  $script:mode=$case[0];$script:readCount=0;$script:saveCount=0;$script:clockCount=0;$r=& $invoke $ops;Check (-not $r.completed -and $r.journal_write_attempted -and -not $r.journal_preparation_recorded -and $r.code -ceq $case[1]) ('write attempted not successful '+$case[0])
 }
 # Full consent -> actual file store, then recovery with file-backed checkpoints.
 $script:mode='';$script:readCount=0;$script:saveCount=0;$script:clockCount=0;$script:actualRoot=$null;$script:actualId=$null
 $ops.SavePreparation={param($r,$d)$script:actualId=$r.session_id;$script:actualRoot=New-JFixtureRoot $r.session_id;return Append-JFixture $script:actualRoot ([pscustomobject][ordered]@{receipt=$r;draft=$d}) ('0'*64) 'prepared' $r.session_id}
 $r=& $invoke $ops;Check ($r.completed -and $r.journal_preparation_recorded -and (Read-JFixture $script:actualRoot $script:actualId).sequence -eq 1) 'real IO consent integration'
 $script:journal=Read-JFixture $script:actualRoot $script:actualId;$script:data=Clone-JFixture $script:journal.last.data;$script:data.draft.phase='arming';foreach($e in $script:data.draft.entries){$e.intent=$true};$next=Append-JFixture $script:actualRoot $script:data $script:journal.head 'model_checkpoint' $script:actualId
 $script:data.draft.phase='armed';$next=Append-JFixture $script:actualRoot $script:data $next.head 'model_checkpoint' $script:actualId
 $script:head=$next.head;$script:memoryRows=Rows-JFixture 'Block';$script:memoryWrites=0
 $recovery=@{
  ReadProfiles={return @(Clone-JFixture $script:memoryRows)}
  Save={param($d)$entry=[pscustomobject][ordered]@{receipt=$script:data.receipt;draft=$d};$saved=Append-JFixture $script:actualRoot $entry $script:head 'model_checkpoint' $script:actualId;$script:head=$saved.head}
  WriteOutbound={param($n,$v)$script:memoryWrites++;$row=@($script:memoryRows|Where-Object{$_.name -ceq $n})[0];$row.local_outbound=$v;$row.effective_outbound=$v}
 }
 $r=& $m {param($d,$ops)& $script:Core {param($d,$ops)Invoke-UfwProfileRecoveryCallbacks $d $ops} $d $ops} $script:data.draft $recovery
 $end=Read-JFixture $script:actualRoot $script:actualId
 Check ($r.model_recovery_completed -and $script:memoryWrites -eq 3 -and $end.last.data.draft.phase -ceq 'restored' -and $end.sequence -eq 11) 'recovery callbacks persist real append-only checkpoints'
 Check (-not $r.original_restore_verified -and -not $end.last.data.receipt.authorizes_firewall_change) 'disk-backed model not Windows certificate'
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){Reject-JFixture {& $m {param($d)Save-UfwNativePreparation $d.receipt $d.draft} (Data-JFixture)} 'ufw_journal_windows_required'}
 # Real CreateNew collision refuses overwrite independently of head checking.
 $target=Join-Path $dir '00000001.json';$collision=$false
 try{& $m {param($p)$f=Open-UfwPrivateJournalFile $p ([IO.FileMode]::CreateNew);$f.Dispose()} $target}catch{$collision=$_.Exception.GetBaseException() -is [IO.IOException]}
 Check $collision 'actual CreateNew refuses existing record'
 Check ([Convert]::ToBase64String([IO.File]::ReadAllBytes($target)) -ceq [Convert]::ToBase64String($original)) 'collision preserves original bytes'
 # Valid envelope checksum with a broken chain must still fail.
 $chainRoot=New-JFixtureRoot;$envelope=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString($original));$body=ConvertFrom-Json $envelope.payload;$body.previous_sha256='e'*64
 $payload=ConvertTo-Json $body -Depth 32 -Compress;$digest=& $m {param($s)Get-UfwJournalHash $s} $payload
 [IO.File]::WriteAllText((Join-Path $chainRoot '00000001.json'),(ConvertTo-Json ([ordered]@{payload=$payload;sha256=$digest}) -Compress))
 Reject-JFixture {Read-JFixture $chainRoot} 'ufw_journal_chain'
 # File write/flush/readback fault injection: preserve uncertain record; never rewrite.
 & $m {$script:originalOpen=${function:Open-UfwPrivateJournalFile};$script:originalRead=${function:Read-UfwPreparationJournal};$script:ioFault='';$script:readCalls=0
  function script:Open-UfwPrivateJournalFile {
   param($Path,$Mode)$f=& $script:originalOpen $Path $Mode
   if($script:ioFault -cnotin @('partial','flush') -or [IO.Path]::GetFileName($Path) -cnotmatch '^\d{8}\.json$'){return $f}
   $proxy=[pscustomobject]@{inner=$f;fault=$script:ioFault}
   $proxy|Add-Member ScriptMethod Write {param($b,$o,$n)if($this.fault -ceq 'partial'){$this.inner.Write($b,$o,[Math]::Min(17,$n));throw 'fixture_partial_write'};$this.inner.Write($b,$o,$n)}
   $proxy|Add-Member ScriptMethod Flush {param($disk)if($this.fault -ceq 'flush'){throw 'fixture_flush_failed'};$this.inner.Flush($disk)}
   $proxy|Add-Member ScriptMethod Dispose {$this.inner.Dispose()};return $proxy
  }
  function script:Read-UfwPreparationJournal {param($Root,$SessionId)$script:readCalls++;if($script:ioFault -ceq 'readback' -and $script:readCalls -eq 2){throw 'fixture_readback_failed'};return & $script:originalRead $Root $SessionId}
 }
 foreach($fault in @('partial','flush','readback')){
  $faultRoot=New-JFixtureRoot;& $m {param($v)$script:ioFault=$v;$script:readCalls=0} $fault
  $caught=$false;try{Append-JFixture $faultRoot (Data-JFixture)|Out-Null}catch{$caught=$true};Check $caught ('IO failure not success '+$fault)
  Check ([IO.File]::Exists((Join-Path $faultRoot '00000001.json'))) ('uncertain record retained '+$fault)
  & $m {$script:ioFault='';$script:readCalls=0}
  if($fault -ceq 'partial'){$caught=$false;try{Read-JFixture $faultRoot|Out-Null}catch{$caught=$true};Check $caught 'partial IO cannot load as valid'}else{Check ((Read-JFixture $faultRoot).sequence -eq 1) ('valid full record may exist after failure '+$fault);Reject-JFixture {Append-JFixture $faultRoot (Data-JFixture)} 'ufw_journal_stale_head'}
 }
 # Test actual ACL validation logic with metadata fixtures, NOT Windows ACL syscalls.
 & $m {
  function script:Test-UfwJournalWindows {return $true}
  function script:Get-Acl {param($LiteralPath,$ErrorAction)return $script:aclFixture}
 }
 foreach($case in @('valid_file','valid_dir','owner','unprotected','extra','duplicate','inherited','deny','rights','propagation','inheritance','missing_system')){
  $directory=($case -ceq 'valid_dir');$inherit=if($directory){'ContainerInherit, ObjectInherit'}else{'None'}
  $acl=[pscustomobject]@{AreAccessRulesProtected=$true;owner='S-1-5-32-544';rules=@(foreach($sid in @('S-1-5-32-544','S-1-5-18')){[pscustomobject]@{IdentityReference=[pscustomobject]@{Value=$sid};IsInherited=$false;AccessControlType='Allow';FileSystemRights='FullControl';PropagationFlags='None';InheritanceFlags=$inherit}})}
  $acl|Add-Member ScriptMethod GetOwner {param($t)[pscustomobject]@{Value=$this.owner}}
  $acl|Add-Member ScriptMethod GetAccessRules {param($a,$b,$c)return $this.rules}
  switch($case){owner{$acl.owner='S-1-5-21-1-2-3-1001'};unprotected{$acl.AreAccessRulesProtected=$false};extra{$acl.rules[1].IdentityReference.Value='S-1-1-0'};duplicate{$acl.rules[1].IdentityReference.Value='S-1-5-32-544'};inherited{$acl.rules[1].IsInherited=$true};deny{$acl.rules[1].AccessControlType='Deny'};rights{$acl.rules[1].FileSystemRights='Read'};propagation{$acl.rules[1].PropagationFlags='InheritOnly'};inheritance{$acl.rules[1].InheritanceFlags='ObjectInherit'};missing_system{$acl.rules=@($acl.rules[0])}}
  & $m {param($a)$script:aclFixture=$a} $acl
  $accepted=$true;try{& $m {param($p,$d)Assert-UfwJournalAcl $p $d} $Root $directory}catch{$accepted=$false}
  Check ($accepted -eq ($case -in @('valid_file','valid_dir'))) ('ACL metadata '+$case)
 }
 $exports=@(Get-Command -Module Ufw.SessionJournal);Check ($exports.Count -eq 1 -and $exports[0].Name -ceq 'Get-UfwPreparationCapabilities') 'public execution remains disabled'
 $cap=Get-UfwPreparationCapabilities;Check (-not $cap.public_preparation_execution_enabled -and -not $cap.native_firewall_writer_present -and -not $cap.ready_for_apply) 'capabilities explicitly incomplete'
 $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'source/Ufw.SessionJournal.psm1'),[ref]$t,[ref]$e);Check ($e.Count -eq 0) 'source parsed'
 foreach($cmd in $ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){if($cmd.GetCommandName() -match '^(Set-Net.*|New-Net.*|Remove-Net.*|Enable-Net.*|Disable-Net.*|Set-ExecutionPolicy|Register-ScheduledTask|Unregister-ScheduledTask|Resolve-DnsName|Invoke-Expression|Start-Process|USave|IsoSave)$'){throw 'unexpected native policy mutation'}}
 Check $true 'no firewall/VPN/DNS mutation commands'
 $result=[ordered]@{suite='session-preparation-consent-and-append-only-journal-01';passed=$true;assertions=$script:checks;real_Linux_file_IO_and_exclusive_lock_tested=$true;Windows_native_ACL_executed=$false;real_human_prompt_executed=$false;file_backed_recovery_with_memory_profile_writes_tested=$true;native_firewall_write_adapter_present=$false;deployed=$false;ready_for_apply=$false}
 $result|ConvertTo-Json|Set-Content (Join-Path $Root 'evidence/model-tests.json') -Encoding UTF8;$result|ConvertTo-Json -Compress
}finally{
 foreach($parent in $script:cleanup){if([IO.Directory]::Exists($parent)){Remove-Item -LiteralPath $parent -Recurse -Force}}
}
