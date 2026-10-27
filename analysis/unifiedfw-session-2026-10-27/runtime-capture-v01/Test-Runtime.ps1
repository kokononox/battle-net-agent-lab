param([string]$Root=(Join-Path $PSScriptRoot 'package/UFW-RUNTIME-CAPTURE-01'))
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $Root 'ProgramReader.cs')))
Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $Root 'RuntimeNative.cs')))
$m=Import-Module (Join-Path $Root 'Ufw.SessionJournal.psm1') -Force -PassThru
$script:checks=0
function Check($b,$label){$script:checks++;if(-not $b){throw $label}}
function Expect-Throw($Action,$Label){$caught=$false;try{& $Action|Out-Null}catch{$caught=$true};Check $caught $Label}
function Run-Case($Mode){
 & $m {
  param($root,$mode)
  . (Join-Path $root 'CandidateEntry.ps1');. (Join-Path $root 'ObserverEntry.ps1');. (Join-Path $root 'RuntimeCore.ps1');. (Join-Path $root 'RuntimeEntry.ps1')
  $script:T=[pscustomobject]@{mode=$mode;calls=(New-Object 'Collections.Generic.List[string]');loads=0;observes=0;clocks=0;actors=0;sets=0;windows=0;saves=0;archives=0;pending=$null;data=$null;mask=@{};baseline=@{};backup_seen=$false}
  foreach($p in (Get-UfwRuntimeAuditSpec)){$script:T.mask[$p.id]=0;$script:T.baseline[$p.id]=0}
  $p=[pscustomobject][ordered]@{program_id='program01';path='C:\Fixture\installer.exe';sha256=('a'*64);file_id='0000000000000001';volume_id='12345678';length=[long]1024;architecture='x86'}
  $script:D=[pscustomobject][ordered]@{schema='ufw-program-candidate-01';candidate_id=('a'*32);generation=1;profile_kind='installer';phase='programs_reviewed_destinations_pending';programs=@($p);destinations=@();receipt=[pscustomobject][ordered]@{schema='ufw-program-candidate-consent-01';purpose='record_installer_program_selection_only';candidate_id=('a'*32);actor_sid='S-1-5-21-100-100-100-1001';created_utc='2026-10-27 07:00:00.0000000 UTC';nonce_sha256=('b'*64);programs_sha256=(Get-UfwCandidateProgramDigest @($p));authorizes_firewall_change=$false;authorizes_program_execution=$false};execution_authorized=$false;ready_for_apply=$false}
  if($mode.StartsWith('recover_')){
   $plan=Get-UfwRuntimeAuditPlan {param($id)return [int]0}
   $d=[pscustomobject][ordered]@{schema='ufw-runtime-audit-journal-01';session_id=('b'*32);actor_sid=$script:D.receipt.actor_sid;created_utc='2026-10-27 07:00:00.0000000 UTC';audit_plan=$plan}
   $script:T.pending=[pscustomobject]@{data=$d;head=(Get-UfwJournalHash (Get-UfwCandidateJson $d));readback_verified=$true};$script:T.backup_seen=$true
   foreach($p in $plan){$script:T.mask[$p.id]=$p.during}
   if($mode -ceq 'recover_drift'){$script:T.mask[$plan[1].id]=2}
  }
  $ops=@{
   Pending={$script:T.calls.Add('pending');return $script:T.pending}
   Confirm={param($mode,$programs)$script:T.calls.Add('consent');if($script:T.mode -cin @('cancel_review','recover_cancel')){return $false};if($script:T.mode -ceq 'ui_failure'){throw 'PRIVATE_UI_PATH'};return $true}
   Actor={$script:T.actors++;if($script:T.mode -ceq 'actor' -or ($script:T.mode -ceq 'late_actor' -and $script:T.actors -gt 1)){return 'S-1-5-21-200-200-200-2002'};return $script:D.receipt.actor_sid}
   AuditQuery={param($id)return [int]$script:T.mask[$id]}
   AuditSet={param($id,$v)$s=$script:T;if(-not $s.backup_seen){throw 'WRITE_WITHOUT_BACKUP'};$s.sets++;$s.calls.Add('set');$s.mask[$id]=[int]$v;if($s.mode -ceq 'set_partial_failure' -and $s.sets -eq 2){throw 'PRIVATE_NATIVE_PARTIAL'};if($s.mode -ceq 'restore_failure' -and $v -eq 0){$s.mask[$id]=1;throw 'PRIVATE_RESTORE_ERROR'}}
   Archive={param($j)$script:T.archives++;if($script:T.mode -ceq 'archive_failure'){throw 'PRIVATE_ARCHIVE_PATH'};$script:T.pending=$null;$script:T.calls.Add('archive')}
   Select={$script:T.calls.Add('select');return [pscustomobject]@{cancelled=($script:T.mode -ceq 'cancel_select');path=$(if($script:T.mode -ceq 'cancel_select'){''}else{'PRIVATE_CANDIDATE_PATH'})}}
   Load={param($path)$script:T.loads++;$d=ConvertFrom-Json (Get-UfwCandidateJson $script:D);if($script:T.mode -ceq 'bad_candidate'){$d.ready_for_apply=$true};if($script:T.mode -ceq 'candidate_change' -and $script:T.loads -ge 2){$d.receipt.nonce_sha256='c'*64};return [pscustomobject]@{data=$d;head=(Get-UfwJournalHash (Get-UfwCandidateJson $d));readback_verified=$true}}
   Observe={param($path)$script:T.observes++;$h='a'*64;if(($script:T.mode -ceq 'pre_file_change' -and $script:T.observes -ge 2) -or ($script:T.mode -ceq 'post_file_change' -and $script:T.observes -ge 3)){$h='c'*64};return [pscustomobject]@{Path=$path;Sha256=$h;FileId='0000000000000001';VolumeId='12345678';Length=[long]1024;Architecture='x86';SameHandleDoubleHashMatched=$true;NativeIdentityObserved=$true;ExecutionAuthorized=$false;ProgramTrusted=$false;AuthenticodeVerified=$false}}
   Clock={$script:T.clocks++;$t=[datetime]::Parse('2026-10-27T07:00:00Z').ToUniversalTime();if($script:T.mode -ceq 'expired' -and $script:T.clocks -ge 2){return $t.AddSeconds(121)};return $t}
   FirewallGuard={$script:T.calls.Add('guard');if($script:T.mode -ceq 'firewall_failure'){throw 'ufw_runtime_unreviewed_allow_rules_no_launch'};return [pscustomobject]@{profiles_blocked=$true;unreviewed_allow_rules=0}}
   ExistingProcesses={param($p)if($script:T.mode -ceq 'already_running'){return ,@(1)};return ,@()}
   DeviceMap={return ,@([pscustomobject]@{drive='C:';device='\Device\HarddiskVolume1'})}
   WriteJournal={param($d)$s=$script:T;$s.calls.Add('backup');if($s.mode -ceq 'journal_failure'){throw 'PRIVATE_JOURNAL_PATH'};$s.backup_seen=$true;$s.pending=[pscustomobject]@{data=$d;head=(Get-UfwJournalHash (Get-UfwCandidateJson $d));readback_verified=$true};if($s.mode -ceq 'journal_wrong_head'){$s.pending.head='f'*64};return $s.pending}
   LogEdge={param($reverse)return [long]100}
   SelfTest={param($map)$script:T.calls.Add('selftest');if($script:T.mode -ceq 'selftest_failure'){throw 'ufw_runtime_selftest_events_missing_no_launch'};return $true}
   Window={param($guard)$script:T.windows++;$script:T.calls.Add('window');& $guard|Out-Null;if($script:T.mode -ceq 'window_failure'){throw 'PRIVATE_WINDOW_ERROR'};if($script:T.mode -ceq 'restore_drift'){$spec=Get-UfwRuntimeAuditSpec;$script:T.mask[$spec[1].id]=2};return [pscustomobject]@{interrupted=($script:T.mode -ceq 'interrupted')}}
   ReadEvents={param($a,$b,$map)$script:T.calls.Add('events');if($script:T.mode -ceq 'log_failure'){throw 'ufw_runtime_security_log_gap'}
    $time=[datetime]::Parse('2026-10-27T07:00:00Z').ToUniversalTime();$events=@()
    if($script:T.mode -cne 'no_root'){
     $events+=,[pscustomobject]@{id=4688;record=[long]101;time=$time;pid=42;path='C:\Fixture\installer.exe';parent_pid=10;parent_path='C:\Windows\explorer.exe';actor=$script:D.receipt.actor_sid}
     $events+=,[pscustomobject]@{id=4688;record=[long]102;time=$time;pid=43;path='C:\Fixture\helper.exe';parent_pid=42;parent_path='C:\Fixture\installer.exe';actor=$script:D.receipt.actor_sid}
     if($script:T.mode -cne 'no_endpoint'){$events+=,[pscustomobject]@{id=5157;record=[long]103;time=$time;pid=43;path='C:\Fixture\helper.exe';direction='%%14593';address='8.8.8.8';port=443;protocol=6}}
    }
    if($script:T.mode -ceq 'integrity_warning'){$events+=,[pscustomobject]@{id=1101;record=[long]104;time=$time}}
    return [pscustomobject]@{events=$events;parse_errors=$(if($script:T.mode -ceq 'parse_warning'){1}else{0})}
   }
   Save={param($d)$s=$script:T;$s.calls.Add('save');$s.saves++;$s.data=$d;if($s.pending -ne $null){throw 'SAVE_BEFORE_AUDIT_ARCHIVE'};if($s.mode -ceq 'save_failure'){throw 'PRIVATE_SAVE_PATH'};return [pscustomobject]@{head=(Get-UfwJournalHash (Get-UfwCandidateJson $d));readback_verified=($s.mode -cne 'save_unverified')}}
  }
  Invoke-UfwRuntimeCallbacks $ops
 } $Root $Mode
}
try{
 $modes=@('normal','no_root','no_endpoint','interrupted','integrity_warning','parse_warning','post_file_change','cancel_select','cancel_review','ui_failure','actor','late_actor','bad_candidate','candidate_change','pre_file_change','expired','firewall_failure','already_running','journal_failure','journal_wrong_head','set_partial_failure','restore_failure','restore_drift','archive_failure','selftest_failure','window_failure','log_failure','save_failure','save_unverified','recover_success','recover_cancel','recover_drift')
 foreach($mode in $modes){
  $r=Run-Case $mode;$s=& $m {$script:T}
  $success=$mode -cin @('normal','no_root','no_endpoint','interrupted','integrity_warning','parse_warning','post_file_change')
  $cancel=$mode -cin @('cancel_select','cancel_review','recover_cancel')
  Check ($r.completed -eq ($success -or $cancel -or $mode -ceq 'recover_success')) ('completed '+$mode+' '+$r.code)
  $expected=@{normal='ufw_runtime_proposals_pending_review';no_root='ufw_runtime_no_selected_start_not_safety_proof';no_endpoint='ufw_runtime_selected_started_zero_endpoints_not_safety_proof';interrupted='ufw_runtime_partial_events_not_coverage_proof';integrity_warning='ufw_runtime_partial_events_not_coverage_proof';parse_warning='ufw_runtime_partial_events_not_coverage_proof';post_file_change='ufw_runtime_partial_events_not_coverage_proof';cancel_select='ufw_runtime_cancelled_no_capture';cancel_review='ufw_runtime_cancelled_no_capture';ui_failure='ufw_runtime_unavailable';actor='ufw_runtime_same_actor_required';late_actor='ufw_runtime_consent_expired_or_actor_changed';bad_candidate='ufw_candidate_data_invalid';candidate_change='ufw_runtime_candidate_changed';pre_file_change='ufw_runtime_selected_file_changed';expired='ufw_runtime_consent_expired_or_actor_changed';firewall_failure='ufw_runtime_unreviewed_allow_rules_no_launch';already_running='ufw_runtime_target_already_running_no_launch';journal_failure='ufw_runtime_unavailable';journal_wrong_head='ufw_runtime_journal_unverified';set_partial_failure='ufw_runtime_unavailable';restore_failure='ufw_runtime_audit_recovery_required';restore_drift='ufw_runtime_audit_recovery_required';archive_failure='ufw_runtime_audit_recovery_required';selftest_failure='ufw_runtime_selftest_events_missing_no_launch';window_failure='ufw_runtime_unavailable';log_failure='ufw_runtime_security_log_gap';save_failure='ufw_runtime_private_proposal_write_unverified';save_unverified='ufw_runtime_private_proposal_write_unverified';recover_success='ufw_runtime_audit_recovered_no_capture';recover_cancel='ufw_runtime_recovery_cancelled_pending';recover_drift='ufw_runtime_audit_drift_recovery_required'}
  Check ($r.code -ceq $expected[$mode]) ('exact failure/success code '+$mode+' '+$r.code)
  if($success){
   Check ($r.audit_during_verified -and $r.audit_restore_verified -and -not $r.audit_recovery_required -and $r.private_proposals_saved -and $s.saves -eq 1 -and $s.windows -eq 1) ('success scope '+$mode)
   Check ($s.calls.IndexOf('consent') -lt $s.calls.IndexOf('backup') -and $s.calls.IndexOf('backup') -lt $s.calls.IndexOf('set') -and $s.calls.IndexOf('selftest') -lt $s.calls.IndexOf('window') -and $s.calls.IndexOf('archive') -lt $s.calls.IndexOf('save')) ('ordering '+$mode)
   Check (-not $s.data.destinations_approved -and -not $s.data.execution_authorized -and -not $s.data.ready_for_apply) ('private not authority '+$mode)
   if($mode -ceq 'normal'){Check ($r.root_start_events -eq 1 -and $r.descendant_start_events -eq 1 -and $r.blocked_events -eq 1 -and $r.suggestion_count -eq 1) 'real execution evidence counters';Check ($s.data.endpoints[0].program_kind -ceq 'unreviewed_descendant') 'child never approved'}
   if($mode -ceq 'post_file_change'){Check ($r.selected_file_revalidation_failed -and $s.data.selected_file_revalidation_failed -and $r.code -ceq 'ufw_runtime_partial_events_not_coverage_proof') 'self-updating target retained as partial observations only'}
  }elseif($cancel){Check ($s.windows -eq 0 -and $s.sets -eq 0 -and $s.saves -eq 0) ('cancel no arm/run/save '+$mode)}
  elseif($mode -ceq 'recover_success'){Check ($r.mode -ceq 'audit_recovery' -and $r.audit_restore_verified -and -not $r.audit_recovery_required -and $s.windows -eq 0 -and $s.saves -eq 0 -and -not $s.calls.Contains('select')) 'explicit recovery never starts capture or selects target'}
  else{Check (-not $r.private_proposals_saved) ('failure not saved '+$mode)}
  if($mode -cin @('restore_failure','restore_drift','archive_failure','journal_failure','journal_wrong_head','recover_drift')){Check $r.audit_recovery_required ('pending retained '+$mode)}
  if($mode -cin @('set_partial_failure','selftest_failure','window_failure','log_failure','save_failure','save_unverified')){Check ($r.audit_restore_verified -and -not $r.audit_recovery_required) ('restore after failure '+$mode)}
  if($mode -cin @('firewall_failure','already_running','bad_candidate','actor','late_actor','expired','pre_file_change','candidate_change','ui_failure')){Check ($s.sets -eq 0 -and $s.windows -eq 0) ('refusal before audit/ready '+$mode)}
  if($mode -cin @('selftest_failure','set_partial_failure','journal_failure','journal_wrong_head')){Check ($s.windows -eq 0) ('never ready after gate failure '+$mode)}
  foreach($k in @('raw_identity_exported','target_launched_by_tool','target_terminated_by_tool','candidate_write_requested','baseline_journal_access_requested','firewall_change_requested','VPN_change_requested','DNS_query_generated','packet_capture_requested','security_log_cleared','destinations_approved','complete_coverage','isolation_certified','ready_for_apply','no_leak_certified','fingerprint_prevention_certified')){Check ($r.$k -is [bool] -and $r.$k -eq $false) ('boundary '+$mode+' '+$k)}
  Check (($r|ConvertTo-Json -Depth 16) -cnotmatch 'PRIVATE_|C:\\|8\.8\.8\.8|[a-f0-9]{32}|actor_sid|candidate_id|runtime-proposals.json') ('public privacy '+$mode)
 }
 # Exhaustive normalized audit bit preservation (4^3 pre-states), restore all subsets of partial installation.
 $audit=& $m {
  param($root). (Join-Path $root 'RuntimeCore.ps1');$count=0;$restoreCount=0
  for($a=0;$a -lt 4;$a++){for($b=0;$b -lt 4;$b++){for($c=0;$c -lt 4;$c++){
   $script:A=@{};$spec=Get-UfwRuntimeAuditSpec;$script:A[$spec[0].id]=$a;$script:A[$spec[1].id]=$b;$script:A[$spec[2].id]=$c
   $query={param($id)return [int]$script:A[$id]};$set={param($id,$v)$script:A[$id]=[int]$v};$plan=Get-UfwRuntimeAuditPlan $query;Assert-UfwRuntimeAuditPlan $plan
   if($plan[0].during -ne ($a -bor 3) -or $plan[1].during -ne ($b -bor 1) -or $plan[2].during -ne ($c -bor 1)){throw 'bits'};$count++
   for($mask=0;$mask -lt 8;$mask++){
    for($i=0;$i -lt 3;$i++){$script:A[$spec[$i].id]=$(if($mask -band (1 -shl $i)){$plan[$i].during}else{$plan[$i].before})}
    if(-not (Restore-UfwRuntimeAuditPlan $plan $query $set)){throw 'restore'}
    for($i=0;$i -lt 3;$i++){if($script:A[$spec[$i].id] -ne $plan[$i].before){throw 'restored bits'}};$restoreCount++
   }
  }}}
  [pscustomobject]@{plans=$count;partial_installs_restored=$restoreCount}
 } $Root
 Check ($audit.plans -eq 64 -and $audit.partial_installs_restored -eq 512) 'all audit bit combinations and partial installs'
 # XML fixtures: provider, DTD, named fields, decimal/hex PID, device mapping and UTF-8 bounds.
 $xmlresult=& $m {
  param($root). (Join-Path $root 'RuntimeCore.ps1')
  function Fixture($id,$fields,$provider='{54849625-5478-4994-a5ba-3e3b0328c30d}'){
   $items='';foreach($k in $fields.Keys){$items+='<Data Name="'+$k+'">'+[Security.SecurityElement]::Escape([string]$fields[$k])+'</Data>'}
   return '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Guid="'+$provider+'"/><EventID>'+ $id+'</EventID><TimeCreated SystemTime="2026-10-27T07:00:00.0000000Z"/><EventRecordID>101</EventRecordID><Channel>Security</Channel></System><EventData>'+$items+'</EventData></Event>'
  }
  $map=@([pscustomobject]@{drive='C:';device='\Device\HarddiskVolume1'})
  $net=@{ProcessID='0x2a';Application='\device\harddiskvolume1\Fixture\installer.exe';Direction='%%14593';DestAddress='2001:4860::1';DestPort='443';Protocol='17'}
  $x=ConvertFrom-UfwRuntimeXml (Fixture 5157 $net) $map
  $start=@{NewProcessId='43';NewProcessName='c:\Fixture\helper.exe';ProcessId='0x2a';SubjectUserSid='S-1-5-18';TargetUserSid='S-1-5-21-100-100-100-1001';ParentProcessName='C:\Fixture\installer.exe'}
  $y=ConvertFrom-UfwRuntimeXml (Fixture 4688 $start) $map
  $z=ConvertFrom-UfwRuntimeXml (Fixture 4689 @{ProcessId='43';ProcessName='C:\Fixture\helper.exe'}) $map
  $reject=0
  foreach($mode in @('provider','duplicate','dtd','port','pid','fields','unmapped')){
   $n=@{};foreach($key in $net.Keys){$n[$key]=$net[$key]};$text=Fixture 5157 $n
   if($mode -ceq 'provider'){$text=Fixture 5157 $n '{00000000-0000-0000-0000-000000000000}'}
   if($mode -ceq 'duplicate'){$text=$text.Replace('</EventData>','<Data Name="ProcessID">42</Data></EventData>')}
   if($mode -ceq 'dtd'){$text='<!DOCTYPE Event [<!ENTITY test SYSTEM "file:///etc/passwd">]>'+$text}
   if($mode -ceq 'port'){$n.DestPort='PRIVATE';$text=Fixture 5157 $n}
   if($mode -ceq 'pid'){$n.ProcessID='-42';$text=Fixture 5157 $n}
   if($mode -ceq 'fields'){$n.Remove('Application');$text=Fixture 5157 $n}
   if($mode -ceq 'unmapped'){$n.Application='\Device\HarddiskVolume99\Fixture\installer.exe';$text=Fixture 5157 $n}
   try{$bad=ConvertFrom-UfwRuntimeXml $text $map;throw 'ACCEPTED_BAD_FIXTURE'}catch{if($_.Exception.Message -ceq 'ACCEPTED_BAD_FIXTURE'){throw};$reject++}
  }
  [pscustomobject]@{net=$x;start=$y;stop=$z;rejected=$reject;shared_host_observable=(ConvertTo-UfwRuntimePath 'C:\Windows\System32\svchost.exe' $map)}
 } $Root
 Check ($xmlresult.net.pid -eq 42 -and $xmlresult.net.protocol -eq 17 -and $xmlresult.net.path -ceq 'C:\Fixture\installer.exe' -and $xmlresult.net.direction -ceq '%%14593') 'native-style WFP event parser'
 Check ($xmlresult.start.pid -eq 43 -and $xmlresult.start.parent_pid -eq 42 -and $xmlresult.start.path -ceq 'C:\Fixture\helper.exe' -and $xmlresult.start.actor -ceq 'S-1-5-21-100-100-100-1001') '4688 hex/decimal creator/target identity'
 Check ($xmlresult.stop.pid -eq 43 -and $xmlresult.rejected -eq 7 -and $xmlresult.shared_host_observable.EndsWith('svchost.exe')) '4689/refusals/shared-host observation not approval'
 # Reuse safety against PID reuse, path mismatch, inbound traffic, missing creator, and parsed-event barriers.
 $reducer=& $m {
  param($root). (Join-Path $root 'RuntimeCore.ps1');$t=[datetime]::Parse('2026-10-27T07:00:00Z').ToUniversalTime();$p=@([pscustomobject]@{program_id='program01';path='C:\Fixture\installer.exe'});$actor='S-1-5-21-100-100-100-1001';$results=@{}
  foreach($mode in @('normal','reuse','stop','path','inbound','wrong_actor','unknown_parent','barrier','udp','permitted')){
   $events=@([pscustomobject]@{id=4688;record=[long]1;time=$t;pid=42;path='C:\Fixture\installer.exe';parent_pid=10;parent_path='C:\Windows\explorer.exe';actor=$actor})
   if($mode -ceq 'wrong_actor'){$events[0].actor='S-1-5-18'}
   if($mode -ceq 'reuse'){$events+=,[pscustomobject]@{id=4688;record=[long]2;time=$t;pid=42;path='C:\Fixture\other.exe';parent_pid=10;parent_path='C:\Windows\explorer.exe';actor=$actor}}
   if($mode -ceq 'stop'){$events+=,[pscustomobject]@{id=4689;record=[long]2;time=$t;pid=42;path='C:\Fixture\installer.exe'}}
   if($mode -ceq 'barrier'){$events+=,[pscustomobject]@{id=0;record=[long]2;time=$t}}
   $events+=,[pscustomobject]@{id=$(if($mode -ceq 'permitted'){5156}else{5157});record=[long]3;time=$t;pid=42;path=$(if($mode -ceq 'path'){'C:\Fixture\other.exe'}else{'C:\Fixture\installer.exe'});direction=$(if($mode -ceq 'inbound'){'%%14592'}else{'%%14593'});address='8.8.8.8';port=443;protocol=$(if($mode -ceq 'udp'){17}else{6})}
   if($mode -ceq 'unknown_parent'){$events[0].path='C:\Fixture\helper.exe'}
   $v=Get-UfwRuntimeProposals $events $p $actor $t $t.AddSeconds(1);$results[$mode]=$v
  };return $results
 } $Root
 foreach($mode in @('reuse','stop','path','inbound','wrong_actor','unknown_parent','barrier')){Check ($reducer[$mode].endpoints.Count -eq 0) ('no false association '+$mode)}
 Check ($reducer.normal.endpoints.Count -eq 1 -and $reducer.udp.endpoints[0].protocol -ceq 'UDP' -and $reducer.permitted.endpoints[0].permitted_events -eq 1 -and $reducer.permitted.blocked_events -eq 0) 'TCP/UDP permit and block are different observations'
 # Exercise the exact native firewall gate against mock native cmdlets, not a second implementation.
 $firewall=& $m {
  param($root). (Join-Path $root 'RuntimeCore.ps1');. (Join-Path $root 'RuntimeEntry.ps1')
  function Get-UfwRuntimeSystemHostPath{return 'C:\Windows\System32\svchost.exe'}
  function Get-NetFirewallProfile {param($PolicyStore,$ErrorAction)
   foreach($n in @('Domain','Private','Public')){[pscustomobject]@{Name=$n;Enabled=$(if($script:GuardMode -ceq 'disabled'){'False'}else{'True'});DefaultOutboundAction=$(if($script:GuardMode -ceq 'default_allow'){'Allow'}else{'Block'})}}
  }
  function Get-NetFirewallRule {param($PolicyStore,$Enabled,$Direction,$Action,$ErrorAction)
   if($script:GuardMode -ceq 'empty'){return}
   [pscustomobject]@{Enabled='True';Direction='Outbound';Action='Allow';RemoteDynamicKeywordAddresses=$(if($script:GuardMode -ceq 'dynamic'){@('keyword')}else{@()})}
  }
  function Get-NetFirewallServiceFilter {param([Parameter(ValueFromPipeline=$true)]$InputObject)process{[pscustomobject]@{Service=$(if($script:GuardMode -ceq 'generic_service'){'Any'}else{'SstpSvc'})}}}
  function Get-NetFirewallApplicationFilter {param([Parameter(ValueFromPipeline=$true)]$InputObject)process{[pscustomobject]@{Program=$(if($script:GuardMode -ceq 'generic_app'){'Any'}else{'C:\Windows\System32\svchost.exe'})}}}
  function Get-NetFirewallPortFilter {param([Parameter(ValueFromPipeline=$true)]$InputObject)process{[pscustomobject]@{Protocol=$(if($script:GuardMode -ceq 'udp'){'UDP'}else{'TCP'});RemotePort=$(if($script:GuardMode -ceq 'any_port'){'Any'}else{'443'})}}}
  function Get-NetFirewallAddressFilter {param([Parameter(ValueFromPipeline=$true)]$InputObject)process{[pscustomobject]@{RemoteAddress=$(if($script:GuardMode -ceq 'any_address'){@('Any')}elseif($script:GuardMode -ceq 'cidr'){@('8.8.8.0/24')}else{@('8.8.8.8')})}}}
  $results=@{}
  foreach($mode in @('empty','exact_sstp','disabled','default_allow','generic_service','generic_app','udp','any_port','any_address','cidr','dynamic')){
   $script:GuardMode=$mode;try{$g=Get-UfwRuntimeFirewallGuard;$results[$mode]=$g.profiles_blocked -and $g.unreviewed_allow_rules -eq 0}catch{$results[$mode]=$false}
  };return $results
 } $Root
 foreach($mode in @('empty','exact_sstp','disabled','default_allow','generic_service','generic_app','udp','any_port','any_address','cidr','dynamic')){Check ($firewall[$mode] -eq ($mode -cin @('empty','exact_sstp'))) ('native gate '+$mode)}
 # Native journal helpers on actual Linux I/O, replacing only OS root adapter.
 $temp=Join-Path ([IO.Path]::GetTempPath()) ('ufw-runtime-tests-'+[guid]::NewGuid().ToString('N'))
 try{
  $io=& $m {
   param($root,$temp). (Join-Path $root 'CandidateEntry.ps1');. (Join-Path $root 'RuntimeCore.ps1');. (Join-Path $root 'RuntimeEntry.ps1')
   $script:TestRoot=$temp;function Get-UfwRuntimeRoot{return $script:TestRoot}
   $plan=Get-UfwRuntimeAuditPlan {param($id)return [int]0};$data=[pscustomobject][ordered]@{schema='ufw-runtime-audit-journal-01';session_id=('c'*32);actor_sid='S-1-5-21-100-100-100-1001';created_utc='2026-10-27 07:00:00.0000000 UTC';audit_plan=$plan}
   $back=Write-UfwRuntimePending $data;$file=Join-Path $temp 'audit-pending.json';$bytes=[IO.File]::ReadAllBytes($file);$collision=$false
   try{$again=Write-UfwRuntimePending $data}catch{$collision=$true};$unchanged=[Convert]::ToBase64String([IO.File]::ReadAllBytes($file)) -ceq [Convert]::ToBase64String($bytes)
   [IO.File]::WriteAllText($file,'{}');$tamper=$false;try{$bad=Read-UfwRuntimePending}catch{$tamper=$true};[IO.File]::WriteAllBytes($file,$bytes)
   Archive-UfwRuntimePending $back;$pending=Read-UfwRuntimePending;$archived=Test-Path -LiteralPath (Join-Path $temp ('audit-restored-'+$data.session_id+'.json'))
   [pscustomobject]@{readback=$back.readback_verified;collision=$collision;unchanged=$unchanged;tamper=$tamper;pending_absent=($null -eq $pending);archived=$archived}
  } $Root $temp
  foreach($k in @('readback','collision','unchanged','tamper','pending_absent','archived')){Check $io.$k ('real file '+$k)}
 }finally{if([IO.Directory]::Exists($temp)){Remove-Item -LiteralPath $temp -Recurse -Force}}
 foreach($n in @('RuntimeCore.ps1','RuntimeEntry.ps1','Run-Runtime.ps1')){
  $t=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $n),[ref]$t,[ref]$errors);Check ($errors.Count -eq 0) ('parse '+$n)
  $commands=@($ast.FindAll({param($a)$a -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
  Check (@($commands|Where-Object{$_ -match '^(Set-Net.*|New-Net.*|Remove-Net.*|Enable-Net.*|Disable-Net.*|Resolve-DnsName|rasdial|netsh|auditpol|Clear-EventLog|wevtutil|Set-ExecutionPolicy|Start-Process|Invoke-Expression|Read-UfwPreparationJournal|Save-UfwProgramCandidateNative)$'}).Count -eq 0) ('no network/target/baseline/clear commands '+$n)
 }
 Check ([Runtime.InteropServices.Marshal]::SizeOf([type][UfwRuntime01.AuditInfo]) -eq 36) 'native audit layout36'
 $out=[ordered]@{suite='runtime-event-capture-01';passed=$true;assertions=$script:checks;callback_cases=$modes.Count;exhaustive_audit_plans=64;partial_install_restore_scenarios=512;Windows_audit_TCP_event_log_UI_native_executed=$false;real_Linux_file_IO_executed=$true;diagnostic_child_native_executed=$false;ready_for_apply=$false;no_leak_certified=$false}
 $out|ConvertTo-Json|Set-Content (Join-Path $PSScriptRoot 'evidence/model-tests.json') -Encoding UTF8;$out|ConvertTo-Json -Compress
}finally{Remove-Module $m.Name -Force -ErrorAction SilentlyContinue}
