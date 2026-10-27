param([string]$Root=(Join-Path $PSScriptRoot 'package/UFW-PROGRAM-OBSERVER-01'))
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $Root 'ProgramReader.cs'))) -Language CSharp
$m=Import-Module (Join-Path $Root 'Ufw.SessionJournal.psm1') -Force -PassThru
$script:checks=0
function Check($b,$label){$script:checks++;if(-not $b){throw $label}}
function Run-Case($Mode){
 & $m {
  param($root,$mode)
  . (Join-Path $root 'CandidateEntry.ps1');. (Join-Path $root 'ObserverEntry.ps1')
  $script:T=[pscustomobject]@{mode=$mode;loads=0;observes=0;confirms=0;tcp=0;procs=0;saves=0;clocks=0;actors=0;sleeps=0;private=$null}
  $program=[pscustomobject][ordered]@{program_id='program01';path='C:\Fixture\installer.exe';sha256=('a'*64);file_id='0000000000000001';volume_id='12345678';length=[long]1024;architecture='x86'}
  $script:D=[pscustomobject][ordered]@{schema='ufw-program-candidate-01';candidate_id=('a'*32);generation=1;profile_kind='installer';phase='programs_reviewed_destinations_pending';programs=@($program);destinations=@();receipt=[pscustomobject][ordered]@{schema='ufw-program-candidate-consent-01';purpose='record_installer_program_selection_only';candidate_id=('a'*32);actor_sid='S-1-5-21-100-100-100-1001';created_utc='2026-10-27 07:00:00.0000000 UTC';nonce_sha256=('b'*64);programs_sha256=(Get-UfwCandidateProgramDigest @($program));authorizes_firewall_change=$false;authorizes_program_execution=$false};execution_authorized=$false;ready_for_apply=$false}
  $ops=@{
   Select={return [pscustomobject]@{cancelled=($script:T.mode -ceq 'cancel_select');path=$(if($script:T.mode -ceq 'cancel_select'){''}else{'PRIVATE_CANDIDATE_PATH'})}}
   Load={param($p)$script:T.loads++;$d=ConvertFrom-Json (Get-UfwCandidateJson $script:D)
    if($script:T.mode -ceq 'bad_checksum'){return [pscustomobject]@{data=$d;head=('f'*64);readback_verified=$true}}
    if($script:T.mode -ceq 'bad_data'){$d.ready_for_apply=$true}
    if(($script:T.mode -ceq 'candidate_change' -and $script:T.loads -ge 2) -or ($script:T.mode -ceq 'post_candidate_change' -and $script:T.loads -ge 3)){$d.receipt.nonce_sha256='c'*64}
    return [pscustomobject]@{data=$d;head=(Get-UfwJournalHash (Get-UfwCandidateJson $d));readback_verified=$true}
   }
   Observe={param($p)$script:T.observes++;$hash='a'*64
    if(($script:T.mode -ceq 'file_changed' -and $script:T.observes -ge 1) -or ($script:T.mode -ceq 'pre_file_change' -and $script:T.observes -ge 2) -or ($script:T.mode -ceq 'post_file_change' -and $script:T.observes -ge 3)){$hash='c'*64}
    return [pscustomobject]@{Path=$p;Sha256=$hash;FileId='0000000000000001';VolumeId='12345678';Length=[long]1024;Architecture='x86';SameHandleDoubleHashMatched=$true;NativeIdentityObserved=$true;ExecutionAuthorized=$false;ProgramTrusted=$false;AuthenticodeVerified=$false}
   }
   Actor={$script:T.actors++;if($script:T.mode -ceq 'actor' -or ($script:T.mode -ceq 'actor_after_review' -and $script:T.actors -ge 2) -or ($script:T.mode -ceq 'actor_after_sample' -and $script:T.actors -ge 3)){return 'S-1-5-21-200-200-200-2002'};return 'S-1-5-21-100-100-100-1001'}
   Clock={$script:T.clocks++;$t=[datetime]::Parse('2026-10-27T07:00:00Z').ToUniversalTime();if($script:T.mode -ceq 'expired' -and $script:T.clocks -ge 2){return $t.AddSeconds(121)};if($script:T.mode -ceq 'deadline' -and $script:T.clocks -ge 4){return $t.AddSeconds(400)};if($script:T.mode -ceq 'bad_clock'){return 'PRIVATE_TIME'};return $t}
   Confirm={param($p)$script:T.confirms++;if($script:T.mode -ceq 'ui_failure'){throw 'PRIVATE_UI_PATH'};if($script:T.mode -ceq 'cancel_review'){return $false};if($script:T.mode -ceq 'string_consent'){return 'true'};return $true}
   Processes={param($p)$script:T.procs++;if($script:T.mode -ceq 'no_process'){return ,@()};$ticks=[long]100;$path='C:\Fixture\installer.exe'
    if($script:T.mode -ceq 'pid_reuse' -and $script:T.procs%2 -eq 0){$ticks=[long]200}
    if($script:T.mode -ceq 'path_change' -and $script:T.procs%2 -eq 0){$path='C:\Fixture\other.exe'}
    if($script:T.mode -ceq 'exit_after' -and $script:T.procs%2 -eq 0){return ,@()}
    return ,@([pscustomobject]@{pid=[int]42;start_ticks=$ticks;path=$path})
   }
   Tcp={$script:T.tcp++;if($script:T.mode -ceq 'tcp_failure'){throw 'PRIVATE_TCP_ERROR'};if($script:T.mode -ceq 'empty_tcp'){return ,@()}
    $rows=@([pscustomobject]@{pid=[int]42;remote_address='8.8.8.8';remote_port=[int]443;state='Established'},[pscustomobject]@{pid=[int]99;remote_address='9.9.9.9';remote_port=[int]80;state='Established'})
    if($script:T.mode -ceq 'bad_ip'){$rows[0].remote_address='PRIVATE_BAD_IP'}
    if($script:T.mode -ceq 'ipv6'){$rows[0].remote_address='2001:4860:4860::8888'}
    if($script:T.mode -ceq 'loopback'){$rows[0].remote_address='127.0.0.1'}
    if($script:T.mode -ceq 'state_timewait'){$rows[0].state='TimeWait'}
    return ,$rows
   }
   Sleep={$script:T.sleeps++}
   Save={param($d)$script:T.saves++;$script:T.private=$d;if($script:T.mode -ceq 'save_failure'){throw 'PRIVATE_STORAGE_PATH'};return [pscustomobject]@{readback_verified=($script:T.mode -cne 'unverified_save');head=(Get-UfwJournalHash (Get-UfwCandidateJson $d))}}
  }
  Invoke-UfwObserverCallbacks $ops
 } $Root $Mode
}
try{
 foreach($mode in @('normal','ipv6','no_process','empty_tcp','pid_reuse','path_change','exit_after','loopback','state_timewait','cancel_select','cancel_review','string_consent','bad_checksum','bad_data','file_changed','pre_file_change','post_file_change','candidate_change','post_candidate_change','actor','actor_after_review','actor_after_sample','expired','deadline','bad_clock','ui_failure','tcp_failure','bad_ip','save_failure','unverified_save')){
  $r=Run-Case $mode;$s=& $m {$script:T}
  $success=$mode -cin @('normal','ipv6','no_process','empty_tcp','pid_reuse','path_change','exit_after','loopback','state_timewait')
  $cancel=$mode -cin @('cancel_select','cancel_review','string_consent')
  Check ($r.completed -eq ($success -or $cancel)) ('completed '+$mode+' '+$r.code)
  if($success){
   Check ($r.samples_completed -eq 15 -and $s.tcp -eq 15 -and $s.procs -eq 30 -and $s.sleeps -eq 14) ('sample bounds '+$mode)
   Check ($s.loads -eq 3 -and $s.observes -eq 3 -and $r.file_observation_passes -eq 3) ('revalidate '+$mode)
   Check ($r.private_suggestions_saved -and $s.saves -eq 1 -and $s.private.sample_count -eq 15) ('saved '+$mode)
   $n=if($mode -cin @('normal','ipv6')){1}else{0};Check ($r.suggestion_count -eq $n -and $s.private.suggestions.Count -eq $n) ('endpoint count '+$mode)
   if($n){Check ($s.private.suggestions[0].observations -eq 15 -and $s.private.suggestions[0].direction -ceq 'unknown_tcp_table' -and $s.private.suggestions[0].approval -ceq 'not_reviewed') ('not approved '+$mode)}
   else{Check ($r.code -ceq 'ufw_observer_completed_zero_suggestions_not_safety_proof') ('zero not proof '+$mode)}
   if($mode -ceq 'pid_reuse'){Check ($r.unstable_tcp_rows -eq 15) 'PID reuse rejected'}
  }elseif($cancel){Check ($s.tcp -eq 0 -and $s.saves -eq 0 -and -not $r.consent_received) ('cancel no tcp/write '+$mode)}
  else{
   Check (-not $r.private_suggestions_saved) ('failure not saved '+$mode)
   if($mode -cin @('save_failure','unverified_save')){Check ($s.saves -eq 1 -and $r.private_write_status -ceq 'attempted_may_exist_inspect_if_failed') ('uncertain '+$mode)}else{Check ($s.saves -eq 0 -and $r.private_write_status -ceq 'not_requested') ('no save '+$mode)}
   if($mode -cin @('bad_checksum','bad_data','file_changed','pre_file_change','candidate_change','actor','actor_after_review','expired','bad_clock','ui_failure')){Check ($s.tcp -eq 0) ('pre refusal no TCP '+$mode)}
  }
  if($mode -ceq 'ui_failure'){Check (-not $r.review_displayed) 'UI failure not displayed'}
  foreach($k in @('raw_identity_exported','candidate_write_requested','baseline_journal_access_requested','program_execution_requested','firewall_change_requested','VPN_change_requested','DNS_query_generated','audit_change_requested','packet_capture_requested','udp_observed','blocked_connections_covered','complete_coverage','destinations_approved','ready_for_apply','no_leak_certified','fingerprint_prevention_certified')){Check ($r.$k -is [bool] -and $r.$k -eq $false) ('boundary '+$mode+' '+$k)}
  Check (($r|ConvertTo-Json -Depth 16) -cnotmatch 'PRIVATE_|C:\\|8\.8\.8\.8|9\.9\.9\.9|2001:4860|[a-f0-9]{32}|actor_sid|start_ticks|candidate_id|remote_address') ('diagnostic privacy '+$mode)
 }
 # Direct reducer: canonicalization, duplicate endpoint aggregation, address/state exclusion and limits.
 $n=& $m {
  param($root)
  . (Join-Path $root 'ObserverEntry.ps1')
  $p=@([pscustomobject]@{program_id='program01';path='C:\Fixture\installer.exe'})
  $b=@([pscustomobject]@{pid=[int]42;start_ticks=[long]100;path='c:\fixture\INSTALLER.exe'})
  $items=@{};$counts=@()
  foreach($ip in @('::ffff:8.8.8.8','8.8.8.8','2001:4860:4860::8888','192.168.1.2','::1','::','0.0.0.0','0.1.2.3','127.2.3.4','224.0.0.1','255.255.255.255','ff02::1','169.254.2.3','fe80::1','fe80::1%12')){
   $row=@([pscustomobject]@{pid=[int]42;remote_address=$ip;remote_port=[int]443;state='SynSent'})
   $counts+=,(Add-UfwObserverSample $b $row $b $p $items)
  }
  $err=@()
  foreach($mode in @('duplicate_pid','invalid_shape','invalid_port','limit')){
   $q=$b;$rows=@([pscustomobject]@{pid=[int]42;remote_address='8.8.4.4';remote_port=[int]443;state='Established'});$dest=@{}
   if($mode -ceq 'duplicate_pid'){$q=@($b[0],$b[0])}
   if($mode -ceq 'invalid_shape'){$rows[0].pid='42'}
   if($mode -ceq 'invalid_port'){$rows[0].remote_port=[int]0}
   if($mode -ceq 'limit'){for($i=1;$i -le 256;$i++){$dest['fake'+$i]=$true}}
   try{$x=Add-UfwObserverSample $q $rows $b $p $dest;$err+=,$(if($mode -ceq 'invalid_port' -and $x.excluded -eq 1){'port_excluded'}else{'not_rejected'})}catch{$err+=,$_.Exception.GetBaseException().Message}
  }
  [pscustomobject]@{count=$items.Count;mapped=$items['program01|8.8.8.8|443'].observations;excluded=(@($counts|Where-Object{$_.excluded -eq 1})).Count;errors=$err}
 } $Root
 Check ($n.count -eq 3 -and $n.mapped -eq 2 -and $n.excluded -eq 11) 'canonical/excluded IP scopes'
 Check ($n.errors[0] -ceq 'ufw_observer_duplicate_pid' -and $n.errors[1] -ceq 'ufw_observer_tcp_shape' -and $n.errors[2] -ceq 'port_excluded' -and $n.errors[3] -ceq 'ufw_observer_endpoint_limit') 'reject invalid/over-limit reducer'
 # Actual Linux file I/O via existing helpers; only native root adapter is replaced.
 $temp=Join-Path ([IO.Path]::GetTempPath()) ('ufw-observer-test-'+[guid]::NewGuid().ToString('N'))
 try{
  $v=Run-Case 'normal';$saved=& $m {
   param($root,$temp)
   . (Join-Path $root 'CandidateEntry.ps1');. (Join-Path $root 'ObserverEntry.ps1')
   function Get-UfwProgramCandidateNativeRoot{return 'test-only'}
   # Test interception of OS CommonApplicationData is intentionally not needed: replace root factory only.
   function Get-UfwObserverStorageRoot{return $temp}
   Save-UfwObserverSuggestions $script:T.private
  } $Root $temp
  Check ($saved.readback_verified -and $saved.head -match '^[a-f0-9]{64}$') 'real private file write/readback'
  $files=@(Get-ChildItem -LiteralPath $temp -Recurse -File);Check ($files.Count -eq 1 -and $files[0].Name -ceq 'suggestions.json') 'separate new storage only'
  $en=ConvertFrom-Json ([IO.File]::ReadAllText($files[0].FullName));$private=ConvertFrom-Json $en.payload
  Check ($private.suggestions.Count -eq 1 -and -not $private.ready_for_apply -and -not $private.execution_authorized -and -not $private.destinations_approved) 'stored no authority'
 }finally{if([IO.Directory]::Exists($temp)){Remove-Item -LiteralPath $temp -Recurse -Force}}
 foreach($n in @('ObserverEntry.ps1','Run-Observer.ps1')){
  $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $n),[ref]$t,[ref]$e);Check ($e.Count -eq 0) ('parse '+$n)
  $cmds=@($ast.FindAll({param($a)$a -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
  Check (@($cmds|Where-Object{$_ -match '^(Start-Process|Invoke-Expression|Get-AuthenticodeSignature|Set-Net.*|New-Net.*|Remove-Net.*|Resolve-DnsName|Invoke-WebRequest|Invoke-RestMethod|rasdial|netsh|auditpol|Save-UfwProgramCandidateNative|Read-UfwPreparationJournal|Add-UfwPreparationCheckpoint|Set-ExecutionPolicy)$'}).Count -eq 0) ('no active mutation/target/network/baseline cmd '+$n)
 }
 $out=[ordered]@{suite='passive-program-observer-01';passed=$true;assertions=$script:checks;cases=30;real_Linux_file_IO_executed=$true;Windows_native_TCP_process_picker_ACL_executed=$false;PS51_native_executed=$false;callbacks_mocked=$true;ready_for_apply=$false}
 $out|ConvertTo-Json|Set-Content (Join-Path $PSScriptRoot 'evidence/model-tests.json') -Encoding UTF8;$out|ConvertTo-Json -Compress
}finally{Remove-Module $m.Name -Force -ErrorAction SilentlyContinue}
