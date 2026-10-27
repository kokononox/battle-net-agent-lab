param([string]$Root='/data/ufw-program-candidate-v01/package/UFW-PROGRAM-CANDIDATE-01')
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $Root 'ProgramReader.cs'))) -Language CSharp
$m=Import-Module (Join-Path $Root 'Ufw.SessionJournal.psm1') -Force -PassThru
$script:checks=0
function Check($b,$label){$script:checks++;if(-not $b){throw $label}}
$base=Join-Path ([IO.Path]::GetTempPath()) ('ufw-program-candidate-test-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($base)
function Run-Case($Mode){
 return & $m {
  param($entry,$mode,$base)
  . $entry
  $script:CandidateTest=[pscustomobject]@{mode=$mode;reads=0;confirms=0;clocks=0;actors=0;saves=0;data=$null;root=(Join-Path $base $mode)}
  function Get-UfwProgramCandidateNativeRoot {return $script:CandidateTest.root}
  $ops=@{
   Select={
    $s=$script:CandidateTest
    if($s.mode -ceq 'cancel_selection'){return [pscustomobject]@{cancelled=$true;paths=@()}}
    $paths=@('C:\Fixture\installer.exe');if($s.mode -ceq 'two'){$paths+=,'C:\Fixture\helper.exe'};if($s.mode -ceq 'duplicate'){$paths+=,'C:\Fixture\INSTALLER.exe'}
    return [pscustomobject]@{cancelled=$false;paths=$paths}
   }
   Observe={
    param($path)$s=$script:CandidateTest;$s.reads++;$n=if($path.EndsWith('helper.exe')){2}else{1};$hash='a'*64
    if($s.mode -ceq 'raw_failure'){throw 'PRIVATE_PROGRAM_PATH'}
    if($s.mode -ceq 'prewrite_change' -and $s.reads -ge 2){$hash='c'*64}
    if($s.mode -ceq 'postwrite_change' -and $s.reads -ge 3){$hash='c'*64}
    return [pscustomobject]@{Path=$path;Sha256=$hash;FileId=('{0:x16}' -f $n);VolumeId='12345678';Length=[long]1024;Architecture='x86';SameHandleDoubleHashMatched=$true;NativeIdentityObserved=$true;ExecutionAuthorized=$false;ProgramTrusted=$false;AuthenticodeVerified=$false}
   }
   Confirm={param($p)$s=$script:CandidateTest;$s.confirms++;if($s.mode -ceq 'ui_failure'){throw 'PRIVATE_UI_ERROR'};if($s.mode -ceq 'cancel_review'){return $false};if($s.mode -ceq 'string_confirmation'){return 'true'};return $true}
   Clock={$s=$script:CandidateTest;$s.clocks++;$t=[datetime]::Parse('2026-10-27T07:00:00Z').ToUniversalTime();if(($s.mode -ceq 'prewrite_expired' -and $s.clocks -ge 2) -or ($s.mode -ceq 'postwrite_expired' -and $s.clocks -ge 3)){return $t.AddSeconds(121)};return $t}
   Actor={$s=$script:CandidateTest;$s.actors++;if($s.mode -ceq 'actor_changed' -and $s.actors -ge 2){return 'S-1-5-21-200-200-200-2002'};return 'S-1-5-21-100-100-100-1001'}
   Save={param($data)$s=$script:CandidateTest;$s.saves++;$s.data=$data;if($s.mode -ceq 'write_failure'){throw 'PRIVATE_STORE_PATH'};if($s.mode -cin @('unverified_save','wrong_head')){return [pscustomobject]@{readback_verified=($s.mode -ceq 'wrong_head');head='a'*64}};return Save-UfwProgramCandidateNative $data}
  }
  Invoke-UfwProgramCandidateCallbacks $ops
 } (Join-Path $Root 'CandidateEntry.ps1') $Mode $base
}
try{
 foreach($mode in @('one','two','cancel_selection','cancel_review','string_confirmation','duplicate','raw_failure','ui_failure','prewrite_change','postwrite_change','prewrite_expired','postwrite_expired','actor_changed','write_failure','unverified_save','wrong_head')){
  $r=Run-Case $mode;$s=& $m {$script:CandidateTest}
  if($mode -cin @('one','two')){
   Check ($r.completed -and $r.candidate_recorded -and $r.program_config_saved -and $r.consent_received -and $s.saves -eq 1 -and $s.confirms -eq 1) ('success '+$mode)
   Check ($r.observation_passes -eq 3 -and $s.reads -eq 3*$r.selected_count -and $r.write_status -ceq 'recorded_revalidated_no_authority') 'fresh three-pass identity observation'
   $read=& $m {param($entry). $entry;$s=$script:CandidateTest;$id=$s.data.candidate_id;Read-UfwProgramCandidateRecord (Join-Path $s.root ('UfwProgramCandidate-'+$id)) $id} (Join-Path $Root 'CandidateEntry.ps1')
   Check ($read.readback_verified -and $read.data.phase -ceq 'programs_reviewed_destinations_pending' -and $read.data.destinations.Count -eq 0 -and $read.data.programs.Count -eq $r.selected_count) 'actual file readback of bounded candidate without destinations'
   Check (-not $read.data.execution_authorized -and -not $read.data.receipt.authorizes_firewall_change -and -not $read.data.receipt.authorizes_program_execution) 'file receipt no authority'
  }elseif($mode -cin @('cancel_selection','cancel_review','string_confirmation')){
   Check ($r.completed -and $r.code -ceq 'ufw_candidate_cancelled_no_write' -and -not $r.candidate_write_attempted -and $s.saves -eq 0 -and -not [IO.Directory]::Exists($s.root)) ('no candidate on '+$mode)
  }else{
   Check (-not $r.completed -and -not $r.candidate_recorded) ('refuse '+$mode)
   $expected=@{duplicate='ufw_candidate_duplicate_program';raw_failure='ufw_candidate_unavailable';ui_failure='ufw_candidate_unavailable';prewrite_change='ufw_candidate_program_changed_after_review';postwrite_change='ufw_candidate_program_changed_after_write';prewrite_expired='ufw_candidate_review_expired_or_actor_changed';postwrite_expired='ufw_candidate_review_expired_after_write';actor_changed='ufw_candidate_review_expired_or_actor_changed';write_failure='ufw_candidate_unavailable';unverified_save='ufw_candidate_save_unverified';wrong_head='ufw_candidate_save_unverified'}
   Check ($r.code -ceq $expected[$mode]) ('code '+$mode+' got '+$r.code)
   if($mode -cin @('postwrite_change','postwrite_expired','write_failure','unverified_save','wrong_head')){Check ($r.candidate_write_attempted -and $r.write_status -ceq 'attempted_may_exist_inspect_if_failed') 'postwrite uncertainty never claimed no write'}
   else{Check ($s.saves -eq 0 -and -not [IO.Directory]::Exists($s.root)) 'prewrite refusal creates no directory'}
  }
  if($mode -ceq 'ui_failure'){Check (-not $r.review_displayed) 'failed UI is not reported displayed'}
  foreach($k in @('raw_identity_exported','program_trusted','program_execution_requested','firewall_change_requested','baseline_journal_access_requested','VPN_change_requested','DNS_query_generated','baseline_linked','ready_for_apply','no_leak_certified')){Check ($r.$k -ceq $false) ('boundary '+$mode+' '+$k)}
  Check (($r|ConvertTo-Json -Depth 16) -notmatch 'PRIVATE_|[a-f0-9]{32}|C:\\|candidate_id|actor_sid|programs_sha256|nonce_sha256') ('no raw identity/receipt leak '+$mode)
 }
 # Reuse successful stored candidate, no overwrite; schema/checksum/ACL checks use actual helpers.
 $r=Run-Case 'store_checks';$s=& $m {$script:CandidateTest};Check $r.candidate_recorded 'store fixture ready'
 $dir=Join-Path $s.root ('UfwProgramCandidate-'+$s.data.candidate_id);$file=Join-Path $dir 'candidate.json';$bytes=[IO.File]::ReadAllBytes($file);$hash=(Get-FileHash $file).Hash
 $caught='';try{& $m {param($entry). $entry;function Get-UfwProgramCandidateNativeRoot {return $script:CandidateTest.root};Save-UfwProgramCandidateNative $script:CandidateTest.data} (Join-Path $Root 'CandidateEntry.ps1')|Out-Null}catch{$caught=$_.Exception.GetBaseException().Message}
 Check ($caught -ceq 'ufw_journal_directory_collision' -and (Get-FileHash $file).Hash -ceq $hash) 'same candidate cannot overwrite or replay'
 foreach($mode in @('checksum','extra','authority','receipt','partial','kind_array','architecture_array','id_array')){
  [IO.File]::WriteAllBytes($file,$bytes)
  if($mode -ceq 'extra'){[IO.File]::WriteAllText((Join-Path $dir 'extra.txt'),'unknown')}
  elseif($mode -ceq 'partial'){[IO.File]::WriteAllText($file,'{')}
  else{
   & $m {param($entry,$file,$mode). $entry;$en=ConvertFrom-Json ([IO.File]::ReadAllText($file));if($mode -ceq 'checksum'){$en.sha256='0'*64}else{$data=ConvertFrom-Json $en.payload;switch($mode){authority{$data.execution_authorized=$true};receipt{$data.receipt.authorizes_firewall_change=$true};kind_array{$data.profile_kind=@('installer')};architecture_array{$data.programs[0].architecture=@('x86')};id_array{$data.programs[0].program_id=@('program01')}};$en.payload=Get-UfwCandidateJson $data;$en.sha256=Get-UfwJournalHash $en.payload};[IO.File]::WriteAllText($file,(Get-UfwCandidateJson $en))} (Join-Path $Root 'CandidateEntry.ps1') $file $mode
  }
  $caught='';try{& $m {param($entry,$dir). $entry;Read-UfwProgramCandidateRecord $dir $script:CandidateTest.data.candidate_id} (Join-Path $Root 'CandidateEntry.ps1') $dir|Out-Null}catch{$caught=$_.Exception.GetBaseException().Message}
  Check (-not [string]::IsNullOrEmpty($caught)) ('reject record '+$mode)
  if($mode -ceq 'extra'){[IO.File]::Delete((Join-Path $dir 'extra.txt'))}
 }
 [IO.File]::WriteAllBytes($file,$bytes)
 function global:ConvertFrom-Json {param([Parameter(ValueFromPipeline=$true)]$InputObject)process{$v=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject;if([string]$InputObject -match '^\s*\['){Write-Output -NoEnumerate @($v)}else{$v}}}
 try{$r=Run-Case 'ps51_array';Check $r.candidate_recorded 'PS51 JSON array contract'}finally{Remove-Item Function:\global:ConvertFrom-Json}
 foreach($n in @('CandidateEntry.ps1','Run-Candidate.ps1')){
  $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $n),[ref]$t,[ref]$e);Check ($e.Count -eq 0) ('parse '+$n)
  $cmds=@($ast.FindAll({param($a)$a -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
  Check (@($cmds|Where-Object{$_ -match '^(Start-Process|Get-AuthenticodeSignature|Set-Net|New-Net|Remove-Net|Resolve-DnsName|Invoke-WebRequest|Invoke-RestMethod|rasdial|netsh|Set-Acl|Add-UfwPreparationCheckpoint|Save-UfwNativePreparation|Read-UfwPreparationJournal)$'}).Count -eq 0) ('no executable/network/firewall or baseline journal cmd '+$n)
 }
 $out=[ordered]@{suite='protected-installer-program-candidate-01';passed=$true;assertions=$script:checks;real_Linux_file_IO_executed=$true;Windows_ACL_executed=$false;Windows_file_picker_and_program_observation_mocked=$true;candidate_consent_UI_mocked=$true;PS51_JSON_array_contract_shim_tested=$true;native_firewall_executor_present=$false;ready_for_apply=$false}
 $out|ConvertTo-Json|Set-Content '/data/ufw-program-candidate-v01/evidence/model-tests.json' -Encoding UTF8;$out|ConvertTo-Json -Compress
}finally{if([IO.Directory]::Exists($base)){Remove-Item -LiteralPath $base -Recurse -Force}}
