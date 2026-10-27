param([string]$Root='/data/ufw-program-review-v011/package/UFW-PROGRAM-REVIEW-011')
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $Root 'ProgramReader.cs'))) -Language CSharp
. (Join-Path $Root 'ProgramReview.ps1')
$script:checks=0
function Check($b,$label){$script:checks++;if(-not $b){throw $label}}
function script:Select-UfwProgramFiles {
 $s=$script:test;$s.pickerCalls++
 if($s.mode -ceq 'picker_failure'){throw 'PRIVATE_PICKER_PATH'}
 return $s.selection
}
function script:Read-UfwProgramNativeObservation([string]$Path){
 $s=$script:test;$s.reads++
 if($s.mode -ceq 'reader_failure'){throw 'PRIVATE_EXE_PATH'}
 if($s.mode -ceq 'safe_failure'){throw 'ufw_program_changed_during_observation'}
 $i=$s.reads;if($s.mode -ceq 'duplicate_identity'){$i=1}
 return [pscustomobject]@{Path=('C:\PRIVATE_LOCAL_PATH\program'+$i+'.exe');Sha256=('a'*64);FileId=('b'*15+$i);VolumeId='c'*8;Architecture='x86';Length=1024;SameHandleDoubleHashMatched=$true;NativeIdentityObserved=$true;AuthenticodeVerified=$false;ProgramTrusted=$false;ExecutionAuthorized=$false}
}
foreach($mode in @('cancel','one','two','maximum','excess','empty_ok','cancel_with_paths','cancel_wrong_type','paths_not_array','duplicate_path','duplicate_identity','invalid_path','nonstring_path','picker_failure','reader_failure','safe_failure')){
 $p=[pscustomobject]@{cancelled=$false;paths=@('C:\Fixture\one.exe')}
 switch($mode){
 cancel{$p.cancelled=$true;$p.paths=@()};two{$p.paths=@('C:\Fixture\one.exe','C:\Fixture\two.exe')}
 maximum{$p.paths=@(1..16|ForEach-Object{'C:\Fixture\'+$_+'.exe'})};excess{$p.paths=@(1..17|ForEach-Object{'C:\Fixture\'+$_+'.exe'})}
 empty_ok{$p.paths=@()};cancel_with_paths{$p.cancelled=$true};cancel_wrong_type{$p.cancelled='true'};paths_not_array{$p.paths='C:\Fixture\one.exe'}
 duplicate_path{$p.paths=@('C:\Fixture\one.exe','C:\Fixture\ONE.EXE')};duplicate_identity{$p.paths=@('C:\Fixture\one.exe','C:\Fixture\two.exe')}
 invalid_path{$p.paths=@('C:\Fixture\one.exe','\\server\share\two.exe')};nonstring_path{$p.paths=@('C:\Fixture\one.exe',1)}
 }
 $script:test=[pscustomobject]@{mode=$mode;selection=$p;pickerCalls=0;reads=0}
 $r=Invoke-UfwProgramLocalReview
 Check ($script:test.pickerCalls -eq 1) ('one picker invocation '+$mode)
 if($mode -cin @('one','two','maximum')){Check ($r.completed -and $r.picker_completed -and $r.review_displayed -and $r.observed_count -eq $p.paths.Count -and $r.selected_count -eq $p.paths.Count -and $r.results.Count -eq $p.paths.Count) ('review success '+$mode)}
 elseif($mode -ceq 'cancel'){Check ($r.completed -and $r.selection_cancelled -and $r.code -ceq 'ufw_program_cancelled_no_selection' -and $script:test.reads -eq 0) 'cancel not a successful EXE observation'}
 else{
  Check (-not $r.completed -and -not $r.review_displayed) ('refusal '+$mode)
  $expected=@{excess='ufw_program_selection_count';empty_ok='ufw_program_selection_count';cancel_with_paths='ufw_program_picker_invalid_result';cancel_wrong_type='ufw_program_picker_invalid_result';paths_not_array='ufw_program_picker_invalid_result';duplicate_path='ufw_program_duplicate_selection';duplicate_identity='ufw_program_duplicate_selection';invalid_path='ufw_program_exact_local_exe_path';nonstring_path='ufw_program_picker_invalid_result';picker_failure='ufw_program_observation_unavailable';reader_failure='ufw_program_observation_unavailable';safe_failure='ufw_program_changed_during_observation'}
  Check ($r.code -ceq $expected[$mode]) ('code '+$mode+' got '+$r.code)
  if($mode -cnotin @('duplicate_identity','reader_failure','safe_failure')){Check ($script:test.reads -eq 0) ('whole invalid selection rejected before EXE observation '+$mode)}
 }
 foreach($k in @('raw_identity_exported','program_config_saved','program_trusted','authenticode_verification_requested','program_execution_requested','firewall_change_requested','journal_write_requested','VPN_change_requested','DNS_query_generated','ready_for_apply','no_leak_certified')){Check ($r.$k -ceq $false) ('boundary '+$mode+' '+$k)}
 $j=$r|ConvertTo-Json -Depth 16;Check ($j -notmatch 'PRIVATE_|[a-f0-9]{64}|FileId|VolumeId|Sha256|C:\\') ('no private selection or error in report '+$mode)
}
foreach($n in @('ProgramReview.ps1','Run-Review.ps1')){
 $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $n),[ref]$t,[ref]$e);Check ($e.Count -eq 0) ('parse '+$n)
 $cmds=@($ast.FindAll({param($a)$a -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
 Check (@($cmds|Where-Object{$_ -match '^(Read-Host|Start-Process|Get-AuthenticodeSignature|Set-Net|New-Net|Remove-Net|Resolve-DnsName|Invoke-WebRequest|Invoke-RestMethod|rasdial|netsh|Set-Acl)$'}).Count -eq 0) ('no typed path prompt/execution/network/firewall cmd '+$n)
}
$s=[IO.File]::ReadAllText((Join-Path $Root 'ProgramReview.ps1'))
foreach($text in @('System.Windows.Forms.OpenFileDialog','GetApartmentState()','Multiselect=$true','CheckFileExists=$true','CheckPathExists=$true','ValidateNames=$true','DereferenceLinks=$false','RestoreDirectory=$true','AutoUpgradeEnabled=$false','finally{$dialog.Dispose()}')){Check ($s.Contains($text)) ('picker configuration present (not UI executed) '+$text)}
Check ((Get-FileHash (Join-Path $Root 'ProgramReader.cs')).Hash -ceq (Get-FileHash '/data/ufw-program-review-v01/package/UFW-PROGRAM-REVIEW-01/ProgramReader.cs').Hash) 'native reader unchanged byte-for-byte'
$result=[ordered]@{suite='file-picker-program-review-model-011';passed=$true;assertions=$script:checks;selection_scenarios=16;Windows_file_dialog_mocked=$true;native_file_observation_mocked=$true;native_reader_unchanged=$true;Windows_dialog_executed=$false;Windows_file_API_executed=$false;program_config_saved=$false;ready_for_apply=$false}
$result|ConvertTo-Json|Set-Content '/data/ufw-program-review-v011/evidence/model-tests.json' -Encoding UTF8;$result|ConvertTo-Json -Compress
