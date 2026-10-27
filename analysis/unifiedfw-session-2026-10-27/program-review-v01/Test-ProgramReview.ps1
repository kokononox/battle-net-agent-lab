param([string]$Root='/data/ufw-program-review-v01/package/UFW-PROGRAM-REVIEW-01')
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $Root 'ProgramReader.cs'))) -Language CSharp
$script:checks=0
function Check($b,$label){$script:checks++;if(-not $b){throw $label}}
function Reject($block,$code){$got='';try{& $block|Out-Null}catch{$got=$_.Exception.GetBaseException().Message};Check ($got -ceq $code) ('expected '+$code+' got '+$got)}
foreach($p in @('C:\Fixture\installer.exe','D:\Other folder\agent.EXE')){Check ([UfwProgramReview01.Reader]::ValidatePathText($p) -ceq $p) 'exact local path accepted as text only'}
foreach($p in @('','Any','*','installer.exe','.\installer.exe','c:\Fixture\installer.exe','C:/Fixture/installer.exe','\\server\share\installer.exe','\\?\C:\Fixture\installer.exe','%TEMP%\installer.exe','C:\Fixture\..\installer.exe','C:\Fixture\installer.exe:stream','C:\Fixture\installer.exe ','C:\Fixture.\installer.exe','C:\Fixture\CON.exe','C:\Fixture\installer.dll','C:\Fixture\*.exe',"C:\Fixture\`ninstaller.exe")) {Reject {[UfwProgramReview01.Reader]::ValidatePathText($p)} 'ufw_program_exact_local_exe_path'}
foreach($leaf in @('svchost.exe','rundll32.exe','dllhost.exe')){Reject {[UfwProgramReview01.Reader]::ValidatePathText('C:\Fixture\'+$leaf)} 'ufw_program_shared_host_requires_service_design'}
function Fixture([string]$Arch='x64'){
 $b=New-Object byte[] 1024
 [Array]::Copy([BitConverter]::GetBytes([uint16]0x5a4d),0,$b,0,2);[Array]::Copy([BitConverter]::GetBytes([int]128),0,$b,0x3c,4)
 [Array]::Copy([BitConverter]::GetBytes([uint32]0x4550),0,$b,128,4);[Array]::Copy([BitConverter]::GetBytes([uint16]$(if($Arch -ceq 'x64'){0x8664}else{0x14c})),0,$b,132,2)
 [Array]::Copy([BitConverter]::GetBytes([uint16]1),0,$b,134,2);[Array]::Copy([BitConverter]::GetBytes([uint16]$(if($Arch -ceq 'x64'){240}else{224})),0,$b,148,2)
 [Array]::Copy([BitConverter]::GetBytes([uint16]2),0,$b,150,2);[Array]::Copy([BitConverter]::GetBytes([uint16]$(if($Arch -ceq 'x64'){0x20b}else{0x10b})),0,$b,152,2);[Array]::Copy([BitConverter]::GetBytes([uint16]2),0,$b,220,2)
 return ,$b
}
function Pe($Bytes){$s=New-Object IO.MemoryStream(,$Bytes);try{return [UfwProgramReview01.Reader]::InspectPe($s)}finally{$s.Dispose()}}
foreach($arch in @('x86','x64')){Check ((Pe (Fixture $arch)) -ceq $arch) 'PE fixture architecture'}
foreach($mode in @('MZ','negative_offset','large_offset','PE','zero_sections','too_many_sections','dll','not_executable','optional_short','wrong_machine','wrong_magic','subsystem','section_table_past_eof')){
 $b=Fixture
 switch($mode){
 MZ{$b[0]=0};negative_offset{[Array]::Copy([BitConverter]::GetBytes(-1),0,$b,0x3c,4)};large_offset{[Array]::Copy([BitConverter]::GetBytes([int]2000000),0,$b,0x3c,4)}
 PE{$b[128]=0};zero_sections{$b[134]=0};too_many_sections{$b[134]=97};dll{[Array]::Copy([BitConverter]::GetBytes([uint16]0x2002),0,$b,150,2)};not_executable{$b[150]=0};optional_short{$b[148]=1;$b[149]=0};wrong_machine{$b[132]=0};wrong_magic{$b[152]=0};subsystem{$b[220]=1};section_table_past_eof{$b[134]=50}
 }
 $failed=$false;try{Pe $b|Out-Null}catch{$failed=$true};Check $failed ('reject PE '+$mode)
}
Reject {[UfwProgramReview01.Reader]::Observe('C:\Fixture\installer.exe')} 'ufw_program_windows_required'
# Exercise private same-handle metadata comparison with reflection only, not native Windows handles.
$t=[UfwProgramReview01.Reader].GetNestedType('Info',[Reflection.BindingFlags]::NonPublic);$method=[UfwProgramReview01.Reader].GetMethod('Stable',[Reflection.BindingFlags]'NonPublic,Static')
$a=[Activator]::CreateInstance($t);$b=[Activator]::CreateInstance($t);Check ($method.Invoke($null,@($a,$b))) 'equal mocked handle info'
foreach($field in @('Attributes','Volume','SizeHigh','SizeLow','Links','IndexHigh','IndexLow')){
 $b=[Activator]::CreateInstance($t);$t.GetField($field).SetValue($b,[uint32]1);Check (-not $method.Invoke($null,@($a,$b))) ('identity drift '+$field)
}
. (Join-Path $Root 'ProgramReview.ps1')
function script:Read-Host {param($Prompt)$s=$script:test;$s.calls++;if($s.calls -le $s.answers.Count){return $s.answers[$s.calls-1]};return ''}
function script:Read-UfwProgramNativeObservation([string]$Path){
 $s=$script:test;$s.reads++
 if($s.mode -ceq 'failure'){throw 'PRIVATE_USER_PATH_OR_SERVER'}
 if($s.mode -ceq 'safe_failure'){throw 'ufw_program_changed_during_observation'}
 $n=$s.reads;if($s.mode -ceq 'duplicate'){$n=1}
 return [pscustomobject]@{Path=('C:\PRIVATE_USER_PATH\program'+$n+'.exe');Sha256=('a'*64);FileId=('b'*15+$n);VolumeId='c'*8;Architecture='x64';Length=1024;SameHandleDoubleHashMatched=$true;NativeIdentityObserved=$true;AuthenticodeVerified=$false;ProgramTrusted=$false;ExecutionAuthorized=$false}
}
foreach($mode in @('cancel','single','two','duplicate','failure','safe_failure','maximum')){
 $answers=@('C:\Fixture\one.exe');if($mode -ceq 'cancel'){$answers=@()};if($mode -cin @('two','duplicate')){$answers=@('C:\Fixture\one.exe','C:\Fixture\two.exe')};if($mode -ceq 'maximum'){$answers=@(1..17|ForEach-Object{'C:\Fixture\'+$_+'.exe'})}
 $script:test=[pscustomobject]@{answers=$answers;mode=$mode;calls=0;reads=0}
 $r=Invoke-UfwProgramLocalReview
 if($mode -cin @('single','two','maximum')){Check ($r.completed -and $r.review_displayed -and $r.observed_count -eq $(if($mode -ceq 'maximum'){16}else{$answers.Count})) ('successful mock review '+$mode)}
 elseif($mode -ceq 'cancel'){Check ($r.completed -and $r.code -ceq 'ufw_program_cancelled_no_selection' -and $script:test.reads -eq 0) 'empty selection no reads'}
 else{Check (-not $r.completed -and -not $r.review_displayed) ('fail '+$mode)}
 if($mode -ceq 'duplicate'){Check ($r.code -ceq 'ufw_program_duplicate_selection') 'duplicate identity not inherited'}
 if($mode -ceq 'failure'){Check ($r.code -ceq 'ufw_program_observation_unavailable') 'raw exception redacted'}
 if($mode -ceq 'safe_failure'){Check ($r.code -ceq 'ufw_program_changed_during_observation') 'safe failure preserved'}
 foreach($k in @('raw_identity_exported','program_config_saved','program_trusted','authenticode_verification_requested','program_execution_requested','firewall_change_requested','journal_write_requested','VPN_change_requested','DNS_query_generated','ready_for_apply','no_leak_certified')){Check ($r.$k -ceq $false) ('boundary '+$mode+' '+$k)}
 $json=$r|ConvertTo-Json -Depth 16;Check ($json -notmatch 'PRIVATE_USER_PATH|[a-f0-9]{64}|FileId|VolumeId|Sha256|C:\\') ('safe public report '+$mode)
}
foreach($name in @('ProgramReview.ps1','Run-Review.ps1')){
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $name),[ref]$tokens,[ref]$errors);Check ($errors.Count -eq 0) ('parse '+$name)
 $cmds=@($ast.FindAll({param($a)$a -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
 Check (@($cmds|Where-Object{$_ -match '^(Start-Process|Get-AuthenticodeSignature|Set-Net|New-Net|Remove-Net|Resolve-DnsName|Invoke-WebRequest|Invoke-RestMethod|rasdial|netsh|Set-Acl)$'}).Count -eq 0) ('no execution/network/trust mutation '+$name)
}
$src=[IO.File]::ReadAllText((Join-Path $Root 'ProgramReader.cs'))
Check ($src.Contains('CreateFileW(requested,0x80000000,1,IntPtr.Zero,3,0x08200000') -and $src.Contains('before.Links!=1') -and $src.Contains('first!=second')) 'native read-only open/one-link/two-hash guards present (not live tested)'
Check ($src -notmatch 'Process\.Start|WinVerifyTrust|WriteFile|CreateProcess|HttpClient|WebClient|Socket|FileAccess\.Write') 'no native execution/trust/network/writer entrypoints'
$result=[ordered]@{suite='local-program-observation-model-01';passed=$true;assertions=$script:checks;CSharp_compiled_on_Linux=$true;PE_header_and_path_fixtures_executed=$true;review_prompt_and_native_observations_mocked=$true;Windows_file_API_executed=$false;real_EXE_identity_verified=$false;real_user_program_selected=$false;program_config_saved=$false;native_executor_implemented=$false;ready_for_apply=$false}
$result|ConvertTo-Json|Set-Content '/data/ufw-program-review-v01/evidence/model-tests.json' -Encoding UTF8;$result|ConvertTo-Json -Compress
