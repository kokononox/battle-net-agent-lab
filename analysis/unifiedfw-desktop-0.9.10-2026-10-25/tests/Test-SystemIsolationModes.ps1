param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Check($b,$m){$script:checks++;if(-not $b){throw $m}}
function Fails($Block,$Code){$caught=$false;try{& $Block|Out-Null}catch{$caught=$_.Exception.Message -ceq $Code};Check $caught ('expected '+$Code)}
. (Join-Path $Root 'lab/session-core.ps1');. (Join-Path $Root 'lab/native.ps1');. (Join-Path $Root 'app/isolation-native.ps1');. (Join-Path $Root 'app/policy-mode-model.ps1')
Check ((Resolve-PolicyMode 0 1) -ceq 'blacklist_only') 'blacklist selection';Check ((Resolve-PolicyMode 1 0) -ceq 'direct_isolation') 'direct selection';Check ((Resolve-PolicyMode 1 1) -ceq 'full_isolation') 'VPN selection'
foreach($code in @('blacklist_only','direct_isolation','full_isolation')){$x=Get-PolicySelection $code;Check ((Resolve-PolicyMode $x.policy $x.connection) -ceq $code) ('roundtrip '+$code)}
$x=Get-PolicySelection 'vpn_allowlist';Check ($x.legacy -and (Resolve-PolicyMode $x.policy $x.connection) -ceq 'full_isolation') 'legacy UI choice requires explicit new save'
$script:sstpCalls=0;$script:disabledProfile=$false;$script:bypass=$false
function IsoAssertNoOtherEngine{param($S)@{read_only=$true}}
function IsoDetectSstp{$script:sstpCalls++;throw 'unexpected_SSTP_detection_in_direct_mode'}
function IsoForeignAllows{param($S)return ,@()}
function IsoProfileRead{param($Name)[pscustomobject]@{name=$Name;enabled=$(if($script:disabledProfile){'False'}else{'True'});default_outbound='Allow';allow_local_rules='True'}}
function Get-NetFirewallSecurityFilter{param($PolicyStore,$ErrorAction)if($script:bypass){[pscustomobject]@{OverrideBlockRules='True'}}}
$policy=[pscustomobject]@{schema='unified-isolation-policy-1';owner=('a'*32);generation=1;connection='direct';whitelist=@([pscustomobject]@{remote_addresses=@('8.8.8.8');protocol='TCP';remote_port='443-445'});overlaps=@()}
$p=IsoPrepare $policy $null;Check ($script:sstpCalls -eq 0) 'normal isolation must not require VPN';Check ($null -eq $p.vpn) 'no VPN fixture invented';Check ($p.rules.Count -eq 1) 'no implicit DNS/DHCP/transport rules';$rule=$p.rules[0].spec;Check ($rule.program -ceq 'Any' -and $rule.service -ceq 'Any') 'global all applications';Check ($rule.interface_alias -ceq 'Any' -and $rule.interface_type -ceq 'Any') 'not forced into VPN';Check ($rule.remote_addresses[0] -ceq '8.8.8.8' -and $rule.port -ceq '443-445') 'precise endpoint range';Check ($p.profiles.Count -eq 3) 'all profiles';Check (-not $p.no_leak_certified) 'no leak claims'
$active=[pscustomobject]@{phase='armed';plan=[pscustomobject]@{policy=[pscustomobject]@{connection='vpn'}}};Fails {IsoPrepare $policy $active} 'iso_connection_change_requires_explicit_restore'
$script:disabledProfile=$true;Fails {IsoPrepare $policy $null} 'iso_profile_not_ready_for_isolation';$script:disabledProfile=$false;$script:bypass=$true;Fails {IsoPrepare $policy $null} 'iso_authenticated_bypass_detected';$script:bypass=$false
$bad=$policy.PSObject.Copy();$bad.connection='mystery';Fails {IsoPrepare $bad $null} 'iso_invalid_connection_method'
$review=[pscustomobject]@{connection='direct';vpn=$null;quarantine_allow_count=4;whitelist=$policy.whitelist;overlaps=@()};$text=Get-IsolationReviewText $review;Check ($text.Contains('کل ویندوز') -and $text.Contains('VPN اجباری نیست')) 'human scope';Check ($text.Contains('DNS') -and $text.Contains('DHCP') -and $text.Contains('SYSTEM')) 'risk scope';Check (-not $text.Contains('"quarantine_allow_count"')) 'no JSON review'
$value=[pscustomobject]@{phase='armed';connection='direct';configuration_verified=$true;guardian_running=$true;guardian_heartbeat_fresh=$true};$text=Get-IsolationStatusText $value '12:00:00';Check ($text.Contains('معمولی') -and $text.Contains('تأیید نبود نشتی نیست')) 'human direct status'
$value|Add-Member NoteProperty guardian_last_error 'fixture failure';$text=Get-IsolationStatusText $value '12:00:01';Check (-not $text.Contains('تنظیمات فعال و محافظِ دارای گزارش تازه تأیید شدند')) 'guardian error not healthy status'
# Extract production controller-install/version functions. Run only with mock tasks, physical temp directory, real hash and private writes on Linux (not Windows ACL).
function Load-ProductionFunction($Name){$t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/isolation-worker.ps1'),[ref]$t,[ref]$e);$n=$a.Find({param($x)$x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -ceq $Name},$true);. ([scriptblock]::Create('function script:'+ $Name+$n.Extent.Text.Substring(('function '+$Name).Length).Replace('$PSScriptRoot',("'"+(Join-Path $Root 'app')+"'"))))}
Load-ProductionFunction 'IsoAssertActiveControllerVersion';Load-ProductionFunction 'IsoInstallController'
$script:IsoRoot=Join-Path ([IO.Path]::GetTempPath()) ('iso010-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($script:IsoRoot);$flat=$false
function IsoTaskRead{param($S)return $null}
function New-ScheduledTaskAction{param($Execute,$Argument)@{Execute=$Execute}}
function New-ScheduledTaskTrigger{param([switch]$AtStartup)@{}}
function New-ScheduledTaskPrincipal{param($UserId,$LogonType,$RunLevel)@{}}
function New-ScheduledTaskSettingsSet{param($ExecutionTimeLimit,$RestartCount,$RestartInterval,[switch]$StartWhenAvailable,[switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries,$MultipleInstances)@{}}
function Register-ScheduledTask{param($TaskName,$TaskPath,$Action,$Trigger,$Principal,$Settings,$Description,$ErrorAction)$script:taskRegistrationCount++}
function IsoTaskExpectedArguments{'fixture'};function IsoTaskName{param($S)'fixture'};$script:taskRegistrationCount=0;$env:SystemRoot=$script:IsoRoot
try{
 foreach($n in @('isolation-worker.ps1','isolation-core.ps1','isolation-native.ps1')){[IO.File]::WriteAllText((Join-Path $script:IsoRoot $n),'old fixture')}
 Fails {IsoAssertActiveControllerVersion ([pscustomobject]@{phase='armed'})} 'iso_protected_controller_changed_restore_with_original_version_first'
 # Functions extracted outside their file bind PSScriptRoot to test file; provide exact script invocation with module-local source root.
 $sourceRoot=Join-Path $Root 'app';$install=(Get-Command IsoInstallController).ScriptBlock.ToString().Replace('$PSScriptRoot',"'$sourceRoot'");Set-Item Function:IsoInstallController ([scriptblock]::Create($install))
 $s=[pscustomobject]@{owner=('a'*32);phase='prepared'};$script:IsoCanUpgradeControllers=$false
 Fails {IsoInstallController $s} 'iso_protected_controller_changed_restore_with_original_version_first'
 $script:IsoCanUpgradeControllers=$true;IsoInstallController $s
 foreach($n in @('isolation-worker.ps1','isolation-core.ps1','isolation-native.ps1')){Check ((Get-FileHash (Join-Path $script:IsoRoot $n)).Hash -ceq (Get-FileHash (Join-Path $sourceRoot $n)).Hash) ('controller upgrade readback '+$n)}
 Check ($script:taskRegistrationCount -eq 1) 'task registered only after controller copy'
}finally{Remove-Item $script:IsoRoot -Recurse -Force}
$main=[IO.File]::ReadAllText((Join-Path $Root 'app/ui.ps1'));$ui=[IO.File]::ReadAllText((Join-Path $Root 'app/ui-policy-review.ps1'));Check ($main.Contains("BeginOp 'policy_review'")) 'preview handler uses readable route';Check ($ui.Contains('جزئیات فنی — اختیاری')) 'JSON opt in only';Check (-not $ui.Contains('ConvertTo-Json')) 'no JSON on default review';Check ($main.Contains('Get-SelectedPolicyMode')) 'stable mode mapping in save';Check ($main.Contains("@('policy_review','load'")) 'review excluded from automatic technical navigation'
$result=@{suite='system-isolation-modes-and-human-review';assertions=$script:checks;passed=$true;Windows_GUI_executed=$false;Windows_network_executed=$false;protected_controller_files_tested_on_Linux_without_Windows_ACL_claim=$true};[IO.File]::WriteAllText((Join-Path $Root 'evidence/system-isolation-modes-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
