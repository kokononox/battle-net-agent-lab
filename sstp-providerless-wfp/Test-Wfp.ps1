param([Parameter(Mandatory=$true)][string]$OutputPath)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
. "$PSScriptRoot/../sstp-allowlist-backend/Journal.ps1"
. "$PSScriptRoot/../sstp-policy-compare/Inventory.ps1"
$script:checks=0;$script:faults=0;$script:recoveries=0;$script:pairs=0;$script:conflicts=0;$script:fixtures=@();$script:native=$null;$script:stage='setup';$passed=$false;$errorCode=$null;$cleanup=0;$remaining=-1;$equal=$false;$display=-1;$baseline=$null;$epochCases=0
function Check([bool]$Ok){if(-not $Ok){throw 'wfp_test_assertion'};$script:checks++}
function RunNative($Plan,[string]$Mode,[int]$Expected=0){
 $a=@($Mode)+@($Plan.keys)+@([string]$Plan.luid,[string]$Plan.ip,[string]$Plan.app)
 $t=& $script:native @a;$code=$LASTEXITCODE
 if($code -ne $Expected){$safe=($t -join '') -replace '[^a-zA-Z0-9_]','';Write-Host ('wfp_native_code_'+$code+'_'+$safe.Substring(0,[Math]::Min(60,$safe.Length)));throw 'wfp_test_native'}
 Check ($code -eq $Expected)
 if($Expected -eq 0){return (($t -join "`n")|ConvertFrom-Json)}
}
function Audit($Fixture,[string]$State){$a=RunNative $Fixture.plan 'audit';Check ($a.state -ceq $State -and $a.strict_readback -eq $true -and $a.providerless -eq $true -and $a.disabled_filters -eq 0 -and $a.objects -eq $(if($State -eq 'installed'){4}else{0}) -and $a.filters -eq $(if($State -eq 'installed'){3}else{0}))}
function Worker($Fixture,[string]$Action,[string]$Fault='none',[int]$Expected=0){
 & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PSScriptRoot/Worker.ps1" -Root $Fixture.root -Action $Action -Fault $Fault
 Check ($LASTEXITCODE -eq $Expected)
}
function Phase($Fixture,[string]$Expected){$j=ReadJournal $Fixture.root;Check ($j.status -ceq 'valid' -and $j.record.state.phase -ceq $Expected)}
function NewFixture([string]$Luid,[string]$Ip){
 $dir=Join-Path $script:work ([guid]::NewGuid().ToString('N'));$null=InitializeJournalRoot $dir
 $plan=[pscustomobject][ordered]@{keys=@(1..4|ForEach-Object{[guid]::NewGuid().ToString('B')});luid=$Luid;ip=$Ip;app=$script:probeA}
 $s=[pscustomobject][ordered]@{schema='sstp-providerless-state-1';phase='planned';plan=$plan;native_path=$script:native;native_hash=(Get-FileHash -LiteralPath $script:native -Algorithm SHA256).Hash.ToLowerInvariant()}
 $null=WriteJournal $dir -1 $s;$f=[pscustomobject]@{root=$dir;plan=$plan};$script:fixtures+=,$f;return $f
}
function Probe([string]$Path,[string]$Ip){& $Path $Ip '443' | Out-Null;return [int]$LASTEXITCODE}
function Pair([string]$Ip,[bool]$Blocked){$a=Probe $script:probeA $Ip;$b=Probe $script:probeB $Ip;Check ($a -eq $(if($Blocked){2}else{0}) -and $b -eq 0);$script:pairs++}
try {
 $script:work=Join-Path $env:RUNNER_TEMP ('sstp-wfp-'+[guid]::NewGuid().ToString('N'));$null=InitializeJournalRoot $script:work
 $script:native=Join-Path $script:work 'sstp-providerless-native.exe';$script:probeA=Join-Path $script:work ('sstp-providerless-probe-'+[guid]::NewGuid().ToString('N')+'.exe');$script:probeB=Join-Path $script:work ('sstp-providerless-control-'+[guid]::NewGuid().ToString('N')+'.exe')
 $script:stage='compile'
 $vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
 $vs=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
 Check ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($vs))
 $vc=Join-Path $vs 'Common7\Tools\VsDevCmd.bat';$source=Join-Path $PSScriptRoot 'WfpLab.cpp';$obj=Join-Path $script:work 'native.obj';$log=Join-Path $script:work 'compile.log';$batch=Join-Path $script:work 'compile.cmd'
 $commands="@echo off`r`ncall `"$vc`" -arch=x64 -host_arch=x64 >nul 2>&1`r`nif errorlevel 1 exit /b 1`r`ncl.exe /nologo /EHsc /W4 /WX /MT /Fe:`"$script:native`" /Fo:`"$obj`" `"$source`" >`"$log`" 2>&1`r`nexit /b %errorlevel%`r`n"
 [IO.File]::WriteAllText($batch,$commands,[Text.Encoding]::ASCII);& $batch
 if($LASTEXITCODE -ne 0){$errors=@([regex]::Matches([IO.File]::ReadAllText($log),'(?:error|warning) [A-Z]+[0-9]+')|ForEach-Object{$_.Value}|Select-Object -Unique -First 8);Write-Host ('wfp_compile_'+($errors -join '_'));foreach($m in [regex]::Matches([IO.File]::ReadAllText($log),"WfpLab\.cpp\(([0-9]+)\): error (C[0-9]+): '([A-Za-z_][A-Za-z_0-9]*)'")){Write-Host ('wfp_source_line_'+$m.Groups[1].Value+'_'+$m.Groups[2].Value+'_'+$m.Groups[3].Value)};throw 'wfp_compile_failed'}
 Check (Test-Path -LiteralPath $script:native)
 Add-Type -TypeDefinition ([IO.File]::ReadAllText("$PSScriptRoot/Probe.cs")) -OutputAssembly $script:probeA -OutputType ConsoleApplication
 Copy-Item -LiteralPath $script:probeA -Destination $script:probeB;Check (Test-Path -LiteralPath $script:probeB)
 $script:stage='binding_epoch_model'
 . "$PSScriptRoot/BindingEpoch.ps1"
 . "$PSScriptRoot/Test-Epoch.ps1"
 $epochCases=TestEpochModel
 Check ($epochCases -eq 20)
 $script:stage='baseline' 
 $baseline=ReadPolicyInventory
 $target=$null
 foreach($ip in @([Net.Dns]::GetHostAddresses('github.com')|Where-Object{$_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork}|Select-Object -First 3)){
  if((Probe $script:probeA $ip.IPAddressToString) -eq 0 -and (Probe $script:probeB $ip.IPAddressToString) -eq 0){$target=$ip.IPAddressToString;break}
 }
 Check ($null -ne $target)
 $idText=& $script:native 'identity' $target;Check ($LASTEXITCODE -eq 0);$identity=($idText -join "`n")|ConvertFrom-Json
 Check ($identity.roundtrip -eq $true -and $identity.selected_luid -is [string] -and $identity.loopback_luid -is [string] -and $identity.selected_luid -cne $identity.loopback_luid)
 # Each helper exits before a fresh audit / probe. B is a different executable path.
 $script:stage='matching_interface'
 $f=NewFixture $identity.selected_luid $target;Audit $f 'absent';Worker $f 'Install';Phase $f 'installed';Audit $f 'installed';Pair $target $false;Worker $f 'Install';Audit $f 'installed'
 # Wrong expected binding cannot audit/remove the real installed filter set.
 foreach($field in @('luid','ip')){
  $wrong=($f.plan|ConvertTo-Json -Depth 8 -Compress)|ConvertFrom-Json
  if($field -ceq 'luid'){$wrong.luid=$identity.loopback_luid}else{$wrong.ip='192.0.2.44'}
  $null=RunNative $wrong 'audit' 1;$null=RunNative $wrong 'remove' 1;Audit $f 'installed';$script:conflicts++
 }
 # Corrupt journal: stop, leave exact rules installed; lab restores original bytes only.
 $jp=Join-Path $f.root 'journal.json';$bytes=[IO.File]::ReadAllBytes($jp)
 [IO.File]::WriteAllText($jp,'corrupt');Worker $f 'Remove' 'none' 1;Audit $f 'installed';[IO.File]::WriteAllBytes($jp,$bytes);$script:conflicts++
 Worker $f 'Remove';Phase $f 'removed';Audit $f 'absent';Pair $target $false;Worker $f 'Remove'
 $script:stage='wrong_interface'
 $f=NewFixture $identity.loopback_luid $target;Worker $f 'Install';Audit $f 'installed';Pair $target $true;Worker $f 'Remove';Audit $f 'absent';Pair $target $false
 $script:stage='wrong_destination'
 $f=NewFixture $identity.selected_luid '192.0.2.44';Worker $f 'Install';Audit $f 'installed';Pair $target $true;Worker $f 'Remove';Audit $f 'absent';Pair $target $false
 $script:stage='fault_recovery'
 foreach($case in @('before-native','abort-add','after-install-commit','abort-remove','after-remove-commit')){
  $f=NewFixture $identity.selected_luid $target
  if($case -in @('abort-remove','after-remove-commit')){Worker $f 'Install';$action='Remove';$pending='removing'}else{$action='Install';$pending='installing'}
  Worker $f $action $case 73;Phase $f $pending;$script:faults++
  $expected=if($case -in @('after-install-commit','abort-remove')){'installed'}else{'absent'}
  Audit $f $expected;Worker $f 'Recover';$script:recoveries++
  $phase=if($case -in @('before-native','abort-add')){'planned'}elseif($case -ceq 'after-remove-commit'){'removed'}else{'installed'}
  Phase $f $phase;Audit $f $expected
  if($expected -ceq 'installed'){Worker $f 'Remove';Audit $f 'absent'}else{Worker $f 'Install';Audit $f 'installed';Worker $f 'Remove';Audit $f 'absent'}
 }
 $script:stage='final_connectivity';Pair $target $false
 $passed=$true
} catch {
 $errorCode='wfp_test_failed';Write-Host ('wfp_test_stage_'+$script:stage)
 # Fixed code, source basename and numeric line only; never private exception text.
 $ln=$_.InvocationInfo.ScriptLineNumber;Write-Host ('wfp_test_line_'+$ln)
} finally {
 if($script:fixtures.Count -gt 0 -and $null -ne $script:native -and (Test-Path -LiteralPath $script:native)){
  try {
   foreach($f in $script:fixtures){$null=RunNative $f.plan 'remove';Audit $f 'absent';$cleanup++}
   $remaining=0
  }catch{$passed=$false;$errorCode='wfp_cleanup_failed';Write-Host 'wfp_cleanup_stopped'}
 } elseif($script:fixtures.Count -eq 0){$remaining=0}
 if($null -ne $baseline){try{$c=ComparePolicyInventory $baseline (ReadPolicyInventory);$equal=[bool]$c.policy_equal;$display=[int]$c.display_rule_changes;if(-not $equal){$passed=$false;$errorCode='wfp_policy_drift'}}catch{$passed=$false;$errorCode='wfp_inventory_failed'}}
 $r=[ordered]@{schema='sstp-providerless-test-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;passed=$passed;error_code=$errorCode;checks=$script:checks;epoch_model_cases=$epochCases;providerless_tested=$passed;fault_cases=$script:faults;fresh_process_recoveries=$script:recoveries;packet_pairs=$script:pairs;owned_conflict_stops=$script:conflicts;fixture_sets=$script:fixtures.Count;cleanup_sets=$cleanup;remaining_objects=$remaining;unrelated_windows_firewall_policy_equal=$equal;unrelated_display_changes=$display;whole_machine_guard_tested=$false;active_sstp_tested=$false;ipv6_packet_tested=$false;reboot_tested=$false;user_device_tested=$false;ready_for_user_apply=$false}
 [IO.File]::WriteAllText($OutputPath,(ConvertTo-Json -InputObject $r -Depth 8),[Text.Encoding]::UTF8)
 # Private files are not uploaded. Remove only after native cleanup succeeds.
 if($remaining -eq 0 -and (Get-Variable work -Scope Script -ErrorAction SilentlyContinue)) {Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction SilentlyContinue}
}
if(-not $passed){exit 1};exit 0
