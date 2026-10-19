param([Parameter(Mandatory=$true)][string]$OutputPath)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
. "$PSScriptRoot/../sstp-allowlist-backend/Journal.ps1"
. "$PSScriptRoot/../sstp-policy-compare/Inventory.ps1"
$script:checks=0;$script:faults=0;$script:recoveries=0;$script:conflicts=0;$script:flows=0;$script:controls=0;$script:fresh=0;$script:payloadBytes=-1;$script:fixtures=@();$script:children=@();$script:servers=@();$script:native=$null;$script:stage='setup';$passed=$false;$errorCode=$null;$baseline=$null;$equal=$false;$display=-1;$cleanup=0;$remaining=-1
function Check([bool]$Ok){if(-not $Ok){throw 'reauth_assertion'};$script:checks++}
function RunNative($Plan,[string]$Mode,[int]$Expected=0){
 $argsNative=@($Mode)+@($Plan.keys)+@([string]$Plan.app);$t=& $script:native @argsNative;$code=$LASTEXITCODE
 if($code -ne $Expected){$safe=($t -join '') -replace '[^a-zA-Z0-9_]','';Write-Host ('reauth_native_code_'+$code+'_'+$safe.Substring(0,[Math]::Min(120,$safe.Length)));throw 'reauth_native_failed'}
 Check ($code -eq $Expected);if($Expected -eq 0){return (($t -join "`n")|ConvertFrom-Json)}
}
function Audit($Fixture,[string]$State){$a=RunNative $Fixture.plan 'audit';Check ($a.state -ceq $State -and $a.strict_readback -eq $true -and $a.providerless -eq $true -and $a.disabled_filters -eq 0 -and $a.objects -eq $(if($State -eq 'installed'){3}else{0}) -and $a.filters -eq $(if($State -eq 'installed'){2}else{0}))}
function Worker($Fixture,[string]$Action,[string]$Fault='none',[int]$Expected=0){
 & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PSScriptRoot/Worker.ps1" -Root $Fixture.root -Action $Action -Fault $Fault
 Check ($LASTEXITCODE -eq $Expected)
}
function Phase($Fixture,[string]$Expected){$j=ReadJournal $Fixture.root;Check ($j.status -ceq 'valid' -and $j.record.state.phase -ceq $Expected)}
function NewFixture {
 $dir=Join-Path $script:work ([guid]::NewGuid().ToString('N'));$null=InitializeJournalRoot $dir
 $plan=[pscustomobject][ordered]@{keys=@(1..3|ForEach-Object{[guid]::NewGuid().ToString('B')});app=$script:probeA}
 $s=[pscustomobject][ordered]@{schema='sstp-reauth-state-1';phase='planned';plan=$plan;native_path=$script:native;native_hash=(Get-FileHash -LiteralPath $script:native -Algorithm SHA256).Hash.ToLowerInvariant()}
 $null=WriteJournal $dir -1 $s;$f=[pscustomobject]@{root=$dir;plan=$plan};$script:fixtures+=,$f;return $f
}
function ReadProbe($Probe){$task=$Probe.process.StandardOutput.ReadLineAsync();if(-not $task.Wait(7000)){throw 'reauth_probe_timeout'};return [string]$task.Result}
function StartProbe([string]$Exe,[string]$Ip,[int]$Port){
 $tag=[guid]::NewGuid().ToString('N');$si=New-Object Diagnostics.ProcessStartInfo;$si.FileName=$Exe;$si.Arguments=$Ip+' '+$Port+' '+$tag;$si.UseShellExecute=$false;$si.RedirectStandardInput=$true;$si.RedirectStandardOutput=$true;$si.RedirectStandardError=$true;$si.CreateNoWindow=$true
 $p=New-Object Diagnostics.Process;$p.StartInfo=$si;$null=$p.Start();$v=[pscustomobject]@{process=$p;tag=$tag};$script:children+=,$v;Check ((ReadProbe $v) -ceq 'READY');return $v
}
function InvokeFlowEcho($Probe,[string]$Expected='OK'){$Probe.process.StandardInput.WriteLine([guid]::NewGuid().ToString('N'));$Probe.process.StandardInput.Flush();$reply=ReadProbe $Probe;if($reply -cne $Expected){$safe=if($reply -cin @('READY','OK','BLOCKED','CONNECT_FAILED')){$reply}else{'eof_or_invalid'};$code='running';if($Probe.process.WaitForExit(50)){$code=[string]$Probe.process.ExitCode};Write-Host ('reauth_probe_reply_'+$safe+'_exit_'+$code)};Check ($reply -ceq $Expected)}
function CloseProbe($Probe){if(-not $Probe.process.HasExited){try{$Probe.process.StandardInput.WriteLine('QUIT');$Probe.process.StandardInput.Flush()}catch{};if(-not $Probe.process.WaitForExit(2000)){$Probe.process.Kill();$Probe.process.WaitForExit()}}}
try {
 $script:work=Join-Path $env:RUNNER_TEMP ('sstp-reauth-'+[guid]::NewGuid().ToString('N'));$null=InitializeJournalRoot $script:work
 $script:native=Join-Path $script:work 'sstp-reauth-native.exe';$script:probeA=Join-Path $script:work ('sstp-reauth-probe-'+[guid]::NewGuid().ToString('N')+'.exe');$probeB=Join-Path $script:work ('sstp-reauth-control-'+[guid]::NewGuid().ToString('N')+'.exe');$probeC=Join-Path $script:work ('sstp-reauth-probe-'+[guid]::NewGuid().ToString('N')+'.exe')
 $script:stage='compile'
 $vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe';$vs=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
 Check ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($vs))
 $vc=Join-Path $vs 'Common7\Tools\VsDevCmd.bat';$source=Join-Path $PSScriptRoot 'WfpLab.cpp';$obj=Join-Path $script:work 'native.obj';$log=Join-Path $script:work 'compile.log';$batch=Join-Path $script:work 'compile.cmd'
 $commands="@echo off`r`ncall `"$vc`" -arch=x64 -host_arch=x64 >nul 2>&1`r`nif errorlevel 1 exit /b 1`r`ncl.exe /nologo /EHsc /W4 /WX /MT /Fe:`"$script:native`" /Fo:`"$obj`" `"$source`" >`"$log`" 2>&1`r`nexit /b %errorlevel%`r`n"
 [IO.File]::WriteAllText($batch,$commands,[Text.Encoding]::ASCII);& $batch
 if($LASTEXITCODE -ne 0){foreach($m in [regex]::Matches([IO.File]::ReadAllText($log),"WfpLab\.cpp\(([0-9]+)\): (?:error|warning) (C[0-9]+):(?: '([A-Za-z_][A-Za-z_0-9]*)')?")){Write-Host ('reauth_compile_line_'+$m.Groups[1].Value+'_'+$m.Groups[2].Value+'_'+$m.Groups[3].Value)};throw 'reauth_compile_failed'}
 Add-Type -TypeDefinition ([IO.File]::ReadAllText("$PSScriptRoot/FlowProbe.cs")) -OutputAssembly $script:probeA -OutputType ConsoleApplication
 Add-Type -TypeDefinition ([IO.File]::ReadAllText("$PSScriptRoot/FlowServer.cs"))
 Copy-Item -LiteralPath $script:probeA -Destination $probeB;Copy-Item -LiteralPath $script:probeA -Destination $probeC
 Check ((Get-FileHash $script:probeA).Hash -ceq (Get-FileHash $probeB).Hash -and (Get-FileHash $script:probeA).Hash -ceq (Get-FileHash $probeC).Hash)
 $script:stage='baseline';$baseline=ReadPolicyInventory
 foreach($family in @('IPv4','IPv6')){
  $script:stage='existing_'+$family;$v6=$family -ceq 'IPv6';$server=New-Object FlowLabServer($v6);$script:servers+=,$server;$ip=if($v6){'::1'}else{'127.0.0.1'}
  $a=StartProbe $script:probeA $ip $server.Port;$b=StartProbe $probeB $ip $server.Port;InvokeFlowEcho $a;InvokeFlowEcho $b
  $before=[long]$server.Bytes($a.tag);Check ($before -eq 33);Check ($server.Bytes($b.tag) -eq 33)
  $f=NewFixture;Audit $f 'absent';Worker $f 'Install';Phase $f 'installed';Audit $f 'installed'
  # The installer has exited. Only the client fixtures retain their old TCP sockets.
  InvokeFlowEcho $b;$script:controls++;InvokeFlowEcho $a 'BLOCKED'
  Start-Sleep -Milliseconds 500
  $delta=[long]$server.Bytes($a.tag)-$before;if($script:payloadBytes -lt 0){$script:payloadBytes=0};$script:payloadBytes+=[int]$delta
  Check ($delta -eq 0);Check ($server.Bytes($b.tag) -eq 66);$script:flows++
  # This primitive blocks reauthorization, not initial authorization: fresh A must work.
  $fresh=StartProbe $script:probeA $ip $server.Port;InvokeFlowEcho $fresh;Check ($server.Bytes($fresh.tag) -eq 33);$script:fresh++
  Worker $f 'Install';Audit $f 'installed'
  if(-not $v6){
   $wrong=($f.plan|ConvertTo-Json -Depth 8 -Compress)|ConvertFrom-Json;$wrong.app=$probeC;$null=RunNative $wrong 'audit' 1;$null=RunNative $wrong 'remove' 1;Audit $f 'installed';$script:conflicts++
   $wrong=($f.plan|ConvertTo-Json -Depth 8 -Compress)|ConvertFrom-Json;$wrong.keys[1]=[guid]::NewGuid().ToString('B');$null=RunNative $wrong 'audit' 1;$null=RunNative $wrong 'remove' 1;Audit $f 'installed';$script:conflicts++
   $jp=Join-Path $f.root 'journal.json';$bytes=[IO.File]::ReadAllBytes($jp);[IO.File]::WriteAllText($jp,'corrupt');Worker $f 'Remove' 'none' 1;Audit $f 'installed';[IO.File]::WriteAllBytes($jp,$bytes);$script:conflicts++
  }
  InvokeFlowEcho $b;$script:controls++
  Worker $f 'Remove';Phase $f 'removed';Audit $f 'absent';InvokeFlowEcho $fresh;InvokeFlowEcho $b;$script:controls++;Worker $f 'Remove'
  foreach($p in @($a,$b,$fresh)){CloseProbe $p};$server.Dispose()
 }
 $script:stage='fault_recovery'
 foreach($case in @('before-native','abort-add','after-install-commit','abort-remove','after-remove-commit')){
  $f=NewFixture
  if($case -in @('abort-remove','after-remove-commit')){Worker $f 'Install';$action='Remove';$pending='removing'}else{$action='Install';$pending='installing'}
  Worker $f $action $case 73;Phase $f $pending;$script:faults++
  $expected=if($case -in @('after-install-commit','abort-remove')){'installed'}else{'absent'}
  Audit $f $expected;Worker $f 'Recover';$script:recoveries++
  $phase=if($case -in @('before-native','abort-add')){'planned'}elseif($case -ceq 'after-remove-commit'){'removed'}else{'installed'}
  Phase $f $phase;Audit $f $expected
  if($expected -ceq 'installed'){Worker $f 'Remove';Audit $f 'absent'}else{Worker $f 'Install';Audit $f 'installed';Worker $f 'Remove';Audit $f 'absent'}
 }
 $passed=$true
}catch{
 $errorCode='reauth_test_failed';Write-Host ('reauth_stage_'+$script:stage+'_line_'+$_.InvocationInfo.ScriptLineNumber+'_type_'+$_.Exception.GetType().Name)
 $m=[string]$_.Exception.Message;if($m -cmatch '^reauth_[a-z_]+$'){Write-Host $m}
}finally{
 foreach($p in $script:children){try{CloseProbe $p}catch{}}
 foreach($s in $script:servers){try{$s.Dispose()}catch{}}
 if($script:fixtures.Count -gt 0 -and $null -ne $script:native -and (Test-Path -LiteralPath $script:native)){
  try{foreach($f in $script:fixtures){$null=RunNative $f.plan 'remove';Audit $f 'absent';$cleanup++};$remaining=0}catch{$passed=$false;$errorCode='reauth_cleanup_failed';Write-Host 'reauth_cleanup_stopped'}
 }elseif($script:fixtures.Count -eq 0){$remaining=0}
 if($null -ne $baseline){try{$c=ComparePolicyInventory $baseline (ReadPolicyInventory);$equal=[bool]$c.policy_equal;$display=[int]$c.display_rule_changes;if(-not $equal){$passed=$false;$errorCode='reauth_policy_drift'}}catch{$passed=$false;$errorCode='reauth_inventory_failed'}}
 $r=[ordered]@{schema='sstp-reauth-test-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;passed=$passed;error_code=$errorCode;checks=$script:checks;fault_cases=$script:faults;fresh_process_recoveries=$script:recoveries;existing_flow_cases=$script:flows;control_roundtrips=$script:controls;fresh_flow_cases=$script:fresh;post_guard_payload_bytes=$script:payloadBytes;owned_conflict_stops=$script:conflicts;fixture_sets=$script:fixtures.Count;cleanup_sets=$cleanup;remaining_objects=$remaining;unrelated_windows_firewall_policy_equal=$equal;unrelated_display_changes=$display;whole_machine_guard_tested=$false;active_sstp_tested=$false;vpn_disconnect_tested=$false;reboot_tested=$false;wire_capture_tested=$false;synchronous_commit_barrier_tested=$false;user_device_tested=$false;ready_for_user_apply=$false}
 [IO.File]::WriteAllText($OutputPath,(ConvertTo-Json -InputObject $r -Depth 8),[Text.Encoding]::UTF8)
 if($remaining -eq 0 -and (Get-Variable work -Scope Script -ErrorAction SilentlyContinue)){Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction SilentlyContinue}
}
if(-not $passed){exit 1};exit 0
