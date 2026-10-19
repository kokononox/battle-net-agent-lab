param([string]$OutputPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Overlay.ps1')
$script:checks=0;$script:workers=0;$script:probePairs=0
function Check($Value){if(-not $Value){throw ('overlay_check_'+($script:checks+1))};$script:checks++}
function Worker([string]$Root,[string]$Action,[string]$Fault='None',[int]$Expected=0){
 $a=@('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+(Join-Path $PSScriptRoot 'Test-Worker.ps1')+'"'),'-Root',('"'+$Root+'"'),'-Action',$Action,'-Fault',$Fault)
 $p=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $a -Wait -PassThru -WindowStyle Hidden
 Check ($p.HasExited -and $p.ExitCode -eq $Expected);$script:workers++
}
function Probe([string]$Exe,[string]$HostIp,[int]$Port){
 $p=Start-Process -FilePath $Exe -ArgumentList @($HostIp,[string]$Port) -Wait -PassThru -WindowStyle Hidden
 if($p.ExitCode -notin @(0,2)){throw 'overlay_probe_error'}
 return $p.ExitCode -eq 0
}
function Pair([string]$HostIp,[int]$Port,[bool]$WantA){
 Check ((Probe $script:a $HostIp $Port) -eq $WantA)
 Check (Probe $script:b $HostIp $Port);$script:probePairs++
}
$r=[ordered]@{schema='sstp-overlay-native-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;passed=$false;checks=0;worker_exits=0;fault_recoveries=0;probe_pairs=0;remaining_objects=-1;unrelated_policy_equal=$false;foreign_display_changes=-1;error_code=$null;fixture_only=$true;ipv6_packet_tested=$false;remote_access_packet_tested=$false;real_sstp_tested=$false;disconnect_tested=$false;reboot_tested=$false;user_device_tested=$false;ready_for_production=$false}
$root=Join-Path $env:RUNNER_TEMP ('sstp-overlay-'+[guid]::NewGuid().ToString('N'));$dir=Join-Path $env:RUNNER_TEMP ('sstp-overlay-probes-'+[guid]::NewGuid().ToString('N'))
$rec=$null;$before=$null;$target=$null
try{
 $null=[IO.Directory]::CreateDirectory($dir)
 $script:a=Join-Path $dir ('sstp-overlay-fixture-'+[guid]::NewGuid().ToString('N')+'.exe');$script:b=Join-Path $dir ('control-'+[guid]::NewGuid().ToString('N')+'.exe')
 Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Probe.cs'))) -OutputAssembly $script:a -OutputType ConsoleApplication -ErrorAction Stop
 [IO.File]::Copy($script:a,$script:b)
 # NetSecurity Windows Firewall is not qualified here for loopback filtering.
 # One public IPv4 TCP handshake endpoint, no HTTP/application payload.
 $candidates=@([Net.Dns]::GetHostAddresses('github.com')|Where-Object{$_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork}|Select-Object -First 4)
 foreach($ip in $candidates){if(Probe $script:b $ip.ToString() 443){$target=$ip.ToString();break}}
 if(-not $target){throw 'overlay_baseline_unavailable'}
 Pair $target 443 $true
 $before=ReadPolicyInventory
 NewOverlay $root @($target,'2001:db8::1') -Scope Fixture -FixtureProgram $script:a|Out-Null
 $rec=OverlayLoad $root;Check ($rec.state.phase -ceq 'prepared');Check (@($rec.state.objects|Where-Object{$_.enabled}).Count -eq 0)
 Worker $root Enable
 $rec=OverlayLoad $root;Check ($rec.state.phase -ceq 'active');Check (-not $rec.state.objects[0].enabled -and $rec.state.objects[1].enabled -and $rec.state.objects[2].enabled)
 Pair $target 443 $true
 Worker $root Status
 # Conflict: only this harness restores its known original label; product refuses it.
 $name=$rec.state.objects[2].spec.name
 Set-NetFirewallRule -PolicyStore PersistentStore -Name $name -Description 'intentional test fixture conflict' -ErrorAction Stop
 Worker $root Disable -Expected 1
 Set-NetFirewallRule -PolicyStore PersistentStore -Name $name -Description 'Destination overlay test build; not an independent kill switch' -ErrorAction Stop
 Worker $root Disable
 Pair $target 443 $true
 foreach($fault in @('BeforeSet','AfterSet')){
  Worker $root Enable $fault 73
  Pair $target 443 ($fault -ceq 'BeforeSet')
  Worker $root Disable
  $s=OverlayLoad $root;Check ($s.state.phase -ceq 'inactive' -and $null -eq $s.state.pending)
  Check (@($s.state.objects|Where-Object{$_.enabled}).Count -eq 0)
  $r.fault_recoveries++
 }
 Worker $root Remove
 $rec=OverlayLoad $root;Check ($rec.state.phase -ceq 'removed');Check (@($rec.state.objects|Where-Object{$_.exists}).Count -eq 0)
 # Reuse the same secure root only after exact removal.
 NewOverlay $root @('192.0.2.1','2001:db8::1') -Scope Fixture -FixtureProgram $script:a|Out-Null
 Worker $root Enable
 Pair $target 443 $false
 Worker $root Disable;Worker $root Remove
 $rec=OverlayLoad $root;$remaining=0;foreach($o in $rec.state.objects){if($null -ne (OverlayRead $o.spec.name)){$remaining++}}
 $r.remaining_objects=$remaining;Check ($remaining -eq 0)
 # Real RemoteAccess field/readback is staged DISABLED only, never enabled in CI.
 NewOverlay $root @('192.0.2.1','2001:db8::1') -Scope RemoteAccess|Out-Null
 $rr=OverlayLoad $root;Check (@($rr.state.objects|Where-Object{$_.enabled}).Count -eq 0)
 foreach($o in $rr.state.objects){AssertOverlaySemantic $o.spec (OverlayRead $o.spec.name) $false;Check ($o.spec.interface_type -ceq 'RemoteAccess')}
 InvokeOverlay $root Remove|Out-Null
 $cmp=ComparePolicyInventory $before (ReadPolicyInventory)
 $r.unrelated_policy_equal=$cmp.policy_equal;$r.foreign_display_changes=$cmp.display_rule_changes;Check $cmp.policy_equal
 $r.passed=$true
}catch{
 $r.error_code='overlay_native_failed'
 if($_.Exception.Message -cmatch '^overlay_[a-z_0-9]{1,80}$'){$r.error_code=$_.Exception.Message}
 # Code/line only, no raw local inventory or private journal in CI output.
 [Console]::Error.WriteLine('overlay_failure_line_'+$_.InvocationInfo.ScriptLineNumber+'_type_'+$_.Exception.GetType().Name)
}finally{
 # On failures, attempt only exact journaled recovery. Never broad-delete by group.
 if(-not $r.passed -and [IO.Directory]::Exists($root)){
  try{InvokeOverlay $root Disable|Out-Null;InvokeOverlay $root Remove|Out-Null;$rr=OverlayLoad $root;$left=0;foreach($o in $rr.state.objects){if($null -ne (OverlayRead $o.spec.name)){$left++}};$r.remaining_objects=$left}catch{}
 }
 if($null -ne $before -and $r.remaining_objects -eq 0){try{$cmp=ComparePolicyInventory $before (ReadPolicyInventory);$r.unrelated_policy_equal=$cmp.policy_equal;$r.foreign_display_changes=$cmp.display_rule_changes}catch{}}
 $r.checks=$script:checks;$r.worker_exits=$script:workers;$r.probe_pairs=$script:probePairs
 if($OutputPath){[IO.File]::WriteAllText($OutputPath,($r|ConvertTo-Json -Depth 5),(New-Object Text.UTF8Encoding($false)))}
}
$r|ConvertTo-Json -Depth 5
if(-not $r.passed){exit 1};exit 0
