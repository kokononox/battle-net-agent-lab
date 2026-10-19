param([Parameter(Mandatory=$true)][string]$OutputPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Guard.ps1"
$checks=0;$faults=0;$recoveries=0;$conflicts=0;$packets=0;$roots=@();$fixtures=@();$passed=$false;$code=$null;$remaining=-1;$baselineEqual=$false;$drift=-1;$baseline=$null
function Check([bool]$Ok){if(-not $Ok){throw 'guard_test_assertion'};$script:checks++}
function Reject([scriptblock]$Body,[string]$Expected){$ok=$false;try{& $Body | Out-Null}catch{if($_.Exception.Message -cne $Expected){throw};$ok=$true};Check $ok}
function Root { $r=InitializeJournalRoot (Join-Path $env:RUNNER_TEMP ('sstp-guard-'+[guid]::NewGuid().ToString('N')));$script:roots+=,$r;return $r }
function Fixture([string]$Program){$r=Root;$x=NewDisabledTransitionGuard -Root $r -Scope Fixture -FixtureProgram $Program;$s=(ReadGuardState $r).state;$script:fixtures+=,$s.original;Check ($s.phase -ceq 'staged');return $r}
function Worker([string]$R,[string]$A,[string]$F='None'){
 & (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PSScriptRoot/Worker.ps1" -Root $R -Action $A -Fault $F | Out-Host
 return $LASTEXITCODE
}
function Probe([string]$Path,[string]$Ip){& $Path $Ip 443;return $LASTEXITCODE}
try{
 $baseline=ReadPolicyInventory
 $dir=Join-Path $env:RUNNER_TEMP ('guard-probe-'+[guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($dir)|Out-Null
 $a=Join-Path $dir 'guarded.exe';$b=Join-Path $dir 'control.exe'
 Add-Type -TypeDefinition ([IO.File]::ReadAllText("$PSScriptRoot/Probe.cs")) -Language CSharp -OutputAssembly $a -OutputType ConsoleApplication
 Copy-Item -LiteralPath $a -Destination $b -ErrorAction Stop
 # DNS is LAB setup only, outside either probe, never an exception in the product guard.
 $ips=@([Net.Dns]::GetHostAddresses('github.com')|Where-Object{$_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork}|ForEach-Object{$_.ToString()})
 Check ($ips.Count -ge 1);$ip=$ips[0]
 Check ((Probe $a $ip) -eq 0);Check ((Probe $b $ip) -eq 0)
 $r=Fixture $a
 # Fresh controller exits; the native PersistentStore rule alone must retain the block.
 Check ((Worker $r Hold) -eq 0);Check ((ReadGuardState $r).state.phase -ceq 'held')
 for($i=0;$i -lt 2;$i++){Check ((Probe $b $ip) -eq 0);Check ((Probe $a $ip) -eq 2);$packets++}
 $rev=(ReadGuardState $r).revision;Check ((Worker $r Hold) -eq 0);Check ((ReadGuardState $r).revision -eq $rev)
 Check ((Worker $r Release) -eq 0);Check ((Probe $a $ip) -eq 0);Check ((Probe $b $ip) -eq 0)
 $rev=(ReadGuardState $r).revision;Check ((Worker $r Release) -eq 0);Check ((ReadGuardState $r).revision -eq $rev)
 Reject {InvokeTransitionGuard $r Hold} 'guard_release_started'
 foreach($action in @('Hold','Release')){foreach($point in @('BeforeMutation','AfterMutation')){
  $r=Fixture (Join-Path $dir ('absent-'+[guid]::NewGuid().ToString('N')+'.exe'))
  if($action -ceq 'Release'){Check ((Worker $r Hold) -eq 0)}
  Check ((Worker $r $action $point) -eq 73);$faults++;Check ((ReadGuardState $r).state.pending)
  Check ((Worker $r $action) -eq 0);$recoveries++
  $s=(ReadGuardState $r).state;Check (-not $s.pending);Check ($s.enabled -eq ($action -ceq 'Hold'))
  if($action -ceq 'Hold'){Check ((Worker $r Release) -eq 0)}
  Write-Host ('guard_fault_recovered_'+$faults)
 }}
 # A failed/unfinished Hold can be explicitly released without briefly activating it first.
 foreach($point in @('BeforeMutation','AfterMutation')){
  $r=Fixture (Join-Path $dir ('absent-'+[guid]::NewGuid().ToString('N')+'.exe'))
  Check ((Worker $r Hold $point) -eq 73);$faults++
  Check ((Worker $r Release) -eq 0);$recoveries++;Check ((ReadGuardState $r).state.phase -ceq 'released')
 }
 # Any owned raw property/filter drift stops; no metadata exception for our guard.
 $r=Fixture (Join-Path $dir 'absent-conflict.exe');$s=(ReadGuardState $r).state;$name=$s.original.name
 Set-NetFirewallRule -InputObject (GetIntegratedRule $name) -Description 'external change' -ErrorAction Stop|Out-Null
 $rev=(ReadGuardState $r).revision
 Reject {InvokeTransitionGuard $r Hold} 'guard_owned_conflict';$conflicts++;Check ((ReadGuardState $r).revision -eq $rev)
 Set-NetFirewallRule -InputObject (GetIntegratedRule $name) -Description 'SSTP transaction guard; not final allowlist policy' -ErrorAction Stop|Out-Null
 Set-NetFirewallRule -InputObject (GetIntegratedRule $name) -RemoteAddress '192.0.2.44' -ErrorAction Stop|Out-Null
 Reject {InvokeTransitionGuard $r Hold} 'guard_owned_conflict';$conflicts++;Check ((ReadGuardState $r).revision -eq $rev)
 Set-NetFirewallRule -InputObject (GetIntegratedRule $name) -RemoteAddress Any -ErrorAction Stop|Out-Null
 # Missing/corrupt journal cannot release a known held native rule.
 $r=Fixture (Join-Path $dir 'absent-corrupt.exe');Check ((Worker $r Hold) -eq 0);$name=(ReadGuardState $r).state.original.name
 [IO.File]::WriteAllText((Join-Path $r 'journal.json'),'bad')
 Reject {InvokeTransitionGuard $r Release} 'guard_journal_required';Check ((GetIntegratedRule $name).Enabled -eq 'True')
 $r=Root;Reject {InvokeTransitionGuard $r Release} 'guard_journal_required'
 $code=$null
}catch{
 $code='guard_test_failed'
 Write-Host ('guard_checks_before_failure_'+$checks)
 $msg=$_.Exception.Message;if($msg -match '^(guard|journal|integrated|inventory)_[a-z_]+$'){Write-Host $msg}else{Write-Host ('guard_provider_failure_'+$_.Exception.GetType().Name.ToLowerInvariant())}
}finally{
 # CI emergency cleanup, NOT product release: only this run's exact original/Enabled variants.
 try{
  foreach($orig in $fixtures){
   $rule=GetIntegratedRule $orig.name;$row=ReadIntegratedRow $rule
   if([string]$rule.Group -cne $orig.name -or (IntegratedHash $row) -cnotin @((IntegratedHash $orig),(IntegratedHash (GuardImage $orig $true)))){throw 'guard_cleanup_conflict'}
   Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
  }
  $remaining=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop|Where-Object{$_.Name -cin @($fixtures|ForEach-Object{$_.name})}).Count
  if($null -ne $baseline){$delta=ComparePolicyInventory $baseline (ReadPolicyInventory);$baselineEqual=$delta.policy_equal;$drift=$delta.display_rule_changes}
  if($remaining -ne 0 -or -not $baselineEqual){$code='guard_cleanup_failed'}
 }catch{$code='guard_cleanup_failed';Write-Host ('guard_cleanup_failure_'+$_.Exception.GetType().Name.ToLowerInvariant())}
 $passed=$null -eq $code -and $faults -eq 6 -and $recoveries -eq 6 -and $packets -eq 2 -and $conflicts -eq 2 -and $remaining -eq 0 -and $baselineEqual
 $out=[ordered]@{schema='sstp-guard-test-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;passed=$passed;error_code=$code;checks=$checks;fault_cases=$faults;fresh_process_recoveries=$recoveries;packet_block_pairs=$packets;owned_conflict_stops=$conflicts;fixture_rules=$fixtures.Count;remaining_test_rules=$remaining;unrelated_full_policy_equal=$baselineEqual;unrelated_display_changes=$drift;whole_machine_guard_tested=$false;profile_defaults_changed=$false;ipv6_packet_tested=$false;sstp_tested=$false;reboot_tested=$false;user_device_tested=$false;ready_for_user_apply=$false}
 [IO.File]::WriteAllText($OutputPath,($out|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
}
if(-not $passed){exit 1}
