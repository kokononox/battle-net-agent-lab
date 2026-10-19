param([Parameter(Mandatory=$true)][string]$OutputPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Coordinator.ps1"
$checks=0;$faults=0;$recoveries=0;$partials=0;$modelCases=0;$releaseStops=0;$pauseCases=0;$exits=0;$fixtureCount=0;$remaining=-1;$baselineEqual=$false;$cleanup=$false;$finalNC=$false;$passed=$false;$code=$null;$display=-1
$originalProfiles=$null;$globalBefore=$null;$fixtureInventory=$null;$template=$null;$rows=@();$names=@();$extra=$null
$session=[guid]::NewGuid().ToString('N');$group='SstpCoordLab-'+$session
$program=Join-Path $env:windir ('System32\sstp-coordinator-fixture-'+$session+'.exe')
function Check([bool]$Ok){if(-not $Ok){throw 'coord_test_assertion'};$script:checks++}
function Reject([scriptblock]$Body,[string]$Expected){$ok=$false;try{& $Body|Out-Null}catch{if($_.Exception.Message -cne $Expected){throw};$ok=$true};Check $ok}
function Root {InitializeJournalRoot (Join-Path $env:RUNNER_TEMP ('sstp-coord-'+[guid]::NewGuid().ToString('N')))}
function Worker([string]$Root,[string]$Action,[string]$Fault='None',[int]$Index=0){
 & (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PSScriptRoot/Worker.ps1" -Root $Root -Action $Action -Fault $Fault -FaultIndex $Index|Out-Host
 $result=$LASTEXITCODE;if($result -eq 73){$script:exits++};return $result
}
function Prepare {
 # Reuse the SAME immutable initial snapshot and verified native restore canary; re-audit before each new case.
 $s=CoordClone $script:template;ReadCoordFrontier $s|Out-Null;$r=Root;WriteJournal $r -1 $s|Out-Null;return $r
}
function StateInventory($State,[bool[]]$Bits){
 $x=CoordClone $script:fixtureInventory
 for($i=0;$i -lt $x.rules.Count;$i++){for($j=0;$j -lt 3;$j++){if($x.rules[$i].name -ceq $State.rows[$j].name){$x.rules[$i]=CoordRuleImage $State.rows[$j] $Bits[@(0,1,3)[$j]]}}}
 $x.profiles=ProfileExpected $State.profiles $Bits[2];return $x
}
function GuardEnabled {return [string](GetIntegratedRule $script:names[0]).Enabled -ceq 'True'}
function CheckDisabled([string]$Root){
 $r=ReadCoordRecord $Root;Check ($r.state.phase -ceq 'disabled');Check (($r.state.bits-join ',') -ceq 'False,True,False,False')
 Check (-not (GuardEnabled));Check ([string](GetStoredDomain).DefaultOutboundAction -ceq 'NotConfigured')
}
try{
 AssertInactiveDomain;Check (-not (Test-Path -LiteralPath $program))
 $globalBefore=ReadPolicyInventory;$originalProfiles=ReadProfileImages
 Check ([string](GetStoredDomain).DefaultOutboundAction -ceq 'NotConfigured')
 foreach($role in @('guard','old','allow')){
  $name=$group+'-'+$role;$action='Allow';$enabled='False';$params=@{Protocol='TCP';RemotePort='65534';RemoteAddress=@('192.0.2.44','2001:db8::44')}
  if($role -ceq 'guard'){$action='Block';$params=@{Protocol='Any';RemoteAddress='Any'}}
  if($role -ceq 'old'){$enabled='True'}
  New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Group $group -Description 'P12 scoped coordinator fixture' -Enabled $enabled -Direction Outbound -Action $action -Profile Any -Program $program -Service Any -InterfaceAlias Any -InterfaceType Any -LocalAddress Any -EdgeTraversalPolicy Block @params -ErrorAction Stop|Out-Null
  $rows+=,(ReadIntegratedRow (GetIntegratedRule $name));$names+=,$name;$fixtureCount++
 }
 $fixtureInventory=ReadPolicyInventory;$root=Root
 $v=InitializeCoordinatorLab $root $names;Check $v.native_restore_probe;$template=CoordClone (ReadCoordRecord $root).state
 # Exhaustive before/after model of the TEN typed native transitions, with one common frontier.
 foreach($phase in @('enable','disable')){
  $s=CoordClone $template
  if($phase -ceq 'disable'){$s.phase='disable';$s.origin=@($false,$false,$true,$true);$s.bits=@($s.origin)}
  for($i=0;$i -lt 5;$i++){
   $s.cursor=$i;$op=(CoordSteps $phase)[$i];$s.pending=$true
   foreach($after in @($false,$true)){
    $bits=@($s.bits);if($after){$bits[[int]$op[0]]=[bool]$op[1]}
    $v=CompareCoordFrontier $s (StateInventory $s $bits);Check ($v.pending_after -eq $after);$modelCases++
   }
   $s.bits[[int]$op[0]]=[bool]$op[1];$s.pending=$false
  }
 }
 $s=CoordClone $template;$bad=CoordClone $s;$bad.cursor=1
 Reject {AssertCoordState $bad} 'coord_frontier_schema'
 $bad=CoordClone $s;$bad.profiles[0].image|Add-Member -NotePropertyName UnknownFutureField -NotePropertyValue ('x'*1100000)
 Reject {AssertCoordCapacity $bad} 'coord_capacity'
 # Shared frontier rejects nonselected-filter, owned metadata, membership and profile drift in memory.
 $x=StateInventory $s $s.bits;$x.rules=@($x.rules|Where-Object{$_.name -cne $names[2]});Reject {CompareCoordFrontier $s $x} 'coord_membership_conflict'
 $x=StateInventory $s $s.bits;$a=@($x.rules|Where-Object{$_.name -ceq $names[2]})[0];$a.rule.Description='external';Reject {CompareCoordFrontier $s $x} 'coord_policy_conflict'
 $x=StateInventory $s $s.bits;$a=@($x.rules|Where-Object{$_.name -cnotin $names})[0];$a.address.RemoteAddress=@('192.0.2.99');Reject {CompareCoordFrontier $s $x} 'coord_policy_conflict'
 $x=StateInventory $s $s.bits;$x.profiles[0].image.NotifyOnListen='external';Reject {CompareCoordFrontier $s $x} 'profile_external_conflict'
 $lock=OpenIntegratedLock $root;try{Check ((Worker $root Enable) -eq 1)}finally{$lock.Dispose()}
 Check ((Worker $root Enable) -eq 0);$r=ReadCoordRecord $root;Check ($r.state.phase -ceq 'enabled');Check (($r.state.bits-join ',') -ceq 'False,False,True,True')
 $rev=$r.revision;Check ((Worker $root Enable) -eq 0);Check ((ReadCoordRecord $root).revision -eq $rev)
 Check ((Worker $root Disable) -eq 0);CheckDisabled $root
 $rev=(ReadCoordRecord $root).revision;Check ((Worker $root Disable) -eq 0);Check ((ReadCoordRecord $root).revision -eq $rev)
 Reject {InvokeCoordinatorLab $root Enable} 'coord_disable_started'
 $cases=@(
  @('Enable','AfterMutation',0,'Enable',$true),
  @('Enable','AfterMutation',1,'Enable',$true),
  @('Enable','AfterMutation',2,'Disable',$true),
  @('Enable','AfterMutation',3,'Enable',$true),
  @('Enable','BeforeReleaseAudit',4,'Disable',$true),
  @('Enable','AfterMutation',4,'Enable',$false),
  @('Disable','AfterMutation',2,'Disable',$true),
  @('Disable','BeforeReleaseAudit',4,'Disable',$true)
 )
 foreach($c in $cases){
  $root=Prepare;if($c[0] -ceq 'Disable'){Check ((Worker $root Enable) -eq 0)}
  Check ((Worker $root $c[0] $c[1] ([int]$c[2])) -eq 73);$faults++
  Check ((GuardEnabled) -eq [bool]$c[4])
  Check ((Worker $root $c[3]) -eq 0);$recoveries++
  if($c[0] -ceq 'Enable' -and $c[3] -ceq 'Disable'){$partials++}
  if($c[3] -ceq 'Enable'){Check ((Worker $root Disable) -eq 0)}
  CheckDisabled $root;Write-Host ('coord_fault_recovered_'+$faults)
 }
 # Pause BEFORE the guard-release audit. A new conflict must leave guard held and journal unchanged.
 $root=Prepare;Check ((Worker $root Enable BeforeReleaseAudit 4) -eq 73);$pauseCases++
 $rev=(ReadCoordRecord $root).revision
 Set-NetFirewallRule -InputObject (GetIntegratedRule $names[2]) -Description 'known negative-test drift' -ErrorAction Stop|Out-Null
 Check ((Worker $root Enable) -eq 1);Check (GuardEnabled);Check ((ReadCoordRecord $root).revision -eq $rev);$releaseStops++
 # Undo only our exact known mutation, not an unknown foreign change.
 $expected=CoordRuleImage $rows[2] $true;$expected.rule.Description='known negative-test drift'
 Check ((IntegratedHash (ReadIntegratedRow (GetIntegratedRule $names[2]))) -ceq (IntegratedHash $expected))
 Set-NetFirewallRule -InputObject (GetIntegratedRule $names[2]) -Description 'P12 scoped coordinator fixture' -ErrorAction Stop|Out-Null
 $extraName=$group+'-extra'
 New-NetFirewallRule -PolicyStore PersistentStore -Name $extraName -DisplayName $extraName -Group $group -Enabled False -Direction Outbound -Action Allow -Profile Any -Program $program -Protocol TCP -RemotePort 65534 -RemoteAddress '192.0.2.44' -ErrorAction Stop|Out-Null
 $extra=ReadIntegratedRow (GetIntegratedRule $extraName);$fixtureCount++
 Check ((Worker $root Enable) -eq 1);Check (GuardEnabled);Check ((ReadCoordRecord $root).revision -eq $rev);$releaseStops++
 Check ((IntegratedHash (ReadIntegratedRow (GetIntegratedRule $extraName))) -ceq (IntegratedHash $extra))
 Remove-NetFirewallRule -InputObject (GetIntegratedRule $extraName) -ErrorAction Stop;$extra=$null
 Check ((Worker $root Disable) -eq 0);CheckDisabled $root
 $root=Prepare;Check ((Worker $root Enable BeforeReleaseAudit 4) -eq 73);$pauseCases++
 [IO.File]::WriteAllText((Join-Path $root 'journal.json'),'bad')
 Check ((Worker $root Disable) -eq 1);Check (GuardEnabled)
 $missing=Root;Check ((Worker $missing Disable) -eq 1);Check (GuardEnabled)
}catch{
 $code='coord_test_failed';Write-Host ('coord_checks_before_failure_'+$checks)
 Write-Host ('coord_failure_at_'+[IO.Path]::GetFileName($_.InvocationInfo.ScriptName)+'_'+$_.InvocationInfo.ScriptLineNumber)
 if($_.Exception.Message -cmatch "property '([A-Za-z][A-Za-z0-9_]{0,80})'"){Write-Host ('coord_missing_property_'+$Matches[1])}
 if($_.Exception.Message -match '^(coord|profile|journal|integrated|inventory)_[a-z_]+$'){Write-Host $_.Exception.Message}else{Write-Host ('coord_provider_failure_'+$_.Exception.GetType().Name.ToLowerInvariant())}
}finally{
 # CI cleanup only, NOT product recovery: original images known in THIS process, exact owned scope.
 try{
  if($null -ne $originalProfiles){
   AssertInactiveDomain;$actual=ReadProfileImages
   if(TestProfileImagesEqual $actual (ProfileExpected $originalProfiles $true)){
    Set-NetFirewallProfile -InputObject (GetStoredDomain) -DefaultOutboundAction NotConfigured -ErrorAction Stop|Out-Null
   }elseif(-not (TestProfileImagesEqual $actual $originalProfiles)){throw 'coord_cleanup_profile_conflict'}
   for($i=0;$i -lt 12;$i++){if(TestProfileImagesEqual (ReadProfileImages) $originalProfiles){break};Start-Sleep -Milliseconds 250}
   $cleanup=TestProfileImagesEqual (ReadProfileImages) $originalProfiles
   $finalNC=[string](GetStoredDomain).DefaultOutboundAction -ceq 'NotConfigured'
  }
  foreach($orig in @($rows)+@($extra|Where-Object{$null -ne $_})){
   $rule=GetIntegratedRule $orig.name;$a=ReadIntegratedRow $rule
   if([string]$rule.Group -cne $group -or (IntegratedHash $a) -cnotin @((IntegratedHash (CoordRuleImage $orig $false)),(IntegratedHash (CoordRuleImage $orig $true)))){throw 'coord_cleanup_rule_conflict'}
   Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
  }
  $remaining=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop|Where-Object{[string]$_.Group -ceq $group}).Count
  if($null -ne $globalBefore){$d=ComparePolicyInventory $globalBefore (ReadPolicyInventory);$baselineEqual=$d.policy_equal;$display=$d.display_rule_changes}
  if(-not $cleanup -or -not $finalNC -or -not $baselineEqual -or $remaining -ne 0){$code='coord_cleanup_failed'}
 }catch{$code='coord_cleanup_failed';$remaining=-1;Write-Host ('coord_cleanup_failure_'+$_.Exception.GetType().Name.ToLowerInvariant())}
 $passed=$null -eq $code -and $faults -eq 8 -and $recoveries -eq 8 -and $partials -eq 2 -and $modelCases -eq 20 -and $releaseStops -eq 2 -and $pauseCases -eq 2 -and $exits -eq 10 -and $fixtureCount -eq 4 -and $cleanup -and $finalNC -and $baselineEqual -and $remaining -eq 0
 if(-not $passed -and $null -eq $code){$code='coord_test_failed'}
 $out=[ordered]@{schema='sstp-coordinator-test-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;passed=$passed;error_code=$code;checks=$checks;model_pending_cases=$modelCases;fault_cases=$faults;fresh_process_recoveries=$recoveries;partial_enable_disables=$partials;release_conflict_stops=$releaseStops;pre_release_pause_cases=$pauseCases;injected_process_exits=$exits;fixture_rules=$fixtureCount;remaining_test_rules=$remaining;cleanup_exact=$cleanup;final_stored_notconfigured=$finalNC;unrelated_full_policy_equal=$baselineEqual;unrelated_display_changes=$display;whole_machine_guard_tested=$false;active_profile_targeted=$false;sstp_binding_tested=$false;packet_enforcement_tested=$false;reboot_tested=$false;user_device_tested=$false;ready_for_user_apply=$false}
 [IO.File]::WriteAllText($OutputPath,($out|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
}
if(-not $passed){exit 1}
