# P12: qualification-only unified native coordinator. Fixture rules + INACTIVE Domain only.
# This is NOT an SSTP enforcement product and cannot target real user rules.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../sstp-profile-roundtrip/Profile.ps1')
function CoordClone($Object){$Object|ConvertTo-Json -Depth 24 -Compress|ConvertFrom-Json}
function CoordRuleImage($Row,[bool]$Enabled){$x=CoordClone $Row;$x.rule.Enabled='2';if($Enabled){$x.rule.Enabled='1'};return $x}
function CoordSteps([string]$Phase){
 if($Phase -cin @('enable','enabled')){return ,@(@(0,$true),@(1,$false),@(2,$true),@(3,$true),@(0,$false))}
 return ,@(@(0,$true),@(3,$false),@(2,$false),@(1,$true),@(0,$false))
}
function CoordReachable($Bits){
 $x=@($false,$true,$false,$false)
 if(($x-join ',') -ceq ($Bits-join ',')){return $true}
 foreach($op in (CoordSteps 'enable')){$x[[int]$op[0]]=[bool]$op[1];if(($x-join ',') -ceq ($Bits-join ',')){return $true}}
 return $false
}
function AssertCoordState($S){
 if($null -eq $S -or (($S.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'baseline,bits,cursor,origin,pending,phase,profiles,restore_probe,rows,schema' -or $S.schema -cne 'sstp-coordinator-lab-1' -or $S.phase -cnotin @('enable','enabled','disable','disabled') -or $S.cursor -isnot [int] -or $S.cursor -lt 0 -or $S.cursor -gt 5 -or $S.pending -isnot [bool] -or $S.restore_probe -isnot [bool] -or $S.rows -isnot [array] -or $S.rows.Count -ne 3 -or $S.baseline -isnot [array] -or $S.baseline.Count -lt 3 -or $S.baseline.Count -gt 10000){throw 'coord_state_schema'}
 foreach($v in @($S.bits,$S.origin)){if($v -isnot [array] -or $v.Count -ne 4 -or @($v|Where-Object{$_ -isnot [bool]}).Count -gt 0){throw 'coord_bits_schema'}}
 AssertPolicyInventory ([pscustomobject]@{schema='sstp-policy-inventory-1';rules=$S.rows;profiles=$S.profiles})
 $tag=$S.rows[0].name
 if($tag -cmatch '^(SstpCoordLab-[a-f0-9]{32})-guard$'){$group=$Matches[1]}else{throw 'coord_fixture_identity'}
 $roles=@('guard','old','allow');$actions=@('4','2','2');$enabled=@('2','1','2')
 for($i=0;$i -lt 3;$i++){
  $r=$S.rows[$i]
  if($r.name -cne ($group+'-'+$roles[$i]) -or $r.rule.RuleGroup -cne $group -or $r.rule.Action -cne $actions[$i] -or $r.rule.Enabled -cne $enabled[$i] -or $r.rule.Direction -cne '2'){throw 'coord_fixture_identity'}
 }
 $stored=@($S.profiles|Where-Object{$_.store -ceq 'PersistentStore' -and $_.name -ceq 'Domain'})[0]
 if($stored.image.DefaultOutboundAction -cne '0'){throw 'coord_original_profile'}
 foreach($p in $S.profiles){if($p.name -ceq 'Domain' -and ($p.image.Enabled -cne '1' -or $p.image.DefaultOutboundAction -cnotin @('0','2'))){throw 'coord_original_profile'}}
 $seals=@{};foreach($b in $S.baseline){
  if((($b.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'name,policy_sha256,strict_sha256' -or $b.name -isnot [string] -or [string]::IsNullOrWhiteSpace($b.name) -or $seals.ContainsKey($b.name) -or $b.policy_sha256 -cnotmatch '^[a-f0-9]{64}$' -or $b.strict_sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'coord_baseline_schema'};$seals[$b.name]=$b
 }
 for($i=0;$i -lt 3;$i++){$r=$S.rows[$i];$seal=SealIntegratedRow $r ($i -ne 1);if(-not $seals.ContainsKey($r.name) -or $seals[$r.name].name -cne $r.name -or $seal.policy_sha256 -cne $seals[$r.name].policy_sha256 -or $seal.strict_sha256 -cne $seals[$r.name].strict_sha256){throw 'coord_original_seal'}}
 if($S.phase -cin @('enable','enabled')){if(($S.origin-join ',') -cne 'False,True,False,False'){throw 'coord_origin'}}elseif(-not (CoordReachable $S.origin)){throw 'coord_origin'}
 $bits=@($S.origin);$steps=CoordSteps $S.phase
 for($i=0;$i -lt $S.cursor;$i++){$bits[[int]$steps[$i][0]]=[bool]$steps[$i][1]}
 if(($bits-join ',') -cne ($S.bits-join ',') -or ($S.cursor -eq 5 -and $S.pending) -or ($S.phase -cin @('enabled','disabled') -and ($S.cursor -ne 5 -or $S.pending)) -or ($S.pending -and $S.bits[[int]$steps[$S.cursor][0]] -eq [bool]$steps[$S.cursor][1]) -or (-not $S.restore_probe -and ($S.phase -cne 'enable' -or $S.cursor -ne 0 -or $S.pending))){throw 'coord_frontier_schema'}
}
function CoordProfileState($S){
 $pending=$false;$target=$S.bits[2]
 if($S.pending){$op=(CoordSteps $S.phase)[$S.cursor];if([int]$op[0] -eq 2){$pending=$true;$target=[bool]$op[1]}}
 $phase='prepared';if($S.bits[2]){$phase='blocked'};if($pending){$phase='restoring';if($target){$phase='blocking'}}
 return [pscustomobject]@{schema='sstp-profile-roundtrip-1';phase=$phase;blocked=[bool]$S.bits[2];pending=$pending;target=[bool]$target;restore_probe=$true;original=$S.profiles}
}
function CompareCoordFrontier($S,$Actual){
 AssertCoordState $S;AssertPolicyInventory $Actual
 if($Actual.rules.Count -ne $S.baseline.Count){throw 'coord_membership_conflict'}
 $profile=CompareProfileObserved (CoordProfileState $S) $Actual.profiles
 if(-not $profile.settled){throw 'coord_profiles_unsettled'}
 $after=$false;$pendingBit=-1;$pendingValue=$false
 if($S.pending){$op=(CoordSteps $S.phase)[$S.cursor];$pendingBit=[int]$op[0];$pendingValue=[bool]$op[1];if($pendingBit -eq 2){$after=$profile.blocked -ne $S.bits[2]}}
 $map=@{};foreach($r in $Actual.rules){$map[$r.name]=$r};$roles=@{};for($i=0;$i -lt 3;$i++){$roles[$S.rows[$i].name]=$i};$display=0
 foreach($base in $S.baseline){
  if(-not $map.ContainsKey($base.name) -or $map[$base.name].name -cne $base.name){throw 'coord_membership_conflict'}
  $owned=$false;$expected=$base
  if($roles.ContainsKey($base.name)){
   $i=[int]$roles[$base.name];$owned=$i -ne 1;$bit=@(0,1,3)[$i]
   $expected=SealIntegratedRow (CoordRuleImage $S.rows[$i] $S.bits[$bit]) $owned
   $a=SealIntegratedRow $map[$base.name] $owned
   if($a.policy_sha256 -cne $expected.policy_sha256 -and $S.pending -and $pendingBit -eq $bit){
    $next=SealIntegratedRow (CoordRuleImage $S.rows[$i] $pendingValue) $owned
    if($a.policy_sha256 -ceq $next.policy_sha256){$expected=$next;$after=$true}
   }
  }else{$a=SealIntegratedRow $map[$base.name] $false}
  if($a.policy_sha256 -cne $expected.policy_sha256){throw 'coord_policy_conflict'}
  if($a.strict_sha256 -cne $expected.strict_sha256){$display++}
 };return [pscustomobject]@{pending_after=$after;display_changed_rules=$display}
}
function ReadCoordFrontier($S){
 AssertInactiveDomain
 # Wait using six cheap profile reads before the expensive complete inventory audit.
 $ps=CoordProfileState $S;ReadProfileFrontier $ps|Out-Null
 return CompareCoordFrontier $S (ReadPolicyInventory)
}
function ReadCoordRecord([string]$Root){$j=ReadJournal $Root;if($j.status -cne 'valid'){throw 'coord_journal_required'};AssertCoordState $j.record.state;return $j.record}
function AssertCoordCapacity($S){
 $worst=CoordClone $S;$worst.phase='disabled';$worst.cursor=5;$worst.pending=$false
 $payload=ConvertTo-Json -InputObject ([ordered]@{schema='sstp-journal-1';revision=[int]::MaxValue;state=$worst}) -Depth 32 -Compress
 $envelope=ConvertTo-Json -InputObject ([ordered]@{schema='sstp-journal-envelope-1';payload=$payload;sha256=(JournalHash $payload)}) -Compress
 if([Text.Encoding]::UTF8.GetByteCount($envelope) -gt 1048576){throw 'coord_capacity'}
}
function InitializeCoordinatorLab([string]$Root,[string[]]$Names){
 $lock=OpenIntegratedLock $Root
 try{
  if((ReadJournal $Root).status -cne 'absent'){throw 'coord_existing_journal'}
  if($Names.Count -ne 3){throw 'coord_selection'};AssertInactiveDomain
  $one=ReadPolicyInventory;$two=ReadPolicyInventory
  if(-not (ComparePolicyInventory $one $two @($Names[0],$Names[2])).policy_equal){throw 'coord_unstable_inventory'}
  $rows=@();foreach($name in $Names){$r=@($two.rules|Where-Object{$_.name -ceq $name});if($r.Count -ne 1){throw 'coord_selection'};$rows+=,$r[0]}
  $seals=@();foreach($r in $two.rules){$seals+=,(SealIntegratedRow $r ($r.name -cin @($Names[0],$Names[2])))}
  $s=[pscustomobject][ordered]@{schema='sstp-coordinator-lab-1';phase='enable';cursor=0;pending=$false;restore_probe=$false;bits=@($false,$true,$false,$false);origin=@($false,$true,$false,$false);rows=$rows;profiles=$two.profiles;baseline=$seals}
  AssertCoordState $s;AssertCoordCapacity $s
  # Hard CI fixture gate; never relax this into a production apply endpoint.
  $program=$rows[0].application.Program
  if($program -isnot [string] -or $program -cnotmatch 'sstp-coordinator-fixture-[a-f0-9]{32}\.exe$' -or (Test-Path -LiteralPath $program)){throw 'coord_fixture_scope'}
  foreach($r in $rows){if($r.application.Program -cne $program){throw 'coord_fixture_scope'}}
  $record=WriteJournal $Root -1 $s
  $p=GetStoredDomain;if([string]$p.DefaultOutboundAction -cne 'NotConfigured'){throw 'coord_restore_contract'}
  ReadCoordFrontier $s|Out-Null;AssertInactiveDomain
  Set-NetFirewallProfile -InputObject $p -DefaultOutboundAction NotConfigured -ErrorAction Stop|Out-Null
  ReadCoordFrontier $s|Out-Null;$s.restore_probe=$true;WriteJournal $Root $record.revision $s|Out-Null
  return [pscustomobject]@{phase='enable';native_restore_probe=$true}
 }finally{$lock.Dispose()}
}
function SetCoordMutation($S,$Op){
 AssertInactiveDomain
 $bit=[int]$Op[0];$want=[bool]$Op[1]
 if($bit -eq 2){
  $ps=CoordProfileState $S;$v=ReadProfileFrontier $ps
  if($v.blocked -ne $S.bits[2]){throw 'coord_resource_conflict'}
  $p=GetStoredDomain;AssertInactiveDomain;$value='NotConfigured';if($want){$value='Block'}
  Set-NetFirewallProfile -InputObject $p -DefaultOutboundAction $value -ErrorAction Stop|Out-Null
 }else{
  $idx=@{0=0;1=1;3=2}[$bit];$original=$S.rows[$idx];$owned=$idx -ne 1
  $rule=GetIntegratedRule $original.name;$actual=SealIntegratedRow (ReadIntegratedRow $rule) $owned
  $from=SealIntegratedRow (CoordRuleImage $original $S.bits[$bit]) $owned
  if($actual.policy_sha256 -cne $from.policy_sha256){throw 'coord_resource_conflict'}
  $value='False';if($want){$value='True'}
  Set-NetFirewallRule -InputObject $rule -Enabled $value -ErrorAction Stop|Out-Null
 }
}
function ReadCoordMutation($S,$Op){
 $bit=[int]$Op[0];$want=[bool]$Op[1]
 if($bit -eq 2){$require='Original';if($want){$require='Blocked'};ReadProfileFrontier (CoordProfileState $S) $require|Out-Null}
 else{
  $idx=@{0=0;1=1;3=2}[$bit];$original=$S.rows[$idx];$owned=$idx -ne 1
  $actual=SealIntegratedRow (ReadIntegratedRow (GetIntegratedRule $original.name)) $owned
  if($actual.policy_sha256 -cne (SealIntegratedRow (CoordRuleImage $original $want) $owned).policy_sha256){throw 'coord_mutation_readback'}
 }
}
function InvokeCoordinatorLab {
 param([string]$Root,[ValidateSet('Enable','Disable')][string]$Action,[ValidateSet('None','BeforeMutation','AfterMutation','BeforeReleaseAudit')][string]$Fault='None',[int]$FaultIndex=0)
 $lock=OpenIntegratedLock $Root
 try{
  $record=ReadCoordRecord $Root;$s=$record.state
  if(-not $s.restore_probe){throw 'coord_restore_probe_required'}
  $observed=ReadCoordFrontier $s
  if($Action -ceq 'Enable' -and $s.phase -cin @('disable','disabled')){throw 'coord_disable_started'}
  if($s.pending){
   if($observed.pending_after){$op=(CoordSteps $s.phase)[$s.cursor];$s.bits[[int]$op[0]]=[bool]$op[1];$s.cursor++}
   $s.pending=$false;$record=WriteJournal $Root $record.revision $s;$s=$record.state
  }
  if($Action -ceq 'Disable' -and $s.phase -cin @('enable','enabled')){$s.origin=@($s.bits);$s.phase='disable';$s.cursor=0;$record=WriteJournal $Root $record.revision $s;$s=$record.state}
  if(($Action -ceq 'Enable' -and $s.phase -ceq 'enabled') -or ($Action -ceq 'Disable' -and $s.phase -ceq 'disabled')){return [pscustomobject]@{phase=$s.phase}}
  while($s.cursor -lt 5){
   $op=(CoordSteps $s.phase)[$s.cursor];$bit=[int]$op[0];$want=[bool]$op[1]
   if($s.cursor -eq 4){
    if($Fault -ceq 'BeforeReleaseAudit' -and $FaultIndex -eq 4){[Environment]::Exit(73)}
   }
   if($s.bits[$bit] -ne $want){
    $s.pending=$true;$record=WriteJournal $Root $record.revision $s;$s=$record.state
    if($Fault -ceq 'BeforeMutation' -and $FaultIndex -eq $s.cursor){[Environment]::Exit(73)}
    # Fresh complete audit immediately before releasing the guard; no stale completion token.
    if($s.cursor -eq 4){ReadCoordFrontier $s|Out-Null}
    SetCoordMutation $s $op
    if($Fault -ceq 'AfterMutation' -and $FaultIndex -eq $s.cursor){[Environment]::Exit(73)}
    ReadCoordMutation $s $op;$s.bits[$bit]=$want;$s.pending=$false
   }
   $s.cursor++;$record=WriteJournal $Root $record.revision $s;$s=$record.state
  }
  ReadCoordFrontier $s|Out-Null
  $s.phase='disabled';if($Action -ceq 'Enable'){$s.phase='enabled'}
  WriteJournal $Root $record.revision $s|Out-Null
  return [pscustomobject]@{phase=$s.phase;ready_for_user_apply=$false}
 }finally{$lock.Dispose()}
}
