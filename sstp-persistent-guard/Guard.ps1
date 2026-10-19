# P10 internal persistent transition guard. NOT an end-user kill switch/coordinator.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../sstp-integrated-transaction/Engine.ps1')
function GuardClone($Object) { $Object | ConvertTo-Json -Depth 24 -Compress | ConvertFrom-Json }
function GuardImage($Original,[bool]$Enabled) {
 $row=GuardClone $Original;$row.rule.Enabled='2';if($Enabled){$row.rule.Enabled='1'};return $row
}
function AssertGuardState($State) {
 if($null -eq $State -or (($State.PSObject.Properties.Name | Sort-Object)-join ',') -cne 'enabled,original,pending,phase,schema,target' -or $State.schema -cne 'sstp-persistent-guard-1' -or $State.phase -cnotin @('staged','holding','held','releasing','released') -or $State.enabled -isnot [bool] -or $State.pending -isnot [bool] -or $State.target -isnot [bool]){throw 'guard_state_schema'}
 $r=$State.original
 if($null -eq $r -or (($r.PSObject.Properties.Name | Sort-Object)-join ',') -cne 'address,application,interface,interface_type,name,port,rule,security,service' -or $r.name -cnotmatch '^SstpTransitionGuard-[a-f0-9]{32}$'){throw 'guard_original_schema'}
 foreach($part in @('rule')+$script:InventoryParts){AssertInventoryRaw $r.$part;if($r.$part.InstanceID -cne $r.name){throw 'guard_original_identity'}}
 if($r.rule.Enabled -cne '2' -or $r.rule.Action -cne '4' -or $r.rule.Direction -cne '2' -or $r.rule.RuleGroup -cne $r.name){throw 'guard_original_policy'}
 if(($State.phase -eq 'staged' -and ($State.enabled -or $State.pending -or $State.target)) -or ($State.phase -eq 'held' -and (-not $State.enabled -or $State.pending -or -not $State.target)) -or ($State.phase -eq 'released' -and ($State.enabled -or $State.pending -or $State.target)) -or ($State.phase -eq 'holding' -and -not $State.target) -or ($State.phase -eq 'releasing' -and $State.target)){throw 'guard_state_frontier'}
}
function ReadGuardState([string]$Root) {
 $r=ReadJournal $Root;if($r.status -cne 'valid'){throw 'guard_journal_required'};AssertGuardState $r.record.state;return $r.record
}
function CompareGuardObserved($State,$Actual) {
 AssertGuardState $State
 $expected=GuardImage $State.original $State.enabled
 if((IntegratedHash $Actual) -ceq (IntegratedHash $expected)){return $State.enabled}
 if($State.pending -and (IntegratedHash $Actual) -ceq (IntegratedHash (GuardImage $State.original $State.target))){return $State.target}
 throw 'guard_owned_conflict'
}
function NewDisabledTransitionGuard {
 param([Parameter(Mandatory=$true)][string]$Root,[Parameter(Mandatory=$true)][ValidateSet('WholeMachine','Fixture')][string]$Scope,[string]$FixtureProgram)
 $lock=OpenIntegratedLock $Root
 try {
  $existing=ReadJournal $Root;if($existing.status -cne 'absent'){throw 'guard_existing_journal'}
  $program='Any'
  if($Scope -ceq 'Fixture'){
   if([string]::IsNullOrWhiteSpace($FixtureProgram) -or -not [IO.Path]::IsPathRooted($FixtureProgram) -or $FixtureProgram -match '[*?\[\]%`\r\n]' -or [IO.Path]::GetExtension($FixtureProgram) -ine '.exe'){throw 'guard_fixture_program'}
   $program=[IO.Path]::GetFullPath($FixtureProgram)
  } elseif(-not [string]::IsNullOrEmpty($FixtureProgram)){throw 'guard_whole_machine_scope'}
  $name='SstpTransitionGuard-'+[guid]::NewGuid().ToString('N')
  # Creation is DISABLED; a crash before durable original capture cannot leave an active broad block.
  New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Description 'SSTP transaction guard; not final allowlist policy' -Group $name -Enabled False -Direction Outbound -Action Block -Profile Any -Program $program -Service Any -Protocol Any -LocalAddress Any -RemoteAddress Any -InterfaceAlias Any -InterfaceType Any -EdgeTraversalPolicy Block -ErrorAction Stop | Out-Null
  $rule=GetIntegratedRule $name;$row=ReadIntegratedRow $rule
  $a=Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
  $ip=Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
  $port=Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
  $iface=Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
  $type=Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
  $svc=Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
  if([string]$rule.Enabled -cne 'False' -or [string]$rule.Direction -cne 'Outbound' -or [string]$rule.Action -cne 'Block' -or [string]$rule.Profile -cne 'Any' -or [string]$rule.Group -cne $name -or [string]$a.Program -ine $program -or (@($ip.LocalAddress)-join ',') -cne 'Any' -or (@($ip.RemoteAddress)-join ',') -cne 'Any' -or [string]$port.Protocol -cnotin @('Any','256') -or (@($port.LocalPort)-join ',') -cne 'Any' -or (@($port.RemotePort)-join ',') -cne 'Any' -or (@($iface.InterfaceAlias)-join ',') -cne 'Any' -or [string]$type.InterfaceType -cne 'Any' -or [string]$svc.Service -cne 'Any'){throw 'guard_create_readback'}
  $state=[pscustomobject][ordered]@{schema='sstp-persistent-guard-1';phase='staged';enabled=$false;pending=$false;target=$false;original=$row}
  AssertGuardState $state
  WriteJournal $Root -1 $state | Out-Null
  return [pscustomobject]@{name=$name;phase='staged'}
 } finally {$lock.Dispose()}
}
function InvokeTransitionGuard {
 param([Parameter(Mandatory=$true)][string]$Root,[Parameter(Mandatory=$true)][ValidateSet('Hold','Release')][string]$Action,[ValidateSet('None','BeforeMutation','AfterMutation')][string]$Fault='None')
 $lock=OpenIntegratedLock $Root
 try {
  $record=ReadGuardState $Root;$s=$record.state;$revision=$record.revision
  $rule=GetIntegratedRule $s.original.name;$observed=CompareGuardObserved $s (ReadIntegratedRow $rule)
  if($Action -ceq 'Hold' -and $s.phase -cin @('releasing','released')){throw 'guard_release_started'}
  $want=$Action -ceq 'Hold'
  if($s.pending){$s.enabled=[bool]$observed;$s.pending=$false;$record=WriteJournal $Root $revision $s;$revision=$record.revision;$s=$record.state}
  if(($want -and $s.phase -ceq 'held') -or (-not $want -and $s.phase -ceq 'released')){return [pscustomobject]@{phase=$s.phase;name=$s.original.name}}
  $s.target=$want;$s.phase='releasing';if($want){$s.phase='holding'}
  if($s.enabled -ne $want){
   $s.pending=$true;$record=WriteJournal $Root $revision $s;$revision=$record.revision;$s=$record.state
   if($Fault -ceq 'BeforeMutation'){[Environment]::Exit(73)}
   # Check ALL owned raw fields and all seven filters, including labels, immediately before mutation.
   $rule=GetIntegratedRule $s.original.name
   if((IntegratedHash (ReadIntegratedRow $rule)) -cne (IntegratedHash (GuardImage $s.original $s.enabled))){throw 'guard_owned_conflict'}
   $value='False';if($want){$value='True'}
   Set-NetFirewallRule -InputObject $rule -Enabled $value -ErrorAction Stop | Out-Null
   if($Fault -ceq 'AfterMutation'){[Environment]::Exit(73)}
   if((IntegratedHash (ReadIntegratedRow (GetIntegratedRule $s.original.name))) -cne (IntegratedHash (GuardImage $s.original $want))){throw 'guard_set_readback'}
   $s.enabled=$want;$s.pending=$false
  }
  $s.phase='released';if($want){$s.phase='held'}
  $record=WriteJournal $Root $revision $s;$revision=$record.revision;$s=$record.state
  return [pscustomobject]@{phase=$s.phase;name=$s.original.name}
 } finally {$lock.Dispose()}
}
# No timer, resident process, implicit release, journal adoption, deletion or broad reset.
# Release is an INTERNAL primitive; a future qualified coordinator must authorize it.
