# TEST BUILD: subtractive destination overlay for ALL RemoteAccess interfaces.
# Never adds an Allow, changes a profile, controls a VPN or alters a foreign rule.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Ranges.ps1')
. (Join-Path $PSScriptRoot 'Journal.ps1')
. (Join-Path $PSScriptRoot 'Inventory.ps1')
function OverlayHash($Value){JournalHash (ConvertTo-Json -InputObject $Value -Depth 24 -Compress)}
function OverlayClone($Value){ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Value -Depth 24 -Compress)}
function OverlayOperationLock([string]$Root){
 $null=AssertJournalPath $Root;AssertJournalAcl $Root
 $path=AssertJournalPath (Join-Path $Root 'overlay-operation.lock')
 [IO.File]::Open($path,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
}
function OverlayExpected($Object,[bool]$Enabled){
 $x=OverlayClone $Object.original;$x.rule.Enabled='2';if($Enabled){$x.rule.Enabled='1'};return $x
}
function OverlayRead([string]$Name,[string]$Store='PersistentStore'){
 $rows=@(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop|Where-Object{[string]$_.Name -ceq $Name})
 if($rows.Count -eq 0){return $null};if($rows.Count -ne 1){throw 'overlay_rule_duplicate'}
 $r=$rows[0];$image=[ordered]@{rule=(InventoryRaw $r)};$view=[ordered]@{}
 foreach($pair in @(@('address','Get-NetFirewallAddressFilter'),@('application','Get-NetFirewallApplicationFilter'),@('interface','Get-NetFirewallInterfaceFilter'),@('interface_type','Get-NetFirewallInterfaceTypeFilter'),@('port','Get-NetFirewallPortFilter'),@('security','Get-NetFirewallSecurityFilter'),@('service','Get-NetFirewallServiceFilter'))){
  $f=@(& $pair[1] -AssociatedNetFirewallRule $r -ErrorAction Stop)
  if($f.Count -ne 1){throw 'overlay_filter_count'};$image[$pair[0]]=InventoryRaw $f[0]
  switch($pair[0]){
   'application'{$view.program=[string]$f[0].Program}
   'service'{$view.service=[string]$f[0].Service}
   'interface'{$view.alias=@($f[0].InterfaceAlias)}
   'interface_type'{$view.interface_type=[string]$f[0].InterfaceType}
   'port'{$view.protocol=[string]$f[0].Protocol;$view.local_port=@($f[0].LocalPort);$view.remote_port=@($f[0].RemotePort)}
   'address'{$view.local=@($f[0].LocalAddress);$view.remote=@($f[0].RemoteAddress)}
  }
 }
 [pscustomobject]@{image=[pscustomobject]$image;rule=$r;view=[pscustomobject]$view}
}
function AssertOverlaySemantic($Spec,$Read,[bool]$Enabled){
 if($null -eq $Read){throw 'overlay_rule_missing'}
 $r=$Read.rule;$v=$Read.view
 $value='False';if($Enabled){$value='True'}
 if([string]$r.Name -cne $Spec.name -or [string]$r.DisplayName -cne $Spec.name -or [string]$r.Description -cne 'Destination overlay test build; not an independent kill switch' -or [string]$r.Group -cne $Spec.group -or [string]$r.Enabled -cne $value -or [string]$r.Direction -cne 'Outbound' -or [string]$r.Action -cne 'Block' -or [string]$r.Profile -cne 'Any'){throw 'overlay_rule_semantic'}
 if([string]$v.program -ine $Spec.program -or [string]$v.service -cne 'Any' -or (@($v.alias)-join ',') -cne 'Any' -or [string]$v.interface_type -cne $Spec.interface_type -or [string]$v.protocol -cnotin @('Any','256') -or (@($v.local)-join ',') -cne 'Any'){throw 'overlay_filter_semantic'}
 if((@($v.local_port)-join ',') -cne 'Any' -or (@($v.remote_port)-join ',') -cne 'Any'){throw 'overlay_port_semantic'}
 $remote=@($v.remote)
 if($Spec.kind -ceq 'guard'){if(($remote-join ',') -cne 'Any'){throw 'overlay_guard_semantic'}}
 elseif((IntervalSignature $remote) -cne (IntervalSignature $Spec.remote)){throw 'overlay_address_semantic'}
}
function AssertOverlayState($State){
 if($null -eq $State -or $State.schema -cne 'sstp-destination-overlay-1' -or $State.session -cnotmatch '^[a-f0-9]{32}$' -or $State.phase -cnotin @('staging','prepared','enabling','active','disabling','inactive','removing','removed') -or $State.objects -isnot [array] -or $State.objects.Count -ne 3){throw 'overlay_state_schema'}
 $kinds=@('guard','v4','v6');$pos=0
 foreach($o in $State.objects){
  if($o.spec.kind -cne $kinds[$pos] -or $o.spec.name -cne ('SstpDestinationOverlay-'+$State.session+'-'+$kinds[$pos]) -or $o.spec.group -cne ('SstpDestinationOverlay-'+$State.session) -or $o.exists -isnot [bool] -or $o.enabled -isnot [bool]){throw 'overlay_state_identity'}
  if($State.scope -ceq 'RemoteAccess'){
   if($o.spec.interface_type -cne 'RemoteAccess' -or $o.spec.program -cne 'Any'){throw 'overlay_state_scope'}
  }elseif($State.scope -ceq 'Fixture'){
   if($o.spec.interface_type -cne 'Any' -or [IO.Path]::GetFileName($o.spec.program) -cnotmatch '^sstp-overlay-fixture-[a-f0-9]{32}\.exe$' -or -not [IO.Path]::IsPathRooted($o.spec.program)){throw 'overlay_state_fixture'}
  }else{throw 'overlay_state_scope'}
  if($null -ne $o.original -and $o.original.rule.Enabled -cne '2'){throw 'overlay_state_original'}
  if($o.exists -and $null -eq $o.original){throw 'overlay_state_original'}
  $pos++
 }
 if($null -ne $State.pending){if($State.pending.index -isnot [int] -or $State.pending.index -lt 0 -or $State.pending.index -gt 2 -or $State.pending.operation -cnotin @('set','delete','create')){throw 'overlay_state_pending'}}
}
function OverlaySave([string]$Root,$Record){
 AssertOverlayState $Record.state
 WriteJournal $Root $Record.revision $Record.state
}
function OverlayLoad([string]$Root){
 $r=ReadJournal $Root;if($r.status -cne 'valid'){throw 'overlay_journal_required'}
 AssertOverlayState $r.record.state;return $r.record
}
function ReconcileOverlay([string]$Root,$Record){
 $s=$Record.state;$p=$s.pending
 for($n=0;$n -lt 3;$n++){
  $o=$s.objects[$n];$r=OverlayRead $o.spec.name
  if($null -ne $p -and $p.index -eq $n){
   if($p.operation -ceq 'create'){throw 'overlay_uncaptured_disabled_rule_stop'}
   if($p.operation -ceq 'delete' -and $null -eq $r){$o.exists=$false;$s.pending=$null;continue}
   if($p.operation -ceq 'set' -and $null -ne $r -and (OverlayHash $r.image) -ceq (OverlayHash (OverlayExpected $o ([bool]$p.target)))){$o.enabled=[bool]$p.target;$s.pending=$null;continue}
  }
  if(-not $o.exists){if($null -ne $r){throw 'overlay_rule_collision'};continue}
  if($null -eq $r -or (OverlayHash $r.image) -cne (OverlayHash (OverlayExpected $o $o.enabled))){throw 'overlay_owned_conflict'}
 }
 if($null -ne $s.pending){$s.pending=$null}
 return (OverlaySave $Root $Record)
}
function SetOverlayObject([string]$Root,$Record,[int]$Index,[bool]$Enabled,[string]$Fault='None'){
 $o=$Record.state.objects[$Index];if(-not $o.exists){throw 'overlay_rule_missing'}
 if($o.enabled -eq $Enabled){return $Record}
 $Record.state.pending=[pscustomobject]@{index=$Index;operation='set';target=$Enabled}
 $Record=OverlaySave $Root $Record;$o=$Record.state.objects[$Index]
 if($Fault -ceq 'BeforeSet'){[Environment]::Exit(73)}
 $r=OverlayRead $o.spec.name
 if($null -eq $r -or (OverlayHash $r.image) -cne (OverlayHash (OverlayExpected $o $o.enabled))){throw 'overlay_owned_conflict'}
 $value='False';if($Enabled){$value='True'}
 Set-NetFirewallRule -InputObject $r.rule -Enabled $value -ErrorAction Stop|Out-Null
 if($Fault -ceq 'AfterSet'){[Environment]::Exit(73)}
 $read=OverlayRead $o.spec.name
 if($null -eq $read -or (OverlayHash $read.image) -cne (OverlayHash (OverlayExpected $o $Enabled))){throw 'overlay_set_readback'}
 AssertOverlaySemantic $o.spec $read $Enabled
 $o.enabled=$Enabled;$Record.state.pending=$null
 return (OverlaySave $Root $Record)
}
function AssertOverlayActiveRules($Record){
 foreach($o in $Record.state.objects){
  if(-not $o.exists){throw 'overlay_rule_missing'}
  $read=OverlayRead $o.spec.name 'ActiveStore'
  AssertOverlaySemantic $o.spec $read $o.enabled
  if($o.enabled){
   # Official MSFT_NetFirewallRule CIM values: Enforcement Full=1, Primary OK=1.
   # Do not compare localized/PowerShell presentation enum labels.
   $status=@($read.rule.CimInstanceProperties['EnforcementStatus'].Value)
   $primary=$read.rule.CimInstanceProperties['PrimaryStatus'].Value
   if(-not (QualifiedOverlayEnforcement $status ([int]$primary))){throw 'overlay_active_enforcement_unqualified'}
  }
 }
}
function NewOverlay {
 param([string]$Root,[string[]]$Allowed,[ValidateSet('RemoteAccess','Fixture')][string]$Scope='RemoteAccess',[string]$FixtureProgram='',[string]$ConfigSha256='')
 $null=InitializeJournalRoot $Root;$lock=OverlayOperationLock $Root
 try{
  $current=ReadJournal $Root;$initialRevision=-1
  if($current.status -cne 'absent'){
   if($current.status -cne 'valid'){throw 'overlay_existing_journal'}
   AssertOverlayState $current.record.state
   if($current.record.state.phase -cne 'removed'){throw 'overlay_existing_journal'}
   foreach($old in $current.record.state.objects){if($old.exists -or $old.enabled -or $null -ne (OverlayRead $old.spec.name)){throw 'overlay_previous_rules_remain'}}
   $initialRevision=$current.record.revision
  }
  if($Allowed.Count -lt 1 -or $Allowed.Count -gt 512){throw 'overlay_allow_size'}
  $ips=@($Allowed|ForEach-Object{if($Scope -ceq 'RemoteAccess'){AssertPublicTarget $_}else{(AddressNumber $_).canonical}}|Sort-Object -Unique)
  $program='Any';$type='RemoteAccess'
  if($Scope -ceq 'Fixture'){
   if(-not [IO.Path]::IsPathRooted($FixtureProgram) -or [IO.Path]::GetFileName($FixtureProgram) -cnotmatch '^sstp-overlay-fixture-[a-f0-9]{32}\.exe$' -or -not [IO.File]::Exists($FixtureProgram)){throw 'overlay_fixture_program'}
   $program=[IO.Path]::GetFullPath($FixtureProgram);$type='Any'
  }elseif($FixtureProgram){throw 'overlay_fixture_argument'}
  $id=[guid]::NewGuid().ToString('N');$objects=@()
  foreach($kind in @('guard','v4','v6')){
   $remote=@('Any');if($kind -ceq 'v4'){$remote=ComplementAddresses $ips 32};if($kind -ceq 'v6'){$old=ComplementAddresses $ips 128;$remote=IntervalsToCidrs $old}
   if($remote.Count -lt 1){throw 'overlay_empty_complement'}
   $spec=[pscustomobject]@{name=('SstpDestinationOverlay-'+$id+'-'+$kind);group=('SstpDestinationOverlay-'+$id);kind=$kind;program=$program;interface_type=$type;remote=@($remote)}
   $objects+=,[pscustomobject]@{spec=$spec;original=$null;exists=$false;enabled=$false}
  }
  $s=[pscustomobject]@{schema='sstp-destination-overlay-1';session=$id;scope=$Scope;phase='staging';allowed_ips=$ips;config_sha256=$ConfigSha256;pending=$null;objects=$objects}
  AssertOverlayState $s;$rec=WriteJournal $Root $initialRevision $s
  for($n=0;$n -lt 3;$n++){
   $o=$rec.state.objects[$n]
   if($null -ne (OverlayRead $o.spec.name)){throw 'overlay_rule_collision'}
   $rec.state.pending=[pscustomobject]@{index=$n;operation='create';target=$false};$rec=OverlaySave $Root $rec;$o=$rec.state.objects[$n]
   New-NetFirewallRule -PolicyStore PersistentStore -Name $o.spec.name -DisplayName $o.spec.name -Description 'Destination overlay test build; not an independent kill switch' -Group $o.spec.group -Direction Outbound -Action Block -Profile Any -Enabled False -Program $o.spec.program -Service Any -Protocol Any -LocalAddress Any -RemoteAddress $o.spec.remote -InterfaceAlias Any -InterfaceType $o.spec.interface_type -EdgeTraversalPolicy Block -ErrorAction Stop|Out-Null
   $read=OverlayRead $o.spec.name;AssertOverlaySemantic $o.spec $read $false
   if($read.image.rule.Enabled -cne '2'){throw 'overlay_raw_enabled'}
   $o.original=$read.image;$o.exists=$true;$rec.state.pending=$null;$rec=OverlaySave $Root $rec
  }
  $rec.state.phase='prepared';$rec=OverlaySave $Root $rec
  return [pscustomobject]@{phase=$rec.state.phase;scope=$Scope;rules=3;ready_for_user_apply=$false}
 }finally{$lock.Dispose()}
}
function InvokeOverlay {
 param([string]$Root,[ValidateSet('Enable','Disable','Remove','Status')][string]$Action,[ValidateSet('None','BeforeSet','AfterSet')][string]$Fault='None')
 $lock=OverlayOperationLock $Root
 try{
  $rec=OverlayLoad $Root
  if($Action -ceq 'Status'){
   # Status reads; it does NOT reconcile/save or silently change any state.
   $exact=$true
   foreach($o in $rec.state.objects){$r=OverlayRead $o.spec.name;if($o.exists){if($null -eq $r -or (OverlayHash $r.image) -cne (OverlayHash (OverlayExpected $o $o.enabled))){$exact=$false}}elseif($null -ne $r){$exact=$false}}
   return [pscustomobject]@{phase=$rec.state.phase;scope=$rec.state.scope;pending=($null -ne $rec.state.pending);owned_exact=$exact;allowed_ips=$rec.state.allowed_ips;independent_kill_switch=$false;real_sstp_tested=$false}
  }
  $rec=ReconcileOverlay $Root $rec
  if($Action -ceq 'Remove'){
   if($rec.state.phase -cnotin @('prepared','inactive','removing','removed') -or @($rec.state.objects|Where-Object{$_.enabled}).Count -ne 0){throw 'overlay_disable_before_remove'}
   $rec.state.phase='removing';$rec=OverlaySave $Root $rec
   for($n=0;$n -lt 3;$n++){
    $o=$rec.state.objects[$n];if(-not $o.exists){continue}
    $rec.state.pending=[pscustomobject]@{index=$n;operation='delete';target=$false};$rec=OverlaySave $Root $rec;$o=$rec.state.objects[$n]
    $r=OverlayRead $o.spec.name;if($null -eq $r -or (OverlayHash $r.image) -cne (OverlayHash (OverlayExpected $o $false))){throw 'overlay_owned_conflict'}
    Remove-NetFirewallRule -InputObject $r.rule -ErrorAction Stop
    if($null -ne (OverlayRead $o.spec.name)){throw 'overlay_remove_readback'}
    $o.exists=$false;$rec.state.pending=$null;$rec=OverlaySave $Root $rec
   }
   $rec.state.phase='removed';$rec=OverlaySave $Root $rec;return [pscustomobject]@{phase='removed';remaining_objects=0}
  }
  if($rec.state.phase -cin @('staging','removing','removed')){throw 'overlay_phase_not_applicable'}
  if($Action -ceq 'Enable' -and $rec.state.phase -cin @('disabling')){throw 'overlay_disable_in_progress'}
  $rec.state.phase='disabling';if($Action -ceq 'Enable'){$rec.state.phase='enabling'};$rec=OverlaySave $Root $rec
  # No wildcard/group deletion. A process exit never releases the guard automatically.
  $rec=SetOverlayObject $Root $rec 0 $true $Fault
  if($Action -ceq 'Enable'){AssertOverlayActiveRules $rec}
  $want=$Action -ceq 'Enable'
  $rec=SetOverlayObject $Root $rec 1 $want
  $rec=SetOverlayObject $Root $rec 2 $want
  $rec=ReconcileOverlay $Root $rec
  if($want){AssertOverlayActiveRules $rec}
  $rec=SetOverlayObject $Root $rec 0 $false
  $rec=ReconcileOverlay $Root $rec
  if($want){AssertOverlayActiveRules $rec}
  $rec.state.phase='inactive';if($want){$rec.state.phase='active'};$rec=OverlaySave $Root $rec
  return [pscustomobject]@{phase=$rec.state.phase;scope=$rec.state.scope;controller_will_exit=$true;independent_kill_switch=$false}
 }finally{$lock.Dispose()}
}
