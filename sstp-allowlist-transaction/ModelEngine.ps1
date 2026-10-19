# P4 reference transaction engine. The only adapter here is a FILE MODEL, never Windows firewall.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../sstp-allowlist-backend/Journal.ps1')
function ModelClone($Object) { $Object | ConvertTo-Json -Depth 24 -Compress | ConvertFrom-Json }
function AssertModelResources($Resources) {
 if ($Resources -isnot [array] -or $Resources.Count -lt 6 -or $Resources.Count -gt 36) { throw 'transaction_resources' }
 $seen=@{};$profiles=0;$locals=0;$owned=0;$guards=0
 foreach($r in $Resources) {
  if ((($r.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'after,before,key' -or $r.key -isnot [string] -or $r.before -isnot [string] -or $r.after -isnot [string] -or $seen.ContainsKey($r.key)) { throw 'transaction_resource_schema' }
  $seen[$r.key]=$true
  if ($r.key -ceq 'guard') {
   if ($r.before -cne 'absent' -or $r.after -cne 'blocked') { throw 'transaction_guard_schema' };$guards++
  } elseif ($r.key -cmatch '^profile:(Domain|Private|Public)$') {
   if ($r.before -cnotin @('Allow','Block','NotConfigured') -or $r.after -cne 'Block') { throw 'transaction_profile_schema' };$profiles++
  } elseif ($r.key -cmatch '^local:[a-f0-9]{16}$') {
   if ($r.before -cnotmatch '^enabled:[a-f0-9]{64}$' -or $r.after -cne ('disabled:'+$r.before.Substring(8))) { throw 'transaction_local_schema' };$locals++
  } elseif ($r.key -cmatch '^owned:[a-f0-9]{16}$') {
   if ($r.before -cne 'absent' -or $r.after -cnotmatch '^present:[a-f0-9]{64}$') { throw 'transaction_owned_schema' };$owned++
  } else { throw 'transaction_resource_key' }
 }
 if ($guards -ne 1 -or $profiles -ne 3 -or $locals -lt 1 -or $locals -gt 16 -or $owned -lt 1 -or $owned -gt 16) { throw 'transaction_resources' }
}
function NewModelTransaction($Resources) {
 AssertModelResources $Resources
 [pscustomobject][ordered]@{schema='sstp-model-transaction-1';session=[guid]::NewGuid().ToString('N');phase='enable';cursor=0;pending=$null;resources=@($Resources | Sort-Object key);restore_from=$null}
}
function NewModelOperation([string]$Kind,[string]$Key,[string]$Before,[string]$After) {
 [pscustomobject]@{kind=$Kind;key=$Key;before=$Before;after=$After}
}
function GetModelOperations($State) {
 $ops=@();$guardBefore='absent'
 if ($State.phase -eq 'disable') { $guardBefore=$State.restore_from.guard }
 $ops+=NewModelOperation 'resource' 'guard' $guardBefore 'blocked'
 $body=@($State.resources | Where-Object {$_.key -like 'local:*'} | Sort-Object key)
 $body+=@($State.resources | Where-Object {$_.key -like 'profile:*'} | Sort-Object key)
 $body+=@($State.resources | Where-Object {$_.key -like 'owned:*'} | Sort-Object key)
 foreach($r in $body) {
  if ($State.phase -eq 'enable') { $ops+=NewModelOperation 'resource' $r.key $r.before $r.after }
  else { $ops+=NewModelOperation 'resource' $r.key $State.restore_from.($r.key) $r.before }
 }
 $ops+=NewModelOperation 'verify' '' '' ''
 $ops+=NewModelOperation 'resource' 'guard' 'blocked' 'absent'
 return $ops
}
function AssertModelTransaction($State) {
 if ($null -eq $State -or (($State.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'cursor,pending,phase,resources,restore_from,schema,session' -or $State.schema -cne 'sstp-model-transaction-1' -or $State.session -cnotmatch '^[a-f0-9]{32}$' -or $State.phase -cnotin @('enable','disable') -or $State.cursor -isnot [int] -or $State.cursor -lt 0) { throw 'transaction_state_schema' }
 AssertModelResources $State.resources
 if ($State.phase -eq 'enable') { if ($null -ne $State.restore_from) { throw 'transaction_restore_schema' } }
 else {
  if ($null -eq $State.restore_from -or (($State.restore_from.PSObject.Properties.Name | Sort-Object) -join ',') -cne (($State.resources.key | Sort-Object) -join ',')) { throw 'transaction_restore_schema' }
  foreach($r in $State.resources) {
   if ($State.restore_from.($r.key) -cnotin @($r.before,$r.after)) { throw 'transaction_restore_schema' }
  }
 }
 $count=@(GetModelOperations $State).Count
 if ($State.cursor -gt $count -or ($null -ne $State.pending -and ($State.pending -isnot [int] -or $State.pending -ne $State.cursor -or $State.cursor -eq $count))) { throw 'transaction_cursor' }
}
function ModelBaseline($State) {
 $o=[ordered]@{};foreach($r in $State.resources) { $o[$r.key]=$r.before };[pscustomobject]$o
}
function ModelFinal($State,[string]$Phase) {
 $o=[ordered]@{};foreach($r in $State.resources) { $o[$r.key]=$r.before;if ($Phase -eq 'enable' -and $r.key -ne 'guard') { $o[$r.key]=$r.after } };[pscustomobject]$o
}
function GetModelFrontier($State) {
 $expected=ModelBaseline $State
 if ($State.phase -eq 'disable') { $expected=ModelClone $State.restore_from }
 $ops=@(GetModelOperations $State)
 for($n=0;$n -lt $State.cursor;$n++) { if ($ops[$n].kind -eq 'resource') { $expected.($ops[$n].key)=$ops[$n].after } }
 return $expected
}
function ReadModelWorld([string]$Root) {
 $path=AssertJournalPath (Join-Path $Root 'model.json')
 if (-not [IO.File]::Exists($path) -or (Get-Item -LiteralPath $path).Length -gt 65536) { throw 'transaction_model_missing' }
 [IO.File]::ReadAllText($path,[Text.Encoding]::UTF8) | ConvertFrom-Json
}
function AssertModelFrontier($State,$World) {
 $expected=GetModelFrontier $State
 if ((($World.PSObject.Properties.Name | Sort-Object) -join ',') -cne (($expected.PSObject.Properties.Name | Sort-Object) -join ',')) { throw 'transaction_observation_schema' }
 $pendingKey=$null;$pendingAfter=$null
 if ($null -ne $State.pending) {
  $op=@(GetModelOperations $State)[$State.pending]
  if ($op.kind -eq 'resource') { $pendingKey=$op.key;$pendingAfter=$op.after }
 }
 foreach($key in $expected.PSObject.Properties.Name) {
  if ($World.$key -isnot [string]) { throw 'transaction_observation_schema' }
  if ($World.$key -ceq $expected.$key) { continue }
  if ($key -ceq $pendingKey -and $World.$key -ceq $pendingAfter) { continue }
  throw 'transaction_state_conflict'
 }
}
function WriteModelResource([string]$Root,[string]$Key,[string]$Value) {
 # FILE MODEL ONLY: this function has no NetSecurity, VPN, DNS or registry calls.
 $world=ReadModelWorld $Root
 if ($Key -cnotin $world.PSObject.Properties.Name) { throw 'transaction_unknown_resource' }
 $world.$Key=$Value
 [IO.File]::WriteAllText((Join-Path $Root 'model.json'),($world | ConvertTo-Json -Depth 5 -Compress),[Text.UTF8Encoding]::new($false))
}
function OpenModelTransactionLock([string]$Root) {
 $Root=AssertJournalPath $Root;AssertJournalAcl $Root
 $path=AssertJournalPath (Join-Path $Root 'transaction.lock')
 New-Object IO.FileStream($path,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
}
function InvokeModelPolicyTransaction {
 param([string]$Root,[ValidateSet('Enable','Disable')][string]$Action,$Resources=$null,[int]$FaultBefore=-1,[int]$FaultAfter=-1)
 $lock=OpenModelTransactionLock $Root
 try {
  $journal=ReadJournal $Root
  if ($journal.status -eq 'recovery_required') { throw 'transaction_journal_recovery_required' }
  if ($journal.status -eq 'absent') {
   if ($Action -ne 'Enable') { throw 'transaction_missing_journal' }
   $state=NewModelTransaction $Resources
   AssertModelFrontier $state (ReadModelWorld $Root)
   $record=WriteJournal $Root -1 $state
  } else { $record=$journal.record }
  $state=$record.state;AssertModelTransaction $state
  $world=ReadModelWorld $Root;AssertModelFrontier $state $world
  if ($Action -eq 'Disable' -and $state.phase -eq 'enable') {
   # Keep original before/after snapshots. Capture observed partial progress, including an unacknowledged operation.
   $state.phase='disable';$state.cursor=0;$state.pending=$null;$state.restore_from=ModelClone $world
   AssertModelTransaction $state
   $record=WriteJournal $Root $record.revision $state;$state=$record.state
  } elseif ($Action -eq 'Enable' -and $state.phase -eq 'disable') {
   if ($state.cursor -ne @(GetModelOperations $state).Count) { throw 'transaction_finish_disable_first' }
   $state.phase='enable';$state.cursor=0;$state.pending=$null;$state.restore_from=$null
   AssertModelTransaction $state
   $record=WriteJournal $Root $record.revision $state;$state=$record.state
  }
  $ops=@(GetModelOperations $state)
  while ($state.cursor -lt $ops.Count) {
   $world=ReadModelWorld $Root;AssertModelFrontier $state $world
   if ($null -eq $state.pending) {
    $state.pending=$state.cursor
    $record=WriteJournal $Root $record.revision $state;$state=$record.state
   }
   $op=$ops[$state.cursor]
   # Deliberate CI worker termination AFTER durable intent, before/after model mutation. No finally runs.
   if ($state.cursor -eq $FaultBefore) { [Environment]::Exit(73) }
   $world=ReadModelWorld $Root;AssertModelFrontier $state $world
   if ($op.kind -eq 'resource' -and $world.($op.key) -cne $op.after) { WriteModelResource $Root $op.key $op.after }
   if ($state.cursor -eq $FaultAfter) { [Environment]::Exit(73) }
   $readback=ReadModelWorld $Root;AssertModelFrontier $state $readback
   if ($op.kind -eq 'resource' -and $readback.($op.key) -cne $op.after) { throw 'transaction_readback' }
   # A verify step is a full model-frontier comparison, NOT WFP/packet verification.
   $state.cursor++;$state.pending=$null
   $record=WriteJournal $Root $record.revision $state;$state=$record.state
  }
  AssertModelFrontier $state (ReadModelWorld $Root)
  [pscustomobject]@{phase=$state.phase;complete=$true;revision=$record.revision;network_enforcement_qualified=$false;ready_for_user_apply=$false}
 } finally { $lock.Dispose() }
}
