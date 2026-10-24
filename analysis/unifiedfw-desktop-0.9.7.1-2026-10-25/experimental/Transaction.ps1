# Adapter-neutral transaction engine, development only.
# This module has no native adapter. Tests supply a file-backed mock; see lab/ for the separate live-session engine.
# Flush(true) + atomic file replacement protect journal ordering under injected
# execution failures, NOT a certification against power loss/storage failure.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function TxJson($Value){ConvertTo-Json -InputObject $Value -Depth 64 -Compress}
function TxClone($Value){
 if($Value -is [array]){return ,@(ConvertFrom-Json -InputObject (TxJson $Value))}
 return (ConvertFrom-Json -InputObject (TxJson $Value))
}
function TxHash([string]$Text){
 $h=[Security.Cryptography.SHA256]::Create()
 try{([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
}
function TxEqual($Left,$Right){
 # Provider image order must be normalized by the future adapter. This engine is strict.
 (TxJson $Left) -ceq (TxJson $Right)
}
function TxCheckpoint([scriptblock]$Hook,[string]$Name){if($null -ne $Hook){& $Hook $Name | Out-Null}}
function TxRoot([string]$Root){
 if(-not [IO.Path]::IsPathRooted($Root) -or $Root.StartsWith('\\')){throw 'tx_local_absolute_root_required'}
 $p=[IO.Path]::GetFullPath($Root)
 if(-not [IO.Directory]::Exists($p)){throw 'tx_root_missing'}
 $cursor=$p
 while($cursor){
  if(([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'tx_reparse_root'}
  $parent=[IO.Path]::GetDirectoryName($cursor);if($parent -eq $cursor){break};$cursor=$parent
 }
 return $p
}
function TxLock([string]$Root){
 $root=TxRoot $Root
 $file=Join-Path $root 'transaction.lock'
 if([IO.File]::Exists($file) -and ([IO.File]::GetAttributes($file) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'tx_reparse_lock'}
 [IO.File]::Open($file,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
}
function TxValidateOperations($Operations){
 if($Operations -isnot [array] -or $Operations.Count -lt 1 -or $Operations.Count -gt 2048){throw 'tx_plan_size'}
 $keys=@{}
 foreach($op in $Operations){
  if((@($op.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'after,before,key'){throw 'tx_operation_schema'}
  if($op.key -isnot [string] -or $op.key.Length -lt 1 -or $op.key.Length -gt 256 -or $op.key -match '[\x00-\x1f]' -or $keys.ContainsKey($op.key)){throw 'tx_duplicate_or_invalid_key'}
  if($null -eq $op.before -or $null -eq $op.after -or (TxEqual $op.before $op.after)){throw 'tx_noop_or_missing_image'}
  $keys[$op.key]=$true
 }
}
function TxValidate($State){
 if($State.schema -cne 'sstp-transaction-dev-1' -or $State.id -cnotmatch '^[a-f0-9]{32}$' -or $State.phase -cnotin @('prepared','applying','applied','restoring','restored','conflict')){throw 'tx_state_schema'}
 TxValidateOperations $State.operations
 if($State.plan_hash -cne (TxHash (TxJson $State.operations))){throw 'tx_plan_hash'}
 if($State.intents -isnot [array] -or $State.intents.Count -ne $State.operations.Count -or $State.restored -isnot [array] -or $State.restored.Count -ne $State.operations.Count){throw 'tx_state_flags'}
 foreach($v in @($State.intents)+@($State.restored)){if($v -isnot [bool]){throw 'tx_state_flag_type'}}
}
function TxRead([string]$Root){
 $file=Join-Path (TxRoot $Root) 'transaction.json'
 if(-not [IO.File]::Exists($file)){return $null}
 if(([IO.File]::GetAttributes($file) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'tx_reparse_journal'}
 if((New-Object IO.FileInfo($file)).Length -gt 33554432){throw 'tx_journal_too_large'}
 $e=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($file))
 if((@($e.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'payload,sha256' -or $e.payload -isnot [string] -or (TxHash $e.payload) -cne $e.sha256){throw 'tx_journal_integrity'}
 $s=ConvertFrom-Json -InputObject $e.payload;TxValidate $s;return $s
}
function TxSave([string]$Root,$State,[scriptblock]$Hook,[string]$Label){
 TxValidate $State
 TxCheckpoint $Hook ('journal.before.'+$Label)
 $dir=TxRoot $Root;$file=Join-Path $dir 'transaction.json';$tmp=Join-Path $dir ('next-'+[guid]::NewGuid().ToString('N')+'.tmp')
 if([IO.File]::Exists($file) -and ([IO.File]::GetAttributes($file) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'tx_reparse_journal'}
 $payload=TxJson $State;$bytes=[Text.Encoding]::UTF8.GetBytes((TxJson ([ordered]@{payload=$payload;sha256=(TxHash $payload)})))
 $f=$null
 try{
  $f=[IO.File]::Open($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  $f.Write($bytes,0,$bytes.Length);$f.Flush($true);$f.Dispose();$f=$null
  if([IO.File]::Exists($file)){[IO.File]::Replace($tmp,$file,[Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($tmp,$file)}
 }finally{if($null -ne $f){$f.Dispose()};if([IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
 TxCheckpoint $Hook ('journal.after.'+$Label)
}
function NewMockableTransaction([string]$Root,[array]$Operations,[scriptblock]$Hook=$null){
 TxValidateOperations $Operations;$lock=TxLock $Root
 try{
  if($null -ne (TxRead $Root)){throw 'tx_existing_journal'}
  $flags=@($Operations|ForEach-Object{$false})
  $state=[pscustomobject]@{schema='sstp-transaction-dev-1';id=[guid]::NewGuid().ToString('N');phase='prepared';operations=(TxClone $Operations);plan_hash=(TxHash (TxJson $Operations));intents=@($flags);restored=@($flags)}
  TxSave $Root $state $Hook 'prepare'
 }finally{$lock.Dispose()}
}
function InvokeMockableTransaction([string]$Root,[scriptblock]$Read,[scriptblock]$CompareAndWrite,[scriptblock]$Hook=$null){
 $lock=TxLock $Root
 try{
  $s=TxRead $Root;if($null -eq $s -or $s.phase -cne 'prepared'){throw 'tx_restore_before_reapply'}
  $s.phase='applying';TxSave $Root $s $Hook 'apply-start'
  for($i=0;$i -lt $s.operations.Count;$i++){
   $op=$s.operations[$i];$current=& $Read $op.key
   if(-not (TxEqual $current $op.before)){$s.phase='conflict';TxSave $Root $s $null 'apply-conflict';throw 'tx_resource_conflict'}
   $s.intents[$i]=$true;TxSave $Root $s $Hook ('intent-'+$i)
   TxCheckpoint $Hook ('resource.before.apply-'+$i)
   # Adapter contract: recheck FULL image before writing; reject on any difference.
   & $CompareAndWrite $op.key $op.before $op.after | Out-Null
   TxCheckpoint $Hook ('resource.after.apply-'+$i)
   $current=& $Read $op.key
   if(-not (TxEqual $current $op.after)){throw 'tx_apply_readback'}
  }
  $s.phase='applied';TxSave $Root $s $Hook 'applied'
 }finally{$lock.Dispose()}
}
function RestoreMockableTransaction([string]$Root,[scriptblock]$Read,[scriptblock]$CompareAndWrite,[scriptblock]$Hook=$null){
 $lock=TxLock $Root
 try{
  $s=TxRead $Root;if($null -eq $s){return 'absent'}
  if($s.phase -ceq 'restored'){return 'restored'}
  $s.phase='restoring';TxSave $Root $s $Hook 'restore-start'
  for($i=$s.operations.Count-1;$i -ge 0;$i--){
   # No intent persisted => no mutation by this transaction is possible.
   if(-not $s.intents[$i]){continue}
   $op=$s.operations[$i];$current=& $Read $op.key
   if(TxEqual $current $op.before){$s.restored[$i]=$true;TxSave $Root $s $Hook ('already-restored-'+$i);continue}
   if(-not (TxEqual $current $op.after)){$s.phase='conflict';TxSave $Root $s $null 'restore-conflict';throw 'tx_restore_conflict'}
   TxCheckpoint $Hook ('resource.before.restore-'+$i)
   & $CompareAndWrite $op.key $op.after $op.before | Out-Null
   TxCheckpoint $Hook ('resource.after.restore-'+$i)
   $current=& $Read $op.key
   if(-not (TxEqual $current $op.before)){throw 'tx_restore_readback'}
   $s.restored[$i]=$true;TxSave $Root $s $Hook ('restored-'+$i)
  }
  $s.phase='restored';TxSave $Root $s $Hook 'restored'
  return 'restored'
 }finally{$lock.Dispose()}
}
