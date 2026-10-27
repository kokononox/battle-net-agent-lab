# Private global registry; no network, policy setters, automatic repair or deletion.
# Requires StorageBridge and the unchanged private Ufw.SessionJournal helpers.
function Assert-UfwRegistryLease($Lease){
 if($null -eq $Lease -or $null -eq $Lease.lock -or -not $Lease.lock.CanWrite -or $Lease.root -cne (Get-UfwUnifiedStorageRoot)){throw 'ufw_registry_lock_required'}
 Assert-UfwJournalAcl $Lease.root $true
}
function Open-UfwSessionRegistry {
 $root=Get-UfwUnifiedStorageRoot
 if([IO.Directory]::Exists($root)){Assert-UfwJournalAcl $root $true}else{New-UfwPrivateJournalDirectory $root}
 $path=Join-Path $root 'global.lock'
 # Never truncate an existing lock; ShareNone covers other processes as well.
 $mode=[IO.FileMode]::CreateNew;if([IO.File]::Exists($path)){$mode=[IO.FileMode]::Open}
 $file=Open-UfwPrivateJournalFile $path $mode
 return [pscustomobject]@{root=$root;lock=$file;pending=$null;scanned=$false;closed_count=0}
}
function Close-UfwSessionRegistry($Lease){
 if($null -ne $Lease){Close-UfwUnifiedStorage $Lease.pending;$Lease.pending=$null;if($null -ne $Lease.lock){$Lease.lock.Dispose();$Lease.lock=$null};$Lease.scanned=$false}
}
function Open-UfwRegisteredStorage($Lease,[string]$Id){
 Assert-UfwRegistryLease $Lease
 if($Id -cnotmatch '^[a-f0-9]{32}$'){throw 'ufw_registry_id'}
 $dir=Join-Path $Lease.root ('session-'+$Id);Assert-UfwJournalAcl $dir $true
 $file=Open-UfwPrivateJournalFile (Join-Path $dir 'operation.lock') ([IO.FileMode]::Open)
 $h=[pscustomobject]@{id=$Id;dir=$dir;sequence=0;head=('0'*64);lock=$file;total_bytes=[long]0}
 try{
  $state=Read-UfwUnifiedStorage $h
  # Empty/partly allocated session is ambiguous, never silently discarded.
  if($state.sequence -eq 0){throw 'ufw_registry_empty_session_requires_local_review'}
  $h.sequence=$state.sequence;$h.head=$state.head;$h.total_bytes=$state.total_bytes
  # Reuse the SAME backend protocol parser, even for already-closed folders.
  # A checksum and a terminal word alone must not hide malformed operation order.
  $protocol=Get-UfwLocalBackendState ([pscustomobject]@{storage=$h;view=$state.records[0].data})
  return $h
 }catch{Close-UfwUnifiedStorage $h;throw}
}
function Find-UfwPendingSession($Lease){
 Assert-UfwRegistryLease $Lease
 if($Lease.scanned -or $null -ne $Lease.pending){throw 'ufw_registry_already_scanned'}
 $items=@(Get-ChildItem -LiteralPath $Lease.root -Force -ErrorAction Stop)
 if($items.Count -gt 4097){throw 'ufw_registry_entry_cap'}
 try{
  foreach($item in $items){
   if(-not $item.PSIsContainer -and $item.Name -ceq 'global.lock'){Assert-UfwJournalAcl $item.FullName $false;continue}
   if(-not $item.PSIsContainer -or $item.Name -cnotmatch '^session-[a-f0-9]{32}$'){throw 'ufw_registry_unexpected_entry'}
   $h=Open-UfwRegisteredStorage $Lease $item.Name.Substring(8)
   try{
    $state=Read-UfwUnifiedStorage $h
    if($state.records[-1].kind -ceq 'restored'){$Lease.closed_count++}
    else{
     if($null -ne $Lease.pending){throw 'ufw_registry_multiple_pending_requires_local_review'}
     $Lease.pending=$h;$h=$null
    }
   }finally{Close-UfwUnifiedStorage $h}
  }
  $Lease.scanned=$true
  # Private handle, not a portable recovery approval or a sanitized report.
  return $Lease.pending
 }catch{Close-UfwUnifiedStorage $Lease.pending;$Lease.pending=$null;throw}
}
function New-UfwRegisteredStorage($Lease,[string]$SessionId=''){
 Assert-UfwRegistryLease $Lease
 if(-not $Lease.scanned -or $null -ne $Lease.pending){throw 'ufw_registry_pending_scan_required'}
 # Re-scan is forbidden once allocation begins; one fresh session per lease.
 $Lease.scanned=$false
 return New-UfwUnifiedStorage $SessionId
}
function New-UfwRegistryCoordinatorBindings($State){
 # Caller owns State={lease=$null}; recovery must still validate baseline,
 # actor, audit state, target quiescence and local exit consent independently.
 return @{
  Lock=(New-UfwLocalModuleCallback {param($s)if($null -ne $s.lease){throw 'ufw_registry_already_locked'};$s.lease=Open-UfwSessionRegistry;return $true} $State)
  Pending=(New-UfwLocalModuleCallback {param($s)return Find-UfwPendingSession $s.lease} $State)
  Unlock=(New-UfwLocalModuleCallback {param($s)Close-UfwSessionRegistry $s.lease;$s.lease=$null} $State)
 }
}
