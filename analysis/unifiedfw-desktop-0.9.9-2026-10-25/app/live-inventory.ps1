function Test-InventoryPort($Port){
 if($Port -is [int] -or $Port -is [long]){return ($Port -ge 1 -and $Port -le 65535)}
 if($Port -is [string] -and $Port -cmatch '^[1-9][0-9]{0,4}-[1-9][0-9]{0,4}$'){$p=$Port.Split('-');return ([int]$p[0] -lt [int]$p[1] -and [int]$p[1] -le 65535)};return $false
}
# Read-only owned-journal snapshot. Never creates a journal/lock or calls a rule mutation.
# Requires explicit admin for protected journal access. Failure is unknown, not 'allowed'.
function Get-MonitorInventory([string]$Owner,$Programs){
 $result=[ordered]@{schema='unified-monitor-inventory-1';available=$false;complete=$false;checked_utc=[DateTime]::UtcNow.ToString('o');rules=@();reason='not_checked';scope='this_owner_selected_paths_only_not_all_Windows_rules';packet_drop_verified=$false;configuration_changed=$false}
 $lock=$null
 try{
  UAdmin
  Import-Module NetSecurity -ErrorAction Stop
  $root=USecureRoot $false
  if(-not [IO.Directory]::Exists($root)){$result.available=$true;$result.complete=$true;$result.reason='no_protected_session';return [pscustomobject]$result}
  $lockPath=Join-Path $root 'session.lock';UAssertPath $lockPath
  if(-not [IO.File]::Exists($lockPath)){throw 'existing_session_lock_missing'}
  $lock=[IO.File]::Open($lockPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
  $s=ULoad $root
  if($null -eq $s){$result.available=$true;$result.complete=$true;$result.reason='no_protected_session';return [pscustomobject]$result}
  if($s.owner -cne $Owner){throw 'protected_session_other_owner'}
  if($s.phase -ceq 'restored'){$result.available=$true;$result.complete=$true;$result.reason='journal_restored_no_active_spec_claim';return [pscustomobject]$result}
  if($s.phase -cne 'applied'){throw 'session_not_fully_applied'}
  $selected=@{};foreach($p in $Programs){$selected[[string]$p.id]=[string]$p.path}
  $good=@();$rejected=0;$addressCount=0
  foreach($entry in @($s.entries)){
   try{
    if($entry.removed -or -not $entry.intent -or $null -eq $entry.enabled_image){throw 'session_entry_not_applied'}
    $rule=$entry.rule;$spec=$rule.spec
    if($rule.owner -cne $Owner -or $rule.name -cne $entry.name -or $rule.component -cne 'blacklist'){throw 'unexpected_component_or_owner'}
    if(-not $selected.ContainsKey([string]$spec.program_id)){continue}
    if([string]$spec.program -ine $selected[[string]$spec.program_id] -or $spec.action -cne 'Block' -or $spec.direction -cne 'Outbound' -or $spec.interface_type -cne 'Any' -or $spec.protocol -cnotin @('TCP','UDP') -or -not (Test-InventoryPort $spec.port)){throw 'snapshot_spec_scope'}
    $addressCount+=@($spec.remote_addresses).Count
    if($good.Count -ge 256 -or $addressCount -gt 16384){throw 'bounded_inventory_limit'}
    $persistent=UReadNative $entry.name 'PersistentStore'
    if(-not (UEqual $persistent $entry.enabled_image)){throw 'persistent_image_drift'}
    UValidateNative $persistent $rule $s.id 'PersistentStore' 'True'
    $active=UReadNative $entry.name 'ActiveStore'
    UValidateNative $active $rule $s.id 'ActiveStore' 'True'
    $good+=,[pscustomobject]@{name=[string]$entry.name;program_id=[string]$spec.program_id;program=[string]$spec.program;protocol=[string]$spec.protocol;port=$spec.port;remote_addresses=@($spec.remote_addresses)}
   }catch{$rejected++}
  }
  if(-not (UEqual $s (ULoad $root))){throw 'journal_changed_during_snapshot'}
  $result.rules=$good;$result.available=$true;$result.complete=($rejected -eq 0);$result.reason=if($rejected){'partial_drift_or_read_failure'}else{'persistent_and_active_owned_specs_verified'}
 }catch{$result.reason='inventory_unavailable_or_permission_drift_lock_error';$result.rules=@();$result.available=$false;$result.complete=$false}
 finally{if($null -ne $lock){$lock.Dispose()};$result.checked_utc=[DateTime]::UtcNow.ToString('o')}
 return [pscustomobject]$result
}
